use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};

use crate::core::state::State;

const DEFAULT_STATE_BASENAME: &str = "sagy";
const STATE_DIR_ENV: &str = "SAGY_HOME";
const REPO_SYNC_CONFIG_FILENAME: &str = "repo-sync.json";
const BIN_DIR_NAME: &str = "bin";
const RUNTIME_DIR_NAME: &str = "runtime";
const TMP_DIR_NAME: &str = "tmp";

pub fn resolve_state_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_dir {
        return Ok(expand_user_path(path));
    }

    if let Some(path) = configured_state_dir_from_env() {
        return Ok(path);
    }

    default_state_dir()
}

pub fn bin_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(BIN_DIR_NAME)
}

pub fn runtime_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(RUNTIME_DIR_NAME)
}

pub fn tmp_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(TMP_DIR_NAME)
}

pub fn accounts_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("accounts")
}

fn configured_state_dir_from_env() -> Option<PathBuf> {
    env::var_os(STATE_DIR_ENV).map(|value| expand_user_path(Path::new(&value)))
}

fn default_state_dir() -> Result<PathBuf> {
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        return Ok(home.join(format!(".{DEFAULT_STATE_BASENAME}")));
    }

    let base_dirs =
        BaseDirs::new().context("unable to resolve base directories for current user")?;
    Ok(default_state_dir_for_home(None, base_dirs.data_local_dir()))
}

fn default_state_dir_for_home(home: Option<&Path>, data_local_dir: &Path) -> PathBuf {
    home.map(|home| home.join(format!(".{DEFAULT_STATE_BASENAME}")))
        .unwrap_or_else(|| data_local_dir.join(DEFAULT_STATE_BASENAME))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RepoSyncConfig {
    #[serde(default)]
    pub last_repo: Option<String>,
}

pub fn load_state(state_dir: &Path) -> Result<State> {
    let state_file = state_dir.join("state.json");
    if !state_file.exists() {
        return Ok(State::default());
    }

    let contents = fs::read_to_string(&state_file)
        .with_context(|| format!("failed to read {}", state_file.display()))?;
    let mut state: State = serde_json::from_str(&contents)
        .with_context(|| format!("invalid state file: {}", state_file.display()))?;
    cleanup_invalid_legacy_accounts(&mut state);
    normalize_state_account_paths(state_dir, &mut state);
    Ok(state)
}

pub fn write_file_atomically(target: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let pid = std::process::id();
    let unique_id = uuid::Uuid::new_v4();
    let temp_name = format!(".{file_name}.{pid}.{unique_id}.tmp");
    let temp_path = target
        .parent()
        .map(|p| p.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(&temp_name));

    {
        use std::io::Write;
        let mut file = fs::File::create(&temp_path)
            .with_context(|| format!("failed to create temporary file {}", temp_path.display()))?;
        file.write_all(content)
            .with_context(|| format!("failed to write temporary file {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary file {}", temp_path.display()))?;
    }

    fs::rename(&temp_path, target).with_context(|| {
        format!(
            "failed to replace {} with {}",
            target.display(),
            temp_path.display()
        )
    })?;

    Ok(())
}

pub fn save_state(state_dir: &Path, state: &State) -> Result<()> {
    let target = state_dir.join("state.json");
    let contents = serde_json::to_string_pretty(state).context("failed to serialize state")?;
    write_file_atomically(&target, contents.as_bytes())
}

pub fn load_repo_sync_config(state_dir: &Path) -> Result<RepoSyncConfig> {
    let config_path = state_dir.join(REPO_SYNC_CONFIG_FILENAME);
    if !config_path.exists() {
        return Ok(RepoSyncConfig::default());
    }
    let contents = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: RepoSyncConfig = serde_json::from_str(&contents)
        .with_context(|| format!("invalid JSON in {}", config_path.display()))?;
    Ok(config)
}

pub fn save_repo_sync_config(state_dir: &Path, config: &RepoSyncConfig) -> Result<()> {
    let target = state_dir.join(REPO_SYNC_CONFIG_FILENAME);
    let contents =
        serde_json::to_string_pretty(config).context("failed to serialize repo sync config")?;
    write_file_atomically(&target, contents.as_bytes())
}

pub fn ensure_exists(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        bail!("{label} does not exist: {}", path.display());
    }
    Ok(())
}

pub fn expand_user_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
            return home;
        }
    } else if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
            return home.join(stripped);
        }
    }
    path.to_path_buf()
}

fn cleanup_invalid_legacy_accounts(state: &mut State) {
    let mut dropped_ids = Vec::new();
    state.accounts.retain(|account| {
        let is_bogus_google_accounts = account.email.eq_ignore_ascii_case("google_accounts")
            && account.oauth_token.is_none()
            && account.api_key.is_none()
            && account.refresh_token.is_none();
        if is_bogus_google_accounts {
            dropped_ids.push(account.id.clone());
        }
        !is_bogus_google_accounts
    });
    for id in &dropped_ids {
        state.usage_cache.remove(id);
        if state.current_account_id.as_deref() == Some(id.as_str()) {
            state.current_account_id = None;
        }
    }
}

fn normalize_state_account_paths(state_dir: &Path, state: &mut State) {
    let accounts_root = accounts_dir(state_dir);
    for account in &mut state.accounts {
        let account_root = accounts_root.join(&account.id);
        let token_file = account_root.join("antigravity-oauth-token");
        let creds_file = account_root.join("credentials.json");

        if let Some(token) = &account.oauth_token {
            if !token_file.exists() {
                let _ = fs::create_dir_all(&account_root);
                let _ = fs::write(&token_file, token);
            }
            account.auth_path = token_file.to_string_lossy().into_owned();
        } else if let Some(api_key) = &account.api_key {
            if !creds_file.exists() {
                let _ = fs::create_dir_all(&account_root);
                let creds_json = serde_json::json!({
                    "api_key": api_key,
                    "email": account.email,
                    "project_id": account.project_id,
                });
                let _ = fs::write(
                    &creds_file,
                    serde_json::to_string_pretty(&creds_json).unwrap_or_default(),
                );
            }
            account.auth_path = creds_file.to_string_lossy().into_owned();
        } else if token_file.exists() {
            account.auth_path = token_file.to_string_lossy().into_owned();
        } else {
            account.auth_path = creds_file.to_string_lossy().into_owned();
        }

        let expected_config_path = account_root.join("settings.json");
        if expected_config_path.exists() {
            account.config_path = Some(expected_config_path.to_string_lossy().into_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state::{AccountRecord, AccountType};

    #[test]
    fn test_token_account_paths_persist_across_load_state() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();

        let mut state = State::default();
        let acc_id = "test-token-acc-123";
        let acc_root = accounts_dir(state_dir).join(acc_id);
        fs::create_dir_all(&acc_root).expect("create acc dir");
        let token_path = acc_root.join("antigravity-oauth-token");
        fs::write(&token_path, "sample_jwt_token_12345").expect("write token");

        let record = AccountRecord {
            id: acc_id.to_string(),
            email: "user@example.com".to_string(),
            account_type: AccountType::OAuth,
            oauth_token: Some("sample_jwt_token_12345".to_string()),
            auth_path: token_path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        state.accounts.push(record);
        save_state(state_dir, &state).expect("save state");

        // Reload state
        let loaded = load_state(state_dir).expect("load state");
        assert_eq!(loaded.accounts.len(), 1);
        let loaded_acc = &loaded.accounts[0];
        assert_eq!(loaded_acc.id, acc_id);
        assert_eq!(loaded_acc.auth_path, token_path.to_string_lossy().as_ref());
        assert!(Path::new(&loaded_acc.auth_path).exists());
    }

    #[test]
    fn test_cleanup_invalid_legacy_google_accounts() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();

        let mut state = State::default();
        state.accounts.push(AccountRecord {
            id: "fake-ga-id".to_string(),
            email: "google_accounts".to_string(),
            account_type: AccountType::OAuth,
            ..Default::default()
        });
        save_state(state_dir, &state).expect("save state");

        let loaded = load_state(state_dir).expect("load state");
        assert_eq!(loaded.accounts.len(), 0);
    }

    #[test]
    fn test_write_file_atomically_concurrent() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let target_file = temp_dir.path().join("sub").join("atomic.txt");
        let content = b"hello atomic world";
        write_file_atomically(&target_file, content).expect("atomic write");

        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).expect("read"), content);
    }

    #[test]
    fn test_repo_sync_config_roundtrip() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();

        let cfg = RepoSyncConfig {
            last_repo: Some("git@github.com:test/pool.git".to_string()),
        };
        save_repo_sync_config(state_dir, &cfg).expect("save config");

        let loaded = load_repo_sync_config(state_dir).expect("load config");
        assert_eq!(
            loaded.last_repo,
            Some("git@github.com:test/pool.git".to_string())
        );
    }
}
