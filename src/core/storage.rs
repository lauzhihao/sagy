use std::collections::HashSet;
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

pub fn create_secure_dir_all(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if current.as_os_str().is_empty() || current.exists() {
            continue;
        }
        fs::create_dir(&current)
            .with_context(|| format!("failed to create directory {}", current.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&current).with_context(|| {
                format!("failed to inspect created directory {}", current.display())
            })?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&current, perms).with_context(|| {
                format!(
                    "failed to restrict directory permissions for {}",
                    current.display()
                )
            })?;
        }
    }
    Ok(())
}

pub fn load_state(state_dir: &Path) -> Result<State> {
    let state_dir_metadata = match fs::symlink_metadata(state_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect state directory {}", state_dir.display())
            });
        }
    };
    if state_dir_metadata.file_type().is_symlink() {
        bail!("state directory cannot be a symlink");
    }
    if !state_dir_metadata.is_dir() {
        bail!("state path is not a directory");
    }

    let state_file = state_dir.join("state.json");
    let state_file_metadata = match fs::symlink_metadata(&state_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(State::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect state file {}", state_file.display()));
        }
    };
    if state_file_metadata.file_type().is_symlink() {
        bail!("state file cannot be a symlink");
    }
    if !state_file_metadata.is_file() {
        bail!("state path is not a regular file");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = state_file_metadata.permissions().mode();
        if mode & 0o077 != 0 {
            let mut perms = state_file_metadata.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&state_file, perms);
        }
    }

    let contents = fs::read_to_string(&state_file)
        .with_context(|| format!("failed to read {}", state_file.display()))?;
    let mut state: State = serde_json::from_str(&contents)
        .with_context(|| format!("invalid state file: {}", state_file.display()))?;
    cleanup_invalid_legacy_accounts(&mut state);
    validate_state_before_normalization(state_dir, &state)?;
    normalize_state_account_paths(state_dir, &mut state);
    Ok(state)
}

pub fn write_file_atomically(target: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        create_secure_dir_all(parent)?;
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

pub fn write_secret_file(target: &Path, content: &[u8]) -> Result<()> {
    write_file_atomically(target, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(target)
            .with_context(|| format!("failed to inspect secret file {}", target.display()))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(target, perms).with_context(|| {
            format!(
                "failed to restrict secret file permissions for {}",
                target.display()
            )
        })?;
    }
    Ok(())
}

pub fn save_state(state_dir: &Path, state: &State) -> Result<()> {
    let target = state_dir.join("state.json");
    let contents = serde_json::to_string_pretty(state).context("failed to serialize state")?;
    write_secret_file(&target, contents.as_bytes())
}

pub fn load_repo_sync_config(state_dir: &Path) -> Result<RepoSyncConfig> {
    let config_path = state_dir.join(REPO_SYNC_CONFIG_FILENAME);
    let metadata = match fs::symlink_metadata(&config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RepoSyncConfig::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", config_path.display()));
        }
    };
    restrict_repo_sync_directory(state_dir)?;
    if metadata.file_type().is_symlink() {
        bail!("repository sync configuration cannot be a symlink");
    }
    if !metadata.is_file() {
        bail!("repository sync configuration is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms).with_context(|| {
                format!(
                    "failed to restrict repository sync configuration {}",
                    config_path.display()
                )
            })?;
        }
    }
    let contents = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: RepoSyncConfig = serde_json::from_str(&contents)
        .with_context(|| format!("invalid JSON in {}", config_path.display()))?;
    Ok(config)
}

pub fn save_repo_sync_config(state_dir: &Path, config: &RepoSyncConfig) -> Result<()> {
    create_secure_dir_all(state_dir)?;
    restrict_repo_sync_directory(state_dir)?;
    let target = state_dir.join(REPO_SYNC_CONFIG_FILENAME);
    let contents =
        serde_json::to_string_pretty(config).context("failed to serialize repo sync config")?;
    write_secret_file(&target, contents.as_bytes())
}

fn restrict_repo_sync_directory(state_dir: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(state_dir).with_context(|| {
        format!(
            "failed to inspect repository sync configuration directory {}",
            state_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        bail!("repository sync configuration directory cannot be a symlink");
    }
    if !metadata.is_dir() {
        bail!("repository sync configuration path is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(state_dir, perms).with_context(|| {
            format!(
                "failed to restrict repository sync configuration directory {}",
                state_dir.display()
            )
        })?;
    }
    Ok(())
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
                let _ = write_secret_file(&token_file, token.as_bytes());
            }
            account.auth_path = token_file.to_string_lossy().into_owned();
        } else if let Some(api_key) = &account.api_key {
            if !creds_file.exists() {
                let creds_json = serde_json::json!({
                    "api_key": api_key,
                    "email": account.email,
                    "project_id": account.project_id,
                });
                let _ = write_secret_file(
                    &creds_file,
                    serde_json::to_string_pretty(&creds_json)
                        .unwrap_or_default()
                        .as_bytes(),
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

fn validate_state_before_normalization(state_dir: &Path, state: &State) -> Result<()> {
    let mut account_ids = HashSet::with_capacity(state.accounts.len());
    for account in &state.accounts {
        crate::adapters::antigravity::paths::validate_account_id(&account.id)
            .context("state contains an invalid account id")?;
        if !account_ids.insert(account.id.as_str()) {
            bail!("state contains duplicate account ids");
        }
    }

    if let Some(current_account_id) = state.current_account_id.as_deref() {
        crate::adapters::antigravity::paths::validate_account_id(current_account_id)
            .context("state contains an invalid current account id")?;
        if !account_ids.contains(current_account_id) {
            bail!("state current account does not exist");
        }
    }

    for account_id in state.usage_cache.keys() {
        crate::adapters::antigravity::paths::validate_account_id(account_id)
            .context("state contains an invalid usage cache account id")?;
        if !account_ids.contains(account_id.as_str()) {
            bail!("state usage cache refers to a missing account");
        }
    }

    for account_id in &account_ids {
        crate::adapters::antigravity::paths::account_dir_checked(state_dir, account_id)
            .context("state account path is outside the state directory")?;
    }

    Ok(())
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
