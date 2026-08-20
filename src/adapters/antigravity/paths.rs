use std::env;
use std::path::{Path, PathBuf};

use crate::core::storage::expand_user_path;

pub fn find_agy_bin(state_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGY_BIN") {
        let candidate = expand_user_path(Path::new(&path));
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    if let Some(state_dir) = state_dir {
        let runtime_candidate = state_dir.join("runtime").join("bin").join(bin_name("agy"));
        if runtime_candidate.is_file() {
            return Some(runtime_candidate);
        }
    }

    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        let candidates = [
            home.join(".gemini/antigravity-cli/bin")
                .join(bin_name("agy")),
            home.join(".local/bin").join(bin_name("agy")),
            home.join(".cargo/bin").join(bin_name("agy")),
        ];
        for candidate in candidates {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    find_program("agy")
}

pub fn find_git_bin() -> Option<PathBuf> {
    find_program("git")
}

pub fn find_program(name: &str) -> Option<PathBuf> {
    let name_ext = bin_name(name);
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join(&name_ext);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let well_known = [
        PathBuf::from("/usr/local/bin").join(&name_ext),
        PathBuf::from("/opt/homebrew/bin").join(&name_ext),
        PathBuf::from("/usr/bin").join(&name_ext),
    ];
    well_known.into_iter().find(|candidate| candidate.is_file())
}

pub fn default_antigravity_cli_home() -> Option<PathBuf> {
    if let Some(override_path) = env::var_os("ANTIGRAVITY_CONFIG_DIR") {
        return Some(expand_user_path(Path::new(&override_path)));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".gemini").join("antigravity-cli"))
}

pub fn default_gemini_home() -> Option<PathBuf> {
    if let Some(override_path) = env::var_os("GEMINI_HOME") {
        return Some(expand_user_path(Path::new(&override_path)));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".gemini"))
}

pub fn account_dir(state_dir: &Path, account_id: &str) -> PathBuf {
    state_dir.join("accounts").join(account_id)
}

pub fn account_credentials_file(account_dir: &Path) -> PathBuf {
    account_dir.join("credentials.json")
}

pub fn account_token_file(account_dir: &Path) -> PathBuf {
    account_dir.join("antigravity-oauth-token")
}

pub fn account_settings_file(account_dir: &Path) -> PathBuf {
    account_dir.join("settings.json")
}

fn bin_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_paths() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();
        let acc_id = "test-acc-123";

        let acc_dir = account_dir(state_dir, acc_id);
        assert_eq!(acc_dir, state_dir.join("accounts").join(acc_id));

        let creds_file = account_credentials_file(&acc_dir);
        assert_eq!(creds_file, acc_dir.join("credentials.json"));

        let token_file = account_token_file(&acc_dir);
        assert_eq!(token_file, acc_dir.join("antigravity-oauth-token"));

        let settings_file = account_settings_file(&acc_dir);
        assert_eq!(settings_file, acc_dir.join("settings.json"));
    }

    #[test]
    fn test_find_git_bin() {
        let git = find_git_bin();
        assert!(git.is_some());
    }
}
