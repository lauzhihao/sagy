use std::env;
use std::path::Path;

use anyhow::{Result, bail};

use crate::core::storage::{load_repo_sync_config, save_repo_sync_config};

pub fn resolve_repo_sync_repo(state_dir: &Path, repo_arg: Option<&str>) -> Result<String> {
    let mut config = load_repo_sync_config(state_dir)?;

    if let Some(repo) = repo_arg {
        let trimmed = repo.trim().to_string();
        if !trimmed.is_empty() {
            config.last_repo = Some(trimmed.clone());
            let _ = save_repo_sync_config(state_dir, &config);
            return Ok(trimmed);
        }
    }

    if let Some(last_repo) = config.last_repo {
        return Ok(last_repo);
    }

    if let Ok(env_repo) = env::var("SAGY_POOL_REPO") {
        let trimmed = env_repo.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    bail!("No Git repository specified. Please provide a repository URL, e.g. `sagy push git@github.com:user/sagy-accounts.git`")
}
