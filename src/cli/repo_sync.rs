use std::env;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::adapters::antigravity::repo_sync::validate_repo_source;
use crate::core::storage::{load_repo_sync_config, save_repo_sync_config};

pub fn resolve_repo_sync_repo(state_dir: &Path, repo_arg: Option<&str>) -> Result<String> {
    let mut config =
        load_repo_sync_config(state_dir).context("failed to load repository sync configuration")?;

    if let Some(repo) = repo_arg {
        let trimmed = repo.trim().to_string();
        if !trimmed.is_empty() {
            validate_repo_location(&trimmed)?;
            config.last_repo = Some(trimmed.clone());
            save_repo_sync_config(state_dir, &config)
                .context("failed to save repository sync configuration")?;
            return Ok(trimmed);
        }
    }

    if let Some(last_repo) = config.last_repo {
        validate_repo_location(&last_repo)?;
        return Ok(last_repo);
    }

    if let Ok(env_repo) = env::var("SAGY_POOL_REPO") {
        let trimmed = env_repo.trim().to_string();
        if !trimmed.is_empty() {
            validate_repo_location(&trimmed)?;
            return Ok(trimmed);
        }
    }

    bail!(
        "No Git repository specified. Please provide a repository URL, e.g. `sagy push git@github.com:user/sagy-accounts.git`"
    )
}

fn validate_repo_location(repo: &str) -> Result<()> {
    // 信任边界只能有一份实现：CLI 侧"凭据 URL 绝不落盘"与 adapter 侧"凭据 URL
    // 绝不进 argv"必须共用同一个校验函数，否则任一侧单独加固都会静默失配。
    validate_repo_source(repo)
}
