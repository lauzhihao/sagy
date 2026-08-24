use std::env;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::core::storage::{load_repo_sync_config, save_repo_sync_config};

pub fn resolve_repo_sync_repo(state_dir: &Path, repo_arg: Option<&str>) -> Result<String> {
    let mut config = load_repo_sync_config(state_dir)?;

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
    let Some(scheme_end) = repo.find("://") else {
        // SCP-like SSH 地址（例如 git@github.com:user/repo.git）没有 HTTP
        // authority，必须保持兼容。
        return Ok(());
    };

    let scheme = &repo[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }

    let authority_start = scheme_end + 3;
    let tail = &repo[authority_start..];
    if tail.contains(['?', '#']) {
        bail!("HTTP(S) repository URL cannot contain a query or fragment");
    }

    let authority_end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
    let authority = &tail[..authority_end];
    if authority.is_empty() {
        bail!("HTTP(S) repository URL must contain a host");
    }
    if authority.contains('@') {
        bail!("HTTP(S) repository URL cannot contain userinfo");
    }

    Ok(())
}
