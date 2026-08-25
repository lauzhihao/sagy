use std::env;
use std::path::Path;

use anyhow::{Context, Result, bail};

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
    validate_repo_location_impl(repo)
}

fn validate_repo_location_impl(repo: &str) -> Result<()> {
    if repo.is_empty() || repo.chars().any(|ch| ch.is_control()) {
        bail!("repository location is empty or contains control characters");
    }

    let Some(scheme_end) = repo.find("://") else {
        // SCP-like SSH 地址没有 URL authority。用户名可以包含一个 @，但不能伪装成
        // user:password@host:path。
        if let Some(at) = repo.find('@') {
            let user = &repo[..at];
            let Some(colon_offset) = repo[at + 1..].find(':') else {
                bail!("invalid SCP-like SSH repository location");
            };
            let host = &repo[at + 1..at + 1 + colon_offset];
            if user.is_empty() || user.contains(':') || host.is_empty() {
                bail!("SCP-like SSH repository location cannot contain credentials");
            }
        }
        return Ok(());
    };

    let scheme = &repo[..scheme_end];
    if scheme.is_empty()
        || !scheme.chars().enumerate().all(|(index, ch)| {
            (index == 0 && ch.is_ascii_alphabetic())
                || (index > 0 && (ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')))
        })
    {
        bail!("invalid repository URL scheme");
    }

    let authority_start = scheme_end + 3;
    let tail = &repo[authority_start..];
    if tail.contains(['?', '#']) {
        bail!("repository URL cannot contain a query or fragment");
    }

    let authority_end = tail.find('/').unwrap_or(tail.len());
    let authority = &tail[..authority_end];
    if authority.is_empty() {
        bail!("repository URL must contain a host");
    }
    if let Some((userinfo, host)) = authority.rsplit_once('@') {
        if authority[..authority.len() - host.len() - 1].contains('@')
            || userinfo.is_empty()
            || host.is_empty()
            || !scheme.eq_ignore_ascii_case("ssh")
            || userinfo.contains(':')
        {
            bail!("repository URL cannot contain credentials");
        }
    }

    Ok(())
}
