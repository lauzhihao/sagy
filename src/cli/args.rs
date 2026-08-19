use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Args;

use crate::adapters::antigravity::LoginMode;

#[derive(Debug, Args)]
pub struct LaunchArgs {
    #[arg(long)]
    pub no_import_known: bool,
    #[arg(long)]
    pub no_login: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub no_resume: bool,
    #[arg(long)]
    pub no_launch: bool,
    #[arg(trailing_var_arg = true)]
    pub extra_args: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct AutoArgs {
    #[arg(long)]
    pub no_import_known: bool,
    #[arg(long)]
    pub no_login: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long)]
    pub oauth: bool,
    #[arg(long)]
    pub api: bool,
    #[arg(long = "token")]
    pub token: Option<String>,
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
    #[arg(long = "email")]
    pub email: Option<String>,
    #[arg(long = "project-id")]
    pub project_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    #[arg(long)]
    pub switch: bool,
    #[command(flatten)]
    pub login: LoginArgs,
}

#[derive(Debug, Args)]
pub struct RepoSyncArgs {
    #[arg(long, value_name = "REPO_PATH")]
    pub path: Option<String>,

    #[arg(short = 'i', value_name = "IDENTITY_FILE")]
    pub identity_file: Option<PathBuf>,

    #[arg(long)]
    pub all: bool,

    pub repo: Option<String>,
}

#[derive(Debug, Args)]
pub struct UseArgs {
    pub email: String,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    #[arg(short = 'y', long = "yes")]
    pub assume_yes: bool,
    pub email: String,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(short = 'f', long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ImportAuthArgs {
    pub path: PathBuf,
}

pub fn resolve_login_mode(args: &LoginArgs) -> Result<LoginMode<'_>> {
    if let Some(token) = &args.token {
        return Ok(LoginMode::Token {
            token: token.trim(),
            email: args.email.as_deref(),
        });
    }

    if let Some(api_key) = &args.api_key {
        return Ok(LoginMode::ApiKey {
            api_key: api_key.trim(),
            email: args.email.as_deref(),
            project_id: args.project_id.as_deref(),
        });
    }

    if args.api {
        bail!("When using --api, please also provide --api-key <KEY>");
    }

    Ok(LoginMode::OAuth {
        email_hint: args.email.as_deref(),
    })
}
