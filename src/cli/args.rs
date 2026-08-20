use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Args;

use crate::adapters::antigravity::LoginMode;

#[derive(Debug, Args)]
#[command(about = "Select the healthiest account, switch credentials, and launch Antigravity CLI")]
pub struct LaunchArgs {
    #[arg(
        long,
        help = "Skip automatic discovery and import of local ~/.gemini credentials"
    )]
    pub no_import_known: bool,
    #[arg(
        long,
        help = "Preview the selected account without switching or launching"
    )]
    pub dry_run: bool,
    #[arg(
        long,
        help = "Do not automatically resume the previous conversation session"
    )]
    pub no_resume: bool,
    #[arg(
        long,
        help = "Switch to the best account and exit without launching the CLI"
    )]
    pub no_launch: bool,
    #[arg(
        trailing_var_arg = true,
        help = "Extra arguments passed directly to the agy CLI"
    )]
    pub extra_args: Vec<OsString>,
}

#[derive(Debug, Args)]
#[command(about = "Select and switch to the healthiest account without launching the CLI")]
pub struct AutoArgs {
    #[arg(long, help = "Skip automatic discovery of local ~/.gemini credentials")]
    pub no_import_known: bool,
    #[arg(long, help = "Preview the selected account without switching")]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
#[command(about = "Configure or log in with new account credentials")]
pub struct LoginArgs {
    #[arg(long, help = "Use OAuth login flow")]
    pub oauth: bool,
    #[arg(long, help = "Use API key authentication")]
    pub api: bool,
    #[arg(long = "token", help = "Raw OAuth / Antigravity token")]
    pub token: Option<String>,
    #[arg(long = "api-key", help = "Google Gemini API Key")]
    pub api_key: Option<String>,
    #[arg(long = "email", help = "Associated email address for the account")]
    pub email: Option<String>,
    #[arg(long = "project-id", help = "Google Cloud Project ID (optional)")]
    pub project_id: Option<String>,
}

#[derive(Debug, Args)]
#[command(about = "Add a new account credential to the local pool")]
pub struct AddArgs {
    #[arg(long, help = "Immediately switch to this account after adding")]
    pub switch: bool,
    #[command(flatten)]
    pub login: LoginArgs,
}

#[derive(Debug, Args)]
#[command(about = "Push or pull encrypted account pools via Git")]
pub struct RepoSyncArgs {
    #[arg(
        long,
        value_name = "REPO_PATH",
        help = "Subdirectory inside the repository (default: .sagy-account-pool)"
    )]
    pub path: Option<String>,

    #[arg(
        short = 'i',
        value_name = "IDENTITY_FILE",
        help = "SSH private key path for repository authentication"
    )]
    pub identity_file: Option<PathBuf>,

    #[arg(long, help = "Include all accounts regardless of portability")]
    pub all: bool,

    #[arg(
        long,
        help = "Disable SSH strict host key verification (insecure, opt-in)"
    )]
    pub insecure_host_key: bool,

    #[arg(help = "Git repository URL (e.g. git@github.com:user/sagy-pool.git)")]
    pub repo: Option<String>,
}

#[derive(Debug, Args)]
#[command(about = "Switch manually to a specified account by email or ID")]
pub struct UseArgs {
    #[arg(help = "Account email address or account ID")]
    pub email: String,
}

#[derive(Debug, Args)]
#[command(about = "Remove an account credential from the local pool")]
pub struct RmArgs {
    #[arg(short = 'y', long = "yes", help = "Skip confirmation prompt")]
    pub assume_yes: bool,
    #[arg(help = "Account email address or account ID")]
    pub email: String,
}

#[derive(Debug, Args)]
#[command(about = "Check and self-update to the latest release from GitHub")]
pub struct UpdateArgs {
    #[arg(short = 'f', long, help = "Force update even if version matches")]
    pub force: bool,
}

#[derive(Debug, Args)]
#[command(about = "Import an account from a JSON credential or token file")]
pub struct ImportAuthArgs {
    #[arg(help = "Path to credentials file (e.g. oauth_creds.json or token file)")]
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
