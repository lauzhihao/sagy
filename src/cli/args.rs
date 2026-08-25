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
        help = "Start a new agy session instead of resuming the previous conversation \
                (sagy resumes by default unless the agy arguments already carry a prompt)"
    )]
    pub no_resume: bool,
    #[arg(
        long,
        help = "Switch to the best account and exit without launching the CLI"
    )]
    pub no_launch: bool,
    // 逃生口沿用 `--insecure-host-key` 的形状：默认安全，显式 opt-in。
    #[arg(
        long,
        help = "Take over credentials already present in the active Antigravity home that sagy \
                does not manage; the replaced antigravity-oauth-token / oauth_creds.json are kept \
                as <name>.sagy-backup-<txid> next to the originals (opt-in)"
    )]
    pub takeover: bool,
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
    // 逃生口沿用 `--insecure-host-key` 的形状：默认安全，显式 opt-in。
    #[arg(
        long,
        help = "Take over credentials already present in the active Antigravity home that sagy \
                does not manage; the replaced antigravity-oauth-token / oauth_creds.json are kept \
                as <name>.sagy-backup-<txid> next to the originals (opt-in)"
    )]
    pub takeover: bool,
}

#[derive(Debug, Args)]
#[command(about = "Configure or log in with new account credentials")]
pub struct LoginArgs {
    #[arg(
        long,
        conflicts_with_all = ["api", "api_key", "token"],
        // sagy 没有任何 OAuth 授权交换：这条 flag 只是显式选中"粘贴一个你已经
        // 持有的 token"这条隐藏输入分支，并与非交互的 key/token 模式互斥。
        // 帮助文案必须据实描述，否则用户会以为它会打开浏览器完成授权。
        help = "Select the interactive prompt that takes an OAuth token you already hold \
                (sagy performs no browser authorization)"
    )]
    pub oauth: bool,
    // `--api` 本身不认证任何东西，缺少 --api-key 时只会报错退出。
    #[arg(
        long,
        help = "Select API-key mode; requires --api-key <API_KEY> in the same invocation"
    )]
    pub api: bool,
    #[arg(long = "token", help = "Raw OAuth / Antigravity token")]
    pub token: Option<String>,
    #[arg(long = "api-key", help = "Google Gemini API Key")]
    pub api_key: Option<String>,
    #[arg(long = "email", help = "Associated email address for the account")]
    pub email: Option<String>,
    #[arg(long = "project-id", help = "Google Cloud Project ID (optional)")]
    pub project_id: Option<String>,
    // 逃生口沿用 `--insecure-host-key` 的形状：默认安全，显式 opt-in。
    #[arg(
        long,
        help = "Take over credentials already present in the active Antigravity home that sagy \
                does not manage; the replaced antigravity-oauth-token / oauth_creds.json are kept \
                as <name>.sagy-backup-<txid> next to the originals (opt-in)"
    )]
    pub takeover: bool,
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
    // 逃生口沿用 `--insecure-host-key` 的形状：默认安全，显式 opt-in。
    #[arg(
        long,
        help = "Take over credentials already present in the active Antigravity home that sagy \
                does not manage; the replaced antigravity-oauth-token / oauth_creds.json are kept \
                as <name>.sagy-backup-<txid> next to the originals (opt-in)"
    )]
    pub takeover: bool,
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

/// `--oauth` 的语义完全由 clap 的 `conflicts_with_all` 承担，这里不再读它。
///
/// 原因：`--oauth` 与 `--token` / `--api-key` / `--api` 互斥，所以任何能通过
/// 解析的输入里，"显式 --oauth" 和"什么都没给"落到的都是同一个 OAuth 分支——
/// 再写一段提前 return 只会制造"这个字段在运行时生效"的错觉。真正可观察的
/// 差异发生在解析期：`--oauth --api-key K` 由"静默用 API key"变成报错退出。
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// 渲染一个 `Args` 结构体的真实 help 输出。
    ///
    /// 直接断言源码里的属性字符串等于什么都没测；用户看到的是 clap 渲染后的
    /// 文本，只有它才能证明文案改没改。
    fn rendered_help<T: clap::Args>() -> String {
        let mut command = T::augment_args(clap::Command::new("probe"));
        command.render_long_help().to_string()
    }

    /// AC-R12-6.1: `--oauth` 只是选中"粘贴一个你已经持有的 token"的隐藏输入
    /// 提示，实现里没有任何授权交换，帮助文案不得把它描述成 OAuth 登录流程。
    #[test]
    fn the_oauth_flag_help_does_not_claim_an_authorization_flow() {
        let help = rendered_help::<LoginArgs>();
        assert!(help.contains("--oauth"), "login lost --oauth: {help}");
        assert!(
            !help.to_lowercase().contains("oauth login"),
            "--oauth help still describes an OAuth login: {help}"
        );
        assert!(
            !help.to_lowercase().contains("login flow"),
            "--oauth help still describes a login flow: {help}"
        );
        assert!(
            help.contains("no browser authorization"),
            "--oauth help must say that sagy performs no authorization exchange: {help}"
        );
    }

    /// AC-R12-6.2: 遗漏检查的方法——把本模块每个 `Args` 结构体的真实 help
    /// 全部渲染出来，一次性过同一份夸大用语黑名单，并强制 ASCII-only。
    /// 新增任何一条 help 文案都会自动落进这个扫描里。
    #[test]
    fn no_argument_help_text_overstates_what_sagy_implements() {
        const OVERSTATED: [&str; 3] = ["oauth login", "login flow", "api key authentication"];
        let surfaces = [
            ("launch", rendered_help::<LaunchArgs>()),
            ("auto", rendered_help::<AutoArgs>()),
            ("login", rendered_help::<LoginArgs>()),
            ("add", rendered_help::<AddArgs>()),
            ("repo-sync", rendered_help::<RepoSyncArgs>()),
            ("use", rendered_help::<UseArgs>()),
            ("rm", rendered_help::<RmArgs>()),
            ("update", rendered_help::<UpdateArgs>()),
            ("import-auth", rendered_help::<ImportAuthArgs>()),
        ];
        for (name, help) in surfaces {
            assert!(help.is_ascii(), "{name} help is not ASCII-only: {help}");
            let lowered = help.to_lowercase();
            for phrase in OVERSTATED {
                assert!(
                    !lowered.contains(phrase),
                    "{name} help claims an unimplemented capability ({phrase}): {help}"
                );
            }
        }
        // Cli 顶层的 about/flag 文案走同一份检查。
        let root = crate::cli::Cli::command()
            .render_long_help()
            .to_string()
            .to_lowercase();
        for phrase in OVERSTATED {
            assert!(
                !root.contains(phrase),
                "root help claims an unimplemented capability ({phrase})"
            );
        }
    }
}
