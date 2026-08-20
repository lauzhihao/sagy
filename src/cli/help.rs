use crate::core::ui;
use std::ffi::OsString;

pub fn requested_help_topic(args: &[OsString]) -> Option<Option<String>> {
    if args.len() <= 1 {
        return None;
    }

    let first = args[1].to_string_lossy();
    if first == "-h" || first == "--help" {
        if args.len() > 2 {
            return Some(Some(args[2].to_string_lossy().to_string()));
        }
        return Some(None);
    }

    if first == "help" {
        if args.len() > 2 {
            return Some(Some(args[2].to_string_lossy().to_string()));
        }
        return Some(None);
    }

    // Check if any subcommand followed by --help or -h
    if args.iter().any(|a| {
        let s = a.to_string_lossy();
        s == "-h" || s == "--help"
    }) {
        for arg in args.iter().skip(1) {
            let s = arg.to_string_lossy();
            if is_known_subcmd(&s) {
                return Some(Some(s.to_string()));
            }
        }
        return Some(None);
    }

    None
}

pub fn is_known_subcmd(s: &str) -> bool {
    matches!(
        s,
        "launch"
            | "auto"
            | "add"
            | "login"
            | "push"
            | "pull"
            | "use"
            | "rm"
            | "list"
            | "refresh"
            | "update"
            | "upgrade"
            | "import-auth"
            | "import-known"
    )
}

pub fn render_help(topic: Option<String>) -> String {
    let ui = ui::messages();
    let is_zh = ui.is_zh();

    if let Some(t) = topic {
        return render_topic_help(&t, is_zh);
    }

    if is_zh {
        r#"sagy - Google Antigravity CLI (agy) 智能多账号与快速启动器

用法:
  sagy [命令] [参数...]

核心命令:
  sagy [launch]          选择最佳账号，切换后启动或恢复 Antigravity CLI
  sagy auto              只选择并切换到最佳账号，不启动 CLI
  sagy add               添加新账号凭据（OAuth / Token / API Key）
  sagy login             登录并绑定账号凭据
  sagy use <email>       按邮箱或 ID 手动切换到指定账号
  sagy rm <email>        删除指定账号
  sagy list              显示所有已知账号的健康状态与配额表格
  sagy refresh           立即刷新所有账号的实时状态与健康探测
  sagy import-known      从本地 ~/.gemini 自动扫描并导入现有凭据
  sagy import-auth <路径> 导入指定的认证文件（json/token）
  sagy push [仓库]       将账号池加密推送到指定的 Git 仓库
  sagy pull [仓库]       从 Git 仓库拉取并解密同步账号池
  sagy update            从 GitHub Releases 自动检查并自更新

全局选项:
  --state-dir <路径>     自定义状态与账号存储目录 (默认: ~/.sagy)
  -V, --version          显示当前版本号
  -h, --help             显示帮助信息
"#
        .to_string()
    } else {
        r#"sagy - Smart multi-account launcher and orchestrator for Google Antigravity CLI (agy)

Usage:
  sagy [command] [args...]

Commands:
  sagy [launch]          Select best account, switch, and launch Antigravity CLI
  sagy auto              Select and switch to the best account without launching
  sagy add               Add a new account credential (OAuth / Token / API Key)
  sagy login             Log in or configure a new account
  sagy use <email>       Switch directly to a specified account
  sagy rm <email>        Remove a specified account
  sagy list              Display account list, health, and quota table
  sagy refresh           Refresh status and probe health for all accounts
  sagy import-known      Auto-discover and import existing ~/.gemini credentials
  sagy import-auth <path> Import credentials from a file
  sagy push [repo]       Encrypt and push account pool to a Git repository
  sagy pull [repo]       Pull and decrypt account pool from a Git repository
  sagy update            Check and self-update from GitHub Releases

Global Options:
  --state-dir <path>     Override state and account directory (default: ~/.sagy)
  -V, --version          Print version information
  -h, --help             Print help information
"#
        .to_string()
    }
}

fn render_topic_help(topic: &str, is_zh: bool) -> String {
    let lower = topic.to_ascii_lowercase();
    match lower.as_str() {
        "launch" => {
            if is_zh {
                "sagy launch [选项] [-- 额外参数...]\n\n选择健康度最高的可用账号，切换环境后启动或恢复 Antigravity CLI。\n\n选项:\n  --dry-run          仅预览选中账号，不切换也不拉起 CLI\n  --no-resume        不自动恢复上一次对话会话\n  --no-import-known  跳过对 ~/.gemini 本地凭据的自动扫描\n  --no-launch        仅完成账号切换，不启动 CLI\n".to_string()
            } else {
                "sagy launch [options] [-- extra_args...]\n\nSelect the healthiest account, switch credentials, and launch or resume Antigravity CLI.\n\nOptions:\n  --dry-run          Preview the selected account without switching or launching\n  --no-resume        Do not automatically resume the previous conversation session\n  --no-import-known  Skip automatic discovery of local credentials\n  --no-launch        Switch credentials and exit without launching\n".to_string()
            }
        }
        "push" => {
            if is_zh {
                "sagy push [仓库URL] [选项]\n\n使用 SAGY_POOL_KEY (XChaCha20Poly1305) 强加密并将本地账号池推送到指定的 Git 仓库。\n\n选项:\n  --path <路径>      仓库内存储目录 (默认: .sagy-account-pool)\n  -i <密钥文件>      指定 SSH 私钥文件\n  --all              强制导出全部账号（包含无便携凭据的本地账号）\n".to_string()
            } else {
                "sagy push [repo_url] [options]\n\nEncrypt (XChaCha20Poly1305) and push the local account pool to a Git repository using SAGY_POOL_KEY.\n\nOptions:\n  --path <path>      Subdirectory inside repo (default: .sagy-account-pool)\n  -i <key_file>      SSH private key path\n  --all              Export all accounts including local-only profiles\n".to_string()
            }
        }
        "pull" => {
            if is_zh {
                "sagy pull [仓库URL] [选项]\n\n从 Git 仓库拉取加密账号池并使用 SAGY_POOL_KEY 解密合并到本地。\n\n选项:\n  --path <路径>      仓库内存储目录 (默认: .sagy-account-pool)\n  -i <密钥文件>      指定 SSH 私钥文件\n".to_string()
            } else {
                "sagy pull [repo_url] [options]\n\nPull and decrypt an account pool bundle from a Git repository into the local state.\n\nOptions:\n  --path <path>      Subdirectory inside repo (default: .sagy-account-pool)\n  -i <key_file>      SSH private key path\n".to_string()
            }
        }
        "auto" => {
            if is_zh {
                "sagy auto [选项]\n\n仅优选并切换到最佳账号，不拉起 CLI。\n\n选项:\n  --dry-run          仅预览选中账号\n  --no-import-known  跳过本地凭据扫描\n".to_string()
            } else {
                "sagy auto [options]\n\nSelect and switch to the best account without launching the CLI.\n\nOptions:\n  --dry-run          Preview selection only\n  --no-import-known  Skip local scan\n".to_string()
            }
        }
        _ => {
            if is_zh {
                format!(
                    "关于命令 `{topic}` 的详细说明:\n运行 `sagy {topic} --help` 查看完整参数列表。\n"
                )
            } else {
                format!(
                    "Detailed help for command `{topic}`:\nRun `sagy {topic} --help` to view all arguments.\n"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn test_requested_help_topic() {
        let args1 = vec![OsString::from("sagy"), OsString::from("-h")];
        assert_eq!(requested_help_topic(&args1), Some(None));

        let args2 = vec![
            OsString::from("sagy"),
            OsString::from("help"),
            OsString::from("launch"),
        ];
        assert_eq!(
            requested_help_topic(&args2),
            Some(Some("launch".to_string()))
        );

        let args3 = vec![
            OsString::from("sagy"),
            OsString::from("push"),
            OsString::from("--help"),
        ];
        assert_eq!(requested_help_topic(&args3), Some(Some("push".to_string())));

        let args4 = vec![OsString::from("sagy"), OsString::from("list")];
        assert_eq!(requested_help_topic(&args4), None);
    }

    #[test]
    fn test_render_help_topics() {
        let help_main = render_help(None);
        assert!(help_main.contains("sagy"));

        let help_launch = render_help(Some("launch".to_string()));
        assert!(help_launch.contains("sagy launch"));

        let help_push = render_help(Some("push".to_string()));
        assert!(help_push.contains("sagy push"));
    }
}
