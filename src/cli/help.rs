use crate::core::ui;

pub fn requested_help_topic(args: &[std::ffi::OsString]) -> Option<Option<String>> {
    if args.len() <= 1 {
        return None;
    }
    let first = args[1].to_string_lossy();
    if first == "-h" || first == "--help" || first == "help" {
        if args.len() > 2 {
            return Some(Some(args[2].to_string_lossy().to_string()));
        }
        return Some(None);
    }
    None
}

pub fn render_help(topic: Option<String>) -> String {
    let ui = ui::messages();
    if let Some(topic) = topic {
        return render_topic_help(&topic, ui.is_zh());
    }

    if ui.is_zh() {
        r#"sagy - Google Antigravity CLI (agy) 智能多账号与快速启动器

用法:
  sagy [命令] [参数...]
  flash [参数...]        使用 gemini-3.7-flash (effort: low) 快速启动
  pro [参数...]          使用 gemini-3.7-pro (effort: high) 快速启动
  think [参数...]        使用 gemini-3.7-flash (effort: high) 深度思考模式启动

核心命令:
  sagy [launch]          选择最佳账号，切换后启动或恢复 Antigravity CLI
  sagy auto              只选择并切换到最佳账号，不启动 CLI
  sagy add               添加新账号凭据（OAuth / Token / API Key）
  sagy login             登录并绑定账号凭据
  sagy use <email>       按邮箱或 ID 手动切换到指定账号
  sagy rm <email>        删除指定账号
  sagy list              显示所有已知账号的健康状态与配额表格
  sagy refresh           立即刷新所有账号的实时状态
  sagy import-known      从本地 ~/.gemini 自动扫描并导入现有凭据
  sagy import-auth <路径> 导入指定的认证文件（json/token）
  sagy push [仓库]       将账号池加密推送到指定的 Git 仓库
  sagy pull [仓库]       从 Git 仓库拉取并解密同步账号池
  sagy update            从 GitHub Releases 自动检查并自更新

全局选项:
  --state-dir <路径>     自定义状态与账号存储目录 (默认: ~/.sagy)
  -h, --help             显示帮助信息
"#
        .to_string()
    } else {
        r#"sagy - Smart multi-account launcher and orchestrator for Google Antigravity CLI (agy)

Usage:
  sagy [command] [args...]
  flash [args...]        Launch with gemini-3.7-flash (effort: low)
  pro [args...]          Launch with gemini-3.7-pro (effort: high)
  think [args...]        Launch with gemini-3.7-flash (effort: high)

Commands:
  sagy [launch]          Select best account, switch, and launch Antigravity CLI
  sagy auto              Select and switch to the best account without launching
  sagy add               Add a new account credential (OAuth / Token / API Key)
  sagy login             Log in or configure a new account
  sagy use <email>       Switch directly to a specified account
  sagy rm <email>        Remove a specified account
  sagy list              Display account list, health, and quota table
  sagy refresh           Refresh status and quota for all accounts
  sagy import-known      Auto-discover and import existing ~/.gemini credentials
  sagy import-auth <path> Import credentials from a file
  sagy push [repo]       Encrypt and push account pool to a Git repository
  sagy pull [repo]       Pull and decrypt account pool from a Git repository
  sagy update            Check and self-update from GitHub Releases

Global Options:
  --state-dir <path>     Override state and account directory (default: ~/.sagy)
  -h, --help             Print help information
"#
        .to_string()
    }
}

fn render_topic_help(topic: &str, _is_zh: bool) -> String {
    format!("Help for topic `{topic}`:\nRun `sagy {topic} --help` for specific arguments.\n")
}
