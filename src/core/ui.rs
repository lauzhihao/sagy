use std::env;
use std::path::Path;

use anyhow::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLanguage {
    En,
    ZhHans,
}

#[derive(Debug, Clone, Copy)]
pub struct Messages {
    language: UiLanguage,
}

pub fn messages() -> Messages {
    Messages {
        language: detect_ui_language(),
    }
}

pub fn detect_ui_language() -> UiLanguage {
    let locale = env::var("LC_ALL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            env::var("LC_MESSAGES")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            env::var("LANG")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });

    locale
        .as_deref()
        .and_then(parse_ui_language_from_locale)
        .unwrap_or(UiLanguage::En)
}

pub fn parse_ui_language_from_locale(locale: &str) -> Option<UiLanguage> {
    let normalized = locale.trim().to_ascii_lowercase();
    if !normalized.starts_with("zh") {
        return None;
    }
    if normalized.contains("utf-8") || normalized.contains("utf8") {
        Some(UiLanguage::ZhHans)
    } else {
        None
    }
}

pub fn format_top_level_error(error: &Error) -> String {
    let ui = messages();
    let prefix = if ui.is_zh() { "错误" } else { "Error" };
    let chain = error.chain().map(ToString::to_string).collect::<Vec<_>>();
    if chain.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}: {}", chain.join(": "))
    }
}

impl Messages {
    pub fn is_zh(&self) -> bool {
        matches!(self.language, UiLanguage::ZhHans)
    }

    pub fn cli_about(&self) -> &'static str {
        if self.is_zh() {
            "面向 Google Antigravity CLI (agy) 的智能多账号与快速启动器。"
        } else {
            "Smart multi-account launcher and orchestrator for Google Antigravity CLI (agy)."
        }
    }

    pub fn no_usable_account(&self) -> &'static str {
        if self.is_zh() {
            "没有找到可用账号。"
        } else {
            "No usable account found."
        }
    }

    pub fn no_usable_account_hint(&self) -> &'static str {
        if self.is_zh() {
            "没有可用账号，请先执行 `sagy add` 或 `sagy login`，或执行 `sagy import-known` 导入当前配置。"
        } else {
            "No usable accounts found. Run `sagy add`, `sagy login`, or `sagy import-known` first."
        }
    }

    pub fn no_importable_accounts(&self) -> &'static str {
        if self.is_zh() {
            "没有在系统中找到可导入的 Antigravity 账号或凭据。"
        } else {
            "No importable Antigravity accounts or credentials found on this system."
        }
    }

    pub fn added_account(&self, email: &str) -> String {
        if self.is_zh() {
            format!("已成功添加账号: {email}")
        } else {
            format!("Added account: {email}")
        }
    }

    pub fn imported_account(&self, email: &str, id: &str) -> String {
        if self.is_zh() {
            format!("已成功导入账号: {email} (ID: {id})")
        } else {
            format!("Imported account: {email} (ID: {id})")
        }
    }

    pub fn removed_account(&self, email: &str) -> String {
        if self.is_zh() {
            format!("已删除账号: {email}")
        } else {
            format!("Removed account: {email}")
        }
    }

    pub fn unknown_account(&self, email: &str) -> String {
        if self.is_zh() {
            format!("未找到账号: {email}")
        } else {
            format!("Unknown account: {email}")
        }
    }

    pub fn confirm_rm(&self, email: &str) -> String {
        if self.is_zh() {
            format!("确定要删除账号 `{email}` 吗？[y/N]: ")
        } else {
            format!("Are you sure you want to remove account `{email}`? [y/N]: ")
        }
    }

    pub fn rm_cancelled(&self) -> &'static str {
        if self.is_zh() {
            "已取消删除。"
        } else {
            "Removal cancelled."
        }
    }

    pub fn rm_requires_tty(&self) -> &'static str {
        if self.is_zh() {
            "非交互式终端下删除账号需要添加 `-y` / `--yes` 参数。"
        } else {
            "`sagy rm` requires `-y`/`--yes` in non-interactive environments."
        }
    }

    pub fn invalid_yes_no(&self) -> &'static str {
        if self.is_zh() {
            "请输入 y 或 n。"
        } else {
            "Please enter 'y' or 'n'."
        }
    }

    pub fn selection_switched(&self) -> &'static str {
        if self.is_zh() {
            "当前选用账号"
        } else {
            "Using account"
        }
    }

    pub fn selection_would_select(&self) -> &'static str {
        if self.is_zh() {
            "预选最佳账号 (Dry Run)"
        } else {
            "Best account (Dry Run)"
        }
    }

    pub fn refreshed_accounts(&self, count: usize) -> String {
        if self.is_zh() {
            format!("已刷新 {count} 个账号的运行状态与配额。")
        } else {
            format!("Refreshed status and quota for {count} account(s).")
        }
    }

    pub fn repo_push_completed(&self, repo: &str, count: usize) -> String {
        if self.is_zh() {
            format!("已加密推送 {count} 个账号至仓库: {repo}")
        } else {
            format!("Encrypted and pushed {count} account(s) to repo: {repo}")
        }
    }

    pub fn repo_push_no_changes(&self, repo: &str) -> String {
        if self.is_zh() {
            format!("远端仓库 {repo} 已经是最新，无账号数据变更。")
        } else {
            format!("Remote repo {repo} is already up to date, no changes.")
        }
    }

    pub fn repo_pull_completed(&self, repo: &str, count: usize) -> String {
        if self.is_zh() {
            format!("已从仓库 {repo} 解密并同步导入 {count} 个账号。")
        } else {
            format!("Pulled and decrypted {count} account(s) from repo: {repo}")
        }
    }

    pub fn update_already_current(&self, version: &str, path: &Path) -> String {
        if self.is_zh() {
            format!("当前已是最新版本 v{version} ({})", path.display())
        } else {
            format!("Already up to date at v{version} ({})", path.display())
        }
    }

    pub fn update_completed(&self, from: &str, to: &str, path: &Path) -> String {
        if self.is_zh() {
            format!("已成功从 v{from} 更新至 v{to} ({})", path.display())
        } else {
            format!("Successfully updated from v{from} to v{to} ({})", path.display())
        }
    }

    pub fn restart_terminal_hint(&self) -> &'static str {
        if self.is_zh() {
            "请重新打开终端或刷新环境变量以生效。"
        } else {
            "Please restart your terminal to use the new binary."
        }
    }
}
