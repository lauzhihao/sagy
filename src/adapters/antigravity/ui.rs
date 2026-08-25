use chrono::{Local, TimeZone, Utc};
use unicode_width::UnicodeWidthStr;

use crate::core::state::{LiveIdentity, State};

/// 表格与脚注都保持 ASCII，且与 `policy::eligibility` 使用同一个判定
/// (`UsageSnapshot::probe_channel_unreachable`)，避免"能启动但显示成故障"。
const PROBE_UNREACHABLE_STATUS: &str = "Degraded (probe unreachable)";
const PROBE_UNREACHABLE_NOTE: &str = concat!(
    "Note: the health probe got no verdict from the provider (offline, proxy, DNS,\n",
    "gateway, or server failure).\n",
    "Status above comes from the cached and locally validated credentials; accounts marked\n",
    "\"Degraded (probe unreachable)\" can still be selected and launched."
);

impl super::AntigravityAdapter {
    pub fn render_account_table(
        &self,
        state: &State,
        active_identity: Option<&LiveIdentity>,
    ) -> String {
        if state.accounts.is_empty() {
            return "No accounts registered. Use `sagy add` or `sagy import-known` to get started.\n"
                .to_string();
        }

        let now = Utc::now().timestamp();
        let mut probe_unreachable = false;
        let headers = [
            " ",
            "Email / Label",
            "Type",
            "Plan",
            "Status",
            "Quota",
            "Last Used",
        ];
        let mut rows = Vec::new();

        for account in &state.accounts {
            let is_active = state.current_account_id.as_deref() == Some(&account.id)
                || active_identity
                    .map(|id| id.email.eq_ignore_ascii_case(&account.email))
                    .unwrap_or(false);

            let active_str = if is_active { "*" } else { " " };
            let email_str = account.email.as_str();
            let type_str = account.account_type.as_str();
            let plan_str = account.plan.as_deref().unwrap_or("Antigravity");

            let usage = state.usage_cache.get(&account.id);
            let status_str = if let Some(u) = usage {
                // 必须走归一化语义（与 `is_in_cooldown` / `eligibility` 同一份），
                // 否则时钟前跳留下的伪窗口会被显示成 Cooldown，而选择器照常
                // 把账号选出去。
                if let Some(remaining) = u.cooldown_remaining(now) {
                    format!("Cooldown ({remaining}s)")
                } else if u.needs_relogin() {
                    "Relogin Required".to_string()
                } else if u.probe_channel_unreachable() {
                    // 传输层失败不是账号的问题；显示成裸的 TransientFailure 会让
                    // 用户以为凭据坏了，而这些账号其实仍然可以被选中启动。
                    probe_unreachable = true;
                    PROBE_UNREACHABLE_STATUS.to_string()
                } else {
                    u.health.to_string()
                }
            } else {
                // 缺少探测记录不是成功证据；UI 必须与 eligibility 的 fail-closed
                // 语义一致，避免把尚未验证的凭据展示成 Ready。
                "Unverified".to_string()
            };

            let quota_str = usage
                .and_then(|u| u.remaining_quota_percent)
                .map(|q| format!("{q}%"))
                .unwrap_or_else(|| "-".to_string());

            let last_used_str = account
                .last_used_at
                .map(|ts| {
                    if let Some(dt) = Local.timestamp_opt(ts, 0).single() {
                        dt.format("%Y-%m-%d %H:%M").to_string()
                    } else {
                        "-".to_string()
                    }
                })
                .unwrap_or_else(|| "Never".to_string());

            rows.push(vec![
                active_str.to_string(),
                email_str.to_string(),
                type_str.to_string(),
                plan_str.to_string(),
                status_str,
                quota_str,
                last_used_str,
            ]);
        }

        // Calculate column widths
        let mut col_widths = vec![0usize; headers.len()];
        for (i, h) in headers.iter().enumerate() {
            col_widths[i] = UnicodeWidthStr::width(*h);
        }
        for row in &rows {
            for (i, cell) in row.iter().enumerate() {
                let w = UnicodeWidthStr::width(cell.as_str());
                if w > col_widths[i] {
                    col_widths[i] = w;
                }
            }
        }

        let mut output = String::new();

        // Print header
        for (i, h) in headers.iter().enumerate() {
            let pad = col_widths[i] - UnicodeWidthStr::width(*h);
            output.push_str(h);
            output.push_str(&" ".repeat(pad + 2));
        }
        output.push('\n');

        // Print separator
        for (i, _) in headers.iter().enumerate() {
            output.push_str(&"-".repeat(col_widths[i]));
            output.push_str("  ");
        }
        output.push('\n');

        // Print rows
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                let pad = col_widths[i] - UnicodeWidthStr::width(cell.as_str());
                output.push_str(cell);
                output.push_str(&" ".repeat(pad + 2));
            }
            output.push('\n');
        }

        if probe_unreachable {
            output.push('\n');
            output.push_str(PROBE_UNREACHABLE_NOTE);
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::health::{Cooldown, HealthErrorKind};
    use crate::core::state::{AccountRecord, AccountType, HealthStatus, UsageSnapshot};

    fn state_with(health: HealthStatus, last_error: Option<HealthErrorKind>) -> State {
        let mut state = State {
            accounts: vec![AccountRecord {
                id: "acc".to_string(),
                email: "user@example.test".to_string(),
                account_type: AccountType::ApiKey,
                ..Default::default()
            }],
            ..Default::default()
        };
        state.usage_cache.insert(
            "acc".to_string(),
            UsageSnapshot {
                health,
                last_error,
                last_probe_at: Some(1_000),
                ..Default::default()
            },
        );
        state
    }

    /// AC-1.4：探测通道不可达时，表格必须说明真实原因而不是让用户去 `sagy add`。
    #[test]
    fn probe_outage_is_explained_and_never_reported_as_a_plain_failure() {
        let rendered = super::super::AntigravityAdapter.render_account_table(
            &state_with(
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Network),
            ),
            None,
        );
        assert!(rendered.contains("probe unreachable"), "{rendered}");
        assert!(rendered.contains("probe"), "{rendered}");
        assert!(rendered.contains("cached"), "{rendered}");
        assert!(rendered.is_ascii(), "{rendered}");

        let healthy = super::super::AntigravityAdapter
            .render_account_table(&state_with(HealthStatus::Ready, None), None);
        assert!(!healthy.contains("probe"), "{healthy}");
    }

    /// AC-2.2：400 归类后的凭据无效状态必须显示成需要用户处理。
    #[test]
    fn invalid_credential_is_reported_as_relogin_required() {
        let rendered = super::super::AntigravityAdapter.render_account_table(
            &state_with(
                HealthStatus::InvalidCredential,
                Some(HealthErrorKind::InvalidCredential),
            ),
            None,
        );
        assert!(rendered.contains("Relogin Required"), "{rendered}");
        assert!(!rendered.contains("probe"), "{rendered}");
    }

    /// AC-R6-5.1：Cooldown 列必须与 `is_in_cooldown` / `eligibility` 读同一份
    /// 归一化结果。时钟前跳留下的伪窗口不是限流证据：账号照常可以被选中，
    /// 表格就不能把它显示成 Cooldown。
    #[test]
    fn cooldown_column_uses_the_same_normalized_semantics_as_selection() {
        let now = Utc::now().timestamp();
        let skewed = Cooldown {
            started_at: now + 5_000,
            until: now + 6_000,
            last_evidence_at: now + 5_000,
        };
        let mut state = state_with(HealthStatus::Ready, None);
        let usage = state.usage_cache.get_mut("acc").expect("seeded usage");
        usage.cooldown = Some(skewed);
        let snapshot = usage.clone();

        assert!(
            !snapshot.is_in_cooldown(now),
            "a future-skewed window is not cooldown evidence"
        );
        let rendered = super::super::AntigravityAdapter.render_account_table(&state, None);
        assert!(
            !rendered.contains("Cooldown"),
            "the table must not invent a cooldown the selector ignores: {rendered}"
        );
        assert!(rendered.contains("Ready"), "{rendered}");

        // 真正生效的窗口仍然要显示出来。
        let active = Cooldown {
            started_at: now - 10,
            until: now + 120,
            last_evidence_at: now - 10,
        };
        state
            .usage_cache
            .get_mut("acc")
            .expect("seeded usage")
            .cooldown = Some(active);
        let rendered = super::super::AntigravityAdapter.render_account_table(&state, None);
        assert!(rendered.contains("Cooldown ("), "{rendered}");
    }
}
