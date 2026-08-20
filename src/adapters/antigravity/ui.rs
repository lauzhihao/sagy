use chrono::{Local, TimeZone, Utc};
use unicode_width::UnicodeWidthStr;

use crate::core::state::{LiveIdentity, State};

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
                if let Some(cooldown) = u.cooldown_until {
                    if now < cooldown {
                        format!("Cooldown ({}s)", cooldown - now)
                    } else {
                        u.status.clone()
                    }
                } else if u.needs_relogin {
                    "Relogin Required".to_string()
                } else {
                    u.status.clone()
                }
            } else {
                "Ready".to_string()
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

        output
    }
}
