use std::path::Path;
use chrono::Utc;

use crate::core::state::{AccountRecord, DEFAULT_COOLDOWN_SECONDS, State, UsageSnapshot};

impl super::AntigravityAdapter {
    pub fn refresh_account_usage(
        &self,
        _state_dir: &Path,
        state: &mut State,
        account: &AccountRecord,
    ) -> UsageSnapshot {
        let now = Utc::now().timestamp();
        let current_usage = state.usage_cache.get(&account.id).cloned();

        let mut usage = current_usage.unwrap_or_else(|| UsageSnapshot {
            plan: account.plan.clone(),
            status: "Ready".to_string(),
            cooldown_until: None,
            remaining_quota_percent: Some(100),
            last_synced_at: Some(now),
            last_sync_error: None,
            needs_relogin: false,
        });

        // Check if cooldown has expired
        if let Some(cooldown) = usage.cooldown_until {
            if now >= cooldown {
                usage.cooldown_until = None;
                usage.status = "Ready".to_string();
            }
        }

        usage.last_synced_at = Some(now);
        state.usage_cache.insert(account.id.clone(), usage.clone());
        usage
    }

    pub fn refresh_all_accounts(&self, state_dir: &Path, state: &mut State) {
        let accounts = state.accounts.clone();
        for account in accounts {
            self.refresh_account_usage(state_dir, state, &account);
        }
    }

    pub fn mark_rate_limited(&self, state: &mut State, account_id: &str) {
        let now = Utc::now().timestamp();
        let cooldown_until = now + DEFAULT_COOLDOWN_SECONDS;

        if let Some(usage) = state.usage_cache.get_mut(account_id) {
            usage.status = "RateLimited".to_string();
            usage.cooldown_until = Some(cooldown_until);
            usage.last_synced_at = Some(now);
        }
    }
}
