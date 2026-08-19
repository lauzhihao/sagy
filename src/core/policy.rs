use std::cmp::Ordering;
use chrono::Utc;

use crate::core::state::{AccountRecord, State, UsageSnapshot};

pub fn select_best_account<'a>(
    state: &'a State,
    accounts: &'a [AccountRecord],
) -> Option<(&'a AccountRecord, UsageSnapshot)> {
    if accounts.is_empty() {
        return None;
    }

    let now = Utc::now().timestamp();

    // 1. Stickiness check: If current account is still healthy, keep it
    if let Some(current_id) = &state.current_account_id {
        if let Some(current_account) = accounts.iter().find(|a| &a.id == current_id) {
            let usage = state
                .usage_cache
                .get(&current_account.id)
                .cloned()
                .unwrap_or_default();

            if usage.is_healthy(now) {
                return Some((current_account, usage));
            }
        }
    }

    // 2. Score all candidate accounts
    let mut candidates: Vec<(&'a AccountRecord, UsageSnapshot, f64)> = accounts
        .iter()
        .map(|account| {
            let usage = state
                .usage_cache
                .get(&account.id)
                .cloned()
                .unwrap_or_default();
            let score = score_account(account, &usage, now);
            (account, usage, score)
        })
        .collect();

    // Sort descending by score
    candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal));

    candidates.first().map(|(acc, usage, _)| (*acc, usage.clone()))
}

fn score_account(account: &AccountRecord, usage: &UsageSnapshot, now: i64) -> f64 {
    let mut score = 1000.0;

    // Hard penalty for requiring re-login
    if usage.needs_relogin {
        return -10000.0;
    }

    // Cooldown penalty
    if let Some(cooldown) = usage.cooldown_until {
        if now < cooldown {
            let remaining_seconds = (cooldown - now) as f64;
            // Negative score proportional to remaining cooldown
            return -5000.0 - remaining_seconds;
        }
    }

    // Quota percentage bonus
    if let Some(remaining) = usage.remaining_quota_percent {
        score += (remaining as f64) * 5.0;
    } else {
        // Unknown quota gets a neutral median bonus
        score += 250.0;
    }

    // Account type preferences
    if account.is_oauth() {
        score += 50.0;
    }

    // Plan preferences (Pro / Paid plans have higher priority)
    if let Some(plan) = &account.plan {
        let plan_lower = plan.to_ascii_lowercase();
        if plan_lower.contains("pro") || plan_lower.contains("advanced") || plan_lower.contains("ultra") {
            score += 100.0;
        }
    }

    // Recency / freshness bonus (slight preference for recently used healthy accounts)
    if let Some(last_used) = account.last_used_at {
        let age_hours = ((now - last_used) as f64) / 3600.0;
        if age_hours < 24.0 {
            score += 10.0;
        }
    }

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state::AccountType;

    #[test]
    fn test_select_best_account_healthy_current() {
        let mut state = State::default();
        let acc1 = AccountRecord {
            id: "acc-1".to_string(),
            email: "user1@gmail.com".to_string(),
            account_type: AccountType::OAuth,
            plan: Some("Pro".to_string()),
            ..Default::default()
        };
        let acc2 = AccountRecord {
            id: "acc-2".to_string(),
            email: "user2@gmail.com".to_string(),
            account_type: AccountType::OAuth,
            plan: Some("Free".to_string()),
            ..Default::default()
        };
        state.accounts = vec![acc1.clone(), acc2.clone()];
        state.current_account_id = Some("acc-1".to_string());
        state.usage_cache.insert(
            "acc-1".to_string(),
            UsageSnapshot {
                status: "Ready".to_string(),
                remaining_quota_percent: Some(90),
                ..Default::default()
            },
        );

        let selected = select_best_account(&state, &state.accounts);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().0.id, "acc-1");
    }

    #[test]
    fn test_select_best_account_skips_cooldown() {
        let mut state = State::default();
        let acc1 = AccountRecord {
            id: "acc-1".to_string(),
            email: "user1@gmail.com".to_string(),
            account_type: AccountType::OAuth,
            ..Default::default()
        };
        let acc2 = AccountRecord {
            id: "acc-2".to_string(),
            email: "user2@gmail.com".to_string(),
            account_type: AccountType::OAuth,
            ..Default::default()
        };
        state.accounts = vec![acc1.clone(), acc2.clone()];
        state.current_account_id = Some("acc-1".to_string());

        let now = Utc::now().timestamp();
        state.usage_cache.insert(
            "acc-1".to_string(),
            UsageSnapshot {
                status: "RateLimited".to_string(),
                cooldown_until: Some(now + 300),
                ..Default::default()
            },
        );
        state.usage_cache.insert(
            "acc-2".to_string(),
            UsageSnapshot {
                status: "Ready".to_string(),
                remaining_quota_percent: Some(100),
                ..Default::default()
            },
        );

        let selected = select_best_account(&state, &state.accounts);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().0.id, "acc-2");
    }
}

