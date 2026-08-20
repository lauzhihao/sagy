use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

use crate::core::state::{
    AccountRecord, AccountType, DEFAULT_COOLDOWN_SECONDS, State, UsageSnapshot,
};

pub const PROBE_TTL_SECS: i64 = 300;
pub const PROBE_TIMEOUT_SECS: u64 = 3;

impl super::AntigravityAdapter {
    pub fn refresh_account_usage(
        &self,
        _state_dir: &Path,
        state: &mut State,
        account: &AccountRecord,
        force: bool,
    ) -> UsageSnapshot {
        let now = Utc::now().timestamp();
        let current_usage = state.usage_cache.get(&account.id).cloned();

        let mut usage = current_usage.unwrap_or_else(|| UsageSnapshot {
            plan: account.plan.clone(),
            status: "Ready".to_string(),
            cooldown_until: None,
            remaining_quota_percent: Some(100),
            last_synced_at: None,
            last_sync_error: None,
            needs_relogin: false,
        });

        // 1. If currently in cooldown, check if cooldown window has passed
        let in_cooldown = if let Some(cooldown) = usage.cooldown_until {
            if now >= cooldown {
                usage.cooldown_until = None;
                usage.status = "Ready".to_string();
                false
            } else {
                true
            }
        } else {
            false
        };

        // 2. Check if cache is still valid
        let is_cached = !force
            && !in_cooldown
            && usage
                .last_synced_at
                .map(|t| now - t < PROBE_TTL_SECS)
                .unwrap_or(false);

        if !is_cached {
            probe_account(account, &mut usage, now);
            usage.last_synced_at = Some(now);
        }

        state.usage_cache.insert(account.id.clone(), usage.clone());
        usage
    }

    pub fn refresh_all_accounts(&self, _state_dir: &Path, state: &mut State, force: bool) {
        let now = Utc::now().timestamp();
        let accounts = state.accounts.clone();
        let existing_usage = state.usage_cache.clone();

        let results: Vec<(String, UsageSnapshot)> = std::thread::scope(|s| {
            let mut handles = Vec::new();
            for account in &accounts {
                let current = existing_usage.get(&account.id).cloned();
                handles.push(s.spawn(move || {
                    let mut usage = current.unwrap_or_else(|| UsageSnapshot {
                        plan: account.plan.clone(),
                        status: "Ready".to_string(),
                        cooldown_until: None,
                        remaining_quota_percent: Some(100),
                        last_synced_at: None,
                        last_sync_error: None,
                        needs_relogin: false,
                    });

                    let in_cooldown = if let Some(cooldown) = usage.cooldown_until {
                        if now >= cooldown {
                            usage.cooldown_until = None;
                            usage.status = "Ready".to_string();
                            false
                        } else {
                            true
                        }
                    } else {
                        false
                    };

                    let is_cached = !force
                        && !in_cooldown
                        && usage
                            .last_synced_at
                            .map(|t| now - t < PROBE_TTL_SECS)
                            .unwrap_or(false);

                    if !is_cached {
                        probe_account(account, &mut usage, now);
                        usage.last_synced_at = Some(now);
                    }

                    (account.id.clone(), usage)
                }));
            }

            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        for (id, usage) in results {
            state.usage_cache.insert(id, usage);
        }
    }

    pub fn mark_rate_limited(&self, state: &mut State, account_id: &str) {
        let now = Utc::now().timestamp();
        let cooldown_until = now + DEFAULT_COOLDOWN_SECONDS;

        if let Some(usage) = state.usage_cache.get_mut(account_id) {
            usage.status = "RateLimited".to_string();
            usage.cooldown_until = Some(cooldown_until);
            usage.remaining_quota_percent = Some(0);
            usage.last_sync_error = Some("Rate limit 429 detected during execution".to_string());
            usage.last_synced_at = Some(now);
        }
    }

    pub fn mark_needs_relogin(&self, state: &mut State, account_id: &str, error_msg: &str) {
        let now = Utc::now().timestamp();
        if let Some(usage) = state.usage_cache.get_mut(account_id) {
            usage.status = "AuthError".to_string();
            usage.needs_relogin = true;
            usage.remaining_quota_percent = Some(0);
            usage.last_sync_error = Some(error_msg.to_string());
            usage.last_synced_at = Some(now);
        }
    }
}

fn probe_account(account: &AccountRecord, usage: &mut UsageSnapshot, now: i64) {
    let client = match Client::builder()
        .timeout(Duration::from_secs(PROBE_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    match account.account_type {
        AccountType::ApiKey => {
            if let Some(key) = &account.api_key {
                let url = "https://generativelanguage.googleapis.com/v1beta/models";
                match client.get(url).header("x-goog-api-key", key.trim()).send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() {
                            usage.status = "Ready".to_string();
                            usage.needs_relogin = false;
                            usage.remaining_quota_percent = Some(100);
                            usage.last_sync_error = None;
                        } else if status.as_u16() == 429 {
                            usage.status = "RateLimited".to_string();
                            usage.needs_relogin = false;
                            usage.cooldown_until = Some(now + DEFAULT_COOLDOWN_SECONDS);
                            usage.remaining_quota_percent = Some(0);
                            usage.last_sync_error =
                                Some("Rate limit exceeded (HTTP 429)".to_string());
                        } else if status.as_u16() == 400
                            || status.as_u16() == 401
                            || status.as_u16() == 403
                        {
                            usage.status = "InvalidKey".to_string();
                            usage.needs_relogin = true;
                            usage.remaining_quota_percent = Some(0);
                            usage.last_sync_error =
                                Some(format!("Invalid API key (HTTP {})", status.as_u16()));
                        } else {
                            usage.last_sync_error = Some(format!("Probe HTTP {}", status.as_u16()));
                        }
                    }
                    Err(e) => {
                        // Network error during probe: do not invalidate key, just record error without secrets
                        usage.last_sync_error = Some(format!("Network probe error: {e}"));
                    }
                }
            }
        }
        AccountType::OAuth => {
            let has_refresh_material =
                account.refresh_token.is_some() || account.auth_path.ends_with(".json");

            if let Some(token) = &account.oauth_token {
                let trimmed = token.trim();
                if trimmed.starts_with("ya29.") {
                    // Google OAuth access token
                    let url = "https://www.googleapis.com/oauth2/v3/tokeninfo";
                    match client
                        .get(url)
                        .header("Authorization", format!("Bearer {trimmed}"))
                        .send()
                    {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.is_success() {
                                usage.status = "Ready".to_string();
                                usage.needs_relogin = false;
                                usage.remaining_quota_percent = Some(100);
                                usage.last_sync_error = None;
                            } else if status.as_u16() == 429 {
                                usage.status = "RateLimited".to_string();
                                usage.needs_relogin = false;
                                usage.cooldown_until = Some(now + DEFAULT_COOLDOWN_SECONDS);
                                usage.remaining_quota_percent = Some(0);
                                usage.last_sync_error =
                                    Some("Rate limit exceeded (HTTP 429)".to_string());
                            } else if status.as_u16() == 400 || status.as_u16() == 401 {
                                if has_refresh_material {
                                    usage.status = "Stale".to_string();
                                    usage.needs_relogin = false;
                                    usage.remaining_quota_percent = Some(50);
                                    usage.last_sync_error = Some(
                                        "OAuth access token stale (can be refreshed by agy)"
                                            .to_string(),
                                    );
                                } else {
                                    usage.status = "Expired".to_string();
                                    usage.needs_relogin = true;
                                    usage.remaining_quota_percent = Some(0);
                                    usage.last_sync_error =
                                        Some("OAuth access token expired or revoked".to_string());
                                }
                            } else {
                                usage.last_sync_error =
                                    Some(format!("Probe HTTP {}", status.as_u16()));
                            }
                        }
                        Err(e) => {
                            usage.last_sync_error = Some(format!("Token probe error: {e}"));
                        }
                    }
                } else if trimmed.contains('.') {
                    // Possible JWT token (header.payload.signature)
                    if let Some(exp) = extract_jwt_exp(trimmed) {
                        if now >= exp {
                            if has_refresh_material {
                                usage.status = "Stale".to_string();
                                usage.needs_relogin = false;
                                usage.remaining_quota_percent = Some(50);
                                usage.last_sync_error = Some(
                                    "Antigravity OAuth JWT expired (can be refreshed by agy)"
                                        .to_string(),
                                );
                            } else {
                                usage.status = "Expired".to_string();
                                usage.needs_relogin = true;
                                usage.remaining_quota_percent = Some(0);
                                usage.last_sync_error =
                                    Some("Antigravity OAuth JWT token expired".to_string());
                            }
                        } else {
                            usage.status = "Ready".to_string();
                            usage.needs_relogin = false;
                            usage.remaining_quota_percent = Some(100);
                            usage.last_sync_error = None;
                        }
                    }
                }
            } else if has_refresh_material {
                // Account only has refresh_token (e.g. from oauth_creds.json)
                usage.status = "Stale".to_string();
                usage.needs_relogin = false;
                usage.remaining_quota_percent = Some(50);
                usage.last_sync_error = None;
            }
        }
        AccountType::Vertex => {}
    }
}

fn extract_jwt_exp(jwt: &str) -> Option<i64> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let payload_b64 = parts[1];
    // Pad if necessary
    let padded = match payload_b64.len() % 4 {
        2 => format!("{payload_b64}=="),
        3 => format!("{payload_b64}="),
        _ => payload_b64.to_string(),
    };

    let decoded = URL_SAFE_NO_PAD
        .decode(padded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()))
        .ok()?;

    let json: Value = serde_json::from_slice(&decoded).ok()?;
    json.get("exp").and_then(Value::as_i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_jwt_exp() {
        let fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODcxOTk5OTksImVtYWlsIjoidGVzdEBnb29nbGUuY29tIn0.fake_signature";
        let exp = extract_jwt_exp(fake_jwt);
        assert_eq!(exp, Some(1787199999));

        let invalid_jwt = "invalid_jwt_format";
        assert_eq!(extract_jwt_exp(invalid_jwt), None);
    }

    #[test]
    fn test_mark_rate_limited_and_relogin() {
        let mut state = State::default();
        let acc_id = "test-acc-usage";
        state.usage_cache.insert(
            acc_id.to_string(),
            UsageSnapshot {
                status: "Ready".to_string(),
                ..Default::default()
            },
        );

        let adapter = super::super::AntigravityAdapter;
        adapter.mark_rate_limited(&mut state, acc_id);
        let usage = state.usage_cache.get(acc_id).unwrap();
        assert_eq!(usage.status, "RateLimited");
        assert!(usage.cooldown_until.is_some());

        adapter.mark_needs_relogin(&mut state, acc_id, "Auth error 401");
        let usage_relogin = state.usage_cache.get(acc_id).unwrap();
        assert_eq!(usage_relogin.status, "AuthError");
        assert!(usage_relogin.needs_relogin);
    }
}
