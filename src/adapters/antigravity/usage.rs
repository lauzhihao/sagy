use std::path::Path;
use std::time::Duration;
use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::Value;

use crate::core::state::{AccountRecord, AccountType, DEFAULT_COOLDOWN_SECONDS, State, UsageSnapshot};

const PROBE_TIMEOUT_SECS: u64 = 5;

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

        // 1. If currently in cooldown, check if cooldown window has passed
        if let Some(cooldown) = usage.cooldown_until {
            if now >= cooldown {
                usage.cooldown_until = None;
                usage.status = "Ready".to_string();
            }
        }

        // 2. Perform live network health check / probe
        probe_account(account, &mut usage, now);

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
                let url = format!(
                    "https://generativelanguage.googleapis.com/v1beta/models?key={}",
                    key.trim()
                );
                match client.get(&url).send() {
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
                            usage.last_sync_error = Some("Rate limit exceeded (HTTP 429)".to_string());
                        } else if status.as_u16() == 400 || status.as_u16() == 401 || status.as_u16() == 403 {
                            usage.status = "InvalidKey".to_string();
                            usage.needs_relogin = true;
                            usage.remaining_quota_percent = Some(0);
                            usage.last_sync_error = Some(format!("Invalid API key (HTTP {})", status.as_u16()));
                        } else {
                            usage.last_sync_error = Some(format!("Probe HTTP {}", status.as_u16()));
                        }
                    }
                    Err(e) => {
                        // Network error during probe: do not invalidate key, just record error
                        usage.last_sync_error = Some(format!("Network probe error: {e}"));
                    }
                }
            }
        }
        AccountType::OAuth => {
            if let Some(token) = &account.oauth_token {
                let trimmed = token.trim();
                if trimmed.starts_with("ya29.") {
                    // Google OAuth access token
                    let url = format!(
                        "https://oauth2.googleapis.com/tokeninfo?access_token={}",
                        trimmed
                    );
                    match client.get(&url).send() {
                        Ok(resp) => {
                            let status = resp.status();
                            if status.is_success() {
                                usage.status = "Ready".to_string();
                                usage.needs_relogin = false;
                                usage.remaining_quota_percent = Some(100);
                                usage.last_sync_error = None;
                            } else if status.as_u16() == 400 || status.as_u16() == 401 {
                                usage.status = "Expired".to_string();
                                usage.needs_relogin = true;
                                usage.remaining_quota_percent = Some(0);
                                usage.last_sync_error = Some("OAuth access token expired or revoked".to_string());
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
                            usage.status = "Expired".to_string();
                            usage.needs_relogin = true;
                            usage.remaining_quota_percent = Some(0);
                            usage.last_sync_error = Some("Antigravity OAuth JWT token expired".to_string());
                        } else {
                            usage.status = "Ready".to_string();
                            usage.needs_relogin = false;
                            usage.remaining_quota_percent = Some(100);
                            usage.last_sync_error = None;
                        }
                    }
                }
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

    let decoded = URL_SAFE_NO_PAD.decode(padded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()))
        .ok()?;

    let json: Value = serde_json::from_slice(&decoded).ok()?;
    json.get("exp").and_then(Value::as_i64)
}
