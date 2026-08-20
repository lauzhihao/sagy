use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATE_VERSION: u32 = 1;
pub const DEFAULT_COOLDOWN_SECONDS: i64 = 300; // 5 minutes cooldown after 429

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AccountType {
    #[default]
    #[serde(rename = "oauth", alias = "o_auth")]
    OAuth,
    #[serde(rename = "api_key")]
    ApiKey,
    #[serde(rename = "vertex")]
    Vertex,
}

impl AccountType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ApiKey => "api_key",
            Self::Vertex => "vertex",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccountRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub account_type: AccountType,
    #[serde(default)]
    pub provider_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub identity_fingerprint: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub auth_path: String,
    #[serde(default)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub oauth_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub added_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub last_used_at: Option<i64>,
}

impl AccountRecord {
    pub fn is_oauth(&self) -> bool {
        matches!(self.account_type, AccountType::OAuth)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UsageSnapshot {
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub cooldown_until: Option<i64>,
    #[serde(default)]
    pub remaining_quota_percent: Option<i64>,
    #[serde(default)]
    pub last_synced_at: Option<i64>,
    #[serde(default)]
    pub last_sync_error: Option<String>,
    #[serde(default)]
    pub needs_relogin: bool,
}

impl UsageSnapshot {
    pub fn is_healthy(&self, now: i64) -> bool {
        if self.needs_relogin {
            return false;
        }
        if let Some(cooldown) = self.cooldown_until {
            if now < cooldown {
                return false;
            }
        }
        if let Some(remaining) = self.remaining_quota_percent {
            if remaining <= 0 {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveIdentity {
    pub email: String,
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct State {
    #[serde(default = "default_state_version")]
    pub version: u32,
    #[serde(default)]
    pub accounts: Vec<AccountRecord>,
    #[serde(default)]
    pub usage_cache: BTreeMap<String, UsageSnapshot>,
    #[serde(default)]
    pub current_account_id: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            accounts: Vec::new(),
            usage_cache: BTreeMap::new(),
            current_account_id: None,
        }
    }
}

const fn default_state_version() -> u32 {
    STATE_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_type_serde_consistency() {
        let oauth_type = AccountType::OAuth;
        assert_eq!(oauth_type.as_str(), "oauth");
        let serialized = serde_json::to_string(&oauth_type).unwrap();
        assert_eq!(serialized, "\"oauth\"");

        // Test backward-compatible alias "o_auth"
        let deserialized: AccountType = serde_json::from_str("\"o_auth\"").unwrap();
        assert_eq!(deserialized, AccountType::OAuth);

        let api_key_type = AccountType::ApiKey;
        assert_eq!(api_key_type.as_str(), "api_key");
        let serialized_api = serde_json::to_string(&api_key_type).unwrap();
        assert_eq!(serialized_api, "\"api_key\"");
        let deserialized_api: AccountType = serde_json::from_str(&serialized_api).unwrap();
        assert_eq!(deserialized_api, AccountType::ApiKey);
    }

    #[test]
    fn test_usage_snapshot_health() {
        let now = 1000;
        let healthy = UsageSnapshot {
            status: "Ready".to_string(),
            cooldown_until: None,
            needs_relogin: false,
            ..Default::default()
        };
        assert!(healthy.is_healthy(now));

        let cooldown = UsageSnapshot {
            status: "RateLimited".to_string(),
            cooldown_until: Some(2000),
            needs_relogin: false,
            ..Default::default()
        };
        assert!(!cooldown.is_healthy(now));

        let relogin = UsageSnapshot {
            status: "AuthError".to_string(),
            needs_relogin: true,
            ..Default::default()
        };
        assert!(!relogin.is_healthy(now));
    }
}
