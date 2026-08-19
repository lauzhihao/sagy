#![allow(dead_code)]

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

pub const STATE_VERSION: u32 = 1;
pub const DEFAULT_COOLDOWN_SECONDS: i64 = 300; // 5 minutes cooldown after 429

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AccountType {
    #[default]
    OAuth,
    ApiKey,
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

    pub fn is_api_key(&self) -> bool {
        matches!(self.account_type, AccountType::ApiKey)
    }

    pub fn is_vertex(&self) -> bool {
        matches!(self.account_type, AccountType::Vertex)
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

    pub fn is_in_cooldown(&self, now: i64) -> bool {
        self.cooldown_until.map(|until| now < until).unwrap_or(false)
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
