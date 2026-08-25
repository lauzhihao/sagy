//! Runtime account state and the schema metadata used by `StateStore`.
//!
//! `AccountRecord` intentionally remains a compatibility/runtime type for the
//! existing adapter.  It is not the v2 wire type: StateStore encodes v2 via a
//! private `AccountV2Wire` that never contains secrets or filesystem paths.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use super::health::{Cooldown, HealthErrorKind, HealthStatus, UsageSnapshot};

pub const STATE_VERSION: u32 = 1;
pub const STATE_V2_VERSION: u32 = 2;
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRefKind {
    OauthAccessToken,
    OauthAuthorizedUser,
    ApiKey,
    VertexServiceAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub kind: CredentialRefKind,
    pub fingerprint: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveIdentity {
    pub email: String,
    pub account_id: Option<String>,
}

/// The durable state of one credential file managed for the active profile.
///
/// `Absent` is intentionally different from an omitted field: an active
/// profile always records both fixed slots.  `Exact` carries only the
/// content digest, never a path or credential material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SlotState {
    #[default]
    Absent,
    Exact {
        sha256: String,
    },
}

/// Complete fixed credential layout for an active OAuth home.
///
/// The two fields are deliberately required.  This prevents a state reader
/// from silently treating a missing slot as absent and losing evidence about
/// the other managed file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedLayout {
    /// `~/.gemini/antigravity-cli/antigravity-oauth-token` slot.
    pub antigravity_token: SlotState,
    /// `~/.gemini/oauth_creds.json` slot.
    pub gemini_authorized_user: SlotState,
}

impl Default for ManagedLayout {
    fn default() -> Self {
        Self {
            antigravity_token: SlotState::Absent,
            gemini_authorized_user: SlotState::Absent,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActiveProfile {
    pub account_id: String,
    pub credential_fingerprint: String,
    pub home_scope_id: String,
    pub managed_layout: ManagedLayout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncWatermark {
    pub generation: u64,
    pub semantic_sha256: String,
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
    /// Runtime-only revision. StateStore owns the v2 wire revision field.
    #[serde(skip)]
    pub revision: u64,
    /// Runtime-only v2 profile metadata.
    #[serde(skip)]
    pub active_profile: Option<ActiveProfile>,
    /// Runtime-only v2 sync metadata.
    #[serde(skip)]
    pub sync_watermarks: BTreeMap<String, SyncWatermark>,
    /// Runtime-only v2 credential references keyed by account id. Keeping the
    /// map outside AccountRecord preserves the adapter's struct-literal API.
    #[serde(skip)]
    pub credential_refs: BTreeMap<String, CredentialRef>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            accounts: Vec::new(),
            usage_cache: BTreeMap::new(),
            current_account_id: None,
            revision: 0,
            active_profile: None,
            sync_watermarks: BTreeMap::new(),
            credential_refs: BTreeMap::new(),
        }
    }
}

const fn default_state_version() -> u32 {
    STATE_VERSION
}

pub(crate) fn validate_account_id(account_id: &str) -> anyhow::Result<()> {
    use anyhow::bail;
    let bytes = account_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        bail!("invalid account id: expected 1-64 ASCII characters");
    }
    let first = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let rest = |byte: u8| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
    };
    if !first(bytes[0]) || !bytes.iter().copied().skip(1).all(rest) {
        bail!("invalid account id: use [a-z0-9][a-z0-9_-]{{0,63}}");
    }
    Ok(())
}

pub(crate) fn validate_sha256(label: &str, value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
    {
        anyhow::bail!("{label} must be a lowercase SHA-256 digest");
    }
    Ok(())
}

pub(crate) fn validate_credential_fingerprint(value: &str) -> anyhow::Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("credential fingerprint must use sha256:<hex>"))?;
    validate_sha256("credential fingerprint", digest)
}

pub(crate) fn validate_state_invariants(state: &State) -> anyhow::Result<()> {
    use anyhow::bail;
    if state.version != STATE_VERSION && state.version != STATE_V2_VERSION {
        bail!("unsupported state version {}", state.version);
    }
    let mut ids = std::collections::BTreeSet::new();
    for account in &state.accounts {
        validate_account_id(&account.id)?;
        validate_text("account email", &account.email)?;
        for (label, value) in [
            ("provider id", account.provider_id.as_deref()),
            ("project id", account.project_id.as_deref()),
            ("provider account id", account.account_id.as_deref()),
            ("plan", account.plan.as_deref()),
        ] {
            if let Some(value) = value {
                validate_text(label, value)?;
            }
        }
        if !ids.insert(account.id.as_str()) {
            bail!("state contains duplicate account ids");
        }
        if state.version == STATE_V2_VERSION && !state.credential_refs.contains_key(&account.id) {
            bail!("v2 account is missing credential_ref");
        }
        if let Some(reference) = state.credential_refs.get(&account.id) {
            validate_credential_fingerprint(&reference.fingerprint)?;
            let compatible = match account.account_type {
                AccountType::OAuth => matches!(
                    reference.kind,
                    CredentialRefKind::OauthAccessToken | CredentialRefKind::OauthAuthorizedUser
                ),
                AccountType::ApiKey => matches!(reference.kind, CredentialRefKind::ApiKey),
                AccountType::Vertex => {
                    matches!(reference.kind, CredentialRefKind::VertexServiceAccount)
                }
            };
            if !compatible {
                bail!("credential_ref kind does not match account type");
            }
        }
    }
    if state.version == STATE_V2_VERSION
        && state
            .credential_refs
            .keys()
            .any(|account_id| !ids.contains(account_id.as_str()))
    {
        bail!("v2 credential_refs contains an unknown account id");
    }
    if let Some(current) = state.current_account_id.as_deref() {
        validate_account_id(current)?;
        if !ids.contains(current) {
            bail!("state current account does not exist");
        }
    }
    if state.version == STATE_V2_VERSION {
        match (
            state.current_account_id.as_deref(),
            state.active_profile.as_ref(),
        ) {
            (None, None) | (Some(_), Some(_)) => {}
            (Some(_), None) => {
                bail!("v2 current_account_id requires active_profile");
            }
            (None, Some(_)) => {
                bail!("v2 active_profile requires current_account_id");
            }
        }
    }
    for id in state.usage_cache.keys() {
        validate_account_id(id)?;
        if !ids.contains(id.as_str()) {
            bail!("state usage cache refers to a missing account");
        }
    }
    for usage in state.usage_cache.values() {
        validate_usage_snapshot(usage)?;
    }
    if let Some(profile) = &state.active_profile {
        if state.version != STATE_V2_VERSION {
            bail!("active_profile is only valid in v2 state");
        }
        validate_account_id(&profile.account_id)?;
        if state.current_account_id.as_deref() != Some(profile.account_id.as_str()) {
            bail!("active profile and current account differ");
        }
        let account = state
            .accounts
            .iter()
            .find(|account| account.id == profile.account_id)
            .ok_or_else(|| anyhow::anyhow!("active profile refers to a missing account"))?;
        let reference = state
            .credential_refs
            .get(&account.id)
            .ok_or_else(|| anyhow::anyhow!("active profile account has no credential_ref"))?;
        if reference.fingerprint != profile.credential_fingerprint {
            bail!("active profile credential fingerprint differs from account");
        }
        validate_sha256("active profile home_scope_id", &profile.home_scope_id)?;
        validate_managed_layout(
            account.account_type,
            reference.kind,
            &profile.managed_layout,
        )?;
    }
    for (pool_id, watermark) in &state.sync_watermarks {
        let parsed = uuid::Uuid::parse_str(pool_id)
            .map_err(|error| anyhow::anyhow!(error).context("invalid sync pool id"))?;
        if parsed.to_string() != *pool_id {
            bail!("sync pool id must use canonical UUID spelling");
        }
        validate_sha256("sync semantic sha256", &watermark.semantic_sha256)?;
    }
    Ok(())
}

fn validate_usage_snapshot(usage: &UsageSnapshot) -> anyhow::Result<()> {
    use anyhow::bail;
    if usage
        .remaining_quota_percent
        .is_some_and(|value| value > 100)
    {
        bail!("remaining quota percentage must be between 0 and 100");
    }
    match usage.health {
        HealthStatus::Unverified | HealthStatus::TransientFailure => {
            if usage.remaining_quota_percent.is_some() {
                bail!("unverified/transient usage cannot carry a quota claim");
            }
        }
        HealthStatus::AuthInvalid
        | HealthStatus::PermissionDenied
        | HealthStatus::InvalidCredential => {
            if usage.remaining_quota_percent.is_some() {
                bail!("invalid credential usage cannot carry a quota claim");
            }
        }
        HealthStatus::RateLimited => {
            if usage
                .remaining_quota_percent
                .is_some_and(|remaining| remaining != 0)
            {
                bail!("rate-limited usage cannot carry a positive quota claim");
            }
        }
        HealthStatus::Ready | HealthStatus::RefreshRequired => {}
    }
    if usage.cooldown.is_some() && !matches!(usage.health, HealthStatus::RateLimited) {
        bail!("cooldown is only valid for rate-limited usage");
    }
    Ok(())
}

fn validate_managed_layout(
    account_type: AccountType,
    credential_kind: CredentialRefKind,
    layout: &ManagedLayout,
) -> anyhow::Result<()> {
    use anyhow::bail;

    validate_slot_state("managed antigravity_token", &layout.antigravity_token)?;
    validate_slot_state(
        "managed gemini_authorized_user",
        &layout.gemini_authorized_user,
    )?;

    match account_type {
        AccountType::ApiKey | AccountType::Vertex => {
            if !matches!(layout.antigravity_token, SlotState::Absent)
                || !matches!(layout.gemini_authorized_user, SlotState::Absent)
            {
                bail!("API and Vertex active profiles require both managed slots absent");
            }
        }
        AccountType::OAuth => match credential_kind {
            CredentialRefKind::OauthAccessToken => {
                if !matches!(layout.antigravity_token, SlotState::Exact { .. })
                    || !matches!(layout.gemini_authorized_user, SlotState::Absent)
                {
                    bail!(
                        "OAuth access-token profile requires token exact and authorized_user absent"
                    );
                }
            }
            CredentialRefKind::OauthAuthorizedUser => {
                if !matches!(layout.antigravity_token, SlotState::Absent)
                    || !matches!(layout.gemini_authorized_user, SlotState::Exact { .. })
                {
                    bail!(
                        "OAuth authorized-user profile requires token absent and authorized_user exact"
                    );
                }
            }
            _ => bail!("OAuth active profile has an incompatible credential_ref kind"),
        },
    }
    Ok(())
}

fn validate_slot_state(label: &str, slot: &SlotState) -> anyhow::Result<()> {
    if let SlotState::Exact { sha256 } = slot {
        validate_sha256(&format!("{label} sha256"), sha256)?;
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> anyhow::Result<()> {
    if value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        anyhow::bail!("{label} is too long or contains a control character");
    }
    Ok(())
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
        let deserialized: AccountType = serde_json::from_str("\"o_auth\"").unwrap();
        assert_eq!(deserialized, AccountType::OAuth);
        let api_key_type = AccountType::ApiKey;
        assert_eq!(api_key_type.as_str(), "api_key");
    }
}
