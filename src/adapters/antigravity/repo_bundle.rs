//! Strict, path-free repository bundle v2.
//!
//! This module deliberately has no filesystem or Git responsibilities.  It
//! only defines the bounded plaintext wire value that a repository adapter may
//! encrypt, publish, or import.  Keeping this boundary independent makes it
//! possible to validate an untrusted bundle before taking any state lock.

use std::collections::{BTreeSet, HashSet};
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::core::credential::{
    CredentialKind, MAX_CREDENTIAL_FIELD_BYTES, MAX_CREDENTIAL_NESTING_DEPTH, PortableCredential,
};
use crate::core::state::{AccountType, SyncWatermark};

/// The only bundle wire version understood by this binary.
pub const BUNDLE_VERSION: u32 = 2;
/// Maximum number of accounts in one bundle.
pub const MAX_BUNDLE_ACCOUNTS: usize = 256;
/// Maximum plaintext JSON size, in bytes.
pub const MAX_BUNDLE_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
/// A single exported timestamp must be a non-negative Unix second before 2100.
/// This catches accidental millisecond values and sentinel overflows without
/// making normal clock skew a synchronization failure.
pub const MAX_BUNDLE_EXPORTED_AT: i64 = 4_102_444_800;
/// Maximum number of deletion records carried by one bundle.
///
/// Tombstones must stay bounded: an unbounded list would grow forever and
/// eventually push the plaintext past [`MAX_BUNDLE_PLAINTEXT_BYTES`].
pub const MAX_BUNDLE_TOMBSTONES: usize = 256;
/// A tombstone stops being replayed after this many seconds.
///
/// 90 days is comfortably longer than any realistic offline window for a
/// machine that still participates in the pool, and short enough that the
/// list drains on its own.
pub const BUNDLE_TOMBSTONE_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;

const MAX_BUNDLE_NESTING_DEPTH: usize = MAX_CREDENTIAL_NESTING_DEPTH + 8;
const MAX_BUNDLE_CONTAINER_ITEMS: usize = 256;
const MAX_BUNDLE_JSON_VALUES: usize = 1_000_000;

/// A non-secret account metadata record carried by a bundle.
///
/// Runtime paths and credential material intentionally have no corresponding
/// fields here.  The `credential` field on [`BundleAccount`] is the sole
/// transport for provider credential material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleAccountMetadata {
    pub email: String,
    pub account_type: AccountType,
    pub provider_id: Option<String>,
    pub project_id: Option<String>,
    pub account_id: Option<String>,
    pub identity_fingerprint: Option<String>,
    pub plan: Option<String>,
    pub added_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

impl BundleAccountMetadata {
    /// Construct metadata after checking its portable scalar fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        email: impl Into<String>,
        account_type: AccountType,
        provider_id: Option<String>,
        project_id: Option<String>,
        account_id: Option<String>,
        identity_fingerprint: Option<String>,
        plan: Option<String>,
        added_at: i64,
        updated_at: i64,
        last_used_at: Option<i64>,
    ) -> Result<Self, BundleError> {
        let metadata = Self {
            email: email.into(),
            account_type,
            provider_id,
            project_id,
            account_id,
            identity_fingerprint,
            plan,
            added_at,
            updated_at,
            last_used_at,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<(), BundleError> {
        validate_nonempty_text(&self.email, "email")?;
        for value in [
            self.provider_id.as_deref(),
            self.project_id.as_deref(),
            self.account_id.as_deref(),
            self.identity_fingerprint.as_deref(),
            self.plan.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_text(value)?;
        }
        for timestamp in [self.added_at, self.updated_at] {
            if timestamp < 0 {
                return Err(BundleError::InvalidMetadata);
            }
        }
        if self.last_used_at.is_some_and(|timestamp| timestamp < 0) {
            return Err(BundleError::InvalidMetadata);
        }
        Ok(())
    }
}

/// A bounded deletion record.
///
/// The pool carries deletions explicitly: without them a machine that already
/// holds a removed account would simply merge it back on the next pull and the
/// deletion could never propagate.  `fingerprint` pins the record to the exact
/// credential that was deleted so a later re-import under the same id is not
/// mistaken for the deleted account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleTombstone {
    pub account_id: String,
    pub fingerprint: String,
    pub deleted_at: i64,
}

impl BundleTombstone {
    /// Construct a tombstone after validating its portable scalar fields.
    pub fn new(
        account_id: impl Into<String>,
        fingerprint: impl Into<String>,
        deleted_at: i64,
    ) -> Result<Self, BundleError> {
        let tombstone = Self {
            account_id: account_id.into(),
            fingerprint: fingerprint.into(),
            deleted_at,
        };
        tombstone.validate()?;
        Ok(tombstone)
    }

    /// True when the record is still inside the replay window.
    pub fn is_live_at(&self, now: i64) -> bool {
        now.saturating_sub(self.deleted_at) <= BUNDLE_TOMBSTONE_TTL_SECONDS
    }

    fn validate(&self) -> Result<(), BundleError> {
        validate_account_id(&self.account_id).map_err(|_| BundleError::InvalidTombstone)?;
        validate_credential_fingerprint(&self.fingerprint)?;
        if !(0..=MAX_BUNDLE_EXPORTED_AT).contains(&self.deleted_at) {
            return Err(BundleError::InvalidTombstone);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BundleTombstone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let StrictValue(value) = StrictValue::deserialize(deserializer)?;
        let wire: BundleTombstoneWire = serde_json::from_value(value)
            .map_err(|_| de::Error::custom(BundleError::InvalidStructure))?;
        Self::new(wire.account_id, wire.fingerprint, wire.deleted_at).map_err(de::Error::custom)
    }
}

/// One account's path-free metadata and complete portable credential.
#[derive(Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleAccount {
    pub id: String,
    pub metadata: BundleAccountMetadata,
    pub credential: PortableCredential,
}

impl BundleAccount {
    /// Construct one account and validate the account/credential pairing.
    pub fn new(
        id: impl Into<String>,
        metadata: BundleAccountMetadata,
        credential: PortableCredential,
    ) -> Result<Self, BundleError> {
        let account = Self {
            id: id.into(),
            metadata,
            credential,
        };
        account.validate()?;
        Ok(account)
    }

    fn validate(&self) -> Result<(), BundleError> {
        validate_account_id(&self.id)?;
        self.metadata.validate()?;
        validate_credential_pair(self.metadata.account_type, &self.credential)?;
        Ok(())
    }
}

impl fmt::Debug for BundleAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleAccount")
            .field("id", &self.id)
            .field("metadata", &self.metadata)
            .field("credential", &self.credential)
            .finish()
    }
}

/// A strict version-2 account pool bundle.
///
/// The fields are public for the later repository adapter's conversion layer,
/// but every boundary method revalidates them.  Callers should prefer
/// [`BundleV2::new`] or [`BundleV2::from_json_bytes`].
#[derive(Clone, PartialEq, Serialize)]
pub struct BundleV2 {
    pub version: u32,
    pub pool_id: String,
    pub generation: u64,
    pub exported_at: i64,
    pub accounts: Vec<BundleAccount>,
    // 空 tombstone 列表必须完全不出现在 wire 上：这样没有删除记录的 bundle 与
    // 旧版本产生的字节完全一致，既不破坏已存储的 semantic 水位，也不会让旧
    // 二进制的 deny_unknown_fields 解析失败。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<BundleTombstone>,
}

impl BundleV2 {
    /// Construct and validate a bundle.  Account order is normalized by id.
    pub fn new(
        pool_id: impl Into<String>,
        generation: u64,
        exported_at: i64,
        accounts: Vec<BundleAccount>,
    ) -> Result<Self, BundleError> {
        Self::new_with_tombstones(pool_id, generation, exported_at, accounts, Vec::new())
    }

    /// Construct and validate a bundle that also carries deletion records.
    pub fn new_with_tombstones(
        pool_id: impl Into<String>,
        generation: u64,
        exported_at: i64,
        accounts: Vec<BundleAccount>,
        tombstones: Vec<BundleTombstone>,
    ) -> Result<Self, BundleError> {
        let mut bundle = Self {
            version: BUNDLE_VERSION,
            pool_id: pool_id.into(),
            generation,
            exported_at,
            accounts,
            tombstones,
        };
        bundle.validate_and_sort()?;
        Ok(bundle)
    }

    /// Parse strict UTF-8 JSON, including duplicate-key detection at every
    /// object depth, and enforce the plaintext size bound before parsing.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.len() > MAX_BUNDLE_PLAINTEXT_BYTES {
            return Err(BundleError::PlaintextTooLarge);
        }
        let StrictValue(value) =
            serde_json::from_slice::<StrictValue>(bytes).map_err(|_| BundleError::InvalidJson)?;
        Self::from_value(value)
    }

    /// Parse strict UTF-8 JSON from a string.
    pub fn from_json_str(input: &str) -> Result<Self, BundleError> {
        Self::from_json_bytes(input.as_bytes())
    }

    /// Alias used by repository adapters when decoding decrypted plaintext.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        Self::from_json_bytes(bytes)
    }

    /// Return compact canonical JSON bytes.  Accounts are sorted by id and
    /// serde_json's normal map representation emits object keys canonically.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, BundleError> {
        self.validate_and_sorted_clone()
            .and_then(|bundle| serialize_bounded(&bundle))
    }

    /// Return compact canonical JSON text.
    pub fn canonical_json_string(&self) -> Result<String, BundleError> {
        String::from_utf8(self.canonical_json_bytes()?)
            .map_err(|_| BundleError::SerializationFailed)
    }

    /// Alias used by callers that do not need to distinguish canonical JSON
    /// from the wire encoding.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        self.canonical_json_bytes()
    }

    /// Return the semantic canonical bytes used for no-op and rollback
    /// comparison.  Generation and export time are intentionally omitted;
    /// pool id remains included so two pools cannot share an accidental hash.
    pub fn semantic_bytes(&self) -> Result<Vec<u8>, BundleError> {
        let bundle = self.validate_and_sorted_clone()?;
        let semantic = SemanticBundle {
            version: BUNDLE_VERSION,
            pool_id: bundle.pool_id,
            accounts: bundle.accounts,
            tombstones: bundle.tombstones,
        };
        serialize_bounded(&semantic)
    }

    /// Return the lowercase SHA-256 digest of [`BundleV2::semantic_bytes`].
    pub fn semantic_sha256(&self) -> Result<String, BundleError> {
        Ok(format!("{:x}", Sha256::digest(self.semantic_bytes()?)))
    }

    /// Alias for [`BundleV2::semantic_sha256`].
    pub fn semantic_hash(&self) -> Result<String, BundleError> {
        self.semantic_sha256()
    }

    /// Check an incoming bundle against the watermark stored for a pool.
    ///
    /// A missing or older watermark accepts the bundle; equal generation and
    /// equal semantic hash is an idempotent no-op.  A lower incoming
    /// generation, or a same-generation hash mismatch, is rejected.
    pub fn rollback_decision(
        &self,
        stored_pool_id: &str,
        watermark: Option<&SyncWatermark>,
    ) -> Result<SyncDecision, BundleError> {
        validate_pool_id(stored_pool_id)?;
        if stored_pool_id != self.pool_id {
            return Err(BundleError::PoolIdMismatch);
        }
        let Some(watermark) = watermark else {
            return Ok(SyncDecision::Accept);
        };
        validate_semantic_sha256(&watermark.semantic_sha256)?;
        let semantic_hash = self.semantic_sha256()?;
        match watermark.generation.cmp(&self.generation) {
            std::cmp::Ordering::Greater => Err(BundleError::RollbackDetected),
            std::cmp::Ordering::Equal if watermark.semantic_sha256 == semantic_hash => {
                Ok(SyncDecision::NoOp)
            }
            std::cmp::Ordering::Equal => Err(BundleError::GenerationConflict),
            std::cmp::Ordering::Less => Ok(SyncDecision::Accept),
        }
    }

    /// Name emphasizing that the watermark is evaluated before mutation.
    pub fn check_sync_watermark(
        &self,
        stored_pool_id: &str,
        watermark: Option<&SyncWatermark>,
    ) -> Result<SyncDecision, BundleError> {
        self.rollback_decision(stored_pool_id, watermark)
    }

    /// Compatibility spelling for callers that perform an explicit rollback
    /// gate before deciding whether to publish a bundle.
    pub fn check_rollback(
        &self,
        stored_pool_id: &str,
        watermark: Option<&SyncWatermark>,
    ) -> Result<SyncDecision, BundleError> {
        self.rollback_decision(stored_pool_id, watermark)
    }

    /// Validate all fields and account invariants without changing order.
    pub fn validate(&self) -> Result<(), BundleError> {
        let mut clone = self.clone();
        clone.validate_and_sort()
    }

    pub fn pool_id(&self) -> &str {
        &self.pool_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn exported_at(&self) -> i64 {
        self.exported_at
    }

    pub fn accounts(&self) -> &[BundleAccount] {
        &self.accounts
    }

    pub fn tombstones(&self) -> &[BundleTombstone] {
        &self.tombstones
    }

    fn from_value(value: Value) -> Result<Self, BundleError> {
        let mut budget = MAX_BUNDLE_JSON_VALUES;
        validate_json_value(&value, 0, &mut budget)?;

        let wire: BundleWire =
            serde_json::from_value(value).map_err(|_| BundleError::InvalidStructure)?;
        if wire.version > BUNDLE_VERSION {
            return Err(BundleError::FutureVersion);
        }
        if wire.version != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion);
        }
        Self::new_with_tombstones(
            wire.pool_id,
            wire.generation,
            wire.exported_at,
            wire.accounts,
            wire.tombstones,
        )
    }

    fn validate_and_sorted_clone(&self) -> Result<Self, BundleError> {
        let mut clone = self.clone();
        clone.validate_and_sort()?;
        Ok(clone)
    }

    fn validate_and_sort(&mut self) -> Result<(), BundleError> {
        if self.version > BUNDLE_VERSION {
            return Err(BundleError::FutureVersion);
        }
        if self.version != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion);
        }
        validate_pool_id(&self.pool_id)?;
        if self.generation == 0 {
            return Err(BundleError::InvalidGeneration);
        }
        if !(0..=MAX_BUNDLE_EXPORTED_AT).contains(&self.exported_at) {
            return Err(BundleError::InvalidExportedAt);
        }
        if self.accounts.len() > MAX_BUNDLE_ACCOUNTS {
            return Err(BundleError::TooManyAccounts);
        }

        let mut ids = HashSet::<String>::with_capacity(self.accounts.len());
        let mut fingerprints = HashSet::with_capacity(self.accounts.len());
        for account in &self.accounts {
            account.validate()?;
            if !ids.insert(account.id.clone()) {
                return Err(BundleError::DuplicateAccountId);
            }
            if !fingerprints.insert(account.credential.fingerprint()) {
                return Err(BundleError::DuplicateCredentialFingerprint);
            }
        }
        self.accounts.sort_by(|left, right| left.id.cmp(&right.id));

        if self.tombstones.len() > MAX_BUNDLE_TOMBSTONES {
            return Err(BundleError::TooManyTombstones);
        }
        let mut tombstone_ids = HashSet::with_capacity(self.tombstones.len());
        for tombstone in &self.tombstones {
            tombstone.validate()?;
            if !tombstone_ids.insert(tombstone.account_id.as_str()) {
                return Err(BundleError::DuplicateTombstone);
            }
            // 一个账号不可能同时"存在"和"已删除"：这种自相矛盾的 bundle 只会
            // 让接收方无法判断该保留还是该删除，直接拒绝。
            if ids.contains(tombstone.account_id.as_str()) {
                return Err(BundleError::TombstoneConflictsWithAccount);
            }
        }
        self.tombstones
            .sort_by(|left, right| left.account_id.cmp(&right.account_id));

        // Serialize once after normalization so programmatically-built values
        // receive the same global limit as decoded plaintext.
        let bytes = serde_json::to_vec(self).map_err(|_| BundleError::SerializationFailed)?;
        if bytes.len() > MAX_BUNDLE_PLAINTEXT_BYTES {
            return Err(BundleError::PlaintextTooLarge);
        }
        Ok(())
    }
}

impl fmt::Debug for BundleV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleV2")
            .field("version", &self.version)
            .field("pool_id", &self.pool_id)
            .field("generation", &self.generation)
            .field("exported_at", &self.exported_at)
            .field("account_count", &self.accounts.len())
            .finish()
    }
}

impl<'de> Deserialize<'de> for BundleAccountMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let StrictValue(value) = StrictValue::deserialize(deserializer)?;
        let wire: BundleMetadataWire = serde_json::from_value(value)
            .map_err(|_| de::Error::custom(BundleError::InvalidStructure))?;
        Self::new(
            wire.email,
            wire.account_type,
            wire.provider_id,
            wire.project_id,
            wire.account_id,
            wire.identity_fingerprint,
            wire.plan,
            wire.added_at,
            wire.updated_at,
            wire.last_used_at,
        )
        .map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for BundleAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let StrictValue(value) = StrictValue::deserialize(deserializer)?;
        let wire: BundleAccountWire = serde_json::from_value(value)
            .map_err(|_| de::Error::custom(BundleError::InvalidStructure))?;
        Self::new(wire.id, wire.metadata, wire.credential).map_err(de::Error::custom)
    }
}

/// The result of evaluating a bundle against a pool watermark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDecision {
    Accept,
    NoOp,
}

/// Errors returned by the strict bundle boundary.
///
/// Variants intentionally contain no source JSON or credential material, so
/// displaying an error is safe even when the input came from an untrusted
/// encrypted repository.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    InvalidJson,
    InvalidStructure,
    FutureVersion,
    UnsupportedVersion,
    InvalidPoolId,
    PoolIdMismatch,
    InvalidGeneration,
    InvalidExportedAt,
    InvalidAccountId,
    InvalidMetadata,
    InvalidCredential,
    CredentialKindMismatch,
    DuplicateAccountId,
    DuplicateCredentialFingerprint,
    InvalidTombstone,
    DuplicateTombstone,
    TombstoneConflictsWithAccount,
    TooManyTombstones,
    TooManyAccounts,
    PlaintextTooLarge,
    TooDeep,
    TooManyContainerItems,
    TooManyValues,
    FieldTooLarge,
    InvalidSemanticHash,
    RollbackDetected,
    GenerationConflict,
    SerializationFailed,
}

impl BundleError {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid bundle JSON",
            Self::InvalidStructure => "invalid bundle structure",
            Self::FutureVersion => "bundle version is newer than this binary",
            Self::UnsupportedVersion => "unsupported bundle version",
            Self::InvalidPoolId => "bundle pool id must be a canonical UUID",
            Self::PoolIdMismatch => "bundle pool id does not match the stored pool",
            Self::InvalidGeneration => "bundle generation must be at least one",
            Self::InvalidExportedAt => "bundle export time is outside the supported range",
            Self::InvalidAccountId => "bundle account id is invalid",
            Self::InvalidMetadata => "bundle account metadata is invalid",
            Self::InvalidCredential => "bundle credential is invalid",
            Self::CredentialKindMismatch => "bundle credential kind does not match account type",
            Self::DuplicateAccountId => "bundle contains duplicate account ids",
            Self::DuplicateCredentialFingerprint => {
                "bundle contains duplicate credential fingerprints"
            }
            Self::InvalidTombstone => "bundle deletion record is invalid",
            Self::DuplicateTombstone => "bundle contains duplicate deletion records",
            Self::TombstoneConflictsWithAccount => "bundle deletes and carries the same account id",
            Self::TooManyTombstones => "bundle contains too many deletion records",
            Self::TooManyAccounts => "bundle contains too many accounts",
            Self::PlaintextTooLarge => "bundle plaintext exceeds the size limit",
            Self::TooDeep => "bundle JSON is nested too deeply",
            Self::TooManyContainerItems => "bundle JSON container is too large",
            Self::TooManyValues => "bundle JSON contains too many values",
            Self::FieldTooLarge => "bundle JSON field is too large",
            Self::InvalidSemanticHash => "stored bundle semantic hash is invalid",
            Self::RollbackDetected => "bundle generation is older than the stored watermark",
            Self::GenerationConflict => "bundle conflicts with the stored generation",
            Self::SerializationFailed => "bundle serialization failed",
        }
    }
}

impl fmt::Debug for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for BundleError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleWire {
    version: u32,
    pool_id: String,
    generation: u64,
    exported_at: i64,
    accounts: Vec<BundleAccount>,
    #[serde(default)]
    tombstones: Vec<BundleTombstone>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleTombstoneWire {
    account_id: String,
    fingerprint: String,
    deleted_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleMetadataWire {
    email: String,
    account_type: AccountType,
    provider_id: Option<String>,
    project_id: Option<String>,
    account_id: Option<String>,
    identity_fingerprint: Option<String>,
    plan: Option<String>,
    added_at: i64,
    updated_at: i64,
    last_used_at: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleAccountWire {
    id: String,
    metadata: BundleAccountMetadata,
    credential: PortableCredential,
}

#[derive(Serialize)]
struct SemanticBundle {
    version: u32,
    pool_id: String,
    accounts: Vec<BundleAccount>,
    // 同上：无删除记录时不写入该字段，保持既有 semantic hash 不变。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tombstones: Vec<BundleTombstone>,
}

/// A best-effort description of a pre-v2 bundle plaintext.
///
/// It exists purely so the adapter can print an actionable recovery message
/// instead of a bare "unsupported bundle version": a repository that still
/// holds a legacy bundle would otherwise be permanently unusable in both
/// directions with no indication of what the user must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyBundleSummary {
    pub version: u64,
    pub account_count: usize,
    pub emails: Vec<String>,
}

/// Recognize a decrypted plaintext that is a bundle older than
/// [`BUNDLE_VERSION`].  Returns `None` for anything else, including a v2
/// bundle that merely failed strict validation.
pub fn inspect_legacy_bundle(bytes: &[u8]) -> Option<LegacyBundleSummary> {
    if bytes.len() > MAX_BUNDLE_PLAINTEXT_BYTES {
        return None;
    }
    let value = serde_json::from_slice::<Value>(bytes).ok()?;
    let object = value.as_object()?;
    let version = object.get("version")?.as_u64()?;
    if version == 0 || version >= u64::from(BUNDLE_VERSION) {
        return None;
    }
    let accounts = object.get("accounts")?.as_array()?;
    let emails = accounts
        .iter()
        .filter_map(|account| account.as_object())
        .filter_map(|account| account.get("email"))
        .filter_map(Value::as_str)
        .filter(|email| !email.trim().is_empty() && email.is_ascii())
        .take(MAX_BUNDLE_ACCOUNTS)
        .map(str::to_owned)
        .collect();
    Some(LegacyBundleSummary {
        version,
        account_count: accounts.len(),
        emails,
    })
}

fn serialize_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>, BundleError> {
    let bytes = serde_json::to_vec(value).map_err(|_| BundleError::SerializationFailed)?;
    if bytes.len() > MAX_BUNDLE_PLAINTEXT_BYTES {
        return Err(BundleError::PlaintextTooLarge);
    }
    Ok(bytes)
}

fn validate_pool_id(pool_id: &str) -> Result<(), BundleError> {
    let parsed = Uuid::parse_str(pool_id).map_err(|_| BundleError::InvalidPoolId)?;
    if parsed.to_string() != pool_id {
        return Err(BundleError::InvalidPoolId);
    }
    Ok(())
}

fn validate_account_id(account_id: &str) -> Result<(), BundleError> {
    let bytes = account_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err(BundleError::InvalidAccountId);
    }
    let first = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let rest = |byte: u8| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
    };
    if !first(bytes[0]) || !bytes.iter().copied().skip(1).all(rest) {
        return Err(BundleError::InvalidAccountId);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), BundleError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_FIELD_BYTES || value.contains('\0') {
        return Err(BundleError::InvalidMetadata);
    }
    Ok(())
}

fn validate_nonempty_text(value: &str, _field: &'static str) -> Result<(), BundleError> {
    if value.trim().is_empty() {
        return Err(BundleError::InvalidMetadata);
    }
    validate_text(value)
}

fn validate_credential_pair(
    account_type: AccountType,
    credential: &PortableCredential,
) -> Result<(), BundleError> {
    let compatible = match account_type {
        AccountType::OAuth => matches!(
            credential.kind(),
            CredentialKind::OAuthAccessToken | CredentialKind::OAuthAuthorizedUser
        ),
        AccountType::ApiKey => credential.kind() == CredentialKind::ApiKey,
        AccountType::Vertex => credential.kind() == CredentialKind::VertexServiceAccount,
    };
    if compatible {
        Ok(())
    } else {
        Err(BundleError::CredentialKindMismatch)
    }
}

fn validate_credential_fingerprint(value: &str) -> Result<(), BundleError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(BundleError::InvalidTombstone);
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BundleError::InvalidTombstone);
    }
    Ok(())
}

fn validate_semantic_sha256(value: &str) -> Result<(), BundleError> {
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
    {
        return Err(BundleError::InvalidSemanticHash);
    }
    Ok(())
}

fn validate_json_value(value: &Value, depth: usize, budget: &mut usize) -> Result<(), BundleError> {
    if depth > MAX_BUNDLE_NESTING_DEPTH {
        return Err(BundleError::TooDeep);
    }
    *budget = budget.checked_sub(1).ok_or(BundleError::TooManyValues)?;
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) => {
            if value.len() > MAX_CREDENTIAL_FIELD_BYTES {
                Err(BundleError::FieldTooLarge)
            } else {
                Ok(())
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_BUNDLE_CONTAINER_ITEMS {
                return Err(BundleError::TooManyContainerItems);
            }
            for value in values {
                validate_json_value(value, depth + 1, budget)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_BUNDLE_CONTAINER_ITEMS {
                return Err(BundleError::TooManyContainerItems);
            }
            for (key, value) in object {
                if key.len() > MAX_CREDENTIAL_FIELD_BYTES {
                    return Err(BundleError::FieldTooLarge);
                }
                validate_json_value(value, depth + 1, budget)?;
            }
            Ok(())
        }
    }
}

/// A duplicate-aware JSON value.  serde_json's default map deserializer keeps
/// the last duplicate key; this visitor rejects duplicates before any wire
/// struct can observe or normalize them.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = Map::new();
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    let StrictValue(value) = map.next_value()?;
                    object.insert(key, value);
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

impl<'de> Deserialize<'de> for BundleV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let StrictValue(value) = StrictValue::deserialize(deserializer)?;
        Self::from_value(value).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POOL_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    fn metadata(account_type: AccountType, ordinal: usize) -> BundleAccountMetadata {
        BundleAccountMetadata::new(
            format!("user-{ordinal}@example.test"),
            account_type,
            Some("provider".to_string()),
            Some("project".to_string()),
            Some(format!("provider-{ordinal}")),
            None,
            Some("pro".to_string()),
            1_700_000_000,
            1_700_000_001,
            None,
        )
        .unwrap()
    }

    fn credentials() -> Vec<(AccountType, PortableCredential)> {
        vec![
            (
                AccountType::OAuth,
                PortableCredential::oauth_access_token("access-secret").unwrap(),
            ),
            (
                AccountType::OAuth,
                PortableCredential::oauth_authorized_user(json!({
                    "type": "authorized_user",
                    "client_id": "client-id",
                    "client_secret": "client-secret",
                    "refresh_token": "refresh-secret",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "unknown_provider_field": {"enabled": true}
                }))
                .unwrap(),
            ),
            (
                AccountType::ApiKey,
                PortableCredential::api_key_document(json!({
                    "api_key": "api-secret",
                    "email": "api@example.test",
                    "project_id": "project"
                }))
                .unwrap(),
            ),
            (
                AccountType::Vertex,
                PortableCredential::vertex_service_account(json!({
                    "type": "service_account",
                    "project_id": "project",
                    "private_key": "private-key-secret",
                    "client_email": "service@example.test",
                    "token_uri": "https://oauth.example.test/token",
                    "unmodeled": ["field"]
                }))
                .unwrap(),
            ),
        ]
    }

    fn sample_bundle() -> BundleV2 {
        let accounts = credentials()
            .into_iter()
            .enumerate()
            .map(|(index, (account_type, credential))| {
                BundleAccount::new(
                    format!("account-{}", index + 1),
                    metadata(account_type, index),
                    credential,
                )
                .unwrap()
            })
            .collect();
        BundleV2::new(POOL_ID, 1, 1_700_000_100, accounts).unwrap()
    }

    #[test]
    fn all_four_credentials_round_trip_with_semantic_hash() {
        let bundle = sample_bundle();
        let encoded = bundle.encode().unwrap();
        let decoded = BundleV2::decode(&encoded).unwrap();
        assert_eq!(encoded, decoded.encode().unwrap());
        assert_eq!(
            bundle.semantic_sha256().unwrap(),
            decoded.semantic_sha256().unwrap()
        );
        assert!(format!("{decoded:?}").contains("account_count: 4"));
    }

    #[test]
    fn account_order_does_not_change_canonical_or_semantic_bytes() {
        let mut reversed = sample_bundle();
        reversed.accounts.reverse();
        assert_eq!(
            sample_bundle().encode().unwrap(),
            reversed.encode().unwrap()
        );
        assert_eq!(
            sample_bundle().semantic_sha256().unwrap(),
            reversed.semantic_sha256().unwrap()
        );
    }

    #[test]
    fn generation_and_export_time_are_excluded_from_semantic_hash() {
        let first = sample_bundle();
        let second = BundleV2::new(POOL_ID, 2, 1_800_000_000, first.accounts.clone()).unwrap();
        assert_eq!(
            first.semantic_sha256().unwrap(),
            second.semantic_sha256().unwrap()
        );
        assert_ne!(first.encode().unwrap(), second.encode().unwrap());
    }

    #[test]
    fn unknown_and_duplicate_fields_are_rejected_without_secret_echo() {
        let encoded = sample_bundle().canonical_json_string().unwrap();
        let unknown = encoded.replacen("\"version\":2", "\"version\":2,\"unknown\":1", 1);
        let error = BundleV2::from_json_str(&unknown).unwrap_err();
        assert_eq!(error, BundleError::InvalidStructure);
        assert!(!error.to_string().contains("access-secret"));

        let duplicate = encoded.replacen("\"version\":2", "\"version\":2,\"version\":2", 1);
        assert_eq!(
            BundleV2::from_json_str(&duplicate).unwrap_err(),
            BundleError::InvalidJson
        );

        let nested_duplicate = encoded.replacen(
            "\"access_token\":\"access-secret\"",
            "\"access_token\":\"access-secret\",\"access_token\":\"other-secret\"",
            1,
        );
        assert_eq!(
            BundleV2::from_json_str(&nested_duplicate).unwrap_err(),
            BundleError::InvalidJson
        );
    }

    #[test]
    fn bounds_and_duplicate_identity_conflicts_are_rejected() {
        let mut duplicate_id = sample_bundle();
        duplicate_id.accounts[1].id = duplicate_id.accounts[0].id.clone();
        assert_eq!(
            duplicate_id.validate().unwrap_err(),
            BundleError::DuplicateAccountId
        );

        let mut duplicate_fingerprint = sample_bundle();
        duplicate_fingerprint.accounts[1].credential =
            duplicate_fingerprint.accounts[0].credential.clone();
        assert_eq!(
            duplicate_fingerprint.validate().unwrap_err(),
            BundleError::DuplicateCredentialFingerprint
        );

        let too_many = (0..=MAX_BUNDLE_ACCOUNTS)
            .map(|index| {
                let credential =
                    PortableCredential::oauth_access_token(format!("secret-{index}")).unwrap();
                BundleAccount::new(
                    format!("account-{index}"),
                    metadata(AccountType::OAuth, index),
                    credential,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            BundleV2::new(POOL_ID, 1, 1, too_many).unwrap_err(),
            BundleError::TooManyAccounts
        );
    }

    #[test]
    fn depth_and_plaintext_bounds_are_enforced() {
        let mut nested = json!({
            "type": "authorized_user",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "refresh_token": "refresh-secret",
            "token_uri": "https://oauth2.googleapis.com/token"
        });
        for _ in 0..(MAX_BUNDLE_NESTING_DEPTH + 2) {
            nested = json!({"nested": nested});
        }
        let raw = json!({
            "version": 2,
            "pool_id": POOL_ID,
            "generation": 1,
            "exported_at": 1,
            "accounts": [{
                "id": "account-1",
                "metadata": metadata(AccountType::OAuth, 0),
                "credential": {
                    "schema_version": 1,
                    "kind": "oauth_authorized_user",
                    "payload": nested
                }
            }]
        });
        assert_eq!(
            BundleV2::from_json_str(&raw.to_string()).unwrap_err(),
            BundleError::TooDeep
        );

        let oversized = vec![b' '; MAX_BUNDLE_PLAINTEXT_BYTES + 1];
        assert_eq!(
            BundleV2::from_json_bytes(&oversized).unwrap_err(),
            BundleError::PlaintextTooLarge
        );
    }

    #[test]
    fn rollback_and_noop_decisions_are_generation_and_pool_bound() {
        let bundle = sample_bundle();
        let hash = bundle.semantic_sha256().unwrap();
        let same = SyncWatermark {
            generation: 1,
            semantic_sha256: hash.clone(),
        };
        assert_eq!(
            bundle.rollback_decision(POOL_ID, Some(&same)).unwrap(),
            SyncDecision::NoOp
        );
        let lower = SyncWatermark {
            generation: 2,
            semantic_sha256: hash.clone(),
        };
        assert_eq!(
            bundle.rollback_decision(POOL_ID, Some(&lower)).unwrap_err(),
            BundleError::RollbackDetected
        );
        let conflict = SyncWatermark {
            generation: 1,
            semantic_sha256: "0".repeat(64),
        };
        assert_eq!(
            bundle
                .rollback_decision(POOL_ID, Some(&conflict))
                .unwrap_err(),
            BundleError::GenerationConflict
        );
        let newer = SyncWatermark {
            generation: 0,
            semantic_sha256: hash,
        };
        assert_eq!(
            bundle.rollback_decision(POOL_ID, Some(&newer)).unwrap(),
            SyncDecision::Accept
        );
        assert_eq!(
            bundle.rollback_decision(POOL_ID, None).unwrap(),
            SyncDecision::Accept
        );
        assert_eq!(
            bundle.rollback_decision("123e4567-e89b-12d3-a456-426614174001", None),
            Err(BundleError::PoolIdMismatch)
        );
    }

    #[test]
    fn public_debug_never_contains_credential_material() {
        let bundle = sample_bundle();
        let debug = format!("{bundle:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("client-secret"));
        assert!(!debug.contains("refresh-secret"));
        assert!(!debug.contains("api-secret"));
        assert!(!debug.contains("private-key-secret"));
        let account_debug = format!("{:?}", bundle.accounts[0]);
        assert!(!account_debug.contains("access-secret"));
    }
}
