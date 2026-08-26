//! Strict, versioned state storage over the generic atomic document store.
//!
//! This module is deliberately not wired into the current CLI in S0. The
//! existing adapter still consumes the legacy runtime `AccountRecord`; the
//! StateStore wire boundary is prepared for the later atomic cutover.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::atomic_io::{
    DocumentDigest, NormalizedStoreRoot, OwnedStoreRoot, SafeRelativePath, TopLevelEntryKind,
    inspect_top_level_inventory, is_link_or_reparse, read_normalized_relative_file_bounded,
};
use super::atomic_store::{
    AccountStoreCapability, AdoptionArtifact, AdoptionInventoryEntry, AdoptionPreflight,
    AtomicStore, AtomicStoreError, DocumentSnapshot, ExpectedDigest, JournalPreview,
    LockedAtomicStore, RecoveryPreview, inspect_recovery_from_normalized,
    read_snapshot_from_normalized,
};
use super::credential::PortableCredential;
use super::health::{Cooldown, HealthErrorKind, HealthStatus};
use super::state::{
    AccountRecord, AccountType, ActiveProfile, CredentialRef, CredentialRefKind, ManagedLayout,
    STATE_V2_VERSION, STATE_VERSION, State, SyncWatermark, UsageSnapshot, validate_account_id,
    validate_credential_fingerprint, validate_state_invariants,
};

const STATE_TARGET: &str = "state.json";
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACCOUNTS: usize = 4096;
const MAX_USAGE_ENTRIES: usize = 4096;
const MAX_WATERMARKS: usize = 4096;
const MAX_REPO_SYNC_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACCOUNT_FILES: usize = 32;
const MAX_ACCOUNT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ACCOUNT_DIRECTORIES: usize = 4096;
/// state root 同时是安装目录，顶层可能混有 bin/、用户笔记、编辑器残留等条目，
/// 上限只用来挡住"把一个巨大的无关目录当成 state root"这种明显误用。
const MAX_ROOT_INVENTORY_ENTRIES: usize = 4096;
/// 损坏的 state 文档被改名隔离时使用的前缀，绝不删除用户数据。
const CORRUPT_STATE_PREFIX: &str = "state.json.corrupt-";
const CREDENTIAL_JOURNAL_MAX_BYTES: usize = 32 * 1024;
const ACTIVE_HOME_JOURNAL_MAX_BYTES: usize = 64 * 1024;
const ACTIVE_HOME_JOURNAL_PREFIX: &str = ".sagy-active-home-";
const ACTIVE_HOME_JOURNAL_SUFFIX: &str = ".journal";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevisionGeneration {
    Missing,
    Legacy,
    Current(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Revision {
    pub(crate) generation: RevisionGeneration,
    pub(crate) document_sha256: Option<String>,
}

/// An opaque capability minted only while the state lock is held.  The
/// credential adapter consumes this value to derive the fixed account layout;
/// callers cannot construct it from an arbitrary path.
pub(crate) struct CredentialMutationPermit {
    capability: AccountStoreCapability,
    account_id: String,
    state_revision: Revision,
    before_ref: Option<CredentialRef>,
    mode: CredentialMutationMode,
}

/// A sealed active-home mutation permission minted while the State lock is
/// held.  The account capability is intentionally carried by value: an
/// active-home operation must remain tied to the same state-owned account
/// root that supplied the credential and cannot manufacture a path later.
pub(crate) struct ActiveHomeMutationPermit {
    capability: AccountStoreCapability,
    account_id: String,
    base_revision: Revision,
    before_profile: Option<ActiveProfile>,
    target_profile: Option<ActiveProfile>,
    target_ref: Option<CredentialRef>,
    home_scope_id: Option<String>,
}

impl std::fmt::Debug for ActiveHomeMutationPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveHomeMutationPermit")
            .field("account_id", &self.account_id)
            .field("base_revision", &self.base_revision)
            .field("before_profile", &self.before_profile)
            .field("target_ref", &self.target_ref)
            .field("target_profile", &self.target_profile)
            .field("home_scope_id", &self.home_scope_id)
            .finish()
    }
}

impl ActiveHomeMutationPermit {
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn account_capability(&self) -> &AccountStoreCapability {
        &self.capability
    }

    pub(crate) fn base_revision(&self) -> &Revision {
        &self.base_revision
    }

    pub(crate) fn before_profile(&self) -> Option<&ActiveProfile> {
        self.before_profile.as_ref()
    }

    pub(crate) fn target_profile(&self) -> Option<&ActiveProfile> {
        self.target_profile.as_ref()
    }

    pub(crate) fn target_ref(&self) -> Option<&CredentialRef> {
        self.target_ref.as_ref()
    }

    pub(crate) fn home_scope_id(&self) -> Option<&str> {
        self.home_scope_id.as_deref()
    }
}

/// The state transaction decides whether a credential mutation is an exact
/// current-state replacement or part of the one-time v1/missing migration.
/// This is intentionally private to this module; callers can only receive a
/// value minted while the state lock is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialMutationMode {
    CurrentExact,
    Migration,
}

impl std::fmt::Debug for CredentialMutationPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialMutationPermit")
            .field("account_id", &self.account_id)
            .field("state_revision", &self.state_revision)
            .finish()
    }
}

impl CredentialMutationPermit {
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn account_capability(&self) -> &AccountStoreCapability {
        &self.capability
    }

    pub(crate) fn state_revision(&self) -> &Revision {
        &self.state_revision
    }

    pub(crate) fn before_ref(&self) -> Option<&CredentialRef> {
        self.before_ref.as_ref()
    }

    pub(crate) fn mode(&self) -> CredentialMutationMode {
        self.mode
    }
}

/// Opaque evidence that a credential journal was durably written before a
/// migration state commit.  Only the credential adapter can mint this proof.
pub(crate) struct CredentialJournalProof {
    account_id: String,
    txid: Uuid,
    journal_digest: String,
    base_revision: Revision,
    before_ref: Option<CredentialRef>,
    after_ref: Option<CredentialRef>,
}

/// Opaque evidence that the two external active-home roots were durably
/// journaled and published under the exact State revision.
pub(crate) struct ActiveHomeJournalProof {
    account_id: String,
    txid: Uuid,
    journal_digest: String,
    base_revision: Revision,
    before_profile: Option<ActiveProfile>,
    after_profile: Option<ActiveProfile>,
    target_ref: Option<CredentialRef>,
    adoption_mode: String,
    before_layout: ManagedLayout,
    after_layout: ManagedLayout,
}

impl std::fmt::Debug for ActiveHomeJournalProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActiveHomeJournalProof")
            .field("account_id", &self.account_id)
            .field("txid", &self.txid)
            .field("journal_digest", &self.journal_digest)
            .field("base_revision", &self.base_revision)
            .field("before_profile", &self.before_profile)
            .field("after_profile", &self.after_profile)
            .field("adoption_mode", &self.adoption_mode)
            .finish()
    }
}

impl ActiveHomeJournalProof {
    /// Only the active-home adapter can create this evidence. StateStore
    /// re-reads the journal bytes before accepting a coordinated commit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        account_id: &str,
        txid: Uuid,
        journal_digest: String,
        base_revision: Revision,
        before_profile: Option<ActiveProfile>,
        after_profile: Option<ActiveProfile>,
        target_ref: Option<CredentialRef>,
        adoption_mode: String,
        before_layout: ManagedLayout,
        after_layout: ManagedLayout,
    ) -> Result<Self> {
        validate_account_id(account_id)?;
        validate_revision(&base_revision)?;
        validate_journal_digest("active-home journal digest", &journal_digest)?;
        if let Some(profile) = before_profile.as_ref() {
            validate_active_profile_shape(profile)?;
        }
        if let Some(profile) = after_profile.as_ref() {
            validate_active_profile_shape(profile)?;
        }
        if let (Some(before), Some(after)) = (before_profile.as_ref(), after_profile.as_ref())
            && before.home_scope_id != after.home_scope_id
        {
            bail!("active-home proof changes home scope");
        }
        let expected_account = after_profile
            .as_ref()
            .map(|profile| profile.account_id.as_str())
            .or_else(|| {
                before_profile
                    .as_ref()
                    .map(|profile| profile.account_id.as_str())
            });
        if expected_account != Some(account_id) {
            bail!("active-home proof account differs from profile transition target");
        }
        if (before_profile.is_some() || after_profile.is_some()) && target_ref.is_none() {
            bail!("active-home profile transition requires a credential reference");
        }
        if let Some(reference) = target_ref.as_ref() {
            validate_credential_ref(reference)?;
            if let Some(profile) = after_profile.as_ref()
                && profile.credential_fingerprint != reference.fingerprint
            {
                bail!("active-home target reference differs from target profile");
            }
            if let Some(profile) = after_profile.as_ref() {
                validate_active_layout_for_reference(reference.kind, &profile.managed_layout)?;
            }
        }
        if !matches!(adoption_mode.as_str(), "strict" | "adopt" | "takeover") {
            bail!("active-home adoption mode is invalid");
        }
        validate_managed_layout_shape(&before_layout)?;
        validate_managed_layout_shape(&after_layout)?;
        if adoption_mode != "takeover" {
            match before_profile.as_ref() {
                Some(profile) if profile.managed_layout != before_layout => {
                    bail!("strict/adopt active-home before layout differs from State")
                }
                Some(_) => {}
                None if adoption_mode == "adopt" && before_layout != after_layout => {
                    bail!("adopted first active-home layout differs from target")
                }
                None if adoption_mode == "strict" && before_layout != ManagedLayout::default() => {
                    bail!("strict first active-home layout must start empty")
                }
                None => {}
            }
        }
        Ok(Self {
            account_id: account_id.to_string(),
            txid,
            journal_digest,
            base_revision,
            before_profile,
            after_profile,
            target_ref,
            adoption_mode,
            before_layout,
            after_layout,
        })
    }

    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn txid(&self) -> Uuid {
        self.txid
    }

    pub(crate) fn journal_digest(&self) -> &str {
        &self.journal_digest
    }

    pub(crate) fn base_revision(&self) -> &Revision {
        &self.base_revision
    }

    pub(crate) fn before_profile(&self) -> Option<&ActiveProfile> {
        self.before_profile.as_ref()
    }

    pub(crate) fn after_profile(&self) -> Option<&ActiveProfile> {
        self.after_profile.as_ref()
    }

    pub(crate) fn target_ref(&self) -> Option<&CredentialRef> {
        self.target_ref.as_ref()
    }

    pub(crate) fn adoption_mode(&self) -> &str {
        &self.adoption_mode
    }

    pub(crate) fn before_layout(&self) -> &ManagedLayout {
        &self.before_layout
    }

    pub(crate) fn after_layout(&self) -> &ManagedLayout {
        &self.after_layout
    }
}

fn validate_journal_digest(label: &str, digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
    {
        bail!("{label} must be a lowercase SHA-256 digest");
    }
    Ok(())
}

fn validate_active_profile_shape(profile: &ActiveProfile) -> Result<()> {
    validate_account_id(&profile.account_id)?;
    validate_credential_fingerprint(&profile.credential_fingerprint)?;
    super::state::validate_sha256("active profile home_scope_id", &profile.home_scope_id)?;
    validate_profile_layout_combination(&profile.managed_layout)?;
    for (label, slot) in [
        (
            "active antigravity_token",
            &profile.managed_layout.antigravity_token,
        ),
        (
            "active gemini_authorized_user",
            &profile.managed_layout.gemini_authorized_user,
        ),
    ] {
        if let super::state::SlotState::Exact { sha256 } = slot {
            super::state::validate_sha256(label, sha256)?;
        }
    }
    Ok(())
}

fn validate_profile_layout_combination(layout: &ManagedLayout) -> Result<()> {
    let valid = matches!(
        (&layout.antigravity_token, &layout.gemini_authorized_user,),
        (
            super::state::SlotState::Absent,
            super::state::SlotState::Absent,
        ) | (
            super::state::SlotState::Exact { .. },
            super::state::SlotState::Absent,
        ) | (
            super::state::SlotState::Absent,
            super::state::SlotState::Exact { .. },
        )
    );
    if !valid {
        bail!("active profile managed layout has an invalid slot combination");
    }
    Ok(())
}

fn validate_managed_layout_shape(layout: &ManagedLayout) -> Result<()> {
    for (label, slot) in [
        ("active antigravity_token", &layout.antigravity_token),
        (
            "active gemini_authorized_user",
            &layout.gemini_authorized_user,
        ),
    ] {
        if let super::state::SlotState::Exact { sha256 } = slot {
            super::state::validate_sha256(label, sha256)?;
        }
    }
    Ok(())
}

fn validate_active_layout_for_reference(
    kind: CredentialRefKind,
    layout: &ManagedLayout,
) -> Result<()> {
    validate_managed_layout_shape(layout)?;
    match kind {
        CredentialRefKind::OauthAccessToken | CredentialRefKind::AntigravityToken => {
            if !matches!(
                layout.antigravity_token,
                super::state::SlotState::Exact { .. }
            ) || !matches!(
                layout.gemini_authorized_user,
                super::state::SlotState::Absent
            ) {
                bail!("active OAuth token layout has an invalid slot combination");
            }
        }
        CredentialRefKind::OauthAuthorizedUser | CredentialRefKind::GeminiOauthSession => {
            if !matches!(layout.antigravity_token, super::state::SlotState::Absent)
                || !matches!(
                    layout.gemini_authorized_user,
                    super::state::SlotState::Exact { .. }
                )
            {
                bail!("active authorized-user layout has an invalid slot combination");
            }
        }
        CredentialRefKind::ApiKey | CredentialRefKind::VertexServiceAccount => {
            if layout != &ManagedLayout::default() {
                bail!("active API/Vertex layout must have both slots absent");
            }
        }
    }
    Ok(())
}

impl std::fmt::Debug for CredentialJournalProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialJournalProof")
            .field("account_id", &self.account_id)
            .field("txid", &self.txid)
            .field("journal_digest", &self.journal_digest)
            .field("base_revision", &self.base_revision)
            .field("before_ref", &self.before_ref)
            .field("after_ref", &self.after_ref)
            .finish()
    }
}

impl CredentialJournalProof {
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn credential_ref(&self) -> &CredentialRef {
        self.after_ref
            .as_ref()
            .expect("legacy proof has an after ref")
    }

    pub(crate) fn before_ref(&self) -> Option<&CredentialRef> {
        self.before_ref.as_ref()
    }

    pub(crate) fn after_ref(&self) -> Option<&CredentialRef> {
        self.after_ref.as_ref()
    }

    pub(crate) fn txid(&self) -> Uuid {
        self.txid
    }

    pub(crate) fn journal_digest(&self) -> &str {
        &self.journal_digest
    }

    pub(crate) fn base_revision(&self) -> &Revision {
        &self.base_revision
    }

    pub(crate) fn new(
        account_id: &str,
        txid: Uuid,
        journal_digest: String,
        credential_ref: CredentialRef,
    ) -> Result<Self> {
        Self::new_transition(
            account_id,
            txid,
            journal_digest,
            Revision {
                generation: RevisionGeneration::Missing,
                document_sha256: None,
            },
            None,
            Some(credential_ref),
        )
    }

    pub(crate) fn new_transition(
        account_id: &str,
        txid: Uuid,
        journal_digest: String,
        base_revision: Revision,
        before_ref: Option<CredentialRef>,
        after_ref: Option<CredentialRef>,
    ) -> Result<Self> {
        validate_account_id(account_id)?;
        if journal_digest.len() != 64
            || !journal_digest.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
            })
        {
            bail!("credential journal digest must be a lowercase SHA-256 digest");
        }
        validate_revision(&base_revision)?;
        if let Some(reference) = &before_ref {
            validate_credential_ref(reference)?;
        }
        if let Some(reference) = &after_ref {
            validate_credential_ref(reference)?;
        }
        Ok(Self {
            account_id: account_id.to_string(),
            txid,
            journal_digest,
            base_revision,
            before_ref,
            after_ref,
        })
    }
}

fn validate_credential_ref(reference: &CredentialRef) -> Result<()> {
    validate_credential_fingerprint(&reference.fingerprint)?;
    Ok(())
}

fn validate_revision(revision: &Revision) -> Result<()> {
    match revision.generation {
        RevisionGeneration::Missing => {
            if revision.document_sha256.is_some() {
                bail!("missing revision cannot carry a document digest");
            }
        }
        RevisionGeneration::Legacy => {
            if let Some(digest) = revision.document_sha256.as_deref()
                && (digest.len() != 64
                    || !digest.bytes().all(|byte| {
                        byte.is_ascii_digit()
                            || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
                    }))
            {
                bail!("legacy revision digest must be a lowercase SHA-256 digest");
            }
        }
        RevisionGeneration::Current(value) => {
            if value == 0 {
                bail!("current revision generation must be positive");
            }
            let Some(digest) = revision.document_sha256.as_deref() else {
                bail!("current revision must carry a document digest");
            };
            if digest.len() != 64
                || !digest.bytes().all(|byte| {
                    byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
                })
            {
                bail!("current revision digest must be a lowercase SHA-256 digest");
            }
        }
    }
    Ok(())
}

/// Sealed permission to make the one-time missing/v1 -> v2 state transition.
pub(crate) struct MigrationCommitPermit {
    expected: Revision,
    proofs: Vec<CredentialJournalProof>,
}

/// Receipt returned by a state commit.  It is the only proof accepted by a
/// later credential finalize operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateCommitReceipt {
    revision: Revision,
    transitions: BTreeMap<String, CredentialCommitTransition>,
    active_home_transition: Option<ActiveHomeCommitTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialCommitTransition {
    account_id: String,
    txid: Uuid,
    base_revision: Revision,
    committed_revision: Revision,
    before_ref: Option<CredentialRef>,
    after_ref: Option<CredentialRef>,
}

impl CredentialCommitTransition {
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn txid(&self) -> Uuid {
        self.txid
    }

    pub(crate) fn base_revision(&self) -> &Revision {
        &self.base_revision
    }

    pub(crate) fn committed_revision(&self) -> &Revision {
        &self.committed_revision
    }

    pub(crate) fn before_ref(&self) -> Option<&CredentialRef> {
        self.before_ref.as_ref()
    }

    pub(crate) fn after_ref(&self) -> Option<&CredentialRef> {
        self.after_ref.as_ref()
    }
}

impl StateCommitReceipt {
    pub(crate) fn revision(&self) -> &Revision {
        &self.revision
    }

    pub(crate) fn credential_ref(&self, account_id: &str) -> Option<&CredentialRef> {
        self.transitions
            .get(account_id)
            .and_then(|transition| transition.after_ref.as_ref())
    }

    pub(crate) fn credential_transition(
        &self,
        account_id: &str,
    ) -> Option<&CredentialCommitTransition> {
        self.transitions.get(account_id)
    }

    pub(crate) fn active_home_transition(&self) -> Option<&ActiveHomeCommitTransition> {
        self.active_home_transition.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveHomeCommitTransition {
    account_id: String,
    txid: Uuid,
    journal_digest: String,
    base_revision: Revision,
    committed_revision: Revision,
    before_profile: Option<ActiveProfile>,
    after_profile: Option<ActiveProfile>,
    target_ref: Option<CredentialRef>,
}

impl ActiveHomeCommitTransition {
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn txid(&self) -> Uuid {
        self.txid
    }

    pub(crate) fn journal_digest(&self) -> &str {
        &self.journal_digest
    }

    pub(crate) fn base_revision(&self) -> &Revision {
        &self.base_revision
    }

    pub(crate) fn committed_revision(&self) -> &Revision {
        &self.committed_revision
    }

    pub(crate) fn before_profile(&self) -> Option<&ActiveProfile> {
        self.before_profile.as_ref()
    }

    pub(crate) fn after_profile(&self) -> Option<&ActiveProfile> {
        self.after_profile.as_ref()
    }

    pub(crate) fn target_ref(&self) -> Option<&CredentialRef> {
        self.target_ref.as_ref()
    }
}

/// A state snapshot proof used by restart recovery.  Unlike
/// [`StateCommitReceipt`], this value is minted from a locked, exact current
/// snapshot and is never constructed by the credential adapter.  Recovery
/// uses it to decide whether a journal's before/after reference matches the
/// durable state that is already on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CurrentCredentialRefProof {
    revision: Revision,
    credential_refs: BTreeMap<String, CredentialRef>,
}

/// Preferred name for the sealed current-state recovery authority.  The
/// compatibility alias below keeps the in-flight adapter buildable while the
/// CLI/account cutover adopts the more explicit terminology.
pub(crate) type CurrentStateProof = CurrentCredentialRefProof;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyRecoveryProof {
    revision: Revision,
}

impl LegacyRecoveryProof {
    pub(crate) fn revision(&self) -> &Revision {
        &self.revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryAuthority {
    Current(CurrentStateProof),
    Legacy(LegacyRecoveryProof),
}

/// Active-home recovery uses a dedicated sealed authority so a credential
/// recovery proof cannot be mistaken for permission to finalize user-home
/// files. The current variant carries only the exact profile snapshot and
/// revision minted under the State lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveHomeCurrentProof {
    revision: Revision,
    active_profile: Option<ActiveProfile>,
}

impl ActiveHomeCurrentProof {
    pub(crate) fn revision(&self) -> &Revision {
        &self.revision
    }

    pub(crate) fn active_profile(&self) -> Option<&ActiveProfile> {
        self.active_profile.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveHomeLegacyProof {
    revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActiveHomeRecoveryAuthority {
    Current(ActiveHomeCurrentProof),
    Legacy(ActiveHomeLegacyProof),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveHomeRecoveryState {
    Finalized,
    RolledBack,
}

impl CurrentCredentialRefProof {
    pub(crate) fn revision(&self) -> &Revision {
        &self.revision
    }

    pub(crate) fn credential_ref(&self, account_id: &str) -> Option<&CredentialRef> {
        self.credential_refs.get(account_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationStatus {
    None,
    Missing,
    LegacyV1,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StateRead {
    pub(crate) state: State,
    pub(crate) revision: Revision,
    pub(crate) migration: MigrationStatus,
    pub(crate) recovery_pending: bool,
}

/// The result of a state commit.  A caller receives the committed value, the
/// exact after-snapshot and the sealed receipt together; it never needs to
/// reconstruct a revision from a mutable `State` value.
#[derive(Debug, Clone)]
pub(crate) struct Committed<T> {
    value: T,
    after: StateRead,
    receipt: StateCommitReceipt,
}

impl<T> Committed<T> {
    pub(crate) fn value(&self) -> &T {
        &self.value
    }

    pub(crate) fn into_value(self) -> T {
        self.value
    }

    pub(crate) fn after(&self) -> &StateRead {
        &self.after
    }

    pub(crate) fn receipt(&self) -> &StateCommitReceipt {
        &self.receipt
    }
}

#[derive(Debug)]
pub(crate) enum StateStoreError {
    MigrationRequired,
    Conflict {
        expected: Revision,
        actual: Revision,
    },
    Atomic(AtomicStoreError),
    Invalid(anyhow::Error),
}

impl std::fmt::Display for StateStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MigrationRequired => write!(
                formatter,
                "state migration requires credential-store proof and a sealed migration commit"
            ),
            Self::Conflict { expected, actual } => write!(
                formatter,
                "state revision conflict: expected {expected:?}, actual {actual:?}"
            ),
            Self::Atomic(error) => write!(formatter, "state atomic store error: {error}"),
            Self::Invalid(error) => write!(formatter, "invalid state: {error}"),
        }
    }
}

impl std::error::Error for StateStoreError {}

impl From<AtomicStoreError> for StateStoreError {
    fn from(error: AtomicStoreError) -> Self {
        Self::Atomic(error)
    }
}

impl From<anyhow::Error> for StateStoreError {
    fn from(error: anyhow::Error) -> Self {
        Self::Invalid(error)
    }
}

/// One state-owned exact session.  The session is the sole high-level owner
/// of the mutable snapshot/revision pair: callers submit a candidate state,
/// receive the committed value plus its after-snapshot and sealed receipt,
/// and the session advances itself to that after-snapshot.
#[derive(Debug, Clone)]
pub(crate) struct StateSession {
    store: StateStore,
    read: StateRead,
}

impl StateSession {
    fn from_store(store: StateStore) -> Result<Self, StateStoreError> {
        // 开 session 是"任何一条命令打开 state"的唯一入口，因此把两件恢复性动作
        // 挂在这里，而不是挂在纯读的 `StateStore::read` 上：
        //  1. 文档本身在 JSON 语法层坏掉时，把它改名隔离并给出恢复指引；
        //  2. 收紧历史遗留的宽权限凭据（0644/0755 -> 0600/0700），fail-closed。
        //
        // 顺序不能反过来（R1-6.1）：只读校验必须先跑完。先 chmod 会对一批随后
        // 就要被判非法的条目改权限，还会用一句笼统的权限错误顶掉
        // `validate_accounts_dir` 更精确的文案。
        let read = match store.read() {
            Ok(read) => read,
            Err(error) => return Err(quarantine_unreadable_document(&store, error)),
        };
        harden_state_root_permissions(&store.root).map_err(StateStoreError::Invalid)?;
        Ok(Self { store, read })
    }

    /// Pure session bootstrap from an already opened store.
    pub(crate) fn bootstrap_exact(store: &StateStore) -> Result<Self, StateStoreError> {
        store.session()
    }

    pub(crate) fn open(path: &Path) -> Result<Self, StateStoreError> {
        StateStore::open(path)?.session()
    }

    pub(crate) fn read(&self) -> &StateRead {
        &self.read
    }

    pub(crate) fn state(&self) -> &State {
        &self.read.state
    }

    pub(crate) fn revision(&self) -> &Revision {
        &self.read.revision
    }

    pub(crate) fn migration(&self) -> MigrationStatus {
        self.read.migration
    }

    /// Run one callback under this session's exact State lock and refresh the
    /// session from the lock-held after-snapshot.  The callback result is
    /// intentionally separated from snapshot refresh: callers may report a
    /// post-commit recovery-pending error while the session still advances to
    /// the committed revision, preventing a later caller from reusing a stale
    /// snapshot or minting a second transaction.
    pub(crate) fn with_locked_exact<T, E, F>(&mut self, callback: F) -> Result<T, E>
    where
        E: From<StateStoreError>,
        F: FnOnce(&mut LockedStateTxn<'_>) -> Result<T, E>,
    {
        let expected = self.read.revision.clone();
        let (result, after) = self
            .store
            .with_locked_exact(&expected, |transaction| {
                let result = callback(transaction);
                let after = transaction.snapshot()?;
                Ok((result, after))
            })
            .map_err(E::from)?;
        self.read = after;
        result
    }

    /// Alias for callers that model a state mutation as a transaction rather
    /// than as an exact-lock callback.
    pub(crate) fn transact<T, E, F>(&mut self, callback: F) -> Result<T, E>
    where
        E: From<StateStoreError>,
        F: FnOnce(&mut LockedStateTxn<'_>) -> Result<T, E>,
    {
        self.with_locked_exact(callback)
    }

    /// Commit one current-generation candidate against this session's exact
    /// revision.  The candidate's runtime revision/version are normalized by
    /// the state layer, and the session is updated only after the durable
    /// after-snapshot has been parsed successfully.
    pub(crate) fn commit(&mut self, state: &State) -> Result<Committed<State>, StateStoreError> {
        self.commit_exact(state)
    }

    pub(crate) fn commit_exact(
        &mut self,
        state: &State,
    ) -> Result<Committed<State>, StateStoreError> {
        if !matches!(
            self.read.revision.generation,
            RevisionGeneration::Current(_)
        ) {
            return Err(StateStoreError::MigrationRequired);
        }
        let expected = self.read.revision.clone();
        let (receipt, after) = self.store.with_locked_exact(&expected, |transaction| {
            let receipt = transaction.commit_exact_receipt(state)?;
            let after = transaction.snapshot()?;
            Ok((receipt, after))
        })?;
        self.read = after.clone();
        Ok(Committed {
            value: after.state.clone(),
            after,
            receipt,
        })
    }

    pub(crate) fn commit_coordinated(
        &mut self,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
    ) -> Result<Committed<State>, StateStoreError> {
        self.commit_coordinated_with_active(state, proofs, None)
    }

    pub(crate) fn commit_coordinated_with_active(
        &mut self,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
        active_proof: Option<ActiveHomeJournalProof>,
    ) -> Result<Committed<State>, StateStoreError> {
        let expected = self.read.revision.clone();
        let (receipt, after) = self.store.with_locked_exact(&expected, |transaction| {
            let receipt =
                transaction.commit_coordinated_with_active(state, proofs, active_proof)?;
            let after = transaction.snapshot()?;
            Ok((receipt, after))
        })?;
        self.read = after.clone();
        Ok(Committed {
            value: after.state.clone(),
            after,
            receipt,
        })
    }

    /// Create the sealed one-time migration permit while rechecking this
    /// session's exact revision.  The state layer validates only durable
    /// journal proofs; it does not inspect credentials or infer home layout.
    pub(crate) fn migration_permit(
        &self,
        proofs: Vec<CredentialJournalProof>,
    ) -> Result<MigrationCommitPermit, StateStoreError> {
        if matches!(self.read.migration, MigrationStatus::None) {
            return Err(StateStoreError::Invalid(anyhow!(
                "migration permit is valid only for missing or legacy state"
            )));
        }
        let expected = self.read.revision.clone();
        self.store.with_locked_exact(&expected, |transaction| {
            transaction.migration_commit_permit(proofs)
        })
    }

    pub(crate) fn commit_migration(
        &mut self,
        state: &State,
        permit: MigrationCommitPermit,
    ) -> Result<Committed<State>, StateStoreError> {
        if matches!(self.read.migration, MigrationStatus::None) {
            return Err(StateStoreError::Invalid(anyhow!(
                "migration commit is valid only for missing or legacy state"
            )));
        }
        let expected = self.read.revision.clone();
        let (receipt, after) = self.store.with_locked_exact(&expected, |transaction| {
            let receipt = transaction.commit_migration(state, permit)?;
            let after = transaction.snapshot()?;
            Ok((receipt, after))
        })?;
        self.read = after.clone();
        Ok(Committed {
            value: after.state.clone(),
            after,
            receipt,
        })
    }

    /// Explicitly bootstrap a completely missing store to an empty v2
    /// document.  The empty proof set is sealed by `migration_permit`; no
    /// credential material, account directory, or user home is consulted.
    pub(crate) fn bootstrap_empty_v2(&mut self) -> Result<Committed<State>, StateStoreError> {
        if !matches!(self.read.migration, MigrationStatus::Missing)
            || !self.read.state.accounts.is_empty()
            || !self.read.state.credential_refs.is_empty()
        {
            return Err(StateStoreError::Invalid(anyhow!(
                "empty v2 bootstrap requires a completely missing state"
            )));
        }
        let permit = self.migration_permit(Vec::new())?;
        let state = State {
            version: STATE_V2_VERSION,
            ..State::default()
        };
        self.commit_migration(&state, permit)
    }
}

/// A StateStore handle only retains a normalized root and target locator.
/// Claiming, adoption, recovery and locking are scoped to a transaction.
#[derive(Clone)]
pub(crate) struct StateStore {
    root: NormalizedStoreRoot,
    target: SafeRelativePath,
}

impl std::fmt::Debug for StateStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StateStore").finish_non_exhaustive()
    }
}

impl StateStore {
    pub(crate) fn open(path: &Path) -> Result<Self, StateStoreError> {
        let normalized = normalize_candidate(path).map_err(StateStoreError::Invalid)?;
        let target = target_locator().map_err(StateStoreError::Invalid)?;
        Ok(Self {
            root: normalized,
            target,
        })
    }

    /// Start one exact state session from a pure read.  The session owns the
    /// store handle and its read snapshot, so every subsequent commit can
    /// advance that same exact revision without asking callers to perform a
    /// manual compare-and-swap dance.
    pub(crate) fn session(&self) -> Result<StateSession, StateStoreError> {
        StateSession::from_store(self.clone())
    }

    /// State-layer bootstrap entry point.  This is intentionally pure: a
    /// missing root is represented by a Missing session until the caller
    /// explicitly requests the sealed empty-v2 bootstrap.
    pub(crate) fn bootstrap_exact(&self) -> Result<StateSession, StateStoreError> {
        self.session()
    }

    /// Pure read: no mkdir, lock, chmod, recovery, credential write or
    /// migration write is performed here.
    pub(crate) fn read(&self) -> Result<StateRead, StateStoreError> {
        let (snapshot, recovery_pending) =
            read_root_snapshot(&self.root, &self.target).map_err(StateStoreError::Invalid)?;
        let mut read = parse_snapshot(&snapshot).map_err(StateStoreError::Invalid)?;
        read.recovery_pending = recovery_pending;
        Ok(read)
    }

    /// Pure path read retained for diagnostics and tests. It validates the
    /// read-only root inventory but never claims or locks it.
    pub(crate) fn read_from_path(path: &Path) -> Result<StateRead, StateStoreError> {
        Self::open(path)?.read()
    }

    pub(crate) fn commit(
        &self,
        expected: &Revision,
        state: &State,
    ) -> std::result::Result<Revision, StateStoreError> {
        if !matches!(expected.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::MigrationRequired);
        }
        let mut committed = None;
        self.with_locked_exact(expected, |transaction| {
            committed = Some(transaction.commit_exact(state)?);
            Ok(())
        })?;
        committed
            .ok_or_else(|| StateStoreError::Invalid(anyhow!("state transaction did not commit")))
    }

    /// Perform the sealed one-time migration commit.  The caller must provide
    /// one durable credential-journal proof per account; ordinary `commit`
    /// cannot cross the missing/legacy boundary.
    pub(crate) fn commit_migration(
        &self,
        expected: &Revision,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        let mut committed = None;
        self.with_locked_exact(expected, |transaction| {
            let permit = transaction.migration_commit_permit(proofs)?;
            committed = Some(transaction.commit_migration(state, permit)?);
            Ok(())
        })?;
        committed.ok_or_else(|| StateStoreError::Invalid(anyhow!("state migration did not commit")))
    }

    pub(crate) fn commit_coordinated(
        &self,
        expected: &Revision,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        let mut committed = None;
        self.with_locked_exact(expected, |transaction| {
            committed = Some(transaction.commit_coordinated(state, proofs)?);
            Ok(())
        })?;
        committed.ok_or_else(|| {
            StateStoreError::Invalid(anyhow!("coordinated state transaction did not commit"))
        })
    }

    pub(crate) fn commit_coordinated_with_active(
        &self,
        expected: &Revision,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
        active_proof: ActiveHomeJournalProof,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        let mut committed = None;
        self.with_locked_exact(expected, |transaction| {
            committed = Some(transaction.commit_coordinated_with_active(
                state,
                proofs,
                Some(active_proof),
            )?);
            Ok(())
        })?;
        committed.ok_or_else(|| {
            StateStoreError::Invalid(anyhow!(
                "coordinated active-home state transaction did not commit"
            ))
        })
    }

    /// Execute an exact state transaction while keeping one filesystem lock.
    /// The closure may call `commit_exact` more than once; an error does not
    /// implicitly rollback an earlier commit.
    pub(crate) fn with_locked_exact<T, F>(
        &self,
        expected: &Revision,
        callback: F,
    ) -> std::result::Result<T, StateStoreError>
    where
        F: FnOnce(&mut LockedStateTxn<'_>) -> std::result::Result<T, StateStoreError>,
    {
        // Compare before claim/adoption so stale expectations fail without a
        // filesystem side effect. `StateStore::commit` rejects legacy/missing
        // generations before entering this mutation API; this lower-level
        // transaction remains available for a future sealed migration permit.
        let observed = self.read()?;
        ensure_revision(expected, &observed.revision)?;
        let expected_digest = digest_from_revision(expected).map_err(StateStoreError::Invalid)?;
        let Some(metadata) = root_metadata(&self.root).map_err(StateStoreError::Invalid)? else {
            // This branch is retained for a future sealed migration permit;
            // Current revisions cannot normally observe a missing root after
            // the pure comparison above.
            let claim_root = normalize_for_claim(&self.root).map_err(StateStoreError::Invalid)?;
            let owned = OwnedStoreRoot::claim(claim_root).map_err(StateStoreError::Invalid)?;
            let store =
                AtomicStore::new(owned, self.target.clone()).map_err(StateStoreError::Invalid)?;
            let guard = store.lock_exact(expected_digest)?;
            let snapshot = guard.read_snapshot().map_err(StateStoreError::Invalid)?;
            let current = parse_snapshot(&snapshot).map_err(StateStoreError::Invalid)?;
            ensure_revision(expected, &current.revision)?;
            let mut txn = LockedStateTxn::new(&guard, current.revision, self.root.clone());
            return callback(&mut txn);
        };
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            return Err(StateStoreError::Invalid(anyhow!(
                "state root is not a regular directory"
            )));
        }
        if directory_is_empty(self.root.as_path()).map_err(StateStoreError::Invalid)? {
            let claim_root = normalize_for_claim(&self.root).map_err(StateStoreError::Invalid)?;
            let owned = OwnedStoreRoot::claim(claim_root).map_err(StateStoreError::Invalid)?;
            let store =
                AtomicStore::new(owned, self.target.clone()).map_err(StateStoreError::Invalid)?;
            let guard = store.lock_exact(expected_digest)?;
            let snapshot = guard.read_snapshot().map_err(StateStoreError::Invalid)?;
            let current = parse_snapshot(&snapshot).map_err(StateStoreError::Invalid)?;
            ensure_revision(expected, &current.revision)?;
            let mut txn = LockedStateTxn::new(&guard, current.revision, self.root.clone());
            return callback(&mut txn);
        }

        let mutation_root = normalize_for_claim(&self.root).map_err(StateStoreError::Invalid)?;
        let preflight = AtomicStore::preflight_existing(&mutation_root, self.target.clone())?;
        validate_adoption_root(&mutation_root, &preflight).map_err(StateStoreError::Invalid)?;
        let validator_root = mutation_root.clone();
        let adopted = unsafe {
            AtomicStore::adopt_existing_with(
                mutation_root.clone(),
                self.target.clone(),
                &preflight,
                move |current| validate_adoption_root(&validator_root, current),
            )
        }?;
        let _ = adopted.recover()?;
        let snapshot = adopted.check_exact(ExpectedDigest::Exact(expected_digest))?;
        let current = parse_snapshot(&snapshot).map_err(StateStoreError::Invalid)?;
        ensure_revision(expected, &current.revision)?;
        let mut txn = LockedStateTxn::new(&adopted, current.revision, mutation_root);
        callback(&mut txn)
    }
}

/// A state transaction over one already-held AtomicStore lock.
pub(crate) struct LockedStateTxn<'a> {
    guard: &'a LockedAtomicStore,
    revision: Revision,
    root: NormalizedStoreRoot,
}

impl<'a> LockedStateTxn<'a> {
    fn new(guard: &'a LockedAtomicStore, revision: Revision, root: NormalizedStoreRoot) -> Self {
        Self {
            guard,
            revision,
            root,
        }
    }

    /// Mint a credential-store capability for one validated account while the
    /// state lock remains held.  Migration callers must use
    /// [`Self::migration_commit_permit`] before writing a v2 document.
    pub(crate) fn credential_mutation_permit(
        &self,
        account_id: &str,
    ) -> std::result::Result<CredentialMutationPermit, StateStoreError> {
        validate_account_id(account_id).map_err(StateStoreError::Invalid)?;
        // A transaction may add a new account.  The state lock and validated
        // account component are the authority; membership is checked later
        // when the candidate v2 state and credential reference are committed.
        let capability = self
            .guard
            .account_capability(account_id)
            .map_err(StateStoreError::Invalid)?;
        let snapshot = self.snapshot()?;
        Ok(CredentialMutationPermit {
            capability,
            account_id: account_id.to_string(),
            state_revision: self.revision.clone(),
            before_ref: snapshot.state.credential_refs.get(account_id).cloned(),
            mode: if matches!(self.revision.generation, RevisionGeneration::Current(_)) {
                CredentialMutationMode::CurrentExact
            } else {
                CredentialMutationMode::Migration
            },
        })
    }

    /// Mint the only capability accepted by the active-home adapter. The
    /// profile and credential reference are copied under the State lock so a
    /// caller cannot switch the target while home locks are being acquired.
    pub(crate) fn active_home_mutation_permit(
        &self,
        target_profile: Option<ActiveProfile>,
    ) -> std::result::Result<ActiveHomeMutationPermit, StateStoreError> {
        let snapshot = self.snapshot()?;
        let target_ref = match target_profile.as_ref() {
            Some(profile) => snapshot
                .state
                .credential_refs
                .get(&profile.account_id)
                .cloned(),
            None => snapshot
                .state
                .active_profile
                .as_ref()
                .and_then(|profile| snapshot.state.credential_refs.get(&profile.account_id))
                .cloned(),
        };
        self.active_home_mutation_permit_with_ref(target_profile, target_ref)
    }

    /// Variant used when one coordinated commit creates the target account
    /// and credential reference in the same State CAS.
    pub(crate) fn active_home_mutation_permit_with_ref(
        &self,
        target_profile: Option<ActiveProfile>,
        target_ref: Option<CredentialRef>,
    ) -> std::result::Result<ActiveHomeMutationPermit, StateStoreError> {
        let snapshot = self.snapshot()?;
        let before_profile = snapshot.state.active_profile.clone();
        let home_scope_id = target_profile
            .as_ref()
            .map(|profile| profile.home_scope_id.clone())
            .or_else(|| {
                before_profile
                    .as_ref()
                    .map(|profile| profile.home_scope_id.clone())
            });
        if let (Some(target), Some(before)) = (
            target_profile
                .as_ref()
                .map(|profile| profile.home_scope_id.as_str()),
            before_profile
                .as_ref()
                .map(|profile| profile.home_scope_id.as_str()),
        ) && target != before
        {
            return Err(StateStoreError::Invalid(anyhow!(
                "active-home target and before profiles use different home scopes"
            )));
        }
        let account_id = target_profile
            .as_ref()
            .map(|profile| profile.account_id.clone())
            .or_else(|| {
                before_profile
                    .as_ref()
                    .map(|profile| profile.account_id.clone())
            })
            .ok_or_else(|| {
                StateStoreError::Invalid(anyhow!(
                    "active-home delete requires an existing active profile"
                ))
            })?;
        validate_account_id(&account_id).map_err(StateStoreError::Invalid)?;
        if let Some(profile) = target_profile.as_ref() {
            if profile.account_id != account_id {
                return Err(StateStoreError::Invalid(anyhow!(
                    "active-home target account differs from permit account"
                )));
            }
            validate_active_profile_shape(profile).map_err(StateStoreError::Invalid)?;
            if let Some(reference) = target_ref.as_ref()
                && profile.credential_fingerprint != reference.fingerprint
            {
                return Err(StateStoreError::Invalid(anyhow!(
                    "active-home target reference differs from target profile"
                )));
            }
        }
        let capability = self
            .guard
            .account_capability(&account_id)
            .map_err(StateStoreError::Invalid)?;
        Ok(ActiveHomeMutationPermit {
            capability,
            account_id,
            base_revision: self.revision.clone(),
            before_profile,
            target_profile,
            target_ref,
            home_scope_id,
        })
    }

    /// Recovery may need the account capability after the committed State has
    /// already removed the account/profile. This endpoint still requires the
    /// State lock and a validated account component, but deliberately carries
    /// no caller-supplied profile or path evidence; the durable journal is
    /// checked by the active-home recovery function.
    pub(crate) fn active_home_recovery_permit(
        &self,
        account_id: &str,
    ) -> std::result::Result<ActiveHomeMutationPermit, StateStoreError> {
        validate_account_id(account_id).map_err(StateStoreError::Invalid)?;
        let snapshot = self.snapshot()?;
        let home_scope_id = snapshot
            .state
            .active_profile
            .as_ref()
            .map(|profile| profile.home_scope_id.clone());
        let capability = self
            .guard
            .account_capability(account_id)
            .map_err(StateStoreError::Invalid)?;
        Ok(ActiveHomeMutationPermit {
            capability,
            account_id: account_id.to_string(),
            base_revision: self.revision.clone(),
            before_profile: snapshot.state.active_profile,
            target_profile: None,
            target_ref: snapshot.state.credential_refs.get(account_id).cloned(),
            home_scope_id,
        })
    }

    /// Mint a proof of the exact current credential-reference map while the
    /// state lock is retained.  Legacy and missing generations deliberately
    /// cannot mint this proof because they have no v2 commit receipt.
    pub(crate) fn current_credential_ref_proof(
        &self,
    ) -> std::result::Result<CurrentCredentialRefProof, StateStoreError> {
        if !matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::MigrationRequired);
        }
        let snapshot = self.snapshot()?;
        ensure_revision(&self.revision, &snapshot.revision)?;
        Ok(CurrentCredentialRefProof {
            revision: snapshot.revision,
            credential_refs: snapshot.state.credential_refs,
        })
    }

    pub(crate) fn legacy_recovery_proof(
        &self,
    ) -> std::result::Result<LegacyRecoveryProof, StateStoreError> {
        if matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::Invalid(anyhow!(
                "legacy recovery proof cannot be minted for current state"
            )));
        }
        Ok(LegacyRecoveryProof {
            revision: self.revision.clone(),
        })
    }

    pub(crate) fn recovery_authority(
        &self,
    ) -> std::result::Result<RecoveryAuthority, StateStoreError> {
        if matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            Ok(RecoveryAuthority::Current(
                self.current_credential_ref_proof()?,
            ))
        } else {
            Ok(RecoveryAuthority::Legacy(self.legacy_recovery_proof()?))
        }
    }

    /// Mint an active-home-only recovery authority. It never exposes the
    /// credential reference map and therefore cannot be reused to finalize a
    /// credential journal.
    pub(crate) fn active_home_recovery_authority(
        &self,
    ) -> std::result::Result<ActiveHomeRecoveryAuthority, StateStoreError> {
        let snapshot = self.snapshot()?;
        ensure_revision(&self.revision, &snapshot.revision)?;
        match self.revision.generation {
            RevisionGeneration::Current(_) => Ok(ActiveHomeRecoveryAuthority::Current(
                ActiveHomeCurrentProof {
                    revision: snapshot.revision,
                    active_profile: snapshot.state.active_profile,
                },
            )),
            RevisionGeneration::Missing | RevisionGeneration::Legacy => {
                Ok(ActiveHomeRecoveryAuthority::Legacy(ActiveHomeLegacyProof {
                    revision: self.revision.clone(),
                }))
            }
        }
    }

    /// Enumerate the capability-owned account directory set.  This is kept on
    /// the locked transaction so recovery cannot race a root/path read or
    /// manufacture an account capability from an arbitrary absolute path.
    pub(crate) fn account_ids(&self) -> std::result::Result<Vec<String>, StateStoreError> {
        self.guard.account_ids().map_err(StateStoreError::Invalid)
    }

    /// Seal the one-time migration proof after each account's credential
    /// journal has been durably staged.  The permit has no public constructor.
    pub(crate) fn migration_commit_permit(
        &self,
        proofs: Vec<CredentialJournalProof>,
    ) -> std::result::Result<MigrationCommitPermit, StateStoreError> {
        if matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::Invalid(anyhow!(
                "migration permit is valid only for missing or legacy state"
            )));
        }
        let snapshot = self.snapshot()?;
        let expected_ids: BTreeSet<&str> = snapshot
            .state
            .accounts
            .iter()
            .map(|account| account.id.as_str())
            .collect();
        let actual_ids: BTreeSet<&str> = proofs
            .iter()
            .map(|proof| proof.account_id.as_str())
            .collect();
        if !expected_ids.is_subset(&actual_ids) || proofs.len() != actual_ids.len() {
            return Err(StateStoreError::Invalid(anyhow!(
                "credential journal proof set does not cover the legacy state"
            )));
        }
        for proof in &proofs {
            let capability = self
                .guard
                .account_capability(&proof.account_id)
                .map_err(StateStoreError::Invalid)?;
            validate_durable_credential_proof(&capability, proof)
                .map_err(StateStoreError::Invalid)?;
        }
        Ok(MigrationCommitPermit {
            expected: self.revision.clone(),
            proofs,
        })
    }

    pub(crate) fn snapshot(&self) -> std::result::Result<StateRead, StateStoreError> {
        let snapshot = self
            .guard
            .read_snapshot()
            .map_err(StateStoreError::Invalid)?;
        parse_snapshot(&snapshot).map_err(StateStoreError::Invalid)
    }

    pub(crate) fn commit_exact(
        &mut self,
        state: &State,
    ) -> std::result::Result<Revision, StateStoreError> {
        if !matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::MigrationRequired);
        }
        self.commit_state(state, false)
            .map(|receipt| receipt.revision)
    }

    /// Current-generation exact commit returning an ordinary receipt. It has
    /// no credential transitions and therefore cannot authorize finalization;
    /// credential mutations must use [`Self::commit_coordinated`].
    pub(crate) fn commit_exact_receipt(
        &mut self,
        state: &State,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        if !matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::MigrationRequired);
        }
        self.commit_state(state, false)
    }

    pub(crate) fn commit_migration(
        &mut self,
        state: &State,
        permit: MigrationCommitPermit,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        if permit.expected != self.revision {
            return Err(StateStoreError::Conflict {
                expected: permit.expected,
                actual: self.revision.clone(),
            });
        }
        if permit.proofs.is_empty() {
            if !state.accounts.is_empty() || !state.credential_refs.is_empty() {
                return Err(StateStoreError::Invalid(anyhow!(
                    "empty migration proof set may only bootstrap an empty v2 state"
                )));
            }
            self.commit_state(state, true)
        } else {
            self.commit_coordinated(state, permit.proofs)
        }
    }

    /// Commit a candidate state together with the exact durable credential
    /// transitions that were published under this state lock.  Every proof is
    /// checked against the pre-commit snapshot and the candidate before any
    /// bytes are written.  Ordinary commits deliberately never manufacture
    /// these transitions, so they cannot grant credential-finalize authority.
    pub(crate) fn commit_coordinated(
        &mut self,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        self.commit_coordinated_with_active(state, proofs, None)
    }

    /// Commit credential and active-home evidence in one state CAS.  An
    /// active-home proof is optional for credential-only operations, but a
    /// profile transition without one is rejected below.
    pub(crate) fn commit_coordinated_with_active(
        &mut self,
        state: &State,
        proofs: Vec<CredentialJournalProof>,
        active_proof: Option<ActiveHomeJournalProof>,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        if proofs.is_empty() && active_proof.is_none() {
            return Err(StateStoreError::Invalid(anyhow!(
                "coordinated commit requires credential or active-home proof"
            )));
        }
        let before = self.snapshot()?;
        let transitions = self.validate_coordinated_proofs(&before.state, state, &proofs)?;
        let active_transition = active_proof
            .as_ref()
            .map(|proof| self.validate_active_home_proof(&before.state, state, proof))
            .transpose()?;
        self.commit_state_with_transitions(
            state,
            !matches!(self.revision.generation, RevisionGeneration::Current(_)),
            transitions,
            active_transition,
        )
    }

    fn validate_coordinated_proofs(
        &self,
        before: &State,
        candidate: &State,
        proofs: &[CredentialJournalProof],
    ) -> std::result::Result<Vec<CredentialCommitTransition>, StateStoreError> {
        let mut accounts = BTreeSet::new();
        let mut txids = BTreeSet::new();
        let mut transitions = Vec::with_capacity(proofs.len());
        for proof in proofs {
            if !accounts.insert(proof.account_id.clone()) {
                return Err(StateStoreError::Invalid(anyhow!(
                    "coordinated credential proof repeats an account"
                )));
            }
            if !txids.insert(proof.txid) {
                return Err(StateStoreError::Invalid(anyhow!(
                    "coordinated credential proof repeats a transaction"
                )));
            }
            if proof.base_revision != self.revision {
                return Err(StateStoreError::Conflict {
                    expected: self.revision.clone(),
                    actual: proof.base_revision.clone(),
                });
            }
            let capability = self
                .guard
                .account_capability(&proof.account_id)
                .map_err(StateStoreError::Invalid)?;
            validate_durable_credential_proof(&capability, proof)
                .map_err(StateStoreError::Invalid)?;
            let before_ref = before.credential_refs.get(&proof.account_id);
            let after_ref = candidate.credential_refs.get(&proof.account_id);
            if before_ref != proof.before_ref() {
                return Err(StateStoreError::Invalid(anyhow!(
                    "credential journal before reference differs from durable state"
                )));
            }
            if after_ref != proof.after_ref() {
                return Err(StateStoreError::Invalid(anyhow!(
                    "credential journal after reference differs from candidate state"
                )));
            }
            transitions.push(CredentialCommitTransition {
                account_id: proof.account_id.clone(),
                txid: proof.txid,
                base_revision: proof.base_revision.clone(),
                // Filled with the actual committed revision immediately
                // before the state bytes are published.
                committed_revision: Revision {
                    generation: RevisionGeneration::Missing,
                    document_sha256: None,
                },
                before_ref: proof.before_ref.clone(),
                after_ref: proof.after_ref.clone(),
            });
        }
        let changed_ids: BTreeSet<&str> = before
            .credential_refs
            .keys()
            .chain(candidate.credential_refs.keys())
            .filter(|account_id| {
                before.credential_refs.get(*account_id)
                    != candidate.credential_refs.get(*account_id)
            })
            .map(String::as_str)
            .collect();
        let proof_ids: BTreeSet<&str> = accounts.iter().map(String::as_str).collect();
        if !changed_ids.is_subset(&proof_ids) {
            return Err(StateStoreError::Invalid(anyhow!(
                "coordinated credential proof set does not cover every credential reference change"
            )));
        }
        Ok(transitions)
    }

    fn validate_active_home_proof(
        &self,
        before: &State,
        candidate: &State,
        proof: &ActiveHomeJournalProof,
    ) -> std::result::Result<ActiveHomeCommitTransition, StateStoreError> {
        if proof.base_revision != self.revision {
            return Err(StateStoreError::Conflict {
                expected: self.revision.clone(),
                actual: proof.base_revision.clone(),
            });
        }
        if before.active_profile != proof.before_profile {
            return Err(StateStoreError::Invalid(anyhow!(
                "active-home journal before profile differs from State"
            )));
        }
        if candidate.active_profile != proof.after_profile {
            return Err(StateStoreError::Invalid(anyhow!(
                "active-home journal after profile differs from candidate State"
            )));
        }
        let expected_ref = candidate
            .credential_refs
            .get(&proof.account_id)
            .or_else(|| before.credential_refs.get(&proof.account_id));
        if expected_ref != proof.target_ref.as_ref() {
            return Err(StateStoreError::Invalid(anyhow!(
                "active-home target credential reference differs from State transition"
            )));
        }
        let capability = self
            .guard
            .account_capability(&proof.account_id)
            .map_err(StateStoreError::Invalid)?;
        validate_durable_active_home_proof(&capability, proof).map_err(StateStoreError::Invalid)?;
        Ok(ActiveHomeCommitTransition {
            account_id: proof.account_id.clone(),
            txid: proof.txid,
            journal_digest: proof.journal_digest.clone(),
            base_revision: proof.base_revision.clone(),
            committed_revision: Revision {
                generation: RevisionGeneration::Missing,
                document_sha256: None,
            },
            before_profile: proof.before_profile.clone(),
            after_profile: proof.after_profile.clone(),
            target_ref: proof.target_ref.clone(),
        })
    }

    fn commit_state(
        &mut self,
        state: &State,
        allow_migration: bool,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        self.commit_state_with_transitions(state, allow_migration, Vec::new(), None)
    }

    fn commit_state_with_transitions(
        &mut self,
        state: &State,
        allow_migration: bool,
        mut transitions: Vec<CredentialCommitTransition>,
        mut active_transition: Option<ActiveHomeCommitTransition>,
    ) -> std::result::Result<StateCommitReceipt, StateStoreError> {
        if !allow_migration && !matches!(self.revision.generation, RevisionGeneration::Current(_)) {
            return Err(StateStoreError::MigrationRequired);
        }
        let generation =
            next_generation(self.revision.generation).map_err(StateStoreError::Invalid)?;
        let revision_number = match generation {
            RevisionGeneration::Current(value) => value,
            RevisionGeneration::Missing | RevisionGeneration::Legacy => unreachable!(),
        };
        let mut next = state.clone();
        next.version = STATE_V2_VERSION;
        next.revision = revision_number;
        if active_transition.is_none() || transitions.is_empty() {
            let before = self.snapshot()?;
            if active_transition.is_none() && before.state.active_profile != next.active_profile {
                return Err(StateStoreError::Invalid(anyhow!(
                    "active profile transition requires a sealed active-home journal proof"
                )));
            }
            // 凭据引用与 active profile 同级: 没有一条 credential transition 的
            // 普通提交绝不能改动 credential_refs, 否则调用方只要绕开
            // commit_coordinated 就能删掉别人的账号引用而不留任何证明。
            // 有 transition 时的逐条覆盖率校验在 validate_coordinated_proofs 里。
            if transitions.is_empty() && before.state.credential_refs != next.credential_refs {
                return Err(StateStoreError::Invalid(anyhow!(
                    "credential reference transition requires a sealed credential journal proof"
                )));
            }
        }
        validate_state_invariants(&next).map_err(StateStoreError::Invalid)?;
        let bytes = encode_v2(&next).map_err(StateStoreError::Invalid)?;
        let expected_digest =
            digest_from_revision(&self.revision).map_err(StateStoreError::Invalid)?;
        let receipt = self
            .guard
            .commit_exact(expected_digest, &bytes)
            .map_err(StateStoreError::Atomic)?;
        let result = Revision {
            generation: RevisionGeneration::Current(revision_number),
            document_sha256: Some(receipt.digest.to_hex()),
        };
        for transition in &mut transitions {
            transition.committed_revision = result.clone();
        }
        if let Some(transition) = active_transition.as_mut() {
            transition.committed_revision = result.clone();
        }
        let transition_map = transitions
            .into_iter()
            .map(|transition| (transition.account_id.clone(), transition))
            .collect();
        let state_receipt = StateCommitReceipt {
            revision: result.clone(),
            transitions: transition_map,
            active_home_transition: active_transition,
        };
        self.revision = result.clone();
        Ok(state_receipt)
    }
}

fn ensure_revision(
    expected: &Revision,
    actual: &Revision,
) -> std::result::Result<(), StateStoreError> {
    if expected == actual {
        Ok(())
    } else {
        Err(StateStoreError::Conflict {
            expected: expected.clone(),
            actual: actual.clone(),
        })
    }
}

fn next_generation(generation: RevisionGeneration) -> Result<RevisionGeneration> {
    let value = match generation {
        RevisionGeneration::Missing | RevisionGeneration::Legacy => 1,
        RevisionGeneration::Current(value) => value
            .checked_add(1)
            .ok_or_else(|| anyhow!("state revision overflow"))?,
    };
    Ok(RevisionGeneration::Current(value))
}

fn digest_from_revision(revision: &Revision) -> Result<Option<DocumentDigest>> {
    let Some(value) = revision.document_sha256.as_deref() else {
        return Ok(None);
    };
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
    {
        bail!("revision document_sha256 must be a lowercase SHA-256 digest");
    }
    DocumentDigest::from_hex(value).map(Some)
}

fn validate_durable_credential_proof(
    capability: &AccountStoreCapability,
    proof: &CredentialJournalProof,
) -> Result<()> {
    let journal = capability.locator(&format!(".sagy-credential-{}.journal", proof.txid))?;
    let bytes = capability
        .read_bounded(&journal, CREDENTIAL_JOURNAL_MAX_BYTES)?
        .ok_or_else(|| anyhow!("credential journal proof references a missing journal"))?;
    let mut digest = Sha256::new();
    digest.update(&bytes);
    let actual = format!("{:x}", digest.finalize());
    if actual != proof.journal_digest {
        bail!("credential journal proof digest does not match durable bytes");
    }
    let value = strict_json_value(&bytes)?;
    validate_credential_journal_value(&value, proof)?;
    Ok(())
}

fn validate_durable_active_home_proof(
    capability: &AccountStoreCapability,
    proof: &ActiveHomeJournalProof,
) -> Result<()> {
    let journal_name = format!(
        "{ACTIVE_HOME_JOURNAL_PREFIX}{}{ACTIVE_HOME_JOURNAL_SUFFIX}",
        proof.txid
    );
    let journal = capability.locator(&journal_name)?;
    let bytes = capability
        .read_bounded(&journal, ACTIVE_HOME_JOURNAL_MAX_BYTES)?
        .ok_or_else(|| anyhow!("active-home journal proof references a missing journal"))?;
    let mut digest = Sha256::new();
    digest.update(&bytes);
    let actual = format!("{:x}", digest.finalize());
    if actual != proof.journal_digest {
        bail!("active-home journal proof digest does not match durable bytes");
    }
    let value = strict_json_value(&bytes)?;
    validate_active_home_journal_value(&value, proof)
}

fn validate_active_home_journal_value(value: &Value, proof: &ActiveHomeJournalProof) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("active-home journal must be a JSON object"))?;
    require_exact_keys(
        object,
        &[
            "journal_version",
            "txid",
            "phase",
            "account_id",
            "base_revision",
            "before_profile",
            "after_profile",
            "target_ref",
            "mode",
            "state_before_layout",
            "before_layout",
            "after_layout",
            "token_stage",
            "token_stage_digest",
            "token_tombstone",
            "token_tombstone_digest",
            "document_stage",
            "document_stage_digest",
            "document_tombstone",
            "document_tombstone_digest",
        ],
    )?;
    if object.get("journal_version").and_then(Value::as_u64) != Some(1) {
        bail!("active-home journal version is unsupported");
    }
    if object.get("txid").and_then(Value::as_str) != Some(&proof.txid.to_string()) {
        bail!("active-home journal transaction id does not match proof");
    }
    if object.get("phase").and_then(Value::as_str) != Some("published") {
        bail!("active-home proof must reference a published journal");
    }
    if object.get("account_id").and_then(Value::as_str) != Some(proof.account_id.as_str()) {
        bail!("active-home journal account id does not match proof");
    }
    if journal_revision_value(object.get("base_revision"))? != proof.base_revision {
        bail!("active-home journal base revision does not match proof");
    }

    let before_profile = parse_optional_active_profile(object, "before_profile")?;
    let after_profile = parse_optional_active_profile(object, "after_profile")?;
    if before_profile != proof.before_profile || after_profile != proof.after_profile {
        bail!("active-home journal profile transition does not match proof");
    }
    let target_ref = credential_ref_value(object.get("target_ref"))?;
    if target_ref != proof.target_ref {
        bail!("active-home journal target reference does not match proof");
    }
    if let (Some(reference), Some(profile)) = (target_ref.as_ref(), after_profile.as_ref()) {
        validate_active_layout_for_reference(reference.kind, &profile.managed_layout)?;
    }
    if object.get("mode").and_then(Value::as_str) != Some(proof.adoption_mode.as_str()) {
        bail!("active-home journal adoption mode does not match proof");
    }
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("active-home journal mode is missing"))?;
    if !matches!(mode, "strict" | "adopt" | "takeover") {
        bail!("active-home journal adoption mode is invalid");
    }
    let state_before_layout = object
        .get("state_before_layout")
        .ok_or_else(|| anyhow!("active-home journal is missing state_before_layout"))?;
    if layout_value_from_profile(before_profile.as_ref()) != *state_before_layout {
        bail!("active-home state-before layout evidence does not match profile transition");
    }
    let before_layout = object
        .get("before_layout")
        .ok_or_else(|| anyhow!("active-home journal is missing before_layout"))?;
    let after_layout = object
        .get("after_layout")
        .ok_or_else(|| anyhow!("active-home journal is missing after_layout"))?;
    if layout_value_from_profile(after_profile.as_ref()) != *after_layout {
        bail!("active-home journal after layout evidence does not match profile transition");
    }
    if serde_json::to_value(proof.before_layout.clone()).expect("layout serializable")
        != *before_layout
        || serde_json::to_value(proof.after_layout.clone()).expect("layout serializable")
            != *after_layout
    {
        bail!("active-home journal observed layout evidence does not match proof");
    }
    let state_before: ManagedLayout = serde_json::from_value(state_before_layout.clone())
        .context("invalid active-home state-before layout")?;
    let observed_before: ManagedLayout = serde_json::from_value(before_layout.clone())
        .context("invalid active-home before layout")?;
    let observed_after: ManagedLayout =
        serde_json::from_value(after_layout.clone()).context("invalid active-home after layout")?;
    if mode != "takeover" {
        if before_profile.is_some() && state_before != observed_before {
            bail!("strict/adopt active-home before layout differs from State");
        }
        if before_profile.is_none() && mode == "adopt" && observed_before != observed_after {
            bail!("adopted first active-home layout differs from target");
        }
        if before_profile.is_none()
            && mode == "strict"
            && observed_before != ManagedLayout::default()
        {
            bail!("strict first active-home layout must start empty");
        }
    }
    let before_layout_wire = observed_before;
    let after_layout_wire = observed_after;
    for (prefix, before_slot, after_slot) in [
        (
            "token",
            &before_layout_wire.antigravity_token,
            &after_layout_wire.antigravity_token,
        ),
        (
            "document",
            &before_layout_wire.gemini_authorized_user,
            &after_layout_wire.gemini_authorized_user,
        ),
    ] {
        let stage_digest = object
            .get(&format!("{prefix}_stage_digest"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-home journal stage digest is missing"))?;
        let tombstone_digest = object
            .get(&format!("{prefix}_tombstone_digest"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-home journal tombstone digest is missing"))?;
        if stage_digest != slot_state_digest(after_slot)
            || tombstone_digest != slot_state_digest(before_slot)
        {
            bail!("active-home journal slot digest evidence does not match layout");
        }
    }

    validate_active_home_locator(
        object,
        "token_stage",
        &format!(".sagy-active-home-{}.token.stage", proof.txid),
    )?;
    validate_active_home_locator(
        object,
        "document_stage",
        &format!(".sagy-active-home-{}.document.stage", proof.txid),
    )?;
    validate_active_home_locator(
        object,
        "token_tombstone",
        &format!(".sagy-active-home-{}.token.tombstone", proof.txid),
    )?;
    validate_active_home_locator(
        object,
        "document_tombstone",
        &format!(".sagy-active-home-{}.document.tombstone", proof.txid),
    )?;
    for field in [
        "token_stage_digest",
        "token_tombstone_digest",
        "document_stage_digest",
        "document_tombstone_digest",
    ] {
        let value = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-home journal field {field} must be a string"))?;
        if !value.is_empty() {
            validate_journal_digest(field, value)?;
        }
    }
    Ok(())
}

fn slot_state_digest(slot: &super::state::SlotState) -> &str {
    match slot {
        super::state::SlotState::Absent => "",
        super::state::SlotState::Exact { sha256 } => sha256.as_str(),
    }
}

fn parse_optional_active_profile(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<ActiveProfile>> {
    let value = object
        .get(field)
        .ok_or_else(|| anyhow!("active-home journal is missing {field}"))?;
    if value.is_null() {
        return Ok(None);
    }
    let profile: ActiveProfile = serde_json::from_value(value.clone())
        .with_context(|| format!("invalid active-home journal {field}"))?;
    validate_active_profile_shape(&profile)?;
    Ok(Some(profile))
}

fn layout_value_from_profile(profile: Option<&ActiveProfile>) -> Value {
    profile
        .map(|profile| {
            serde_json::to_value(&profile.managed_layout).expect("layout is serializable")
        })
        .unwrap_or_else(|| {
            serde_json::to_value(ManagedLayout::default()).expect("layout serializable")
        })
}

fn validate_active_home_locator(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<()> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("active-home journal field {field} must be a string"))?;
    if value != expected {
        bail!("active-home journal locator {field} does not match transaction");
    }
    Ok(())
}

fn validate_credential_journal_value(value: &Value, proof: &CredentialJournalProof) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("credential journal must be a JSON object"))?;
    require_exact_keys(
        object,
        &[
            "journal_version",
            "txid",
            "phase",
            "base_revision",
            "before_ref",
            "after_ref",
            "before",
            "after",
            "stage",
            "stage_digest",
            "token_backup",
            "token_backup_digest",
            "document_backup",
            "document_backup_digest",
            "token_tombstone",
            "token_tombstone_digest",
            "document_tombstone",
            "document_tombstone_digest",
        ],
    )?;
    if object.get("journal_version").and_then(Value::as_u64) != Some(2) {
        bail!("credential journal version is unsupported");
    }
    if object.get("txid").and_then(Value::as_str) != Some(&proof.txid.to_string()) {
        bail!("credential journal transaction id does not match proof");
    }
    if object.get("phase").and_then(Value::as_str) != Some("published") {
        bail!("credential journal proof must reference a published phase");
    }

    let base_revision = journal_revision_value(object.get("base_revision"))?;
    if base_revision != *proof.base_revision() {
        bail!("credential journal base revision does not match proof");
    }
    let before_ref = credential_ref_value(object.get("before_ref"))?;
    let after_ref = credential_ref_value(object.get("after_ref"))?;
    if before_ref != proof.before_ref().cloned() || after_ref != proof.after_ref().cloned() {
        bail!("credential journal credential transition does not match proof");
    }

    let before = journal_layout_value(object, "before")?;
    let after = journal_layout_value(object, "after")?;
    let (after_kind, after_fingerprint, after_digest, after_slot) = {
        let token = before_or_after_descriptor(after, "token")?;
        let document = before_or_after_descriptor(after, "document")?;
        match (token, document) {
            (Some((kind, fingerprint, digest)), None) => {
                if !matches!(
                    kind,
                    CredentialRefKind::OauthAccessToken | CredentialRefKind::AntigravityToken
                ) {
                    bail!("token journal slot has a non-token credential kind");
                }
                (kind, fingerprint, digest, "token")
            }
            (None, Some((kind, fingerprint, digest))) => {
                if matches!(
                    kind,
                    CredentialRefKind::OauthAccessToken | CredentialRefKind::AntigravityToken
                ) {
                    bail!("document journal slot has a raw token kind");
                }
                (kind, fingerprint, digest, "document")
            }
            (None, None) => {
                if after_ref.is_some() {
                    bail!("empty credential after layout has a non-empty after ref");
                }
                (
                    CredentialRefKind::OauthAccessToken,
                    String::new(),
                    String::new(),
                    "none",
                )
            }
            _ => bail!("credential journal after layout contains multiple slots"),
        }
    };
    if let Some(after_ref) = &after_ref {
        if after_kind != after_ref.kind || after_fingerprint != after_ref.fingerprint {
            bail!("credential journal after reference does not match after layout");
        }
    }
    if after_slot != "none"
        && object.get("stage_digest").and_then(Value::as_str) != Some(after_digest.as_str())
    {
        bail!("credential journal stage digest does not match after descriptor");
    }
    if proof.after_ref().is_some() && after_slot == "none" {
        bail!("proof after reference has no after layout slot");
    }

    let txid = proof.txid;
    let expected_stage = format!(".sagy-credential-{}.stage", txid);
    let expected_token_tombstone = format!(".sagy-credential-{}.token.tombstone", txid);
    let expected_document_tombstone = format!(".sagy-credential-{}.document.tombstone", txid);
    let stage = required_string(object, "stage")?;
    if stage != expected_stage {
        bail!("credential journal stage locator does not match transaction");
    }
    if required_string(object, "token_tombstone")? != expected_token_tombstone
        || required_string(object, "document_tombstone")? != expected_document_tombstone
    {
        bail!("credential journal tombstone locator does not match transaction");
    }
    let before_token = before_or_after_descriptor(before, "token")?;
    let before_document = before_or_after_descriptor(before, "document")?;
    validate_journal_evidence_value(
        object,
        "token",
        before_token.as_ref().map(|(_, _, digest)| digest.as_str()),
        &expected_token_tombstone,
    )?;
    validate_journal_evidence_value(
        object,
        "document",
        before_document
            .as_ref()
            .map(|(_, _, digest)| digest.as_str()),
        &expected_document_tombstone,
    )?;
    let _ = after_slot;
    Ok(())
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<()> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        bail!("credential journal has unknown or missing fields");
    }
    Ok(())
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
        .ok_or_else(|| anyhow!("credential journal field {key} must be a safe filename"))
}

fn optional_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    let value = object
        .get(key)
        .ok_or_else(|| anyhow!("credential journal field {key} is missing"))?;
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(
        value
            .as_str()
            .filter(|value| !value.is_empty() && !value.contains('/') && !value.contains('\\'))
            .ok_or_else(|| anyhow!("credential journal field {key} must be a safe filename"))?,
    ))
}

fn journal_layout_value<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>> {
    let value = object
        .get(key)
        .ok_or_else(|| anyhow!("credential journal layout {key} is missing"))?;
    let layout = value
        .as_object()
        .ok_or_else(|| anyhow!("credential journal layout {key} is not an object"))?;
    require_exact_keys(layout, &["token", "document"])?;
    Ok(layout)
}

fn journal_revision_value(value: Option<&Value>) -> Result<Revision> {
    let object = value
        .ok_or_else(|| anyhow!("credential journal base revision is missing"))?
        .as_object()
        .ok_or_else(|| anyhow!("credential journal base revision is not an object"))?;
    require_exact_keys(object, &["generation", "revision", "document_sha256"])?;
    let generation = object
        .get("generation")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("credential journal base generation is invalid"))?;
    let revision = match generation {
        "missing" => {
            if !object.get("revision").is_some_and(Value::is_null) {
                bail!("missing credential journal base revision has a number");
            }
            if !object.get("document_sha256").is_some_and(Value::is_null) {
                bail!("missing credential journal base revision has a digest");
            }
            RevisionGeneration::Missing
        }
        "legacy" => {
            if !object.get("revision").is_some_and(Value::is_null) {
                bail!("legacy credential journal base revision has a number");
            }
            RevisionGeneration::Legacy
        }
        "current" => RevisionGeneration::Current(
            object
                .get("revision")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("current credential journal generation is missing"))?,
        ),
        _ => bail!("credential journal base generation is invalid"),
    };
    let document_sha256 = object
        .get("document_sha256")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    if let Some(digest) = document_sha256.as_deref() {
        if digest.len() != 64
            || !digest.bytes().all(|byte| {
                byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
            })
        {
            bail!("credential journal base digest is invalid");
        }
    }
    if matches!(revision, RevisionGeneration::Current(_)) && document_sha256.is_none() {
        bail!("current credential journal base revision has no digest");
    }
    Ok(Revision {
        generation: match generation {
            "legacy" => RevisionGeneration::Legacy,
            _ => revision,
        },
        document_sha256,
    })
}

fn credential_ref_value(value: Option<&Value>) -> Result<Option<CredentialRef>> {
    let Some(value) = value else {
        bail!("credential journal credential reference is missing");
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("credential journal credential reference is not an object"))?;
    require_exact_keys(object, &["kind", "fingerprint"])?;
    let kind = match object.get("kind").and_then(Value::as_str) {
        Some("oauth_access_token") => CredentialRefKind::OauthAccessToken,
        Some("oauth_authorized_user") => CredentialRefKind::OauthAuthorizedUser,
        Some("api_key") => CredentialRefKind::ApiKey,
        Some("vertex_service_account") => CredentialRefKind::VertexServiceAccount,
        Some("antigravity_token") => CredentialRefKind::AntigravityToken,
        Some("gemini_oauth_session") => CredentialRefKind::GeminiOauthSession,
        _ => bail!("credential journal credential reference kind is invalid"),
    };
    let fingerprint = object
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("credential journal credential fingerprint is missing"))?
        .to_string();
    validate_credential_fingerprint(&fingerprint)?;
    Ok(Some(CredentialRef { kind, fingerprint }))
}

fn before_or_after_descriptor(
    layout: &Map<String, Value>,
    slot: &str,
) -> Result<Option<(CredentialRefKind, String, String)>> {
    let value = layout
        .get(slot)
        .ok_or_else(|| anyhow!("credential journal slot {slot} is missing"))?;
    if value.is_null() {
        return Ok(None);
    }
    let descriptor = value
        .as_object()
        .ok_or_else(|| anyhow!("credential journal slot {slot} is not an object or null"))?;
    require_exact_keys(descriptor, &["kind", "fingerprint", "material_digest"])?;
    let kind = match descriptor.get("kind").and_then(Value::as_str) {
        Some("oauth_access_token") => CredentialRefKind::OauthAccessToken,
        Some("oauth_authorized_user") => CredentialRefKind::OauthAuthorizedUser,
        Some("api_key") => CredentialRefKind::ApiKey,
        Some("vertex_service_account") => CredentialRefKind::VertexServiceAccount,
        Some("antigravity_token") => CredentialRefKind::AntigravityToken,
        Some("gemini_oauth_session") => CredentialRefKind::GeminiOauthSession,
        _ => bail!("credential journal descriptor kind is invalid"),
    };
    let fingerprint = descriptor
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("credential journal descriptor fingerprint is missing"))?
        .to_string();
    validate_credential_fingerprint(&fingerprint)?;
    let digest = descriptor
        .get("material_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("credential journal descriptor digest is missing"))?
        .to_string();
    validate_material_digest(&digest)?;
    Ok(Some((kind, fingerprint, digest)))
}

fn validate_material_digest(value: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        bail!("credential journal material digest must be SHA-256");
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
    {
        bail!("credential journal material digest must be lowercase SHA-256");
    }
    Ok(())
}

fn validate_journal_evidence_value(
    object: &Map<String, Value>,
    slot: &str,
    baseline_digest: Option<&str>,
    expected_tombstone: &str,
) -> Result<()> {
    let backup_key = format!("{slot}_backup");
    let backup_digest_key = format!("{slot}_backup_digest");
    let tombstone_key = format!("{slot}_tombstone");
    let tombstone_digest_key = format!("{slot}_tombstone_digest");
    let backup = optional_string(object, &backup_key)?;
    let backup_digest = optional_string(object, &backup_digest_key)?;
    let tombstone = required_string(object, &tombstone_key)?;
    let tombstone_digest = optional_string(object, &tombstone_digest_key)?;
    if tombstone != expected_tombstone {
        bail!("credential journal tombstone locator does not match transaction");
    }
    match baseline_digest {
        Some(expected) => {
            validate_material_digest(expected)?;
            if backup.is_none()
                || backup_digest != Some(expected)
                || tombstone_digest != Some(expected)
            {
                bail!("credential journal baseline evidence is incomplete");
            }
            let expected_backup = expected_tombstone.replace(".tombstone", ".backup");
            if backup != Some(expected_backup.as_str()) {
                bail!("credential journal backup locator does not match transaction");
            }
        }
        None => {
            if backup.is_some() || backup_digest.is_some() || tombstone_digest.is_some() {
                bail!("credential journal has evidence for an absent baseline slot");
            }
        }
    }
    Ok(())
}

fn normalize_candidate(path: &Path) -> Result<NormalizedStoreRoot> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    NormalizedStoreRoot::normalize(&absolute)
}

/// Re-normalize immediately before claiming a root.  A pure session can have
/// observed a missing path that another state-layer operation then created;
/// reusing the original `missing_suffix` would incorrectly treat that now
/// existing root as a path race.  Re-normalization remains side-effect free
/// and still rejects a final symlink/reparse point.
fn normalize_for_claim(root: &NormalizedStoreRoot) -> Result<NormalizedStoreRoot> {
    NormalizedStoreRoot::normalize(root.as_path())
}

fn target_locator() -> Result<SafeRelativePath> {
    SafeRelativePath::new(Path::new(STATE_TARGET))
}

fn root_metadata(root: &NormalizedStoreRoot) -> Result<Option<fs::Metadata>> {
    classify_root_metadata(fs::symlink_metadata(root.as_path())).with_context(|| {
        format!(
            "failed to inspect normalized state root: {}",
            root.as_path().display()
        )
    })
}

fn classify_root_metadata(result: std::io::Result<fs::Metadata>) -> Result<Option<fs::Metadata>> {
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn directory_is_empty(path: &Path) -> Result<bool> {
    Ok(fs::read_dir(path)?.next().transpose()?.is_none())
}

fn read_root_snapshot(
    root: &NormalizedStoreRoot,
    target: &SafeRelativePath,
) -> Result<(DocumentSnapshot, bool)> {
    let Some(metadata) = root_metadata(root)? else {
        return Ok((read_snapshot_from_normalized(root, target)?, false));
    };
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!("state root is not a regular directory");
    }
    if directory_is_empty(root.as_path())? {
        return Ok((read_snapshot_from_normalized(root, target)?, false));
    }
    validate_readonly_root(root, target)
}

// -------------------------------------------------------------------------
// Private v1/v2 wire models

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountV1Wire {
    #[serde(default)]
    id: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    account_type: AccountType,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    identity_fingerprint: Option<String>,
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    auth_path: String,
    #[serde(default)]
    config_path: Option<String>,
    #[serde(default)]
    oauth_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    added_at: i64,
    #[serde(default)]
    updated_at: i64,
    #[serde(default)]
    last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageV1Wire {
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    cooldown_until: Option<i64>,
    #[serde(default)]
    remaining_quota_percent: Option<i64>,
    #[serde(default)]
    last_synced_at: Option<i64>,
    #[serde(default)]
    last_sync_error: Option<String>,
    #[serde(default)]
    needs_relogin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageWire {
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    health: HealthStatus,
    #[serde(default)]
    cooldown: Option<Cooldown>,
    #[serde(default)]
    remaining_quota_percent: Option<u8>,
    #[serde(default)]
    last_probe_at: Option<i64>,
    #[serde(default)]
    last_success_at: Option<i64>,
    #[serde(default)]
    last_rate_limit_at: Option<i64>,
    #[serde(default)]
    last_error: Option<HealthErrorKind>,
}

impl From<UsageWire> for UsageSnapshot {
    fn from(value: UsageWire) -> Self {
        Self {
            plan: value.plan,
            health: value.health,
            cooldown: value.cooldown,
            remaining_quota_percent: value.remaining_quota_percent,
            last_probe_at: value.last_probe_at,
            last_success_at: value.last_success_at,
            last_rate_limit_at: value.last_rate_limit_at,
            last_error: value.last_error,
        }
    }
}

impl From<&UsageSnapshot> for UsageWire {
    fn from(value: &UsageSnapshot) -> Self {
        Self {
            plan: value.plan.clone(),
            health: value.health,
            cooldown: value.cooldown,
            remaining_quota_percent: value.remaining_quota_percent,
            last_probe_at: value.last_probe_at,
            last_success_at: value.last_success_at,
            last_rate_limit_at: value.last_rate_limit_at,
            last_error: value.last_error,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV1Wire {
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    accounts: Vec<AccountV1Wire>,
    #[serde(default)]
    usage_cache: std::collections::BTreeMap<String, UsageV1Wire>,
    #[serde(default)]
    current_account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountV2Wire {
    id: String,
    email: String,
    account_type: AccountType,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    plan: Option<String>,
    #[serde(default)]
    added_at: i64,
    #[serde(default)]
    updated_at: i64,
    #[serde(default)]
    last_used_at: Option<i64>,
    credential_ref: CredentialRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateV2Wire {
    version: u32,
    revision: u64,
    accounts: Vec<AccountV2Wire>,
    usage_cache: std::collections::BTreeMap<String, UsageWire>,
    current_account_id: Option<String>,
    active_profile: Option<ActiveProfile>,
    sync_watermarks: std::collections::BTreeMap<String, SyncWatermark>,
}

fn parse_snapshot(snapshot: &DocumentSnapshot) -> Result<StateRead> {
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(StateRead {
            state: State::default(),
            revision: Revision {
                generation: RevisionGeneration::Missing,
                document_sha256: None,
            },
            migration: MigrationStatus::Missing,
            recovery_pending: false,
        });
    };
    if bytes.len() > MAX_STATE_BYTES {
        bail!("state document exceeds {MAX_STATE_BYTES} bytes");
    }
    let value = strict_json_value(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("state document must be a JSON object"))?;
    let version = match object.get("version") {
        None => None,
        Some(Value::Number(number)) => Some(
            number
                .as_u64()
                .ok_or_else(|| anyhow!("state version must be a non-negative integer"))?,
        ),
        Some(_) => bail!("state version must be an integer"),
    };
    let digest = snapshot
        .digest
        .ok_or_else(|| anyhow!("state document digest is missing"))?;
    match version {
        None => parse_v1(value, digest),
        Some(version) if version == STATE_VERSION as u64 => parse_v1(value, digest),
        Some(version) if version == STATE_V2_VERSION as u64 => parse_v2(value, digest),
        Some(version) => bail!("unsupported state version {version}"),
    }
}

/// v1 里的 `google_accounts` 占位账号：没有 oauth_token / api_key / refresh_token
/// 中的任何一个，因此不可能承载凭据，也不可能被迁移。
fn is_v1_placeholder_account(account: &AccountV1Wire) -> bool {
    account.email.eq_ignore_ascii_case("google_accounts")
        && account.oauth_token.is_none()
        && account.api_key.is_none()
        && account.refresh_token.is_none()
}

fn parse_v1(value: Value, digest: DocumentDigest) -> Result<StateRead> {
    let wire: StateV1Wire = serde_json::from_value(value).context("invalid v1 state document")?;
    let _ = wire.version;
    if wire.accounts.len() > MAX_ACCOUNTS || wire.usage_cache.len() > MAX_USAGE_ENTRIES {
        bail!("v1 state exceeds bounded collection limits");
    }
    let mut credential_refs = std::collections::BTreeMap::new();
    // 真实的 v1 state 里存在 email == "google_accounts" 且三个凭据字段全空的
    // 占位账号。它没有任何可迁移的凭据，放进来只会在后续迁移里炸掉整笔迁移，
    // 所以在生产读路径就丢弃，与 legacy `cleanup_invalid_legacy_accounts` 一致。
    let mut dropped_ids: std::collections::BTreeSet<String> = Default::default();
    let mut accounts = Vec::with_capacity(wire.accounts.len());
    for account in wire.accounts {
        if is_v1_placeholder_account(&account) {
            dropped_ids.insert(account.id.clone());
            continue;
        }
        let reference = derive_credential_ref(&account);
        let migrated = migrate_v1_account(account);
        if let Some(reference) = reference {
            credential_refs.insert(migrated.id.clone(), reference);
        }
        accounts.push(migrated);
    }
    let usage_cache = wire
        .usage_cache
        .into_iter()
        .filter(|(id, _)| !dropped_ids.contains(id))
        .map(|(id, usage)| (id, migrate_v1_usage(usage)))
        .collect();
    // 丢弃占位账号后，指向它的 current_account_id 会变成悬空引用，
    // 必须一起清掉，否则 invariant 校验会把整份 state 判成非法。
    let current_account_id = wire
        .current_account_id
        .filter(|id| !dropped_ids.contains(id));
    let state = State {
        version: STATE_VERSION,
        accounts,
        usage_cache,
        current_account_id,
        revision: 0,
        active_profile: None,
        sync_watermarks: Default::default(),
        credential_refs,
    };
    validate_state_invariants(&state)?;
    Ok(StateRead {
        state,
        revision: Revision {
            generation: RevisionGeneration::Legacy,
            document_sha256: Some(digest.to_hex()),
        },
        migration: MigrationStatus::LegacyV1,
        recovery_pending: false,
    })
}

/// Convert the legacy free-form health fields into the closed v2 vocabulary.
/// Unknown or failed legacy values stay non-ready and never inherit a fake
/// 100% quota.  The old error text is deliberately discarded at this boundary.
fn migrate_v1_usage(value: UsageV1Wire) -> UsageSnapshot {
    let status = value.status.trim().to_ascii_lowercase();
    let had_probe_error = value
        .last_sync_error
        .as_deref()
        .is_some_and(|error| !error.trim().is_empty());
    let health = if value.needs_relogin {
        HealthStatus::AuthInvalid
    } else if had_probe_error {
        // v1 会在探测失败后保留旧 Ready/100；迁移时不能把这个 fail-open
        // 快照提升为可信的 v2 health。
        HealthStatus::TransientFailure
    } else {
        match status.as_str() {
            "ready" => HealthStatus::Ready,
            "stale" | "refresh_required" => HealthStatus::RefreshRequired,
            "ratelimited" | "rate_limited" => HealthStatus::RateLimited,
            "expired" | "autherror" | "auth_invalid" => HealthStatus::AuthInvalid,
            "invalidkey" | "invalid_credential" => HealthStatus::InvalidCredential,
            "permissiondenied" | "permission_denied" => HealthStatus::PermissionDenied,
            "" => HealthStatus::Unverified,
            _ => HealthStatus::TransientFailure,
        }
    };
    let last_error = match health {
        HealthStatus::AuthInvalid => Some(HealthErrorKind::Unauthorized),
        HealthStatus::PermissionDenied => Some(HealthErrorKind::PermissionDenied),
        HealthStatus::InvalidCredential => Some(HealthErrorKind::InvalidCredential),
        HealthStatus::RateLimited => Some(HealthErrorKind::RateLimited),
        HealthStatus::TransientFailure => Some(HealthErrorKind::Unknown),
        _ => None,
    };
    let quota = value
        .remaining_quota_percent
        .and_then(|quota| u8::try_from(quota.clamp(0, 100)).ok())
        .filter(|_| matches!(health, HealthStatus::Ready | HealthStatus::RefreshRequired));
    let cooldown = if matches!(health, HealthStatus::RateLimited) {
        value.cooldown_until.map(|until| Cooldown {
            started_at: value.last_synced_at.unwrap_or_default(),
            until,
            last_evidence_at: value.last_synced_at.unwrap_or_default(),
        })
    } else {
        None
    };
    UsageSnapshot {
        plan: value.plan,
        health,
        cooldown,
        remaining_quota_percent: quota,
        last_probe_at: value.last_synced_at,
        last_success_at: if matches!(health, HealthStatus::Ready) {
            value.last_synced_at
        } else {
            None
        },
        last_rate_limit_at: if matches!(health, HealthStatus::RateLimited) {
            value.last_synced_at
        } else {
            None
        },
        last_error,
    }
}

fn parse_v2(value: Value, digest: DocumentDigest) -> Result<StateRead> {
    let wire: StateV2Wire = serde_json::from_value(value).context("invalid v2 state document")?;
    if wire.version != STATE_V2_VERSION {
        bail!("unsupported v2 wire version {}", wire.version);
    }
    if wire.revision == 0 {
        bail!("v2 state revision must be positive");
    }
    if wire.accounts.len() > MAX_ACCOUNTS
        || wire.usage_cache.len() > MAX_USAGE_ENTRIES
        || wire.sync_watermarks.len() > MAX_WATERMARKS
    {
        bail!("v2 state exceeds bounded collection limits");
    }
    let mut credential_refs = std::collections::BTreeMap::new();
    let accounts = wire
        .accounts
        .into_iter()
        .map(|account| {
            credential_refs.insert(account.id.clone(), account.credential_ref);
            AccountRecord {
                id: account.id,
                email: account.email,
                account_type: account.account_type,
                provider_id: account.provider_id,
                project_id: account.project_id,
                account_id: account.account_id,
                identity_fingerprint: None,
                plan: account.plan,
                auth_path: String::new(),
                config_path: None,
                oauth_token: None,
                refresh_token: None,
                api_key: None,
                added_at: account.added_at,
                updated_at: account.updated_at,
                last_used_at: account.last_used_at,
            }
        })
        .collect();
    let state = State {
        version: STATE_V2_VERSION,
        accounts,
        usage_cache: wire
            .usage_cache
            .into_iter()
            .map(|(id, usage)| (id, usage.into()))
            .collect(),
        current_account_id: wire.current_account_id,
        revision: wire.revision,
        active_profile: wire.active_profile,
        sync_watermarks: wire.sync_watermarks,
        credential_refs,
    };
    let revision = state.revision;
    validate_state_invariants(&state)?;
    Ok(StateRead {
        state,
        revision: Revision {
            generation: RevisionGeneration::Current(revision),
            document_sha256: Some(digest.to_hex()),
        },
        migration: MigrationStatus::None,
        recovery_pending: false,
    })
}

fn migrate_v1_account(account: AccountV1Wire) -> AccountRecord {
    AccountRecord {
        id: account.id,
        email: account.email,
        account_type: account.account_type,
        provider_id: account.provider_id,
        project_id: account.project_id,
        account_id: account.account_id,
        identity_fingerprint: account.identity_fingerprint,
        plan: account.plan,
        auth_path: account.auth_path,
        config_path: account.config_path,
        oauth_token: account.oauth_token,
        refresh_token: account.refresh_token,
        api_key: account.api_key,
        added_at: account.added_at,
        updated_at: account.updated_at,
        last_used_at: account.last_used_at,
    }
}

fn derive_credential_ref(account: &AccountV1Wire) -> Option<CredentialRef> {
    let credential = if let Some(token) = account.oauth_token.as_deref().filter(|v| !v.is_empty()) {
        PortableCredential::oauth_access_token(token).ok()
    } else if let Some(api_key) = account.api_key.as_deref().filter(|v| !v.is_empty()) {
        PortableCredential::api_key(api_key).ok()
    } else {
        None
    }?;
    let kind = match credential.kind().as_str() {
        "oauth_access_token" => CredentialRefKind::OauthAccessToken,
        "oauth_authorized_user" => CredentialRefKind::OauthAuthorizedUser,
        "api_key" => CredentialRefKind::ApiKey,
        "vertex_service_account" => CredentialRefKind::VertexServiceAccount,
        _ => return None,
    };
    Some(CredentialRef {
        kind,
        fingerprint: credential.fingerprint(),
    })
}

fn encode_v2(state: &State) -> Result<Vec<u8>> {
    if state.version != STATE_V2_VERSION {
        bail!("v2 encoder requires state version 2");
    }
    validate_state_invariants(state)?;
    // 写入端必须和读取端用同一套上限，否则会写出一份自己读不回来的 state：
    // 提交成功，下一次任何命令都直接失败。
    if state.accounts.len() > MAX_ACCOUNTS
        || state.usage_cache.len() > MAX_USAGE_ENTRIES
        || state.sync_watermarks.len() > MAX_WATERMARKS
    {
        bail!("v2 state exceeds bounded collection limits");
    }
    let accounts = state
        .accounts
        .iter()
        .map(|account| {
            Ok(AccountV2Wire {
                id: account.id.clone(),
                email: account.email.clone(),
                account_type: account.account_type,
                provider_id: account.provider_id.clone(),
                project_id: account.project_id.clone(),
                account_id: account.account_id.clone(),
                plan: account.plan.clone(),
                added_at: account.added_at,
                updated_at: account.updated_at,
                last_used_at: account.last_used_at,
                credential_ref: state
                    .credential_refs
                    .get(&account.id)
                    .cloned()
                    .ok_or_else(|| anyhow!("v2 account is missing credential_ref"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let wire = StateV2Wire {
        version: STATE_V2_VERSION,
        revision: state.revision,
        accounts,
        usage_cache: state
            .usage_cache
            .iter()
            .map(|(id, usage)| (id.clone(), UsageWire::from(usage)))
            .collect(),
        current_account_id: state.current_account_id.clone(),
        active_profile: state.active_profile.clone(),
        sync_watermarks: state.sync_watermarks.clone(),
    };
    let encoded = serde_json::to_vec_pretty(&wire).context("failed to encode v2 state")?;
    ensure_document_within_reader_limit(&encoded)?;
    Ok(encoded)
}

/// 读取端在 `parse_snapshot` 里按 MAX_STATE_BYTES 截断，写入端必须用同一个数，
/// 否则会提交一份"写得进、读不回"的 state。
fn ensure_document_within_reader_limit(encoded: &[u8]) -> Result<()> {
    if encoded.len() > MAX_STATE_BYTES {
        bail!("v2 state document exceeds {MAX_STATE_BYTES} bytes");
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Strict duplicate-aware JSON and root-adoption validation

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }
    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }
    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(
            serde_json::Number::from_f64(value)
                .ok_or_else(|| E::custom("non-finite JSON number"))?,
        )))
    }
    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_string())))
    }
    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }
    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }
    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON field: {key}")));
            }
            values.insert(key, map.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn strict_json_value(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| anyhow!(error).context("invalid JSON state document"))?
        .0;
    deserializer
        .end()
        .map_err(|error| anyhow!(error).context("trailing bytes after state document"))?;
    Ok(value)
}

fn validate_readonly_root(
    root: &NormalizedStoreRoot,
    target: &SafeRelativePath,
) -> Result<(DocumentSnapshot, bool)> {
    let inventory = inspect_top_level_inventory(root, MAX_ROOT_INVENTORY_ENTRIES)?;
    let recovery = inspect_recovery_from_normalized(root, target)
        .map_err(|error| anyhow!(error.to_string()))?;
    if let RecoveryPreview::Conflict { live, base, target } = &recovery.recovery {
        bail!(
            "state recovery journal conflicts with live document: live={live:?}, base={base:?}, target={target}"
        );
    }
    if let Some(staged) = recovery.staged_bytes.as_deref() {
        // The generic layer proves the exact staged digest. The schema layer
        // must additionally prove that the staged bytes are a valid state
        // document before exposing the pending recovery to callers.
        let digest = DocumentDigest::from_bytes(staged);
        parse_snapshot(&DocumentSnapshot {
            bytes: Some(staged.to_vec()),
            digest: Some(digest),
        })?;
    }
    let snapshot = recovery.snapshot;
    let target_digest = DocumentDigest::from_bytes(STATE_TARGET.as_bytes()).to_hex();
    let lock_name = format!(".sagy-{target_digest}.lock");
    let journal_name = format!(".sagy-{target_digest}.journal");
    let inventory = inventory
        .into_iter()
        .map(|entry| AdoptionInventoryEntry {
            artifact: readonly_artifact(
                entry.locator.as_path().to_str().unwrap_or_default(),
                &lock_name,
                &journal_name,
            ),
            locator: entry.locator,
            kind: entry.kind,
            size: entry.size,
        })
        .collect::<Vec<_>>();
    validate_inventory(root, &inventory, &snapshot, None)?;
    let pending = matches!(
        recovery.recovery,
        RecoveryPreview::Finalize { .. } | RecoveryPreview::Rollback { .. }
    );
    Ok((snapshot, pending))
}

fn readonly_artifact(name: &str, lock_name: &str, journal_name: &str) -> AdoptionArtifact {
    if name == lock_name {
        return AdoptionArtifact::FixedLock;
    }
    if name == journal_name {
        return AdoptionArtifact::FixedJournal;
    }
    if let Some(raw) = name
        .strip_prefix(".sagy-")
        .and_then(|value| value.strip_suffix(".staged"))
        && let Ok(txid) = uuid::Uuid::parse_str(raw)
        && txid.to_string() == raw
    {
        return AdoptionArtifact::DocumentStage(txid);
    }
    if let Some(raw) = name
        .strip_prefix(".sagy-")
        .and_then(|value| value.strip_suffix(".journal.staged"))
        && let Ok(txid) = uuid::Uuid::parse_str(raw)
        && txid.to_string() == raw
    {
        return AdoptionArtifact::JournalStage(txid);
    }
    AdoptionArtifact::Ordinary
}

fn validate_adoption_root(root: &NormalizedStoreRoot, preflight: &AdoptionPreflight) -> Result<()> {
    validate_inventory(
        root,
        &preflight.inventory,
        &preflight.snapshot,
        Some(preflight),
    )?;
    if let JournalPreview::Prepared(journal) = &preflight.journal_preview
        && journal.staged_present
    {
        let staged = read_normalized_relative_file_bounded(root, &journal.staged, MAX_STATE_BYTES)?
            .ok_or_else(|| anyhow!("referenced staged state disappeared"))?;
        let digest = DocumentDigest::from_bytes(&staged);
        if digest != journal.target_digest {
            bail!("staged state digest does not match journal target");
        }
        parse_snapshot(&DocumentSnapshot {
            bytes: Some(staged),
            digest: Some(digest),
        })?;
    }
    Ok(())
}

fn validate_inventory(
    root: &NormalizedStoreRoot,
    inventory: &[AdoptionInventoryEntry],
    snapshot: &DocumentSnapshot,
    preflight: Option<&AdoptionPreflight>,
) -> Result<()> {
    let mut names = BTreeSet::new();
    for entry in inventory {
        let name = entry
            .locator
            .as_path()
            .to_str()
            .ok_or_else(|| anyhow!("root entry name is not valid UTF-8"))?;
        names.insert(name.to_string());
        match name {
            STATE_TARGET => {
                if entry.kind != TopLevelEntryKind::RegularFile {
                    bail!("state.json must be a regular file");
                }
                // 顶层 inventory 不再对陌生条目设大小上限，所以 sagy 自己纳管的
                // state.json 必须在这里显式收边界。
                if entry.size > MAX_STATE_BYTES as u64 {
                    bail!("state.json exceeds {MAX_STATE_BYTES} bytes");
                }
            }
            "accounts" => {
                if entry.kind != TopLevelEntryKind::Directory {
                    bail!("accounts must be a directory");
                }
                validate_accounts_dir(root.as_path())?;
            }
            "repo-sync.json" => {
                if entry.kind != TopLevelEntryKind::RegularFile {
                    bail!("repo-sync.json must be a regular file");
                }
                if entry.size > MAX_REPO_SYNC_BYTES as u64 {
                    bail!("repo-sync.json is too large");
                }
            }
            "tmp" | "runtime" => {
                if entry.kind != TopLevelEntryKind::Directory {
                    bail!("{name} must be a directory");
                }
            }
            _ if matches!(
                entry.artifact,
                AdoptionArtifact::FixedLock | AdoptionArtifact::FixedJournal
            ) =>
            {
                if entry.kind != TopLevelEntryKind::RegularFile {
                    bail!("atomic artifact must be a regular file");
                }
            }
            _ if matches!(
                entry.artifact,
                AdoptionArtifact::DocumentStage(_) | AdoptionArtifact::JournalStage(_)
            ) =>
            {
                if entry.kind != TopLevelEntryKind::RegularFile {
                    bail!("atomic stage must be a regular file");
                }
            }
            _ if is_legacy_temp_name(name) && entry.kind != TopLevelEntryKind::RegularFile => {
                bail!("legacy temporary entry must be a regular file");
            }
            // 未知的顶层条目一律忽略：不纳管、不校验、不触碰。
            //
            // 为什么不是"把白名单再扩大一点"：SAGY_HOME 同时是安装目录，
            // install.sh/install.ps1 必然在其中创建 bin/ 和 tmp/，用户也会往
            // 里放自己的东西（notes.txt、.DS_Store、backup/）。任何固定白名单
            // 都追不上真实目录，而一旦追不上，产品在正常安装路径上就直接不可用。
            // sagy 自己管理的名字（上面各分支）仍然严格校验。
            _ => {}
        }
    }
    if snapshot.bytes.is_some() {
        if !names.contains(STATE_TARGET) {
            bail!("state snapshot exists but state.json is not in inventory");
        }
        parse_snapshot(snapshot)?;
    }
    if let Some(preflight) = preflight
        && matches!(preflight.recovery_preview, RecoveryPreview::Conflict { .. })
    {
        bail!("state recovery journal conflicts with the live document");
    }
    Ok(())
}

/// Tighten pre-existing wide permissions under `accounts/` back to the modes
/// sagy writes today (0700 for directories, 0600 for credential files).
///
/// 为什么放在这里：新写入的凭据早已是 0600，但 0.1 之前留下的 0644 文件不会
/// 自己变紧。收紧必须 fail-closed —— 收不紧就不要继续用这份凭据。
#[cfg(unix)]
fn harden_state_root_permissions(root: &NormalizedStoreRoot) -> Result<()> {
    let accounts = root.as_path().join("accounts");
    let metadata = match fs::symlink_metadata(&accounts) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", accounts.display()));
        }
    };
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        // 类型本身非法，交给 inventory 校验去报更精确的错误，这里不改任何权限。
        return Ok(());
    }
    tighten_mode(&accounts, &metadata, 0o700)?;

    let mut directories = 0usize;
    for entry in fs::read_dir(&accounts)
        .with_context(|| format!("failed to enumerate {}", accounts.display()))?
    {
        directories += 1;
        if directories > MAX_ACCOUNT_DIRECTORIES {
            bail!("too many account directories");
        }
        let entry = entry.with_context(|| format!("failed to enumerate {}", accounts.display()))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if is_link_or_reparse(&metadata) {
            // 无法证明一个 symlink 背后的对象是不是本机凭据，也就无法证明收紧
            // 生效，所以 fail-closed 而不是跳过。
            bail!(
                "cannot tighten permissions through a symlink: {}",
                path.display()
            );
        }
        if !metadata.is_dir() {
            continue;
        }
        tighten_mode(&path, &metadata, 0o700)?;

        let mut files = 0usize;
        for child in fs::read_dir(&path)
            .with_context(|| format!("failed to enumerate {}", path.display()))?
        {
            files += 1;
            if files > MAX_ACCOUNT_FILES {
                bail!("too many files in account directory");
            }
            let child = child.with_context(|| format!("failed to enumerate {}", path.display()))?;
            let child_path = child.path();
            let child_metadata = fs::symlink_metadata(&child_path)
                .with_context(|| format!("failed to inspect {}", child_path.display()))?;
            if is_link_or_reparse(&child_metadata) {
                bail!(
                    "cannot tighten permissions through a symlink: {}",
                    child_path.display()
                );
            }
            if !child_metadata.is_file() {
                continue;
            }
            tighten_mode(&child_path, &child_metadata, 0o600)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_state_root_permissions(_root: &NormalizedStoreRoot) -> Result<()> {
    // Windows ACL 无法用 std 的 mode 表达，权限由 create-new + 目录 ACL 保证。
    Ok(())
}

#[cfg(unix)]
fn tighten_mode(path: &Path, metadata: &fs::Metadata, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let current = metadata.permissions().mode();
    let mut permissions = metadata.permissions();
    tighten_mode_verified(
        path,
        current,
        mode,
        |desired| {
            permissions.set_mode(desired);
            fs::set_permissions(path, permissions.clone())
                .with_context(|| format!("failed to tighten permissions for {}", path.display()))
        },
        || {
            Ok(fs::symlink_metadata(path)
                .with_context(|| format!("failed to re-inspect {}", path.display()))?
                .permissions()
                .mode())
        },
    )
}

/// chmod 之后必须复核实际生效的 mode。
///
/// 为什么把 chmod 与复核抽成两个注入点：非 root 进程在普通文件系统上无法让
/// chmod 真的失败或被静默忽略，端到端根本走不到这条分支；把它做成可直接驱动的
/// 形状，测试才能证明 "chmod 报错" 和 "chmod 静默无效" 两种情况都是 fail-closed。
#[cfg(unix)]
fn tighten_mode_verified<S, O>(
    path: &Path,
    current_mode: u32,
    desired_mode: u32,
    set_mode: S,
    observe_mode: O,
) -> Result<()>
where
    S: FnOnce(u32) -> Result<()>,
    O: FnOnce() -> Result<u32>,
{
    if current_mode & 0o7777 == desired_mode {
        return Ok(());
    }
    set_mode(desired_mode)?;
    // 有些文件系统会静默忽略 chmod。收紧无法被验证时必须 fail-closed，
    // 而不是假装凭据已经安全并继续使用。
    let observed = observe_mode()? & 0o7777;
    if observed != desired_mode {
        bail!(
            "failed to tighten permissions for {}: mode is still {:o}",
            path.display(),
            observed
        );
    }
    Ok(())
}

/// Preserve an unreadable state document by renaming it aside and returning an
/// error that tells the user exactly where it went and what to do next.
///
/// 为什么改名而不是删除：损坏的 state 里仍然有用户的账号元数据，静默删除等于
/// 丢数据。改名后下一次命令从空 state 起步，用户随时可以回去捞。
fn quarantine_unreadable_document(store: &StateStore, error: StateStoreError) -> StateStoreError {
    // 大到读取端不敢读的文档同样属于"读得出来的坏"：不隔离，但必须给指引。
    if let Some(hint) = oversized_state_hint(store) {
        return hint;
    }
    let Some(bytes) =
        read_normalized_relative_file_bounded(&store.root, &store.target, MAX_STATE_BYTES)
            .ok()
            .flatten()
    else {
        return error;
    };
    if document_is_syntactically_valid(&bytes) {
        // 只有 JSON 语法层坏掉（截断、非法字节、重复键、尾随垃圾）的文档才没有
        // 人工修复的余地。语义校验失败——版本号更高、revision 非法、集合超上限、
        // invariant 违规——都是读得出来、能人工修的完好文档；一旦被改名，用户下一条
        // 命令就会提交一份全新的空 state，旧文档永久变成孤儿。所以原样上抛，
        // 不改名、不移动。
        return error;
    }

    let source = store.root.as_path().join(STATE_TARGET);
    match fs::symlink_metadata(&source) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {}
        _ => return error,
    }
    let quarantine_name = format!("{CORRUPT_STATE_PREFIX}{}", uuid::Uuid::new_v4());
    let destination = store.root.as_path().join(&quarantine_name);
    if let Err(rename_error) = fs::rename(&source, &destination) {
        return StateStoreError::Invalid(anyhow!(
            "state.json cannot be parsed and could not be moved aside ({rename_error}). \
             Move {} somewhere safe by hand, then re-run the command.",
            source.display()
        ));
    }
    StateStoreError::Invalid(anyhow!(
        "state.json could not be parsed and was preserved as {quarantine_name} in {}. \
         Nothing was deleted. Re-run the command to start from an empty state, then run \
         `sagy import-known` to re-register local accounts.",
        store.root.as_path().display()
    ))
}

/// 只判定"JSON 语法层是否完好"，不做任何 schema / 语义判断。
///
/// 隔离（改名）会让旧文档在下一条命令后永久变成孤儿，所以它的打击面必须
/// 严格收在"人工也修不回来"的这一类失败上。
fn document_is_syntactically_valid(bytes: &[u8]) -> bool {
    strict_json_value(bytes).is_ok()
}

/// state.json 超过读取上限时，读取端在 inventory 阶段就拒绝，用户只会拿到一句
/// 没有恢复指引的裸错误。这条入口按上面的规则同样不隔离，但必须给出与隔离路径
/// 一致的、可操作的下一步。
fn oversized_state_hint(store: &StateStore) -> Option<StateStoreError> {
    let path = store.root.as_path().join(STATE_TARGET);
    let metadata = fs::symlink_metadata(&path).ok()?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return None;
    }
    if metadata.len() <= MAX_STATE_BYTES as u64 {
        return None;
    }
    Some(StateStoreError::Invalid(anyhow!(
        "state.json is {} bytes, above the {MAX_STATE_BYTES} byte limit sagy will read. \
         Nothing was moved or deleted. Move {} somewhere safe by hand, then re-run the \
         command to start from an empty state and run `sagy import-known` to re-register \
         local accounts.",
        metadata.len(),
        path.display()
    )))
}

fn validate_accounts_dir(root: &Path) -> Result<()> {
    let accounts = root.join("accounts");
    let metadata = fs::symlink_metadata(&accounts)?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!("accounts directory cannot be a symlink");
    }
    let mut count = 0;
    for entry in fs::read_dir(&accounts)? {
        count += 1;
        if count > MAX_ACCOUNT_DIRECTORIES {
            bail!("too many account directories");
        }
        let entry = entry?;
        let name_os = entry.file_name();
        let name = name_os
            .to_str()
            .ok_or_else(|| anyhow!("account directory name is not valid UTF-8"))?
            .to_string();
        validate_account_id(&name)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            bail!("account directory cannot be a symlink: {name}");
        }
        let mut files = 0;
        for child in fs::read_dir(entry.path())? {
            files += 1;
            if files > MAX_ACCOUNT_FILES {
                bail!("too many files in account directory: {name}");
            }
            let child = child?;
            let child_os = child.file_name();
            let child_name = child_os
                .to_str()
                .ok_or_else(|| anyhow!("account file name is not valid UTF-8"))?
                .to_string();
            if !matches!(
                child_name.as_str(),
                "credentials.json" | "antigravity-oauth-token" | "settings.json"
            ) && !is_legacy_temp_name(&child_name)
                && !is_credential_artifact_name(&child_name)
                && !is_active_home_artifact_name(&child_name)
            {
                bail!("unknown account file: {name}/{child_name}");
            }
            let metadata = fs::symlink_metadata(child.path())?;
            if is_link_or_reparse(&metadata) || !metadata.is_file() {
                bail!("account file is not a regular file: {name}/{child_name}");
            }
            if metadata.len() > MAX_ACCOUNT_FILE_BYTES {
                bail!("account file is too large: {name}/{child_name}");
            }
        }
    }
    Ok(())
}

fn is_credential_artifact_name(name: &str) -> bool {
    name == ".sagy-credential.lock"
        || name
            .strip_prefix(".sagy-credential-")
            .is_some_and(|rest| !rest.is_empty() && rest.len() <= 256)
}

fn is_active_home_artifact_name(name: &str) -> bool {
    if name == ".sagy-active-home.account.lock" {
        return true;
    }
    let Some(rest) = name.strip_prefix(".sagy-active-home-") else {
        return false;
    };
    let raw = rest
        .strip_suffix(".journal.update")
        .or_else(|| rest.strip_suffix(".journal"));
    raw.is_some_and(|raw| Uuid::parse_str(raw).is_ok_and(|txid| txid.to_string() == raw))
}

fn is_legacy_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(".tmp") else {
        return false;
    };
    let mut parts = rest.rsplitn(3, '.');
    let Some(uuid) = parts.next() else {
        return false;
    };
    let Some(pid) = parts.next() else {
        return false;
    };
    let Some(base) = parts.next() else {
        return false;
    };
    matches!(
        base,
        "state.json"
            | "repo-sync.json"
            | "credentials.json"
            | "antigravity-oauth-token"
            | "settings.json"
    ) && !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && uuid::Uuid::parse_str(uuid)
            .map(|value| value.to_string() == uuid)
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state::{ManagedLayout, SlotState};
    use std::fs;
    use std::io;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn digest() -> String {
        "a".repeat(64)
    }

    fn ref_for(kind: CredentialRefKind) -> CredentialRef {
        CredentialRef {
            kind,
            fingerprint: "sha256:".to_string() + &digest(),
        }
    }

    fn token_layout() -> ManagedLayout {
        ManagedLayout {
            antigravity_token: SlotState::Exact { sha256: digest() },
            gemini_authorized_user: SlotState::Absent,
        }
    }

    fn authorized_user_layout() -> ManagedLayout {
        ManagedLayout {
            antigravity_token: SlotState::Absent,
            gemini_authorized_user: SlotState::Exact { sha256: digest() },
        }
    }

    fn absent_layout() -> ManagedLayout {
        ManagedLayout::default()
    }

    #[test]
    fn credential_journal_accepts_provider_native_reference_tags() {
        let fingerprint = format!("sha256:{}", "a".repeat(64));
        for (tag, expected) in [
            ("antigravity_token", CredentialRefKind::AntigravityToken),
            (
                "gemini_oauth_session",
                CredentialRefKind::GeminiOauthSession,
            ),
        ] {
            let value = serde_json::json!({
                "kind": tag,
                "fingerprint": fingerprint.clone(),
            });
            assert_eq!(
                credential_ref_value(Some(&value)).unwrap().unwrap().kind,
                expected
            );
        }
        assert!(
            validate_active_layout_for_reference(
                CredentialRefKind::AntigravityToken,
                &token_layout()
            )
            .is_ok()
        );
        assert!(
            validate_active_layout_for_reference(
                CredentialRefKind::GeminiOauthSession,
                &authorized_user_layout()
            )
            .is_ok()
        );
    }

    fn v2_state() -> State {
        let credential_ref = ref_for(CredentialRefKind::OauthAccessToken);
        let mut credential_refs = std::collections::BTreeMap::new();
        credential_refs.insert("acc-1".to_string(), credential_ref);
        State {
            version: STATE_V2_VERSION,
            accounts: vec![AccountRecord {
                id: "acc-1".to_string(),
                email: "user@example.com".to_string(),
                ..Default::default()
            }],
            current_account_id: None,
            revision: 1,
            credential_refs,
            ..Default::default()
        }
    }

    /// AC-5.1: 写入端必须和读取端用同一套上限。
    #[test]
    fn v2_encoder_rejects_collections_the_reader_cannot_accept() {
        let mut state = v2_state();
        let template = state.accounts[0].clone();
        let credential_ref = ref_for(CredentialRefKind::OauthAccessToken);
        for index in 0..MAX_ACCOUNTS {
            let id = format!("acc-overflow-{index}");
            state.accounts.push(AccountRecord {
                id: id.clone(),
                ..template.clone()
            });
            state.credential_refs.insert(id, credential_ref.clone());
        }
        assert!(state.accounts.len() > MAX_ACCOUNTS);

        let error = encode_v2(&state).unwrap_err().to_string();
        assert!(
            error.contains("bounded collection limits"),
            "unexpected encoder error: {error}"
        );
    }

    /// AC-R1-2.1: 一份**通过全部 invariant 与集合上限**、但编码后超过读取端
    /// MAX_STATE_BYTES 的 state 必须被写入端拒绝。
    ///
    /// 为什么可构造：`validate_text` 每个字段放行 16KB，`MAX_ACCOUNTS` 放行 4096
    /// 个账号，两者相乘远大于 16MB。所以"集合上限已经覆盖了大小上限"并不成立，
    /// 大小守卫必须是 encode_v2 里一条独立的、真的会被走到的分支。
    #[test]
    fn v2_encoder_rejects_a_valid_state_whose_document_exceeds_the_reader_limit() {
        const EMAIL_BYTES: usize = 16 * 1024;
        let mut state = v2_state();
        state.accounts.clear();
        state.credential_refs.clear();
        let credential_ref = ref_for(CredentialRefKind::OauthAccessToken);
        let email = "e".repeat(EMAIL_BYTES);
        let accounts = MAX_STATE_BYTES / EMAIL_BYTES + 64;
        assert!(accounts < MAX_ACCOUNTS);
        for index in 0..accounts {
            let id = format!("acc-bulk-{index}");
            state.accounts.push(AccountRecord {
                id: id.clone(),
                email: email.clone(),
                ..Default::default()
            });
            state.credential_refs.insert(id, credential_ref.clone());
        }
        // 前置条件：这份 state 的语义完全合法，唯一的问题就是编码后太大。
        validate_state_invariants(&state).expect("bulk state must stay semantically valid");

        let error = encode_v2(&state)
            .expect_err("an oversized document must not be encodable")
            .to_string();
        assert!(
            error.contains("exceeds"),
            "unexpected encoder error: {error}"
        );
    }

    /// AC-R1-3.1: chmod 之后的复核必须 fail-closed。
    ///
    /// 为什么不能端到端：非 root 进程在普通文件系统上既没法让 `chmod` 报错，
    /// 也没法让它"返回成功但不生效"，这条分支跑不到。所以把 chmod 与复核抽成
    /// 两个注入点，测试直接驱动 `tighten_mode_verified` 的这两种失败。
    #[cfg(unix)]
    #[test]
    fn tighten_mode_bails_when_chmod_silently_did_not_apply() {
        let path = Path::new("/tmp/sagy-tighten-probe/credentials.json");
        let mut applied = 0usize;
        let error = tighten_mode_verified(
            path,
            0o644,
            0o600,
            |desired| {
                assert_eq!(desired, 0o600);
                applied += 1;
                Ok(())
            },
            // 文件系统静默忽略了 chmod：复核看到的还是旧 mode。
            || Ok(0o644),
        )
        .expect_err("an ineffective chmod must fail closed")
        .to_string();
        assert_eq!(applied, 1, "chmod was not attempted");
        assert!(
            error.contains("mode is still 644"),
            "unexpected tighten error: {error}"
        );
    }

    /// AC-R1-3.1: chmod 自身报错时同样必须上抛，不能吞掉。
    #[cfg(unix)]
    #[test]
    fn tighten_mode_propagates_a_failing_chmod() {
        let path = Path::new("/tmp/sagy-tighten-probe/credentials.json");
        let error = tighten_mode_verified(
            path,
            0o644,
            0o600,
            |_| bail!("simulated chmod failure"),
            // 复核本身会说"权限已经是 0600"，所以只有 chmod 的错误被上抛才会失败。
            || Ok(0o600),
        )
        .expect_err("a failing chmod must fail closed")
        .to_string();
        assert!(
            error.contains("simulated chmod failure"),
            "unexpected tighten error: {error}"
        );
    }

    /// 已经足够紧的 mode 不得触发任何 chmod。
    #[cfg(unix)]
    #[test]
    fn tighten_mode_skips_files_that_are_already_tight() {
        let path = Path::new("/tmp/sagy-tighten-probe/credentials.json");
        tighten_mode_verified(
            path,
            0o600,
            0o600,
            |_| panic!("an already tight file must not be chmod-ed"),
            || panic!("an already tight file must not be re-inspected"),
        )
        .expect("an already tight file is accepted");
    }

    #[test]
    fn v2_encoder_never_emits_runtime_secret_or_path() {
        let mut state = v2_state();
        state.accounts[0].oauth_token = Some("secret-token".to_string());
        state.accounts[0].auth_path = "/absolute/private/token".to_string();
        let encoded = String::from_utf8(encode_v2(&state).unwrap()).unwrap();
        assert!(!encoded.contains("secret-token"));
        assert!(!encoded.contains("absolute/private"));
        assert!(encoded.contains("credential_ref"));
    }

    #[test]
    fn v2_encoder_rejects_account_without_ref() {
        let mut state = v2_state();
        state.credential_refs.clear();
        assert!(encode_v2(&state).is_err());
    }

    #[test]
    fn v2_current_and_active_profile_are_one_consistent_source() {
        let mut current_without_profile = v2_state();
        current_without_profile.current_account_id = Some("acc-1".to_string());
        assert!(encode_v2(&current_without_profile).is_err());

        let mut profile_without_current = v2_state();
        profile_without_current.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: profile_without_current.credential_refs["acc-1"]
                .fingerprint
                .clone(),
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        assert!(encode_v2(&profile_without_current).is_err());
    }

    #[test]
    fn v2_managed_layout_is_limited_to_matching_oauth_slots() {
        let mut state = v2_state();
        state.current_account_id = Some("acc-1".to_string());
        state.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: state.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        assert!(encode_v2(&state).is_ok());

        state
            .credential_refs
            .insert("acc-1".to_string(), ref_for(CredentialRefKind::ApiKey));
        state.accounts[0].account_type = AccountType::ApiKey;
        state.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: state.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        assert!(encode_v2(&state).is_err());
    }

    #[test]
    fn v2_wire_round_trip_preserves_profile_and_watermark() {
        let mut state = v2_state();
        state.current_account_id = Some("acc-1".to_string());
        let fingerprint = state.credential_refs["acc-1"].fingerprint.clone();
        state.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: fingerprint,
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        state.sync_watermarks.insert(
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            SyncWatermark {
                generation: 3,
                semantic_sha256: digest(),
            },
        );
        let bytes = encode_v2(&state).unwrap();
        let parsed = parse_snapshot(&DocumentSnapshot {
            digest: Some(DocumentDigest::from_bytes(&bytes)),
            bytes: Some(bytes),
        })
        .unwrap();
        assert_eq!(parsed.state.active_profile, state.active_profile);
        assert_eq!(parsed.state.sync_watermarks, state.sync_watermarks);
    }

    #[test]
    fn managed_layout_round_trips_all_valid_slot_shapes() {
        let cases = [
            (
                AccountType::OAuth,
                CredentialRefKind::OauthAccessToken,
                token_layout(),
            ),
            (
                AccountType::OAuth,
                CredentialRefKind::OauthAuthorizedUser,
                authorized_user_layout(),
            ),
            (
                AccountType::ApiKey,
                CredentialRefKind::ApiKey,
                absent_layout(),
            ),
            (
                AccountType::Vertex,
                CredentialRefKind::VertexServiceAccount,
                absent_layout(),
            ),
        ];
        for (account_type, reference_kind, layout) in cases {
            let mut state = v2_state();
            state.accounts[0].account_type = account_type;
            state
                .credential_refs
                .insert("acc-1".to_string(), ref_for(reference_kind));
            state.current_account_id = Some("acc-1".to_string());
            state.active_profile = Some(ActiveProfile {
                account_id: "acc-1".to_string(),
                credential_fingerprint: state.credential_refs["acc-1"].fingerprint.clone(),
                home_scope_id: digest(),
                managed_layout: layout,
            });
            let bytes = encode_v2(&state).unwrap();
            let parsed = parse_snapshot(&DocumentSnapshot {
                digest: Some(DocumentDigest::from_bytes(&bytes)),
                bytes: Some(bytes),
            })
            .unwrap();
            assert_eq!(parsed.state.active_profile, state.active_profile);
        }
    }

    #[test]
    fn managed_layout_rejects_api_vertex_files_and_oauth_slot_mismatch() {
        let mut api = v2_state();
        api.accounts[0].account_type = AccountType::ApiKey;
        api.credential_refs
            .insert("acc-1".to_string(), ref_for(CredentialRefKind::ApiKey));
        api.current_account_id = Some("acc-1".to_string());
        api.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: api.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        assert!(encode_v2(&api).is_err());

        let mut vertex = api.clone();
        vertex.accounts[0].account_type = AccountType::Vertex;
        vertex.credential_refs.insert(
            "acc-1".to_string(),
            ref_for(CredentialRefKind::VertexServiceAccount),
        );
        vertex.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: vertex.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: authorized_user_layout(),
        });
        assert!(encode_v2(&vertex).is_err());

        let mut oauth_access = v2_state();
        oauth_access.current_account_id = Some("acc-1".to_string());
        oauth_access.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: oauth_access.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: authorized_user_layout(),
        });
        assert!(encode_v2(&oauth_access).is_err());

        let mut oauth_authorized = v2_state();
        oauth_authorized.credential_refs.insert(
            "acc-1".to_string(),
            ref_for(CredentialRefKind::OauthAuthorizedUser),
        );
        oauth_authorized.current_account_id = Some("acc-1".to_string());
        oauth_authorized.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: oauth_authorized.credential_refs["acc-1"]
                .fingerprint
                .clone(),
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        assert!(encode_v2(&oauth_authorized).is_err());
    }

    #[test]
    fn old_or_incomplete_active_profile_wire_is_rejected_explicitly() {
        let profile_base = serde_json::json!({
            "account_id": "acc-1",
            "credential_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "home_scope_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        });
        let old_profile = serde_json::json!({
            "account_id": "acc-1",
            "credential_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "home_scope_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "managed_file": {
                "slot": "antigravity_token",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        });
        let unknown_layout = serde_json::json!({
            "account_id": "acc-1",
            "credential_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "home_scope_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "managed_layout": {
                "token": "absent",
                "authorized_user": "absent",
                "future": "absent"
            }
        });
        for profile in [old_profile, profile_base, unknown_layout] {
            let document = serde_json::json!({
                "version": 2,
                "revision": 1,
                "accounts": [{
                    "id": "acc-1",
                    "email": "user@example.com",
                    "account_type": "oauth",
                    "added_at": 0,
                    "updated_at": 0,
                    "last_used_at": null,
                    "credential_ref": {
                        "kind": "oauth_access_token",
                        "fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }
                }],
                "usage_cache": {},
                "current_account_id": "acc-1",
                "active_profile": profile,
                "sync_watermarks": {}
            });
            let bytes = serde_json::to_vec(&document).unwrap();
            assert!(
                parse_snapshot(&DocumentSnapshot {
                    digest: Some(DocumentDigest::from_bytes(&bytes)),
                    bytes: Some(bytes),
                })
                .is_err()
            );
        }
    }

    #[test]
    fn exact_slot_digest_is_validated_and_unknown_exact_fields_fail() {
        let mut invalid = v2_state();
        invalid.current_account_id = Some("acc-1".to_string());
        invalid.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: invalid.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: ManagedLayout {
                antigravity_token: SlotState::Exact {
                    sha256: "A".repeat(64),
                },
                gemini_authorized_user: SlotState::Absent,
            },
        });
        assert!(encode_v2(&invalid).is_err());

        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [],
            "usage_cache": {},
            "current_account_id": null,
            "active_profile": null,
            "sync_watermarks": {}
        }))
        .unwrap();
        assert!(
            parse_snapshot(&DocumentSnapshot {
                digest: Some(DocumentDigest::from_bytes(&bytes)),
                bytes: Some(bytes),
            })
            .is_ok()
        );

        let unknown_exact = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [{
                "id": "acc-1",
                "email": "user@example.com",
                "account_type": "oauth",
                "added_at": 0,
                "updated_at": 0,
                "last_used_at": null,
                "credential_ref": {
                    "kind": "oauth_access_token",
                    "fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            }],
            "usage_cache": {},
            "current_account_id": "acc-1",
            "active_profile": {
                "account_id": "acc-1",
                "credential_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "home_scope_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "managed_layout": {
                    "token": {"exact": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "future": true}},
                    "authorized_user": "absent"
                }
            },
            "sync_watermarks": {}
        });
        let bytes = serde_json::to_vec(&unknown_exact).unwrap();
        assert!(
            parse_snapshot(&DocumentSnapshot {
                digest: Some(DocumentDigest::from_bytes(&bytes)),
                bytes: Some(bytes),
            })
            .is_err()
        );
    }

    #[test]
    fn strict_duplicate_and_unknown_fields_rejected() {
        for bytes in [
            br#"{"version":2,"revision":1,"accounts":[],"revision":2}"#.as_slice(),
            br#"{"version":2,"revision":1,"accounts":[],"unknown":true}"#.as_slice(),
            br#"{"version":2,"revision":1,"accounts":[]}"#.as_slice(),
        ] {
            assert!(
                parse_snapshot(&DocumentSnapshot {
                    bytes: Some(bytes.to_vec()),
                    digest: Some(DocumentDigest::from_bytes(bytes)),
                })
                .is_err()
            );
        }
    }

    #[test]
    fn future_corrupt_truncated_and_oversized_documents_fail_closed() {
        for bytes in [
            br#"{"version":3,"revision":1,"accounts":[],"usage_cache":{},"current_account_id":null,"active_profile":null,"sync_watermarks":{}}"#.to_vec(),
            br#"{"version":2,"revision":1,"accounts":["#.to_vec(),
        ] {
            assert!(parse_snapshot(&DocumentSnapshot {
                digest: Some(DocumentDigest::from_bytes(&bytes)),
                bytes: Some(bytes),
            })
            .is_err());
        }
        let bytes = vec![b' '; MAX_STATE_BYTES + 1];
        assert!(
            parse_snapshot(&DocumentSnapshot {
                digest: Some(DocumentDigest::from_bytes(&bytes)),
                bytes: Some(bytes),
            })
            .is_err()
        );
    }

    #[test]
    fn v1_read_is_legacy_migration_without_write() {
        let bytes = br#"{"version":1,"accounts":[{"id":"a-1","email":"a@example.com","account_type":"oauth","oauth_token":"token","auth_path":"/tmp/token"}],"usage_cache":{},"current_account_id":null}"#;
        let parsed = parse_snapshot(&DocumentSnapshot {
            bytes: Some(bytes.to_vec()),
            digest: Some(DocumentDigest::from_bytes(bytes)),
        })
        .unwrap();
        assert_eq!(parsed.migration, MigrationStatus::LegacyV1);
        assert_eq!(parsed.revision.generation, RevisionGeneration::Legacy);
        assert!(
            parsed
                .state
                .credential_refs
                .contains_key(&parsed.state.accounts[0].id)
        );
    }

    #[test]
    fn v1_unknown_health_never_migrates_to_ready_or_keeps_error_text() {
        let bytes = br#"{"version":1,"accounts":[{"id":"a-1","email":"a@example.com","account_type":"oauth","oauth_token":"token"}],"usage_cache":{"a-1":{"status":"future-status","remaining_quota_percent":100,"last_synced_at":10,"last_sync_error":"secret endpoint text"}},"current_account_id":null}"#;
        let parsed = parse_snapshot(&DocumentSnapshot {
            bytes: Some(bytes.to_vec()),
            digest: Some(DocumentDigest::from_bytes(bytes)),
        })
        .unwrap();
        let usage = parsed.state.usage_cache.get("a-1").unwrap();
        assert_eq!(usage.health, HealthStatus::TransientFailure);
        assert_eq!(usage.remaining_quota_percent, None);
        assert_eq!(usage.last_error, Some(HealthErrorKind::Unknown));
        let encoded = serde_json::to_string(usage).unwrap();
        assert!(!encoded.contains("secret endpoint text"));
        assert!(!encoded.contains("last_sync_error"));
        assert!(!encoded.contains("needs_relogin"));
        assert!(!encoded.contains("status"));
    }

    #[test]
    fn v2_usage_wire_is_typed_and_rejects_legacy_fields() {
        let bytes = br#"{"version":2,"revision":1,"accounts":[],"usage_cache":{"a-1":{"health":"ready","status":"Ready"}},"current_account_id":null,"active_profile":null,"sync_watermarks":{}}"#;
        assert!(
            parse_snapshot(&DocumentSnapshot {
                bytes: Some(bytes.to_vec()),
                digest: Some(DocumentDigest::from_bytes(bytes)),
            })
            .is_err()
        );

        let bytes = br#"{"version":2,"revision":1,"accounts":[],"usage_cache":{"a-1":{"health":"transient_failure","last_error":"secret"}},"current_account_id":null,"active_profile":null,"sync_watermarks":{}}"#;
        assert!(
            parse_snapshot(&DocumentSnapshot {
                bytes: Some(bytes.to_vec()),
                digest: Some(DocumentDigest::from_bytes(bytes)),
            })
            .is_err()
        );
    }

    #[test]
    fn v1_external_auth_path_is_not_read_or_used_for_reference() {
        let temp = tempfile::tempdir().unwrap();
        let token_path = temp.path().join("legacy-token");
        fs::write(&token_path, b"file-access-token").unwrap();
        let bytes = format!(
            "{{\"version\":1,\"accounts\":[{{\"id\":\"a-1\",\"account_type\":\"oauth\",\"auth_path\":{}}}],\"usage_cache\":{{}}}}",
            serde_json::to_string(&token_path).unwrap()
        )
        .into_bytes();
        let parsed = parse_snapshot(&DocumentSnapshot {
            digest: Some(DocumentDigest::from_bytes(&bytes)),
            bytes: Some(bytes.clone()),
        })
        .unwrap();
        assert!(!parsed.state.credential_refs.contains_key("a-1"));
        fs::remove_file(&token_path).unwrap();
        let reparsed = parse_snapshot(&DocumentSnapshot {
            digest: Some(DocumentDigest::from_bytes(&bytes)),
            bytes: Some(bytes),
        })
        .unwrap();
        assert_eq!(reparsed.state.credential_refs, parsed.state.credential_refs);
        assert!(!temp.path().join("accounts").exists());
    }

    fn seed_current_store(temp: &tempfile::TempDir) -> StateStore {
        let root = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = v2_state();
        fs::write(root.join(STATE_TARGET), encode_v2(&state).unwrap()).unwrap();
        StateStore::open(&root).unwrap()
    }

    fn write_prepared_journal(
        root: &Path,
        base: Option<DocumentDigest>,
        target: DocumentDigest,
        txid: uuid::Uuid,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let staged_name = format!(".sagy-{txid}.staged");
        let journal_name = format!(
            ".sagy-{}.journal",
            DocumentDigest::from_bytes(STATE_TARGET.as_bytes()).to_hex()
        );
        let staged = root.join(&staged_name);
        let journal = root.join(&journal_name);
        let bytes = serde_json::json!({
            "journal_version": 1,
            "txid": txid.to_string(),
            "phase": "prepared",
            "base_digest": base.map(DocumentDigest::to_hex),
            "target_digest": target.to_hex(),
            "target": STATE_TARGET,
            "staged": staged_name,
        })
        .to_string();
        fs::write(&journal, bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        (staged, journal)
    }

    #[test]
    fn pure_read_reports_pending_recovery_without_mutating_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let root = temp.path().join("state");
        let live = fs::read(root.join(STATE_TARGET)).unwrap();
        let mut target_state = v2_state();
        target_state.accounts[0].plan = Some("pro".to_string());
        let staged_bytes = encode_v2(&target_state).unwrap();
        let txid = uuid::Uuid::new_v4();
        let (staged, journal) = write_prepared_journal(
            &root,
            Some(DocumentDigest::from_bytes(&live)),
            DocumentDigest::from_bytes(&staged_bytes),
            txid,
        );
        fs::write(&staged, &staged_bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
        let journal_before = fs::read(&journal).unwrap();
        let staged_before = fs::read(&staged).unwrap();

        let read = store.read().unwrap();
        assert!(read.recovery_pending);
        assert_eq!(read.revision.generation, RevisionGeneration::Current(1));
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert_eq!(fs::read(&staged).unwrap(), staged_before);
    }

    #[test]
    fn pure_read_rejects_recovery_conflict_and_preserves_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let root = temp.path().join("state");
        let live = fs::read(root.join(STATE_TARGET)).unwrap();
        let mut target_state = v2_state();
        target_state.accounts[0].plan = Some("pro".to_string());
        let staged_bytes = encode_v2(&target_state).unwrap();
        let txid = uuid::Uuid::new_v4();
        let (staged, journal) = write_prepared_journal(
            &root,
            Some(DocumentDigest::from_bytes(&live)),
            DocumentDigest::from_bytes(&staged_bytes),
            txid,
        );
        fs::write(&staged, &staged_bytes).unwrap();
        fs::write(root.join(STATE_TARGET), b"unrelated-live-bytes").unwrap();
        let journal_before = fs::read(&journal).unwrap();
        let staged_before = fs::read(&staged).unwrap();

        assert!(store.read().is_err());
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        assert_eq!(fs::read(&staged).unwrap(), staged_before);
    }

    #[test]
    fn pure_read_rejects_future_journal_without_lock_or_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let root = temp.path().join("state");
        let journal = root.join(format!(
            ".sagy-{}.journal",
            DocumentDigest::from_bytes(STATE_TARGET.as_bytes()).to_hex()
        ));
        fs::write(
            &journal,
            br#"{"journal_version":99,"txid":"not-a-uuid","phase":"prepared","base_digest":null,"target_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target":"state.json","staged":".sagy-not-a-uuid.staged"}"#,
        )
        .unwrap();
        assert!(store.read().is_err());
        assert!(journal.exists());
        assert!(
            !root
                .join(format!(
                    ".sagy-{}.lock",
                    DocumentDigest::from_bytes(STATE_TARGET.as_bytes()).to_hex()
                ))
                .exists()
        );
    }

    #[test]
    fn lock_exact_allows_multiple_monotonic_commits() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let current = store.read().unwrap();
        let mut seen = Vec::new();
        store
            .with_locked_exact(&current.revision, |txn| {
                seen.push(txn.commit_exact(&v2_state())?.generation);
                let mut second = v2_state();
                second.current_account_id = None;
                seen.push(txn.commit_exact(&second)?.generation);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            seen,
            [
                RevisionGeneration::Current(2),
                RevisionGeneration::Current(3)
            ]
        );
        assert_eq!(
            store.read().unwrap().revision.generation,
            RevisionGeneration::Current(3)
        );
    }

    #[test]
    fn readonly_read_accepts_its_persistent_lock_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let current = store.read().unwrap();
        store.commit(&current.revision, &v2_state()).unwrap();
        let read = StateStore::read_from_path(temp.path().join("state").as_path()).unwrap();
        assert_eq!(read.revision.generation, RevisionGeneration::Current(2));
    }

    #[test]
    fn independent_handles_report_exact_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let first = seed_current_store(&temp);
        let second = StateStore::open(temp.path().join("state").as_path()).unwrap();
        let current = first.read().unwrap();
        first.commit(&current.revision, &v2_state()).unwrap();
        let error = second.commit(&current.revision, &v2_state()).unwrap_err();
        assert!(matches!(error, StateStoreError::Conflict { .. }));
    }

    #[test]
    fn readonly_missing_path_has_no_side_effect() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing").join("nested");
        let store = StateStore::open(&path).unwrap();
        let constructed = store.read().unwrap();
        assert_eq!(constructed.revision.generation, RevisionGeneration::Missing);
        assert!(!path.exists());
        let read = StateStore::read_from_path(&path).unwrap();
        assert_eq!(read.revision.generation, RevisionGeneration::Missing);
        assert!(!path.exists());
    }

    #[test]
    fn root_metadata_classifier_only_swallows_not_found() {
        assert!(
            classify_root_metadata(Err(io::Error::from(io::ErrorKind::NotFound)))
                .unwrap()
                .is_none()
        );
        let error = classify_root_metadata(Err(io::Error::from(io::ErrorKind::PermissionDenied)))
            .unwrap_err();
        assert!(error.downcast_ref::<io::Error>().is_some());
    }

    #[test]
    fn ordinary_missing_commit_is_rejected_without_claiming_root() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing");
        let store = StateStore::open(&path).unwrap();
        let missing = store.read().unwrap();
        assert!(matches!(
            store.commit(&missing.revision, &v2_state()),
            Err(StateStoreError::MigrationRequired)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn missing_session_bootstraps_only_on_explicit_empty_v2_request() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing");
        let store = StateStore::open(&path).unwrap();
        let mut session = StateSession::bootstrap_exact(&store).unwrap();
        assert_eq!(session.migration(), MigrationStatus::Missing);
        assert_eq!(session.revision().generation, RevisionGeneration::Missing);
        assert!(!path.exists());

        let committed = session.bootstrap_empty_v2().unwrap();
        assert_eq!(
            committed.after().revision.generation,
            RevisionGeneration::Current(1)
        );
        assert_eq!(committed.after().state.version, STATE_V2_VERSION);
        assert!(committed.after().state.accounts.is_empty());
        assert_eq!(
            committed.receipt().revision().generation,
            RevisionGeneration::Current(1)
        );
        assert!(path.join(STATE_TARGET).is_file());
        assert_eq!(session.revision(), &committed.after().revision);
        assert_eq!(session.migration(), MigrationStatus::None);
    }

    #[test]
    fn state_session_commits_are_monotonic_and_return_exact_after_receipts() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let mut session = store.session().unwrap();
        let first = session.commit(&v2_state()).unwrap();
        assert_eq!(
            first.after().revision.generation,
            RevisionGeneration::Current(2)
        );
        assert_eq!(first.receipt().revision(), &first.after().revision);

        let mut candidate = first.value().clone();
        candidate.accounts[0].plan = Some("pro".to_string());
        let second = session.commit_exact(&candidate).unwrap();
        assert_eq!(
            second.after().revision.generation,
            RevisionGeneration::Current(3)
        );
        assert_eq!(session.state(), &second.after().state);
        assert_eq!(session.revision(), &second.after().revision);
        assert_eq!(
            second.after().revision.document_sha256,
            second.receipt().revision().document_sha256
        );
    }

    #[test]
    fn state_session_advances_after_callback_reports_post_commit_recovery_error() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let mut session = store.session().unwrap();
        let before = session.revision().clone();
        let error = session.with_locked_exact::<(), StateStoreError, _>(|transaction| {
            transaction.commit_exact(&v2_state())?;
            Err(StateStoreError::Invalid(anyhow!(
                "active-home finalize requires recovery"
            )))
        });
        assert!(matches!(error, Err(StateStoreError::Invalid(_))));
        assert_ne!(session.revision(), &before);
        assert_eq!(session.revision(), &store.read().unwrap().revision);
        assert_eq!(
            session.revision().generation,
            RevisionGeneration::Current(2)
        );
    }

    #[test]
    fn coordinated_commit_binds_journal_to_before_after_and_txid() {
        use crate::adapters::antigravity::account::credential_store::CredentialStore;

        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let current = store.read().unwrap();
        let credential = PortableCredential::oauth_access_token("coordinated-token").unwrap();
        let mut receipt = None;
        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                candidate.credential_refs.insert(
                    "new-account".to_string(),
                    proof.after_ref().unwrap().clone(),
                );
                let committed = transaction.commit_coordinated(&candidate, vec![proof])?;
                credentials
                    .finalize(published, &committed)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                receipt = Some(committed);
                Ok(())
            })
            .unwrap();
        let receipt = receipt.unwrap();
        let transition = receipt.credential_transition("new-account").unwrap();
        assert_eq!(
            transition.after_ref().unwrap().kind,
            CredentialRefKind::OauthAccessToken
        );
        assert!(transition.before_ref().is_none());
        assert_eq!(transition.committed_revision(), receipt.revision());
        assert!(
            !temp
                .path()
                .join("state/accounts/new-account")
                .read_dir()
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".journal"))
        );
    }

    #[test]
    fn restart_recovery_finalizes_only_after_current_state_commit() {
        use crate::adapters::antigravity::account::credential_store::CredentialStore;

        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let current = store.read().unwrap();
        let credential = PortableCredential::oauth_access_token("restart-finalize").unwrap();
        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                candidate.credential_refs.insert(
                    "new-account".to_string(),
                    proof.after_ref().unwrap().clone(),
                );
                let _committed = transaction.commit_coordinated(&candidate, vec![proof])?;
                drop(published);
                Ok(())
            })
            .unwrap();

        let after = store.read().unwrap();
        store
            .with_locked_exact(&after.revision, |transaction| {
                let authority = transaction.recovery_authority()?;
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                credentials
                    .recover_pending(authority)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .unwrap();
        assert!(
            !temp
                .path()
                .join("state/accounts/new-account")
                .read_dir()
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".journal"))
        );
    }

    #[test]
    fn legacy_recovery_authority_always_rolls_back_published_layout() {
        use crate::adapters::antigravity::account::credential_store::CredentialStore;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join(STATE_TARGET),
            br#"{"version":1,"accounts":[],"usage_cache":{},"current_account_id":null}"#,
        )
        .unwrap();
        let store = StateStore::open(&root).unwrap();
        let legacy = store.read().unwrap();
        assert_eq!(legacy.revision.generation, RevisionGeneration::Legacy);
        store
            .with_locked_exact(&legacy.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let credential = PortableCredential::oauth_access_token("legacy-recovery").unwrap();
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                drop(published);
                let authority = transaction.recovery_authority()?;
                assert!(matches!(authority, RecoveryAuthority::Legacy(_)));
                credentials
                    .recover_pending(authority)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                assert!(
                    credentials
                        .read_kind(CredentialRefKind::OauthAccessToken)
                        .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?
                        .is_none()
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn same_reference_cannot_use_an_old_finalize_receipt() {
        use crate::adapters::antigravity::account::credential_store::{
            CredentialStore, CredentialStoreError,
        };

        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let current = store.read().unwrap();
        let credential = PortableCredential::oauth_access_token("same-reference").unwrap();
        let mut first_receipt = None;
        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                candidate.credential_refs.insert(
                    "new-account".to_string(),
                    proof.after_ref().unwrap().clone(),
                );
                first_receipt = Some(transaction.commit_coordinated(&candidate, vec![proof])?);
                drop(published);
                Ok(())
            })
            .unwrap();
        let first_receipt = first_receipt.unwrap();
        let next = store.read().unwrap();
        store
            .with_locked_exact(&next.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let candidate = transaction.snapshot()?.state;
                let second_receipt = transaction.commit_coordinated(&candidate, vec![proof])?;
                assert!(matches!(
                    credentials.finalize(published, &first_receipt),
                    Err(CredentialStoreError::ReconcileRequired { .. })
                ));
                // The current transaction remains recoverable with its own
                // receipt; the stale receipt must not consume its evidence.
                let _ = second_receipt;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn coordinated_commit_rejects_wrong_txid_and_base_revision() {
        use crate::adapters::antigravity::account::credential_store::CredentialStore;

        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let credential = PortableCredential::oauth_access_token("proof-binding").unwrap();
        let current = store.read().unwrap();

        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let after_ref = proof.after_ref().cloned().unwrap();
                proof.txid = Uuid::new_v4();
                let mut candidate = transaction.snapshot()?.state;
                candidate.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                candidate
                    .credential_refs
                    .insert("new-account".to_string(), after_ref);
                assert!(matches!(
                    transaction.commit_coordinated(&candidate, vec![proof]),
                    Err(StateStoreError::Invalid(_))
                ));
                credentials
                    .restore(published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .unwrap();

        let current = store.read().unwrap();
        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let after_ref = proof.after_ref().cloned().unwrap();
                proof.base_revision = Revision {
                    generation: RevisionGeneration::Current(99),
                    document_sha256: Some(digest()),
                };
                let mut candidate = transaction.snapshot()?.state;
                candidate.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                candidate
                    .credential_refs
                    .insert("new-account".to_string(), after_ref);
                assert!(matches!(
                    transaction.commit_coordinated(&candidate, vec![proof]),
                    Err(StateStoreError::Conflict { .. })
                ));
                credentials
                    .restore(published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.read().unwrap().revision.generation,
            current.revision.generation
        );
    }

    #[test]
    fn ordinary_exact_receipt_cannot_finalize_a_credential_journal() {
        use crate::adapters::antigravity::account::credential_store::{
            CredentialStore, CredentialStoreError,
        };

        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let current = store.read().unwrap();
        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let credential =
                    PortableCredential::oauth_access_token("ordinary-receipt").unwrap();
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut with_reference = transaction.snapshot()?.state;
                with_reference.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                with_reference.credential_refs.insert(
                    "new-account".to_string(),
                    proof.after_ref().cloned().unwrap(),
                );
                // R10-1.2: 普通提交连"改动 credential_refs"这一步都不允许, 引用
                // 变更必须带着 credential journal proof 走协调提交。
                let rejected = transaction
                    .commit_exact_receipt(&with_reference)
                    .expect_err("an ordinary commit must not move a credential reference");
                assert!(
                    format!("{rejected}").contains("sealed credential journal proof"),
                    "unexpected rejection: {rejected}"
                );
                // 引用不变的普通提交仍然可以成功, 但它的 receipt 依旧不携带任何
                // credential transition, 所以 finalize 必须失败。
                let candidate = transaction.snapshot()?.state;
                let receipt = transaction.commit_exact_receipt(&candidate)?;
                assert!(receipt.credential_transition("new-account").is_none());
                let error = credentials.finalize(published, &receipt).unwrap_err();
                let token = match error {
                    CredentialStoreError::ReconcileRequired {
                        token: Some(token), ..
                    } => token,
                    other => panic!("ordinary receipt unexpectedly finalized: {other:?}"),
                };
                credentials
                    .restore_reconcile(token)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn coordinated_delete_commits_after_none_and_finalizes() {
        use crate::adapters::antigravity::account::credential_store::CredentialStore;

        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let credential = PortableCredential::oauth_access_token("delete-coordinated").unwrap();
        let current = store.read().unwrap();

        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let prepared = credentials
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.accounts.push(AccountRecord {
                    id: "new-account".to_string(),
                    email: "new@example.com".to_string(),
                    account_type: AccountType::OAuth,
                    ..Default::default()
                });
                candidate.credential_refs.insert(
                    "new-account".to_string(),
                    proof.after_ref().cloned().unwrap(),
                );
                let receipt = transaction.commit_coordinated(&candidate, vec![proof])?;
                credentials
                    .finalize(published, &receipt)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .unwrap();

        let current = store.read().unwrap();
        store
            .with_locked_exact(&current.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credentials = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let expected = credentials
                    .read_layout()
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?
                    .expected_layout();
                let prepared = credentials
                    .stage_delete(Uuid::new_v4(), &expected)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let published = credentials
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let proof = credentials
                    .journal_proof(&published)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                assert!(proof.after_ref().is_none());
                let mut candidate = transaction.snapshot()?.state;
                candidate
                    .accounts
                    .retain(|account| account.id != "new-account");
                candidate.credential_refs.remove("new-account");
                let receipt = transaction.commit_coordinated(&candidate, vec![proof])?;
                let transition = receipt
                    .credential_transition("new-account")
                    .expect("delete transition");
                assert!(transition.after_ref().is_none());
                credentials
                    .finalize(published, &receipt)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .unwrap();

        let after = store.read().unwrap();
        assert!(
            !after
                .state
                .accounts
                .iter()
                .any(|account| account.id == "new-account")
        );
        assert!(!after.state.credential_refs.contains_key("new-account"));
        assert!(
            !temp
                .path()
                .join("state/accounts/new-account/antigravity-oauth-token")
                .exists()
        );
    }

    #[test]
    fn active_profile_receipt_and_locked_current_proof_are_opaque_and_exact() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let mut session = store.session().unwrap();
        let mut candidate = v2_state();
        candidate.current_account_id = Some("acc-1".to_string());
        candidate.active_profile = Some(ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: candidate.credential_refs["acc-1"].fingerprint.clone(),
            home_scope_id: digest(),
            managed_layout: token_layout(),
        });
        assert!(session.commit(&candidate).is_err());
        // A current credential proof intentionally carries no active-home
        // finalize authority; that authority is minted by the dedicated
        // active_home_recovery_authority endpoint under the State lock.
        let current = store.read().unwrap();
        let authority = store
            .with_locked_exact(&current.revision, |transaction| {
                transaction.active_home_recovery_authority()
            })
            .unwrap();
        assert!(matches!(authority, ActiveHomeRecoveryAuthority::Current(_)));
    }

    #[test]
    fn independent_state_sessions_conflict_on_stale_exact_revision() {
        let temp = tempfile::tempdir().unwrap();
        let store = seed_current_store(&temp);
        let mut first = store.session().unwrap();
        let mut second = store.session().unwrap();
        first.commit(&v2_state()).unwrap();
        let error = second.commit(&v2_state()).unwrap_err();
        assert!(matches!(error, StateStoreError::Conflict { .. }));
        assert_eq!(second.revision().generation, RevisionGeneration::Current(1));
    }

    #[test]
    fn v1_session_exposes_sealed_migration_permit_without_home_scanning() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join(STATE_TARGET),
            br#"{"version":1,"accounts":[],"usage_cache":{},"current_account_id":null}"#,
        )
        .unwrap();
        let store = StateStore::open(&root).unwrap();
        let mut session = store.session().unwrap();
        assert_eq!(session.migration(), MigrationStatus::LegacyV1);
        let permit = session.migration_permit(Vec::new()).unwrap();
        let committed = session
            .commit_migration(
                &State {
                    version: STATE_V2_VERSION,
                    ..State::default()
                },
                permit,
            )
            .unwrap();
        assert_eq!(
            committed.after().revision.generation,
            RevisionGeneration::Current(1)
        );
        assert_eq!(session.migration(), MigrationStatus::None);
    }

    #[test]
    fn sealed_migration_commit_requires_exact_journal_proof_set() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy");
        fs::create_dir(&root).unwrap();
        let bytes = br#"{"version":1,"accounts":[{"id":"a-1","email":"a@example.com","account_type":"oauth","oauth_token":"token"}],"usage_cache":{},"current_account_id":null}"#;
        fs::write(root.join(STATE_TARGET), bytes).unwrap();
        let store = StateStore::open(&root).unwrap();
        let legacy = store.read().unwrap();
        let no_proof = store.commit_migration(&legacy.revision, &legacy.state, Vec::new());
        assert!(matches!(no_proof, Err(StateStoreError::Invalid(_))));
        let proof = CredentialJournalProof::new(
            "a-1",
            Uuid::new_v4(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            CredentialRef {
                kind: CredentialRefKind::OauthAccessToken,
                fingerprint:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_string(),
            },
        )
        .unwrap();
        let rejected = store.commit_migration(&legacy.revision, &legacy.state, vec![proof]);
        assert!(matches!(rejected, Err(StateStoreError::Invalid(_))));
    }

    #[test]
    fn legacy_read_and_commit_preserve_bytes_mode_and_lock_absence() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy");
        fs::create_dir(&root).unwrap();
        let bytes = br#"{"version":1,"accounts":[],"usage_cache":{},"current_account_id":null}"#;
        let target = root.join(STATE_TARGET);
        fs::write(&target, bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let mode_before = {
            #[cfg(unix)]
            {
                fs::metadata(&root).unwrap().permissions().mode() & 0o777
            }
            #[cfg(not(unix))]
            {
                0
            }
        };
        let store = StateStore::open(&root).unwrap();
        let legacy = store.read().unwrap();
        assert_eq!(legacy.revision.generation, RevisionGeneration::Legacy);
        assert!(matches!(
            store.commit(&legacy.revision, &v2_state()),
            Err(StateStoreError::MigrationRequired)
        ));
        assert_eq!(fs::read(&target).unwrap(), bytes);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            mode_before
        );
        assert!(!fs::read_dir(&root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".sagy-")
        }));
    }

    #[test]
    fn independent_transactions_do_not_hold_lock_between_callbacks() {
        let temp = tempfile::tempdir().unwrap();
        let first = seed_current_store(&temp);
        let second = StateStore::open(temp.path().join("state").as_path()).unwrap();
        let first_revision = first.read().unwrap().revision;
        let second_revision = first.commit(&first_revision, &v2_state()).unwrap();
        let third_revision = second.commit(&second_revision, &v2_state()).unwrap();
        assert_eq!(third_revision.generation, RevisionGeneration::Current(3));
    }

    #[test]
    fn unknown_root_entry_is_ignored_without_creating_artifacts() {
        // 语义变更（ROOT-001）：陌生的顶层条目不再让 read 失败。SAGY_HOME 同时是
        // 安装目录，`bin/`、笔记、编辑器残留都会出现在这里。保留的不变量是：
        // 纯读依然不在 root 里创建任何 sagy 自己的产物。
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("marker"), b"x").unwrap();
        let store = StateStore::open(&root).unwrap();
        let read = store.read().unwrap();
        assert_eq!(read.migration, MigrationStatus::Missing);
        assert!(read.state.accounts.is_empty());
        assert_eq!(fs::read(root.join("marker")).unwrap(), b"x");
        assert!(!fs::read_dir(root).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".sagy-")
        }));
    }
}
