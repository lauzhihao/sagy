//! Generic single-document storage over the typed atomic filesystem layer.
//!
//! This module intentionally knows nothing about the state schema.  It stores
//! opaque bytes and protects only their exact SHA-256 digest.  State versioning
//! and migration belong to the layer above this one.

// 2b 接入 StateStore 后这些接口会成为生产调用路径；在独立工作包合并前
// 暂时允许未使用告警，避免用改变可见性来掩盖尚未接线的接口。
#![allow(dead_code)]

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, anyhow};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::atomic_io::{
    DocumentDigest, MutationFailure, NormalizedStoreRoot, OwnedStoreRoot, RootIdentity,
    SafeRelativePath, TopLevelEntryKind, TopLevelInventoryEntry,
    announce_lock_wait_before_blocking, create_new_secure_file, ensure_owned_relative_directory,
    enumerate_owned_relative_directory, enumerate_owned_relative_directory_if_present,
    inspect_normalized_relative_file, inspect_owned_relative_file, inspect_top_level_inventory,
    lock_exclusive_with_wait_notice, normalized_root_identity, open_or_create_secure_file,
    open_or_create_secure_file_normalized, read_normalized_relative_file_bounded,
    read_owned_relative_file_bounded, remove_file, replace_same_dir, sync_file, sync_parent_dir,
    validate_nonempty_root_for_adoption,
};
const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: usize = 32 * 1024;
const MAX_ADOPTION_INVENTORY_ENTRIES: usize = 256;
const MAX_ADOPTION_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ADOPTION_TARGET_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACCOUNT_DIRECTORIES: usize = 4096;

/// The expected digest supplied by a caller before a mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpectedDigest {
    /// Do not perform a compare-and-swap check.
    Any,
    /// Require the live document to have this exact digest. `None` means the
    /// document must be absent.
    Exact(Option<DocumentDigest>),
}

impl ExpectedDigest {
    fn matches(self, actual: Option<DocumentDigest>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => expected == actual,
        }
    }
}

/// A side-effect-free point-in-time read of the configured document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DocumentSnapshot {
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) digest: Option<DocumentDigest>,
}

/// Pure read entry point for callers that have only normalized a root.
/// Normalization never creates the root; this function likewise performs no
/// mutation, locking, permission changes, or recovery.
pub(crate) fn read_snapshot_from_normalized(
    root: &NormalizedStoreRoot,
    target: &SafeRelativePath,
) -> Result<DocumentSnapshot> {
    let bytes = match std::fs::symlink_metadata(root.as_path()) {
        Ok(_) => read_normalized_relative_file_bounded(root, target, MAX_ADOPTION_TARGET_BYTES)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(anyhow!(error).context("failed to inspect normalized store root"));
        }
    };
    let digest = bytes.as_deref().map(DocumentDigest::from_bytes);
    Ok(DocumentSnapshot { bytes, digest })
}

/// The successful result of a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommitReceipt {
    pub(crate) digest: DocumentDigest,
}

/// Result of resolving a prepared journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    None,
    Finalized,
    RolledBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UncertainPhase {
    /// The journal replacement may not have become visible yet; target
    /// replacement has not started.
    JournalPublication,
    /// Target replacement or final cleanup may already have changed the
    /// document; an unreferenced staged file is evidence and must be kept.
    TargetMutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdoptionArtifact {
    Ordinary,
    FixedLock,
    FixedJournal,
    DocumentStage(Uuid),
    JournalStage(Uuid),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdoptionInventoryEntry {
    pub(crate) locator: SafeRelativePath,
    pub(crate) kind: TopLevelEntryKind,
    pub(crate) size: u64,
    pub(crate) artifact: AdoptionArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedJournalPreview {
    pub(crate) txid: Uuid,
    pub(crate) base_digest: Option<DocumentDigest>,
    pub(crate) target_digest: DocumentDigest,
    pub(crate) target: SafeRelativePath,
    pub(crate) staged: SafeRelativePath,
    pub(crate) staged_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JournalPreview {
    Absent,
    Prepared(PreparedJournalPreview),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryPreview {
    Clean,
    Finalize {
        target_digest: DocumentDigest,
    },
    Rollback {
        base_digest: Option<DocumentDigest>,
    },
    Conflict {
        live: Option<DocumentDigest>,
        base: Option<DocumentDigest>,
        target: DocumentDigest,
    },
}

/// A bounded, side-effect-free inspection of the target and its prepared
/// journal.  Unlike recovery itself, this never creates a lock, changes
/// permissions, removes evidence, or mutates the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryInspection {
    pub(crate) snapshot: DocumentSnapshot,
    pub(crate) journal: JournalPreview,
    pub(crate) recovery: RecoveryPreview,
    /// The referenced stage is returned so the schema layer can validate its
    /// bytes without opening the root through an adoption handle.
    pub(crate) staged_bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdoptionPreflight {
    pub(crate) root_identity: RootIdentity,
    pub(crate) target: SafeRelativePath,
    pub(crate) lock: SafeRelativePath,
    pub(crate) journal: SafeRelativePath,
    pub(crate) inventory: Vec<AdoptionInventoryEntry>,
    pub(crate) snapshot: DocumentSnapshot,
    pub(crate) journal_preview: JournalPreview,
    pub(crate) recovery_preview: RecoveryPreview,
    pub(crate) orphan_stages: Vec<SafeRelativePath>,
}

/// Typed failures that callers may act on without string matching.
#[derive(Debug)]
pub(crate) enum AtomicStoreError {
    /// The compare-and-swap precondition did not match the live document.
    Conflict {
        expected: ExpectedDigest,
        actual: Option<DocumentDigest>,
    },
    /// A prepared journal describes a live document that is neither its base
    /// nor its intended target.  The journal is deliberately retained.
    RecoveryConflict {
        live: Option<DocumentDigest>,
        base: Option<DocumentDigest>,
        target: DocumentDigest,
    },
    /// A native operation may have changed the filesystem and the journal was
    /// not safely resolved.
    ReconcileRequired { source: anyhow::Error },
    /// The native mutation definitely did not commit.
    NotApplied { source: anyhow::Error },
    /// The journal is malformed, unknown, from a future version, or unsafe.
    InvalidJournal { source: anyhow::Error },
    /// A filesystem or serialization error outside the typed CAS cases.
    Io { source: anyhow::Error },
    /// A preflight snapshot no longer describes the locked root.
    PreflightChanged { reason: String },
    /// The caller's semantic validator rejected the locked snapshot.
    ValidatorRejected { source: anyhow::Error },
}

impl AtomicStoreError {
    fn io(error: impl Into<anyhow::Error>) -> Self {
        Self::Io {
            source: error.into(),
        }
    }

    fn not_applied(error: impl Into<anyhow::Error>) -> Self {
        Self::NotApplied {
            source: error.into(),
        }
    }

    fn reconcile(error: impl Into<anyhow::Error>) -> Self {
        Self::ReconcileRequired {
            source: error.into(),
        }
    }

    fn invalid_journal(error: impl Into<anyhow::Error>) -> Self {
        Self::InvalidJournal {
            source: error.into(),
        }
    }

    fn validator_rejected(error: impl Into<anyhow::Error>) -> Self {
        Self::ValidatorRejected {
            source: error.into(),
        }
    }

    fn into_reconcile_source(self) -> anyhow::Error {
        match self {
            Self::ReconcileRequired { source } => source,
            other => anyhow!(other.to_string()),
        }
    }

    fn from_mutation(error: MutationFailure) -> Self {
        match error {
            MutationFailure::NotApplied { .. } => Self::not_applied(error.into_source_error()),
            MutationFailure::ReconcileRequired { .. } => Self::reconcile(error.into_source_error()),
        }
    }
}

impl fmt::Display for AtomicStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { expected, actual } => {
                write!(
                    formatter,
                    "document digest conflict: expected {expected:?}, actual {actual:?}"
                )
            }
            Self::RecoveryConflict { live, base, target } => write!(
                formatter,
                "prepared journal cannot be reconciled: live {live:?}, base {base:?}, target {target}"
            ),
            Self::ReconcileRequired { source } => {
                write!(formatter, "mutation requires reconciliation: {source}")
            }
            Self::NotApplied { source } => write!(formatter, "mutation not applied: {source}"),
            Self::InvalidJournal { source } => {
                write!(formatter, "invalid atomic journal: {source}")
            }
            Self::Io { source } => write!(formatter, "atomic store I/O failed: {source}"),
            Self::PreflightChanged { reason } => {
                write!(formatter, "adoption preflight changed: {reason}")
            }
            Self::ValidatorRejected { source } => {
                write!(formatter, "adoption validator rejected root: {source}")
            }
        }
    }
}

impl std::error::Error for AtomicStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReconcileRequired { source }
            | Self::NotApplied { source }
            | Self::InvalidJournal { source }
            | Self::Io { source } => Some(source.as_ref()),
            Self::Conflict { .. } | Self::RecoveryConflict { .. } => None,
            Self::PreflightChanged { .. } => None,
            Self::ValidatorRejected { source } => Some(source.as_ref()),
        }
    }
}

impl From<anyhow::Error> for AtomicStoreError {
    fn from(source: anyhow::Error) -> Self {
        Self::io(source)
    }
}

#[derive(Debug, Serialize)]
struct JournalRecord {
    journal_version: u32,
    txid: String,
    phase: JournalPhase,
    base_digest: Option<String>,
    target_digest: String,
    target: String,
    staged: String,
}

impl<'de> Deserialize<'de> for JournalRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct JournalVisitor;

        impl<'de> Visitor<'de> for JournalVisitor {
            type Value = JournalRecord;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an atomic journal object with unique known fields")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut journal_version = None;
                let mut txid = None;
                let mut phase = None;
                let mut base_digest: Option<Option<String>> = None;
                let mut target_digest = None;
                let mut target = None;
                let mut staged = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "journal_version" => {
                            if journal_version.is_some() {
                                return Err(de::Error::duplicate_field("journal_version"));
                            }
                            journal_version = Some(map.next_value()?);
                        }
                        "txid" => {
                            if txid.is_some() {
                                return Err(de::Error::duplicate_field("txid"));
                            }
                            txid = Some(map.next_value()?);
                        }
                        "phase" => {
                            if phase.is_some() {
                                return Err(de::Error::duplicate_field("phase"));
                            }
                            phase = Some(map.next_value()?);
                        }
                        "base_digest" => {
                            if base_digest.is_some() {
                                return Err(de::Error::duplicate_field("base_digest"));
                            }
                            base_digest = Some(map.next_value()?);
                        }
                        "target_digest" => {
                            if target_digest.is_some() {
                                return Err(de::Error::duplicate_field("target_digest"));
                            }
                            target_digest = Some(map.next_value()?);
                        }
                        "target" => {
                            if target.is_some() {
                                return Err(de::Error::duplicate_field("target"));
                            }
                            target = Some(map.next_value()?);
                        }
                        "staged" => {
                            if staged.is_some() {
                                return Err(de::Error::duplicate_field("staged"));
                            }
                            staged = Some(map.next_value()?);
                        }
                        other => return Err(de::Error::unknown_field(other, JOURNAL_FIELDS)),
                    }
                }

                Ok(JournalRecord {
                    journal_version: journal_version
                        .ok_or_else(|| de::Error::missing_field("journal_version"))?,
                    txid: txid.ok_or_else(|| de::Error::missing_field("txid"))?,
                    phase: phase.ok_or_else(|| de::Error::missing_field("phase"))?,
                    base_digest: base_digest
                        .ok_or_else(|| de::Error::missing_field("base_digest"))?,
                    target_digest: target_digest
                        .ok_or_else(|| de::Error::missing_field("target_digest"))?,
                    target: target.ok_or_else(|| de::Error::missing_field("target"))?,
                    staged: staged.ok_or_else(|| de::Error::missing_field("staged"))?,
                })
            }
        }

        deserializer.deserialize_map(JournalVisitor)
    }
}

const JOURNAL_FIELDS: &[&str] = &[
    "journal_version",
    "txid",
    "phase",
    "base_digest",
    "target_digest",
    "target",
    "staged",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum JournalPhase {
    Prepared,
}

#[derive(Debug)]
struct PreparedJournal {
    base_digest: Option<DocumentDigest>,
    target_digest: DocumentDigest,
    staged: SafeRelativePath,
}

/// A generic raw-byte single-document store.
///
/// Construction requires an [`OwnedStoreRoot`].  This type never promotes a
/// populated directory and never changes root ownership or permissions.
#[derive(Clone, Debug)]
pub(crate) struct AtomicStore {
    root: OwnedStoreRoot,
    target: SafeRelativePath,
    lock: SafeRelativePath,
    journal: SafeRelativePath,
}

/// An adopted store with the fixed lock handle retained for its lifetime.
/// Methods on this type never acquire the lock again.
#[derive(Debug)]
pub(crate) struct LockedAtomicStore {
    store: AtomicStore,
    lock: File,
}

/// Account-relative capability minted from an already-held state-store lock.
/// The account locator is validated once and all later operations remain
/// relative to the owned root; credential code never receives a raw mutation
/// path from this capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountStoreCapability {
    root: OwnedStoreRoot,
    account: SafeRelativePath,
}

impl AccountStoreCapability {
    /// Read-only diagnostic root.  Mutation methods below never accept this
    /// path; they operate only on validated relative locators.
    pub(crate) fn root_path(&self) -> &Path {
        self.root.as_path()
    }

    pub(crate) fn ensure_account_dir(&self) -> Result<()> {
        ensure_owned_relative_directory(&self.root, &self.account)
    }

    pub(crate) fn locator(&self, name: &str) -> Result<SafeRelativePath> {
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(anyhow!("account artifact name is not a safe filename"));
        }
        self.account.child(name)
    }

    pub(crate) fn read_bounded(
        &self,
        locator: &SafeRelativePath,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>> {
        read_owned_relative_file_bounded(&self.root, locator, max_bytes)
    }

    pub(crate) fn inspect(
        &self,
        locator: &SafeRelativePath,
        final_may_be_missing: bool,
    ) -> Result<Option<std::fs::Metadata>> {
        inspect_owned_relative_file(&self.root, locator, final_may_be_missing)
    }

    pub(crate) fn create_new(&self, locator: &SafeRelativePath) -> Result<File> {
        create_new_secure_file(&self.root, locator)
    }

    pub(crate) fn open_or_create_lock(&self, locator: &SafeRelativePath) -> Result<File> {
        let file = open_or_create_secure_file(&self.root, locator)?;
        // 调用方拿到句柄后立刻会 `lock_exclusive` 并可能无限期阻塞（切号路径的
        // credential / active-home 两把锁都在这里）。在那之前预告一次等待，
        // 否则用户看到的就是一条完全静默挂起的命令。
        announce_lock_wait_before_blocking(&file);
        Ok(file)
    }

    pub(crate) fn replace(
        &self,
        prepared: &SafeRelativePath,
        target: &SafeRelativePath,
    ) -> std::result::Result<(), MutationFailure> {
        replace_same_dir(&self.root, prepared, target)
    }

    pub(crate) fn move_file(
        &self,
        source: &SafeRelativePath,
        destination: &SafeRelativePath,
    ) -> std::result::Result<(), MutationFailure> {
        super::atomic_io::move_same_dir(&self.root, source, destination)
    }

    pub(crate) fn remove(
        &self,
        locator: &SafeRelativePath,
    ) -> std::result::Result<bool, MutationFailure> {
        remove_file(&self.root, locator)
    }

    pub(crate) fn sync(&self, locator: &SafeRelativePath) -> Result<()> {
        sync_file(&self.root, locator)
    }

    pub(crate) fn sync_parent(&self, locator: &SafeRelativePath) -> Result<()> {
        sync_parent_dir(&self.root, locator)
    }

    pub(crate) fn artifact_locators(&self) -> Result<Vec<SafeRelativePath>> {
        let entries =
            enumerate_owned_relative_directory(&self.root, &self.account, MAX_ACCOUNT_DIRECTORIES)?;
        let mut locators = Vec::with_capacity(entries.len());
        for (locator, metadata) in entries {
            if !metadata.is_file() {
                return Err(anyhow!("account artifact is not a regular file"));
            }
            if metadata.len() > MAX_ADOPTION_FILE_BYTES {
                return Err(anyhow!("account artifact exceeds the bounded file size"));
            }
            // Re-resolve the capability locator before exposing it to the
            // caller. A concurrent replacement can only yield a regular file
            // through the no-follow resolver, never an arbitrary path.
            if inspect_owned_relative_file(&self.root, &locator, false)?.is_none() {
                return Err(anyhow!("account artifact disappeared during enumeration"));
            }
            locators.push(locator);
        }
        Ok(locators)
    }
}

impl LockedAtomicStore {
    /// Mint a capability for one validated account component while the state
    /// lock is retained by this guard.
    pub(crate) fn account_capability(&self, account_id: &str) -> Result<AccountStoreCapability> {
        crate::core::state::validate_account_id(account_id)
            .map_err(|_| anyhow!("account id is not a safe path component"))?;
        let account = SafeRelativePath::new(Path::new("accounts"))?.child(account_id)?;
        Ok(AccountStoreCapability {
            root: self.store.root.clone(),
            account,
        })
    }

    /// Enumerate account directories below the owned root without following
    /// links or accepting arbitrary filesystem names.  Recovery must inspect
    /// this directory set in addition to state.json accounts because a new
    /// account can have a published credential journal before its state entry
    /// is committed.
    pub(crate) fn account_ids(&self) -> Result<Vec<String>> {
        let accounts = SafeRelativePath::new(Path::new("accounts"))?;
        let Some(entries) = enumerate_owned_relative_directory_if_present(
            &self.store.root,
            &accounts,
            MAX_ACCOUNT_DIRECTORIES,
        )?
        else {
            return Ok(Vec::new());
        };
        let mut ids = Vec::with_capacity(entries.len());
        for (locator, metadata) in entries {
            if !metadata.is_dir() {
                return Err(anyhow!("account entry is not a regular directory"));
            }
            let name = locator
                .as_path()
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| anyhow!("account directory name is not UTF-8"))?;
            crate::core::state::validate_account_id(name)
                .map_err(|_| anyhow!("account directory name is not a valid account id"))?;
            ids.push(name.to_string());
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}

impl LockedAtomicStore {
    pub(crate) fn recover(&self) -> std::result::Result<RecoveryOutcome, AtomicStoreError> {
        self.store.recover_locked()
    }

    /// Commit with an exact expected digest while retaining this same lock.
    /// `Any` is intentionally not exposed on the locked adoption path.
    pub(crate) fn commit_exact(
        &self,
        expected: Option<DocumentDigest>,
        bytes: &[u8],
    ) -> std::result::Result<CommitReceipt, AtomicStoreError> {
        self.store
            .commit_locked(ExpectedDigest::Exact(expected), bytes)
    }

    pub(crate) fn read_snapshot(&self) -> Result<DocumentSnapshot> {
        self.store.read_snapshot()
    }

    /// Verify the live document while retaining this already-held lock.
    pub(crate) fn check_exact(
        &self,
        expected: ExpectedDigest,
    ) -> std::result::Result<DocumentSnapshot, AtomicStoreError> {
        let snapshot = self.read_snapshot().map_err(AtomicStoreError::io)?;
        if !expected.matches(snapshot.digest) {
            return Err(AtomicStoreError::Conflict {
                expected,
                actual: snapshot.digest,
            });
        }
        Ok(snapshot)
    }

    fn cleanup_orphans(
        &self,
        orphan_stages: &[SafeRelativePath],
    ) -> std::result::Result<(), AtomicStoreError> {
        for staged in orphan_stages {
            match remove_file(&self.store.root, staged) {
                Ok(_) => {}
                Err(error) => return Err(AtomicStoreError::from_mutation(error)),
            }
        }
        Ok(())
    }
}

impl AtomicStore {
    /// Build a store for one safe target locator.
    pub(crate) fn new(root: OwnedStoreRoot, target: SafeRelativePath) -> Result<Self> {
        let (lock, journal) = derive_store_locators(&target)?;
        Ok(Self {
            root,
            target,
            lock,
            journal,
        })
    }

    fn from_owned_parts(
        root: OwnedStoreRoot,
        target: SafeRelativePath,
        lock: SafeRelativePath,
        journal: SafeRelativePath,
    ) -> Self {
        Self {
            root,
            target,
            lock,
            journal,
        }
    }

    /// Produce a read-only adoption snapshot. This never creates, chmods,
    /// locks, recovers, or cleans any artifact.
    pub(crate) fn preflight_existing(
        root: &NormalizedStoreRoot,
        target: SafeRelativePath,
    ) -> std::result::Result<AdoptionPreflight, AtomicStoreError> {
        let root_identity = adoption_root_identity(root)?;
        validate_nonempty_root_for_adoption(root).map_err(AtomicStoreError::io)?;
        let (lock, journal) = derive_store_locators(&target).map_err(AtomicStoreError::io)?;
        let raw_inventory = inspect_top_level_inventory(root, MAX_ADOPTION_INVENTORY_ENTRIES)
            .map_err(AtomicStoreError::io)?;
        let bytes = read_normalized_relative_file_bounded(root, &target, MAX_ADOPTION_TARGET_BYTES)
            .map_err(AtomicStoreError::io)?;
        let snapshot = DocumentSnapshot {
            digest: bytes.as_deref().map(DocumentDigest::from_bytes),
            bytes,
        };
        let journal_preview = preview_journal(root, &target, &journal)?;
        let recovery_preview = recovery_preview(snapshot.digest, &journal_preview);
        let (inventory, orphan_stages) =
            classify_inventory(raw_inventory, &lock, &journal, &journal_preview);
        Ok(AdoptionPreflight {
            root_identity,
            target,
            lock,
            journal,
            inventory,
            snapshot,
            journal_preview,
            recovery_preview,
            orphan_stages,
        })
    }

    /// Adopt a populated root using the expected preflight identity and one
    /// lock handle that remains held by the returned store.
    ///
    /// This is the sole explicit adoption entry point. It first invokes the
    /// semantic validator without filesystem side effects, then creates or
    /// opens the target-derived private lock, acquires it, repeats the bounded
    /// preflight, invokes the validator again, and only then crosses the
    /// low-level [`OwnedStoreRoot::adopt_nonempty_locked`] boundary. The
    /// returned store retains that exact lock handle; its recovery and Exact
    /// commit methods never acquire the lock again.
    ///
    /// # Safety
    ///
    /// `expected` must be the result of [`Self::preflight_existing`] for this
    /// same normalized root and target, and the caller must treat that
    /// snapshot as a read-only expected state. The `validator` callback is
    /// invoked once before creating/opening the lock and once again after the
    /// lock is held and the bounded snapshot has been re-read. It must be
    /// repeatable and read-only: it may inspect the supplied snapshot, but
    /// must not mutate the root, replace artifacts, release or reacquire the
    /// fixed lock, or retain a reference that outlives either callback. A
    /// first-call rejection is reported as
    /// [`AtomicStoreError::ValidatorRejected`] without creating the lock; a
    /// second-call rejection leaves the lock and all recovery evidence in
    /// place and does not chmod or adopt the root. Future/unknown journal data
    /// is rejected by preflight before this function is called. The caller is
    /// responsible for making the validator strict enough for the store
    /// schema; this generic layer does not interpret state markers or schema
    /// fields. On success, the caller must keep the returned
    /// [`LockedAtomicStore`] alive while using its adopted root so the
    /// exclusive lock remains held.
    pub(crate) unsafe fn adopt_existing_with<F>(
        root: NormalizedStoreRoot,
        target: SafeRelativePath,
        expected: &AdoptionPreflight,
        validator: F,
    ) -> std::result::Result<LockedAtomicStore, AtomicStoreError>
    where
        F: Fn(&AdoptionPreflight) -> Result<()>,
    {
        let (lock, journal) = derive_store_locators(&target).map_err(AtomicStoreError::io)?;
        if expected.target != target || expected.lock != lock || expected.journal != journal {
            return Err(AtomicStoreError::PreflightChanged {
                reason: "preflight target or fixed artifact locator differs".to_string(),
            });
        }

        // Run the semantic gate before creating or opening any lock. This
        // lets an upper layer reject an unknown schema without a filesystem
        // side effect; the same callback is repeated after the locked
        // bounded re-read below to close the preflight race.
        validator(expected).map_err(AtomicStoreError::validator_rejected)?;

        let lock_file =
            open_or_create_secure_file_normalized(&root, &lock).map_err(AtomicStoreError::io)?;
        lock_exclusive_with_wait_notice(&lock_file).map_err(|error| {
            AtomicStoreError::io(anyhow!(error).context("failed to acquire adoption lock"))
        })?;

        let locked_identity = adoption_root_identity(&root)?;
        if locked_identity != expected.root_identity {
            return Err(AtomicStoreError::PreflightChanged {
                reason: "store root identity changed after preflight".to_string(),
            });
        }
        let current = Self::preflight_existing(&root, target.clone())?;
        if !preflight_equivalent_ignoring_lock(expected, &current) {
            return Err(AtomicStoreError::PreflightChanged {
                reason: "root inventory, target bytes, or journal changed after preflight"
                    .to_string(),
            });
        }
        validator(&current).map_err(AtomicStoreError::validator_rejected)?;

        // SAFETY: this function just acquired `lock_file`, rechecked the
        // identity and bounded snapshot under that lock, and the read-only
        // validator accepted the exact current preflight. The lock handle is
        // moved into `LockedAtomicStore` without being released.
        let owned = unsafe { OwnedStoreRoot::adopt_nonempty_locked(root, &expected.root_identity) }
            .map_err(AtomicStoreError::io)?;
        let store = Self::from_owned_parts(owned, target, lock, journal);
        let locked = LockedAtomicStore {
            store,
            lock: lock_file,
        };
        locked.cleanup_orphans(&current.orphan_stages)?;
        Ok(locked)
    }

    #[cfg(test)]
    fn lock_locator(&self) -> &SafeRelativePath {
        &self.lock
    }

    #[cfg(test)]
    fn journal_locator(&self) -> &SafeRelativePath {
        &self.journal
    }

    /// Read the target without locking, creating, chmod'ing, or recovering.
    pub(crate) fn read_snapshot(&self) -> Result<DocumentSnapshot> {
        let bytes =
            read_owned_relative_file_bounded(&self.root, &self.target, MAX_ADOPTION_TARGET_BYTES)?;
        let digest = bytes.as_deref().map(DocumentDigest::from_bytes);
        Ok(DocumentSnapshot { bytes, digest })
    }

    /// Recover a prepared journal while holding the store's cross-process lock.
    pub(crate) fn recover(&self) -> std::result::Result<RecoveryOutcome, AtomicStoreError> {
        let _lock = self.acquire_lock()?;
        self.recover_locked()
    }

    /// Compare-and-swap the target and publish opaque bytes atomically.
    pub(crate) fn commit(
        &self,
        expected: ExpectedDigest,
        bytes: &[u8],
    ) -> std::result::Result<CommitReceipt, AtomicStoreError> {
        let _lock = self.acquire_lock()?;
        self.commit_locked(expected, bytes)
    }

    /// Acquire the target-derived lock, recover any prepared journal, compare
    /// the live digest and return a guard that can perform multiple commits
    /// without releasing/reacquiring the same lock.
    pub(crate) fn lock_exact(
        &self,
        expected: Option<DocumentDigest>,
    ) -> std::result::Result<LockedAtomicStore, AtomicStoreError> {
        let lock = self.acquire_lock()?;
        self.recover_locked()?;
        let snapshot = self.read_snapshot().map_err(AtomicStoreError::io)?;
        if expected != snapshot.digest {
            return Err(AtomicStoreError::Conflict {
                expected: ExpectedDigest::Exact(expected),
                actual: snapshot.digest,
            });
        }
        Ok(LockedAtomicStore {
            store: self.clone(),
            lock,
        })
    }

    fn commit_locked(
        &self,
        expected: ExpectedDigest,
        bytes: &[u8],
    ) -> std::result::Result<CommitReceipt, AtomicStoreError> {
        match self.recover_locked()? {
            RecoveryOutcome::None | RecoveryOutcome::Finalized | RecoveryOutcome::RolledBack => {}
        }

        let snapshot = self.read_snapshot().map_err(AtomicStoreError::io)?;
        if !expected.matches(snapshot.digest) {
            return Err(AtomicStoreError::Conflict {
                expected,
                actual: snapshot.digest,
            });
        }

        let txid = Uuid::new_v4();
        let staged = self.staged_locator(txid)?;
        let target_digest = DocumentDigest::from_bytes(bytes);
        self.write_staged(&staged, bytes)?;

        let journal = JournalRecord {
            journal_version: JOURNAL_VERSION,
            txid: txid.to_string(),
            phase: JournalPhase::Prepared,
            base_digest: snapshot.digest.map(DocumentDigest::to_hex),
            target_digest: target_digest.to_hex(),
            target: locator_string(&self.target)?,
            staged: locator_string(&staged)?,
        };
        if let Err(error) = self.publish_journal(&journal, txid) {
            // The document staged file is not referenced by a published
            // journal yet.  Best-effort cleanup keeps a definite failure
            // clearly uncommitted; a cleanup failure is surfaced as a
            // reconcile case and leaves evidence for the next operation.
            if matches!(error, AtomicStoreError::ReconcileRequired { .. }) {
                return self.reconcile_uncertain(
                    error.into_reconcile_source(),
                    &staged,
                    target_digest,
                    UncertainPhase::JournalPublication,
                );
            }
            return Err(self.handle_prejournal_failure(error, &staged));
        }

        match replace_same_dir(&self.root, &staged, &self.target) {
            Ok(()) => match self.finalize_journal(&staged) {
                Ok(()) => Ok(CommitReceipt {
                    digest: target_digest,
                }),
                Err(error) => self.reconcile_uncertain(
                    error.into_reconcile_source(),
                    &staged,
                    target_digest,
                    UncertainPhase::TargetMutation,
                ),
            },
            Err(error @ MutationFailure::NotApplied { .. }) => {
                let source = error.into_source_error();
                Err(self.rollback_after_not_applied(source, &staged))
            }
            Err(error @ MutationFailure::ReconcileRequired { .. }) => self.reconcile_uncertain(
                error.into_source_error(),
                &staged,
                target_digest,
                UncertainPhase::TargetMutation,
            ),
        }
    }

    fn acquire_lock(&self) -> std::result::Result<File, AtomicStoreError> {
        let file =
            open_or_create_secure_file(&self.root, &self.lock).map_err(AtomicStoreError::io)?;
        let metadata = file.metadata().map_err(|error| {
            AtomicStoreError::io(anyhow!(error).context("failed to inspect lock file"))
        })?;
        if !metadata.is_file() {
            return Err(AtomicStoreError::io(anyhow!(
                "lock file is not a regular file"
            )));
        }
        lock_exclusive_with_wait_notice(&file).map_err(|error| {
            AtomicStoreError::io(anyhow!(error).context("failed to acquire exclusive store lock"))
        })?;
        Ok(file)
    }

    fn read_journal(&self) -> std::result::Result<Option<PreparedJournal>, AtomicStoreError> {
        let metadata = inspect_owned_relative_file(&self.root, &self.journal, true)
            .map_err(AtomicStoreError::io)?;
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        if metadata.len() > MAX_JOURNAL_BYTES as u64 {
            return Err(AtomicStoreError::invalid_journal(anyhow!(
                "journal exceeds {MAX_JOURNAL_BYTES} bytes"
            )));
        }
        let bytes = read_owned_relative_file_bounded(&self.root, &self.journal, MAX_JOURNAL_BYTES)
            .map_err(AtomicStoreError::io)?
            .ok_or_else(|| AtomicStoreError::io(anyhow!("journal disappeared during read")))?;
        let record = parse_journal_record(&bytes)?;
        self.validate_journal(record)
    }

    fn validate_journal(
        &self,
        record: JournalRecord,
    ) -> std::result::Result<Option<PreparedJournal>, AtomicStoreError> {
        if record.journal_version != JOURNAL_VERSION {
            return Err(AtomicStoreError::invalid_journal(anyhow!(
                "unsupported journal version {}",
                record.journal_version
            )));
        }
        if !matches!(record.phase, JournalPhase::Prepared) {
            return Err(AtomicStoreError::invalid_journal(anyhow!(
                "unsupported journal phase"
            )));
        }
        let txid = Uuid::parse_str(&record.txid).map_err(|error| {
            AtomicStoreError::invalid_journal(anyhow!(error).context("invalid journal txid"))
        })?;
        if record.txid != txid.to_string() {
            return Err(AtomicStoreError::invalid_journal(anyhow!(
                "journal txid must use canonical UUID spelling"
            )));
        }

        let target = SafeRelativePath::new(Path::new(&record.target))
            .map_err(AtomicStoreError::invalid_journal)?;
        if target != self.target {
            return Err(AtomicStoreError::invalid_journal(anyhow!(
                "journal target does not match configured target"
            )));
        }
        let staged = SafeRelativePath::new(Path::new(&record.staged))
            .map_err(AtomicStoreError::invalid_journal)?;
        if !same_parent(&staged, &self.target) || staged != self.staged_locator(txid)? {
            return Err(AtomicStoreError::invalid_journal(anyhow!(
                "journal staged locator is not the txid-derived sibling"
            )));
        }
        inspect_owned_relative_file(&self.root, &staged, true)
            .map_err(AtomicStoreError::invalid_journal)?;

        let base_digest = record
            .base_digest
            .as_deref()
            .map(DocumentDigest::from_hex)
            .transpose()
            .map_err(AtomicStoreError::invalid_journal)?;
        let target_digest = DocumentDigest::from_hex(&record.target_digest)
            .map_err(AtomicStoreError::invalid_journal)?;
        Ok(Some(PreparedJournal {
            base_digest,
            target_digest,
            staged,
        }))
    }

    fn recover_locked(&self) -> std::result::Result<RecoveryOutcome, AtomicStoreError> {
        let Some(journal) = self.read_journal()? else {
            return Ok(RecoveryOutcome::None);
        };
        let live = self.read_snapshot().map_err(AtomicStoreError::io)?.digest;
        if live == Some(journal.target_digest) {
            sync_file(&self.root, &self.target).map_err(AtomicStoreError::reconcile)?;
            sync_parent_dir(&self.root, &self.target).map_err(AtomicStoreError::reconcile)?;
            self.cleanup_journal(&journal.staged).map_err(|error| {
                AtomicStoreError::reconcile(anyhow!(
                    "target is live but journal finalization failed: {error}"
                ))
            })?;
            return Ok(RecoveryOutcome::Finalized);
        }
        if live == journal.base_digest {
            self.cleanup_journal(&journal.staged).map_err(|error| {
                AtomicStoreError::reconcile(anyhow!(
                    "rollback cleanup failed while resolving journal: {error}"
                ))
            })?;
            return Ok(RecoveryOutcome::RolledBack);
        }
        Err(AtomicStoreError::RecoveryConflict {
            live,
            base: journal.base_digest,
            target: journal.target_digest,
        })
    }

    fn write_staged(
        &self,
        staged: &SafeRelativePath,
        bytes: &[u8],
    ) -> std::result::Result<(), AtomicStoreError> {
        let mut file =
            create_new_secure_file(&self.root, staged).map_err(AtomicStoreError::not_applied)?;
        if let Err(error) = file.write_all(bytes) {
            drop(file);
            let _ = remove_file(&self.root, staged);
            return Err(AtomicStoreError::not_applied(
                anyhow!(error).context("failed to write staged document"),
            ));
        }
        if let Err(error) = file.sync_all() {
            drop(file);
            let _ = remove_file(&self.root, staged);
            return Err(AtomicStoreError::not_applied(
                anyhow!(error).context("failed to sync staged document"),
            ));
        }
        Ok(())
    }

    fn publish_journal(
        &self,
        journal: &JournalRecord,
        txid: Uuid,
    ) -> std::result::Result<(), AtomicStoreError> {
        let journal_staged = self.journal_staged_locator(txid)?;
        let encoded = serde_json::to_vec(journal)
            .map_err(|error| AtomicStoreError::not_applied(anyhow!(error)))?;
        let mut file = create_new_secure_file(&self.root, &journal_staged)
            .map_err(AtomicStoreError::not_applied)?;
        if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
            drop(file);
            let _ = remove_file(&self.root, &journal_staged);
            return Err(AtomicStoreError::not_applied(
                anyhow!(error).context("failed to write or sync prepared journal"),
            ));
        }
        match replace_same_dir(&self.root, &journal_staged, &self.journal) {
            Ok(()) => Ok(()),
            Err(error) => {
                let mapped = AtomicStoreError::from_mutation(error);
                if matches!(mapped, AtomicStoreError::NotApplied { .. }) {
                    let _ = remove_file(&self.root, &journal_staged);
                }
                Err(mapped)
            }
        }
    }

    fn finalize_journal(
        &self,
        document_staged: &SafeRelativePath,
    ) -> std::result::Result<(), AtomicStoreError> {
        self.remove_if_present(document_staged)?;
        self.remove_if_present(&self.journal)
    }

    fn cleanup_journal(
        &self,
        document_staged: &SafeRelativePath,
    ) -> std::result::Result<(), AtomicStoreError> {
        self.remove_if_present(document_staged)?;
        self.remove_if_present(&self.journal)
    }

    fn remove_if_present(
        &self,
        relative: &SafeRelativePath,
    ) -> std::result::Result<(), AtomicStoreError> {
        match remove_file(&self.root, relative) {
            Ok(_) => Ok(()),
            Err(error) => Err(AtomicStoreError::from_mutation(error)),
        }
    }

    fn handle_prejournal_failure(
        &self,
        error: AtomicStoreError,
        document_staged: &SafeRelativePath,
    ) -> AtomicStoreError {
        match self.remove_if_present(document_staged) {
            Ok(()) => match error {
                AtomicStoreError::NotApplied { source } => AtomicStoreError::NotApplied { source },
                other => other,
            },
            Err(cleanup) => AtomicStoreError::reconcile(anyhow!(
                "prepared document cleanup failed after journal publication failure: {cleanup}"
            )),
        }
    }

    fn rollback_after_not_applied(
        &self,
        source: anyhow::Error,
        document_staged: &SafeRelativePath,
    ) -> AtomicStoreError {
        match self.cleanup_journal(document_staged) {
            Ok(()) => AtomicStoreError::not_applied(source),
            Err(cleanup) => AtomicStoreError::reconcile(anyhow!(
                "rollback cleanup failed after an unapplied replacement: {cleanup}"
            )),
        }
    }

    fn reconcile_uncertain(
        &self,
        source: anyhow::Error,
        document_staged: &SafeRelativePath,
        target_digest: DocumentDigest,
        phase: UncertainPhase,
    ) -> std::result::Result<CommitReceipt, AtomicStoreError> {
        // A journal, when present, is authoritative after a native operation
        // reports an indeterminate outcome.  If publication itself failed
        // before the journal became visible, clean only the unreferenced
        // document stage and retain the indeterminate error.
        match self.recover_locked() {
            Ok(RecoveryOutcome::Finalized) => Ok(CommitReceipt {
                digest: target_digest,
            }),
            Ok(RecoveryOutcome::RolledBack) => Err(AtomicStoreError::not_applied(anyhow!(
                "target replacement was not committed after reconciliation"
            ))),
            Ok(RecoveryOutcome::None) => {
                self.resolve_without_journal(source, document_staged, target_digest, phase)
            }
            Err(AtomicStoreError::RecoveryConflict { live, base, target }) => {
                Err(AtomicStoreError::RecoveryConflict { live, base, target })
            }
            Err(AtomicStoreError::ReconcileRequired { source: recovery }) => {
                // A cleanup may have removed the journal immediately before a
                // parent sync failed.  Retry the live-target durability path;
                // if the journal is still present, the second recovery pass
                // also retries its final cleanup.
                let live = self.read_snapshot().map_err(AtomicStoreError::io)?.digest;
                if live == Some(target_digest)
                    && sync_file(&self.root, &self.target).is_ok()
                    && sync_parent_dir(&self.root, &self.target).is_ok()
                {
                    match self.recover_locked() {
                        Ok(RecoveryOutcome::Finalized) => Ok(CommitReceipt {
                            digest: target_digest,
                        }),
                        Ok(RecoveryOutcome::None) => {
                            self.remove_if_present(document_staged).map_err(|cleanup| {
                                AtomicStoreError::reconcile(anyhow!(
                                    "target is live but staged cleanup failed: {cleanup}"
                                ))
                            })?;
                            Ok(CommitReceipt {
                                digest: target_digest,
                            })
                        }
                        Ok(RecoveryOutcome::RolledBack) => Err(AtomicStoreError::not_applied(
                            anyhow!("target replacement was not committed after reconciliation"),
                        )),
                        Err(error) => Err(error),
                    }
                } else {
                    Err(AtomicStoreError::reconcile(anyhow!(
                        "reconciliation retry failed: {recovery}; original error: {source}"
                    )))
                }
            }
            Err(error) => Err(error),
        }
    }

    fn resolve_without_journal(
        &self,
        source: anyhow::Error,
        document_staged: &SafeRelativePath,
        target_digest: DocumentDigest,
        phase: UncertainPhase,
    ) -> std::result::Result<CommitReceipt, AtomicStoreError> {
        let live = self.read_snapshot().map_err(AtomicStoreError::io)?.digest;
        if live == Some(target_digest) {
            if let Err(error) = sync_file(&self.root, &self.target)
                .and_then(|_| sync_parent_dir(&self.root, &self.target))
            {
                return Err(AtomicStoreError::reconcile(anyhow!(
                    "live target is present but durability retry failed: {error}; original error: {source}"
                )));
            }
            self.remove_if_present(document_staged).map_err(|cleanup| {
                AtomicStoreError::reconcile(anyhow!(
                    "live target is durable but staged cleanup failed: {cleanup}"
                ))
            })?;
            return Ok(CommitReceipt {
                digest: target_digest,
            });
        }
        if phase == UncertainPhase::TargetMutation {
            return Err(AtomicStoreError::reconcile(source));
        }
        match self.remove_if_present(document_staged) {
            Ok(()) => Err(AtomicStoreError::reconcile(source)),
            Err(cleanup) => Err(AtomicStoreError::reconcile(anyhow!(
                "uncertain journal publication cleanup failed: {cleanup}"
            ))),
        }
    }

    fn staged_locator(&self, txid: Uuid) -> Result<SafeRelativePath> {
        sibling_locator(&self.target, &format!(".sagy-{txid}.staged"))
    }

    fn journal_staged_locator(&self, txid: Uuid) -> Result<SafeRelativePath> {
        sibling_locator(&self.target, &format!(".sagy-{txid}.journal.staged"))
    }
}

fn sibling_locator(target: &SafeRelativePath, name: &str) -> Result<SafeRelativePath> {
    target.sibling(name)
}

fn same_parent(left: &SafeRelativePath, right: &SafeRelativePath) -> bool {
    let left_parent = left.as_path().parent().unwrap_or_else(|| Path::new(""));
    let right_parent = right.as_path().parent().unwrap_or_else(|| Path::new(""));
    left_parent == right_parent
}

fn locator_string(locator: &SafeRelativePath) -> Result<String> {
    locator.to_slash_string()
}

fn derive_store_locators(
    target: &SafeRelativePath,
) -> Result<(SafeRelativePath, SafeRelativePath)> {
    let name_digest = DocumentDigest::from_bytes(locator_string(target)?.as_bytes()).to_hex();
    let lock = sibling_locator(target, &format!(".sagy-{name_digest}.lock"))?;
    let journal = sibling_locator(target, &format!(".sagy-{name_digest}.journal"))?;
    Ok((lock, journal))
}

fn adoption_root_identity(
    root: &NormalizedStoreRoot,
) -> std::result::Result<RootIdentity, AtomicStoreError> {
    normalized_root_identity(root).map_err(AtomicStoreError::io)
}

fn preview_journal(
    root: &NormalizedStoreRoot,
    target: &SafeRelativePath,
    journal: &SafeRelativePath,
) -> std::result::Result<JournalPreview, AtomicStoreError> {
    let metadata =
        inspect_normalized_relative_file(root, journal, true).map_err(AtomicStoreError::io)?;
    let Some(metadata) = metadata else {
        return Ok(JournalPreview::Absent);
    };
    if metadata.len() > MAX_JOURNAL_BYTES as u64 {
        return Err(AtomicStoreError::invalid_journal(anyhow!(
            "journal exceeds {MAX_JOURNAL_BYTES} bytes"
        )));
    }
    let bytes = read_normalized_relative_file_bounded(root, journal, MAX_JOURNAL_BYTES)
        .map_err(AtomicStoreError::io)?
        .ok_or_else(|| AtomicStoreError::io(anyhow!("journal disappeared during preflight")))?;
    let record = parse_journal_record(&bytes)?;
    let prepared = validate_journal_record_normalized(root, target, record)?;
    Ok(JournalPreview::Prepared(prepared))
}

/// Parse one journal through the strict duplicate/unknown-field decoder and
/// reject trailing JSON values. Both mutation recovery and pure inspection
/// use this parser so they cannot disagree about the journal grammar.
fn parse_journal_record(bytes: &[u8]) -> std::result::Result<JournalRecord, AtomicStoreError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let record = JournalRecord::deserialize(&mut deserializer)
        .map_err(|error| AtomicStoreError::invalid_journal(anyhow!(error)))?;
    deserializer
        .end()
        .map_err(|error| AtomicStoreError::invalid_journal(anyhow!(error)))?;
    Ok(record)
}

/// Inspect the target and prepared journal without identity checks or any
/// mutation-side operation. A prepared journal must still reference a
/// present stage whose exact bytes match its target digest; otherwise the
/// journal is invalid and all evidence remains on disk for later recovery.
pub(crate) fn inspect_recovery_from_normalized(
    root: &NormalizedStoreRoot,
    target: &SafeRelativePath,
) -> std::result::Result<RecoveryInspection, AtomicStoreError> {
    let journal = derive_store_locators(target)
        .map(|(_, journal)| journal)
        .map_err(AtomicStoreError::io)?;
    let bytes = read_normalized_relative_file_bounded(root, target, MAX_ADOPTION_TARGET_BYTES)
        .map_err(AtomicStoreError::io)?;
    let snapshot = DocumentSnapshot {
        digest: bytes.as_deref().map(DocumentDigest::from_bytes),
        bytes,
    };
    let journal_preview = preview_journal(root, target, &journal)?;
    let recovery = recovery_preview(snapshot.digest, &journal_preview);
    if let RecoveryPreview::Conflict { live, base, target } = &recovery {
        return Err(AtomicStoreError::RecoveryConflict {
            live: *live,
            base: *base,
            target: *target,
        });
    }
    let staged_bytes = match &journal_preview {
        JournalPreview::Absent => None,
        JournalPreview::Prepared(prepared) => {
            let staged = read_normalized_relative_file_bounded(
                root,
                &prepared.staged,
                MAX_ADOPTION_TARGET_BYTES,
            )
            .map_err(AtomicStoreError::io)?
            .ok_or_else(|| {
                AtomicStoreError::invalid_journal(anyhow!("referenced staged document is missing"))
            })?;
            let digest = DocumentDigest::from_bytes(&staged);
            if digest != prepared.target_digest {
                return Err(AtomicStoreError::invalid_journal(anyhow!(
                    "staged document digest does not match journal target"
                )));
            }
            Some(staged)
        }
    };
    Ok(RecoveryInspection {
        snapshot,
        journal: journal_preview,
        recovery,
        staged_bytes,
    })
}

fn validate_journal_record_normalized(
    root: &NormalizedStoreRoot,
    target: &SafeRelativePath,
    record: JournalRecord,
) -> std::result::Result<PreparedJournalPreview, AtomicStoreError> {
    if record.journal_version != JOURNAL_VERSION {
        return Err(AtomicStoreError::invalid_journal(anyhow!(
            "unsupported journal version {}",
            record.journal_version
        )));
    }
    if !matches!(record.phase, JournalPhase::Prepared) {
        return Err(AtomicStoreError::invalid_journal(anyhow!(
            "unsupported journal phase"
        )));
    }
    let txid = Uuid::parse_str(&record.txid).map_err(|error| {
        AtomicStoreError::invalid_journal(anyhow!(error).context("invalid journal txid"))
    })?;
    if record.txid != txid.to_string() {
        return Err(AtomicStoreError::invalid_journal(anyhow!(
            "journal txid must use canonical UUID spelling"
        )));
    }
    let journal_target = SafeRelativePath::new(Path::new(&record.target))
        .map_err(AtomicStoreError::invalid_journal)?;
    if journal_target != *target {
        return Err(AtomicStoreError::invalid_journal(anyhow!(
            "journal target does not match configured target"
        )));
    }
    let staged = SafeRelativePath::new(Path::new(&record.staged))
        .map_err(AtomicStoreError::invalid_journal)?;
    if !same_parent(&staged, target)
        || staged
            != sibling_locator(target, &format!(".sagy-{txid}.staged"))
                .map_err(AtomicStoreError::invalid_journal)?
    {
        return Err(AtomicStoreError::invalid_journal(anyhow!(
            "journal staged locator is not the txid-derived sibling"
        )));
    }
    let staged_present = inspect_normalized_relative_file(root, &staged, true)
        .map_err(AtomicStoreError::invalid_journal)?
        .is_some();
    let base_digest = record
        .base_digest
        .as_deref()
        .map(DocumentDigest::from_hex)
        .transpose()
        .map_err(AtomicStoreError::invalid_journal)?;
    let target_digest = DocumentDigest::from_hex(&record.target_digest)
        .map_err(AtomicStoreError::invalid_journal)?;
    Ok(PreparedJournalPreview {
        txid,
        base_digest,
        target_digest,
        target: journal_target,
        staged,
        staged_present,
    })
}

fn recovery_preview(live: Option<DocumentDigest>, journal: &JournalPreview) -> RecoveryPreview {
    let JournalPreview::Prepared(prepared) = journal else {
        return RecoveryPreview::Clean;
    };
    if live == Some(prepared.target_digest) {
        RecoveryPreview::Finalize {
            target_digest: prepared.target_digest,
        }
    } else if live == prepared.base_digest {
        RecoveryPreview::Rollback {
            base_digest: prepared.base_digest,
        }
    } else {
        RecoveryPreview::Conflict {
            live,
            base: prepared.base_digest,
            target: prepared.target_digest,
        }
    }
}

fn classify_inventory(
    raw_inventory: Vec<TopLevelInventoryEntry>,
    lock: &SafeRelativePath,
    journal: &SafeRelativePath,
    journal_preview: &JournalPreview,
) -> (Vec<AdoptionInventoryEntry>, Vec<SafeRelativePath>) {
    let referenced_staged = match journal_preview {
        JournalPreview::Prepared(prepared) => Some(&prepared.staged),
        JournalPreview::Absent => None,
    };
    let mut inventory = Vec::with_capacity(raw_inventory.len());
    let mut orphan_stages = Vec::new();
    for entry in raw_inventory {
        let artifact = classify_artifact(&entry.locator, lock, journal);
        if matches!(
            artifact,
            AdoptionArtifact::DocumentStage(_) | AdoptionArtifact::JournalStage(_)
        ) && entry.kind == TopLevelEntryKind::RegularFile
            && referenced_staged != Some(&entry.locator)
        {
            orphan_stages.push(entry.locator.clone());
        }
        inventory.push(AdoptionInventoryEntry {
            locator: entry.locator,
            kind: entry.kind,
            size: entry.size,
            artifact,
        });
    }
    (inventory, orphan_stages)
}

fn classify_artifact(
    locator: &SafeRelativePath,
    lock: &SafeRelativePath,
    journal: &SafeRelativePath,
) -> AdoptionArtifact {
    if locator == lock {
        return AdoptionArtifact::FixedLock;
    }
    if locator == journal {
        return AdoptionArtifact::FixedJournal;
    }
    if locator
        .as_path()
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
    {
        return AdoptionArtifact::Ordinary;
    }
    let Some(name) = locator.as_path().file_name().and_then(|name| name.to_str()) else {
        return AdoptionArtifact::Ordinary;
    };
    if let Some(raw) = name
        .strip_prefix(".sagy-")
        .and_then(|raw| raw.strip_suffix(".staged"))
        && let Ok(txid) = Uuid::parse_str(raw)
        && txid.to_string() == raw
    {
        return AdoptionArtifact::DocumentStage(txid);
    }
    if let Some(raw) = name
        .strip_prefix(".sagy-")
        .and_then(|raw| raw.strip_suffix(".journal.staged"))
        && let Ok(txid) = Uuid::parse_str(raw)
        && txid.to_string() == raw
    {
        return AdoptionArtifact::JournalStage(txid);
    }
    AdoptionArtifact::Ordinary
}

fn preflight_equivalent_ignoring_lock(
    expected: &AdoptionPreflight,
    current: &AdoptionPreflight,
) -> bool {
    expected.root_identity == current.root_identity
        && expected.target == current.target
        && expected.lock == current.lock
        && expected.journal == current.journal
        && expected.snapshot.digest == current.snapshot.digest
        && expected.journal_preview == current.journal_preview
        && inventory_without_lock(&expected.inventory, &expected.lock)
            == inventory_without_lock(&current.inventory, &current.lock)
}

fn inventory_without_lock<'a>(
    inventory: &'a [AdoptionInventoryEntry],
    lock: &SafeRelativePath,
) -> Vec<&'a AdoptionInventoryEntry> {
    inventory
        .iter()
        .filter(|entry| entry.locator != *lock)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn store() -> (tempfile::TempDir, AtomicStore) {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("owned");
        let root = OwnedStoreRoot::claim(
            super::super::atomic_io::NormalizedStoreRoot::normalize(&root_path).unwrap(),
        )
        .unwrap();
        let target = SafeRelativePath::new(Path::new("document.bin")).unwrap();
        (temp, AtomicStore::new(root, target).unwrap())
    }

    fn populated_root() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        NormalizedStoreRoot,
        SafeRelativePath,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("populated");
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("state.json"), br#"{"accounts":[]}"#).unwrap();
        fs::create_dir(root_path.join("accounts")).unwrap();
        let normalized = NormalizedStoreRoot::normalize(&root_path).unwrap();
        let target = SafeRelativePath::new(Path::new("state.json")).unwrap();
        (temp, root_path, normalized, target)
    }

    fn write_journal_file(store: &AtomicStore, bytes: &[u8]) {
        let path = store.root.as_path().join(store.journal.as_path());
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            let path = store.root.as_path().join(store.journal.as_path());
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn journal_json(
        store: &AtomicStore,
        txid: Uuid,
        base: Option<DocumentDigest>,
        target: DocumentDigest,
        staged: &SafeRelativePath,
    ) -> Vec<u8> {
        serde_json::json!({
            "journal_version": 1,
            "txid": txid.to_string(),
            "phase": "prepared",
            "base_digest": base.map(DocumentDigest::to_hex),
            "target_digest": target.to_hex(),
            "target": store.target.as_path().to_str().unwrap(),
            "staged": staged.as_path().to_str().unwrap(),
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn first_and_repeated_commit_and_side_effect_free_read() {
        let (_temp, store) = store();
        let absent = store.read_snapshot().unwrap();
        assert_eq!(absent.bytes, None);
        assert_eq!(absent.digest, None);

        let first = store.commit(ExpectedDigest::Exact(None), b"one").unwrap();
        assert_eq!(first.digest, DocumentDigest::from_bytes(b"one"));
        let second = store
            .commit(ExpectedDigest::Exact(Some(first.digest)), b"two")
            .unwrap();
        assert_eq!(second.digest, DocumentDigest::from_bytes(b"two"));
        assert!(
            store
                .commit(ExpectedDigest::Exact(Some(first.digest)), b"three")
                .is_err()
        );
    }

    #[test]
    fn normalized_root_reader_stays_side_effect_free() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let normalized = NormalizedStoreRoot::normalize(&missing).unwrap();
        let target = SafeRelativePath::new(Path::new("document.bin")).unwrap();
        let snapshot = read_snapshot_from_normalized(&normalized, &target).unwrap();
        assert_eq!(snapshot.bytes, None);
        assert_eq!(snapshot.digest, None);
        assert!(!missing.exists());
    }

    #[test]
    fn exact_conflict_is_typed_and_does_not_write() {
        let (_temp, store) = store();
        let receipt = store.commit(ExpectedDigest::Any, b"live").unwrap();
        let error = store
            .commit(ExpectedDigest::Exact(None), b"new")
            .unwrap_err();
        assert!(matches!(
            error,
            AtomicStoreError::Conflict {
                expected: ExpectedDigest::Exact(None),
                actual: Some(actual),
            } if actual == receipt.digest
        ));
        assert_eq!(
            store.read_snapshot().unwrap().bytes.as_deref(),
            Some(&b"live"[..])
        );
    }

    #[test]
    fn lock_exact_retains_one_lock_for_multiple_commits() {
        let (_temp, store) = store();
        let guard = store.lock_exact(None).unwrap();
        let first = guard.commit_exact(None, b"one").unwrap();
        let second = guard.commit_exact(Some(first.digest), b"two").unwrap();
        assert_eq!(second.digest, DocumentDigest::from_bytes(b"two"));
        drop(guard);
        assert!(matches!(
            store.lock_exact(Some(first.digest)),
            Err(AtomicStoreError::Conflict {
                expected: ExpectedDigest::Exact(Some(expected)),
                actual: Some(actual),
            }) if expected == first.digest && actual == second.digest
        ));
    }

    #[test]
    fn two_independent_handles_compete_under_one_lock() {
        let (temp, first) = store();
        let root = first.root.clone();
        let second = AtomicStore::new(root, first.target.clone()).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let left_barrier = Arc::clone(&barrier);
        let right_barrier = Arc::clone(&barrier);
        let left = thread::spawn(move || {
            left_barrier.wait();
            first.commit(ExpectedDigest::Exact(None), b"left")
        });
        let right = thread::spawn(move || {
            right_barrier.wait();
            second.commit(ExpectedDigest::Exact(None), b"right")
        });
        let left = left.join().unwrap();
        let right = right.join().unwrap();
        assert_eq!(left.is_ok() as u8 + right.is_ok() as u8, 1);
        assert!(matches!(
            (left, right),
            (Err(AtomicStoreError::Conflict { .. }), Ok(_))
                | (Ok(_), Err(AtomicStoreError::Conflict { .. }))
        ));
        let live = fs::read(temp.path().join("owned/document.bin")).unwrap();
        assert!(live == b"left" || live == b"right");
    }

    #[test]
    fn prepared_journal_live_target_finalizes() {
        let (_temp, store) = store();
        let base = b"base";
        store.commit(ExpectedDigest::Any, base).unwrap();
        let txid = Uuid::new_v4();
        let staged = store.staged_locator(txid).unwrap();
        let target = DocumentDigest::from_bytes(b"target");
        fs::write(store.root.as_path().join(staged.as_path()), b"target").unwrap();
        fs::write(store.root.as_path().join(store.target.as_path()), b"target").unwrap();
        write_journal_file(
            &store,
            &journal_json(
                &store,
                txid,
                Some(DocumentDigest::from_bytes(base)),
                target,
                &staged,
            ),
        );
        assert_eq!(store.recover().unwrap(), RecoveryOutcome::Finalized);
        assert!(!store.root.as_path().join(store.journal.as_path()).exists());
        assert!(!store.root.as_path().join(staged.as_path()).exists());
    }

    #[test]
    fn prepared_journal_first_commit_accepts_null_base_digest() {
        let (_temp, store) = store();
        let txid = Uuid::new_v4();
        let staged = store.staged_locator(txid).unwrap();
        let target = DocumentDigest::from_bytes(b"first");
        fs::write(store.root.as_path().join(staged.as_path()), b"first").unwrap();
        fs::write(store.root.as_path().join(store.target.as_path()), b"first").unwrap();
        write_journal_file(&store, &journal_json(&store, txid, None, target, &staged));
        assert_eq!(store.recover().unwrap(), RecoveryOutcome::Finalized);
    }

    #[test]
    fn prepared_journal_live_base_rolls_back() {
        let (_temp, store) = store();
        let base_digest = DocumentDigest::from_bytes(b"base");
        store.commit(ExpectedDigest::Any, b"base").unwrap();
        let txid = Uuid::new_v4();
        let staged = store.staged_locator(txid).unwrap();
        fs::write(store.root.as_path().join(staged.as_path()), b"target").unwrap();
        write_journal_file(
            &store,
            &journal_json(
                &store,
                txid,
                Some(base_digest),
                DocumentDigest::from_bytes(b"target"),
                &staged,
            ),
        );
        assert_eq!(store.recover().unwrap(), RecoveryOutcome::RolledBack);
        assert_eq!(
            store.read_snapshot().unwrap().bytes.as_deref(),
            Some(&b"base"[..])
        );
        assert!(!store.root.as_path().join(store.journal.as_path()).exists());
    }

    #[test]
    fn prepared_journal_neither_keeps_evidence_and_is_typed() {
        let (_temp, store) = store();
        store.commit(ExpectedDigest::Any, b"live").unwrap();
        let txid = Uuid::new_v4();
        let staged = store.staged_locator(txid).unwrap();
        fs::write(store.root.as_path().join(staged.as_path()), b"target").unwrap();
        write_journal_file(
            &store,
            &journal_json(
                &store,
                txid,
                Some(DocumentDigest::from_bytes(b"base")),
                DocumentDigest::from_bytes(b"target"),
                &staged,
            ),
        );
        let error = store.recover().unwrap_err();
        assert!(matches!(error, AtomicStoreError::RecoveryConflict { .. }));
        assert!(store.root.as_path().join(store.journal.as_path()).exists());
    }

    #[test]
    fn journal_rejects_unknown_future_oversize_and_secret_fields() {
        let (_temp, store) = store();
        let txid = Uuid::new_v4();
        let staged = store.staged_locator(txid).unwrap();
        let valid = journal_json(
            &store,
            txid,
            None,
            DocumentDigest::from_bytes(b"target"),
            &staged,
        );
        for invalid in [
            serde_json::from_slice::<serde_json::Value>(&valid)
                .unwrap()
                .as_object()
                .map(|object| {
                    let mut value = serde_json::Value::Object(object.clone());
                    value["journal_version"] = serde_json::json!(2);
                    value.to_string().into_bytes()
                })
                .unwrap(),
            {
                let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
                value["payload"] = serde_json::json!("secret");
                value.to_string().into_bytes()
            },
            {
                let text = String::from_utf8(valid.clone()).unwrap();
                format!("{},\"phase\":\"prepared\"}}", text.trim_end_matches('}')).into_bytes()
            },
            vec![b'x'; MAX_JOURNAL_BYTES + 1],
        ] {
            write_journal_file(&store, &invalid);
            assert!(matches!(
                store.recover(),
                Err(AtomicStoreError::InvalidJournal { .. })
            ));
            fs::remove_file(store.root.as_path().join(store.journal.as_path())).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_and_lock_are_private_and_symlink_is_rejected() {
        let (_temp, store) = store();
        let lock = store.root.as_path().join(store.lock_locator().as_path());
        let journal = store.root.as_path().join(store.journal_locator().as_path());
        drop(store.acquire_lock().unwrap());
        let lock_mode = fs::metadata(&lock).unwrap().permissions().mode() & 0o777;
        assert_eq!(lock_mode, 0o600);

        let victim = store.root.as_path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        fs::remove_file(&lock).unwrap();
        symlink(&victim, &lock).unwrap();
        assert!(store.commit(ExpectedDigest::Any, b"new").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");

        fs::remove_file(&lock).unwrap();
        fs::write(&journal, b"{}").unwrap();
        fs::remove_file(&journal).unwrap();
        symlink(&victim, &journal).unwrap();
        assert!(matches!(store.recover(), Err(AtomicStoreError::Io { .. })));
    }

    #[test]
    fn uncertain_no_journal_live_target_is_rechecked_and_finalized() {
        let (_temp, store) = store();
        let staged = SafeRelativePath::new(Path::new("orphan.staged")).unwrap();
        let target_digest = DocumentDigest::from_bytes(b"target");
        fs::write(store.root.as_path().join(staged.as_path()), b"target").unwrap();
        fs::write(store.root.as_path().join(store.target.as_path()), b"target").unwrap();

        let receipt = store
            .resolve_without_journal(
                anyhow!("simulated cleanup fsync failure"),
                &staged,
                target_digest,
                UncertainPhase::TargetMutation,
            )
            .unwrap();
        assert_eq!(receipt.digest, target_digest);
        assert!(!store.root.as_path().join(staged.as_path()).exists());
    }

    #[test]
    fn uncertain_target_mutation_keeps_unreferenced_stage_as_evidence() {
        let (_temp, store) = store();
        let staged = SafeRelativePath::new(Path::new("target-uncertain.staged")).unwrap();
        let target_digest = DocumentDigest::from_bytes(b"target");
        fs::write(store.root.as_path().join(staged.as_path()), b"target").unwrap();
        fs::write(store.root.as_path().join(store.target.as_path()), b"base").unwrap();

        let error = store
            .reconcile_uncertain(
                anyhow!("simulated target replacement uncertainty"),
                &staged,
                target_digest,
                UncertainPhase::TargetMutation,
            )
            .unwrap_err();
        assert!(matches!(error, AtomicStoreError::ReconcileRequired { .. }));
        assert!(store.root.as_path().join(staged.as_path()).exists());
    }

    #[test]
    fn uncertain_journal_publication_can_clean_unreferenced_stage() {
        let (_temp, store) = store();
        let staged = SafeRelativePath::new(Path::new("journal-uncertain.staged")).unwrap();
        let target_digest = DocumentDigest::from_bytes(b"target");
        fs::write(store.root.as_path().join(staged.as_path()), b"target").unwrap();
        fs::write(store.root.as_path().join(store.target.as_path()), b"base").unwrap();

        let error = store
            .reconcile_uncertain(
                anyhow!("simulated journal publication uncertainty"),
                &staged,
                target_digest,
                UncertainPhase::JournalPublication,
            )
            .unwrap_err();
        assert!(matches!(error, AtomicStoreError::ReconcileRequired { .. }));
        assert!(!store.root.as_path().join(staged.as_path()).exists());
    }

    #[test]
    fn sparse_oversized_journal_is_rejected_from_metadata_without_reading_it() {
        let (_temp, store) = store();
        let journal = store.root.as_path().join(store.journal.as_path());
        let file = fs::File::create(journal).unwrap();
        file.set_len((MAX_JOURNAL_BYTES as u64) + (128 * 1024 * 1024))
            .unwrap();
        drop(file);

        assert!(matches!(
            store.recover(),
            Err(AtomicStoreError::InvalidJournal { .. })
        ));
    }

    #[test]
    fn legal_nonempty_adoption_reuses_one_lock_for_exact_commit() {
        let (_temp, root_path, normalized, target) = populated_root();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let expected_digest = preflight.snapshot.digest;
        let locked = unsafe {
            AtomicStore::adopt_existing_with(normalized, target, &preflight, |current| {
                assert_eq!(current.recovery_preview, RecoveryPreview::Clean);
                Ok(())
            })
        }
        .unwrap();
        let receipt = locked
            .commit_exact(expected_digest, br#"{"accounts":[1]}"#)
            .unwrap();
        assert_eq!(
            receipt.digest,
            DocumentDigest::from_bytes(br#"{"accounts":[1]}"#)
        );
        assert_eq!(
            fs::read(root_path.join("state.json")).unwrap(),
            br#"{"accounts":[1]}"#
        );
        assert!(
            root_path
                .join(preflight.journal.as_path())
                .symlink_metadata()
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_nonempty_adoption_reopens_the_same_root_after_restart() {
        let (_temp, root_path, normalized, target) = populated_root();
        let first_preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let first = unsafe {
            AtomicStore::adopt_existing_with(normalized, target.clone(), &first_preflight, |_| {
                Ok(())
            })
        }
        .unwrap();
        let first_receipt = first
            .commit_exact(first_preflight.snapshot.digest, br#"{"accounts":[1]}"#)
            .unwrap();
        drop(first);

        let normalized = NormalizedStoreRoot::normalize(&root_path).unwrap();
        let second_preflight =
            AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        assert_eq!(second_preflight.snapshot.digest, Some(first_receipt.digest));
        let second = unsafe {
            AtomicStore::adopt_existing_with(normalized, target, &second_preflight, |_| Ok(()))
        }
        .unwrap();
        let second_receipt = second
            .commit_exact(Some(first_receipt.digest), br#"{"accounts":[2]}"#)
            .unwrap();
        assert_eq!(
            second_receipt.digest,
            DocumentDigest::from_bytes(br#"{"accounts":[2]}"#)
        );
        assert_eq!(
            fs::read(root_path.join("state.json")).unwrap(),
            br#"{"accounts":[2]}"#
        );
    }

    #[test]
    fn invalid_journal_preflight_blocks_lock_creation() {
        let (_temp, root_path, normalized, target) = populated_root();
        let (lock, journal) = derive_store_locators(&target).unwrap();
        let txid = Uuid::new_v4();
        let staged = sibling_locator(&target, &format!(".sagy-{txid}.staged")).unwrap();
        let valid = serde_json::json!({
            "journal_version": JOURNAL_VERSION,
            "txid": txid.to_string(),
            "phase": "prepared",
            "base_digest": null,
            "target_digest": DocumentDigest::from_bytes(b"target").to_hex(),
            "target": target.as_path().to_str().unwrap(),
            "staged": staged.as_path().to_str().unwrap(),
        })
        .to_string()
        .into_bytes();
        let mut future: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        future["journal_version"] = serde_json::json!(JOURNAL_VERSION + 1);
        let mut unknown: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        unknown["payload"] = serde_json::json!("must-not-be-accepted");

        for invalid in [
            future.to_string().into_bytes(),
            unknown.to_string().into_bytes(),
        ] {
            fs::write(root_path.join(journal.as_path()), invalid).unwrap();
            let error = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap_err();
            assert!(matches!(error, AtomicStoreError::InvalidJournal { .. }));
            assert!(!root_path.join(lock.as_path()).exists());
            fs::remove_file(root_path.join(journal.as_path())).unwrap();
        }
    }

    #[test]
    fn upper_validator_rejection_can_skip_unsafe_adoption_without_lock() {
        let (_temp, root_path, normalized, target) = populated_root();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let (lock, _) = derive_store_locators(&target).unwrap();
        fn reject_unknown_schema(_: &AdoptionPreflight) -> Result<()> {
            Err(anyhow!("unknown state schema"))
        }
        let error = reject_unknown_schema(&preflight)
            .map_err(AtomicStoreError::validator_rejected)
            .unwrap_err();
        assert!(matches!(error, AtomicStoreError::ValidatorRejected { .. }));
        assert!(!root_path.join(lock.as_path()).exists());
    }

    #[test]
    fn low_level_adoption_has_one_explicit_production_call_site() {
        let source = include_str!("atomic_store.rs");
        let needle = ["OwnedStoreRoot::adopt_nonempty_locked", "("]
            .into_iter()
            .collect::<String>();
        assert_eq!(source.matches(&needle).count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn validator_rejection_does_not_chmod_nonempty_root() {
        let (_temp, root_path, normalized, target) = populated_root();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755)).unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let (lock, _) = derive_store_locators(&target).unwrap();
        let error = unsafe {
            AtomicStore::adopt_existing_with(normalized, target, &preflight, |_| {
                Err(anyhow!("validator rejected unknown schema"))
            })
        }
        .unwrap_err();
        assert!(matches!(error, AtomicStoreError::ValidatorRejected { .. }));
        assert!(!root_path.join(lock.as_path()).exists());
        assert_eq!(
            fs::metadata(root_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn second_validator_rejection_keeps_recovery_evidence_locked() {
        let (_temp, root_path, normalized, target) = populated_root();
        #[cfg(unix)]
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755)).unwrap();
        let txid = Uuid::new_v4();
        let stage_name = format!(".sagy-{txid}.staged");
        let stage = SafeRelativePath::new(Path::new(&stage_name)).unwrap();
        fs::write(root_path.join(&stage_name), b"orphan evidence").unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let (lock, _) = derive_store_locators(&target).unwrap();
        let calls = Cell::new(0_usize);

        let error = unsafe {
            AtomicStore::adopt_existing_with(normalized, target, &preflight, |current| {
                let call = calls.get();
                calls.set(call + 1);
                assert_eq!(current.orphan_stages, vec![stage.clone()]);
                if call == 0 {
                    Ok(())
                } else {
                    Err(anyhow!("locked semantic revalidation rejected state"))
                }
            })
        }
        .unwrap_err();

        assert_eq!(calls.get(), 2);
        assert!(matches!(error, AtomicStoreError::ValidatorRejected { .. }));
        assert!(root_path.join(&stage_name).exists());
        assert!(root_path.join(lock.as_path()).exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(root_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn preflight_inventory_and_target_changes_are_rejected_before_chmod() {
        let (_temp, root_path, normalized, target) = populated_root();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755)).unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        fs::write(root_path.join("unexpected"), b"changed").unwrap();
        fs::write(root_path.join("state.json"), br#"{"accounts":[2]}"#).unwrap();
        let error =
            unsafe { AtomicStore::adopt_existing_with(normalized, target, &preflight, |_| Ok(())) }
                .unwrap_err();
        assert!(matches!(error, AtomicStoreError::PreflightChanged { .. }));
        assert_eq!(
            fs::metadata(root_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn root_identity_change_after_preflight_is_rejected_before_chmod() {
        let (_temp, root_path, normalized, target) = populated_root();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755)).unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();

        let moved = root_path.with_extension("moved");
        fs::rename(&root_path, &moved).unwrap();
        fs::create_dir(&root_path).unwrap();
        fs::write(root_path.join("state.json"), br#"{"accounts":[]}"#).unwrap();
        fs::create_dir(root_path.join("accounts")).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755)).unwrap();

        let error =
            unsafe { AtomicStore::adopt_existing_with(normalized, target, &preflight, |_| Ok(())) }
                .unwrap_err();
        assert!(matches!(error, AtomicStoreError::PreflightChanged { .. }));
        assert_eq!(
            fs::metadata(root_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn foreign_symlink_is_classified_as_other_without_root_chmod() {
        // 语义变更（ROOT-001）：顶层的陌生 symlink 不再让整个 root 不可用。
        // 这一层只如实分类为 `Other`，由 schema 层决定"sagy 纳管的名字必须是
        // 什么类型"。本测试保留的不变量是：preflight 依然不 chmod root，
        // 也不把 symlink 当成可清理的 stage 证据。
        let (_temp, root_path, normalized, target) = populated_root();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o755)).unwrap();
        let victim = root_path.parent().unwrap().join("victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, root_path.join("link-entry")).unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target).unwrap();
        let entry = preflight
            .inventory
            .iter()
            .find(|entry| entry.locator.as_path() == Path::new("link-entry"))
            .expect("foreign symlink is inventoried");
        assert_eq!(entry.kind, TopLevelEntryKind::Other);
        assert_eq!(entry.artifact, AdoptionArtifact::Ordinary);
        assert!(preflight.orphan_stages.is_empty());
        assert_eq!(
            fs::metadata(root_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_stage_name_is_never_treated_as_removable_evidence() {
        // 陌生条目被忽略后，唯一危险是"名字长得像 sagy 自己的 stage 的 symlink"
        // 被当成孤儿 stage 删除。这条不变量必须继续成立。
        let (_temp, root_path, normalized, target) = populated_root();
        let victim = root_path.parent().unwrap().join("victim");
        fs::write(&victim, b"victim").unwrap();
        let stage_name = format!(".sagy-{}.staged", Uuid::new_v4());
        symlink(&victim, root_path.join(&stage_name)).unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target).unwrap();
        assert!(preflight.orphan_stages.is_empty());
        assert!(victim.exists());
    }

    #[test]
    fn canonical_orphan_stages_are_cleaned_only_after_validator() {
        let (_temp, root_path, normalized, target) = populated_root();
        let txid = Uuid::new_v4();
        let stage_name = format!(".sagy-{txid}.staged");
        fs::write(root_path.join(&stage_name), b"orphan").unwrap();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let stage = SafeRelativePath::new(Path::new(&stage_name)).unwrap();
        assert_eq!(preflight.orphan_stages, vec![stage.clone()]);
        let rejected = unsafe {
            AtomicStore::adopt_existing_with(normalized.clone(), target.clone(), &preflight, |_| {
                Err(anyhow!("reject before cleanup"))
            })
        };
        assert!(matches!(
            rejected,
            Err(AtomicStoreError::ValidatorRejected { .. })
        ));
        assert!(root_path.join(&stage_name).exists());

        let adopted =
            unsafe { AtomicStore::adopt_existing_with(normalized, target, &preflight, |_| Ok(())) }
                .unwrap();
        drop(adopted);
        assert!(!root_path.join(&stage_name).exists());
    }

    #[test]
    fn two_adoptions_compete_for_the_same_fixed_lock_without_reentrant_deadlock() {
        let (_temp, _root_path, normalized, target) = populated_root();
        let preflight = AtomicStore::preflight_existing(&normalized, target.clone()).unwrap();
        let first = unsafe {
            AtomicStore::adopt_existing_with(normalized.clone(), target.clone(), &preflight, |_| {
                Ok(())
            })
        }
        .unwrap();
        let second_preflight = preflight.clone();
        let thread = std::thread::spawn(move || unsafe {
            AtomicStore::adopt_existing_with(normalized, target, &second_preflight, |_| Ok(()))
        });
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(!thread.is_finished());
        drop(first);
        let second = thread.join().unwrap().unwrap();
        let digest = second.read_snapshot().unwrap().digest;
        assert!(digest.is_some());
    }
}
