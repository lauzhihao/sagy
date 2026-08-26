//! Safe, fixed-layout credential storage for one account.
//!
//! This module is deliberately independent from the legacy `AccountRecord`.
//! Reads derive their target from the account id and credential kind; the
//! legacy `auth_path` is never consulted.  Mutating methods leave a bounded
//! stage/backup pair until the caller has either published or reconciled it.

use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use fs2::FileExt;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapters::antigravity::paths::{account_dir, validate_account_id};
#[cfg(test)]
use crate::core::atomic_io::OwnedStoreRoot;
use crate::core::atomic_io::{
    NormalizedStoreRoot, SafeRelativePath, is_link_or_reparse,
    read_normalized_relative_file_bounded,
};
use crate::core::atomic_store::AccountStoreCapability;
#[cfg(test)]
use crate::core::atomic_store::AtomicStore;
use crate::core::credential::{
    CredentialError, CredentialKind, MAX_CREDENTIAL_SERIALIZED_BYTES, PortableCredential,
};
use crate::core::state::{AccountRecord, AccountType, CredentialRef, CredentialRefKind, State};
use crate::core::state_store::{
    CredentialJournalProof, CredentialMutationMode, CredentialMutationPermit,
    CurrentCredentialRefProof, RecoveryAuthority, Revision, RevisionGeneration, StateCommitReceipt,
};

const TOKEN_FILENAME: &str = "antigravity-oauth-token";
const CREDENTIALS_FILENAME: &str = "credentials.json";
const LOCK_FILENAME: &str = ".sagy-credential.lock";
const STAGE_PREFIX: &str = ".sagy-credential-";
const STAGE_SUFFIX: &str = ".stage";
const TOKEN_BACKUP_SUFFIX: &str = ".token.backup";
const DOCUMENT_BACKUP_SUFFIX: &str = ".document.backup";
const TOKEN_TOMBSTONE_SUFFIX: &str = ".token.tombstone";
const DOCUMENT_TOMBSTONE_SUFFIX: &str = ".document.tombstone";
const JOURNAL_SUFFIX: &str = ".journal";
/// Quarantine artifacts stay inside the account directory so the state-root
/// inventory keeps accepting them while nothing else in the store reads them.
const QUARANTINE_PREFIX: &str = ".sagy-credential-quarantine.";
const QUARANTINE_RECORD: &str = ".sagy-credential-quarantine.account.json";
/// 隔离目标名冲突时最多追加到 `.<N>.` 序号，越界即 fail-closed。
const QUARANTINE_MAX_SUFFIX: u32 = 16;
const JOURNAL_VERSION: u32 = 2;
const JOURNAL_MAX_BYTES: usize = 32 * 1024;

/// Raw credential files and provider-native JSON documents share the portable
/// schema's 256 KiB bound.
pub const MAX_CREDENTIAL_FILE_BYTES: usize = MAX_CREDENTIAL_SERIALIZED_BYTES;

/// One slot's expected state in a complete credential layout.
#[derive(Clone, PartialEq, Eq)]
pub enum ExpectedSlot {
    Absent,
    Exact {
        kind: CredentialRefKind,
        fingerprint: String,
        material_digest: String,
    },
}

impl fmt::Debug for ExpectedSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("Absent"),
            Self::Exact {
                kind,
                fingerprint,
                material_digest,
            } => formatter
                .debug_struct("Exact")
                .field("kind", kind)
                .field("fingerprint", fingerprint)
                .field("material_digest", material_digest)
                .finish(),
        }
    }
}

/// The expected state of both fixed credential slots.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedLayout {
    pub token: ExpectedSlot,
    pub document: ExpectedSlot,
}

impl fmt::Debug for ExpectedLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpectedLayout")
            .field("token", &self.token)
            .field("document", &self.document)
            .finish()
    }
}

/// Compatibility name for callers that only need to construct a slot
/// expectation.  Publication itself accepts [`ExpectedLayout`] only.
pub type ExpectedCredential = ExpectedSlot;

/// A bounded, parsed credential and the digest of the exact bytes on disk.
#[derive(Clone, PartialEq)]
pub struct StoredCredential {
    pub credential: PortableCredential,
    pub kind: CredentialRefKind,
    pub material_digest: String,
    pub path: PathBuf,
    bytes: Vec<u8>,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredCredential")
            .field("kind", &self.kind)
            .field("fingerprint", &self.credential.fingerprint())
            .field("material_digest", &self.material_digest)
            .field("path", &self.path)
            .finish()
    }
}

/// A credential read whose account lock remains held for the lifetime of the
/// value.  Keeping the lock beside the parsed bytes closes the gap between
/// validating a state reference and publishing the corresponding active-home
/// layout.  The lock is intentionally not exposed or clonable.
pub(crate) struct CredentialReadLease {
    stored: StoredCredential,
    _lock: File,
}

impl fmt::Debug for CredentialReadLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReadLease(<redacted>)")
    }
}

impl CredentialReadLease {
    pub(crate) fn stored(&self) -> &StoredCredential {
        &self.stored
    }
}

/// A staged credential.  The lock is retained from stage through publish or
/// restore, so an external expected value cannot become stale between those
/// operations.  Secret bytes are intentionally omitted from Debug.
pub struct StagedCredential {
    store: CredentialStore,
    lock: File,
    txid: Uuid,
    target: SafeRelativePath,
    stage: SafeRelativePath,
    kind: CredentialRefKind,
    fingerprint: String,
    material_digest: String,
    baseline: CredentialLayout,
    published: CredentialLayout,
    deleting: bool,
    base_revision: Revision,
    before_ref: Option<CredentialRef>,
    after_ref: Option<CredentialRef>,
    token_backup: Option<SafeRelativePath>,
    document_backup: Option<SafeRelativePath>,
    token_tombstone: SafeRelativePath,
    document_tombstone: SafeRelativePath,
    journal: SafeRelativePath,
}

/// A staged transaction that has not changed either live credential slot.
pub struct PreparedCredentialTxn {
    inner: StagedCredential,
}

/// A prepared transaction after its target layout has been published.  The
/// value must be consumed by either restore or receipt-gated finalize.
pub struct PublishedCredentialTxn {
    inner: StagedCredential,
}

/// Opaque evidence needed when a native operation may have changed a live
/// slot.  It intentionally carries the sealed transaction, not a caller path.
pub struct ReconcileToken {
    inner: Box<StagedCredential>,
}

impl fmt::Debug for ReconcileToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconcileToken")
            .field("txid", &self.inner.txid)
            .field("account_id", &self.inner.store.account_id)
            .finish()
    }
}

impl StagedCredential {
    /// A purge is the only transaction whose baseline, published layout and
    /// after reference are all empty: it retires a legacy account that has no
    /// credential material left to carry into v2.
    fn is_purge(&self) -> bool {
        self.deleting
            && self.baseline.token.is_none()
            && self.baseline.document.is_none()
            && self.published.token.is_none()
            && self.published.document.is_none()
    }
}

impl fmt::Debug for StagedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedCredential")
            .field("txid", &self.txid)
            .field("kind", &self.kind)
            .field("fingerprint", &self.fingerprint)
            .field("material_digest", &self.material_digest)
            .field("baseline", &self.baseline)
            .finish()
    }
}

/// Parsed metadata for both fixed slots.  The bytes are retained privately so
/// restore can prove and reconstruct the exact baseline without trusting a
/// path or a newly-read account record.
#[derive(Clone, PartialEq)]
pub struct CredentialLayout {
    pub token: Option<StoredCredential>,
    pub document: Option<StoredCredential>,
}

impl fmt::Debug for CredentialLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialLayout")
            .field("token", &self.token)
            .field("document", &self.document)
            .finish()
    }
}

impl CredentialLayout {
    pub fn expected_layout(&self) -> ExpectedLayout {
        ExpectedLayout {
            token: expected_slot(self.token.as_ref()),
            document: expected_slot(self.document.as_ref()),
        }
    }

    fn slot(&self, slot: CredentialSlot) -> Option<&StoredCredential> {
        match slot {
            CredentialSlot::Token => self.token.as_ref(),
            CredentialSlot::Document => self.document.as_ref(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialSlot {
    Token,
    Document,
}

impl CredentialSlot {
    const fn kind(self) -> CredentialRefKind {
        match self {
            Self::Token => CredentialRefKind::OauthAccessToken,
            // The document slot is shared by all provider-native documents.
            // This value is only used to derive the fixed filename.
            Self::Document => CredentialRefKind::OauthAuthorizedUser,
        }
    }

    const fn opposite(self) -> Self {
        match self {
            Self::Token => Self::Document,
            Self::Document => Self::Token,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct JournalDescriptor {
    kind: CredentialRefKind,
    fingerprint: String,
    material_digest: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct JournalLayout {
    token: Option<JournalDescriptor>,
    document: Option<JournalDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JournalRevision {
    /// `missing`, `legacy`, or `current`; the optional number is populated
    /// only for the current generation.
    generation: String,
    revision: Option<u64>,
    document_sha256: Option<String>,
}

impl JournalRevision {
    fn from_revision(revision: &Revision) -> StoreResult<Self> {
        let (generation, number) = match revision.generation {
            RevisionGeneration::Missing => ("missing".to_string(), None),
            RevisionGeneration::Legacy => ("legacy".to_string(), None),
            RevisionGeneration::Current(value) => ("current".to_string(), Some(value)),
        };
        if let Some(digest) = revision.document_sha256.as_deref() {
            validate_document_digest(digest).map_err(|_| CredentialStoreError::Corrupt {
                message: "credential journal base revision digest is invalid",
            })?;
        }
        if matches!(revision.generation, RevisionGeneration::Current(_))
            && revision.document_sha256.is_none()
        {
            return Err(CredentialStoreError::Corrupt {
                message: "current credential journal base revision has no digest",
            });
        }
        if matches!(revision.generation, RevisionGeneration::Missing)
            && revision.document_sha256.is_some()
        {
            return Err(CredentialStoreError::Corrupt {
                message: "legacy credential journal base revision has a digest",
            });
        }
        Ok(Self {
            generation,
            revision: number,
            document_sha256: revision.document_sha256.clone(),
        })
    }

    fn to_revision(&self) -> StoreResult<Revision> {
        let generation = match self.generation.as_str() {
            "missing" if self.revision.is_none() => RevisionGeneration::Missing,
            "legacy" if self.revision.is_none() => RevisionGeneration::Legacy,
            "current" => {
                RevisionGeneration::Current(self.revision.ok_or(CredentialStoreError::Corrupt {
                    message: "current credential journal base revision number is missing",
                })?)
            }
            _ => {
                return Err(CredentialStoreError::Corrupt {
                    message: "credential journal base revision generation is invalid",
                });
            }
        };
        if matches!(generation, RevisionGeneration::Missing) && self.document_sha256.is_some() {
            return Err(CredentialStoreError::Corrupt {
                message: "legacy credential journal base revision has a digest",
            });
        }
        if matches!(generation, RevisionGeneration::Current(_)) {
            let Some(digest) = self.document_sha256.as_deref() else {
                return Err(CredentialStoreError::Corrupt {
                    message: "current credential journal base revision has no digest",
                });
            };
            validate_document_digest(digest).map_err(|_| CredentialStoreError::Corrupt {
                message: "credential journal base revision digest is invalid",
            })?;
        }
        Ok(Revision {
            generation,
            document_sha256: self.document_sha256.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CredentialJournal {
    journal_version: u32,
    txid: String,
    phase: String,
    base_revision: JournalRevision,
    before_ref: Option<CredentialRef>,
    after_ref: Option<CredentialRef>,
    before: JournalLayout,
    after: JournalLayout,
    stage: String,
    stage_digest: String,
    token_backup: Option<String>,
    token_backup_digest: Option<String>,
    document_backup: Option<String>,
    document_backup_digest: Option<String>,
    token_tombstone: String,
    token_tombstone_digest: Option<String>,
    document_tombstone: String,
    document_tombstone_digest: Option<String>,
}

const DESCRIPTOR_FIELDS: &[&str] = &["kind", "fingerprint", "material_digest"];
const LAYOUT_FIELDS: &[&str] = &["token", "document"];
const JOURNAL_FIELDS: &[&str] = &[
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
];

impl<'de> Deserialize<'de> for JournalDescriptor {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DescriptorVisitor;
        impl<'de> Visitor<'de> for DescriptorVisitor {
            type Value = JournalDescriptor;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a credential journal descriptor")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut kind = None;
                let mut fingerprint = None;
                let mut material_digest = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "kind" => {
                            if kind.is_some() {
                                return Err(de::Error::duplicate_field("kind"));
                            }
                            kind = Some(map.next_value()?);
                        }
                        "fingerprint" => {
                            if fingerprint.is_some() {
                                return Err(de::Error::duplicate_field("fingerprint"));
                            }
                            fingerprint = Some(map.next_value()?);
                        }
                        "material_digest" => {
                            if material_digest.is_some() {
                                return Err(de::Error::duplicate_field("material_digest"));
                            }
                            material_digest = Some(map.next_value()?);
                        }
                        other => return Err(de::Error::unknown_field(other, DESCRIPTOR_FIELDS)),
                    }
                }
                Ok(JournalDescriptor {
                    kind: kind.ok_or_else(|| de::Error::missing_field("kind"))?,
                    fingerprint: fingerprint
                        .ok_or_else(|| de::Error::missing_field("fingerprint"))?,
                    material_digest: material_digest
                        .ok_or_else(|| de::Error::missing_field("material_digest"))?,
                })
            }
        }
        deserializer.deserialize_map(DescriptorVisitor)
    }
}

impl<'de> Deserialize<'de> for JournalLayout {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LayoutVisitor;
        impl<'de> Visitor<'de> for LayoutVisitor {
            type Value = JournalLayout;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a credential journal layout")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut token = None;
                let mut document = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "token" => {
                            if token.is_some() {
                                return Err(de::Error::duplicate_field("token"));
                            }
                            token = Some(map.next_value()?);
                        }
                        "document" => {
                            if document.is_some() {
                                return Err(de::Error::duplicate_field("document"));
                            }
                            document = Some(map.next_value()?);
                        }
                        other => return Err(de::Error::unknown_field(other, LAYOUT_FIELDS)),
                    }
                }
                Ok(JournalLayout {
                    token: token.ok_or_else(|| de::Error::missing_field("token"))?,
                    document: document.ok_or_else(|| de::Error::missing_field("document"))?,
                })
            }
        }
        deserializer.deserialize_map(LayoutVisitor)
    }
}

impl<'de> Deserialize<'de> for CredentialJournal {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct JournalVisitor;
        impl<'de> Visitor<'de> for JournalVisitor {
            type Value = CredentialJournal;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a credential transaction journal")
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut journal_version = None;
                let mut txid = None;
                let mut phase = None;
                let mut base_revision = None;
                let mut before_ref = None;
                let mut after_ref = None;
                let mut before = None;
                let mut after = None;
                let mut stage = None;
                let mut stage_digest = None;
                let mut token_backup = None;
                let mut token_backup_digest = None;
                let mut document_backup = None;
                let mut document_backup_digest = None;
                let mut token_tombstone = None;
                let mut token_tombstone_digest = None;
                let mut document_tombstone = None;
                let mut document_tombstone_digest = None;
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
                        "base_revision" => {
                            if base_revision.is_some() {
                                return Err(de::Error::duplicate_field("base_revision"));
                            }
                            base_revision = Some(map.next_value()?);
                        }
                        "before_ref" => {
                            if before_ref.is_some() {
                                return Err(de::Error::duplicate_field("before_ref"));
                            }
                            before_ref = Some(map.next_value()?);
                        }
                        "after_ref" => {
                            if after_ref.is_some() {
                                return Err(de::Error::duplicate_field("after_ref"));
                            }
                            after_ref = Some(map.next_value()?);
                        }
                        "before" => {
                            if before.is_some() {
                                return Err(de::Error::duplicate_field("before"));
                            }
                            before = Some(map.next_value()?);
                        }
                        "after" => {
                            if after.is_some() {
                                return Err(de::Error::duplicate_field("after"));
                            }
                            after = Some(map.next_value()?);
                        }
                        "stage" => {
                            if stage.is_some() {
                                return Err(de::Error::duplicate_field("stage"));
                            }
                            stage = Some(map.next_value()?);
                        }
                        "stage_digest" => {
                            if stage_digest.is_some() {
                                return Err(de::Error::duplicate_field("stage_digest"));
                            }
                            stage_digest = Some(map.next_value()?);
                        }
                        "token_backup" => {
                            if token_backup.is_some() {
                                return Err(de::Error::duplicate_field("token_backup"));
                            }
                            token_backup = Some(map.next_value()?);
                        }
                        "token_backup_digest" => {
                            if token_backup_digest.is_some() {
                                return Err(de::Error::duplicate_field("token_backup_digest"));
                            }
                            token_backup_digest = Some(map.next_value()?);
                        }
                        "document_backup" => {
                            if document_backup.is_some() {
                                return Err(de::Error::duplicate_field("document_backup"));
                            }
                            document_backup = Some(map.next_value()?);
                        }
                        "document_backup_digest" => {
                            if document_backup_digest.is_some() {
                                return Err(de::Error::duplicate_field("document_backup_digest"));
                            }
                            document_backup_digest = Some(map.next_value()?);
                        }
                        "token_tombstone" => {
                            if token_tombstone.is_some() {
                                return Err(de::Error::duplicate_field("token_tombstone"));
                            }
                            token_tombstone = Some(map.next_value()?);
                        }
                        "token_tombstone_digest" => {
                            if token_tombstone_digest.is_some() {
                                return Err(de::Error::duplicate_field("token_tombstone_digest"));
                            }
                            token_tombstone_digest = Some(map.next_value()?);
                        }
                        "document_tombstone" => {
                            if document_tombstone.is_some() {
                                return Err(de::Error::duplicate_field("document_tombstone"));
                            }
                            document_tombstone = Some(map.next_value()?);
                        }
                        "document_tombstone_digest" => {
                            if document_tombstone_digest.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "document_tombstone_digest",
                                ));
                            }
                            document_tombstone_digest = Some(map.next_value()?);
                        }
                        other => return Err(de::Error::unknown_field(other, JOURNAL_FIELDS)),
                    }
                }
                Ok(CredentialJournal {
                    journal_version: journal_version
                        .ok_or_else(|| de::Error::missing_field("journal_version"))?,
                    txid: txid.ok_or_else(|| de::Error::missing_field("txid"))?,
                    phase: phase.ok_or_else(|| de::Error::missing_field("phase"))?,
                    base_revision: base_revision
                        .ok_or_else(|| de::Error::missing_field("base_revision"))?,
                    before_ref: before_ref.ok_or_else(|| de::Error::missing_field("before_ref"))?,
                    after_ref: after_ref.ok_or_else(|| de::Error::missing_field("after_ref"))?,
                    before: before.ok_or_else(|| de::Error::missing_field("before"))?,
                    after: after.ok_or_else(|| de::Error::missing_field("after"))?,
                    stage: stage.ok_or_else(|| de::Error::missing_field("stage"))?,
                    stage_digest: stage_digest
                        .ok_or_else(|| de::Error::missing_field("stage_digest"))?,
                    token_backup: token_backup
                        .ok_or_else(|| de::Error::missing_field("token_backup"))?,
                    token_backup_digest: token_backup_digest
                        .ok_or_else(|| de::Error::missing_field("token_backup_digest"))?,
                    document_backup: document_backup
                        .ok_or_else(|| de::Error::missing_field("document_backup"))?,
                    document_backup_digest: document_backup_digest
                        .ok_or_else(|| de::Error::missing_field("document_backup_digest"))?,
                    token_tombstone: token_tombstone
                        .ok_or_else(|| de::Error::missing_field("token_tombstone"))?,
                    token_tombstone_digest: token_tombstone_digest
                        .ok_or_else(|| de::Error::missing_field("token_tombstone_digest"))?,
                    document_tombstone: document_tombstone
                        .ok_or_else(|| de::Error::missing_field("document_tombstone"))?,
                    document_tombstone_digest: document_tombstone_digest
                        .ok_or_else(|| de::Error::missing_field("document_tombstone_digest"))?,
                })
            }
        }
        deserializer.deserialize_map(JournalVisitor)
    }
}

/// Successful restoration metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreReceipt {
    Restored {
        txid: Uuid,
        material_digest: Option<String>,
    },
    AlreadyAbsent {
        txid: Uuid,
    },
}

/// Credential-store failures are typed at the mutation boundary.  Display and
/// Debug intentionally expose only kinds and digests, never credential bytes.
pub enum CredentialStoreError {
    InvalidInput {
        message: &'static str,
    },
    NotFound {
        kind: CredentialRefKind,
    },
    Corrupt {
        message: &'static str,
    },
    Mismatch {
        expected_kind: Option<CredentialRefKind>,
        actual_kind: Option<CredentialRefKind>,
        expected_fingerprint: Option<String>,
        actual_fingerprint: Option<String>,
        expected_material_digest: Option<String>,
        actual_material_digest: Option<String>,
    },
    Conflict {
        message: &'static str,
    },
    NotApplied {
        source: anyhow::Error,
    },
    ReconcileRequired {
        source: anyhow::Error,
        token: Option<ReconcileToken>,
    },
    Io {
        source: anyhow::Error,
    },
    Credential(CredentialError),
}

impl CredentialStoreError {
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
            token: None,
        }
    }

    fn reconcile_with_token(error: impl Into<anyhow::Error>, staged: StagedCredential) -> Self {
        Self::ReconcileRequired {
            source: error.into(),
            token: Some(ReconcileToken {
                inner: Box::new(staged),
            }),
        }
    }
}

impl fmt::Debug for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_string())
    }
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { message } => {
                write!(formatter, "invalid credential input: {message}")
            }
            Self::NotFound { kind } => write!(formatter, "credential file not found for {kind:?}"),
            Self::Corrupt { message } => write!(formatter, "corrupt credential file: {message}"),
            Self::Mismatch {
                expected_kind,
                actual_kind,
                expected_fingerprint,
                actual_fingerprint,
                expected_material_digest,
                actual_material_digest,
            } => write!(
                formatter,
                "credential mismatch: kind {expected_kind:?}/{actual_kind:?}, fingerprint {expected_fingerprint:?}/{actual_fingerprint:?}, material {expected_material_digest:?}/{actual_material_digest:?}"
            ),
            Self::Conflict { message } => {
                write!(formatter, "credential publish conflict: {message}")
            }
            Self::NotApplied { source } => {
                write!(formatter, "credential mutation not applied: {source}")
            }
            Self::ReconcileRequired { source, .. } => {
                write!(
                    formatter,
                    "credential mutation requires reconciliation: {source}"
                )
            }
            Self::Io { source } => write!(formatter, "credential store I/O failed: {source}"),
            Self::Credential(error) => write!(formatter, "invalid credential: {error}"),
        }
    }
}

impl std::error::Error for CredentialStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotApplied { source }
            | Self::ReconcileRequired { source, .. }
            | Self::Io { source } => Some(source.as_ref()),
            Self::Credential(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CredentialError> for CredentialStoreError {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

type StoreResult<T> = std::result::Result<T, CredentialStoreError>;

fn map_mutation_failure(error: crate::core::atomic_io::MutationFailure) -> CredentialStoreError {
    match error {
        crate::core::atomic_io::MutationFailure::NotApplied { source } => {
            CredentialStoreError::not_applied(source)
        }
        crate::core::atomic_io::MutationFailure::ReconcileRequired { source } => {
            CredentialStoreError::reconcile(source)
        }
    }
}

fn reconcile_published(
    staged: StagedCredential,
    error: CredentialStoreError,
) -> CredentialStoreError {
    CredentialStoreError::reconcile_with_token(anyhow::Error::new(error), staged)
}

const fn target_filename(kind: CredentialRefKind) -> &'static str {
    match kind {
        CredentialRefKind::OauthAccessToken => TOKEN_FILENAME,
        CredentialRefKind::OauthAuthorizedUser
        | CredentialRefKind::ApiKey
        | CredentialRefKind::VertexServiceAccount => CREDENTIALS_FILENAME,
    }
}

/// A fixed-layout credential store for one validated account id.
#[derive(Clone)]
pub struct CredentialStore {
    state_dir: PathBuf,
    account_id: String,
    account_dir: PathBuf,
    normalized_root: Option<NormalizedStoreRoot>,
    capability: Option<AccountStoreCapability>,
    mode: CredentialStoreMode,
    base_revision: Option<Revision>,
    before_ref: Option<CredentialRef>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CredentialStoreMode {
    ReadOnly,
    CurrentExact,
    Migration,
}

impl fmt::Debug for CredentialStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialStore")
            .field("account_id", &self.account_id)
            .finish()
    }
}

impl CredentialStore {
    /// Construct a store without creating the state or account directory.
    pub(crate) fn new(state_dir: &Path, account_id: &str) -> StoreResult<Self> {
        validate_account_id(account_id).map_err(|_| CredentialStoreError::InvalidInput {
            message: "account id is not a safe path component",
        })?;
        if !state_dir.is_absolute() {
            return Err(CredentialStoreError::InvalidInput {
                message: "state directory must be absolute",
            });
        }
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            account_id: account_id.to_string(),
            account_dir: account_dir(state_dir, account_id),
            normalized_root: Some(
                NormalizedStoreRoot::normalize(state_dir).map_err(CredentialStoreError::io)?,
            ),
            capability: None,
            mode: CredentialStoreMode::ReadOnly,
            base_revision: None,
            before_ref: None,
        })
    }

    /// Construct a credential store from the sealed state transaction
    /// capability. This is the mutation-safe entry point; the legacy
    /// constructor remains for pure migration planning and compatibility.
    #[allow(dead_code)]
    pub(crate) fn from_permit(permit: CredentialMutationPermit) -> StoreResult<Self> {
        let account_id = permit.account_id().to_string();
        let capability = permit.account_capability().clone();
        // The capability is the mutation authority.  The diagnostic path is
        // derived only for read/debug metadata and is never passed to a
        // mutation helper.
        let state_dir = capability_root_path(&capability)?;
        Ok(Self {
            state_dir: state_dir.clone(),
            account_id: account_id.clone(),
            account_dir: account_dir(&state_dir, &account_id),
            normalized_root: None,
            capability: Some(capability),
            mode: match permit.mode() {
                CredentialMutationMode::CurrentExact => CredentialStoreMode::CurrentExact,
                CredentialMutationMode::Migration => CredentialStoreMode::Migration,
            },
            base_revision: Some(permit.state_revision().clone()),
            before_ref: permit.before_ref().cloned(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }

    pub(crate) fn account_dir(&self) -> &Path {
        &self.account_dir
    }

    /// Read the credential named by a state `CredentialRef`.
    pub fn read(&self, reference: &CredentialRef) -> StoreResult<StoredCredential> {
        let kind = reference_kind(reference.kind);
        let stored = self
            .read_kind(kind)?
            .ok_or(CredentialStoreError::NotFound { kind })?;
        if stored.credential.kind() != credential_kind(kind)
            || stored.credential.fingerprint() != reference.fingerprint
        {
            return Err(CredentialStoreError::Mismatch {
                expected_kind: Some(kind),
                actual_kind: Some(stored.kind),
                expected_fingerprint: Some(reference.fingerprint.clone()),
                actual_fingerprint: Some(stored.credential.fingerprint()),
                expected_material_digest: None,
                actual_material_digest: Some(stored.material_digest.clone()),
            });
        }
        Ok(stored)
    }

    /// Read and validate a credential while retaining the account mutation
    /// lock.  Callers that will use the returned material for a coordinated
    /// mutation must keep this lease alive until every dependent publication,
    /// State CAS, and cleanup step has completed.
    pub(crate) fn read_leased(
        &self,
        reference: &CredentialRef,
    ) -> StoreResult<CredentialReadLease> {
        let lock = self.acquire_lock()?;
        match self.read(reference) {
            Ok(stored) => Ok(CredentialReadLease {
                stored,
                _lock: lock,
            }),
            Err(error) => {
                // Dropping the guard on every validation/read failure is
                // important: a stale reference must never strand the account
                // mutation lock for the next recovery attempt.
                drop(lock);
                Err(error)
            }
        }
    }

    /// Purely read one derived fixed-layout slot.  No chmod, mkdir or lock is
    /// performed, and an absent account directory is treated as empty.
    pub fn read_kind(&self, kind: CredentialRefKind) -> StoreResult<Option<StoredCredential>> {
        if let Some(capability) = &self.capability {
            return self.read_kind_with_capability(capability, kind);
        }
        let root = self
            .normalized_root
            .as_ref()
            .ok_or(CredentialStoreError::InvalidInput {
                message: "read-only credential store has no normalized root",
            })?;
        let target = self.relative_locator(target_filename(kind))?;
        let Some(metadata) = inspect_normalized_credential_file(root, &target)? else {
            return Ok(None);
        };
        if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
            return Err(CredentialStoreError::Corrupt {
                message: "credential file exceeds the size limit",
            });
        }
        let bytes = read_normalized_relative_file_bounded(root, &target, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(CredentialStoreError::io)?
            .ok_or(CredentialStoreError::Corrupt {
                message: "credential file disappeared during read",
            })?;
        let credential = parse_material(kind, &bytes)?;
        let material_digest = material_digest(&bytes);
        Ok(Some(StoredCredential {
            credential,
            kind,
            material_digest,
            path: self.target_path(kind),
            bytes,
        }))
    }

    /// Read and classify the shared provider-native `credentials.json` slot
    /// without imposing an expected kind.  This is used by migration before
    /// checking the legacy account type; callers still receive a typed kind
    /// mismatch if they ask for a specific ref through `read_kind`.
    pub fn read_document(&self) -> StoreResult<Option<StoredCredential>> {
        if let Some(capability) = &self.capability {
            let target = capability
                .locator(CREDENTIALS_FILENAME)
                .map_err(CredentialStoreError::io)?;
            let Some(metadata) = capability
                .inspect(&target, true)
                .map_err(CredentialStoreError::io)?
            else {
                return Ok(None);
            };
            if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
                return Err(CredentialStoreError::Corrupt {
                    message: "credential file exceeds the size limit",
                });
            }
            let bytes = capability
                .read_bounded(&target, MAX_CREDENTIAL_FILE_BYTES)
                .map_err(CredentialStoreError::io)?
                .ok_or(CredentialStoreError::Corrupt {
                    message: "credential file disappeared during read",
                })?;
            return parse_document_bytes(self, target, bytes);
        }
        let root = self
            .normalized_root
            .as_ref()
            .ok_or(CredentialStoreError::InvalidInput {
                message: "read-only credential store has no normalized root",
            })?;
        let target = self.relative_locator(CREDENTIALS_FILENAME)?;
        let Some(metadata) = inspect_normalized_credential_file(root, &target)? else {
            return Ok(None);
        };
        if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
            return Err(CredentialStoreError::Corrupt {
                message: "credential file exceeds the size limit",
            });
        }
        let bytes = read_normalized_relative_file_bounded(root, &target, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(CredentialStoreError::io)?
            .ok_or(CredentialStoreError::Corrupt {
                message: "credential file disappeared during read",
            })?;
        let credential = PortableCredential::from_native_json_str(
            std::str::from_utf8(&bytes)
                .map_err(|_| CredentialStoreError::Corrupt {
                    message: "credential JSON is not UTF-8",
                })?
                .trim(),
        )?;
        if credential.kind() == CredentialKind::OAuthAccessToken {
            return Err(CredentialStoreError::Corrupt {
                message: "raw OAuth token must use the fixed token file",
            });
        }
        Ok(Some(StoredCredential {
            kind: credential_ref_kind(credential.kind()),
            credential,
            material_digest: material_digest(&bytes),
            path: self.account_dir.join(CREDENTIALS_FILENAME),
            bytes,
        }))
    }

    fn read_kind_with_capability(
        &self,
        capability: &AccountStoreCapability,
        kind: CredentialRefKind,
    ) -> StoreResult<Option<StoredCredential>> {
        let target = capability
            .locator(target_filename(kind))
            .map_err(CredentialStoreError::io)?;
        let Some(metadata) = capability
            .inspect(&target, true)
            .map_err(CredentialStoreError::io)?
        else {
            return Ok(None);
        };
        if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
            return Err(CredentialStoreError::Corrupt {
                message: "credential file exceeds the size limit",
            });
        }
        let bytes = capability
            .read_bounded(&target, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(CredentialStoreError::io)?
            .ok_or(CredentialStoreError::Corrupt {
                message: "credential file disappeared during read",
            })?;
        let credential = parse_material(kind, &bytes)?;
        Ok(Some(StoredCredential {
            credential,
            kind,
            material_digest: material_digest(&bytes),
            path: self.account_dir.join(target_filename(kind)),
            bytes,
        }))
    }

    /// Read both fixed slots as one pure snapshot.  This operation never
    /// creates the account directory, acquires the mutation lock or chmods any
    /// existing item.
    pub fn read_layout(&self) -> StoreResult<CredentialLayout> {
        Ok(CredentialLayout {
            token: self.read_kind(CredentialRefKind::OauthAccessToken)?,
            document: self.read_document()?,
        })
    }

    /// Stage a credential after validating the complete two-slot layout while
    /// holding the credential lock.  The lock is retained in the returned
    /// stage until publish, restore or cleanup completes.
    #[allow(dead_code)]
    pub(crate) fn stage(
        &self,
        txid: Uuid,
        credential: &PortableCredential,
    ) -> StoreResult<PreparedCredentialTxn> {
        let bytes = material_bytes(credential)?;
        let expected = self.stage_preflight_layout()?.expected_layout();
        self.stage_exact(txid, credential, &bytes, &expected)
    }

    /// Import helper that captures a read-only preflight and then rechecks it
    /// under the same lock in `stage_exact`.
    pub(crate) fn stage_with_material(
        &self,
        txid: Uuid,
        credential: &PortableCredential,
        bytes: &[u8],
    ) -> StoreResult<PreparedCredentialTxn> {
        let expected = self.stage_preflight_layout()?.expected_layout();
        self.stage_exact(txid, credential, bytes, &expected)
    }

    fn stage_preflight_layout(&self) -> StoreResult<CredentialLayout> {
        if let Some(capability) = &self.capability {
            capability
                .ensure_account_dir()
                .map_err(CredentialStoreError::io)?;
        }
        self.read_layout()
    }

    /// Explicit two-slot staging API.  `expected_layout` is checked only
    /// after the lock is held, and the returned stage seals the observed
    /// baseline for publish/restore.
    pub(crate) fn stage_exact(
        &self,
        txid: Uuid,
        credential: &PortableCredential,
        bytes: &[u8],
        expected_layout: &ExpectedLayout,
    ) -> StoreResult<PreparedCredentialTxn> {
        let capability = self.mutation_capability()?.clone();
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_FILE_BYTES {
            return Err(CredentialStoreError::InvalidInput {
                message: "credential material is empty or oversized",
            });
        }
        let kind = credential_ref_kind(credential.kind());
        let parsed = parse_material(kind, bytes)?;
        if parsed != *credential {
            return Err(CredentialStoreError::Corrupt {
                message: "staged material does not match its parsed credential",
            });
        }

        let lock = self.acquire_lock()?;
        let baseline = self.read_layout()?;
        if baseline.token.is_some()
            && baseline.document.is_some()
            && !matches!(self.mode, CredentialStoreMode::Migration)
        {
            return Err(CredentialStoreError::Conflict {
                message: "dual live credential slots require a sealed migration permit",
            });
        }
        if matches!(self.mode, CredentialStoreMode::CurrentExact)
            && layout_reference(&baseline) != self.before_ref
        {
            return Err(CredentialStoreError::Conflict {
                message: "current credential layout does not match the state reference",
            });
        }
        ensure_layout_expected(expected_layout, &baseline)?;

        let target = capability
            .locator(target_filename(kind))
            .map_err(CredentialStoreError::io)?;
        let stage = capability
            .locator(&format!("{STAGE_PREFIX}{txid}{STAGE_SUFFIX}"))
            .map_err(CredentialStoreError::io)?;
        let token_backup =
            self.backup_slot(txid, CredentialSlot::Token, baseline.token.as_ref())?;
        let document_backup =
            self.backup_slot(txid, CredentialSlot::Document, baseline.document.as_ref())?;

        let token_tombstone = self.tombstone_path(txid, CredentialSlot::Token);
        let document_tombstone = self.tombstone_path(txid, CredentialSlot::Document);
        let journal = self.journal_path(txid);

        write_evidence(&capability, &stage, bytes)?;
        let staged_credential = StoredCredential {
            credential: credential.clone(),
            kind,
            material_digest: material_digest(bytes),
            path: self.account_dir.join(target_filename(kind)),
            bytes: bytes.to_vec(),
        };
        let published = match slot_for_kind(kind) {
            CredentialSlot::Token => CredentialLayout {
                token: Some(staged_credential.clone()),
                document: None,
            },
            CredentialSlot::Document => CredentialLayout {
                token: None,
                document: Some(staged_credential.clone()),
            },
        };

        write_journal(
            &capability,
            &journal,
            &CredentialJournal {
                journal_version: JOURNAL_VERSION,
                txid: txid.to_string(),
                phase: "prepared".to_string(),
                base_revision: JournalRevision::from_revision(self.base_revision.as_ref().ok_or(
                    CredentialStoreError::InvalidInput {
                        message: "credential mutation has no base state revision",
                    },
                )?)?,
                before_ref: self.before_ref.clone(),
                after_ref: Some(CredentialRef {
                    kind,
                    fingerprint: credential.fingerprint(),
                }),
                before: journal_layout(&baseline),
                after: journal_layout(&published),
                stage: artifact_name(&stage)?,
                stage_digest: material_digest(bytes),
                token_backup: token_backup.as_ref().map(artifact_name).transpose()?,
                token_backup_digest: baseline
                    .token
                    .as_ref()
                    .map(|stored| stored.material_digest.clone()),
                document_backup: document_backup.as_ref().map(artifact_name).transpose()?,
                document_backup_digest: baseline
                    .document
                    .as_ref()
                    .map(|stored| stored.material_digest.clone()),
                token_tombstone: artifact_name(&token_tombstone)?,
                token_tombstone_digest: baseline
                    .token
                    .as_ref()
                    .map(|stored| stored.material_digest.clone()),
                document_tombstone: artifact_name(&document_tombstone)?,
                document_tombstone_digest: baseline
                    .document
                    .as_ref()
                    .map(|stored| stored.material_digest.clone()),
            },
        )?;

        Ok(PreparedCredentialTxn {
            inner: StagedCredential {
                store: self.clone(),
                lock,
                txid,
                target,
                stage,
                kind,
                fingerprint: credential.fingerprint(),
                material_digest: material_digest(bytes),
                baseline,
                published,
                deleting: false,
                base_revision: self.base_revision.clone().ok_or(
                    CredentialStoreError::InvalidInput {
                        message: "credential mutation has no base state revision",
                    },
                )?,
                before_ref: self.before_ref.clone(),
                after_ref: Some(CredentialRef {
                    kind,
                    fingerprint: credential.fingerprint(),
                }),
                token_backup,
                document_backup,
                token_tombstone,
                document_tombstone,
                journal,
            },
        })
    }

    /// Stage removal of the one live fixed slot and publish an empty layout.
    /// Deletion uses the same journal/evidence protocol as replacement, so a
    /// crash cannot turn a state reference removal into an unrecoverable
    /// credential loss.
    #[allow(dead_code)]
    pub(crate) fn stage_delete(
        &self,
        txid: Uuid,
        expected_layout: &ExpectedLayout,
    ) -> StoreResult<PreparedCredentialTxn> {
        let capability = self.mutation_capability()?.clone();
        let lock = self.acquire_lock()?;
        let baseline = self.read_layout()?;
        ensure_layout_expected(expected_layout, &baseline)?;
        if matches!(self.mode, CredentialStoreMode::CurrentExact)
            && layout_reference(&baseline) != self.before_ref
        {
            return Err(CredentialStoreError::Conflict {
                message: "current credential layout does not match the state reference",
            });
        }
        let (_slot, stored) = match (&baseline.token, &baseline.document) {
            (Some(token), None) => (CredentialSlot::Token, token),
            (None, Some(document)) => (CredentialSlot::Document, document),
            (None, None) => {
                return Err(CredentialStoreError::NotFound {
                    kind: CredentialRefKind::OauthAccessToken,
                });
            }
            (Some(_), Some(_)) => {
                return Err(CredentialStoreError::Conflict {
                    message: "cannot delete an ambiguous dual live credential layout",
                });
            }
        };
        let kind = stored.kind;
        let stage = capability
            .locator(&format!("{STAGE_PREFIX}{txid}{STAGE_SUFFIX}"))
            .map_err(CredentialStoreError::io)?;
        // Keep an exact copy as bounded evidence; this also lets restart
        // recovery reconstruct the baseline before the target is moved.
        write_evidence(&capability, &stage, &stored.bytes)?;
        let token_backup =
            self.backup_slot(txid, CredentialSlot::Token, baseline.token.as_ref())?;
        let document_backup =
            self.backup_slot(txid, CredentialSlot::Document, baseline.document.as_ref())?;
        let token_tombstone = self.tombstone_path(txid, CredentialSlot::Token);
        let document_tombstone = self.tombstone_path(txid, CredentialSlot::Document);
        let journal = self.journal_path(txid);
        let empty = CredentialLayout {
            token: None,
            document: None,
        };
        let base_revision =
            self.base_revision
                .clone()
                .ok_or(CredentialStoreError::InvalidInput {
                    message: "credential mutation has no base state revision",
                })?;
        let before_ref = self.before_ref.clone();
        let after_ref = None;
        write_journal(
            &capability,
            &journal,
            &CredentialJournal {
                journal_version: JOURNAL_VERSION,
                txid: txid.to_string(),
                phase: "prepared".to_string(),
                base_revision: JournalRevision::from_revision(&base_revision)?,
                before_ref: before_ref.clone(),
                after_ref: after_ref.clone(),
                before: journal_layout(&baseline),
                after: journal_layout(&empty),
                stage: artifact_name(&stage)?,
                stage_digest: material_digest(&stored.bytes),
                token_backup: token_backup.as_ref().map(artifact_name).transpose()?,
                token_backup_digest: baseline
                    .token
                    .as_ref()
                    .map(|value| value.material_digest.clone()),
                document_backup: document_backup.as_ref().map(artifact_name).transpose()?,
                document_backup_digest: baseline
                    .document
                    .as_ref()
                    .map(|value| value.material_digest.clone()),
                token_tombstone: artifact_name(&token_tombstone)?,
                token_tombstone_digest: baseline
                    .token
                    .as_ref()
                    .map(|value| value.material_digest.clone()),
                document_tombstone: artifact_name(&document_tombstone)?,
                document_tombstone_digest: baseline
                    .document
                    .as_ref()
                    .map(|value| value.material_digest.clone()),
            },
        )?;
        Ok(PreparedCredentialTxn {
            inner: StagedCredential {
                store: self.clone(),
                lock,
                txid,
                target: capability
                    .locator(target_filename(kind))
                    .map_err(CredentialStoreError::io)?,
                stage,
                kind,
                fingerprint: stored.credential.fingerprint(),
                material_digest: material_digest(&stored.bytes),
                baseline,
                published: empty,
                deleting: true,
                base_revision,
                before_ref,
                after_ref,
                token_backup,
                document_backup,
                token_tombstone,
                document_tombstone,
                journal,
            },
        })
    }

    /// Quarantine every live credential file of an account that cannot be
    /// migrated, then record the caller's evidence document.
    ///
    /// 为什么是"改名隔离"而不是删除：迁移必须能把坏账号移出 v2 状态，但用户的
    /// 原始凭据与 v1 账号记录是不可再生的数据，只能保留在账号目录里等人工处理。
    ///
    /// 返回本次真正改名产生的隔离文件名。改名是**非事务性**的：调用方所在的
    /// 迁移事务如果随后回滚，这些文件不会被移回去，所以调用方必须拿着这份清单
    /// 把已发生的磁盘变更如实告诉用户（AC-R12-1.1）。
    pub(crate) fn quarantine_unmigratable(&self, evidence: &[u8]) -> StoreResult<Vec<String>> {
        let capability = self.mutation_capability()?.clone();
        capability
            .ensure_account_dir()
            .map_err(CredentialStoreError::io)?;
        let _lock = self.acquire_lock()?;
        let mut moved = Vec::new();
        for filename in [TOKEN_FILENAME, CREDENTIALS_FILENAME] {
            let source = capability
                .locator(filename)
                .map_err(CredentialStoreError::io)?;
            if capability
                .inspect(&source, true)
                .map_err(CredentialStoreError::io)?
                .is_none()
            {
                continue;
            }
            let destination = quarantine_destination(&capability, filename)?;
            let destination_name = destination
                .as_path()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(CredentialStoreError::InvalidInput {
                    message: "quarantine destination is not a plain filename",
                })?
                .to_string();
            capability
                .move_file(&source, &destination)
                .map_err(map_mutation_failure)?;
            moved.push(destination_name);
        }
        let record = capability
            .locator(QUARANTINE_RECORD)
            .map_err(CredentialStoreError::io)?;
        // 反复迁移同一份坏状态时保留最早一次的证据，不覆盖。
        if capability
            .inspect(&record, true)
            .map_err(CredentialStoreError::io)?
            .is_none()
        {
            write_evidence(&capability, &record, evidence)?;
        }
        Ok(moved)
    }

    /// Stage the retirement of a legacy account that has no live credential.
    ///
    /// 为什么需要这笔"空事务"：v2 迁移许可要求每个 v1 账号都提供一份 credential
    /// journal proof，缺一个就整笔失败。坏账号必须也留下一笔可验证的事务，
    /// 迁移才能在跳过它的同时提交（MIG-001）。
    pub(crate) fn stage_purge(&self, txid: Uuid) -> StoreResult<PreparedCredentialTxn> {
        let capability = self.mutation_capability()?.clone();
        let lock = self.acquire_lock()?;
        let baseline = self.read_layout()?;
        if baseline.token.is_some() || baseline.document.is_some() {
            return Err(CredentialStoreError::Conflict {
                message: "credential purge requires an empty live credential layout",
            });
        }
        let stage = capability
            .locator(&format!("{STAGE_PREFIX}{txid}{STAGE_SUFFIX}"))
            .map_err(CredentialStoreError::io)?;
        let token_tombstone = self.tombstone_path(txid, CredentialSlot::Token);
        let document_tombstone = self.tombstone_path(txid, CredentialSlot::Document);
        let journal = self.journal_path(txid);
        let empty = CredentialLayout {
            token: None,
            document: None,
        };
        let base_revision =
            self.base_revision
                .clone()
                .ok_or(CredentialStoreError::InvalidInput {
                    message: "credential mutation has no base state revision",
                })?;
        let before_ref = self.before_ref.clone();
        let empty_digest = material_digest(&[]);
        write_journal(
            &capability,
            &journal,
            &CredentialJournal {
                journal_version: JOURNAL_VERSION,
                txid: txid.to_string(),
                phase: "prepared".to_string(),
                base_revision: JournalRevision::from_revision(&base_revision)?,
                before_ref: before_ref.clone(),
                after_ref: None,
                before: journal_layout(&empty),
                after: journal_layout(&empty),
                stage: artifact_name(&stage)?,
                stage_digest: empty_digest.clone(),
                token_backup: None,
                token_backup_digest: None,
                document_backup: None,
                document_backup_digest: None,
                token_tombstone: artifact_name(&token_tombstone)?,
                token_tombstone_digest: None,
                document_tombstone: artifact_name(&document_tombstone)?,
                document_tombstone_digest: None,
            },
        )?;
        Ok(PreparedCredentialTxn {
            inner: StagedCredential {
                store: self.clone(),
                lock,
                txid,
                target: capability
                    .locator(target_filename(CredentialRefKind::OauthAccessToken))
                    .map_err(CredentialStoreError::io)?,
                stage,
                kind: CredentialRefKind::OauthAccessToken,
                fingerprint: String::new(),
                material_digest: empty_digest,
                baseline: empty.clone(),
                published: empty,
                deleting: true,
                base_revision,
                before_ref,
                after_ref: None,
                token_backup: None,
                document_backup: None,
                token_tombstone,
                document_tombstone,
                journal,
            },
        })
    }

    /// Consume a prepared transaction and publish its complete target layout.
    pub(crate) fn publish(
        &self,
        prepared: PreparedCredentialTxn,
    ) -> StoreResult<PublishedCredentialTxn> {
        let staged = prepared.inner;
        self.ensure_staged_store(&staged)?;
        let _held_lock = &staged.lock;
        let capability = self.mutation_capability()?;
        let current = self.read_layout()?;
        ensure_layout_equal(&staged.baseline, &current)?;
        let journal = read_journal(capability, staged.journal())?;
        validate_journal(&staged, &journal)?;
        // 清退事务没有任何 stage 字节可校验：它既不写入也不移动凭据文件。
        if !staged.is_purge() {
            self.validate_stage(&staged)?;
        }

        // Move the opposite live slot to a transaction-specific tombstone
        // before replacing the target.  An opposite credential is never
        // unlinked: if the second filesystem operation fails, the tombstone
        // and journal evidence are sufficient to reconstruct both slots.
        let published_slot = slot_for_kind(staged.kind);
        let opposite_slot = published_slot.opposite();
        let opposite_moved = staged.baseline.slot(opposite_slot).is_some();
        if staged.deleting {
            if opposite_moved {
                return Err(CredentialStoreError::Conflict {
                    message: "credential deletion requires a single live slot",
                });
            }
            if let Err(failure) = if staged.is_purge() {
                Ok(())
            } else {
                capability.move_file(&staged.target, staged.tombstone(published_slot))
            } {
                return Err(match failure {
                    crate::core::atomic_io::MutationFailure::NotApplied { source } => {
                        CredentialStoreError::not_applied(source)
                    }
                    crate::core::atomic_io::MutationFailure::ReconcileRequired { source } => {
                        CredentialStoreError::reconcile_with_token(source, staged)
                    }
                });
            }
            if let Err(error) = self.update_journal_phase(&staged, "published") {
                return Err(CredentialStoreError::reconcile_with_token(
                    anyhow::Error::new(error),
                    staged,
                ));
            }
            return Ok(PublishedCredentialTxn { inner: staged });
        }
        if opposite_moved {
            let opposite_path = self.target_locator_for_slot(opposite_slot)?;
            let tombstone = staged.tombstone(opposite_slot);
            if let Err(failure) = capability.move_file(&opposite_path, tombstone) {
                return Err(match failure {
                    crate::core::atomic_io::MutationFailure::NotApplied { source } => {
                        CredentialStoreError::not_applied(source)
                    }
                    crate::core::atomic_io::MutationFailure::ReconcileRequired { source } => {
                        CredentialStoreError::reconcile_with_token(source, staged)
                    }
                });
            }
            if let Err(error) = self.update_journal_phase(&staged, "opposite_moved") {
                return Err(CredentialStoreError::reconcile_with_token(
                    anyhow::Error::new(error),
                    staged,
                ));
            }
        }
        if let Err(failure) = capability.replace(&staged.stage, &staged.target) {
            return Err(match failure {
                crate::core::atomic_io::MutationFailure::NotApplied { source }
                    if opposite_moved =>
                {
                    // The opposite slot has already been moved, so the
                    // transaction is no longer NotApplied even if replacing
                    // the target failed before its new bytes became live.
                    CredentialStoreError::reconcile_with_token(source, staged)
                }
                crate::core::atomic_io::MutationFailure::NotApplied { source } => {
                    CredentialStoreError::not_applied(source)
                }
                crate::core::atomic_io::MutationFailure::ReconcileRequired { source } => {
                    CredentialStoreError::reconcile_with_token(source, staged)
                }
            });
        }
        if let Err(error) = self.update_journal_phase(&staged, "published") {
            return Err(CredentialStoreError::reconcile_with_token(
                anyhow::Error::new(error),
                staged,
            ));
        }
        Ok(PublishedCredentialTxn { inner: staged })
    }

    /// Restore both slots only when the complete live layout is exactly the
    /// layout published by this transaction.
    pub(crate) fn restore(&self, published: PublishedCredentialTxn) -> StoreResult<RestoreReceipt> {
        let staged = published.inner;
        self.ensure_staged_store(&staged)?;
        let _held_lock = &staged.lock;
        let capability = match self.mutation_capability() {
            Ok(capability) => capability,
            Err(error) => return Err(reconcile_published(staged, error)),
        };
        let journal = match read_journal(capability, staged.journal()) {
            Ok(journal) => journal,
            Err(error) => return Err(reconcile_published(staged, error)),
        };
        if let Err(error) = validate_journal(&staged, &journal) {
            return Err(reconcile_published(staged, error));
        }
        let current = match self.read_layout() {
            Ok(current) => current,
            Err(error) => return Err(reconcile_published(staged, error)),
        };
        if current != staged.baseline
            && current != staged.published
            && !layout_after_opposite_move(&staged, &current)
            && !layout_after_only_move(&staged, &current)
        {
            return Err(reconcile_published(
                staged,
                CredentialStoreError::Conflict {
                    message: "live credential layout is not a known transaction state",
                },
            ));
        }

        if let Err(error) = self.restore_slot(
            CredentialSlot::Token,
            staged.baseline.token.as_ref(),
            staged.token_backup.as_ref(),
            staged.tombstone(CredentialSlot::Token),
            staged.published.token.as_ref(),
        ) {
            return Err(CredentialStoreError::reconcile_with_token(
                anyhow::Error::new(error),
                staged,
            ));
        }
        if let Err(error) = self.restore_slot(
            CredentialSlot::Document,
            staged.baseline.document.as_ref(),
            staged.document_backup.as_ref(),
            staged.tombstone(CredentialSlot::Document),
            staged.published.document.as_ref(),
        ) {
            return Err(CredentialStoreError::reconcile_with_token(
                anyhow::Error::new(error),
                staged,
            ));
        }
        if let Err(error) = self.update_journal_phase(&staged, "restored") {
            return Err(CredentialStoreError::reconcile_with_token(
                anyhow::Error::new(error),
                staged,
            ));
        }
        if let Err(error) = self.cleanup_unlocked(&staged) {
            return Err(CredentialStoreError::reconcile_with_token(
                anyhow::Error::new(error),
                staged,
            ));
        }
        Ok(RestoreReceipt::Restored {
            txid: staged.txid,
            material_digest: staged
                .baseline
                .token
                .as_ref()
                .or(staged.baseline.document.as_ref())
                .map(|stored| stored.material_digest.clone()),
        })
    }

    /// Finalize published evidence only after the matching State commit
    /// receipt proves that the v2 credential reference points at this exact
    /// credential.
    pub(crate) fn finalize(
        &self,
        published: PublishedCredentialTxn,
        receipt: &StateCommitReceipt,
    ) -> StoreResult<()> {
        let staged = published.inner;
        self.ensure_staged_store(&staged)?;
        let _held_lock = &staged.lock;
        let Some(transition) = receipt.credential_transition(&self.account_id) else {
            return Err(reconcile_published(
                staged,
                CredentialStoreError::Conflict {
                    message: "state receipt has no credential transition for this account",
                },
            ));
        };
        if transition.txid() != staged.txid
            || transition.base_revision() != &staged.base_revision
            || transition.committed_revision() != receipt.revision()
            || transition.before_ref() != staged.before_ref.as_ref()
            || transition.after_ref() != staged.after_ref.as_ref()
        {
            return Err(reconcile_published(
                staged,
                CredentialStoreError::Conflict {
                    message: "state receipt transition does not match staged credential",
                },
            ));
        }
        if receipt.revision().document_sha256.is_none() {
            return Err(reconcile_published(
                staged,
                CredentialStoreError::Conflict {
                    message: "state receipt has no committed document digest",
                },
            ));
        }
        let current = match self.read_layout() {
            Ok(current) => current,
            Err(error) => return Err(reconcile_published(staged, error)),
        };
        if let Err(error) = ensure_layout_equal(&staged.published, &current) {
            return Err(reconcile_published(staged, error));
        }
        match self.cleanup_unlocked(&staged) {
            Ok(()) => Ok(()),
            Err(error) => Err(reconcile_published(staged, error)),
        }
    }

    /// Return opaque proof that this transaction's journal is durable. The
    /// proof contains only account id, txid, journal digest, state revision
    /// and before/after references, never secret credential bytes.
    #[allow(dead_code)]
    pub(crate) fn journal_proof(
        &self,
        published: &PublishedCredentialTxn,
    ) -> StoreResult<CredentialJournalProof> {
        let staged = &published.inner;
        self.ensure_staged_store(staged)?;
        let _held_lock = &staged.lock;
        let capability = self.mutation_capability()?;
        let journal = read_journal(capability, staged.journal())?;
        validate_journal(staged, &journal)?;
        let _metadata = capability
            .inspect(staged.journal(), false)
            .map_err(CredentialStoreError::reconcile)?
            .ok_or(CredentialStoreError::ReconcileRequired {
                source: anyhow!("credential journal disappeared"),
                token: None,
            })?;
        let bytes = capability
            .read_bounded(staged.journal(), JOURNAL_MAX_BYTES)
            .map_err(CredentialStoreError::reconcile)?;
        let bytes = bytes.ok_or(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal disappeared"),
            token: None,
        })?;
        let mut digest = Sha256::new();
        digest.update(bytes);
        CredentialJournalProof::new_transition(
            &self.account_id,
            staged.txid,
            format!("{:x}", digest.finalize()),
            staged.base_revision.clone(),
            staged.before_ref.clone(),
            staged.after_ref.clone(),
        )
        .map_err(CredentialStoreError::reconcile)
    }

    fn ensure_staged_store(&self, staged: &StagedCredential) -> StoreResult<()> {
        if staged.store.account_id != self.account_id
            || staged.store.state_dir != self.state_dir
            || staged.store.capability != self.capability
            || staged.store.mode != self.mode
        {
            return Err(CredentialStoreError::InvalidInput {
                message: "staged credential belongs to another account store",
            });
        }
        Ok(())
    }

    fn validate_stage(&self, staged: &StagedCredential) -> StoreResult<()> {
        let capability = self.mutation_capability()?;
        let metadata = capability
            .inspect(&staged.stage, false)
            .map_err(CredentialStoreError::not_applied)?
            .ok_or(CredentialStoreError::NotApplied {
                source: anyhow!("credential stage is missing"),
            })?;
        if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
            return Err(CredentialStoreError::not_applied(anyhow!(
                "credential stage exceeds the size limit"
            )));
        }
        let bytes = capability
            .read_bounded(&staged.stage, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(CredentialStoreError::not_applied)?;
        let bytes = bytes.ok_or(CredentialStoreError::NotApplied {
            source: anyhow!("credential stage is missing"),
        })?;
        let parsed = parse_material(staged.kind, &bytes)?;
        if parsed.fingerprint() != staged.fingerprint
            || material_digest(&bytes) != staged.material_digest
        {
            return Err(CredentialStoreError::Corrupt {
                message: "credential stage changed after staging",
            });
        }
        Ok(())
    }

    fn backup_slot(
        &self,
        txid: Uuid,
        slot: CredentialSlot,
        baseline: Option<&StoredCredential>,
    ) -> StoreResult<Option<SafeRelativePath>> {
        let Some(stored) = baseline else {
            return Ok(None);
        };
        let capability = self.mutation_capability()?;
        let path = self.backup_path(txid, slot);
        write_evidence(capability, &path, &stored.bytes)?;
        Ok(Some(path))
    }

    fn backup_path(&self, txid: Uuid, slot: CredentialSlot) -> SafeRelativePath {
        let suffix = match slot {
            CredentialSlot::Token => TOKEN_BACKUP_SUFFIX,
            CredentialSlot::Document => DOCUMENT_BACKUP_SUFFIX,
        };
        self.artifact_locator(&format!("{STAGE_PREFIX}{txid}{suffix}"))
            .expect("fixed credential artifact name is safe")
    }

    fn tombstone_path(&self, txid: Uuid, slot: CredentialSlot) -> SafeRelativePath {
        let suffix = match slot {
            CredentialSlot::Token => TOKEN_TOMBSTONE_SUFFIX,
            CredentialSlot::Document => DOCUMENT_TOMBSTONE_SUFFIX,
        };
        self.artifact_locator(&format!("{STAGE_PREFIX}{txid}{suffix}"))
            .expect("fixed credential artifact name is safe")
    }

    fn journal_path(&self, txid: Uuid) -> SafeRelativePath {
        self.artifact_locator(&format!("{STAGE_PREFIX}{txid}{JOURNAL_SUFFIX}"))
            .expect("fixed credential artifact name is safe")
    }

    fn target_locator_for_slot(&self, slot: CredentialSlot) -> StoreResult<SafeRelativePath> {
        let capability = self.mutation_capability()?;
        capability
            .locator(target_filename(slot.kind()))
            .map_err(CredentialStoreError::io)
    }

    #[allow(dead_code)]
    fn restore_slot(
        &self,
        slot: CredentialSlot,
        baseline: Option<&StoredCredential>,
        backup: Option<&SafeRelativePath>,
        tombstone: &SafeRelativePath,
        published: Option<&StoredCredential>,
    ) -> StoreResult<()> {
        let capability = self.mutation_capability()?;
        let target = self.target_locator_for_slot(slot)?;
        if let Some(baseline) = baseline {
            // Prefer the tombstone, which is the exact live file moved during
            // publish.  A pre-publish backup is the fallback for a crash
            // window before the opposite move reached durable storage.
            let source = if capability
                .inspect(tombstone, true)
                .map_err(CredentialStoreError::io)?
                .is_some()
            {
                tombstone
            } else {
                backup.ok_or(CredentialStoreError::Corrupt {
                    message: "credential baseline backup is missing",
                })?
            };
            let metadata = capability
                .inspect(source, false)
                .map_err(CredentialStoreError::io)?
                .ok_or(CredentialStoreError::Corrupt {
                    message: "credential baseline evidence is missing",
                })?;
            if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
                return Err(CredentialStoreError::Corrupt {
                    message: "credential baseline backup exceeds the size limit",
                });
            }
            let bytes = capability
                .read_bounded(source, MAX_CREDENTIAL_FILE_BYTES)
                .map_err(CredentialStoreError::io)?
                .ok_or(CredentialStoreError::Corrupt {
                    message: "credential baseline evidence disappeared",
                })?;
            if bytes != baseline.bytes {
                return Err(CredentialStoreError::Mismatch {
                    expected_kind: Some(baseline.kind),
                    actual_kind: Some(baseline.kind),
                    expected_fingerprint: Some(baseline.credential.fingerprint()),
                    actual_fingerprint: Some(baseline.credential.fingerprint()),
                    expected_material_digest: Some(baseline.material_digest.clone()),
                    actual_material_digest: Some(material_digest(&bytes)),
                });
            }
            if self
                .read_slot(slot)?
                .as_ref()
                .is_some_and(|live| live.bytes == baseline.bytes)
            {
                Ok(())
            } else {
                capability
                    .replace(source, &target)
                    .map_err(map_mutation_failure)
            }
        } else if let Some(published) = published {
            // This is newly created evidence, so only remove it after proving
            // that it still contains this transaction's published bytes.
            let live = self.read_slot(slot)?;
            if live.is_none() {
                Ok(())
            } else if live
                .as_ref()
                .is_some_and(|live| live.bytes == published.bytes)
            {
                capability
                    .remove(&target)
                    .map_err(map_mutation_failure)
                    .map(|_| ())
            } else {
                Err(CredentialStoreError::Conflict {
                    message: "new credential changed before restore",
                })
            }
        } else {
            Ok(())
        }
    }

    fn cleanup_unlocked(&self, staged: &StagedCredential) -> StoreResult<()> {
        let capability = self.mutation_capability()?;
        let current = self.read_layout()?;
        if current != staged.baseline
            && current != staged.published
            && !layout_after_opposite_move(staged, &current)
            && !layout_after_only_move(staged, &current)
        {
            return Err(CredentialStoreError::Conflict {
                message: "live credential layout is not a known cleanup state",
            });
        }
        let journal = read_journal(capability, staged.journal())?;
        validate_journal(staged, &journal)?;
        let evidence = [
            (Some(&staged.stage), Some(staged.material_digest.as_str())),
            (
                staged.token_backup.as_ref(),
                staged
                    .baseline
                    .token
                    .as_ref()
                    .map(|stored| stored.material_digest.as_str()),
            ),
            (
                staged.document_backup.as_ref(),
                staged
                    .baseline
                    .document
                    .as_ref()
                    .map(|stored| stored.material_digest.as_str()),
            ),
            (
                Some(&staged.token_tombstone),
                staged
                    .baseline
                    .token
                    .as_ref()
                    .map(|stored| stored.material_digest.as_str()),
            ),
            (
                Some(&staged.document_tombstone),
                staged
                    .baseline
                    .document
                    .as_ref()
                    .map(|stored| stored.material_digest.as_str()),
            ),
        ];
        for (path, expected_digest) in evidence {
            if let Some(path) = path {
                remove_evidence_exact(capability, path, expected_digest)
                    .map_err(map_remove_failure)?;
            }
        }
        cleanup_orphan_updates(capability)?;
        let journal_digest = journal_digest(capability, staged.journal())?;
        remove_evidence_exact(capability, staged.journal(), Some(&journal_digest))
            .map_err(map_remove_failure)?;
        Ok(())
    }

    fn update_journal_phase(&self, staged: &StagedCredential, phase: &str) -> StoreResult<()> {
        let capability = self.mutation_capability()?;
        let mut journal = read_journal(capability, staged.journal())?;
        validate_journal(staged, &journal)?;
        journal.phase = phase.to_string();
        update_journal(capability, staged.journal(), &journal)
    }

    fn acquire_lock(&self) -> StoreResult<File> {
        let capability = self.mutation_capability()?.clone();
        capability
            .ensure_account_dir()
            .map_err(CredentialStoreError::io)?;
        let lock_path = capability
            .locator(LOCK_FILENAME)
            .map_err(CredentialStoreError::io)?;
        let file = capability
            .open_or_create_lock(&lock_path)
            .map_err(CredentialStoreError::io)?;
        file.lock_exclusive().map_err(|error| {
            CredentialStoreError::io(anyhow!(error).context("failed to lock credential store"))
        })?;
        Ok(file)
    }

    fn target_path(&self, kind: CredentialRefKind) -> PathBuf {
        self.account_dir.join(target_filename(kind))
    }

    fn relative_locator(&self, filename: &str) -> StoreResult<SafeRelativePath> {
        SafeRelativePath::new(&Path::new("accounts").join(&self.account_id).join(filename))
            .map_err(CredentialStoreError::io)
    }

    #[allow(dead_code)]
    fn read_slot(&self, slot: CredentialSlot) -> StoreResult<Option<StoredCredential>> {
        match slot {
            CredentialSlot::Token => self.read_kind(CredentialRefKind::OauthAccessToken),
            CredentialSlot::Document => self.read_document(),
        }
    }
}

impl CredentialStore {
    fn mutation_capability(&self) -> StoreResult<&AccountStoreCapability> {
        self.capability
            .as_ref()
            .ok_or(CredentialStoreError::InvalidInput {
                message: "credential mutation requires a sealed state transaction permit",
            })
    }

    fn artifact_locator(&self, name: &str) -> StoreResult<SafeRelativePath> {
        self.mutation_capability()?
            .locator(name)
            .map_err(CredentialStoreError::io)
    }

    #[allow(dead_code)]
    pub(crate) fn restore_reconcile(&self, token: ReconcileToken) -> StoreResult<RestoreReceipt> {
        self.restore(PublishedCredentialTxn {
            inner: *token.inner,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn finalize_reconcile(
        &self,
        token: ReconcileToken,
        receipt: &StateCommitReceipt,
    ) -> StoreResult<()> {
        self.finalize(
            PublishedCredentialTxn {
                inner: *token.inner,
            },
            receipt,
        )
    }

    /// Recover every fixed journal currently present for this account after a
    /// process restart. The sealed authority derives the state reference and
    /// decides whether a known live layout is rolled back or finalized;
    /// legacy authority can only roll back.
    pub(crate) fn recover_pending(&self, authority: RecoveryAuthority) -> StoreResult<()> {
        match authority {
            RecoveryAuthority::Current(proof) => self.recover_pending_with_current(&proof),
            RecoveryAuthority::Legacy(proof) => {
                if proof.revision()
                    != self
                        .base_revision
                        .as_ref()
                        .ok_or(CredentialStoreError::InvalidInput {
                            message: "legacy recovery store has no base state revision",
                        })?
                {
                    return Err(CredentialStoreError::Conflict {
                        message: "legacy recovery proof revision differs from credential permit",
                    });
                }
                self.recover_pending_legacy()
            }
        }
    }

    fn recover_pending_with_current(&self, proof: &CurrentCredentialRefProof) -> StoreResult<()> {
        self.recover_pending_inner(Some(proof))
    }

    fn recover_pending_legacy(&self) -> StoreResult<()> {
        self.recover_pending_inner(None)
    }

    fn recover_pending_inner(&self, proof: Option<&CurrentCredentialRefProof>) -> StoreResult<()> {
        // A current proof is the sole source of the state reference. Legacy
        // recovery intentionally has no reference authority and can only
        // restore/rollback.
        let state_ref = proof.and_then(|proof| proof.credential_ref(&self.account_id));
        // 账号目录不存在 = 没有 journal、没有 stage，也就没有任何可恢复的东西。
        // 真实 v1 状态里凭据只内嵌在 state.json，accounts/ 可能整个都不存在；
        // 让路径解析错误冒出去会让恢复（进而让每条命令）无条件失败。
        if !account_dir_present(&self.state_dir, &self.account_id)? {
            return Ok(());
        }
        let capability = self.mutation_capability()?.clone();
        let artifacts = match capability.artifact_locators() {
            Ok(artifacts) => artifacts,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(error) => return Err(CredentialStoreError::io(error)),
        };
        let journals: Vec<_> = artifacts
            .iter()
            .filter(|locator| {
                locator
                    .as_path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(JOURNAL_SUFFIX))
            })
            .cloned()
            .collect();
        if journals.is_empty() {
            let lock = self.acquire_lock()?;
            let result = cleanup_orphan_updates(&capability)
                .and_then(|()| cleanup_orphan_stages(&capability));
            drop(lock);
            return result;
        }
        let lock = self.acquire_lock()?;
        cleanup_orphan_updates(&capability)?;
        cleanup_orphan_stages(&capability)?;
        for journal_locator in journals {
            let staged = self.rebuild_staged_from_journal(
                &capability,
                &journal_locator,
                lock.try_clone().map_err(CredentialStoreError::reconcile)?,
            )?;
            if proof.is_none()
                && self
                    .base_revision
                    .as_ref()
                    .is_some_and(|revision| revision != &staged.base_revision)
            {
                return Err(CredentialStoreError::Conflict {
                    message: "legacy recovery journal base revision differs from state permit",
                });
            }
            let current = self.read_layout()?;
            let before = staged.baseline.clone();
            let after = staged.published.clone();
            let before_ref = staged.before_ref.clone();
            let after_ref = staged.after_ref.clone();
            if let Some(proof) = proof {
                if !recovery_revision_compatible(proof.revision(), &staged.base_revision) {
                    return Err(CredentialStoreError::Conflict {
                        message: "credential recovery proof revision differs from journal base",
                    });
                }
                if state_ref != proof.credential_ref(&self.account_id) {
                    return Err(CredentialStoreError::Conflict {
                        message: "credential recovery state reference conflicts with sealed proof",
                    });
                }
            }
            if current == before {
                if state_ref == before_ref.as_ref() {
                    self.restore(PublishedCredentialTxn { inner: staged })?;
                } else {
                    return Err(CredentialStoreError::Conflict {
                        message: "credential recovery before-layout conflicts with state reference",
                    });
                }
                continue;
            }
            if current == after {
                if let Some(proof) = proof {
                    let current_ref = proof.credential_ref(&self.account_id);
                    if current_ref == after_ref.as_ref() {
                        self.finalize_recovered(staged, proof)?;
                    } else if current_ref == before_ref.as_ref() {
                        self.restore(PublishedCredentialTxn { inner: staged })?;
                    } else {
                        return Err(CredentialStoreError::Conflict {
                            message: "credential recovery state reference conflicts with journal",
                        });
                    }
                } else {
                    // Legacy/missing recovery has no authority to finalize a
                    // post-publish layout. Its only safe action is rollback.
                    self.restore(PublishedCredentialTxn { inner: staged })?;
                }
                continue;
            }
            if proof.is_none() || state_ref == before_ref.as_ref() {
                self.restore(PublishedCredentialTxn { inner: staged })?;
            } else {
                return Err(CredentialStoreError::Conflict {
                    message: "credential recovery live layout is not a known transaction state",
                });
            }
        }
        Ok(())
    }

    fn finalize_recovered(
        &self,
        staged: StagedCredential,
        proof: &CurrentCredentialRefProof,
    ) -> StoreResult<()> {
        self.ensure_staged_store(&staged)?;
        let _held_lock = &staged.lock;
        if !recovery_is_committed_revision(proof.revision(), &staged.base_revision)
            || proof.credential_ref(&self.account_id) != staged.after_ref.as_ref()
        {
            return Err(reconcile_published(
                staged,
                CredentialStoreError::Conflict {
                    message: "sealed current-state proof does not match credential journal",
                },
            ));
        }
        let current = match self.read_layout() {
            Ok(current) => current,
            Err(error) => return Err(reconcile_published(staged, error)),
        };
        if let Err(error) = ensure_layout_equal(&staged.published, &current) {
            return Err(reconcile_published(staged, error));
        }
        match self.cleanup_unlocked(&staged) {
            Ok(()) => Ok(()),
            Err(error) => Err(reconcile_published(staged, error)),
        }
    }

    fn rebuild_staged_from_journal(
        &self,
        capability: &AccountStoreCapability,
        journal_locator: &SafeRelativePath,
        lock: File,
    ) -> StoreResult<StagedCredential> {
        let journal = read_journal(capability, journal_locator)?;
        let txid = Uuid::parse_str(&journal.txid).map_err(|_| CredentialStoreError::Corrupt {
            message: "credential journal transaction id is invalid",
        })?;
        let stage = capability
            .locator(&journal.stage)
            .map_err(CredentialStoreError::reconcile)?;
        let published = layout_from_journal_after(self, capability, &journal, &stage)?;
        let baseline = layout_from_journal_before(self, capability, &journal)?;
        // 两侧布局都为空 = 清退事务；它没有目标槽位，恢复时只需回放/清理 journal。
        let purge = published.token.is_none()
            && published.document.is_none()
            && baseline.token.is_none()
            && baseline.document.is_none();
        let kind = if published.token.is_some() {
            CredentialRefKind::OauthAccessToken
        } else if let Some(document) = &published.document {
            document.kind
        } else if let Some(token) = &baseline.token {
            token.kind
        } else if let Some(document) = &baseline.document {
            document.kind
        } else if purge && journal.after_ref.is_none() {
            CredentialRefKind::OauthAccessToken
        } else {
            return Err(CredentialStoreError::Corrupt {
                message: "credential journal has no credential transition slot",
            });
        };
        let identity = published
            .slot(slot_for_kind(kind))
            .or_else(|| baseline.slot(slot_for_kind(kind)));
        if identity.is_none() && !purge {
            return Err(CredentialStoreError::Corrupt {
                message: "credential journal target slot is missing",
            });
        }
        let staged = StagedCredential {
            store: self.clone(),
            lock,
            txid,
            target: capability
                .locator(target_filename(kind))
                .map_err(CredentialStoreError::reconcile)?,
            stage,
            kind,
            fingerprint: identity
                .map(|identity| identity.credential.fingerprint())
                .unwrap_or_default(),
            material_digest: match identity {
                Some(identity) if journal.after_ref.is_some() => identity.material_digest.clone(),
                // A delete stages the old bytes as bounded evidence; the
                // journal's stage digest identifies those bytes.  A purge has
                // no bytes at all and carries the empty digest.
                _ => journal.stage_digest.clone(),
            },
            baseline,
            published,
            deleting: journal.after.token.is_none() && journal.after.document.is_none(),
            base_revision: journal.base_revision.to_revision()?,
            before_ref: journal.before_ref.clone(),
            after_ref: journal.after_ref.clone(),
            token_backup: journal
                .token_backup
                .as_deref()
                .map(|name| capability.locator(name))
                .transpose()
                .map_err(CredentialStoreError::reconcile)?,
            document_backup: journal
                .document_backup
                .as_deref()
                .map(|name| capability.locator(name))
                .transpose()
                .map_err(CredentialStoreError::reconcile)?,
            token_tombstone: capability
                .locator(&journal.token_tombstone)
                .map_err(CredentialStoreError::reconcile)?,
            document_tombstone: capability
                .locator(&journal.document_tombstone)
                .map_err(CredentialStoreError::reconcile)?,
            journal: journal_locator.clone(),
        };
        validate_journal(&staged, &journal)?;
        Ok(staged)
    }

    #[cfg(test)]
    fn test_mutable(state_dir: &Path, account_id: &str) -> StoreResult<Self> {
        validate_account_id(account_id).map_err(|_| CredentialStoreError::InvalidInput {
            message: "account id is not a safe path component",
        })?;
        let normalized =
            NormalizedStoreRoot::normalize(state_dir).map_err(CredentialStoreError::io)?;
        let read_root = normalized.clone();
        let owned = OwnedStoreRoot::claim(normalized).map_err(CredentialStoreError::io)?;
        let target =
            SafeRelativePath::new(Path::new("state.json")).map_err(CredentialStoreError::io)?;
        let atomic = AtomicStore::new(owned, target).map_err(CredentialStoreError::io)?;
        let guard = atomic
            .lock_exact(None)
            .map_err(|error| CredentialStoreError::io(anyhow!(error)))?;
        let capability = guard
            .account_capability(account_id)
            .map_err(CredentialStoreError::io)?;
        drop(guard);
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            account_id: account_id.to_string(),
            account_dir: account_dir(state_dir, account_id),
            normalized_root: Some(read_root),
            capability: Some(capability),
            mode: CredentialStoreMode::Migration,
            base_revision: Some(Revision {
                generation: RevisionGeneration::Missing,
                document_sha256: None,
            }),
            before_ref: None,
        })
    }
}

fn parse_document_bytes(
    store: &CredentialStore,
    _target: SafeRelativePath,
    bytes: Vec<u8>,
) -> StoreResult<Option<StoredCredential>> {
    let credential = PortableCredential::from_native_json_str(
        std::str::from_utf8(&bytes)
            .map_err(|_| CredentialStoreError::Corrupt {
                message: "credential JSON is not UTF-8",
            })?
            .trim(),
    )?;
    if credential.kind() == CredentialKind::OAuthAccessToken {
        return Err(CredentialStoreError::Corrupt {
            message: "raw OAuth token must use the fixed token file",
        });
    }
    Ok(Some(StoredCredential {
        kind: credential_ref_kind(credential.kind()),
        credential,
        material_digest: material_digest(&bytes),
        path: store.account_dir.join(CREDENTIALS_FILENAME),
        bytes,
    }))
}

fn capability_root_path(capability: &AccountStoreCapability) -> StoreResult<PathBuf> {
    Ok(capability.root_path().to_path_buf())
}

impl StagedCredential {
    pub fn txid(&self) -> Uuid {
        self.txid
    }

    pub fn kind(&self) -> CredentialRefKind {
        self.kind
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn material_digest(&self) -> &str {
        &self.material_digest
    }

    pub fn previous_digest(&self) -> Option<&str> {
        self.baseline
            .slot(slot_for_kind(self.kind))
            .map(|stored| stored.material_digest.as_str())
    }

    pub fn target_path(&self) -> PathBuf {
        self.store.account_dir.join(target_filename(self.kind))
    }

    fn tombstone(&self, slot: CredentialSlot) -> &SafeRelativePath {
        match slot {
            CredentialSlot::Token => &self.token_tombstone,
            CredentialSlot::Document => &self.document_tombstone,
        }
    }

    fn journal(&self) -> &SafeRelativePath {
        &self.journal
    }
}

/// A read-only plan for migrating legacy runtime state to credential refs.
#[derive(Debug, Clone, PartialEq)]
pub struct MigrationPlan {
    pub entries: Vec<MigrationEntry>,
    /// 无法迁移的账号。为什么保留而不是直接报错：只要有一个坏账号，
    /// 旧实现就会让整笔 v1->v2 迁移失败，用户连 `sagy rm` 都用不了（MIG-001）。
    pub skipped: Vec<MigrationSkip>,
}

/// One legacy account that carries no migratable credential material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSkip {
    pub account_id: String,
    pub email: String,
    /// ASCII-only reason shown to the user.
    pub reason: String,
}

#[derive(Clone, PartialEq)]
pub struct MigrationEntry {
    pub account_id: String,
    pub credential: PortableCredential,
    pub credential_ref: CredentialRef,
    pub material_digest: String,
    material: Vec<u8>,
}

impl MigrationEntry {
    /// Return the exact bounded bytes selected by the migration planner.  A
    /// pre-existing credential file is carried byte-for-byte when no merge is
    /// required; callers use these bytes for stage/publish rather than
    /// reserializing and dropping provider-specific fields or formatting.
    pub(crate) fn material(&self) -> &[u8] {
        &self.material
    }
}

impl fmt::Debug for MigrationEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationEntry")
            .field("account_id", &self.account_id)
            .field("credential", &self.credential)
            .field("credential_ref", &self.credential_ref)
            .field("material_digest", &self.material_digest)
            .finish()
    }
}

/// Pure planner for v1 state.  It never uses `AccountRecord.auth_path` and
/// never creates, chmods, stages or deletes any filesystem item.
pub struct MigrationPlanner;

impl MigrationPlanner {
    pub fn plan(state_dir: &Path, state: &State) -> StoreResult<MigrationPlan> {
        let mut entries = Vec::with_capacity(state.accounts.len());
        let mut skipped = Vec::new();
        for account in &state.accounts {
            match plan_account(state_dir, account) {
                Ok(entry) => entries.push(entry),
                // 只有"这份账号本身没有可迁移凭据"才降级为 skip；环境类错误
                // （I/O、并发冲突）仍必须上抛，否则会把临时故障误判成数据损坏。
                Err(error) if unmigratable_reason(&error).is_some() => {
                    let reason = unmigratable_reason(&error).unwrap_or("unknown reason");
                    skipped.push(MigrationSkip {
                        account_id: account.id.clone(),
                        email: account.email.clone(),
                        reason: reason.to_string(),
                    });
                }
                Err(error) => return Err(error),
            }
        }
        Ok(MigrationPlan { entries, skipped })
    }
}

/// Classify a planner error as "this account cannot be migrated" and return an
/// ASCII reason, or `None` when the error is environmental and must abort.
fn unmigratable_reason(error: &CredentialStoreError) -> Option<&'static str> {
    match error {
        CredentialStoreError::NotFound { .. } => Some("no credential material was found"),
        CredentialStoreError::Corrupt { message } => Some(message),
        CredentialStoreError::InvalidInput { message } => Some(message),
        CredentialStoreError::Credential(_) => Some("credential material could not be parsed"),
        CredentialStoreError::Mismatch { .. } => Some("stored credential does not match its state"),
        _ => None,
    }
}

fn plan_account(state_dir: &Path, account: &AccountRecord) -> StoreResult<MigrationEntry> {
    validate_account_id(&account.id).map_err(|_| CredentialStoreError::InvalidInput {
        message: "v1 state contains an unsafe account id",
    })?;
    let store = CredentialStore::new(state_dir, &account.id)?;
    // 真实的 v1 布局里账号目录可能根本不存在（凭据只内嵌在 state.json 里），
    // 此时把两个槽位都视为空，而不是让路径解析错误炸掉整笔迁移。
    let (raw, document) = if account_dir_present(state_dir, &account.id)? {
        (
            store.read_kind(CredentialRefKind::OauthAccessToken)?,
            store.read_document()?,
        )
    } else {
        (None, None)
    };
    let raw_original = raw.clone();
    let document_original = document.clone();
    let authorized = document
        .as_ref()
        .filter(|stored| stored.kind == CredentialRefKind::OauthAuthorizedUser)
        .cloned();
    let api = document
        .as_ref()
        .filter(|stored| stored.kind == CredentialRefKind::ApiKey)
        .cloned();
    let vertex = document
        .as_ref()
        .filter(|stored| stored.kind == CredentialRefKind::VertexServiceAccount)
        .cloned();

    let credential = match account.account_type {
        AccountType::OAuth => {
            if api.is_some() || vertex.is_some() {
                return Err(CredentialStoreError::Corrupt {
                    message: "OAuth account has a non-OAuth credential file",
                });
            }
            match (authorized, raw) {
                (Some(authorized), Some(raw)) => authorized
                    .credential
                    .with_access_token(raw.credential.access_token().unwrap_or_default())?,
                (Some(authorized), None) => {
                    if let Some(token) = nonempty_embedded(&account.oauth_token) {
                        authorized.credential.with_access_token(token)?
                    } else {
                        authorized.credential
                    }
                }
                (None, Some(raw)) => {
                    if account
                        .refresh_token
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        return Err(CredentialStoreError::Corrupt {
                            message: "isolated refresh token has no complete authorized-user document",
                        });
                    }
                    raw.credential
                }
                (None, None) => {
                    let token = nonempty_embedded(&account.oauth_token).ok_or(
                        CredentialStoreError::NotFound {
                            kind: CredentialRefKind::OauthAccessToken,
                        },
                    )?;
                    if account
                        .refresh_token
                        .as_deref()
                        .is_some_and(|value| !value.trim().is_empty())
                    {
                        return Err(CredentialStoreError::Corrupt {
                            message: "isolated refresh token has no complete authorized-user document",
                        });
                    }
                    PortableCredential::oauth_access_token(token)?
                }
            }
        }
        AccountType::ApiKey => {
            if raw.is_some() || authorized.is_some() || vertex.is_some() {
                return Err(CredentialStoreError::Corrupt {
                    message: "API account has a non-API credential file",
                });
            }
            if let Some(api) = api {
                api.credential
            } else {
                let key =
                    nonempty_embedded(&account.api_key).ok_or(CredentialStoreError::NotFound {
                        kind: CredentialRefKind::ApiKey,
                    })?;
                PortableCredential::api_key(key)?
            }
        }
        AccountType::Vertex => {
            if raw.is_some() || authorized.is_some() || api.is_some() {
                return Err(CredentialStoreError::Corrupt {
                    message: "Vertex account has a non-Vertex credential file",
                });
            }
            let vertex = vertex.ok_or(CredentialStoreError::NotFound {
                kind: CredentialRefKind::VertexServiceAccount,
            })?;
            vertex.credential
        }
    };

    let material = raw_original
        .as_ref()
        .filter(|stored| stored.credential == credential)
        .map(|stored| stored.bytes.clone())
        .or_else(|| {
            document_original
                .as_ref()
                .filter(|stored| stored.credential == credential)
                .map(|stored| stored.bytes.clone())
        })
        .unwrap_or(material_bytes(&credential)?);
    let digest = material_digest(&material);

    let credential_ref = CredentialRef {
        kind: credential_ref_kind(credential.kind()),
        fingerprint: credential.fingerprint(),
    };
    Ok(MigrationEntry {
        account_id: account.id.clone(),
        credential,
        credential_ref,
        material_digest: digest,
        material,
    })
}

/// Pick a free quarantine filename for `filename`.
///
/// 为什么要唯一化：固定目标名一旦已存在（用户按提示手工把凭据恢复回
/// `credentials.json` 后重跑），`move_file` 直接 "destination already exists"
/// 硬失败，把恢复动作变成又一次故障。名字仍带 `QUARANTINE_PREFIX` 前缀，
/// 只在冲突时追加一个有界序号，避免恶意目录让隔离无限循环。
fn quarantine_destination(
    capability: &AccountStoreCapability,
    filename: &str,
) -> StoreResult<SafeRelativePath> {
    for index in 0..=QUARANTINE_MAX_SUFFIX {
        let candidate = if index == 0 {
            format!("{QUARANTINE_PREFIX}{filename}")
        } else {
            format!("{QUARANTINE_PREFIX}{index}.{filename}")
        };
        let locator = capability
            .locator(&candidate)
            .map_err(CredentialStoreError::io)?;
        if capability
            .inspect(&locator, true)
            .map_err(CredentialStoreError::io)?
            .is_none()
        {
            return Ok(locator);
        }
    }
    // 只说 "names are exhausted" 的话，用户面对的是"每条命令都失败且不知道
    // 动哪个文件"。必须指名道姓地给出目录与文件类别，才有可执行的下一步。
    Err(CredentialStoreError::Conflict {
        // 这些文件是仅存的凭据副本, 删掉就再也拿不回来了 -- 指引只能建议
        // "移走归档", 不能建议删除。
        message: "quarantine destination names are exhausted; move the existing \
`.sagy-credential-quarantine.*` files under `<state dir>/accounts/<account id>/` to a \
backup location outside the state directory, then rerun. Do not delete them: they are \
the only remaining copies of those credentials",
    })
}

/// Report whether `accounts/<id>` exists as a real directory.
///
/// 必须 fail-closed：裸 `is_dir()` 判断会把"这个位置是符号链接或普通文件"
/// 这类异常静默降级成"目录不存在"，于是账号的两个凭据槽都被当成空的，
/// 迁移/恢复照常继续，真实凭据被无声跳过。存在但不是目录属于环境异常，
/// 必须上抛（`unmigratable_reason` 不会把它降级成 skip）。
fn account_dir_present(state_dir: &Path, account_id: &str) -> StoreResult<bool> {
    let path = state_dir.join("accounts").join(account_id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(CredentialStoreError::io(anyhow!(
            "account credential path is not a directory: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CredentialStoreError::io(error)),
    }
}

fn nonempty_embedded(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn expected_slot(stored: Option<&StoredCredential>) -> ExpectedSlot {
    stored
        .map(|stored| ExpectedSlot::Exact {
            kind: stored.kind,
            fingerprint: stored.credential.fingerprint(),
            material_digest: stored.material_digest.clone(),
        })
        .unwrap_or(ExpectedSlot::Absent)
}

fn ensure_layout_expected(expected: &ExpectedLayout, actual: &CredentialLayout) -> StoreResult<()> {
    ensure_slot_expected(
        &expected.token,
        CredentialSlot::Token,
        actual.token.as_ref(),
    )?;
    ensure_slot_expected(
        &expected.document,
        CredentialSlot::Document,
        actual.document.as_ref(),
    )?;
    Ok(())
}

fn ensure_slot_expected(
    expected: &ExpectedSlot,
    slot: CredentialSlot,
    actual: Option<&StoredCredential>,
) -> StoreResult<()> {
    match expected {
        ExpectedSlot::Absent => {
            if actual.is_some() {
                return Err(CredentialStoreError::Conflict {
                    message: "expected credential slot to be absent",
                });
            }
        }
        ExpectedSlot::Exact {
            kind,
            fingerprint,
            material_digest,
        } => {
            let Some(actual) = actual else {
                return Err(CredentialStoreError::Conflict {
                    message: "expected credential slot is absent",
                });
            };
            let kind_matches = match slot {
                CredentialSlot::Token => *kind == CredentialRefKind::OauthAccessToken,
                CredentialSlot::Document => {
                    matches!(
                        kind,
                        CredentialRefKind::OauthAuthorizedUser
                            | CredentialRefKind::ApiKey
                            | CredentialRefKind::VertexServiceAccount
                    )
                }
            };
            if !kind_matches
                || actual.kind != *kind
                || actual.credential.fingerprint() != *fingerprint
                || actual.material_digest != *material_digest
            {
                return Err(CredentialStoreError::Mismatch {
                    expected_kind: Some(*kind),
                    actual_kind: Some(actual.kind),
                    expected_fingerprint: Some(fingerprint.clone()),
                    actual_fingerprint: Some(actual.credential.fingerprint()),
                    expected_material_digest: Some(material_digest.clone()),
                    actual_material_digest: Some(actual.material_digest.clone()),
                });
            }
        }
    }
    Ok(())
}

fn ensure_layout_equal(expected: &CredentialLayout, actual: &CredentialLayout) -> StoreResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(CredentialStoreError::Conflict {
            message: "credential layout changed after staging",
        })
    }
}

fn slot_for_kind(kind: CredentialRefKind) -> CredentialSlot {
    match kind {
        CredentialRefKind::OauthAccessToken => CredentialSlot::Token,
        CredentialRefKind::OauthAuthorizedUser
        | CredentialRefKind::ApiKey
        | CredentialRefKind::VertexServiceAccount => CredentialSlot::Document,
    }
}

fn layout_after_opposite_move(staged: &StagedCredential, current: &CredentialLayout) -> bool {
    let published_slot = slot_for_kind(staged.kind);
    let opposite = published_slot.opposite();
    current.slot(published_slot) == staged.published.slot(published_slot)
        && current.slot(opposite).is_none()
}

fn layout_after_only_move(staged: &StagedCredential, current: &CredentialLayout) -> bool {
    let published_slot = slot_for_kind(staged.kind);
    let opposite = published_slot.opposite();
    current.slot(published_slot) == staged.baseline.slot(published_slot)
        && current.slot(opposite).is_none()
        && staged.baseline.slot(opposite).is_some()
}

fn reference_kind(kind: CredentialRefKind) -> CredentialRefKind {
    kind
}

fn credential_ref_kind(kind: CredentialKind) -> CredentialRefKind {
    match kind {
        CredentialKind::OAuthAccessToken => CredentialRefKind::OauthAccessToken,
        CredentialKind::OAuthAuthorizedUser => CredentialRefKind::OauthAuthorizedUser,
        CredentialKind::ApiKey => CredentialRefKind::ApiKey,
        CredentialKind::VertexServiceAccount => CredentialRefKind::VertexServiceAccount,
    }
}

fn credential_kind(kind: CredentialRefKind) -> CredentialKind {
    match kind {
        CredentialRefKind::OauthAccessToken => CredentialKind::OAuthAccessToken,
        CredentialRefKind::OauthAuthorizedUser => CredentialKind::OAuthAuthorizedUser,
        CredentialRefKind::ApiKey => CredentialKind::ApiKey,
        CredentialRefKind::VertexServiceAccount => CredentialKind::VertexServiceAccount,
    }
}

fn parse_material(kind: CredentialRefKind, bytes: &[u8]) -> StoreResult<PortableCredential> {
    if bytes.is_empty() {
        return Err(CredentialStoreError::Corrupt {
            message: "credential file is empty",
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CredentialStoreError::Corrupt {
        message: "credential file is not UTF-8",
    })?;
    let credential = match kind {
        CredentialRefKind::OauthAccessToken => PortableCredential::oauth_access_token(text.trim())?,
        CredentialRefKind::OauthAuthorizedUser
        | CredentialRefKind::ApiKey
        | CredentialRefKind::VertexServiceAccount => {
            PortableCredential::from_native_json_str(text.trim())?
        }
    };
    if credential_ref_kind(credential.kind()) != kind {
        return Err(CredentialStoreError::Mismatch {
            expected_kind: Some(kind),
            actual_kind: Some(credential_ref_kind(credential.kind())),
            expected_fingerprint: None,
            actual_fingerprint: Some(credential.fingerprint()),
            expected_material_digest: None,
            actual_material_digest: Some(material_digest(bytes)),
        });
    }
    Ok(credential)
}

fn material_bytes(credential: &PortableCredential) -> StoreResult<Vec<u8>> {
    match credential.kind() {
        CredentialKind::OAuthAccessToken => Ok(credential
            .access_token()
            .ok_or(CredentialStoreError::InvalidInput {
                message: "raw OAuth credential has no access token",
            })?
            .as_bytes()
            .to_vec()),
        _ => Ok(credential.to_native_json_string()?.into_bytes()),
    }
}

fn material_digest(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("sha256:{:x}", digest.finalize())
}

fn validate_document_digest(value: &str) -> anyhow::Result<()> {
    if value.len() != 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_hexdigit() && byte.is_ascii_lowercase())
        })
    {
        bail!("digest must be lowercase SHA-256");
    }
    Ok(())
}

/// Inspect a normalized credential locator while treating a missing
/// intermediate directory as an absent account.  The generic bounded reader
/// intentionally rejects missing parents; pure credential reads need the
/// slightly different absent-account semantics while retaining its
/// no-follow handle for the actual bytes.
fn inspect_normalized_credential_file(
    root: &NormalizedStoreRoot,
    relative: &SafeRelativePath,
) -> StoreResult<Option<std::fs::Metadata>> {
    let mut current = root.as_path().to_path_buf();
    let components: Vec<_> = relative.as_path().components().collect();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(value) = component else {
            return Err(CredentialStoreError::InvalidInput {
                message: "credential locator contains an unsafe path component",
            });
        };
        current.push(value);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(CredentialStoreError::io(error)),
        };
        if is_link_or_reparse(&metadata) {
            return Err(CredentialStoreError::Corrupt {
                message: "credential path cannot contain a symlink or reparse point",
            });
        }
        if index + 1 == components.len() {
            if !metadata.is_file() {
                return Err(CredentialStoreError::Corrupt {
                    message: "credential path is not a regular file",
                });
            }
            return Ok(Some(metadata));
        }
        if !metadata.is_dir() {
            return Err(CredentialStoreError::Corrupt {
                message: "credential path contains a non-directory component",
            });
        }
    }
    Ok(None)
}

fn write_evidence(
    capability: &AccountStoreCapability,
    path: &SafeRelativePath,
    bytes: &[u8],
) -> StoreResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(CredentialStoreError::InvalidInput {
            message: "credential evidence is empty or oversized",
        });
    }
    let mut file = capability
        .create_new(path)
        .map_err(CredentialStoreError::not_applied)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| CredentialStoreError::reconcile(anyhow!(error)))?;
    capability
        .sync_parent(path)
        .map_err(CredentialStoreError::reconcile)?;
    Ok(())
}

fn artifact_name(path: &SafeRelativePath) -> StoreResult<String> {
    path.as_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(ToString::to_string)
        .ok_or(CredentialStoreError::InvalidInput {
            message: "credential journal locator is not a safe filename",
        })
}

fn journal_descriptor(stored: Option<&StoredCredential>) -> Option<JournalDescriptor> {
    stored.map(|stored| JournalDescriptor {
        kind: stored.kind,
        fingerprint: stored.credential.fingerprint(),
        material_digest: stored.material_digest.clone(),
    })
}

fn journal_layout(layout: &CredentialLayout) -> JournalLayout {
    JournalLayout {
        token: journal_descriptor(layout.token.as_ref()),
        document: journal_descriptor(layout.document.as_ref()),
    }
}

fn layout_reference(layout: &CredentialLayout) -> Option<CredentialRef> {
    match (&layout.token, &layout.document) {
        (Some(token), None) => Some(CredentialRef {
            kind: token.kind,
            fingerprint: token.credential.fingerprint(),
        }),
        (None, Some(document)) => Some(CredentialRef {
            kind: document.kind,
            fingerprint: document.credential.fingerprint(),
        }),
        _ => None,
    }
}

fn recovery_revision_compatible(current: &Revision, base: &Revision) -> bool {
    if current.document_sha256.is_none()
        || !matches!(current.generation, RevisionGeneration::Current(_))
    {
        return false;
    }
    match (base.generation, current.generation) {
        (
            RevisionGeneration::Missing | RevisionGeneration::Legacy,
            RevisionGeneration::Current(1),
        ) => true,
        (RevisionGeneration::Current(base), RevisionGeneration::Current(current)) => {
            current == base || current == base.saturating_add(1)
        }
        _ => false,
    }
}

fn recovery_is_committed_revision(current: &Revision, base: &Revision) -> bool {
    match (base.generation, current.generation) {
        (
            RevisionGeneration::Missing | RevisionGeneration::Legacy,
            RevisionGeneration::Current(1),
        ) => true,
        (RevisionGeneration::Current(base), RevisionGeneration::Current(current)) => {
            current == base.saturating_add(1)
        }
        _ => false,
    }
}

fn layout_from_journal_after(
    store: &CredentialStore,
    capability: &AccountStoreCapability,
    journal: &CredentialJournal,
    stage: &SafeRelativePath,
) -> StoreResult<CredentialLayout> {
    if journal.after.token.is_none() && journal.after.document.is_none() {
        return Ok(CredentialLayout {
            token: None,
            document: None,
        });
    }
    // Once publish replaces the target, the stage path is consumed.  On a
    // restart the durable after bytes therefore come from the fixed live slot;
    // before target replacement the stage remains the only after evidence.
    let staged_bytes = capability
        .read_bounded(stage, MAX_CREDENTIAL_FILE_BYTES)
        .map_err(CredentialStoreError::reconcile)?;
    let bytes = if let Some(bytes) = staged_bytes {
        bytes
    } else {
        let target_name = if journal.after.token.is_some() {
            TOKEN_FILENAME
        } else if journal.after.document.is_some() {
            CREDENTIALS_FILENAME
        } else {
            return Err(CredentialStoreError::Corrupt {
                message: "credential journal after layout has no target slot",
            });
        };
        let target = capability
            .locator(target_name)
            .map_err(CredentialStoreError::reconcile)?;
        capability
            .read_bounded(&target, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(CredentialStoreError::reconcile)?
            .ok_or(CredentialStoreError::ReconcileRequired {
                source: anyhow!("credential journal stage and published target are missing"),
                token: None,
            })?
    };
    let mut result = CredentialLayout {
        token: None,
        document: None,
    };
    if journal.after.token.is_some() && journal.after.document.is_some() {
        return Err(CredentialStoreError::Corrupt {
            message: "credential journal after layout contains two live slots",
        });
    }
    if let Some(descriptor) = &journal.after.token {
        result.token = Some(stored_from_descriptor(
            store,
            CredentialSlot::Token,
            descriptor,
            &bytes,
        )?);
    }
    if let Some(descriptor) = &journal.after.document {
        result.document = Some(stored_from_descriptor(
            store,
            CredentialSlot::Document,
            descriptor,
            &bytes,
        )?);
    }
    Ok(result)
}

fn layout_from_journal_before(
    store: &CredentialStore,
    capability: &AccountStoreCapability,
    journal: &CredentialJournal,
) -> StoreResult<CredentialLayout> {
    let mut result = CredentialLayout {
        token: None,
        document: None,
    };
    if let Some(descriptor) = &journal.before.token {
        let locator = journal
            .token_backup
            .as_deref()
            .or(Some(journal.token_tombstone.as_str()))
            .ok_or(CredentialStoreError::Corrupt {
                message: "credential journal token baseline locator is missing",
            })?;
        let bytes = capability
            .read_bounded(
                &capability
                    .locator(locator)
                    .map_err(CredentialStoreError::reconcile)?,
                MAX_CREDENTIAL_FILE_BYTES,
            )
            .map_err(CredentialStoreError::reconcile)?
            .ok_or(CredentialStoreError::ReconcileRequired {
                source: anyhow!("credential journal token baseline evidence is missing"),
                token: None,
            })?;
        result.token = Some(stored_from_descriptor(
            store,
            CredentialSlot::Token,
            descriptor,
            &bytes,
        )?);
    }
    if let Some(descriptor) = &journal.before.document {
        let locator = journal
            .document_backup
            .as_deref()
            .or(Some(journal.document_tombstone.as_str()))
            .ok_or(CredentialStoreError::Corrupt {
                message: "credential journal document baseline locator is missing",
            })?;
        let bytes = capability
            .read_bounded(
                &capability
                    .locator(locator)
                    .map_err(CredentialStoreError::reconcile)?,
                MAX_CREDENTIAL_FILE_BYTES,
            )
            .map_err(CredentialStoreError::reconcile)?
            .ok_or(CredentialStoreError::ReconcileRequired {
                source: anyhow!("credential journal document baseline evidence is missing"),
                token: None,
            })?;
        result.document = Some(stored_from_descriptor(
            store,
            CredentialSlot::Document,
            descriptor,
            &bytes,
        )?);
    }
    Ok(result)
}

fn stored_from_descriptor(
    store: &CredentialStore,
    slot: CredentialSlot,
    descriptor: &JournalDescriptor,
    bytes: &[u8],
) -> StoreResult<StoredCredential> {
    let descriptor_slot = slot_for_kind(descriptor.kind);
    if descriptor_slot != slot {
        return Err(CredentialStoreError::Corrupt {
            message: "credential journal descriptor kind does not match its slot",
        });
    }
    if material_digest(bytes) != descriptor.material_digest {
        return Err(CredentialStoreError::Mismatch {
            expected_kind: Some(descriptor.kind),
            actual_kind: Some(slot.kind()),
            expected_fingerprint: Some(descriptor.fingerprint.clone()),
            actual_fingerprint: None,
            expected_material_digest: Some(descriptor.material_digest.clone()),
            actual_material_digest: Some(material_digest(bytes)),
        });
    }
    let credential = parse_material(descriptor.kind, bytes)?;
    if credential.kind() != credential_kind(descriptor.kind)
        || credential.fingerprint() != descriptor.fingerprint
    {
        return Err(CredentialStoreError::Mismatch {
            expected_kind: Some(descriptor.kind),
            actual_kind: Some(credential_ref_kind(credential.kind())),
            expected_fingerprint: Some(descriptor.fingerprint.clone()),
            actual_fingerprint: Some(credential.fingerprint()),
            expected_material_digest: Some(descriptor.material_digest.clone()),
            actual_material_digest: Some(material_digest(bytes)),
        });
    }
    Ok(StoredCredential {
        kind: descriptor.kind,
        credential,
        material_digest: descriptor.material_digest.clone(),
        path: store.account_dir.join(target_filename(descriptor.kind)),
        bytes: bytes.to_vec(),
    })
}

fn write_journal(
    capability: &AccountStoreCapability,
    path: &SafeRelativePath,
    journal: &CredentialJournal,
) -> StoreResult<()> {
    let bytes = serde_json::to_vec(journal).map_err(|_| CredentialStoreError::Corrupt {
        message: "credential journal cannot be serialized",
    })?;
    if bytes.len() > JOURNAL_MAX_BYTES {
        return Err(CredentialStoreError::Corrupt {
            message: "credential journal exceeds the size limit",
        });
    }
    write_evidence(capability, path, &bytes)
}

fn read_journal(
    capability: &AccountStoreCapability,
    path: &SafeRelativePath,
) -> StoreResult<CredentialJournal> {
    let metadata = capability
        .inspect(path, false)
        .map_err(CredentialStoreError::reconcile)?
        .ok_or(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal is missing"),
            token: None,
        })?;
    if metadata.len() > JOURNAL_MAX_BYTES as u64 {
        return Err(CredentialStoreError::Corrupt {
            message: "credential journal exceeds the size limit",
        });
    }
    let bytes = capability
        .read_bounded(path, JOURNAL_MAX_BYTES)
        .map_err(CredentialStoreError::reconcile)?
        .ok_or(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal disappeared"),
            token: None,
        })?;
    let value =
        strict_journal_value(&bytes).map_err(|_| CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal is malformed"),
            token: None,
        })?;
    let journal: CredentialJournal =
        serde_json::from_value(value).map_err(|_| CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal is malformed"),
            token: None,
        })?;
    if journal.journal_version != JOURNAL_VERSION {
        return Err(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal version is unsupported"),
            token: None,
        });
    }
    if !matches!(
        journal.phase.as_str(),
        "prepared" | "opposite_moved" | "target_moved" | "published" | "restored"
    ) {
        return Err(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal phase is unsupported"),
            token: None,
        });
    }
    Ok(journal)
}

struct StrictJournalValue(Value);

impl<'de> Deserialize<'de> for StrictJournalValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJournalVisitor)
    }
}

struct StrictJournalVisitor;

impl<'de> Visitor<'de> for StrictJournalVisitor {
    type Value = StrictJournalValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJournalValue(Value::Number(
            serde_json::Number::from_f64(value)
                .ok_or_else(|| E::custom("non-finite JSON number"))?,
        )))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJournalValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJournalValue>()? {
            values.push(value.0);
        }
        Ok(StrictJournalValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON field: {key}")));
            }
            values.insert(key, map.next_value::<StrictJournalValue>()?.0);
        }
        Ok(StrictJournalValue(Value::Object(values)))
    }
}

fn strict_journal_value(bytes: &[u8]) -> anyhow::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJournalValue::deserialize(&mut deserializer)
        .map_err(|error| anyhow!(error).context("invalid credential journal JSON"))?
        .0;
    deserializer
        .end()
        .map_err(|error| anyhow!(error).context("trailing bytes after credential journal"))?;
    Ok(value)
}

fn validate_journal(staged: &StagedCredential, journal: &CredentialJournal) -> StoreResult<()> {
    let expected = [
        (
            "stage",
            Some(staged.stage.as_path()),
            journal.stage.as_str(),
        ),
        (
            "token backup",
            staged.token_backup.as_ref().map(SafeRelativePath::as_path),
            journal.token_backup.as_deref().unwrap_or(""),
        ),
        (
            "document backup",
            staged
                .document_backup
                .as_ref()
                .map(SafeRelativePath::as_path),
            journal.document_backup.as_deref().unwrap_or(""),
        ),
        (
            "token tombstone",
            Some(staged.token_tombstone.as_path()),
            journal.token_tombstone.as_str(),
        ),
        (
            "document tombstone",
            Some(staged.document_tombstone.as_path()),
            journal.document_tombstone.as_str(),
        ),
    ];
    if journal.txid != staged.txid.to_string()
        || expected.iter().any(|(_, path, recorded)| {
            path.and_then(|path| path.file_name())
                .and_then(|name| name.to_str())
                != (!recorded.is_empty()).then_some(*recorded)
        })
    {
        return Err(CredentialStoreError::Conflict {
            message: "credential journal locator does not match transaction evidence",
        });
    }
    if journal.before != journal_layout(&staged.baseline)
        || journal.after != journal_layout(&staged.published)
        || journal.base_revision.to_revision().ok().as_ref() != Some(&staged.base_revision)
        || journal.before_ref != staged.before_ref
        || journal.after_ref != staged.after_ref
        || journal.stage_digest != staged.material_digest
        || journal.token_backup_digest
            != staged
                .baseline
                .token
                .as_ref()
                .map(|stored| stored.material_digest.clone())
        || journal.document_backup_digest
            != staged
                .baseline
                .document
                .as_ref()
                .map(|stored| stored.material_digest.clone())
        || journal.token_tombstone_digest
            != staged
                .baseline
                .token
                .as_ref()
                .map(|stored| stored.material_digest.clone())
        || journal.document_tombstone_digest
            != staged
                .baseline
                .document
                .as_ref()
                .map(|stored| stored.material_digest.clone())
    {
        return Err(CredentialStoreError::Conflict {
            message: "credential journal layout descriptors do not match transaction",
        });
    }
    Ok(())
}

fn update_journal(
    capability: &AccountStoreCapability,
    path: &SafeRelativePath,
    journal: &CredentialJournal,
) -> StoreResult<()> {
    let name = artifact_name(path)?;
    let update = capability
        .locator(&format!(".{name}.update"))
        .map_err(CredentialStoreError::reconcile)?;
    write_journal(capability, &update, journal)?;
    capability
        .replace(&update, path)
        .map_err(map_mutation_failure)
}

/// Select the `*.stage` artifacts that no journal owns.
///
/// stage 文件先于 journal 落盘（见 `stage_exact`），所以在这个窗口崩溃会在账号目录
/// 留下永不清理的明文凭据副本。持有账号锁时，"没有同 txid 的 journal" 就等价于
/// "没有任何事务认领它"，此时删除是安全的；正在进行中的事务一定有 journal。
fn orphan_stage_names(names: &[String]) -> Vec<String> {
    let journals: std::collections::BTreeSet<&str> = names
        .iter()
        .filter_map(|name| {
            name.strip_prefix(STAGE_PREFIX)
                .and_then(|rest| rest.strip_suffix(JOURNAL_SUFFIX))
        })
        .collect();
    names
        .iter()
        .filter(|name| {
            name.strip_prefix(STAGE_PREFIX)
                .and_then(|rest| rest.strip_suffix(STAGE_SUFFIX))
                .is_some_and(|txid| {
                    Uuid::parse_str(txid).is_ok_and(|parsed| parsed.to_string() == txid)
                        && !journals.contains(txid)
                })
        })
        .cloned()
        .collect()
}

/// Detach and delete an ownerless stage that is too large to be read back
/// under the bounded-read limit.  Returns whether the stage was handled here.
///
/// 为什么不能裸 `remove`：`inspect` 与 `remove` 之间存在替换窗口，裸删有可能
/// 删掉此刻已经换成别的内容的同名文件。超限文件读不回来，没有摘要可比，所以
/// 改用"先改名独占、再复核、才删除"：
///   1. 把它改名到一个本次运行新生成的 stage 名。该名字只有我们知道，
///      改名成功即等价于"这个 inode 已经归我独占"。
///   2. 复核它此刻**仍然**超限——超限就意味着它不可能是任何合法凭据工件
///      （合法工件一律受 MAX_CREDENTIAL_FILE_BYTES 约束），这就是这条路径上
///      可获得的"我认得它"的证据。
///   3. 只有复核通过才删除。复核不通过说明我们改名的并不是刚才看到的那个
///      超限文件，此时把它改回原名，交给下面按内容精确删除的常规路径。
///
/// 崩溃在第 1 步与第 3 步之间也没有残留风险：中转名同样是一个孤儿 stage，
/// 下一次任意命令会重新走这条清理路径。
fn discard_oversized_stage(
    capability: &AccountStoreCapability,
    locator: &SafeRelativePath,
) -> StoreResult<bool> {
    let Some(metadata) = capability
        .inspect(locator, true)
        .map_err(CredentialStoreError::reconcile)?
    else {
        return Ok(false);
    };
    if metadata.len() <= MAX_CREDENTIAL_FILE_BYTES as u64 {
        return Ok(false);
    }
    let detached = capability
        .locator(&format!("{STAGE_PREFIX}{}{STAGE_SUFFIX}", Uuid::new_v4()))
        .map_err(CredentialStoreError::reconcile)?;
    capability
        .move_file(locator, &detached)
        .map_err(map_mutation_failure)?;
    let still_oversized = capability
        .inspect(&detached, true)
        .map_err(CredentialStoreError::reconcile)?
        .is_some_and(|metadata| metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64);
    if !still_oversized {
        capability
            .move_file(&detached, locator)
            .map_err(map_mutation_failure)?;
        return Ok(false);
    }
    capability.remove(&detached).map_err(map_mutation_failure)?;
    Ok(true)
}

/// Remove the ownerless plaintext stage files left by a crash between the
/// stage write and its journal write.
fn cleanup_orphan_stages(capability: &AccountStoreCapability) -> StoreResult<()> {
    let artifacts = capability
        .artifact_locators()
        .map_err(CredentialStoreError::reconcile)?;
    let names: Vec<String> = artifacts
        .iter()
        .filter_map(|locator| {
            locator
                .as_path()
                .file_name()
                .and_then(|name| name.to_str())
                .map(ToString::to_string)
        })
        .collect();
    for name in orphan_stage_names(&names) {
        let locator = capability
            .locator(&name)
            .map_err(CredentialStoreError::reconcile)?;
        // 超过 bounded read 上限的孤儿 stage 不可能是合法凭据，但按原来的路径
        // 走 `read_bounded` 会硬失败，进而让每条命令都失败——与"下一次任意命令
        // 必须清理"的目标正好相反。删除仍然必须是"只删我认得的那个文件"，
        // 而且失败必须上抛，不能 `let _ =` 吞掉（见 discard_oversized_stage）。
        if discard_oversized_stage(capability, &locator)? {
            continue;
        }
        // 没有 journal 就没有可比对的期望摘要；只按"当前内容"精确删除自己刚读到的
        // 那份字节，避免与并发写入竞争。
        let Some(bytes) = capability
            .read_bounded(&locator, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(CredentialStoreError::reconcile)?
        else {
            continue;
        };
        remove_evidence_exact(capability, &locator, Some(&material_digest(&bytes)))
            .map_err(map_remove_failure)?;
    }
    Ok(())
}

/// A failed journal replacement may leave a sibling `.update` artifact.  It
/// is evidence, not a cache: remove it only when its bytes are exactly the
/// durable journal bytes.  Any mismatch remains visible and is surfaced as a
/// conflict so recovery never silently discards forensic evidence.
fn cleanup_orphan_updates(capability: &AccountStoreCapability) -> StoreResult<()> {
    let artifacts = capability
        .artifact_locators()
        .map_err(CredentialStoreError::reconcile)?;
    for locator in artifacts {
        let Some(name) = locator.as_path().file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".journal.update") {
            continue;
        }
        let target_name = name
            .strip_prefix('.')
            .and_then(|value| value.strip_suffix(".update"))
            .ok_or(CredentialStoreError::Corrupt {
                message: "credential journal update locator is invalid",
            })?;
        let target = capability
            .locator(target_name)
            .map_err(CredentialStoreError::reconcile)?;
        let Some(target_bytes) = capability
            .read_bounded(&target, JOURNAL_MAX_BYTES)
            .map_err(CredentialStoreError::reconcile)?
        else {
            return Err(CredentialStoreError::Conflict {
                message: "orphan credential journal update has no durable target",
            });
        };
        let update_bytes = capability
            .read_bounded(&locator, JOURNAL_MAX_BYTES)
            .map_err(CredentialStoreError::reconcile)?
            .ok_or(CredentialStoreError::Conflict {
                message: "credential journal update disappeared during recovery",
            })?;
        if update_bytes != target_bytes {
            return Err(CredentialStoreError::Conflict {
                message: "credential journal update differs from durable target",
            });
        }
        remove_evidence_exact(capability, &locator, Some(&material_digest(&update_bytes)))
            .map_err(map_remove_failure)?;
    }
    Ok(())
}

#[derive(Debug)]
enum RemoveFailure {
    NotApplied(anyhow::Error),
    Reconcile(anyhow::Error),
}

fn remove_evidence_exact(
    capability: &AccountStoreCapability,
    path: &SafeRelativePath,
    expected_digest: Option<&str>,
) -> std::result::Result<(), RemoveFailure> {
    let Some(metadata) = capability
        .inspect(path, true)
        .map_err(RemoveFailure::NotApplied)?
    else {
        return Ok(());
    };
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES.max(JOURNAL_MAX_BYTES) as u64 {
        return Err(RemoveFailure::NotApplied(anyhow!(
            "credential evidence exceeds the size limit"
        )));
    }
    // Read the complete bounded evidence before deleting it. This closes the
    // common replace/race window and ensures cleanup never removes a path
    // whose type changed between validation and unlink.
    let bytes = capability
        .read_bounded(path, MAX_CREDENTIAL_FILE_BYTES.max(JOURNAL_MAX_BYTES))
        .map_err(RemoveFailure::NotApplied)?
        .ok_or_else(|| RemoveFailure::NotApplied(anyhow!("credential evidence disappeared")))?;
    let Some(expected_digest) = expected_digest else {
        return Err(RemoveFailure::NotApplied(anyhow!(
            "credential evidence has no expected digest"
        )));
    };
    if material_digest(&bytes) != expected_digest {
        return Err(RemoveFailure::NotApplied(anyhow!(
            "credential evidence digest changed before cleanup"
        )));
    }
    capability.remove(path).map_err(|error| match error {
        crate::core::atomic_io::MutationFailure::NotApplied { source } => {
            RemoveFailure::NotApplied(source)
        }
        crate::core::atomic_io::MutationFailure::ReconcileRequired { source } => {
            RemoveFailure::Reconcile(source)
        }
    })?;
    Ok(())
}

fn journal_digest(
    capability: &AccountStoreCapability,
    path: &SafeRelativePath,
) -> StoreResult<String> {
    let metadata = capability
        .inspect(path, false)
        .map_err(CredentialStoreError::reconcile)?
        .ok_or(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal disappeared"),
            token: None,
        })?;
    if metadata.len() > JOURNAL_MAX_BYTES as u64 {
        return Err(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal exceeds the size limit"),
            token: None,
        });
    }
    let bytes = capability
        .read_bounded(path, JOURNAL_MAX_BYTES)
        .map_err(CredentialStoreError::reconcile)?
        .ok_or(CredentialStoreError::ReconcileRequired {
            source: anyhow!("credential journal disappeared"),
            token: None,
        })?;
    Ok(material_digest(&bytes))
}

fn map_remove_failure(failure: RemoveFailure) -> CredentialStoreError {
    match failure {
        RemoveFailure::NotApplied(error) => CredentialStoreError::not_applied(error),
        RemoveFailure::Reconcile(error) => CredentialStoreError::reconcile(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// AC-R2-4.1: `accounts/<id>` 存在但不是目录，必须 fail-closed。
    /// 旧实现用裸 `is_dir()` 返回 bool，把这种异常降级成"目录不存在"，
    /// 于是两个凭据槽都被当成空的，账号被无声跳过。
    #[test]
    fn account_dir_present_fails_closed_on_a_non_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let accounts = temp.path().join("accounts");
        fs::create_dir_all(&accounts).expect("accounts dir");
        let account_id = "11111111-1111-4111-8111-111111111111";

        // 不存在 -> false，不报错（真实 v1 布局里凭据可能只内嵌在 state.json）。
        assert!(!account_dir_present(temp.path(), account_id).expect("absent account dir"));

        // 普通文件 -> 硬错误，不得静默跳过。
        fs::write(accounts.join(account_id), b"not-a-directory").expect("write file");
        let error = account_dir_present(temp.path(), account_id)
            .expect_err("a regular file must not be reported as an absent directory");
        assert!(
            unmigratable_reason(&error).is_none(),
            "this is an environment fault and must not be downgraded to a per-account skip"
        );

        // 真目录 -> true。
        fs::remove_file(accounts.join(account_id)).expect("remove file");
        fs::create_dir(accounts.join(account_id)).expect("create dir");
        assert!(account_dir_present(temp.path(), account_id).expect("present account dir"));
    }

    #[cfg(unix)]
    #[test]
    fn account_dir_present_fails_closed_on_a_symlinked_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let accounts = temp.path().join("accounts");
        fs::create_dir_all(&accounts).expect("accounts dir");
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("target dir");
        let account_id = "22222222-2222-4222-8222-222222222222";
        std::os::unix::fs::symlink(&elsewhere, accounts.join(account_id)).expect("symlink");
        assert!(account_dir_present(temp.path(), account_id).is_err());
    }

    #[test]
    fn orphan_stage_selection_only_targets_journal_less_stages() {
        let owned = "11111111-1111-4111-8111-111111111111";
        let live = "22222222-2222-4222-8222-222222222222";
        let names = vec![
            format!("{STAGE_PREFIX}{owned}{STAGE_SUFFIX}"),
            format!("{STAGE_PREFIX}{live}{STAGE_SUFFIX}"),
            format!("{STAGE_PREFIX}{live}{JOURNAL_SUFFIX}"),
            format!("{STAGE_PREFIX}{live}{TOKEN_BACKUP_SUFFIX}"),
            format!("{STAGE_PREFIX}{owned}{DOCUMENT_BACKUP_SUFFIX}"),
            format!("{STAGE_PREFIX}not-a-uuid{STAGE_SUFFIX}"),
            CREDENTIALS_FILENAME.to_string(),
            TOKEN_FILENAME.to_string(),
            LOCK_FILENAME.to_string(),
            "settings.json".to_string(),
        ];
        // AC-5.2: 只有"没有同 txid journal"的 stage 才是无主文件；
        // 正在进行中的事务（有 journal）以及其它任何工件都不能被误删。
        assert_eq!(
            orphan_stage_names(&names),
            vec![format!("{STAGE_PREFIX}{owned}{STAGE_SUFFIX}")]
        );
    }

    #[test]
    fn migration_plan_skips_an_account_without_credential_material() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("accounts").join("broken")).unwrap();
        let mut good = AccountRecord {
            id: "good".to_string(),
            email: "good@example.test".to_string(),
            account_type: AccountType::OAuth,
            ..AccountRecord::default()
        };
        good.oauth_token = Some("live-token".to_string());
        let broken = AccountRecord {
            id: "broken".to_string(),
            email: "broken@example.test".to_string(),
            account_type: AccountType::OAuth,
            ..AccountRecord::default()
        };
        let state = State {
            version: 1,
            accounts: vec![good, broken],
            ..State::default()
        };
        let plan = MigrationPlanner::plan(temp.path(), &state).unwrap();
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].account_id, "good");
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].account_id, "broken");
        assert_eq!(plan.skipped[0].email, "broken@example.test");
        assert!(plan.skipped[0].reason.is_ascii());
        assert!(!plan.skipped[0].reason.is_empty());
    }

    #[test]
    fn pure_read_uses_fixed_slot_and_rejects_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let account = temp.path().join("accounts").join("a-1");
        fs::create_dir_all(&account).unwrap();
        fs::write(account.join(TOKEN_FILENAME), b"token").unwrap();
        let store = CredentialStore::new(temp.path(), "a-1").unwrap();
        let reference = CredentialRef {
            kind: CredentialRefKind::OauthAccessToken,
            fingerprint: PortableCredential::oauth_access_token("token")
                .unwrap()
                .fingerprint(),
        };
        assert_eq!(
            store.read(&reference).unwrap().credential.access_token(),
            Some("token")
        );
        fs::remove_file(account.join(TOKEN_FILENAME)).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/outside", account.join(TOKEN_FILENAME)).unwrap();
        #[cfg(unix)]
        assert!(
            store
                .read_kind(CredentialRefKind::OauthAccessToken)
                .is_err()
        );
    }

    #[test]
    fn stage_publish_expected_restore_and_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let token = PortableCredential::oauth_access_token("first-token").unwrap();
        let staged = store.stage(Uuid::new_v4(), &token).unwrap();
        let published = store.publish(staged).unwrap();
        store.restore(published).unwrap();
        let second = PortableCredential::oauth_access_token("second-token").unwrap();
        let staged_second = store.stage(Uuid::new_v4(), &second).unwrap();
        let published_second = store.publish(staged_second).unwrap();
        let _ = store.restore(published_second).unwrap();
        assert!(
            store
                .read_kind(CredentialRefKind::OauthAccessToken)
                .unwrap()
                .is_none()
        );
        let mode = fs::metadata(store.account_dir())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }

    #[test]
    fn opposite_slot_is_tombstoned_and_restore_recovers_both_exact_slots() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let raw = PortableCredential::oauth_access_token("raw-token").unwrap();
        let raw_stage = store.stage(Uuid::new_v4(), &raw).unwrap();
        let raw_published = store.publish(raw_stage).unwrap();
        store.cleanup_unlocked(&raw_published.inner).unwrap();
        drop(raw_published);

        let authorized = PortableCredential::oauth_authorized_user(serde_json::json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh",
            "token_uri": "https://oauth2.googleapis.com/token",
            "access_token": "new-token",
            "unknown": "preserve"
        }))
        .unwrap();
        let staged = store.stage(Uuid::new_v4(), &authorized).unwrap();
        let published = store.publish(staged).unwrap();
        assert!(
            !store.account_dir().join(TOKEN_FILENAME).exists(),
            "the opposite slot is hidden only after its tombstone is durable"
        );
        assert_eq!(
            store
                .read_kind(CredentialRefKind::OauthAuthorizedUser)
                .unwrap()
                .unwrap()
                .bytes,
            authorized.to_native_json_string().unwrap().into_bytes()
        );
        let journal = fs::read_dir(store.account_dir())
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(JOURNAL_SUFFIX)
            })
            .expect("journal remains until cleanup");
        let journal_bytes = fs::read(journal.path()).unwrap();
        assert!(!String::from_utf8_lossy(&journal_bytes).contains("new-token"));

        store.restore(published).unwrap();
        assert_eq!(
            fs::read(store.account_dir().join(TOKEN_FILENAME)).unwrap(),
            b"raw-token"
        );
        assert!(!store.account_dir().join(CREDENTIALS_FILENAME).exists());
        assert!(
            !fs::read_dir(store.account_dir())
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(STAGE_PREFIX))
        );
    }

    #[test]
    fn restore_handles_crash_after_opposite_move_before_target_publish() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let raw = PortableCredential::oauth_access_token("raw-token").unwrap();
        let raw_stage = store.stage(Uuid::new_v4(), &raw).unwrap();
        let raw_published = store.publish(raw_stage).unwrap();
        store.cleanup_unlocked(&raw_published.inner).unwrap();
        drop(raw_published);

        let authorized = PortableCredential::oauth_authorized_user(serde_json::json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh",
            "token_uri": "https://oauth2.googleapis.com/token"
        }))
        .unwrap();
        let staged = store.stage(Uuid::new_v4(), &authorized).unwrap();
        let staged_inner = staged.inner;
        let tombstone = store.tombstone_path(staged_inner.txid, CredentialSlot::Token);
        let target = store
            .target_locator_for_slot(CredentialSlot::Token)
            .unwrap();
        store
            .capability
            .as_ref()
            .unwrap()
            .move_file(&target, &tombstone)
            .unwrap();
        let published = PublishedCredentialTxn {
            inner: staged_inner,
        };
        store.restore(published).unwrap();
        assert_eq!(
            fs::read(store.account_dir().join(TOKEN_FILENAME)).unwrap(),
            b"raw-token"
        );
        assert!(!store.account_dir().join(CREDENTIALS_FILENAME).exists());
    }

    #[test]
    fn delete_publishes_after_none_and_restore_reconstructs_exact_baseline() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let token = PortableCredential::oauth_access_token("delete-me").unwrap();
        let published = store
            .publish(store.stage(Uuid::new_v4(), &token).unwrap())
            .unwrap();
        store.cleanup_unlocked(&published.inner).unwrap();
        drop(published);

        let expected = store.read_layout().unwrap().expected_layout();
        let prepared = store.stage_delete(Uuid::new_v4(), &expected).unwrap();
        assert!(prepared.inner.after_ref.is_none());
        let published = store.publish(prepared).unwrap();
        assert!(store.read_layout().unwrap().token.is_none());
        store.restore(published).unwrap();
        assert_eq!(
            store
                .read_kind(CredentialRefKind::OauthAccessToken)
                .unwrap()
                .unwrap()
                .credential
                .access_token(),
            Some("delete-me")
        );
    }

    #[test]
    fn purge_publishes_and_restores_without_touching_any_credential_file() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        // 账号目录里一个凭据都没有：这正是"无法迁移"的账号形态。
        let prepared = store.stage_purge(Uuid::new_v4()).unwrap();
        assert!(prepared.inner.after_ref.is_none());
        assert!(prepared.inner.is_purge());
        let journal = prepared.inner.journal.clone();
        let published = store.publish(prepared).unwrap();
        let layout = store.read_layout().unwrap();
        assert!(layout.token.is_none() && layout.document.is_none());

        // 回滚路径必须是纯 no-op，不能因为缺少目标文件而报错。
        store.restore(published).unwrap();
        let capability = store.mutation_capability().unwrap();
        assert!(capability.inspect(&journal, true).unwrap().is_none());
        assert!(!store.account_dir().join(TOKEN_FILENAME).exists());
        assert!(!store.account_dir().join(CREDENTIALS_FILENAME).exists());
    }

    #[test]
    fn current_exact_permit_rejects_dual_live_layout() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        store
            .capability
            .as_ref()
            .unwrap()
            .ensure_account_dir()
            .unwrap();
        let authorized = PortableCredential::oauth_authorized_user(serde_json::json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh",
            "token_uri": "https://oauth2.googleapis.com/token"
        }))
        .unwrap();
        fs::write(store.account_dir().join(TOKEN_FILENAME), b"raw-token").unwrap();
        fs::write(
            store.account_dir().join(CREDENTIALS_FILENAME),
            authorized.to_native_json_string().unwrap(),
        )
        .unwrap();
        store.mode = CredentialStoreMode::CurrentExact;
        let replacement = PortableCredential::oauth_access_token("replacement").unwrap();
        assert!(matches!(
            store.stage(Uuid::new_v4(), &replacement),
            Err(CredentialStoreError::Conflict { .. })
        ));
    }

    #[test]
    fn migration_permit_accepts_dual_live_layout_for_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        store
            .capability
            .as_ref()
            .unwrap()
            .ensure_account_dir()
            .unwrap();
        let authorized = PortableCredential::oauth_authorized_user(serde_json::json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh",
            "token_uri": "https://oauth2.googleapis.com/token"
        }))
        .unwrap();
        fs::write(store.account_dir().join(TOKEN_FILENAME), b"raw-token").unwrap();
        fs::write(
            store.account_dir().join(CREDENTIALS_FILENAME),
            authorized.to_native_json_string().unwrap(),
        )
        .unwrap();

        let replacement = PortableCredential::oauth_access_token("replacement").unwrap();
        let published = store
            .publish(store.stage(Uuid::new_v4(), &replacement).unwrap())
            .unwrap();
        assert_eq!(
            store
                .read_kind(CredentialRefKind::OauthAccessToken)
                .unwrap()
                .unwrap()
                .credential
                .access_token(),
            Some("replacement")
        );
        assert!(
            store
                .read_kind(CredentialRefKind::OauthAuthorizedUser)
                .unwrap()
                .is_none()
        );

        store.restore(published).unwrap();
        assert_eq!(
            store
                .read_kind(CredentialRefKind::OauthAccessToken)
                .unwrap()
                .unwrap()
                .credential
                .access_token(),
            Some("raw-token")
        );
        assert!(
            store
                .read_kind(CredentialRefKind::OauthAuthorizedUser)
                .unwrap()
                .is_some()
        );
    }

    /// AC-R12-2.1: 超大孤儿 stage 仍然被清掉，且只清掉它自己——中转改名不得
    /// 在账号目录里留下任何残留，正常大小的孤儿 stage 与实时凭据都不受影响。
    #[test]
    fn an_oversized_orphan_stage_is_discarded_without_residue() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let capability = store.capability.as_ref().unwrap();
        capability.ensure_account_dir().unwrap();

        // 一份真实的实时凭据，用来证明清理不会误伤。
        let token = PortableCredential::oauth_access_token("live-token").unwrap();
        let staged = store.stage(Uuid::new_v4(), &token).unwrap();
        let published = store.publish(staged).unwrap();
        store.cleanup_unlocked(&published.inner).unwrap();
        drop(published);

        let huge = format!("{STAGE_PREFIX}{}{STAGE_SUFFIX}", Uuid::new_v4());
        fs::write(
            store.account_dir().join(&huge),
            vec![b'A'; MAX_CREDENTIAL_FILE_BYTES + 1],
        )
        .unwrap();
        let small = format!("{STAGE_PREFIX}{}{STAGE_SUFFIX}", Uuid::new_v4());
        fs::write(store.account_dir().join(&small), b"small-orphan").unwrap();

        cleanup_orphan_stages(capability).unwrap();

        assert!(!store.account_dir().join(&huge).exists());
        assert!(!store.account_dir().join(&small).exists());
        let leftovers: Vec<String> = fs::read_dir(store.account_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(STAGE_SUFFIX))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the detach-then-delete path left residue: {leftovers:?}"
        );
        assert_eq!(
            store
                .read_kind(CredentialRefKind::OauthAccessToken)
                .unwrap()
                .unwrap()
                .credential
                .access_token(),
            Some("live-token"),
            "cleanup must never touch the live credential"
        );
    }

    /// AC-R12-2.2: 超大孤儿 stage 删不掉时，错误必须上抛，不得 `let _ =` 吞掉
    /// 后当作清理成功。
    #[cfg(unix)]
    #[test]
    fn a_failed_oversized_stage_removal_is_reported_not_swallowed() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let capability = store.capability.as_ref().unwrap();
        capability.ensure_account_dir().unwrap();
        let huge = format!("{STAGE_PREFIX}{}{STAGE_SUFFIX}", Uuid::new_v4());
        fs::write(
            store.account_dir().join(&huge),
            vec![b'A'; MAX_CREDENTIAL_FILE_BYTES + 1],
        )
        .unwrap();

        // 只读目录 -> rename/unlink 必然 EACCES。root 会绕过权限位，那种环境下
        // 这条断言没有意义，直接跳过。
        let original = fs::metadata(store.account_dir()).unwrap().permissions();
        fs::set_permissions(store.account_dir(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = cleanup_orphan_stages(capability);
        let still_there = store.account_dir().join(&huge).exists();
        fs::set_permissions(store.account_dir(), original).unwrap();

        if still_there {
            assert!(
                result.is_err(),
                "an oversized orphan stage survived but cleanup reported success"
            );
        }
    }

    /// AC-R12-3.1: 隔离名耗尽时的错误必须给出可执行的下一步——清理哪个目录下
    /// 的哪一类文件。
    #[test]
    fn exhausted_quarantine_names_name_the_directory_and_the_file_class() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let capability = store.capability.as_ref().unwrap();
        capability.ensure_account_dir().unwrap();
        fs::write(
            store
                .account_dir()
                .join(format!("{QUARANTINE_PREFIX}{CREDENTIALS_FILENAME}")),
            b"blocker",
        )
        .unwrap();
        for index in 1..=QUARANTINE_MAX_SUFFIX {
            fs::write(
                store
                    .account_dir()
                    .join(format!("{QUARANTINE_PREFIX}{index}.{CREDENTIALS_FILENAME}")),
                b"blocker",
            )
            .unwrap();
        }

        let error = quarantine_destination(capability, CREDENTIALS_FILENAME)
            .expect_err("every quarantine name is taken");
        let message = error.to_string();
        assert!(
            message.is_ascii(),
            "console output must be ASCII: {message}"
        );
        assert!(
            message.contains("accounts/<account id>/"),
            "the error must name the directory to clean up: {message}"
        );
        assert!(
            message.contains(".sagy-credential-quarantine.*"),
            "the error must name the file class to clean up: {message}"
        );
    }

    #[test]
    fn orphan_journal_update_is_removed_only_when_it_matches_target() {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::test_mutable(temp.path(), "a-1").unwrap();
        let capability = store.capability.as_ref().unwrap();
        capability.ensure_account_dir().unwrap();
        let txid = Uuid::new_v4();
        let target_name = format!("{STAGE_PREFIX}{txid}{JOURNAL_SUFFIX}");
        let update_name = format!(".{target_name}.update");
        fs::write(
            store.account_dir().join(&target_name),
            br#"{"journal_version":2}"#,
        )
        .unwrap();
        fs::write(
            store.account_dir().join(&update_name),
            br#"{"journal_version":2}"#,
        )
        .unwrap();
        cleanup_orphan_updates(capability).unwrap();
        assert!(!store.account_dir().join(&update_name).exists());

        fs::write(
            store.account_dir().join(&update_name),
            br#"{"journal_version":3}"#,
        )
        .unwrap();
        assert!(matches!(
            cleanup_orphan_updates(capability),
            Err(CredentialStoreError::Conflict { .. })
        ));
        assert!(store.account_dir().join(&target_name).exists());
        assert!(store.account_dir().join(&update_name).exists());
    }
}
