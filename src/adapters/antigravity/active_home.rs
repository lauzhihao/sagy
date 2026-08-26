//! Transactional switching of the two user-owned Antigravity credential slots.
//!
//! The State lock is acquired by the caller before this module is entered. The
//! active-home store then claims/adopts both external roots in a deterministic
//! order and keeps their fixed lock handles until the transaction is either
//! restored or finalized. Journal records contain only validated locators and
//! digests; credential bytes never enter the journal.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapters::antigravity::paths::active_home_scope_id;
use crate::core::atomic_io::{ExternalDirectoryCapability, NormalizedStoreRoot, SafeRelativePath};
use crate::core::atomic_store::AccountStoreCapability;
use crate::core::credential::MAX_CREDENTIAL_SERIALIZED_BYTES;
use crate::core::state::{
    ActiveProfile, CredentialRef, CredentialRefKind, ManagedLayout, SlotState,
};
use crate::core::state_store::{
    ActiveHomeJournalProof, ActiveHomeMutationPermit, ActiveHomeRecoveryAuthority,
    ActiveHomeRecoveryState, Revision, RevisionGeneration, StateCommitReceipt,
};

const TOKEN_FILENAME: &str = "antigravity-oauth-token";
const DOCUMENT_FILENAME: &str = "oauth_creds.json";
const LOCK_FILENAME: &str = ".sagy-active-home.lock";
const ACCOUNT_LOCK_FILENAME: &str = ".sagy-active-home.account.lock";
const MAX_HOME_FILE_BYTES: usize = MAX_CREDENTIAL_SERIALIZED_BYTES;
const JOURNAL_PREFIX: &str = ".sagy-active-home-";
const JOURNAL_SUFFIX: &str = ".journal";
const STAGE_TOKEN_SUFFIX: &str = ".token.stage";
const STAGE_DOCUMENT_SUFFIX: &str = ".document.stage";
const TOMBSTONE_TOKEN_SUFFIX: &str = ".token.tombstone";
const TOMBSTONE_DOCUMENT_SUFFIX: &str = ".document.tombstone";
const RECOVERY_TOKEN_SUFFIX: &str = ".token.recovery";
const RECOVERY_DOCUMENT_SUFFIX: &str = ".document.recovery";
/// takeover 把被替换掉的原凭据留在同目录下的这个后缀里。
///
/// 为什么不删：takeover 的前提就是"这份凭据 sagy 不认识"，它很可能是用户手上
/// 唯一的一份。finalize 时销毁等于用一条 sagy 命令抹掉用户的数据。
const BACKUP_INFIX: &str = ".sagy-backup-";
/// 孤儿 stage 清理时单个目录的枚举上限；超过就放弃清理而不是无界扫描。
const MAX_SWEEP_ENTRIES: usize = 4096;

#[derive(Debug)]
pub(crate) enum ActiveHomeError {
    Invalid(anyhow::Error),
    ReconcileRequired {
        source: anyhow::Error,
        token: ReconcileToken,
    },
}

impl fmt::Display for ActiveHomeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "invalid active-home transaction: {error}"),
            Self::ReconcileRequired { source, .. } => {
                write!(
                    formatter,
                    "active-home transaction requires reconciliation: {source}"
                )
            }
        }
    }
}

impl std::error::Error for ActiveHomeError {}

impl From<anyhow::Error> for ActiveHomeError {
    fn from(error: anyhow::Error) -> Self {
        Self::Invalid(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveHomeTarget {
    RawOauth,
    AuthorizedUser,
    Api,
    Vertex,
}

impl ActiveHomeTarget {
    #[cfg(test)]
    fn expected_layout(self, material_digest: Option<String>) -> ManagedLayout {
        match self {
            Self::RawOauth => ManagedLayout {
                antigravity_token: SlotState::Exact {
                    sha256: material_digest.expect("raw OAuth target requires material digest"),
                },
                gemini_authorized_user: SlotState::Absent,
            },
            Self::AuthorizedUser => ManagedLayout {
                antigravity_token: SlotState::Absent,
                gemini_authorized_user: SlotState::Exact {
                    sha256: material_digest
                        .expect("authorized-user target requires material digest"),
                },
            },
            Self::Api | Self::Vertex => ManagedLayout::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SlotBytes {
    bytes: Option<Vec<u8>>,
    digest: Option<String>,
}

impl SlotBytes {
    fn absent() -> Self {
        Self {
            bytes: None,
            digest: None,
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut digest = Sha256::new();
        digest.update(&bytes);
        Self {
            digest: Some(format!("{:x}", digest.finalize())),
            bytes: Some(bytes),
        }
    }

    fn layout_state(&self) -> SlotState {
        self.digest
            .as_ref()
            .cloned()
            .map(|sha256| SlotState::Exact { sha256 })
            .unwrap_or(SlotState::Absent)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HomeLayoutBytes {
    token: SlotBytes,
    document: SlotBytes,
}

impl HomeLayoutBytes {
    fn absent() -> Self {
        Self {
            token: SlotBytes::absent(),
            document: SlotBytes::absent(),
        }
    }

    fn managed_layout(&self) -> ManagedLayout {
        ManagedLayout {
            antigravity_token: self.token.layout_state(),
            gemini_authorized_user: self.document.layout_state(),
        }
    }

    fn is_absent(&self) -> bool {
        self.token.bytes.is_none() && self.document.bytes.is_none()
    }
}

#[derive(Debug)]
struct HomeRoot {
    slot: HomeSlot,
    capability: ExternalDirectoryCapability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HomeSlot {
    Token,
    Document,
}

impl HomeSlot {
    fn filename(self) -> &'static str {
        match self {
            Self::Token => TOKEN_FILENAME,
            Self::Document => DOCUMENT_FILENAME,
        }
    }

    fn stage_suffix(self) -> &'static str {
        match self {
            Self::Token => STAGE_TOKEN_SUFFIX,
            Self::Document => STAGE_DOCUMENT_SUFFIX,
        }
    }

    fn tombstone_suffix(self) -> &'static str {
        match self {
            Self::Token => TOMBSTONE_TOKEN_SUFFIX,
            Self::Document => TOMBSTONE_DOCUMENT_SUFFIX,
        }
    }

    fn recovery_suffix(self) -> &'static str {
        match self {
            Self::Token => RECOVERY_TOKEN_SUFFIX,
            Self::Document => RECOVERY_DOCUMENT_SUFFIX,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ActiveHomeStore {
    account_id: String,
    account_capability: AccountStoreCapability,
    _account_lock: File,
    base_revision: Revision,
    before_profile: Option<ActiveProfile>,
    target_profile: Option<ActiveProfile>,
    target_ref: Option<CredentialRef>,
    token_root: HomeRoot,
    document_root: HomeRoot,
    scope_id: String,
}

impl ActiveHomeStore {
    pub(crate) fn from_permit_with_roots(
        permit: ActiveHomeMutationPermit,
        antigravity: NormalizedStoreRoot,
        gemini: NormalizedStoreRoot,
    ) -> Result<Self> {
        if antigravity == gemini {
            bail!("Antigravity and Gemini active-home roots must differ");
        }
        let account_id = permit.account_id().to_string();
        let account_capability = permit.account_capability().clone();
        account_capability.ensure_account_dir()?;
        let account_lock_locator = account_capability.locator(ACCOUNT_LOCK_FILENAME)?;
        let account_lock = account_capability.open_or_create_lock(&account_lock_locator)?;
        account_lock
            .lock_exclusive()
            .context("failed to acquire active-home account lock")?;
        let base_revision = permit.base_revision().clone();
        let before_profile = permit.before_profile().cloned();
        let target_profile = permit.target_profile().cloned();
        let target_ref = permit.target_ref().cloned();
        let expected_scope = active_home_scope_id(&antigravity, &gemini);
        if let Some(scope) = permit.home_scope_id()
            && scope != expected_scope
        {
            bail!("active-home permit scope does not match normalized roots");
        }
        for profile in [before_profile.as_ref(), target_profile.as_ref()]
            .into_iter()
            .flatten()
        {
            if profile.home_scope_id != expected_scope {
                bail!("active-home profile scope does not match normalized roots");
            }
        }

        let lock = SafeRelativePath::new(Path::new(LOCK_FILENAME))?;
        let mut roots = vec![(HomeSlot::Token, antigravity), (HomeSlot::Document, gemini)];
        roots.sort_by(|left, right| left.1.as_path().cmp(right.1.as_path()));
        let mut opened = Vec::with_capacity(roots.len());
        for (slot, root) in roots {
            opened.push(HomeRoot {
                slot,
                capability: ExternalDirectoryCapability::claim_or_adopt(root, lock.clone())?,
            });
        }
        let token_root = opened
            .iter()
            .position(|root| root.slot == HomeSlot::Token)
            .ok_or_else(|| anyhow!("token active-home root was not opened"))?;
        // Moving the two roots out of the temporary vector retains both lock
        // handles for the whole transaction.
        let mut opened = opened.into_iter();
        let first = opened.next().expect("two active-home roots");
        let second = opened.next().expect("two active-home roots");
        let (token_root, document_root) = if token_root == 0 {
            (first, second)
        } else {
            (second, first)
        };
        let store = Self {
            account_id,
            account_capability,
            _account_lock: account_lock,
            base_revision,
            before_profile,
            target_profile,
            target_ref,
            token_root,
            document_root,
            scope_id: expected_scope,
        };
        // 两个 home root 的 fixed lock 和 State 锁都已在手，此刻磁盘上不存在
        // 其它进程的在途事务，是清理孤儿 stage 明文的唯一安全时机。
        store.sweep_orphan_stages()?;
        Ok(store)
    }

    /// Strict mode permits only an empty profile or an exact State-advertised
    /// before layout. Existing unmanaged fixed slots require an explicit
    /// adopt/takeover call.
    pub(crate) fn prepare(
        self,
        txid: Uuid,
    ) -> std::result::Result<PreparedActiveHomeTxn, ActiveHomeError> {
        self.prepare_inner(txid, AdoptionMode::Strict)
    }

    /// Adopt 是"如果磁盘上躺着的就是本次目标账号的凭据，就直接接管"。
    ///
    /// 它**不是**放开覆盖：只要磁盘内容与目标不是逐字节一致，`prepare_inner`
    /// 会把它降级回 Strict，照样 fail-closed。
    pub(crate) fn prepare_adopt(
        self,
        txid: Uuid,
    ) -> std::result::Result<PreparedActiveHomeTxn, ActiveHomeError> {
        self.prepare_inner(txid, AdoptionMode::Adopt)
    }

    pub(crate) fn prepare_takeover(
        self,
        txid: Uuid,
    ) -> std::result::Result<PreparedActiveHomeTxn, ActiveHomeError> {
        self.prepare_inner(txid, AdoptionMode::Takeover)
    }

    fn prepare_inner(
        self,
        txid: Uuid,
        mode: AdoptionMode,
    ) -> std::result::Result<PreparedActiveHomeTxn, ActiveHomeError> {
        let baseline = self.read_layout()?;
        self.validate_before_layout(&baseline, mode)?;
        let target_layout = self.target_layout()?;
        // Adopt 的 publish 会整段跳过搬文件（磁盘上已经是目标内容）。因此
        // Adopt 只在"State 里还没有 active profile、磁盘上已有凭据、且这份
        // 凭据与目标逐字节一致"这一种情形下才成立；其余一律降级回 Strict，
        // 否则普通账号切换会静默漏写凭据。
        let effective_mode = match mode {
            AdoptionMode::Adopt
                if self.before_profile.is_none()
                    && !baseline.is_absent()
                    && baseline.managed_layout() == target_layout.managed_layout()
                    && self.target_profile.as_ref().is_some_and(|profile| {
                        profile.managed_layout == baseline.managed_layout()
                    }) =>
            {
                AdoptionMode::Adopt
            }
            AdoptionMode::Adopt => AdoptionMode::Strict,
            other => other,
        };
        let mut inner = ActiveHomeTxn {
            store: self,
            txid,
            baseline,
            target_layout,
            mode: effective_mode,
            phase: JournalPhase::Prepared,
        };

        if inner.store.before_profile.is_none() && !inner.baseline.is_absent() {
            validate_first_profile_layout(
                &inner.baseline,
                inner.store.target_profile.as_ref(),
                effective_mode,
            )?;
        }
        inner.stage(txid)?;
        Ok(PreparedActiveHomeTxn { inner })
    }

    fn root_for(&self, slot: HomeSlot) -> &HomeRoot {
        match slot {
            HomeSlot::Token => &self.token_root,
            HomeSlot::Document => &self.document_root,
        }
    }

    /// 删除两个 home root 下无主的 `.stage` 文件。
    ///
    /// stage 里是完整的凭据明文，`stage()` 先写 stage 再写 journal，崩在中间就留下
    /// 一个永远不会被 recovery 扫到的孤儿。判定"无主"只看 journal：任何仍有 journal
    /// 的 txid 都属于进行中的事务，一概不碰。tombstone / recovery 里可能是用户唯一
    /// 的凭据副本，永远不在清理范围内。
    fn sweep_orphan_stages(&self) -> Result<()> {
        let Some(live) = self.pending_journal_txids()? else {
            return Ok(());
        };
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            let capability = &self.root_for(slot).capability;
            let Some(names) = orphan_stage_names(capability.root_path(), &live)? else {
                continue;
            };
            for name in names {
                // remove 自己会 sync 父目录，删除即持久。
                let locator = SafeRelativePath::new(Path::new(&name))?;
                remove_artifact(capability, &locator)?;
            }
        }
        Ok(())
    }

    /// 收集所有账号目录下仍然存在的 active-home journal txid。
    ///
    /// 这里只做只读枚举来构造"保护名单"，删除仍然走 capability 的 no-follow 路径；
    /// 枚举不到（目录缺失或超出上限）时返回 None，调用方直接跳过清理，宁可留下孤儿
    /// 也不能在证据不全时删文件。
    fn pending_journal_txids(&self) -> Result<Option<BTreeSet<Uuid>>> {
        let probe = self.account_capability.locator(ACCOUNT_LOCK_FILENAME)?;
        let Some(accounts_relative) = probe.as_path().parent().and_then(Path::parent) else {
            return Ok(None);
        };
        let accounts_dir = self.account_capability.root_path().join(accounts_relative);
        let Some(entries) = bounded_dir_entries(&accounts_dir)? else {
            return Ok(None);
        };
        let mut txids = BTreeSet::new();
        for entry in entries {
            // accounts/ 下混进来的非目录条目不是本模块的事，跳过即可，不能让它把
            // 整条命令变成硬失败。
            if !entry.path().is_dir() {
                continue;
            }
            let Some(names) = bounded_dir_entries(&entry.path())? else {
                return Ok(None);
            };
            for name in names {
                if let Some(txid) = journal_txid(&name.file_name().to_string_lossy()) {
                    txids.insert(txid);
                }
            }
        }
        Ok(Some(txids))
    }

    fn read_layout(&self) -> Result<HomeLayoutBytes> {
        Ok(HomeLayoutBytes {
            token: self.read_slot(&self.token_root.capability, HomeSlot::Token)?,
            document: self.read_slot(&self.document_root.capability, HomeSlot::Document)?,
        })
    }

    fn read_slot(&self, root: &ExternalDirectoryCapability, slot: HomeSlot) -> Result<SlotBytes> {
        let locator = SafeRelativePath::new(Path::new(slot.filename()))?;
        let Some(metadata) = root.inspect(&locator, true)? else {
            return Ok(SlotBytes::absent());
        };
        if metadata.len() > MAX_HOME_FILE_BYTES as u64 {
            bail!(
                "active-home {} exceeds the bounded file size",
                slot.filename()
            );
        }
        let bytes = root
            .read_bounded(&locator, MAX_HOME_FILE_BYTES)?
            .ok_or_else(|| anyhow!("active-home {} disappeared during read", slot.filename()))?;
        Ok(SlotBytes::from_bytes(bytes))
    }

    fn validate_before_layout(&self, baseline: &HomeLayoutBytes, mode: AdoptionMode) -> Result<()> {
        let Some(profile) = self.before_profile.as_ref() else {
            return Ok(());
        };
        if profile.managed_layout == baseline.managed_layout() {
            return Ok(());
        }
        if mode != AdoptionMode::Takeover {
            bail!(
                "active-home {TOKEN_FILENAME} / {DOCUMENT_FILENAME} changed outside sagy and no longer match the State before profile; {}",
                takeover_hint()
            );
        }
        // A takeover is an explicit, journaled adoption of the observed
        // fixed-slot baseline.  `read_layout` has already rejected symlink,
        // reparse, special-file, and unknown-digest inputs through the
        // ExternalDirectoryCapability, so this branch never broadens the
        // filesystem trust boundary.
        Ok(())
    }

    fn target_layout(&self) -> Result<HomeLayoutBytes> {
        let Some(profile) = self.target_profile.as_ref() else {
            return Ok(HomeLayoutBytes::absent());
        };
        let target = match self.target_ref.as_ref().map(|reference| reference.kind) {
            Some(CredentialRefKind::OauthAccessToken) => ActiveHomeTarget::RawOauth,
            Some(CredentialRefKind::OauthAuthorizedUser) => ActiveHomeTarget::AuthorizedUser,
            Some(CredentialRefKind::ApiKey) => ActiveHomeTarget::Api,
            Some(CredentialRefKind::VertexServiceAccount) => ActiveHomeTarget::Vertex,
            None if profile.managed_layout == ManagedLayout::default() => ActiveHomeTarget::Api,
            None => bail!("active-home target layout has no credential reference"),
        };
        let expected_digest = match target {
            ActiveHomeTarget::RawOauth => match &profile.managed_layout.antigravity_token {
                SlotState::Exact { sha256 } => Some(sha256.clone()),
                SlotState::Absent => None,
            },
            ActiveHomeTarget::AuthorizedUser => {
                match &profile.managed_layout.gemini_authorized_user {
                    SlotState::Exact { sha256 } => Some(sha256.clone()),
                    SlotState::Absent => None,
                }
            }
            ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => None,
        };
        let bytes = match target {
            ActiveHomeTarget::RawOauth => self.read_account_file(TOKEN_FILENAME)?,
            ActiveHomeTarget::AuthorizedUser => self.read_account_file("credentials.json")?,
            ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => None,
        };
        let target_layout = match target {
            ActiveHomeTarget::RawOauth => HomeLayoutBytes {
                token: bytes
                    .map(SlotBytes::from_bytes)
                    .ok_or_else(|| anyhow!("target raw OAuth credential is missing"))?,
                document: SlotBytes::absent(),
            },
            ActiveHomeTarget::AuthorizedUser => HomeLayoutBytes {
                token: SlotBytes::absent(),
                document: bytes
                    .map(SlotBytes::from_bytes)
                    .ok_or_else(|| anyhow!("target authorized-user credential is missing"))?,
            },
            ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => HomeLayoutBytes::absent(),
        };
        if let Some(expected_digest) = expected_digest {
            let actual = target_layout
                .token
                .digest
                .as_ref()
                .or(target_layout.document.digest.as_ref())
                .ok_or_else(|| anyhow!("target credential layout has no material"))?;
            if actual != &expected_digest {
                bail!("target credential material does not match State profile layout");
            }
        }
        Ok(target_layout)
    }

    fn read_account_file(&self, filename: &str) -> Result<Option<Vec<u8>>> {
        let locator = self.account_capability.locator(filename)?;
        let Some(metadata) = self.account_capability.inspect(&locator, true)? else {
            return Ok(None);
        };
        if metadata.len() > MAX_HOME_FILE_BYTES as u64 {
            bail!("account credential material exceeds the bounded file size");
        }
        self.account_capability
            .read_bounded(&locator, MAX_HOME_FILE_BYTES)
    }
}

fn validate_first_profile_layout(
    baseline: &HomeLayoutBytes,
    target_profile: Option<&ActiveProfile>,
    mode: AdoptionMode,
) -> Result<()> {
    let target_matches =
        target_profile.is_some_and(|profile| profile.managed_layout == baseline.managed_layout());
    match mode {
        AdoptionMode::Adopt if target_matches => Ok(()),
        AdoptionMode::Takeover => Ok(()),
        _ => bail!(
            "active-home already holds {TOKEN_FILENAME} / {DOCUMENT_FILENAME} that do not belong to any sagy-managed account; {}",
            takeover_hint()
        ),
    }
}

/// active home 里躺着一份 sagy 不认识的凭据时，用户唯一可执行的下一步。
///
/// 必须自带一条真的能敲的命令：HOME-002 的直接成因就是错误信息要求用户
/// "explicit adopt/takeover"，而 CLI 根本没有提供这个入口。
fn takeover_hint() -> String {
    format!(
        "sagy will not overwrite them silently; back them up yourself, or run 'sagy launch --takeover' \
         (the same flag exists on 'sagy auto', 'sagy use', 'sagy login' and 'sagy add') to move each \
         existing file aside to '<name>{BACKUP_INFIX}<txid>' in the same directory and then take over"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdoptionMode {
    Strict,
    Adopt,
    Takeover,
}

impl AdoptionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Adopt => "adopt",
            Self::Takeover => "takeover",
        }
    }
}

#[derive(Debug)]
struct ActiveHomeTxn {
    store: ActiveHomeStore,
    txid: Uuid,
    baseline: HomeLayoutBytes,
    target_layout: HomeLayoutBytes,
    mode: AdoptionMode,
    phase: JournalPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalPhase {
    Prepared,
    /// publish 已经开始搬动用户真实凭据，但尚未全部就位。
    Publishing,
    Published,
}

pub(crate) struct PreparedActiveHomeTxn {
    inner: ActiveHomeTxn,
}

pub(crate) struct PublishedActiveHomeTxn {
    inner: ActiveHomeTxn,
}

pub(crate) struct ReconcileToken {
    inner: Box<ActiveHomeTxn>,
}

impl fmt::Debug for ReconcileToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveHomeReconcileToken")
            .field("txid", &self.inner.txid)
            .field("account_id", &self.inner.store.account_id)
            .finish()
    }
}

impl PreparedActiveHomeTxn {
    #[cfg(test)]
    pub(crate) fn txid(&self) -> Uuid {
        self.inner.txid
    }

    pub(crate) fn publish(
        mut self,
    ) -> std::result::Result<PublishedActiveHomeTxn, ActiveHomeError> {
        if let Err(error) = self.inner.publish_inner() {
            return Err(ActiveHomeError::ReconcileRequired {
                source: error,
                token: ReconcileToken {
                    inner: Box::new(self.inner),
                },
            });
        }
        Ok(PublishedActiveHomeTxn { inner: self.inner })
    }
}

impl PublishedActiveHomeTxn {
    #[cfg(test)]
    pub(crate) fn txid(&self) -> Uuid {
        self.inner.txid
    }

    pub(crate) fn journal_proof(&self) -> Result<ActiveHomeJournalProof> {
        self.inner.journal_proof()
    }

    pub(crate) fn restore(&self) -> Result<()> {
        self.inner.restore_inner()
    }

    pub(crate) fn finalize(self, receipt: &StateCommitReceipt) -> Result<()> {
        let Some(transition) = receipt.active_home_transition() else {
            bail!("state receipt contains no verified active-home transition");
        };
        let journal_digest = self.inner.journal_digest_value()?;
        if transition.txid() != self.inner.txid
            || transition.account_id() != self.inner.store.account_id
            || transition.journal_digest() != journal_digest
            || transition.base_revision() != &self.inner.store.base_revision
            || !committed_revision_follows_base(
                transition.base_revision(),
                transition.committed_revision(),
            )
            || transition.before_profile() != self.inner.store.before_profile.as_ref()
            || transition.after_profile() != self.inner.store.target_profile.as_ref()
            || transition.target_ref() != self.inner.store.target_ref.as_ref()
        {
            bail!("state receipt does not match active-home journal transition");
        }
        self.inner.finalize_inner()
    }
}

impl ActiveHomeTxn {
    fn journal_name(&self) -> String {
        format!("{JOURNAL_PREFIX}{}{JOURNAL_SUFFIX}", self.txid)
    }

    fn artifact_name(&self, _slot: HomeSlot, suffix: &'static str) -> Result<SafeRelativePath> {
        journal_artifact(self.txid, suffix)
    }

    fn stage(&mut self, _txid: Uuid) -> Result<()> {
        self.store.account_capability.ensure_account_dir()?;
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            let desired = self.slot_target(slot).bytes.as_ref();
            if let Some(bytes) = desired {
                let stage = self.artifact_name(slot, slot.stage_suffix())?;
                let mut file = self.stage_file(slot, &stage)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                self.root_for(slot).capability.sync_parent(&stage)?;
            }
        }
        self.write_journal(JournalPhase::Prepared)
    }

    fn stage_file(&self, slot: HomeSlot, stage: &SafeRelativePath) -> Result<File> {
        self.root_for(slot)
            .capability
            .create_new(stage)
            .map_err(|error| anyhow!(error).context("failed to create active-home stage"))
    }

    fn slot_target(&self, slot: HomeSlot) -> &SlotBytes {
        match slot {
            HomeSlot::Token => &self.target_layout.token,
            HomeSlot::Document => &self.target_layout.document,
        }
    }

    fn slot_baseline(&self, slot: HomeSlot) -> &SlotBytes {
        match slot {
            HomeSlot::Token => &self.baseline.token,
            HomeSlot::Document => &self.baseline.document,
        }
    }

    fn root_for(&self, slot: HomeSlot) -> &HomeRoot {
        match slot {
            HomeSlot::Token => &self.store.token_root,
            HomeSlot::Document => &self.store.document_root,
        }
    }

    fn publish_inner(&mut self) -> Result<()> {
        if self.phase != JournalPhase::Prepared {
            bail!("active-home transaction is not prepared");
        }
        let live = self.store.read_layout()?;
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            if layout_slot(&live, slot).digest.as_ref() != self.slot_baseline(slot).digest.as_ref()
            {
                bail!("active-home live layout changed after prepare");
            }
        }
        if self.mode != AdoptionMode::Adopt {
            // 先落 publishing 相位再动用户的真实凭据：崩溃点一旦落在 tombstone 与
            // stage move 之间，journal 必须已经告诉恢复方"文件可能已经被搬走"，
            // 否则 prepared 相位会被误读成"磁盘未被改动"。
            self.phase = JournalPhase::Publishing;
            self.write_journal(JournalPhase::Publishing)?;
            for slot in [HomeSlot::Token, HomeSlot::Document] {
                if self.slot_baseline(slot).bytes.is_some() {
                    let target = SafeRelativePath::new(Path::new(slot.filename()))?;
                    let tombstone = self.artifact_name(slot, slot.tombstone_suffix())?;
                    self.root_for(slot)
                        .capability
                        .move_file(&target, &tombstone)
                        .map_err(|error| {
                            anyhow!(error).context("failed to tombstone active-home slot")
                        })?;
                }
            }
            for slot in [HomeSlot::Token, HomeSlot::Document] {
                if self.slot_target(slot).bytes.is_some() {
                    let stage = self.artifact_name(slot, slot.stage_suffix())?;
                    let target = SafeRelativePath::new(Path::new(slot.filename()))?;
                    self.root_for(slot)
                        .capability
                        .move_file(&stage, &target)
                        .map_err(|error| {
                            anyhow!(error).context("failed to publish active-home slot")
                        })?;
                    self.root_for(slot).capability.sync(&target)?;
                }
            }
        }
        self.phase = JournalPhase::Published;
        self.write_journal(JournalPhase::Published)
    }

    /// 恢复一次没有写出 `published` 的 publish。
    ///
    /// 崩溃可能落在 tombstone 与 stage move 之间的任何一点，此时 live layout 已经
    /// 不再等于 baseline，直接 cleanup 必然 bail 并把真实凭据永久留在 tombstone 里
    /// （HOME-001）。只有在磁盘上完全看不到 publish 痕迹时才走无副作用的 cleanup，
    /// 其余一律交给 restore：它会把 tombstone 移回原位，是唯一能收敛中间态的路径。
    fn recover_incomplete_publish(&self) -> Result<()> {
        if self.publish_left_no_trace()? {
            return self.cleanup_prepared_inner();
        }
        self.restore_inner()
    }

    fn publish_left_no_trace(&self) -> Result<bool> {
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            if self.tombstone_exists(slot)? {
                return Ok(false);
            }
        }
        let live = self.store.read_layout()?;
        Ok(live.managed_layout() == self.baseline.managed_layout())
    }

    fn tombstone_exists(&self, slot: HomeSlot) -> Result<bool> {
        let tombstone = self.artifact_name(slot, slot.tombstone_suffix())?;
        Ok(self
            .root_for(slot)
            .capability
            .inspect(&tombstone, true)?
            .is_some())
    }

    fn cleanup_prepared_inner(&self) -> Result<()> {
        let live = self.store.read_layout()?;
        if live.managed_layout() != self.baseline.managed_layout() {
            bail!("active-home prepared recovery observed an unexpected live layout");
        }
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            let stage = self.artifact_name(slot, slot.stage_suffix())?;
            remove_artifact(&self.root_for(slot).capability, &stage)?;
        }
        self.cleanup_journal()
    }

    fn restore_inner(&self) -> Result<()> {
        let live = self.store.read_layout()?;
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            if !slot_state_is_explained(
                self.slot_baseline(slot),
                self.slot_target(slot),
                self.slot_from_layout(&live, slot),
                self.tombstone_exists(slot)?,
            ) {
                bail!("active-home restore observed an unknown live digest");
            }
        }
        let mut recoveries = Vec::new();
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            let target = SafeRelativePath::new(Path::new(slot.filename()))?;
            let recovery = self.artifact_name(slot, slot.recovery_suffix())?;
            let tombstone = self.artifact_name(slot, slot.tombstone_suffix())?;
            let tombstone_exists = self
                .root_for(slot)
                .capability
                .inspect(&tombstone, true)?
                .is_some();
            let live_present = self
                .root_for(slot)
                .capability
                .inspect(&target, true)?
                .is_some();
            let live_is_baseline = slot_digest_matches(
                self.slot_baseline(slot),
                self.slot_baseline(slot),
                self.slot_from_layout(&live, slot),
            );
            if self.mode != AdoptionMode::Adopt
                && live_present
                && (tombstone_exists || !live_is_baseline)
            {
                self.root_for(slot)
                    .capability
                    .move_file(&target, &recovery)
                    .map_err(|error| {
                        anyhow!(error).context("failed to preserve active-home live slot")
                    })?;
                recoveries.push((slot, recovery.clone()));
            }
            if tombstone_exists {
                self.root_for(slot)
                    .capability
                    .move_file(&tombstone, &target)
                    .map_err(|error| {
                        anyhow!(error).context("failed to restore active-home slot")
                    })?;
            }
            let stage = self.artifact_name(slot, slot.stage_suffix())?;
            remove_artifact(&self.root_for(slot).capability, &stage)?;
            self.root_for(slot).capability.sync_parent(&target)?;
        }
        let restored = self.store.read_layout()?;
        if restored.managed_layout() != self.baseline.managed_layout() {
            bail!("active-home restore did not reproduce the State before layout");
        }
        for (slot, recovery) in recoveries {
            remove_artifact(&self.root_for(slot).capability, &recovery)?;
        }
        self.cleanup_journal()
    }

    fn slot_from_layout<'a>(&self, layout: &'a HomeLayoutBytes, slot: HomeSlot) -> &'a SlotBytes {
        match slot {
            HomeSlot::Token => &layout.token,
            HomeSlot::Document => &layout.document,
        }
    }

    fn finalize_inner(&self) -> Result<()> {
        let live = self.store.read_layout()?;
        if live.managed_layout() != self.target_layout.managed_layout() {
            bail!("active-home live layout changed before finalize");
        }
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            let stage = self.artifact_name(slot, slot.stage_suffix())?;
            let tombstone = self.artifact_name(slot, slot.tombstone_suffix())?;
            let recovery = self.artifact_name(slot, slot.recovery_suffix())?;
            remove_artifact(&self.root_for(slot).capability, &stage)?;
            // takeover 覆盖掉的是 sagy 不认识的凭据，finalize 不能销毁它，
            // 只能把 tombstone 改名成用户可见、可自行恢复的备份。
            if self.mode == AdoptionMode::Takeover {
                self.preserve_takeover_backup(slot, &tombstone)?;
            } else {
                remove_artifact(&self.root_for(slot).capability, &tombstone)?;
            }
            remove_artifact(&self.root_for(slot).capability, &recovery)?;
        }
        self.cleanup_journal()
    }

    /// 把一次 takeover 的 tombstone 迁移成同目录下的持久备份。
    ///
    /// 备份名带 txid，永远不会覆盖上一次 takeover 留下的备份。
    fn preserve_takeover_backup(&self, slot: HomeSlot, tombstone: &SafeRelativePath) -> Result<()> {
        let capability = &self.root_for(slot).capability;
        if capability.inspect(tombstone, true)?.is_none() {
            return Ok(());
        }
        let backup = SafeRelativePath::new(Path::new(&format!(
            "{}{BACKUP_INFIX}{}",
            slot.filename(),
            self.txid
        )))?;
        capability.move_file(tombstone, &backup).map_err(|error| {
            anyhow!(error).context("failed to preserve active-home takeover backup")
        })?;
        capability.sync_parent(&backup)?;
        // 与 `--insecure-host-key` 同一形状: 逃生口真正生效的那一刻必须出声,
        // 并告诉用户被替换掉的凭据备份到了哪个文件名, 否则用户无从恢复。
        // 写失败不影响事务本身, 因此不传播错误。
        let _ = writeln!(
            std::io::stderr(),
            "[sagy] WARNING: --takeover replaced an active-home credential that sagy does not \
manage. The previous file was kept as {}",
            backup.to_slash_string().unwrap_or_default()
        );
        Ok(())
    }

    fn cleanup_journal(&self) -> Result<()> {
        let journal = self
            .store
            .account_capability
            .locator(&self.journal_name())?;
        self.store
            .account_capability
            .remove(&journal)
            .map_err(|error| anyhow!(error))?;
        self.store.account_capability.sync_parent(&journal)?;
        Ok(())
    }

    fn write_journal(&self, phase: JournalPhase) -> Result<()> {
        let value = self.journal_value(phase)?;
        let bytes = serde_json::to_vec_pretty(&value)?;
        if bytes.len() > 64 * 1024 {
            bail!("active-home journal exceeds the bounded size");
        }
        let journal = self
            .store
            .account_capability
            .locator(&self.journal_name())?;
        let update = self
            .store
            .account_capability
            .locator(&format!("{}.update", self.journal_name()))?;
        let mut file = self.store.account_capability.create_new(&update)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        // ReplaceFileW opens the replacement with no sharing mode. Keeping our own update
        // handle alive across the call therefore produces a permanent sharing violation on
        // Windows; the bytes are already durable, so close it before publishing the journal.
        drop(file);
        self.store
            .account_capability
            .replace(&update, &journal)
            .map_err(|error| anyhow!(error))?;
        self.store.account_capability.sync_parent(&journal)?;
        Ok(())
    }

    fn journal_value(&self, phase: JournalPhase) -> Result<Value> {
        let phase = match phase {
            JournalPhase::Prepared => "prepared",
            JournalPhase::Publishing => "publishing",
            JournalPhase::Published => "published",
        };
        let mut object = Map::new();
        object.insert("journal_version".to_string(), Value::from(1));
        object.insert("txid".to_string(), Value::from(self.txid.to_string()));
        object.insert("phase".to_string(), Value::from(phase));
        object.insert(
            "account_id".to_string(),
            Value::from(self.store.account_id.clone()),
        );
        object.insert(
            "base_revision".to_string(),
            revision_value(&self.store.base_revision)?,
        );
        object.insert(
            "before_profile".to_string(),
            self.store
                .before_profile
                .clone()
                .map_or(Value::Null, |profile| {
                    serde_json::to_value(profile).unwrap()
                }),
        );
        object.insert(
            "after_profile".to_string(),
            self.store
                .target_profile
                .clone()
                .map_or(Value::Null, |profile| {
                    serde_json::to_value(profile).unwrap()
                }),
        );
        object.insert(
            "target_ref".to_string(),
            self.store
                .target_ref
                .clone()
                .map_or(Value::Null, |reference| {
                    serde_json::to_value(reference).unwrap()
                }),
        );
        object.insert("mode".to_string(), Value::from(self.mode.as_str()));
        object.insert(
            "state_before_layout".to_string(),
            layout_value(&self.store.before_profile),
        );
        object.insert(
            "before_layout".to_string(),
            serde_json::to_value(self.baseline.managed_layout()).expect("layout serializable"),
        );
        object.insert(
            "after_layout".to_string(),
            serde_json::to_value(self.target_layout.managed_layout()).expect("layout serializable"),
        );
        for slot in [HomeSlot::Token, HomeSlot::Document] {
            let stage = self.artifact_name(slot, slot.stage_suffix())?;
            let tombstone = self.artifact_name(slot, slot.tombstone_suffix())?;
            let prefix = match slot {
                HomeSlot::Token => "token",
                HomeSlot::Document => "document",
            };
            object.insert(
                format!("{prefix}_stage"),
                Value::from(stage.to_slash_string()?),
            );
            object.insert(
                format!("{prefix}_stage_digest"),
                self.slot_target(slot)
                    .digest
                    .clone()
                    .map_or(Value::from(""), Value::from),
            );
            object.insert(
                format!("{prefix}_tombstone"),
                Value::from(tombstone.to_slash_string()?),
            );
            object.insert(
                format!("{prefix}_tombstone_digest"),
                self.slot_baseline(slot)
                    .digest
                    .clone()
                    .map_or(Value::from(""), Value::from),
            );
        }
        Ok(Value::Object(object))
    }

    fn journal_proof(&self) -> Result<ActiveHomeJournalProof> {
        if self.phase != JournalPhase::Published {
            bail!("active-home journal proof requires published phase");
        }
        let journal = self
            .store
            .account_capability
            .locator(&self.journal_name())?;
        let bytes = self
            .store
            .account_capability
            .read_bounded(&journal, 64 * 1024)?
            .ok_or_else(|| anyhow!("active-home journal disappeared"))?;
        let digest = digest_bytes(&bytes);
        ActiveHomeJournalProof::new(
            &self.store.account_id,
            self.txid,
            digest,
            self.store.base_revision.clone(),
            self.store.before_profile.clone(),
            self.store.target_profile.clone(),
            self.store.target_ref.clone(),
            self.mode.as_str().to_string(),
            self.baseline.managed_layout(),
            self.target_layout.managed_layout(),
        )
    }

    fn journal_digest_value(&self) -> Result<String> {
        let journal = self
            .store
            .account_capability
            .locator(&self.journal_name())?;
        let bytes = self
            .store
            .account_capability
            .read_bounded(&journal, 64 * 1024)?
            .ok_or_else(|| anyhow!("active-home journal disappeared"))?;
        Ok(digest_bytes(&bytes))
    }
}

fn committed_revision_follows_base(base: &Revision, committed: &Revision) -> bool {
    match (&base.generation, &committed.generation) {
        (RevisionGeneration::Current(base), RevisionGeneration::Current(committed)) => {
            *committed == base.saturating_add(1)
        }
        (
            RevisionGeneration::Missing | RevisionGeneration::Legacy,
            RevisionGeneration::Current(1),
        ) => true,
        _ => false,
    }
}

/// 枚举一个目录的条目。目录缺失或条目数超出上限时返回 None：调用方只用这个结果
/// 决定"能不能删"，证据不完整时必须放弃删除而不是按空目录处理。
fn bounded_dir_entries(directory: &Path) -> Result<Option<Vec<std::fs::DirEntry>>> {
    let reader = match fs::read_dir(directory) {
        Ok(reader) => reader,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(
                anyhow!(error).context(format!("failed to enumerate {}", directory.display()))
            );
        }
    };
    let mut entries = Vec::new();
    for entry in reader {
        let entry = entry.context("failed to enumerate directory entry")?;
        if entries.len() >= MAX_SWEEP_ENTRIES {
            return Ok(None);
        }
        entries.push(entry);
    }
    Ok(Some(entries))
}

fn journal_txid(name: &str) -> Option<Uuid> {
    parse_artifact_txid(name, JOURNAL_SUFFIX)
}

fn parse_artifact_txid(name: &str, suffix: &str) -> Option<Uuid> {
    let raw = name.strip_prefix(JOURNAL_PREFIX)?.strip_suffix(suffix)?;
    let txid = Uuid::parse_str(raw).ok()?;
    (txid.to_string() == raw).then_some(txid)
}

/// 返回一个 home root 下所有不属于 `live` 中任何 txid 的 stage 文件名。
fn orphan_stage_names(root: &Path, live: &BTreeSet<Uuid>) -> Result<Option<Vec<String>>> {
    let Some(entries) = bounded_dir_entries(root)? else {
        return Ok(None);
    };
    let mut orphans = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(txid) = [STAGE_TOKEN_SUFFIX, STAGE_DOCUMENT_SUFFIX]
            .into_iter()
            .find_map(|suffix| parse_artifact_txid(name, suffix))
        else {
            continue;
        };
        if live.contains(&txid) {
            continue;
        }
        // symlink / 目录不是本模块写出来的 stage，交给 capability 之前先排除，
        // 免得一个陌生同名条目把整条命令变成硬失败。用 DirEntry::file_type 而不是
        // 再 stat 一次路径：Unix 上它通常直接复用 readdir 的 d_type，把 read_dir 与
        // 类型判定之间的 TOCTOU 窗口缩到最小。
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            // 条目在枚举之后消失是恢复路径上的正常竞态（另一个 sagy 进程刚刚完成
            // 同一个事务）。清理是尽力而为的卫生动作，绝不能因为一个已经不存在的
            // 文件把每条 sagy 命令都变成 rc=1——那正是本模块要消灭的死锁形态。
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(anyhow!(error).context(format!("failed to inspect {name}")));
            }
        };
        if !file_type.is_file() {
            continue;
        }
        orphans.push(name.to_string());
    }
    Ok(Some(orphans))
}

fn journal_artifact(txid: Uuid, suffix: &str) -> Result<SafeRelativePath> {
    SafeRelativePath::new(Path::new(&format!("{JOURNAL_PREFIX}{txid}{suffix}")))
}

fn remove_artifact(root: &ExternalDirectoryCapability, locator: &SafeRelativePath) -> Result<()> {
    root.remove(locator)
        .map(|_| ())
        .map_err(|error| anyhow!(error))
}

fn slot_digest_matches(baseline: &SlotBytes, target: &SlotBytes, actual: &SlotBytes) -> bool {
    actual.digest.as_ref() == baseline.digest.as_ref()
        || actual.digest.as_ref() == target.digest.as_ref()
}

/// 判断一个 slot 的现场状态是否能被本次事务解释。
///
/// publish 先把 baseline move 成 tombstone、再把 stage move 到位，中间窗口里目标
/// 文件本来就不存在。tombstone 在场就是"baseline 字节完好地躺在旁边"的证据，此时
/// 目标缺失属于事务自己造成的中间态，不能按第三方改写处理。除此之外仍然只接受
/// baseline / target 两个已知 digest。
fn slot_state_is_explained(
    baseline: &SlotBytes,
    target: &SlotBytes,
    actual: &SlotBytes,
    tombstone_exists: bool,
) -> bool {
    slot_digest_matches(baseline, target, actual) || (tombstone_exists && actual.digest.is_none())
}

fn layout_slot(layout: &HomeLayoutBytes, slot: HomeSlot) -> &SlotBytes {
    match slot {
        HomeSlot::Token => &layout.token,
        HomeSlot::Document => &layout.document,
    }
}

fn revision_value(revision: &Revision) -> Result<Value> {
    Ok(serde_json::json!({
        "generation": match revision.generation {
            RevisionGeneration::Missing => "missing",
            RevisionGeneration::Legacy => "legacy",
            RevisionGeneration::Current(_) => "current",
        },
        "revision": match revision.generation {
            RevisionGeneration::Current(value) => Value::from(value),
            _ => Value::Null,
        },
        "document_sha256": revision.document_sha256,
    }))
}

fn layout_value(profile: &Option<ActiveProfile>) -> Value {
    profile
        .as_ref()
        .map(|profile| serde_json::to_value(&profile.managed_layout).expect("layout serializable"))
        .unwrap_or_else(|| {
            serde_json::to_value(ManagedLayout::default()).expect("layout serializable")
        })
}

/// journal 里记下来的 mode 字符串还原成 `AdoptionMode`。
///
/// 恢复路径必须尊重原事务的 mode: takeover 事务的 finalize 要保留备份,
/// 其余模式才删 tombstone。未知取值一律按最严格的 `Strict` 处理。
fn journal_adoption_mode(mode: &str) -> AdoptionMode {
    match mode {
        "takeover" => AdoptionMode::Takeover,
        "adopt" => AdoptionMode::Adopt,
        _ => AdoptionMode::Strict,
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

/// A published active-home operation can be handed to the caller when a
/// native operation failed after changing one slot. It is deliberately sealed
/// and cannot be turned into a State receipt.
pub(crate) fn restore_reconcile(token: ReconcileToken) -> Result<()> {
    token.inner.restore_inner()
}

/// Recover one durable journal after a restart. The caller must supply the
/// StateStore-minted authority; a random revision/profile can never authorize
/// cleanup or finalization.
pub(crate) fn recover_pending(
    store: ActiveHomeStore,
    authority: ActiveHomeRecoveryAuthority,
    txid: Uuid,
) -> Result<ActiveHomeRecoveryState> {
    let journal = store
        .account_capability
        .locator(&format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}"))?;
    let bytes = store
        .account_capability
        .read_bounded(&journal, 64 * 1024)?
        .ok_or_else(|| anyhow!("active-home journal was not found"))?;
    let value = strict_json_value(&bytes).context("invalid active-home journal")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("active-home journal must be an object"))?;
    let before = parse_profile(object, "before_profile")?;
    let after = parse_profile(object, "after_profile")?;
    for profile in [before.as_ref(), after.as_ref()].into_iter().flatten() {
        if profile.home_scope_id != store.scope_id {
            bail!("active-home recovery journal scope differs from normalized roots");
        }
    }
    let target_ref = parse_target_ref(object)?;
    let phase = object
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let base_revision = parse_journal_revision(object.get("base_revision"))?;
    let state_before_layout = parse_layout(object, "state_before_layout")?;
    let before_layout = parse_layout(object, "before_layout")?;
    let after_layout = parse_layout(object, "after_layout")?;
    if state_before_layout.managed_layout() != layout_from_profile(before.as_ref()).managed_layout()
    {
        bail!("active-home journal state-before layout differs from before profile");
    }
    let recovery_proof = ActiveHomeJournalProof::new(
        &store.account_id,
        txid,
        digest_bytes(&bytes),
        base_revision.clone(),
        before.clone(),
        after.clone(),
        target_ref,
        object
            .get("mode")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-home journal is missing mode"))?
            .to_string(),
        before_layout.managed_layout(),
        after_layout.managed_layout(),
    )
    .map_err(|error| anyhow!(error))?;
    validate_recovery_journal_shape(object, &recovery_proof)?;
    // `prepared` 与 `publishing` 都表示 State 还停在 before profile，一律回滚。
    // 旧二进制只会写 `prepared`，但它的崩溃窗口同样可能已经搬走真实凭据，所以两个
    // 相位都必须按磁盘证据路由，而不是假定 prepared 等于"磁盘未动"。
    if phase == "prepared" || phase == "publishing" {
        let txn = ActiveHomeTxn {
            store,
            txid,
            baseline: before_layout,
            target_layout: after_layout,
            // prepared/publishing 一律按非 adopt 处理：adopt 事务的 baseline 与
            // target 字节必然相同且 publish 不碰磁盘，读 journal 的 mode 与固定
            // Strict 在这条分支上不可能产生不同结果，固定值让恢复语义更窄。
            mode: AdoptionMode::Strict,
            phase: JournalPhase::Prepared,
        };
        txn.recover_incomplete_publish()?;
        return Ok(ActiveHomeRecoveryState::RolledBack);
    }
    if phase != "published" {
        bail!("active-home recovery requires a prepared, publishing, or published journal");
    }
    let live = store.read_layout()?;
    for slot in [HomeSlot::Token, HomeSlot::Document] {
        // restore 自己也有 target->recovery / tombstone->target 两步窗口，崩在中间
        // 同样会看到目标缺失但 tombstone 在场，这里必须和 restore 用同一套判据，
        // 否则恢复成功一半的事务会把 CLI 永久锁死。
        let tombstone = journal_artifact(txid, slot.tombstone_suffix())?;
        let tombstone_exists = store
            .root_for(slot)
            .capability
            .inspect(&tombstone, true)?
            .is_some();
        if !slot_state_is_explained(
            layout_slot(&before_layout, slot),
            layout_slot(&after_layout, slot),
            layout_slot(&live, slot),
            tombstone_exists,
        ) {
            bail!("active-home live digest is unknown; refusing recovery");
        }
    }
    match authority {
        ActiveHomeRecoveryAuthority::Legacy(_) => {
            let mode = if before_layout.managed_layout() == after_layout.managed_layout() {
                AdoptionMode::Adopt
            } else {
                AdoptionMode::Takeover
            };
            let txn = ActiveHomeTxn {
                store,
                txid,
                baseline: before_layout,
                target_layout: after_layout,
                mode,
                phase: JournalPhase::Published,
            };
            // The journal's tombstones are the rollback evidence; restore
            // moves them back without recursively deleting a home.
            txn.restore_inner()?;
            Ok(ActiveHomeRecoveryState::RolledBack)
        }
        ActiveHomeRecoveryAuthority::Current(proof) => {
            let current_revision = proof.revision();
            let adjacent = matches!(
                (&base_revision.generation, &current_revision.generation),
                (RevisionGeneration::Current(base), RevisionGeneration::Current(current))
                    if *current == *base || *current == base.saturating_add(1)
            );
            if !adjacent {
                bail!("active-home journal revision is not adjacent to current State");
            }
            if proof.active_profile() == after.as_ref()
                && current_revision.generation
                    == RevisionGeneration::Current(match base_revision.generation {
                        RevisionGeneration::Current(value) => value.saturating_add(1),
                        _ => 0,
                    })
            {
                // 必须用 journal 里记下来的真实 mode, 不能硬编码。takeover 事务
                // 在 State 提交之后、finalize 之前崩溃时, 硬编码 Adopt 会让
                // finalize_inner 走进删除 tombstone 的分支, 把用户那份被替换掉的
                // 陌生凭据永久销毁 —— 而它可能是用户手上仅存的一份。
                let txn = ActiveHomeTxn {
                    store,
                    txid,
                    baseline: before_layout.clone(),
                    target_layout: after_layout.clone(),
                    mode: journal_adoption_mode(recovery_proof.adoption_mode()),
                    phase: JournalPhase::Published,
                };
                txn.finalize_inner()?;
                Ok(ActiveHomeRecoveryState::Finalized)
            } else if proof.active_profile() == before.as_ref()
                && current_revision.generation == base_revision.generation
            {
                let mode = if before_layout.managed_layout() == after_layout.managed_layout() {
                    AdoptionMode::Adopt
                } else {
                    AdoptionMode::Takeover
                };
                let txn = ActiveHomeTxn {
                    store,
                    txid,
                    baseline: before_layout,
                    target_layout: after_layout,
                    mode,
                    phase: JournalPhase::Published,
                };
                txn.restore_inner()?;
                Ok(ActiveHomeRecoveryState::RolledBack)
            } else {
                bail!("active-home live State does not match journal before/after profile");
            }
        }
    }
}

fn parse_profile(object: &Map<String, Value>, field: &str) -> Result<Option<ActiveProfile>> {
    let value = object
        .get(field)
        .ok_or_else(|| anyhow!("active-home journal is missing {field}"))?;
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(value.clone())?))
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictJsonValue(Value::Number(
            serde_json::Number::from_f64(value)
                .ok_or_else(|| E::custom("non-finite JSON number"))?,
        )))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
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
            values.insert(key, map.next_value::<StrictJsonValue>()?.0);
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

fn strict_json_value(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| anyhow!(error).context("invalid JSON active-home journal"))?
        .0;
    deserializer
        .end()
        .map_err(|error| anyhow!(error).context("trailing bytes after active-home journal"))?;
    Ok(value)
}

fn parse_target_ref(object: &Map<String, Value>) -> Result<Option<CredentialRef>> {
    let value = object
        .get("target_ref")
        .ok_or_else(|| anyhow!("active-home journal is missing target_ref"))?;
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(value.clone())?))
}

fn parse_journal_revision(value: Option<&Value>) -> Result<Revision> {
    let object = value
        .ok_or_else(|| anyhow!("active-home journal is missing base_revision"))?
        .as_object()
        .ok_or_else(|| anyhow!("active-home journal base_revision is not an object"))?;
    let generation = object
        .get("generation")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("active-home journal base generation is invalid"))?;
    let number = object.get("revision").and_then(Value::as_u64);
    let digest = object
        .get("document_sha256")
        .and_then(Value::as_str)
        .map(str::to_string);
    let generation = match generation {
        "missing" => {
            if number.is_some() || digest.is_some() {
                bail!("missing active-home journal revision carries evidence");
            }
            RevisionGeneration::Missing
        }
        "legacy" => RevisionGeneration::Legacy,
        "current" => RevisionGeneration::Current(
            number.ok_or_else(|| anyhow!("current active-home journal revision is missing"))?,
        ),
        _ => bail!("active-home journal base generation is invalid"),
    };
    Ok(Revision {
        generation,
        document_sha256: digest,
    })
}

fn layout_from_managed_layout(layout: &ManagedLayout) -> HomeLayoutBytes {
    let slot = |state: &SlotState| match state {
        SlotState::Absent => SlotBytes::absent(),
        SlotState::Exact { sha256 } => SlotBytes {
            bytes: None,
            digest: Some(sha256.clone()),
        },
    };
    HomeLayoutBytes {
        token: slot(&layout.antigravity_token),
        document: slot(&layout.gemini_authorized_user),
    }
}

fn layout_from_profile(profile: Option<&ActiveProfile>) -> HomeLayoutBytes {
    profile.map_or_else(HomeLayoutBytes::absent, |profile| {
        layout_from_managed_layout(&profile.managed_layout)
    })
}

fn slot_state_digest(slot: &SlotState) -> &str {
    match slot {
        SlotState::Absent => "",
        SlotState::Exact { sha256 } => sha256.as_str(),
    }
}

fn parse_layout(object: &Map<String, Value>, field: &str) -> Result<HomeLayoutBytes> {
    let value = object
        .get(field)
        .ok_or_else(|| anyhow!("active-home journal is missing {field}"))?;
    let layout: ManagedLayout = serde_json::from_value(value.clone())
        .with_context(|| format!("invalid active-home {field}"))?;
    Ok(layout_from_managed_layout(&layout))
}

fn validate_recovery_journal_shape(
    object: &Map<String, Value>,
    proof: &ActiveHomeJournalProof,
) -> Result<()> {
    const FIELDS: &[&str] = &[
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
    ];
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        bail!("active-home recovery journal has an unexpected field set");
    }
    if object.get("journal_version").and_then(Value::as_u64) != Some(1)
        || object.get("txid").and_then(Value::as_str) != Some(&proof.txid().to_string())
        || object.get("account_id").and_then(Value::as_str) != Some(proof.account_id())
    {
        bail!("active-home recovery journal identity does not match authority");
    }
    if !matches!(
        object.get("phase").and_then(Value::as_str),
        Some("prepared") | Some("publishing") | Some("published")
    ) {
        bail!("active-home recovery journal phase is invalid");
    }
    let before_profile = parse_profile(object, "before_profile")?;
    let after_profile = parse_profile(object, "after_profile")?;
    if before_profile != proof.before_profile().cloned()
        || after_profile != proof.after_profile().cloned()
    {
        bail!("active-home recovery profile evidence does not match authority");
    }
    if object.get("mode").and_then(Value::as_str) != Some(proof.adoption_mode()) {
        bail!("active-home recovery adoption mode does not match authority");
    }
    let target_ref = parse_target_ref(object)?;
    if target_ref != proof.target_ref().cloned() {
        bail!("active-home recovery target reference does not match authority");
    }
    let state_before = object
        .get("state_before_layout")
        .ok_or_else(|| anyhow!("active-home recovery journal is missing state_before_layout"))?;
    if layout_value(&proof.before_profile().cloned()) != *state_before {
        bail!("active-home recovery state-before layout is invalid");
    }
    let before = object
        .get("before_layout")
        .ok_or_else(|| anyhow!("active-home recovery journal is missing before_layout"))?;
    let after = object
        .get("after_layout")
        .ok_or_else(|| anyhow!("active-home recovery journal is missing after_layout"))?;
    if serde_json::to_value(proof.before_layout()).expect("layout serializable") != *before
        || serde_json::to_value(proof.after_layout()).expect("layout serializable") != *after
    {
        bail!("active-home recovery layout evidence is invalid");
    }
    let observed_before: ManagedLayout = serde_json::from_value(before.clone())?;
    let observed_after: ManagedLayout = serde_json::from_value(after.clone())?;
    if proof.adoption_mode() != "takeover" {
        if proof.before_profile().is_some()
            && layout_value(&proof.before_profile().cloned()) != *before
        {
            bail!("strict/adopt active-home recovery before layout differs from State");
        }
        if proof.before_profile().is_none()
            && proof.adoption_mode() == "adopt"
            && observed_before != observed_after
        {
            bail!("adopted first active-home recovery layout differs from target");
        }
        if proof.before_profile().is_none()
            && proof.adoption_mode() == "strict"
            && observed_before != ManagedLayout::default()
        {
            bail!("strict first active-home recovery layout must start empty");
        }
    }
    let before_layout = observed_before;
    let after_layout = observed_after;
    for (prefix, before_slot, after_slot) in [
        (
            "token",
            &before_layout.antigravity_token,
            &after_layout.antigravity_token,
        ),
        (
            "document",
            &before_layout.gemini_authorized_user,
            &after_layout.gemini_authorized_user,
        ),
    ] {
        if object
            .get(&format!("{prefix}_stage_digest"))
            .and_then(Value::as_str)
            != Some(slot_state_digest(after_slot))
            || object
                .get(&format!("{prefix}_tombstone_digest"))
                .and_then(Value::as_str)
                != Some(slot_state_digest(before_slot))
        {
            bail!("active-home recovery slot digest evidence is invalid");
        }
    }
    for (field, expected) in [
        (
            "token_stage",
            format!("{JOURNAL_PREFIX}{}{}", proof.txid(), STAGE_TOKEN_SUFFIX),
        ),
        (
            "document_stage",
            format!("{JOURNAL_PREFIX}{}{}", proof.txid(), STAGE_DOCUMENT_SUFFIX),
        ),
        (
            "token_tombstone",
            format!("{JOURNAL_PREFIX}{}{}", proof.txid(), TOMBSTONE_TOKEN_SUFFIX),
        ),
        (
            "document_tombstone",
            format!(
                "{JOURNAL_PREFIX}{}{}",
                proof.txid(),
                TOMBSTONE_DOCUMENT_SUFFIX
            ),
        ),
    ] {
        if object.get(field).and_then(Value::as_str) != Some(expected.as_str()) {
            bail!("active-home recovery locator {field} is invalid");
        }
    }
    for field in [
        "token_stage_digest",
        "token_tombstone_digest",
        "document_stage_digest",
        "document_tombstone_digest",
    ] {
        let digest = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("active-home recovery field {field} is invalid"))?;
        if !digest.is_empty() {
            crate::core::state::validate_sha256(field, digest)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::antigravity::account::credential_store::CredentialStore;
    use crate::core::atomic_io::NormalizedStoreRoot;
    use crate::core::credential::PortableCredential;
    use crate::core::state::{AccountType, CredentialRef, CredentialRefKind};
    use crate::core::state_store::{StateStore, StateStoreError};
    use std::fs;

    fn digest() -> String {
        "a".repeat(64)
    }

    /// 恢复路径必须按 journal 记下来的 mode 前滚。硬编码 `Adopt` 会让 takeover
    /// 事务在崩溃后走进删除 tombstone 的分支, 销毁用户仅存的那份陌生凭据。
    #[test]
    fn journal_mode_round_trips_and_unknown_values_fail_closed() {
        for mode in [
            AdoptionMode::Strict,
            AdoptionMode::Adopt,
            AdoptionMode::Takeover,
        ] {
            assert_eq!(journal_adoption_mode(mode.as_str()), mode);
        }
        // 未知/损坏取值按最严格的 Strict 处理, 不得被当成 takeover 而跳过清理,
        // 也不得被当成 adopt 而跳过搬运。
        for unknown in ["", "TAKEOVER", "adopt ", "unknown"] {
            assert_eq!(journal_adoption_mode(unknown), AdoptionMode::Strict);
        }
    }

    fn account_type(target: ActiveHomeTarget) -> AccountType {
        match target {
            ActiveHomeTarget::RawOauth | ActiveHomeTarget::AuthorizedUser => AccountType::OAuth,
            ActiveHomeTarget::Api => AccountType::ApiKey,
            ActiveHomeTarget::Vertex => AccountType::Vertex,
        }
    }

    fn reference_kind(target: ActiveHomeTarget) -> CredentialRefKind {
        match target {
            ActiveHomeTarget::RawOauth => CredentialRefKind::OauthAccessToken,
            ActiveHomeTarget::AuthorizedUser => CredentialRefKind::OauthAuthorizedUser,
            ActiveHomeTarget::Api => CredentialRefKind::ApiKey,
            ActiveHomeTarget::Vertex => CredentialRefKind::VertexServiceAccount,
        }
    }

    fn fixture_reference(account_id: &str, target: ActiveHomeTarget) -> CredentialRef {
        CredentialRef {
            kind: reference_kind(target),
            fingerprint: format!("sha256:{}", digest_bytes(account_id.as_bytes())),
        }
    }

    fn fixture_material(account_id: &str, target: ActiveHomeTarget) -> Option<Vec<u8>> {
        match target {
            ActiveHomeTarget::RawOauth => Some(format!("raw-{account_id}").into_bytes()),
            ActiveHomeTarget::AuthorizedUser => {
                Some(format!(r#"{{"authorized_user":"{account_id}"}}"#).into_bytes())
            }
            ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => None,
        }
    }

    fn fixture_account(
        account_id: &str,
        target: ActiveHomeTarget,
        reference: &CredentialRef,
    ) -> Value {
        serde_json::json!({
            "id": account_id,
            "email": format!("{account_id}@example.com"),
            "account_type": account_type(target),
            "provider_id": null,
            "project_id": null,
            "account_id": null,
            "plan": null,
            "added_at": 0,
            "updated_at": 0,
            "last_used_at": null,
            "credential_ref": reference,
        })
    }

    fn fixture_profile(
        account_id: &str,
        reference: &CredentialRef,
        scope: &str,
        target: ActiveHomeTarget,
        material: Option<&[u8]>,
    ) -> ActiveProfile {
        ActiveProfile {
            account_id: account_id.to_string(),
            credential_fingerprint: reference.fingerprint.clone(),
            home_scope_id: scope.to_string(),
            managed_layout: target.expected_layout(material.map(digest_bytes)),
        }
    }

    fn write_fixed_layout(
        cli: &Path,
        gemini: &Path,
        target: ActiveHomeTarget,
        material: Option<&[u8]>,
    ) {
        fs::create_dir_all(cli).unwrap();
        fs::create_dir_all(gemini).unwrap();
        match target {
            ActiveHomeTarget::RawOauth => {
                fs::write(cli.join(TOKEN_FILENAME), material.unwrap()).unwrap();
            }
            ActiveHomeTarget::AuthorizedUser => {
                fs::write(gemini.join(DOCUMENT_FILENAME), material.unwrap()).unwrap();
            }
            ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => {}
        }
    }

    fn run_cross_account_switch(from: ActiveHomeTarget, to: ActiveHomeTarget) {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let account_a_root = state_root.join("accounts").join("account-a");
        let account_b_root = state_root.join("accounts").join("account-b");
        fs::create_dir_all(&account_a_root).unwrap();
        fs::create_dir_all(&account_b_root).unwrap();
        let source = fixture_material("account-a", from);
        let target = fixture_material("account-b", to);
        if let Some(bytes) = target.as_deref() {
            match to {
                ActiveHomeTarget::RawOauth => {
                    fs::write(account_b_root.join(TOKEN_FILENAME), bytes).unwrap();
                }
                ActiveHomeTarget::AuthorizedUser => {
                    fs::write(account_b_root.join("credentials.json"), bytes).unwrap();
                }
                ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => unreachable!(),
            }
        }
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        write_fixed_layout(&cli_path, &gemini_path, from, source.as_deref());
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_reference = fixture_reference("account-a", from);
        let to_reference = fixture_reference("account-b", to);
        let before_profile = fixture_profile(
            "account-a",
            &from_reference,
            &scope,
            from,
            source.as_deref(),
        );
        let after_profile =
            fixture_profile("account-b", &to_reference, &scope, to, target.as_deref());
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", from, &from_reference),
                fixture_account("account-b", to, &to_reference),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before_profile,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after_profile.clone()),
                    Some(to_reference.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(Uuid::new_v4())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let published = prepared
                    .publish()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let proof = published
                    .journal_proof()
                    .map_err(StateStoreError::Invalid)?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.current_account_id = Some("account-b".to_string());
                candidate.active_profile = Some(after_profile.clone());
                let receipt = transaction.commit_coordinated_with_active(
                    &candidate,
                    Vec::new(),
                    Some(proof),
                )?;
                published
                    .finalize(&receipt)
                    .map_err(StateStoreError::Invalid)?;
                Ok(())
            })
            .unwrap();

        match to {
            ActiveHomeTarget::RawOauth => {
                assert_eq!(
                    fs::read(cli_path.join(TOKEN_FILENAME)).unwrap(),
                    target.unwrap()
                );
                assert!(!gemini_path.join(DOCUMENT_FILENAME).exists());
            }
            ActiveHomeTarget::AuthorizedUser => {
                assert!(!cli_path.join(TOKEN_FILENAME).exists());
                assert_eq!(
                    fs::read(gemini_path.join(DOCUMENT_FILENAME)).unwrap(),
                    target.unwrap()
                );
            }
            ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => {
                assert!(!cli_path.join(TOKEN_FILENAME).exists());
                assert!(!gemini_path.join(DOCUMENT_FILENAME).exists());
            }
        }
    }

    #[test]
    fn four_targets_have_the_complete_two_slot_matrix() {
        let targets = [
            ActiveHomeTarget::RawOauth,
            ActiveHomeTarget::AuthorizedUser,
            ActiveHomeTarget::Api,
            ActiveHomeTarget::Vertex,
        ];
        for from in targets {
            for to in targets {
                let material =
                    (!matches!(to, ActiveHomeTarget::Api | ActiveHomeTarget::Vertex)).then(digest);
                let layout = to.expected_layout(material);
                match to {
                    ActiveHomeTarget::RawOauth => {
                        assert!(matches!(layout.antigravity_token, SlotState::Exact { .. }));
                        assert!(matches!(layout.gemini_authorized_user, SlotState::Absent));
                    }
                    ActiveHomeTarget::AuthorizedUser => {
                        assert!(matches!(layout.antigravity_token, SlotState::Absent));
                        assert!(matches!(
                            layout.gemini_authorized_user,
                            SlotState::Exact { .. }
                        ));
                    }
                    ActiveHomeTarget::Api | ActiveHomeTarget::Vertex => {
                        assert_eq!(layout, ManagedLayout::default());
                    }
                }
                let _ = from;
            }
        }
    }

    #[test]
    fn cross_account_switch_exercises_all_sixteen_target_pairs() {
        let targets = [
            ActiveHomeTarget::RawOauth,
            ActiveHomeTarget::AuthorizedUser,
            ActiveHomeTarget::Api,
            ActiveHomeTarget::Vertex,
        ];
        for from in targets {
            for to in targets {
                run_cross_account_switch(from, to);
            }
        }
    }

    #[test]
    fn first_profile_requires_explicit_adopt_or_takeover() {
        let baseline = HomeLayoutBytes {
            token: SlotBytes {
                bytes: Some(b"token".to_vec()),
                digest: Some(digest_bytes(b"token")),
            },
            document: SlotBytes::absent(),
        };
        let matching = ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: "sha256:".to_string() + &digest(),
            home_scope_id: digest(),
            managed_layout: baseline.managed_layout(),
        };
        assert!(validate_first_profile_layout(&baseline, None, AdoptionMode::Strict).is_err());
        assert!(
            validate_first_profile_layout(&baseline, Some(&matching), AdoptionMode::Adopt).is_ok()
        );
        let mismatch = ActiveProfile {
            managed_layout: ManagedLayout::default(),
            ..matching.clone()
        };
        assert!(
            validate_first_profile_layout(&baseline, Some(&mismatch), AdoptionMode::Adopt).is_err()
        );
        let dual = HomeLayoutBytes {
            token: baseline.token.clone(),
            document: SlotBytes {
                bytes: Some(b"document".to_vec()),
                digest: Some(digest_bytes(b"document")),
            },
        };
        assert!(
            validate_first_profile_layout(&dual, Some(&matching), AdoptionMode::Strict).is_err()
        );
        assert!(
            validate_first_profile_layout(&dual, Some(&mismatch), AdoptionMode::Takeover).is_ok()
        );
    }

    #[test]
    fn existing_profile_mismatch_requires_and_records_takeover() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        fs::create_dir_all(state_root.join("accounts").join("account-a")).unwrap();
        let account_b_root = state_root.join("accounts").join("account-b");
        fs::create_dir_all(&account_b_root).unwrap();
        let target = b"target-token".to_vec();
        fs::write(account_b_root.join(TOKEN_FILENAME), &target).unwrap();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        fs::create_dir_all(&cli_path).unwrap();
        fs::create_dir_all(&gemini_path).unwrap();
        fs::write(cli_path.join(TOKEN_FILENAME), b"unmanaged-token").unwrap();
        fs::write(gemini_path.join(DOCUMENT_FILENAME), b"unmanaged-document").unwrap();
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::RawOauth);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::RawOauth);
        let before = fixture_profile(
            "account-a",
            &from_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(b"state-token"),
        );
        let after = fixture_profile(
            "account-b",
            &to_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&target),
        );
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::RawOauth, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::RawOauth, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                assert!(homes.prepare(Uuid::new_v4()).is_err());
                Ok(())
            })
            .unwrap();

        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare_takeover(Uuid::new_v4())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let published = prepared
                    .publish()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let proof = published
                    .journal_proof()
                    .map_err(StateStoreError::Invalid)?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.current_account_id = Some("account-b".to_string());
                candidate.active_profile = Some(after.clone());
                let receipt = transaction.commit_coordinated_with_active(
                    &candidate,
                    Vec::new(),
                    Some(proof),
                )?;
                published
                    .finalize(&receipt)
                    .map_err(StateStoreError::Invalid)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(fs::read(cli_path.join(TOKEN_FILENAME)).unwrap(), target);
        assert!(!gemini_path.join(DOCUMENT_FILENAME).exists());
    }

    #[test]
    fn first_profile_empty_root_switches_and_receipt_finalizes() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let account_root = state_root.join("accounts").join("acc-1");
        fs::create_dir_all(&account_root).unwrap();
        let credential = PortableCredential::oauth_access_token("active-token").unwrap();
        // Raw OAuth material is intentionally the fixed token file, not the
        // native JSON representation used by authorized-user credentials.
        let source = credential.access_token().unwrap().as_bytes().to_vec();
        fs::write(account_root.join(TOKEN_FILENAME), &source).unwrap();
        let reference = CredentialRef {
            kind: CredentialRefKind::OauthAccessToken,
            fingerprint: credential.fingerprint(),
        };
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [{
                "id": "acc-1",
                "email": "user@example.com",
                "account_type": "oauth",
                "added_at": 0,
                "updated_at": 0,
                "last_used_at": null,
                "credential_ref": reference.clone(),
            }],
            "usage_cache": {},
            "current_account_id": null,
            "active_profile": null,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        let cli = NormalizedStoreRoot::normalize(&temp.path().join("cli-home")).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&temp.path().join("gemini-home")).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let layout = ManagedLayout {
            antigravity_token: SlotState::Exact {
                sha256: digest_bytes(&source),
            },
            ..ManagedLayout::default()
        };
        let profile = ActiveProfile {
            account_id: "acc-1".to_string(),
            credential_fingerprint: reference.fingerprint.clone(),
            home_scope_id: scope,
            managed_layout: layout,
        };
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(profile.clone()),
                    Some(reference.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(crate::core::state_store::StateStoreError::Invalid)?;
                let prepared = homes.prepare(Uuid::new_v4()).map_err(|error| {
                    crate::core::state_store::StateStoreError::Invalid(anyhow!(error))
                })?;
                let published = prepared.publish().map_err(|error| {
                    crate::core::state_store::StateStoreError::Invalid(anyhow!(error))
                })?;
                let proof = published
                    .journal_proof()
                    .map_err(crate::core::state_store::StateStoreError::Invalid)?;
                let journal_path = account_root.join(format!(
                    "{JOURNAL_PREFIX}{}{JOURNAL_SUFFIX}",
                    published.txid()
                ));
                let journal_bytes = fs::read(&journal_path).unwrap();
                let journal_text = String::from_utf8(journal_bytes.clone()).unwrap();
                assert!(
                    !journal_bytes
                        .windows(source.len())
                        .any(|window| window == source.as_slice())
                );
                assert!(!journal_text.contains(cli.as_path().to_string_lossy().as_ref()));
                assert!(!journal_text.contains(gemini.as_path().to_string_lossy().as_ref()));
                assert!(journal_text.contains(&format!("{JOURNAL_PREFIX}{}", published.txid())));
                assert!(journal_text.contains(&digest_bytes(&source)));
                let mut candidate = transaction.snapshot()?.state;
                candidate.current_account_id = Some("acc-1".to_string());
                candidate.active_profile = Some(profile);
                let receipt = transaction.commit_coordinated_with_active(
                    &candidate,
                    Vec::new(),
                    Some(proof),
                )?;
                published
                    .finalize(&receipt)
                    .map_err(crate::core::state_store::StateStoreError::Invalid)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            fs::read(temp.path().join("cli-home").join(TOKEN_FILENAME)).unwrap(),
            source
        );
    }

    #[test]
    fn deleting_current_account_commits_both_slots_absent() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let account_root = state_root.join("accounts").join("account-a");
        fs::create_dir_all(&account_root).unwrap();
        let credential = PortableCredential::oauth_access_token("delete-me").unwrap();
        let source = credential.access_token().unwrap().as_bytes().to_vec();
        fs::write(account_root.join(TOKEN_FILENAME), &source).unwrap();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        fs::create_dir_all(&cli_path).unwrap();
        fs::create_dir_all(&gemini_path).unwrap();
        fs::write(cli_path.join(TOKEN_FILENAME), &source).unwrap();
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let reference = CredentialRef {
            kind: CredentialRefKind::OauthAccessToken,
            fingerprint: credential.fingerprint(),
        };
        let profile = fixture_profile(
            "account-a",
            &reference,
            &active_home_scope_id(&cli, &gemini),
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [fixture_account(
                "account-a",
                ActiveHomeTarget::RawOauth,
                &reference,
            )],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": profile,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let credential_permit = transaction.credential_mutation_permit("account-a")?;
                let credential_store = CredentialStore::from_permit(credential_permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let credential_layout = credential_store
                    .read_layout()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let txid = Uuid::new_v4();
                let credential_prepared = credential_store
                    .stage_delete(txid, &credential_layout.expected_layout())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let credential_published = credential_store
                    .publish(credential_prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let credential_proof = credential_store
                    .journal_proof(&credential_published)
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let permit = transaction
                    .active_home_mutation_permit_with_ref(None, Some(reference.clone()))?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(txid)
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let published = prepared
                    .publish()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let proof = published
                    .journal_proof()
                    .map_err(StateStoreError::Invalid)?;
                let mut candidate = transaction.snapshot()?.state;
                candidate
                    .accounts
                    .retain(|account| account.id != "account-a");
                candidate.credential_refs.remove("account-a");
                candidate.current_account_id = None;
                candidate.active_profile = None;
                let receipt = transaction.commit_coordinated_with_active(
                    &candidate,
                    vec![credential_proof],
                    Some(proof),
                )?;
                published
                    .finalize(&receipt)
                    .map_err(StateStoreError::Invalid)?;
                credential_store
                    .finalize(credential_published, &receipt)
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                Ok(())
            })
            .unwrap();
        assert!(!temp.path().join("cli-home").join(TOKEN_FILENAME).exists());
        assert!(
            !temp
                .path()
                .join("gemini-home")
                .join(DOCUMENT_FILENAME)
                .exists()
        );
    }

    #[test]
    fn ordinary_receipt_cannot_finalize_active_home_journal() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let account_a_root = state_root.join("accounts").join("account-a");
        let account_b_root = state_root.join("accounts").join("account-b");
        fs::create_dir_all(&account_a_root).unwrap();
        fs::create_dir_all(&account_b_root).unwrap();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        fs::create_dir_all(&cli_path).unwrap();
        fs::create_dir_all(&gemini_path).unwrap();
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::Api);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::Api);
        let before = fixture_profile("account-a", &from_ref, &scope, ActiveHomeTarget::Api, None);
        let after = fixture_profile("account-b", &to_ref, &scope, ActiveHomeTarget::Api, None);
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::Api, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::Api, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction
                    .active_home_mutation_permit_with_ref(Some(after.clone()), Some(to_ref))?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(Uuid::new_v4())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let published = prepared
                    .publish()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let ordinary_receipt =
                    transaction.commit_exact_receipt(&transaction.snapshot()?.state)?;
                if published.finalize(&ordinary_receipt).is_ok() {
                    return Err(StateStoreError::Invalid(anyhow!(
                        "ordinary receipt unexpectedly finalized active-home"
                    )));
                }
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn restart_recovery_with_current_before_state_rolls_back_published_home() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        fs::create_dir_all(state_root.join("accounts").join("account-a")).unwrap();
        fs::create_dir_all(state_root.join("accounts").join("account-b")).unwrap();
        let source = b"recovery-source".to_vec();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        fs::create_dir_all(&cli_path).unwrap();
        fs::create_dir_all(&gemini_path).unwrap();
        fs::write(cli_path.join(TOKEN_FILENAME), &source).unwrap();
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::RawOauth);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::Api);
        let before = fixture_profile(
            "account-a",
            &from_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let after = fixture_profile("account-b", &to_ref, &scope, ActiveHomeTarget::Api, None);
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::RawOauth, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::Api, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        let txid = store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(Uuid::new_v4())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let published = prepared
                    .publish()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                Ok(published.txid())
            })
            .unwrap();
        assert!(!cli_path.join(TOKEN_FILENAME).exists());
        assert!(
            state_root
                .join("accounts")
                .join("account-b")
                .join(format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}"))
                .exists()
        );

        let after_publish = store.read().unwrap();
        let result = store
            .with_locked_exact(&after_publish.revision, |transaction| {
                let authority = transaction.active_home_recovery_authority()?;
                let permit = transaction.active_home_recovery_permit("account-b")?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                recover_pending(homes, authority, txid).map_err(StateStoreError::Invalid)
            })
            .unwrap();
        assert_eq!(result, ActiveHomeRecoveryState::RolledBack);
        assert_eq!(fs::read(cli_path.join(TOKEN_FILENAME)).unwrap(), source);
        assert!(
            !state_root
                .join("accounts")
                .join("account-b")
                .join(format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}"))
                .exists()
        );
    }

    #[test]
    fn restart_recovery_cleans_a_prepared_active_home_journal() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        fs::create_dir_all(state_root.join("accounts").join("account-a")).unwrap();
        fs::create_dir_all(state_root.join("accounts").join("account-b")).unwrap();
        let source = b"prepared-source".to_vec();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        fs::create_dir_all(&cli_path).unwrap();
        fs::create_dir_all(&gemini_path).unwrap();
        fs::write(cli_path.join(TOKEN_FILENAME), &source).unwrap();
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::RawOauth);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::Api);
        let before = fixture_profile(
            "account-a",
            &from_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let after = fixture_profile("account-b", &to_ref, &scope, ActiveHomeTarget::Api, None);
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::RawOauth, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::Api, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        let txid = store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(Uuid::new_v4())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let txid = prepared.txid();
                drop(prepared);
                Ok(txid)
            })
            .unwrap();
        let journal = state_root
            .join("accounts")
            .join("account-b")
            .join(format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}"));
        assert!(journal.exists());
        assert_eq!(fs::read(cli_path.join(TOKEN_FILENAME)).unwrap(), source);

        let current = store.read().unwrap();
        let result = store
            .with_locked_exact(&current.revision, |transaction| {
                let authority = transaction.active_home_recovery_authority()?;
                let permit = transaction.active_home_recovery_permit("account-b")?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                recover_pending(homes, authority, txid).map_err(StateStoreError::Invalid)
            })
            .unwrap();
        assert_eq!(result, ActiveHomeRecoveryState::RolledBack);
        assert_eq!(fs::read(cli_path.join(TOKEN_FILENAME)).unwrap(), source);
        assert!(!journal.exists());
    }

    #[test]
    fn restart_recovery_with_current_after_state_finalizes_home() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        fs::create_dir_all(state_root.join("accounts").join("account-a")).unwrap();
        fs::create_dir_all(state_root.join("accounts").join("account-b")).unwrap();
        let source = b"finalize-source".to_vec();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        fs::create_dir_all(&cli_path).unwrap();
        fs::create_dir_all(&gemini_path).unwrap();
        fs::write(cli_path.join(TOKEN_FILENAME), &source).unwrap();
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::RawOauth);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::Api);
        let before = fixture_profile(
            "account-a",
            &from_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let after = fixture_profile("account-b", &to_ref, &scope, ActiveHomeTarget::Api, None);
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::RawOauth, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::Api, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::create_dir_all(&state_root).unwrap();
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        let txid = store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(Uuid::new_v4())
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let published = prepared
                    .publish()
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                let proof = published
                    .journal_proof()
                    .map_err(StateStoreError::Invalid)?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.current_account_id = Some("account-b".to_string());
                candidate.active_profile = Some(after.clone());
                let _receipt = transaction.commit_coordinated_with_active(
                    &candidate,
                    Vec::new(),
                    Some(proof),
                )?;
                Ok(published.txid())
            })
            .unwrap();
        assert!(!cli_path.join(TOKEN_FILENAME).exists());
        let after_commit = store.read().unwrap();
        let result = store
            .with_locked_exact(&after_commit.revision, |transaction| {
                let authority = transaction.active_home_recovery_authority()?;
                let permit = transaction.active_home_recovery_permit("account-b")?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                recover_pending(homes, authority, txid).map_err(StateStoreError::Invalid)
            })
            .unwrap();
        assert_eq!(result, ActiveHomeRecoveryState::Finalized);
        assert!(!cli_path.join(TOKEN_FILENAME).exists());
        assert!(!gemini_path.join(DOCUMENT_FILENAME).exists());
        assert!(
            !state_root
                .join("accounts")
                .join("account-b")
                .join(format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}"))
                .exists()
        );
    }

    /// AC-3.2 的调用点版本：sweep 跑在生产入口 `ActiveHomeStore::open` 上时，
    /// 只删无主 stage，仍有 journal 的在途事务文件一个都不能少。
    ///
    /// 与下面那个纯函数用例的区别是：这里走的是真实的 journal 扫描 + capability
    /// 删除路径，而不是把一份手工构造的 `live` 集合喂给 `orphan_stage_names`。
    /// 注意不能用 CLI 端到端来断言这条性质——任何留在 accounts/ 下的 journal 都会
    /// 在同一条命令里被 recovery 认领并连同 stage 一起清掉，"还在"这个断言在命令
    /// 结束时必然为假。所以观察点只能停在 open() 之后。
    #[test]
    fn store_open_sweep_keeps_the_stage_of_an_in_flight_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let account_b_root = state_root.join("accounts").join("account-b");
        fs::create_dir_all(state_root.join("accounts").join("account-a")).unwrap();
        fs::create_dir_all(&account_b_root).unwrap();
        let source = fixture_material("account-a", ActiveHomeTarget::RawOauth).unwrap();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        write_fixed_layout(
            &cli_path,
            &gemini_path,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::RawOauth);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::Api);
        let before = fixture_profile(
            "account-a",
            &from_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let after = fixture_profile("account-b", &to_ref, &scope, ActiveHomeTarget::Api, None);
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::RawOauth, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::Api, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        // 进行中的事务：journal 还躺在账号目录里，它的两份 stage 都必须活下来。
        let in_flight = Uuid::new_v4();
        let orphan = Uuid::new_v4();
        fs::write(
            account_b_root.join(format!("{JOURNAL_PREFIX}{in_flight}{JOURNAL_SUFFIX}")),
            b"{}",
        )
        .unwrap();
        let protected_token =
            cli_path.join(format!("{JOURNAL_PREFIX}{in_flight}{STAGE_TOKEN_SUFFIX}"));
        let protected_document = gemini_path.join(format!(
            "{JOURNAL_PREFIX}{in_flight}{STAGE_DOCUMENT_SUFFIX}"
        ));
        let doomed_token = cli_path.join(format!("{JOURNAL_PREFIX}{orphan}{STAGE_TOKEN_SUFFIX}"));
        let doomed_document =
            gemini_path.join(format!("{JOURNAL_PREFIX}{orphan}{STAGE_DOCUMENT_SUFFIX}"));
        fs::write(&protected_token, b"in-flight-token").unwrap();
        fs::write(&protected_document, b"in-flight-document").unwrap();
        fs::write(&doomed_token, b"orphan-token").unwrap();
        fs::write(&doomed_document, b"orphan-document").unwrap();

        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                // open 自己就会跑一次 sweep，这里不需要再做别的。
                ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                    .map_err(StateStoreError::Invalid)?;
                Ok(())
            })
            .unwrap();

        assert!(
            !doomed_token.exists() && !doomed_document.exists(),
            "the sweep did not run: orphan stage plaintext survived"
        );
        assert_eq!(fs::read(&protected_token).unwrap(), b"in-flight-token");
        assert_eq!(
            fs::read(&protected_document).unwrap(),
            b"in-flight-document"
        );
    }

    /// AC-3.2：只清理无主 stage；仍有 journal 的 txid 与含凭据的
    /// tombstone/recovery 一律不碰。
    #[test]
    fn orphan_stage_sweep_only_targets_stages_without_a_journal() {
        let root = tempfile::tempdir().unwrap();
        let pending = Uuid::new_v4();
        let orphan = Uuid::new_v4();
        for txid in [pending, orphan] {
            for suffix in [STAGE_TOKEN_SUFFIX, STAGE_DOCUMENT_SUFFIX] {
                fs::write(
                    root.path().join(format!("{JOURNAL_PREFIX}{txid}{suffix}")),
                    b"x",
                )
                .unwrap();
            }
        }
        for suffix in [TOMBSTONE_TOKEN_SUFFIX, RECOVERY_TOKEN_SUFFIX] {
            fs::write(
                root.path()
                    .join(format!("{JOURNAL_PREFIX}{orphan}{suffix}")),
                b"x",
            )
            .unwrap();
        }
        fs::write(root.path().join(TOKEN_FILENAME), b"x").unwrap();
        fs::write(
            root.path()
                .join(format!("{JOURNAL_PREFIX}not-a-uuid{STAGE_TOKEN_SUFFIX}")),
            b"x",
        )
        .unwrap();
        // 陌生的非普通文件（目录 / 悬空 symlink）只能被跳过：既不能进删除名单，
        // 也不能让类型判定报错——恢复路径上的一次硬失败会把每条 sagy 命令变成 rc=1。
        let intruder_directory = Uuid::new_v4();
        fs::create_dir(root.path().join(format!(
            "{JOURNAL_PREFIX}{intruder_directory}{STAGE_TOKEN_SUFFIX}"
        )))
        .unwrap();
        #[cfg(unix)]
        {
            let dangling = Uuid::new_v4();
            std::os::unix::fs::symlink(
                root.path().join("this-target-does-not-exist"),
                root.path()
                    .join(format!("{JOURNAL_PREFIX}{dangling}{STAGE_DOCUMENT_SUFFIX}")),
            )
            .unwrap();
        }

        let live = BTreeSet::from([pending]);
        let mut names = orphan_stage_names(root.path(), &live).unwrap().unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![
                format!("{JOURNAL_PREFIX}{orphan}{STAGE_DOCUMENT_SUFFIX}"),
                format!("{JOURNAL_PREFIX}{orphan}{STAGE_TOKEN_SUFFIX}"),
            ]
        );
    }

    /// AC-2.3：`publish` 在搬动用户真实凭据之前，必须把 `publishing` 相位真的写到
    /// 磁盘上的 journal 里。
    ///
    /// 这个用例不读任何内部字段：它让 stage -> 目标文件那一步真的失败，然后把账号
    /// 目录里那份 journal 的字节读出来断言 `phase`。只要 `publish_inner` 少写一次
    /// journal，磁盘上留下的就仍然是 `prepared`，用例立刻变红。
    #[test]
    fn publish_persists_the_publishing_phase_before_moving_live_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let account_b_root = state_root.join("accounts").join("account-b");
        fs::create_dir_all(state_root.join("accounts").join("account-a")).unwrap();
        fs::create_dir_all(&account_b_root).unwrap();
        // 同槽位切换：A 与 B 同为 raw OAuth token，publish 必须先 tombstone 再 move。
        let source = fixture_material("account-a", ActiveHomeTarget::RawOauth).unwrap();
        let target = fixture_material("account-b", ActiveHomeTarget::RawOauth).unwrap();
        fs::write(account_b_root.join(TOKEN_FILENAME), &target).unwrap();
        let cli_path = temp.path().join("cli-home");
        let gemini_path = temp.path().join("gemini-home");
        write_fixed_layout(
            &cli_path,
            &gemini_path,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let cli = NormalizedStoreRoot::normalize(&cli_path).unwrap();
        let gemini = NormalizedStoreRoot::normalize(&gemini_path).unwrap();
        let scope = active_home_scope_id(&cli, &gemini);
        let from_ref = fixture_reference("account-a", ActiveHomeTarget::RawOauth);
        let to_ref = fixture_reference("account-b", ActiveHomeTarget::RawOauth);
        let before = fixture_profile(
            "account-a",
            &from_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&source),
        );
        let after = fixture_profile(
            "account-b",
            &to_ref,
            &scope,
            ActiveHomeTarget::RawOauth,
            Some(&target),
        );
        let state = serde_json::json!({
            "version": 2,
            "revision": 1,
            "accounts": [
                fixture_account("account-a", ActiveHomeTarget::RawOauth, &from_ref),
                fixture_account("account-b", ActiveHomeTarget::RawOauth, &to_ref),
            ],
            "usage_cache": {},
            "current_account_id": "account-a",
            "active_profile": before,
            "sync_watermarks": {},
        });
        fs::write(
            state_root.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();

        let txid = Uuid::new_v4();
        let journal_path = account_b_root.join(format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}"));
        let stage_path = cli_path.join(format!("{JOURNAL_PREFIX}{txid}{STAGE_TOKEN_SUFFIX}"));
        let tombstone_path =
            cli_path.join(format!("{JOURNAL_PREFIX}{txid}{TOMBSTONE_TOKEN_SUFFIX}"));

        let store = StateStore::open(&state_root).unwrap();
        let read = store.read().unwrap();
        store
            .with_locked_exact(&read.revision, |transaction| {
                let permit = transaction.active_home_mutation_permit_with_ref(
                    Some(after.clone()),
                    Some(to_ref.clone()),
                )?;
                let homes =
                    ActiveHomeStore::from_permit_with_roots(permit, cli.clone(), gemini.clone())
                        .map_err(StateStoreError::Invalid)?;
                let prepared = homes
                    .prepare(txid)
                    .map_err(|error| StateStoreError::Invalid(anyhow!(error)))?;
                assert_eq!(
                    journal_phase(&journal_path),
                    "prepared",
                    "prepare must leave a prepared journal"
                );
                // 让 stage -> 目标文件那一步失败：publish 会在 tombstone 之后中断，
                // 正好停在 `publishing` 窗口里。
                fs::remove_file(&stage_path).unwrap();
                let token = match prepared.publish() {
                    Ok(_) => panic!("publish must fail once the stage is gone"),
                    Err(ActiveHomeError::ReconcileRequired { token, .. }) => token,
                    Err(error) => panic!("unexpected publish failure: {error}"),
                };
                assert!(
                    tombstone_path.exists(),
                    "publish must tombstone the live credential"
                );
                assert!(!cli_path.join(TOKEN_FILENAME).exists());
                assert_eq!(
                    journal_phase(&journal_path),
                    "publishing",
                    "publish must persist the publishing phase before moving credentials"
                );
                restore_reconcile(token).map_err(StateStoreError::Invalid)?;
                Ok(())
            })
            .unwrap();

        assert_eq!(fs::read(cli_path.join(TOKEN_FILENAME)).unwrap(), source);
        assert!(!tombstone_path.exists());
        assert!(!journal_path.exists());
    }

    fn journal_phase(journal: &Path) -> String {
        let value: Value = serde_json::from_slice(&fs::read(journal).unwrap()).unwrap();
        value["phase"].as_str().unwrap().to_string()
    }

    #[test]
    fn journal_artifact_names_round_trip_through_the_txid_parser() {
        let txid = Uuid::new_v4();
        let journal = format!("{JOURNAL_PREFIX}{txid}{JOURNAL_SUFFIX}");
        assert_eq!(journal_txid(&journal), Some(txid));
        assert_eq!(journal_txid(&journal.to_uppercase()), None);
        assert_eq!(
            journal_txid(&format!("{JOURNAL_PREFIX}{JOURNAL_SUFFIX}")),
            None
        );
        assert_eq!(
            parse_artifact_txid(
                &journal_artifact(txid, STAGE_TOKEN_SUFFIX)
                    .unwrap()
                    .to_slash_string()
                    .unwrap(),
                STAGE_TOKEN_SUFFIX,
            ),
            Some(txid)
        );
    }
}
