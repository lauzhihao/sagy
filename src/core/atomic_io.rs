//! Typed filesystem primitives for the state store.
//!
//! The store root and every locator used by a mutation are represented by
//! private-field newtypes. This keeps a raw `Path` from accidentally reaching
//! an operation that can create or replace state.

#![allow(dead_code)]

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::io;

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use sha2::{Digest as ShaDigest, Sha256};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as WindowsOpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(unix)]
#[link(name = "c")]
unsafe extern "C" {
    fn geteuid() -> u32;
}

/// 等待超过这个时长仍拿不到 flock，就认为用户已经在"卡住"了，必须给出诊断。
const LOCK_WAIT_NOTICE_DELAY: Duration = Duration::from_millis(750);
/// 轮询间隔上限：等待期间不做忙等，最长一次睡这么久。
const LOCK_WAIT_POLL_CAP: Duration = Duration::from_millis(50);
/// 控制台输出必须是 ASCII。
const LOCK_WAIT_NOTICE: &str = "[sagy] waiting for another sagy session to release a lock; this command will continue \
automatically once that session finishes.";

/// 提示在一个进程内至多打印一次：一条命令可能连续拿好几把锁，重复刷屏没有
/// 任何新增信息。
static LOCK_WAIT_NOTICE_EMITTED: AtomicBool = AtomicBool::new(false);

fn emit_lock_wait_notice() {
    if LOCK_WAIT_NOTICE_EMITTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut stderr = std::io::stderr().lock();
    // 提示失败不能影响加锁本身的结果。
    let _ = writeln!(stderr, "{LOCK_WAIT_NOTICE}");
    let _ = stderr.flush();
}

fn lock_is_contended(error: &std::io::Error) -> bool {
    error.kind() == fs2::lock_contended_error().kind() || error.kind() == ErrorKind::WouldBlock
}

/// 在 `delay` 之内轮询 `file` 的独占锁。
///
/// 返回 `Ok(true)` 表示锁已经被本调用持有；`Ok(false)` 表示到点仍未拿到，
/// 此时 `announce` 已经被调用过恰好一次。
///
/// 为什么是轮询而不是"后台线程 + Condvar"：后台线程方案需要在主线程完成后
/// 唤醒并 join，一旦唤醒发生在等待开始之前，通知就丢了，主线程会在**快路径上**
/// 也被 join 拖满一整个阈值。这里没有任何跨线程通知，结构上不存在那条竞态。
fn poll_exclusive_lock<A>(file: &File, delay: Duration, announce: &mut A) -> std::io::Result<bool>
where
    A: FnMut(),
{
    // 快路径：锁立刻可得时只多一次非阻塞系统调用，不睡、不起线程、不打印。
    match file.try_lock_exclusive() {
        Ok(()) => return Ok(true),
        Err(error) if lock_is_contended(&error) => {}
        Err(error) => return Err(error),
    }
    let deadline = Instant::now() + delay;
    let mut backoff = Duration::from_millis(2);
    while Instant::now() < deadline {
        std::thread::sleep(backoff.min(LOCK_WAIT_POLL_CAP));
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(true),
            Err(error) if lock_is_contended(&error) => {}
            Err(error) => return Err(error),
        }
        backoff = backoff.saturating_mul(2);
    }
    announce();
    Ok(false)
}

/// Acquire `file`'s exclusive lock, emitting one ASCII diagnostic when the
/// wait exceeds `LOCK_WAIT_NOTICE_DELAY`.
pub(crate) fn lock_exclusive_with_wait_notice(file: &File) -> std::io::Result<()> {
    if poll_exclusive_lock(file, LOCK_WAIT_NOTICE_DELAY, &mut emit_lock_wait_notice)? {
        return Ok(());
    }
    file.lock_exclusive()
}

/// Announce a pending lock wait for callers that acquire the lock themselves.
///
/// 上层有些调用点先拿到句柄、再自己 `lock_exclusive`（切号路径就是这样）。
/// 这里只做一次非阻塞探测：锁立刻可得就原样放行（探测拿到的锁会立刻释放，
/// 真正的持有仍由调用方完成）；确实被别的会话占着，才在阈值之后打印提示。
pub(crate) fn announce_lock_wait_before_blocking(file: &File) {
    if let Ok(true) = poll_exclusive_lock(file, LOCK_WAIT_NOTICE_DELAY, &mut emit_lock_wait_notice)
    {
        let _ = FileExt::unlock(file);
    }
}

const MAX_LOCATOR_COMPONENT_BYTES: usize = 255;
const MAX_LOCATOR_BYTES: usize = 4096;

/// A canonical absolute root used by read-only operations.
///
/// The field is private on purpose. Values can only be made through
/// [`NormalizedStoreRoot::normalize`], which rejects relative paths, roots,
/// parent components, and a symlink at the final component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NormalizedStoreRoot {
    path: PathBuf,
    creation_anchor: PathBuf,
    missing_suffix: Vec<OsString>,
}

/// Stable identity used to close the preflight-to-adoption race.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RootIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { volume_serial: u32, file_index: u64 },
}

impl NormalizedStoreRoot {
    /// Normalize an absolute store-root candidate without creating it.
    pub(crate) fn normalize(path: &Path) -> Result<Self> {
        validate_root_candidate(path)?;

        let mut candidate = path.to_path_buf();
        let mut missing = Vec::<OsString>::new();
        let existing_ancestor = loop {
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    if is_link_or_reparse(&metadata) {
                        if missing.is_empty() {
                            bail!(
                                "store root final component cannot be a symlink or reparse point: {}",
                                candidate.display()
                            )
                        }
                        #[cfg(windows)]
                        {
                            // Junctions are reparse points too.  Resolving an
                            // existing ancestor on Windows would let a root
                            // silently escape the path that was validated.
                            bail!(
                                "store root ancestor cannot be a symlink or reparse point: {}",
                                candidate.display()
                            )
                        }
                        // An external ancestor may be a symlink or reparse
                        // point (notably macOS /tmp). canonicalize below
                        // resolves it before any missing component is appended.
                    } else if !metadata.is_dir() {
                        bail!(
                            "store root component is not a directory: {}",
                            candidate.display()
                        )
                    }
                    break candidate;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    let name = candidate.file_name().ok_or_else(|| {
                        anyhow!(
                            "store root has no normal component: {}",
                            candidate.display()
                        )
                    })?;
                    missing.push(name.to_os_string());
                    candidate = candidate
                        .parent()
                        .ok_or_else(|| anyhow!("store root has no existing ancestor"))?
                        .to_path_buf();
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect store root: {}", candidate.display())
                    });
                }
            }
        };

        let canonical_ancestor = fs::canonicalize(&existing_ancestor).with_context(|| {
            format!(
                "failed to canonicalize store root ancestor: {}",
                existing_ancestor.display()
            )
        })?;
        let ancestor_metadata = fs::metadata(&canonical_ancestor).with_context(|| {
            format!(
                "failed to inspect canonical store root ancestor: {}",
                canonical_ancestor.display()
            )
        })?;
        if !ancestor_metadata.is_dir() {
            bail!(
                "canonical store root ancestor is not a directory: {}",
                canonical_ancestor.display()
            )
        }
        let missing_suffix: Vec<OsString> = missing.iter().rev().cloned().collect();
        let mut normalized = canonical_ancestor.clone();
        for component in &missing_suffix {
            normalized.push(component);
        }

        // A concurrent creator may have installed a final link while the
        // missing suffix was being assembled. Recheck without following it.
        if let Some(metadata) = inspect_component(&normalized, "normalized store root")? {
            if is_link_or_reparse(&metadata) {
                bail!(
                    "store root final component cannot be a symlink or reparse point: {}",
                    normalized.display()
                )
            }
            if !metadata.is_dir() {
                bail!(
                    "normalized store root is not a directory: {}",
                    normalized.display()
                )
            }
        }

        Ok(Self {
            path: normalized,
            creation_anchor: canonical_ancestor,
            missing_suffix,
        })
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }
}

/// A root that has passed the ownership-claim policy and may be mutated.
///
/// It cannot be constructed from a raw path. Callers must normalize first,
/// then claim the resulting root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedStoreRoot {
    path: PathBuf,
    identity: RootIdentity,
}

impl OwnedStoreRoot {
    /// Claim a missing root or an existing empty root.
    pub(crate) fn claim(root: impl Into<NormalizedStoreRoot>) -> Result<Self> {
        let NormalizedStoreRoot {
            path,
            creation_anchor,
            missing_suffix,
        } = root.into();
        reject_protected_claim_path(&path)?;

        if !missing_suffix.is_empty() {
            secure_create_missing_suffix(&creation_anchor, &missing_suffix)?;
        }

        let metadata = inspect_component(&path, "store root")?
            .ok_or_else(|| anyhow!("store root was not created: {}", path.display()))?;
        if is_link_or_reparse(&metadata) {
            bail!(
                "store root cannot be a symlink or reparse point: {}",
                path.display()
            )
        }
        if !metadata.is_dir() {
            bail!("store root is not a directory: {}", path.display())
        }

        if !directory_is_empty(&path)? {
            // This check intentionally precedes any chmod. A non-empty
            // directory is never silently converted into an owned store.
            bail!("cannot claim non-empty store root: {}", path.display())
        }

        // Always verify the final metadata, including a root created in this
        // call. This closes the gap where a racing creator could otherwise
        // bypass the Unix owner/mode policy.
        verify_existing_root_ownership(&metadata, &path)?;
        secure_existing_directory(&path, &metadata)?;
        let identity = root_identity_from_path(&path)?;
        Ok(Self { path, identity })
    }

    /// Adopt a populated root after the higher-level adoption protocol has
    /// completed its identity, inventory, journal, and semantic checks.
    ///
    /// This low-level boundary is deliberately unsafe because the filesystem
    /// type alone cannot prove that the caller has exclusive ownership of the
    /// fixed lock or that the non-empty directory is the intended store. The
    /// only production caller is `AtomicStore::adopt_existing_with`, which
    /// performs those checks while retaining the same lock handle.
    ///
    /// # Safety
    ///
    /// The caller must hold the target-derived fixed lock exclusively for the
    /// entire call and must not release it until all subsequent adoption
    /// cleanup and use of the returned root are complete. Before entering this
    /// function, the caller must have obtained a read-only preflight for this
    /// exact normalized root and target, rechecked the root identity while
    /// holding that lock, bounded and re-read the top-level inventory,
    /// document, and journal, and obtained approval from its semantic
    /// validator. The caller must not use this function as a marker/path/bool
    /// proof or bypass the preflight protocol.
    pub(crate) unsafe fn adopt_nonempty_locked(
        root: NormalizedStoreRoot,
        expected_identity: &RootIdentity,
    ) -> Result<Self> {
        if !root.missing_suffix.is_empty() {
            bail!("cannot adopt a root with missing path components")
        }
        reject_protected_claim_path(&root.path)?;
        let metadata = inspect_component(&root.path, "store root")?
            .ok_or_else(|| anyhow!("store root disappeared: {}", root.path.display()))?;
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            bail!("store root is not a regular directory")
        }
        let identity = root_identity_from_path(&root.path)?;
        if &identity != expected_identity {
            bail!("store root identity changed before adoption")
        }
        if directory_is_empty(&root.path)? {
            bail!("cannot adopt an empty store root")
        }
        verify_existing_root_ownership(&metadata, &root.path)?;
        secure_existing_directory(&root.path, &metadata)?;
        Ok(Self {
            path: root.path,
            identity,
        })
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }

    fn verify_identity(&self) -> Result<()> {
        let current = root_identity_from_path(&self.path)?;
        if current != self.identity {
            bail!("owned store root identity changed: {}", self.path.display());
        }
        Ok(())
    }

    fn adopt_external_nonempty_locked(
        root: NormalizedStoreRoot,
        expected_identity: &RootIdentity,
    ) -> Result<Self> {
        if !root.missing_suffix.is_empty() {
            bail!("external directory has missing path components")
        }
        reject_protected_claim_path(root.as_path())?;
        let metadata =
            inspect_component(root.as_path(), "external directory")?.ok_or_else(|| {
                anyhow!(
                    "external directory disappeared: {}",
                    root.as_path().display()
                )
            })?;
        if is_link_or_reparse(&metadata) || !metadata.is_dir() {
            bail!("external directory is not a regular directory")
        }
        let identity = root_identity_from_path(root.as_path())?;
        if &identity != expected_identity {
            bail!("external directory identity changed before adoption")
        }
        if directory_is_empty(root.as_path())? {
            bail!("cannot adopt an empty external directory")
        }
        verify_existing_root_ownership(&metadata, root.as_path())?;
        Ok(Self {
            path: root.path,
            identity,
        })
    }
}

impl From<&NormalizedStoreRoot> for NormalizedStoreRoot {
    fn from(root: &NormalizedStoreRoot) -> Self {
        root.clone()
    }
}

/// A validated relative locator used by journal/store mutations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SafeRelativePath {
    path: PathBuf,
}

impl SafeRelativePath {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() {
            bail!("relative locator cannot be empty")
        }
        if path.is_absolute() {
            bail!("relative locator must be relative")
        }

        // Locators are serialized and may be replayed on another platform,
        // so accept only one slash syntax and reject NUL/drive-prefix syntax.
        let text = path
            .to_str()
            .ok_or_else(|| anyhow!("relative locator must be valid UTF-8"))?;
        if text.len() > MAX_LOCATOR_BYTES {
            bail!("relative locator is too long")
        }
        if text.contains('\0')
            || text.contains('\\')
            || text.contains(':')
            || text
                .chars()
                .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
        {
            bail!("relative locator contains an unsafe path character")
        }

        let mut clean = PathBuf::new();
        let segments: Vec<&str> = text.split('/').collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            bail!("relative locator contains an empty component")
        }
        for segment in segments {
            validate_locator_segment(segment)?;
        }
        for component in path.components() {
            match component {
                Component::Normal(value) => clean.push(value),
                Component::CurDir | Component::ParentDir => {
                    bail!("relative locator contains an unsafe path component")
                }
                Component::RootDir | Component::Prefix(_) => {
                    bail!("relative locator must be relative")
                }
            }
        }
        if clean.as_os_str().is_empty() {
            bail!("relative locator cannot be empty")
        }
        Ok(Self { path: clean })
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.path
    }

    /// Append one already validated filename using the platform-native path
    /// representation without weakening the serialized slash-only grammar.
    pub(crate) fn child(&self, name: &str) -> Result<Self> {
        validate_locator_segment(name)?;
        if name.contains('/') || name.contains('\\') {
            bail!("relative locator child must be one filename")
        }
        let mut path = self.path.clone();
        path.push(name);
        let locator = Self { path };
        if locator.to_slash_string()?.len() > MAX_LOCATOR_BYTES {
            bail!("relative locator is too long")
        }
        Ok(locator)
    }

    /// Return a sibling locator while preserving the validated relative
    /// path boundary. This avoids constructing a Windows backslash path and
    /// then accidentally feeding it back through the slash-only parser.
    pub(crate) fn sibling(&self, name: &str) -> Result<Self> {
        validate_locator_segment(name)?;
        if name.contains('/') || name.contains('\\') {
            bail!("relative locator sibling must be one filename")
        }
        let mut path = self.path.clone();
        path.pop();
        path.push(name);
        let locator = Self { path };
        if locator.to_slash_string()?.len() > MAX_LOCATOR_BYTES {
            bail!("relative locator is too long")
        }
        Ok(locator)
    }

    pub(crate) fn to_slash_string(&self) -> Result<String> {
        let mut components = Vec::new();
        for component in self.path.components() {
            let Component::Normal(value) = component else {
                bail!("relative locator contains an unsafe path component")
            };
            let value = value
                .to_str()
                .ok_or_else(|| anyhow!("relative locator must be valid UTF-8"))?;
            components.push(value);
        }
        if components.is_empty() {
            bail!("relative locator cannot be empty")
        }
        Ok(components.join("/"))
    }
}

/// Read-only evidence captured before adopting a user-owned, non-empty
/// directory as an external mutation root.  The lock locator is fixed by the
/// caller but remains a validated relative locator; no raw mutation path is
/// carried by the resulting capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExternalDirectoryPreflight {
    root: NormalizedStoreRoot,
    identity: RootIdentity,
    lock: SafeRelativePath,
}

/// A sealed capability for one externally-owned directory.
///
/// The fixed lock is retained for the lifetime of the capability.  Every
/// operation below revalidates the root identity and resolves a
/// [`SafeRelativePath`] through the no-follow filesystem primitives.  There
/// is intentionally no directory removal or raw-path mutation method here.
#[derive(Debug)]
pub(crate) struct ExternalDirectoryCapability {
    root: OwnedStoreRoot,
    lock: File,
    lock_locator: SafeRelativePath,
}

impl ExternalDirectoryCapability {
    /// 安全 claim 缺失/空的 active-home，或 adopt 已有非空目录。
    ///
    /// 缺失和空目录走 private-root claim：缺失组件按 0700 创建，已有空目录先收紧，
    /// 再创建 fixed lock。非空目录只走无副作用的 identity preflight，不把无关内容解释成
    /// store inventory。
    pub(crate) fn claim_or_adopt(
        root: NormalizedStoreRoot,
        lock: SafeRelativePath,
    ) -> Result<Self> {
        let should_claim = match inspect_component(root.as_path(), "external directory")? {
            None => true,
            Some(metadata) => {
                if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    bail!("external directory is not a regular directory")
                }
                directory_is_empty(root.as_path())?
            }
        };

        if should_claim {
            let owned = OwnedStoreRoot::claim(root)?;
            return Self::from_claimed_root(owned, lock);
        }

        let expected = Self::preflight_existing(&root, lock)?;
        Self::adopt_existing(root, &expected)
    }

    /// Capture identity and link-free root evidence without creating a lock,
    /// changing permissions, or requiring a store-specific inventory.
    pub(crate) fn preflight_existing(
        root: &NormalizedStoreRoot,
        lock: SafeRelativePath,
    ) -> Result<ExternalDirectoryPreflight> {
        // 先记录目录 identity，再检查用户条目，最后重复校验；遍历期间若路径被替换，
        // 必须 fail closed，不能为另一个目录生成可采信的 evidence。
        let identity = normalized_root_identity(root)?;
        validate_external_directory_preflight(root, &lock)?;
        let current_identity = normalized_root_identity(root)?;
        if current_identity != identity {
            bail!("external directory identity changed during preflight")
        }
        Ok(ExternalDirectoryPreflight {
            root: root.clone(),
            identity,
            lock,
        })
    }

    /// Adopt exactly the preflighted root while retaining its fixed lock.
    /// Revalidation under that lock rejects root replacement, new reparse
    /// entries, and any other invalidation observed before mutation.
    pub(crate) fn adopt_existing(
        root: NormalizedStoreRoot,
        expected: &ExternalDirectoryPreflight,
    ) -> Result<Self> {
        if root != expected.root {
            bail!("external directory preflight root differs")
        }
        // 调用方完成 preflight 后若 normalized path 已指向替换目录，不能在那里创建或打开
        // fixed lock。
        if normalized_root_identity(&root)? != expected.identity {
            bail!("external directory identity changed before lock acquisition")
        }
        let lock_file = open_or_create_secure_file_normalized(&root, &expected.lock)?;
        lock_exclusive_with_wait_notice(&lock_file)
            .context("failed to acquire external directory lock")?;

        let current = Self::preflight_existing(&root, expected.lock.clone())?;
        if current.identity != expected.identity {
            bail!("external directory identity changed after preflight")
        }
        let owned = OwnedStoreRoot::adopt_external_nonempty_locked(root, &expected.identity)?;
        Ok(Self {
            root: owned,
            lock: lock_file,
            lock_locator: expected.lock.clone(),
        })
    }

    fn from_claimed_root(root: OwnedStoreRoot, lock_locator: SafeRelativePath) -> Result<Self> {
        let lock = open_or_create_secure_file(&root, &lock_locator)?;
        lock_exclusive_with_wait_notice(&lock)
            .context("failed to acquire external directory lock")?;
        root.verify_identity()
            .context("external directory identity changed after claim")?;
        Ok(Self {
            root,
            lock,
            lock_locator,
        })
    }

    /// Read-only path used only for deterministic lock ordering and
    /// diagnostics. It cannot be supplied to any capability mutation method.
    pub(crate) fn root_path(&self) -> &Path {
        self.root.as_path()
    }

    pub(crate) fn root_identity(&self) -> &RootIdentity {
        &self.root.identity
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
    ) -> Result<Option<Metadata>> {
        inspect_owned_relative_file(&self.root, locator, final_may_be_missing)
    }

    pub(crate) fn create_new(&self, locator: &SafeRelativePath) -> Result<File> {
        self.ensure_mutable_locator(locator)?;
        create_new_secure_file(&self.root, locator)
    }

    pub(crate) fn replace(
        &self,
        prepared: &SafeRelativePath,
        target: &SafeRelativePath,
    ) -> std::result::Result<(), MutationFailure> {
        if let Err(error) = self.ensure_mutable_locator(prepared) {
            return Err(MutationFailure::not_applied(error));
        }
        if let Err(error) = self.ensure_mutable_locator(target) {
            return Err(MutationFailure::not_applied(error));
        }
        replace_same_dir(&self.root, prepared, target)
    }

    pub(crate) fn move_file(
        &self,
        source: &SafeRelativePath,
        destination: &SafeRelativePath,
    ) -> std::result::Result<(), MutationFailure> {
        if let Err(error) = self.ensure_mutable_locator(source) {
            return Err(MutationFailure::not_applied(error));
        }
        if let Err(error) = self.ensure_mutable_locator(destination) {
            return Err(MutationFailure::not_applied(error));
        }
        move_same_dir(&self.root, source, destination)
    }

    pub(crate) fn remove(
        &self,
        locator: &SafeRelativePath,
    ) -> std::result::Result<bool, MutationFailure> {
        if let Err(error) = self.ensure_mutable_locator(locator) {
            return Err(MutationFailure::not_applied(error));
        }
        remove_file(&self.root, locator)
    }

    pub(crate) fn sync(&self, locator: &SafeRelativePath) -> Result<()> {
        self.ensure_mutable_locator(locator)?;
        sync_file(&self.root, locator)
    }

    pub(crate) fn sync_parent(&self, locator: &SafeRelativePath) -> Result<()> {
        self.ensure_mutable_locator(locator)?;
        sync_parent_dir(&self.root, locator)
    }

    fn ensure_mutable_locator(&self, locator: &SafeRelativePath) -> Result<()> {
        if locator == &self.lock_locator {
            bail!("external directory fixed lock cannot be mutated")
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TopLevelEntryKind {
    Directory,
    RegularFile,
    /// Symlink, reparse point, device node or any other non-plain entry.
    ///
    /// 为什么保留而不是直接 bail：state root 同时是安装目录，里面必然混有与
    /// sagy 无关的条目。把"存在一个奇怪条目"当成整个 root 不可用，会让产品在
    /// 正常安装路径上直接不可用。这里只如实记录类型，由 schema 层决定
    /// "sagy 自己纳管的名字必须是什么类型"，未纳管的名字一律忽略。
    Other,
}

/// Bounded, metadata-only inventory item for one top-level root entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TopLevelInventoryEntry {
    pub(crate) locator: SafeRelativePath,
    pub(crate) kind: TopLevelEntryKind,
    pub(crate) size: u64,
}

/// Inspect a normalized root without creating, chmod'ing, recovering, or
/// reading file contents. Every entry is checked through symlink metadata.
///
/// This layer classifies but never rejects individual entries: the state root
/// doubles as the installation directory, so foreign entries are expected and
/// only the schema layer knows which names sagy actually owns.
pub(crate) fn inspect_top_level_inventory(
    root: &NormalizedStoreRoot,
    max_entries: usize,
) -> Result<Vec<TopLevelInventoryEntry>> {
    let metadata =
        inspect_component(root.as_path(), "normalized store root")?.ok_or_else(|| {
            anyhow!(
                "normalized store root is missing: {}",
                root.as_path().display()
            )
        })?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!("normalized store root is not a regular directory")
    }

    let mut inventory = Vec::new();
    for entry in fs::read_dir(root.as_path()).with_context(|| {
        format!(
            "failed to enumerate store root: {}",
            root.as_path().display()
        )
    })? {
        if inventory.len() >= max_entries {
            bail!("store root inventory exceeds {max_entries} entries")
        }
        let entry = entry.with_context(|| "failed to enumerate store root entry")?;
        let name = entry.file_name();
        let name_text = name
            .to_str()
            .ok_or_else(|| anyhow!("store root entry name is not valid UTF-8"))?;
        let locator = SafeRelativePath::new(Path::new(name_text))?;
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("failed to inspect store root entry: {}", name_text))?;
        // 只分类不拒绝：symlink / 特殊文件 / 超大文件都可能是用户或安装器放在
        // SAGY_HOME 里与 sagy 无关的东西。真正的安全判定发生在 schema 层，
        // 那里知道哪些名字属于 sagy，并对它们强制类型与大小上限。
        let (kind, size) = if is_link_or_reparse(&metadata) {
            (TopLevelEntryKind::Other, 0)
        } else if metadata.is_dir() {
            (TopLevelEntryKind::Directory, 0)
        } else if metadata.is_file() {
            (TopLevelEntryKind::RegularFile, metadata.len())
        } else {
            (TopLevelEntryKind::Other, 0)
        };
        inventory.push(TopLevelInventoryEntry {
            locator,
            kind,
            size,
        });
    }
    inventory.sort_by(|left, right| left.locator.as_path().cmp(right.locator.as_path()));
    Ok(inventory)
}

fn validate_locator_segment(segment: &str) -> Result<()> {
    if segment.is_empty() || segment == "." || segment == ".." {
        bail!("relative locator contains an unsafe path component")
    }
    if segment.contains('\0')
        || segment.contains(':')
        || segment
            .chars()
            .any(|character| matches!(character, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        bail!("relative locator contains an unsafe path character")
    }
    if segment.len() > MAX_LOCATOR_COMPONENT_BYTES {
        bail!("relative locator component is too long")
    }
    if segment.ends_with('.') || segment.ends_with(' ') {
        bail!("relative locator component cannot end with dot or space")
    }
    if segment.chars().any(char::is_control) {
        bail!("relative locator component contains a control character")
    }

    let basename = segment
        .split_once('.')
        .map_or(segment, |(stem, _)| stem)
        .trim_end_matches(['.', ' ']);
    let uppercase = basename.to_ascii_uppercase();
    if matches!(
        uppercase.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        bail!("relative locator uses a Windows device name")
    }
    Ok(())
}

/// Classifies whether a mutation was definitely not applied or needs
/// reconciliation because the native operation may have changed the target.
#[derive(Debug)]
pub(crate) enum MutationFailure {
    NotApplied { source: anyhow::Error },
    ReconcileRequired { source: anyhow::Error },
}

impl MutationFailure {
    fn not_applied(error: impl Into<anyhow::Error>) -> Self {
        Self::NotApplied {
            source: error.into(),
        }
    }

    fn reconcile_required(error: impl Into<anyhow::Error>) -> Self {
        Self::ReconcileRequired {
            source: error.into(),
        }
    }

    pub(crate) fn source_error(&self) -> &anyhow::Error {
        match self {
            Self::NotApplied { source } | Self::ReconcileRequired { source } => source,
        }
    }

    pub(crate) fn into_source_error(self) -> anyhow::Error {
        match self {
            Self::NotApplied { source } | Self::ReconcileRequired { source } => source,
        }
    }

    pub(crate) fn requires_reconciliation(&self) -> bool {
        matches!(self, Self::ReconcileRequired { .. })
    }
}

impl std::fmt::Display for MutationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplied { source } => write!(formatter, "mutation not applied: {source}"),
            Self::ReconcileRequired { source } => {
                write!(formatter, "mutation requires reconciliation: {source}")
            }
        }
    }
}

impl std::error::Error for MutationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source_error().as_ref())
    }
}

/// A SHA-256 digest of exact document bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DocumentDigest(pub(crate) [u8; 32]);

impl std::fmt::Debug for DocumentDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("DocumentDigest")
            .field(&self.to_hex())
            .finish()
    }
}

impl std::fmt::Display for DocumentDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl DocumentDigest {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut value = [0_u8; 32];
        value.copy_from_slice(&digest);
        Self(value)
    }

    pub(crate) fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    pub(crate) fn from_hex(value: &str) -> Result<Self> {
        if value.len() != 64 {
            bail!("invalid SHA-256 digest length")
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_value(chunk[0]).ok_or_else(|| anyhow!("invalid SHA-256 digest"))?;
            let low = hex_value(chunk[1]).ok_or_else(|| anyhow!("invalid SHA-256 digest"))?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_root_candidate(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("store root cannot be empty")
    }
    if !path.is_absolute() {
        bail!("store root must be absolute")
    }
    if is_filesystem_root(path) {
        bail!("filesystem root cannot be used as a store root")
    }
    let raw = path
        .to_str()
        .ok_or_else(|| anyhow!("store root must be valid UTF-8"))?;
    if raw.split(['/', '\\']).any(|component| component == ".") {
        bail!("store root cannot contain a current-directory component")
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            bail!("store root cannot contain a parent component")
        }
    }
    Ok(())
}

fn is_filesystem_root(path: &Path) -> bool {
    let mut components = path.components();
    match components.next() {
        Some(Component::RootDir) => components.next().is_none(),
        Some(Component::Prefix(_)) => {
            matches!(components.next(), Some(Component::RootDir)) && components.next().is_none()
        }
        _ => false,
    }
}

pub(crate) fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    is_reparse_attribute(metadata)
}

#[cfg(windows)]
fn is_reparse_attribute(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
const fn is_reparse_attribute(_metadata: &Metadata) -> bool {
    false
}

pub(crate) fn normalized_root_identity(root: &NormalizedStoreRoot) -> Result<RootIdentity> {
    root_identity_from_path(root.as_path())
}

fn root_identity_from_path(path: &Path) -> Result<RootIdentity> {
    let metadata = inspect_component(path, "store root")?
        .ok_or_else(|| anyhow!("store root is missing: {}", path.display()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!("store root is not a regular directory: {}", path.display())
    }
    #[cfg(unix)]
    {
        Ok(RootIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        windows_root_identity(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        bail!("non-empty root adoption identity is unsupported on this platform")
    }
}

#[cfg(windows)]
fn windows_root_identity(path: &Path) -> Result<RootIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, GetFileInformationByHandle,
    };

    let mut options = OpenOptions::new();
    options.read(true);
    // Opening the directory itself (rather than a followed path) gives us a
    // stable file identity and makes junction/reparse adoption fail closed.
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open store root handle: {}", path.display()))?;
    let raw_handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `raw_handle` is a live handle owned by `file` and the output
    // points to a properly initialized value for the duration of this call.
    let success = unsafe { GetFileInformationByHandle(raw_handle, &mut information) };
    if success == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to inspect store root handle: {}", path.display()));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("store root handle is a reparse point: {}", path.display());
    }
    if information.dwFileAttributes & 0x10 == 0 {
        bail!("store root handle is not a directory: {}", path.display());
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok(RootIdentity::Windows {
        volume_serial: information.dwVolumeSerialNumber,
        file_index,
    })
}

fn validate_external_directory_preflight(
    root: &NormalizedStoreRoot,
    lock: &SafeRelativePath,
) -> Result<()> {
    if !root.missing_suffix.is_empty() {
        bail!("external directory has missing path components")
    }
    reject_protected_claim_path(root.as_path())?;
    let metadata = inspect_component(root.as_path(), "external directory")?.ok_or_else(|| {
        anyhow!(
            "external directory is missing: {}",
            root.as_path().display()
        )
    })?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!("external directory is not a regular directory")
    }
    if directory_is_empty(root.as_path())? {
        bail!("cannot adopt an empty external directory")
    }
    verify_existing_root_ownership(&metadata, root.as_path())?;
    // A pre-existing lock must itself be a regular, non-link file. Missing
    // lock files are allowed and are created only after this pure preflight.
    let _ = inspect_normalized_relative_file(root, lock, true)?;
    Ok(())
}

pub(crate) fn validate_nonempty_root_for_adoption(root: &NormalizedStoreRoot) -> Result<()> {
    if !root.missing_suffix.is_empty() {
        bail!("store root has missing path components")
    }
    reject_protected_claim_path(root.as_path())?;
    let metadata = inspect_component(root.as_path(), "store root")?
        .ok_or_else(|| anyhow!("store root disappeared: {}", root.as_path().display()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!("store root is not a regular directory")
    }
    if directory_is_empty(root.as_path())? {
        bail!("cannot adopt an empty store root")
    }
    verify_existing_root_ownership(&metadata, root.as_path())?;
    normalized_root_identity(root).map(|_| ())
}

fn inspect_component(path: &Path, label: &str) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {label}: {}", path.display()))
        }
    }
}

/// Create a previously missing root and its missing ancestors with private-at-
/// creation mode.
///
/// The missing suffix is captured before any mkdir call. Existing components
/// are validated only as the fixed anchor; a component in the captured suffix
/// that appears concurrently is an error rather than an accepted directory.
fn secure_create_missing_suffix(anchor: &Path, missing_suffix: &[OsString]) -> Result<()> {
    if missing_suffix.is_empty() {
        bail!("secure directory creation requires a missing suffix")
    }
    let Some(metadata) = inspect_component(anchor, "directory anchor")? else {
        bail!("directory anchor disappeared: {}", anchor.display())
    };
    if is_link_or_reparse(&metadata) {
        bail!(
            "directory anchor cannot be a symlink or reparse point: {}",
            anchor.display()
        )
    }
    if !metadata.is_dir() {
        bail!("directory anchor is not a directory: {}", anchor.display())
    }

    let mut current = anchor.to_path_buf();
    for name in missing_suffix {
        current.push(name);

        let builder = DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        match builder.create(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                // A missing component appeared after inspection. Do not
                // accept a racing directory or link as part of this claim.
                bail!(
                    "directory component appeared during secure creation: {}",
                    current.display()
                )
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create private directory: {}", current.display())
                });
            }
        }
    }
    Ok(())
}

fn directory_is_empty(path: &Path) -> Result<bool> {
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("failed to inspect directory contents: {}", path.display()))?;
    Ok(entries
        .next()
        .transpose()
        .with_context(|| format!("failed to inspect directory contents: {}", path.display()))?
        .is_none())
}

fn secure_existing_directory(path: &Path, metadata: &Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to secure store root: {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, metadata);
    }
    Ok(())
}

fn reject_protected_claim_path(path: &Path) -> Result<()> {
    if is_filesystem_root(path) {
        bail!("filesystem root cannot be claimed")
    }

    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut protected = Vec::<PathBuf>::new();
    // 当前工作目录**不是**安全边界：把它列为 protected 没有任何安全收益，
    // 只会让 `cd ~/.sagy && sagy list` 这种完全正常的用法随机失败，
    // 且失败原因与真实问题毫无关系。真正要挡的是 $HOME / 系统临时目录 /
    // 文件系统根这类"绝不该被整体纳管"的目录。
    if let Some(home) = home_dir() {
        protected.push(fs::canonicalize(home).unwrap_or_default());
    }
    protected.push(fs::canonicalize(std::env::temp_dir()).unwrap_or_default());
    #[cfg(unix)]
    protected.push(fs::canonicalize(Path::new("/tmp")).unwrap_or_default());

    if protected
        .iter()
        .any(|candidate| !candidate.as_os_str().is_empty() && *candidate == canonical)
    {
        bail!(
            "protected system directory cannot be claimed: {}",
            path.display()
        )
    }
    Ok(())
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[cfg(unix)]
fn verify_existing_root_ownership(metadata: &Metadata, path: &Path) -> Result<()> {
    // SAFETY: geteuid has no preconditions and is provided by the platform C
    // runtime on every supported Unix target.
    let current_euid = unsafe { geteuid() };
    if metadata.uid() != current_euid {
        bail!(
            "store root is not owned by the current user: {}",
            path.display()
        )
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        bail!(
            "store root is group/other writable and cannot be claimed: {}",
            path.display()
        )
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_existing_root_ownership(_metadata: &Metadata, _path: &Path) -> Result<()> {
    // Windows ACL ownership cannot be represented by std metadata. The
    // normalized path and empty-root policy still prevent broad claims.
    Ok(())
}

fn resolve_relative_path(
    root: &Path,
    relative: &SafeRelativePath,
    label: &str,
    final_may_be_missing: bool,
) -> Result<(PathBuf, Option<Metadata>)> {
    let mut current = root.to_path_buf();
    let root_metadata = inspect_component(&current, "owned store root")?
        .ok_or_else(|| anyhow!("owned store root is missing: {}", current.display()))?;
    if is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
        bail!("owned store root is not a directory: {}", current.display())
    }

    let components: Vec<_> = relative.path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(value) = component else {
            bail!("relative locator contains an unsafe path component")
        };
        current.push(value);
        let is_final = index + 1 == components.len();
        let metadata = inspect_component(&current, label)?;
        match metadata {
            Some(metadata) => {
                if is_link_or_reparse(&metadata) {
                    bail!(
                        "{label} cannot contain a symlink or reparse point: {}",
                        current.display()
                    )
                }
                if !is_final && !metadata.is_dir() {
                    bail!(
                        "{label} contains a non-directory component: {}",
                        current.display()
                    )
                }
                if is_final {
                    return Ok((current, Some(metadata)));
                }
            }
            None if is_final && final_may_be_missing => return Ok((current, None)),
            None => bail!("{label} parent component is missing: {}", current.display()),
        }
    }
    unreachable!("SafeRelativePath rejects empty locators")
}

fn resolve_owned_relative_path(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
    label: &str,
    final_may_be_missing: bool,
) -> Result<(PathBuf, Option<Metadata>)> {
    root.verify_identity()?;
    resolve_relative_path(root.as_path(), relative, label, final_may_be_missing)
}

fn apply_no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    options.custom_flags(no_follow_flag());
    #[cfg(windows)]
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

/// Read an import/source file through one bounded, no-follow file handle.
/// This is intentionally a pure inspection helper: it never creates or
/// changes permissions and verifies regular-file metadata again after open so
/// a path replacement race cannot turn an import into an unbounded or
/// directory read.  Store mutations continue to use `OwnedStoreRoot` and
/// `SafeRelativePath`; this helper is only for caller-supplied source files.
pub(crate) fn read_external_regular_file_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect source file: {}", path.display()))?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        bail!(
            "source path is not a regular non-link file: {}",
            path.display()
        );
    }
    if metadata.len() > max_bytes as u64 {
        bail!("source file exceeds {max_bytes} bytes: {}", path.display());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    apply_no_follow(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open source file: {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to stat source file: {}", path.display()))?;
    if is_link_or_reparse(&opened) || !opened.is_file() {
        bail!("opened source is not a regular file: {}", path.display());
    }
    if opened.len() > max_bytes as u64 {
        bail!(
            "source file grew beyond {max_bytes} bytes: {}",
            path.display()
        );
    }
    let probe_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow!("source read limit is too large"))?;
    let mut bytes = Vec::with_capacity(std::cmp::min(opened.len() as usize, max_bytes));
    file.take(probe_limit as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read source file: {}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!(
            "source file grew beyond {max_bytes} bytes: {}",
            path.display()
        );
    }
    Ok(bytes)
}

#[cfg(unix)]
const fn no_follow_flag() -> i32 {
    #[cfg(target_os = "linux")]
    {
        return 0o400000;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return 0x100;
    }
    #[allow(unreachable_code)]
    0
}

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Read a file below a normalized root without creating, chmod'ing, or
/// canonicalizing anything. Missing roots/files return `None`; every existing
/// intermediate and final symlink/reparse point is rejected.
pub(crate) fn read_relative_file(
    root: &NormalizedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<Option<Vec<u8>>> {
    let Some(root_metadata) = inspect_component(root.as_path(), "normalized store root")? else {
        return Ok(None);
    };
    if is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
        bail!(
            "normalized store root is not a directory: {}",
            root.as_path().display()
        )
    }

    let mut path = root.as_path().to_path_buf();
    let components: Vec<_> = relative.path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(value) = component else {
            bail!("relative locator contains an unsafe path component")
        };
        path.push(value);
        let Some(metadata) = inspect_component(&path, "read file")? else {
            return Ok(None);
        };
        if is_link_or_reparse(&metadata) {
            bail!(
                "read file cannot contain a symlink or reparse point: {}",
                path.display()
            )
        }
        if index + 1 == components.len() {
            if !metadata.is_file() {
                bail!("read path is not a regular file: {}", path.display())
            }
            let mut options = OpenOptions::new();
            options.read(true);
            apply_no_follow(&mut options);
            let mut file = options
                .open(&path)
                .with_context(|| format!("failed to open file: {}", path.display()))?;
            let opened = file
                .metadata()
                .with_context(|| format!("failed to inspect opened file: {}", path.display()))?;
            if is_link_or_reparse(&opened) || !opened.is_file() {
                bail!("opened read path is not a regular file: {}", path.display())
            }
            let mut bytes = Vec::with_capacity(opened.len() as usize);
            file.read_to_end(&mut bytes)
                .with_context(|| format!("failed to read file: {}", path.display()))?;
            return Ok(Some(bytes));
        }
        if !metadata.is_dir() {
            bail!(
                "read path contains a non-directory component: {}",
                path.display()
            )
        }
    }
    unreachable!("SafeRelativePath rejects empty locators")
}

/// Read a regular file below an owned root without changing any metadata.
///
/// This is the mutation-side counterpart of [`read_relative_file`].  Keeping
/// the path resolution here means callers cannot accidentally turn an owned
/// root plus an unchecked `Path` into a filesystem operation.
pub(crate) fn read_owned_relative_file(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<Option<Vec<u8>>> {
    let (path, metadata) = resolve_owned_relative_path(root, relative, "read file", true)?;
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    if !metadata.is_file() {
        bail!("read path is not a regular file: {}", path.display())
    }
    let mut options = OpenOptions::new();
    options.read(true);
    apply_no_follow(&mut options);
    let mut file = options
        .open(&path)
        .with_context(|| format!("failed to open file: {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read file: {}", path.display()))?;
    Ok(Some(bytes))
}

/// Read a regular file below an owned root with a hard byte bound.
///
/// The metadata length is checked before opening, then the handle is limited
/// to `max_bytes + 1` so a concurrent growth cannot turn a bounded journal
/// read into an unbounded allocation.
pub(crate) fn read_owned_relative_file_bounded(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let (path, metadata) = resolve_owned_relative_path(root, relative, "bounded read", true)?;
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    if !metadata.is_file() {
        bail!(
            "bounded read path is not a regular file: {}",
            path.display()
        )
    }
    if metadata.len() > max_bytes as u64 {
        bail!(
            "bounded read file exceeds {max_bytes} bytes: {}",
            path.display()
        )
    }

    let mut options = OpenOptions::new();
    options.read(true);
    apply_no_follow(&mut options);
    let file = options
        .open(&path)
        .with_context(|| format!("failed to open bounded file: {}", path.display()))?;
    let probe_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow!("bounded read limit is too large"))?;
    let mut bytes = Vec::with_capacity(std::cmp::min(metadata.len() as usize, max_bytes));
    file.take(probe_limit as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read bounded file: {}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!(
            "bounded read file grew beyond {max_bytes} bytes: {}",
            path.display()
        )
    }
    Ok(Some(bytes))
}

/// Create a relative directory below an owned store root, checking every
/// component through `symlink_metadata` before and after creation.  Missing
/// components are created private at creation time; an existing link, file,
/// or reparse point is never followed.
pub(crate) fn ensure_owned_relative_directory(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<()> {
    root.verify_identity()?;
    let root_metadata = inspect_component(root.as_path(), "owned store root")?
        .ok_or_else(|| anyhow!("owned store root is missing"))?;
    if is_link_or_reparse(&root_metadata) || !root_metadata.is_dir() {
        bail!("owned store root is not a regular directory")
    }

    let mut current = root.as_path().to_path_buf();
    for component in relative.path.components() {
        let Component::Normal(value) = component else {
            bail!("relative directory contains an unsafe path component")
        };
        current.push(value);
        match inspect_component(&current, "owned directory")? {
            Some(metadata) => {
                if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    bail!(
                        "owned directory component is not a regular directory: {}",
                        current.display()
                    )
                }
            }
            None => {
                let builder = DirBuilder::new();
                #[cfg(unix)]
                let mut builder = {
                    let mut builder = builder;
                    builder.mode(0o700);
                    builder
                };
                #[cfg(not(unix))]
                let mut builder = builder;
                builder.recursive(false);
                builder.create(&current).with_context(|| {
                    format!("failed to create private directory: {}", current.display())
                })?;
                let metadata =
                    inspect_component(&current, "owned directory")?.ok_or_else(|| {
                        anyhow!("created directory disappeared: {}", current.display())
                    })?;
                if is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    bail!(
                        "created directory is not a regular directory: {}",
                        current.display()
                    )
                }
                #[cfg(unix)]
                {
                    // Creation mode is the security boundary.  If a race or
                    // umask produced a weaker mode, fail closed rather than
                    // chmod'ing an object we did not create.
                    if metadata.permissions().mode() & 0o077 != 0 {
                        bail!("created directory is not private: {}", current.display())
                    }
                }
            }
        }
    }
    Ok(())
}

/// Enumerate one directory below an owned root and return only validated
/// relative locators.  The directory stream is used solely to discover names;
/// every later mutation still resolves the returned locator through the owned
/// root and opens it with no-follow flags.  This keeps a swapped entry from
/// turning an inventory read into a trusted absolute path.
pub(crate) fn enumerate_owned_relative_directory(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
    max_entries: usize,
) -> Result<Vec<(SafeRelativePath, Metadata)>> {
    let (directory, metadata) =
        resolve_owned_relative_path(root, relative, "owned directory", false)?;
    let Some(metadata) = metadata else {
        bail!("owned directory is missing: {}", directory.display());
    };
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        bail!(
            "owned directory is not a regular directory: {}",
            directory.display()
        );
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(&directory).with_context(|| {
        format!(
            "failed to enumerate owned directory: {}",
            directory.display()
        )
    })? {
        if entries.len() >= max_entries {
            bail!("owned directory exceeds {max_entries} entries");
        }
        let entry = entry.with_context(|| "failed to enumerate owned directory entry")?;
        let name = entry.file_name();
        let name_text = name
            .to_str()
            .ok_or_else(|| anyhow!("owned directory entry name is not valid UTF-8"))?;
        let locator = relative.child(name_text)?;
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("failed to inspect owned directory entry: {name_text}"))?;
        if is_link_or_reparse(&metadata) {
            bail!("owned directory contains a symlink or reparse point: {name_text}");
        }
        entries.push((locator, metadata));
    }
    entries.sort_by(|left, right| left.0.as_path().cmp(right.0.as_path()));
    Ok(entries)
}

pub(crate) fn enumerate_owned_relative_directory_if_present(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
    max_entries: usize,
) -> Result<Option<Vec<(SafeRelativePath, Metadata)>>> {
    let (_, metadata) = resolve_owned_relative_path(root, relative, "owned directory", true)?;
    if metadata.is_none() {
        return Ok(None);
    }
    enumerate_owned_relative_directory(root, relative, max_entries).map(Some)
}

/// Read a bounded regular file below a normalized root without mutation.
pub(crate) fn read_normalized_relative_file_bounded(
    root: &NormalizedStoreRoot,
    relative: &SafeRelativePath,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let (path, metadata) =
        resolve_relative_path(root.as_path(), relative, "normalized bounded read", true)?;
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    if !metadata.is_file() {
        bail!(
            "normalized bounded read path is not a regular file: {}",
            path.display()
        )
    }
    if metadata.len() > max_bytes as u64 {
        bail!(
            "normalized bounded read file exceeds {max_bytes} bytes: {}",
            path.display()
        )
    }
    let mut options = OpenOptions::new();
    options.read(true);
    apply_no_follow(&mut options);
    let file = options
        .open(&path)
        .with_context(|| format!("failed to open normalized bounded file: {}", path.display()))?;
    let probe_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow!("bounded read limit is too large"))?;
    let mut bytes = Vec::with_capacity(std::cmp::min(metadata.len() as usize, max_bytes));
    file.take(probe_limit as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read normalized bounded file: {}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!(
            "normalized bounded read file grew beyond {max_bytes} bytes: {}",
            path.display()
        )
    }
    Ok(Some(bytes))
}

/// Inspect a regular-file locator below an owned root.
pub(crate) fn inspect_owned_relative_file(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
    final_may_be_missing: bool,
) -> Result<Option<Metadata>> {
    let (_, metadata) =
        resolve_owned_relative_path(root, relative, "regular file", final_may_be_missing)?;
    if let Some(metadata) = &metadata
        && !metadata.is_file()
    {
        bail!("path is not a regular file")
    }
    Ok(metadata)
}

pub(crate) fn inspect_normalized_relative_file(
    root: &NormalizedStoreRoot,
    relative: &SafeRelativePath,
    final_may_be_missing: bool,
) -> Result<Option<Metadata>> {
    let (_, metadata) = resolve_relative_path(
        root.as_path(),
        relative,
        "normalized regular file",
        final_may_be_missing,
    )?;
    if let Some(metadata) = &metadata
        && !metadata.is_file()
    {
        bail!("normalized path is not a regular file")
    }
    Ok(metadata)
}

/// Create a new private file below an owned root.
pub(crate) fn create_new_secure_file(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<File> {
    let (path, existing) = resolve_owned_relative_path(root, relative, "new file", true)?;
    if existing.is_some() {
        bail!("new file already exists: {}", path.display())
    }
    root.verify_identity()?;

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    apply_no_follow(&mut options);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(&path)
        .with_context(|| format!("failed to create secure file: {}", path.display()))
}

/// Open an existing regular private file below an owned root without
/// following links.  The lock path uses this to enforce a 0600 regular file.
pub(crate) fn open_existing_secure_file(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<File> {
    let (path, metadata) = resolve_owned_relative_path(root, relative, "secure file", false)?;
    let Some(metadata) = metadata else {
        bail!("secure file does not exist: {}", path.display())
    };
    if !metadata.is_file() {
        bail!("secure file is not a regular file: {}", path.display())
    }
    root.verify_identity()?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    apply_no_follow(&mut options);
    let file = options
        .open(&path)
        .with_context(|| format!("failed to open secure file: {}", path.display()))?;
    #[cfg(unix)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&path, permissions)
            .with_context(|| format!("failed to secure file: {}", path.display()))?;
    }
    Ok(file)
}

/// Open an existing secure file or atomically create it with private mode.
///
/// The path is resolved and checked before either operation.  A concurrent
/// creator is handled by reopening the file and applying the same regular-file
/// and mode checks; callers never need to concatenate a raw path for a lock or
/// journal locator.
pub(crate) fn open_or_create_secure_file(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<File> {
    let (path, existing) = resolve_owned_relative_path(root, relative, "secure file", true)?;
    if let Some(metadata) = existing {
        if !metadata.is_file() {
            bail!("secure file is not a regular file: {}", path.display())
        }
        root.verify_identity()?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        apply_no_follow(&mut options);
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open secure file: {}", path.display()))?;
        #[cfg(unix)]
        {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions)
                .with_context(|| format!("failed to secure file: {}", path.display()))?;
        }
        return Ok(file);
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    root.verify_identity()?;
    apply_no_follow(&mut options);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(&path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            open_existing_secure_file(root, relative)
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to create secure file: {}", path.display()))
        }
    }
}

/// Create/open the fixed adoption lock below a normalized existing root.
/// This is intentionally limited to the lock path and is called only after a
/// caller has captured the expected root identity.
pub(crate) fn open_or_create_secure_file_normalized(
    root: &NormalizedStoreRoot,
    relative: &SafeRelativePath,
) -> Result<File> {
    let (path, existing) =
        resolve_relative_path(root.as_path(), relative, "normalized secure file", true)?;
    if let Some(metadata) = existing {
        if !metadata.is_file() {
            bail!(
                "normalized secure file is not a regular file: {}",
                path.display()
            )
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        apply_no_follow(&mut options);
        let file = options.open(&path).with_context(|| {
            format!("failed to open normalized secure file: {}", path.display())
        })?;
        #[cfg(unix)]
        {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions).with_context(|| {
                format!("failed to secure normalized lock file: {}", path.display())
            })?;
        }
        return Ok(file);
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    apply_no_follow(&mut options);
    #[cfg(unix)]
    options.mode(0o600);
    match options.open(&path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let (existing_path, metadata) =
                resolve_relative_path(root.as_path(), relative, "normalized secure file", false)?;
            let Some(metadata) = metadata else {
                bail!(
                    "normalized secure file disappeared: {}",
                    existing_path.display()
                )
            };
            if !metadata.is_file() {
                bail!(
                    "normalized secure file is not a regular file: {}",
                    existing_path.display()
                )
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            apply_no_follow(&mut options);
            let file = options.open(&existing_path).with_context(|| {
                format!(
                    "failed to open normalized secure file: {}",
                    existing_path.display()
                )
            })?;
            #[cfg(unix)]
            {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                fs::set_permissions(&existing_path, permissions).with_context(|| {
                    format!(
                        "failed to secure normalized lock file: {}",
                        existing_path.display()
                    )
                })?;
            }
            Ok(file)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to create normalized secure file: {}",
                path.display()
            )
        }),
    }
}

/// Synchronize a regular file below an owned root.
pub(crate) fn sync_file(root: &OwnedStoreRoot, relative: &SafeRelativePath) -> Result<()> {
    let (path, metadata) = resolve_owned_relative_path(root, relative, "file", false)?;
    let Some(metadata) = metadata else {
        bail!("file does not exist: {}", path.display())
    };
    if !metadata.is_file() {
        bail!("file is not a regular file: {}", path.display())
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    apply_no_follow(&mut options);
    options
        .open(&path)
        .with_context(|| format!("failed to open file for sync: {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync file: {}", path.display()))
}

/// Remove a regular file below an owned root and synchronize its parent.
pub(crate) fn remove_file(
    root: &OwnedStoreRoot,
    relative: &SafeRelativePath,
) -> std::result::Result<bool, MutationFailure> {
    let (path, metadata) = resolve_owned_relative_path(root, relative, "file", true)
        .map_err(MutationFailure::not_applied)?;
    let Some(metadata) = metadata else {
        return Ok(false);
    };
    if !metadata.is_file() {
        return Err(MutationFailure::not_applied(anyhow!(
            "file is not a regular file: {}",
            path.display()
        )));
    }
    root.verify_identity()
        .map_err(MutationFailure::not_applied)?;
    fs::remove_file(&path).map_err(|error| {
        MutationFailure::not_applied(
            anyhow!(error).context(format!("failed to remove file: {}", path.display())),
        )
    })?;
    sync_parent_path(path.parent().ok_or_else(|| {
        MutationFailure::reconcile_required(anyhow!("file has no parent directory"))
    })?)
    .map_err(MutationFailure::reconcile_required)?;
    Ok(true)
}

/// Synchronize the parent directory of a relative file below an owned root.
pub(crate) fn sync_parent_dir(root: &OwnedStoreRoot, relative: &SafeRelativePath) -> Result<()> {
    let (path, _) = resolve_owned_relative_path(root, relative, "file", true)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("file has no parent directory: {}", path.display()))?;
    sync_parent_path(parent)
}

fn sync_parent_path(parent: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        apply_no_follow(&mut options);
        options
            .open(parent)
            .with_context(|| format!("failed to open parent directory: {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync parent directory: {}", parent.display()))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        // Windows does not provide a portable directory fsync through the
        // standard library.  The file flush and MoveFileExW WRITE_THROUGH
        // operations still provide the durable ordering available here.
        let _ = parent;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = parent;
        Err(anyhow!(
            "parent-directory fsync is not supported on this platform"
        ))
    }
}

/// Atomically replace a target with a prepared file in the same directory.
///
/// Validation failures are `NotApplied`, so the target and prepared file are
/// left alone. On Unix, a failed `rename` call is also `NotApplied`; a
/// successful rename followed by parent synchronization failure is
/// `ReconcileRequired`. On Windows, native replacement failure and every
/// post-replacement synchronization failure are `ReconcileRequired`.
pub(crate) fn replace_same_dir(
    root: &OwnedStoreRoot,
    prepared: &SafeRelativePath,
    target: &SafeRelativePath,
) -> std::result::Result<(), MutationFailure> {
    let prepared_parent = prepared.path.parent().unwrap_or_else(|| Path::new("."));
    let target_parent = target.path.parent().unwrap_or_else(|| Path::new("."));
    if prepared_parent != target_parent {
        return Err(MutationFailure::not_applied(anyhow!(
            "prepared and target must have the same parent directory"
        )));
    }

    let (prepared_path, prepared_metadata) =
        resolve_owned_relative_path(root, prepared, "prepared file", false)
            .map_err(MutationFailure::not_applied)?;
    let Some(prepared_metadata) = prepared_metadata else {
        return Err(MutationFailure::not_applied(anyhow!(
            "prepared file does not exist: {}",
            prepared_path.display()
        )));
    };
    if !prepared_metadata.is_file() {
        return Err(MutationFailure::not_applied(anyhow!(
            "prepared path is not a regular file: {}",
            prepared_path.display()
        )));
    }

    let (target_path, target_metadata) =
        resolve_owned_relative_path(root, target, "target file", true)
            .map_err(MutationFailure::not_applied)?;
    if let Some(metadata) = &target_metadata
        && !metadata.is_file()
    {
        return Err(MutationFailure::not_applied(anyhow!(
            "target path is not a regular file: {}",
            target_path.display()
        )));
    }
    root.verify_identity()
        .map_err(MutationFailure::not_applied)?;

    #[cfg(unix)]
    {
        fs::rename(&prepared_path, &target_path).map_err(|error| {
            MutationFailure::not_applied(anyhow!(error).context(format!(
                "failed to atomically replace {} with {}",
                target_path.display(),
                prepared_path.display()
            )))
        })?;
        sync_parent_path(
            target_path.parent().ok_or_else(|| {
                MutationFailure::reconcile_required(anyhow!("target has no parent"))
            })?,
        )
        .map_err(MutationFailure::reconcile_required)?;
    }

    #[cfg(windows)]
    {
        windows_replace_file(&prepared_path, &target_path, target_metadata.is_some())
            .map_err(MutationFailure::reconcile_required)?;
        if target_metadata.is_some() {
            File::options()
                .read(true)
                .write(true)
                .open(&target_path)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    MutationFailure::reconcile_required(anyhow!(error).context(format!(
                        "failed to sync replaced target: {}",
                        target_path.display()
                    )))
                })?;
        }
    }

    Ok(())
}

/// Move one regular file to another locator in the same directory without
/// following either locator.  This is used for credential tombstones: the
/// destination must be absent and a successful native rename is followed by
/// a parent-directory sync, yielding a typed reconciliation failure if the
/// durable ordering becomes uncertain.
pub(crate) fn move_same_dir(
    root: &OwnedStoreRoot,
    source: &SafeRelativePath,
    destination: &SafeRelativePath,
) -> std::result::Result<(), MutationFailure> {
    let source_parent = source.path.parent().unwrap_or_else(|| Path::new("."));
    let destination_parent = destination.path.parent().unwrap_or_else(|| Path::new("."));
    if source_parent != destination_parent {
        return Err(MutationFailure::not_applied(anyhow!(
            "source and destination must have the same parent directory"
        )));
    }
    let (source_path, source_metadata) =
        resolve_owned_relative_path(root, source, "move source", false)
            .map_err(MutationFailure::not_applied)?;
    let Some(source_metadata) = source_metadata else {
        return Err(MutationFailure::not_applied(anyhow!(
            "move source does not exist"
        )));
    };
    if !source_metadata.is_file() {
        return Err(MutationFailure::not_applied(anyhow!(
            "move source is not a regular file"
        )));
    }
    let (destination_path, destination_metadata) =
        resolve_owned_relative_path(root, destination, "move destination", true)
            .map_err(MutationFailure::not_applied)?;
    if destination_metadata.is_some() {
        return Err(MutationFailure::not_applied(anyhow!(
            "move destination already exists"
        )));
    }
    root.verify_identity()
        .map_err(MutationFailure::not_applied)?;

    #[cfg(unix)]
    {
        fs::rename(&source_path, &destination_path).map_err(|error| {
            MutationFailure::not_applied(
                anyhow!(error).context("failed to move credential evidence"),
            )
        })?;
        sync_parent_path(
            destination_path.parent().ok_or_else(|| {
                MutationFailure::reconcile_required(anyhow!("move has no parent"))
            })?,
        )
        .map_err(MutationFailure::reconcile_required)
    }
    #[cfg(windows)]
    {
        // MoveFileExW 的 WRITE_THROUGH 已经是这条“目标不存在的同卷移动”路径的
        // 持久化边界。移动成功后立刻重新打开目标再 FlushFileBuffers 不会增加顺序
        // 保证，反而会与 Windows Defender / 索引器刚拿到的短暂独占句柄竞争，
        // 把已经完成的 rename 误报成需要 reconciliation。
        windows_replace_file(&source_path, &destination_path, false)
            .map_err(MutationFailure::reconcile_required)?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (source_path, destination_path);
        Err(MutationFailure::not_applied(anyhow!(
            "atomic evidence move is unsupported on this platform"
        )))
    }
}

#[cfg(windows)]
fn windows_replace_file(prepared: &Path, target: &Path, target_exists: bool) -> io::Result<()> {
    use std::ptr::null_mut;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_WRITE_THROUGH, MoveFileExW, ReplaceFileW,
    };

    let prepared_wide = wide_path(prepared);
    let target_wide = wide_path(target);
    // Virus scanners and indexers may briefly open a newly written credential without
    // FILE_SHARE_DELETE. A failed call with ERROR_SHARING_VIOLATION has not applied the
    // rename, so a short bounded retry is safe. Every other error remains fail-closed.
    const MAX_SHARING_RETRIES: usize = 50;
    const SHARING_RETRY_DELAY: Duration = Duration::from_millis(10);
    for attempt in 0..=MAX_SHARING_RETRIES {
        let succeeded = unsafe {
            if target_exists {
                // ReplaceFileW's flags=0 is followed by an explicit read/write
                // handle sync, because write-through is not reliable on every FS.
                ReplaceFileW(
                    target_wide.as_ptr(),
                    prepared_wide.as_ptr(),
                    std::ptr::null(),
                    0,
                    null_mut(),
                    null_mut(),
                ) != 0
            } else {
                // The destination was validated as absent. Omitting REPLACE_EXISTING makes a
                // racing destination fail instead of overwriting an unrecognized file.
                MoveFileExW(
                    prepared_wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                ) != 0
            }
        };
        if succeeded {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SHARING_VIOLATION as i32)
            || attempt == MAX_SHARING_RETRIES
        {
            return Err(error);
        }
        std::thread::sleep(SHARING_RETRY_DELAY);
    }
    unreachable!("bounded Windows sharing retry loop always returns")
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    #[cfg(windows)]
    use std::os::windows::fs::symlink_dir;

    fn root_path(temp: &tempfile::TempDir, name: &str) -> PathBuf {
        temp.path().join(name)
    }

    #[test]
    fn root_normalization_rejects_relative_dot_filesystem_root_and_parent() {
        assert!(NormalizedStoreRoot::normalize(Path::new("relative")).is_err());
        assert!(NormalizedStoreRoot::normalize(Path::new(".")).is_err());
        assert!(NormalizedStoreRoot::normalize(Path::new("/")).is_err());
        assert!(NormalizedStoreRoot::normalize(Path::new("/tmp/../store")).is_err());
    }

    #[test]
    fn safe_relative_path_rejects_unsafe_components_and_devices() {
        assert!(SafeRelativePath::new(Path::new("")).is_err());
        assert!(SafeRelativePath::new(Path::new(".")).is_err());
        assert!(SafeRelativePath::new(Path::new("../state")).is_err());
        assert!(SafeRelativePath::new(Path::new("/state")).is_err());
        assert!(SafeRelativePath::new(Path::new("a//b")).is_err());
        assert!(SafeRelativePath::new(Path::new(r"a\\b")).is_err());
        assert!(SafeRelativePath::new(Path::new("CON.txt")).is_err());
        for character in ['<', '>', '"', '|', '?', '*'] {
            let locator = format!("bad{character}name");
            assert!(SafeRelativePath::new(Path::new(&locator)).is_err());
        }
        assert!(SafeRelativePath::new(Path::new("a/ok")).is_ok());

        let accounts = SafeRelativePath::new(Path::new("accounts")).unwrap();
        let account = accounts.child("account-1").unwrap();
        assert_eq!(account.to_slash_string().unwrap(), "accounts/account-1");
        assert!(accounts.child("account:unsafe").is_err());
        assert!(accounts.sibling("account?unsafe").is_err());
        assert_eq!(
            account
                .sibling("account-2")
                .unwrap()
                .to_slash_string()
                .unwrap(),
            "accounts/account-2"
        );
    }

    #[cfg(unix)]
    #[test]
    fn new_root_is_private_and_existing_broad_nonempty_root_is_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "new");
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        let owned = OwnedStoreRoot::claim(normalized).unwrap();
        assert_eq!(
            fs::metadata(owned.as_path()).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let broad = root_path(&temp, "broad");
        fs::create_dir(&broad).unwrap();
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(broad.join("existing"), b"do not claim").unwrap();
        let before = fs::metadata(&broad).unwrap().permissions().mode() & 0o777;
        let normalized = NormalizedStoreRoot::normalize(&broad).unwrap();
        assert!(OwnedStoreRoot::claim(normalized).is_err());
        let after = fs::metadata(&broad).unwrap().permissions().mode() & 0o777;
        assert_eq!(before, after);
    }

    #[test]
    fn secure_create_rejects_an_existing_fixed_suffix_component() {
        let temp = tempfile::tempdir().unwrap();
        let existing = root_path(&temp, "existing");
        fs::create_dir(&existing).unwrap();
        let suffix = vec![OsString::from("existing")];
        assert!(secure_create_missing_suffix(temp.path(), &suffix).is_err());
        assert!(existing.is_dir());
    }

    #[test]
    fn claim_rejects_components_created_after_normalization() {
        let temp = tempfile::tempdir().unwrap();

        let final_root = root_path(&temp, "created-final");
        let normalized = NormalizedStoreRoot::normalize(&final_root).unwrap();
        fs::create_dir(&final_root).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&final_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(OwnedStoreRoot::claim(normalized).is_err());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&final_root).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let intermediate_root = root_path(&temp, "created-intermediate");
        let normalized = NormalizedStoreRoot::normalize(&intermediate_root.join("leaf")).unwrap();
        fs::create_dir(&intermediate_root).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&intermediate_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(OwnedStoreRoot::claim(normalized).is_err());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&intermediate_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_empty_root_can_tighten_readable_but_not_writable() {
        let temp = tempfile::tempdir().unwrap();
        let readable = root_path(&temp, "readable");
        fs::create_dir(&readable).unwrap();
        fs::set_permissions(&readable, fs::Permissions::from_mode(0o744)).unwrap();
        OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&readable).unwrap()).unwrap();
        assert_eq!(
            fs::metadata(&readable).unwrap().permissions().mode() & 0o777,
            0o700
        );

        for (name, mode) in [("group-writable", 0o770), ("world-writable", 0o777)] {
            let writable = root_path(&temp, name);
            fs::create_dir(&writable).unwrap();
            fs::set_permissions(&writable, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&writable).unwrap()).is_err()
            );
            assert_eq!(
                fs::metadata(&writable).unwrap().permissions().mode() & 0o777,
                mode
            );
        }

        let writable = root_path(&temp, "writable");
        fs::create_dir(&writable).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(writable.join("entry"), b"nonempty").unwrap();
        let before = fs::metadata(&writable).unwrap().permissions().mode() & 0o777;
        assert!(OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&writable).unwrap()).is_err());
        assert_eq!(
            fs::metadata(&writable).unwrap().permissions().mode() & 0o777,
            before
        );
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_symlink_is_normalized_but_final_and_below_links_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let real = root_path(&temp, "real");
        fs::create_dir(&real).unwrap();
        let link = root_path(&temp, "ancestor-link");
        symlink(&real, &link).unwrap();
        let normalized = NormalizedStoreRoot::normalize(&link.join("store")).unwrap();
        assert_eq!(
            normalized.as_path(),
            real.canonicalize().unwrap().join("store")
        );

        let final_link = root_path(&temp, "final-link");
        symlink(&real, &final_link).unwrap();
        assert!(NormalizedStoreRoot::normalize(&final_link).is_err());

        let owned =
            OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&real.join("owned")).unwrap())
                .unwrap();
        let child_link = real.join("owned").join("child-link");
        symlink(&real, &child_link).unwrap();
        let locator = SafeRelativePath::new(Path::new("child-link/file")).unwrap();
        assert!(create_new_secure_file(&owned, &locator).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_mode_and_same_directory_replace_are_atomic() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "store");
        let owned = OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&root).unwrap()).unwrap();

        let first = SafeRelativePath::new(Path::new("first.tmp")).unwrap();
        let target = SafeRelativePath::new(Path::new("state.json")).unwrap();
        let mut file = create_new_secure_file(&owned, &first).unwrap();
        std::io::Write::write_all(&mut file, b"one").unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            fs::metadata(root.join("first.tmp"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        replace_same_dir(&owned, &first, &target).unwrap();
        assert_eq!(fs::read(root.join("state.json")).unwrap(), b"one");

        let second = SafeRelativePath::new(Path::new("second.tmp")).unwrap();
        let mut file = create_new_secure_file(&owned, &second).unwrap();
        std::io::Write::write_all(&mut file, b"two").unwrap();
        file.sync_all().unwrap();
        replace_same_dir(&owned, &second, &target).unwrap();
        assert_eq!(fs::read(root.join("state.json")).unwrap(), b"two");
    }

    #[test]
    fn preflight_failure_preserves_target_and_prepared_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "store");
        let owned = OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&root).unwrap()).unwrap();
        let prepared = SafeRelativePath::new(Path::new("prepared.tmp")).unwrap();
        let target = SafeRelativePath::new(Path::new("state.json")).unwrap();
        let mut file = create_new_secure_file(&owned, &prepared).unwrap();
        std::io::Write::write_all(&mut file, b"new").unwrap();
        file.sync_all().unwrap();
        let mut existing = create_new_secure_file(&owned, &target).unwrap();
        std::io::Write::write_all(&mut existing, b"old").unwrap();
        existing.sync_all().unwrap();

        let other_dir = SafeRelativePath::new(Path::new("nested/prepared.tmp")).unwrap();
        let error = replace_same_dir(&owned, &other_dir, &target).unwrap_err();
        assert!(matches!(error, MutationFailure::NotApplied { .. }));
        assert_eq!(fs::read(root.join("state.json")).unwrap(), b"old");
        assert!(root.join("prepared.tmp").exists());
    }

    #[test]
    fn normalized_read_is_side_effect_free_and_rejects_links() {
        let temp = tempfile::tempdir().unwrap();
        let missing_root = root_path(&temp, "missing-store");
        let normalized = NormalizedStoreRoot::normalize(&missing_root).unwrap();
        let locator = SafeRelativePath::new(Path::new("state.json")).unwrap();
        assert!(read_relative_file(&normalized, &locator).unwrap().is_none());
        assert!(!missing_root.exists());

        let root = root_path(&temp, "read-store");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("state.json"), b"state").unwrap();
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        assert_eq!(
            read_relative_file(&normalized, &locator)
                .unwrap()
                .as_deref(),
            Some(&b"state"[..])
        );
        let nested = SafeRelativePath::new(Path::new("missing/state.json")).unwrap();
        assert!(read_relative_file(&normalized, &nested).unwrap().is_none());
        #[cfg(unix)]
        {
            symlink(root.join("state.json"), root.join("link.json")).unwrap();
            let link = SafeRelativePath::new(Path::new("link.json")).unwrap();
            assert!(read_relative_file(&normalized, &link).is_err());
        }
    }

    #[test]
    fn owned_directory_inventory_returns_capability_locators_and_rejects_links() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "owned");
        let owned = OwnedStoreRoot::claim(NormalizedStoreRoot::normalize(&root).unwrap()).unwrap();
        let accounts = SafeRelativePath::new(Path::new("accounts")).unwrap();
        ensure_owned_relative_directory(&owned, &accounts).unwrap();
        fs::write(root.join("accounts").join("account-1"), b"credential").unwrap();
        let entries = enumerate_owned_relative_directory(&owned, &accounts, 8).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].0.to_slash_string().unwrap(),
            "accounts/account-1"
        );

        #[cfg(unix)]
        {
            symlink(
                root.join("accounts").join("account-1"),
                root.join("accounts").join("link"),
            )
            .unwrap();
            assert!(enumerate_owned_relative_directory(&owned, &accounts, 8).is_err());
        }
    }

    #[test]
    fn external_directory_capability_adopts_arbitrary_nonempty_root_without_chmod() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "external");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("unrelated-data.bin"), b"keep").unwrap();
        fs::create_dir(root.join("config")).unwrap();
        #[cfg(unix)]
        let root_mode_before = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        #[cfg(unix)]
        {
            let unrelated_target = root_path(&temp, "unrelated-target");
            fs::write(&unrelated_target, b"outside fixed locators").unwrap();
            symlink(&unrelated_target, root.join("unrelated-link")).unwrap();
        }
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        let lock = SafeRelativePath::new(Path::new(".sagy-external.lock")).unwrap();
        let preflight = ExternalDirectoryCapability::preflight_existing(&normalized, lock).unwrap();
        let capability =
            ExternalDirectoryCapability::adopt_existing(normalized, &preflight).unwrap();
        assert!(capability.create_new(&preflight.lock).is_err());
        assert!(capability.remove(&preflight.lock).is_err());
        assert!(capability.sync(&preflight.lock).is_err());
        assert!(capability.sync_parent(&preflight.lock).is_err());

        let target = SafeRelativePath::new(Path::new("config/token.json")).unwrap();
        let staged = SafeRelativePath::new(Path::new("config/token.tmp")).unwrap();
        let mut file = capability.create_new(&staged).unwrap();
        std::io::Write::write_all(&mut file, b"secret").unwrap();
        file.sync_all().unwrap();
        capability.replace(&staged, &target).unwrap();
        assert_eq!(
            capability.read_bounded(&target, 64).unwrap().as_deref(),
            Some(&b"secret"[..])
        );

        let moved = SafeRelativePath::new(Path::new("config/token.moved")).unwrap();
        capability.move_file(&target, &moved).unwrap();
        assert!(capability.inspect(&moved, false).unwrap().is_some());
        assert!(capability.remove(&moved).unwrap());
        capability.sync_parent(&moved).unwrap();
        assert!(!root.join("unrelated-data.bin").is_symlink());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            root_mode_before
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_move_retries_a_transient_non_delete_sharing_handle() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::time::Duration;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "windows-sharing");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("unrelated.bin"), b"keep").unwrap();
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        let lock = SafeRelativePath::new(Path::new(".sagy-external.lock")).unwrap();
        let capability = ExternalDirectoryCapability::claim_or_adopt(normalized, lock).unwrap();
        let source = SafeRelativePath::new(Path::new("source.bin")).unwrap();
        let destination = SafeRelativePath::new(Path::new("destination.bin")).unwrap();
        let mut staged = capability.create_new(&source).unwrap();
        std::io::Write::write_all(&mut staged, b"credential").unwrap();
        staged.sync_all().unwrap();
        drop(staged);

        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(root.join("source.bin"))
            .unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(held);
        });

        capability.move_file(&source, &destination).unwrap();
        release.join().unwrap();
        assert!(capability.inspect(&source, true).unwrap().is_none());
        assert_eq!(
            capability
                .read_bounded(&destination, 32)
                .unwrap()
                .as_deref(),
            Some(&b"credential"[..])
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_directory_capability_allows_unrelated_symlink_but_rejects_target_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "external-links");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("keep"), b"keep").unwrap();
        let victim = root_path(&temp, "victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, root.join("top-link")).unwrap();
        let _unrelated_socket = UnixListener::bind(root.join("unrelated.sock")).unwrap();
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        let lock = SafeRelativePath::new(Path::new(".sagy-external.lock")).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        symlink(&victim, root.join("nested/link")).unwrap();
        let preflight = ExternalDirectoryCapability::preflight_existing(&normalized, lock).unwrap();
        let capability =
            ExternalDirectoryCapability::adopt_existing(normalized, &preflight).unwrap();
        let unrelated = SafeRelativePath::new(Path::new("top-link")).unwrap();
        assert!(capability.inspect(&unrelated, false).is_err());
        let locator = SafeRelativePath::new(Path::new("nested/link/file")).unwrap();
        assert!(capability.inspect(&locator, true).is_err());
    }

    #[test]
    fn external_directory_capability_claims_missing_and_empty_roots() {
        let temp = tempfile::tempdir().unwrap();
        let lock = SafeRelativePath::new(Path::new(".sagy-active.lock")).unwrap();

        let missing = root_path(&temp, "missing-active-home");
        let capability = ExternalDirectoryCapability::claim_or_adopt(
            NormalizedStoreRoot::normalize(&missing).unwrap(),
            lock.clone(),
        )
        .unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&missing).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let target = SafeRelativePath::new(Path::new("active.json")).unwrap();
        let mut file = capability.create_new(&target).unwrap();
        std::io::Write::write_all(&mut file, b"active").unwrap();
        file.sync_all().unwrap();
        drop(capability);

        let repeated = ExternalDirectoryCapability::claim_or_adopt(
            NormalizedStoreRoot::normalize(&missing).unwrap(),
            lock,
        )
        .unwrap();
        assert_eq!(
            repeated.read_bounded(&target, 32).unwrap().as_deref(),
            Some(&b"active"[..])
        );
        drop(repeated);

        let empty = root_path(&temp, "empty-active-home");
        fs::create_dir(&empty).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o755)).unwrap();
        let empty_lock = SafeRelativePath::new(Path::new(".sagy-active.lock")).unwrap();
        let empty_capability = ExternalDirectoryCapability::claim_or_adopt(
            NormalizedStoreRoot::normalize(&empty).unwrap(),
            empty_lock,
        )
        .unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&empty).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(empty_capability.inspect(&target, true).unwrap().is_none());
    }

    #[test]
    fn external_directory_capability_rejects_identity_change_after_preflight() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "external-identity");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("old"), b"old").unwrap();
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        let lock = SafeRelativePath::new(Path::new(".sagy-external.lock")).unwrap();
        let preflight = ExternalDirectoryCapability::preflight_existing(&normalized, lock).unwrap();

        let moved = root_path(&temp, "external-identity-moved");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("new"), b"new").unwrap();
        assert!(ExternalDirectoryCapability::adopt_existing(normalized, &preflight).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_root_identity_uses_the_directory_handle_and_rejects_reparse_roots() {
        let temp = tempfile::tempdir().unwrap();
        let root = root_path(&temp, "populated");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("state.json"), b"state").unwrap();
        let normalized = NormalizedStoreRoot::normalize(&root).unwrap();
        let first = normalized_root_identity(&normalized).unwrap();
        let second = normalized_root_identity(&normalized).unwrap();
        assert_eq!(first, second);

        let link = root_path(&temp, "junction-or-link");
        if symlink_dir(&root, &link).is_ok() {
            assert!(NormalizedStoreRoot::normalize(&link).is_err());
        }
    }

    #[test]
    fn digest_round_trip() {
        let digest = DocumentDigest::from_bytes(b"document");
        let encoded = digest.to_hex();
        assert_eq!(DocumentDigest::from_hex(&encoded).unwrap(), digest);
    }

    // ---------------------------------------------------------------
    // R1-5: 锁等待必须可诊断

    /// 打开同一个锁文件的第二个句柄。flock 是按 open-file-description 计的,
    /// 所以同一进程内的两个句柄之间也是真实互斥的。
    fn open_lock_handle(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .expect("open lock handle")
    }

    /// AC-R1-5.2 / 5.3: 锁立刻可得时既不打印, 也不引入任何延迟。
    #[test]
    fn uncontended_lock_never_announces_and_never_waits() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("free.lock");
        let file = open_lock_handle(&path);

        let mut announced = 0usize;
        let started = Instant::now();
        let acquired = poll_exclusive_lock(&file, Duration::from_secs(30), &mut || announced += 1)
            .expect("probe a free lock");
        let elapsed = started.elapsed();

        assert!(acquired, "a free lock was not acquired on the fast path");
        assert_eq!(announced, 0, "a free lock announced a wait");
        assert!(
            elapsed < Duration::from_millis(500),
            "the fast path waited {elapsed:?}"
        );
        FileExt::unlock(&file).expect("release lock");
    }

    /// AC-R1-5.1 / 5.4: 另一个线程真的持有锁时, 等待超过阈值必须打印提示,
    /// 而且提示打印之后仍然要真的把锁拿到手。
    #[test]
    fn contended_lock_announces_once_and_still_acquires() {
        use std::sync::mpsc;

        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("busy.lock");

        let holder_path = path.clone();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            let holder = open_lock_handle(&holder_path);
            FileExt::lock_exclusive(&holder).expect("hold the lock");
            held_tx.send(()).expect("signal that the lock is held");
            release_rx.recv().expect("wait for release");
            FileExt::unlock(&holder).expect("release the lock");
        });
        held_rx.recv().expect("lock is held by the other thread");

        let waiter = open_lock_handle(&path);
        let mut announced = 0usize;
        let acquired =
            poll_exclusive_lock(&waiter, Duration::from_millis(120), &mut || announced += 1)
                .expect("probe a held lock");
        assert!(!acquired, "a held lock was reported as acquired");
        assert_eq!(
            announced, 1,
            "a lock wait past the threshold did not announce"
        );

        // 提示打印之后必须真的把锁拿到手, 而不是把等待变成失败。
        release_tx.send(()).expect("ask the holder to release");
        holder.join().expect("holder thread");
        lock_exclusive_with_wait_notice(&waiter).expect("acquire the released lock");
        FileExt::unlock(&waiter).expect("release lock");
    }

    /// AC-R1-5.3: 阈值内让出锁的等待必须静默返回, 且不得把调用方多拖一个阈值。
    #[test]
    fn lock_released_within_the_threshold_is_acquired_without_a_notice() {
        use std::sync::mpsc;

        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("brief.lock");

        let holder_path = path.clone();
        let (held_tx, held_rx) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            let holder = open_lock_handle(&holder_path);
            FileExt::lock_exclusive(&holder).expect("hold the lock");
            held_tx.send(()).expect("signal that the lock is held");
            std::thread::sleep(Duration::from_millis(80));
            FileExt::unlock(&holder).expect("release the lock");
        });
        held_rx.recv().expect("lock is held by the other thread");

        let waiter = open_lock_handle(&path);
        let mut announced = 0usize;
        let started = Instant::now();
        let acquired =
            poll_exclusive_lock(&waiter, Duration::from_secs(10), &mut || announced += 1)
                .expect("probe a briefly held lock");
        let elapsed = started.elapsed();
        holder.join().expect("holder thread");

        assert!(acquired, "a released lock was not acquired");
        assert_eq!(announced, 0, "a sub-threshold wait announced");
        assert!(
            elapsed < Duration::from_secs(5),
            "the waiter was parked for {elapsed:?} after the lock was released"
        );
        FileExt::unlock(&waiter).expect("release lock");
    }

    /// AC-R1-5.2: 探测式预告在快路径上必须把锁原样交还给调用方。
    #[test]
    fn announce_probe_leaves_the_lock_available_to_the_caller() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("probe.lock");
        let file = open_lock_handle(&path);

        announce_lock_wait_before_blocking(&file);

        let other = open_lock_handle(&path);
        FileExt::try_lock_exclusive(&other)
            .expect("the probe kept a lock it was supposed to release");
        FileExt::unlock(&other).expect("release lock");
    }
}
