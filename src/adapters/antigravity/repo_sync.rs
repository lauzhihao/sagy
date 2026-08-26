use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer as _, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::repo_bundle;
use crate::adapters::antigravity::account::credential_store::{
    CredentialStore, PublishedCredentialTxn,
};
use crate::adapters::antigravity::active_home::{
    ActiveHomeError, ActiveHomeStore, restore_reconcile,
};
use crate::adapters::antigravity::paths::{
    active_home_roots, find_git_bin, validate_bundle_dir, validate_path_under_root,
};
use crate::core::atomic_io::read_external_regular_file_bounded;
use crate::core::credential::{CredentialKind, PortableCredential};
use crate::core::state::{
    AccountRecord, CredentialRef, CredentialRefKind, STATE_V2_VERSION, State, SyncWatermark,
    UsageSnapshot, validate_state_invariants,
};
use crate::core::state_store::{
    MigrationStatus, RevisionGeneration, StateSession, StateStoreError,
};
use crate::core::storage;

const DEFAULT_BUNDLE_DIR: &str = ".sagy-account-pool";
const BUNDLE_FILENAME: &str = "bundle.enc.json";
const BUNDLE_KEY_ENV: &str = "SAGY_POOL_KEY";
const BUNDLE_ALGORITHM: &str = "xchacha20poly1305-argon2id";
const MAX_BUNDLE_CIPHERTEXT_BYTES: usize = 12 * 1024 * 1024;
const MAX_BUNDLE_CIPHERTEXT_BASE64_BYTES: usize = 4 * MAX_BUNDLE_CIPHERTEXT_BYTES.div_ceil(3);
// Base64 expands a 12 MiB ciphertext to roughly 16 MiB before the JSON
// envelope fields are added. Keep the envelope bound comfortably above that
// expansion while remaining a fixed pre-allocation guard.
const MAX_ENCRYPTED_PAYLOAD_BYTES: usize = 24 * 1024 * 1024;

/// Legacy source-compatibility shape. It is intentionally not accepted by
/// the v2 repository adapter; keeping the type avoids breaking downstream
/// code while preventing the old lossy wire format from being emitted.
#[deprecated(note = "repository synchronization uses repo_bundle::BundleV2")]
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountPoolBundle {
    pub version: u32,
    pub exported_at: i64,
    pub accounts: Vec<AccountRecord>,
}

#[allow(deprecated)]
impl std::fmt::Debug for AccountPoolBundle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountPoolBundle")
            .field("version", &self.version)
            .field("exported_at", &self.exported_at)
            .field("account_count", &self.accounts.len())
            .finish()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EncryptedBundlePayload {
    pub algorithm: String,
    #[serde(default)]
    pub salt: Option<String>,
    pub nonce: String,
    pub ciphertext: String,
}

impl<'de> Deserialize<'de> for EncryptedBundlePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let payload = deserializer.deserialize_map(EncryptedBundleVisitor)?;
        validate_encrypted_payload(&payload).map_err(de::Error::custom)?;
        Ok(payload)
    }
}

impl EncryptedBundlePayload {
    fn decode_strict(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENCRYPTED_PAYLOAD_BYTES {
            bail!("encrypted bundle envelope exceeds the size limit");
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let payload = deserializer
            .deserialize_map(EncryptedBundleVisitor)
            .map_err(|_| anyhow!("invalid encrypted bundle envelope"))?;
        deserializer
            .end()
            .map_err(|_| anyhow!("trailing data after encrypted bundle envelope"))?;
        validate_encrypted_payload(&payload)?;
        Ok(payload)
    }
}

struct EncryptedBundleVisitor;

impl<'de> Visitor<'de> for EncryptedBundleVisitor {
    type Value = EncryptedBundlePayload;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a strict encrypted bundle envelope")
    }

    fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut algorithm = None;
        let mut salt = None;
        let mut nonce = None;
        let mut ciphertext = None;
        let mut salt_seen = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "algorithm" => {
                    if algorithm.is_some() {
                        return Err(de::Error::duplicate_field("algorithm"));
                    }
                    algorithm = Some(map.next_value()?);
                }
                "salt" => {
                    if salt_seen {
                        return Err(de::Error::duplicate_field("salt"));
                    }
                    salt_seen = true;
                    salt = Some(map.next_value::<String>()?);
                }
                "nonce" => {
                    if nonce.is_some() {
                        return Err(de::Error::duplicate_field("nonce"));
                    }
                    nonce = Some(map.next_value()?);
                }
                "ciphertext" => {
                    if ciphertext.is_some() {
                        return Err(de::Error::duplicate_field("ciphertext"));
                    }
                    ciphertext = Some(map.next_value()?);
                }
                other => {
                    return Err(de::Error::unknown_field(
                        other,
                        &["algorithm", "salt", "nonce", "ciphertext"],
                    ));
                }
            }
        }
        Ok(EncryptedBundlePayload {
            algorithm: algorithm.ok_or_else(|| de::Error::missing_field("algorithm"))?,
            salt,
            nonce: nonce.ok_or_else(|| de::Error::missing_field("nonce"))?,
            ciphertext: ciphertext.ok_or_else(|| de::Error::missing_field("ciphertext"))?,
        })
    }
}

struct IncomingAccount {
    account_id: String,
    metadata: repo_bundle::BundleAccountMetadata,
    credential: PortableCredential,
    credential_ref: CredentialRef,
    material: Vec<u8>,
}

fn validate_v2_state(state: &State) -> Result<()> {
    if state.version != STATE_V2_VERSION {
        bail!("repository synchronization requires State v2");
    }
    validate_state_invariants(state)?;
    Ok(())
}

fn credential_ref_kind(kind: CredentialKind) -> CredentialRefKind {
    match kind {
        CredentialKind::OAuthAccessToken => CredentialRefKind::OauthAccessToken,
        CredentialKind::OAuthAuthorizedUser => CredentialRefKind::OauthAuthorizedUser,
        CredentialKind::ApiKey => CredentialRefKind::ApiKey,
        CredentialKind::VertexServiceAccount => CredentialRefKind::VertexServiceAccount,
        CredentialKind::AntigravityToken => CredentialRefKind::AntigravityToken,
        CredentialKind::GeminiOAuthSession => CredentialRefKind::GeminiOauthSession,
    }
}

fn credential_material(credential: &PortableCredential) -> Result<Vec<u8>> {
    // Provider-native sources are deliberately retained byte-for-byte.  The
    // active-home file is consumed by the provider itself, so canonicalizing
    // JSON here would be a lossy repository round-trip.
    if let Some(source) = credential.source_bytes() {
        return Ok(source.to_vec());
    }
    if credential.kind() == CredentialKind::OAuthAccessToken {
        return credential
            .access_token()
            .map(str::as_bytes)
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("raw OAuth credential has no access token"));
    }
    Ok(credential
        .to_native_json_string()
        .map_err(anyhow::Error::new)?
        .into_bytes())
}

/// Normalize the path portion of a remote repository location.
///
/// Leading/trailing separators, empty segments, `.`/`..` and one trailing
/// `.git` suffix are all pure spelling differences for the same repository.
fn normalize_remote_repo_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let joined = segments.join("/");
    joined
        .strip_suffix(".git")
        .map(str::to_owned)
        .unwrap_or(joined)
}

/// Normalize a local filesystem repository location lexically.
///
/// `.git` is deliberately *not* stripped here: `/srv/pool` and `/srv/pool.git`
/// can both exist as distinct directories on the same machine.
fn normalize_local_repo_path(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.last().is_some_and(|last| *last != "..") {
                    segments.pop();
                } else {
                    segments.push("..");
                }
            }
            other => segments.push(other),
        }
    }
    let joined = segments.join("/");
    if absolute {
        format!("/{joined}")
    } else {
        joined
    }
}

/// Derive a spelling-independent identity for a repository location.
///
/// 审计指出 pool_id 直接哈希原始字符串，导致 `https://h/u/r.git`、`https://h/u/r`、
/// `git@h:u/r.git`、`ssh://git@h/u/r.git` 派生出四个不同的 pool，用户换一种写法
/// 就永久卡在 "different account pool"。身份必须只由 host + 仓库路径决定。
fn canonical_repo_identity(repo: &str) -> String {
    let trimmed = repo.trim();
    if let Some(scheme_end) = trimmed.find("://") {
        let scheme = trimmed[..scheme_end].to_ascii_lowercase();
        let tail = &trimmed[scheme_end + 3..];
        if scheme == "file" {
            // file:// 的 authority 只可能是空或 localhost，其余部分就是本地路径。
            let path = tail.strip_prefix("localhost").unwrap_or(tail);
            return format!("local:{}", normalize_local_repo_path(path));
        }
        let authority_end = tail.find('/').unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        let path = &tail[authority_end..];
        return format!(
            "remote:{}/{}",
            host.to_ascii_lowercase(),
            normalize_remote_repo_path(path)
        );
    }
    if let Some(at) = trimmed.find('@') {
        let user = &trimmed[..at];
        let rest = &trimmed[at + 1..];
        if !user.contains('/') {
            if let Some(colon_offset) = rest.find(':') {
                let host = &rest[..colon_offset];
                let path = &rest[colon_offset + 1..];
                if !host.is_empty() && !host.contains('/') {
                    return format!(
                        "remote:{}/{}",
                        host.to_ascii_lowercase(),
                        normalize_remote_repo_path(path)
                    );
                }
            }
        }
    }
    format!("local:{}", normalize_local_repo_path(trimmed))
}

/// Shape a 32-byte digest into the canonical UUIDv4 textual form.
fn pool_id_from_digest(digest: &[u8]) -> String {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Mark this deterministic identifier as a UUIDv4-shaped value so every
    // platform uses the same canonical textual representation.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn pool_id_for_repo(repo: &str) -> String {
    // The state schema stores watermarks by pool UUID, not by a repository
    // path. Deriving a stable UUID keeps separate repositories isolated while
    // avoiding another secret-bearing state field.
    pool_id_from_digest(&Sha256::digest(canonical_repo_identity(repo).as_bytes()))
}

/// The pre-canonicalization pool id: a plain digest of the raw repository
/// string.
///
/// 归一化之前发布的每一个 v2 bundle 都带着这个旧 pool_id。没有兼容分支的话,
/// 升级后所有存量仓库都会命中 "different account pool" 而 push/pull 双向锁死,
/// 唯一的"恢复"办法是删掉远端 bundle——那等于丢账号。
fn legacy_pool_id_for_repo(repo: &str) -> String {
    pool_id_from_digest(&Sha256::digest(repo.as_bytes()))
}

/// Split an scp-style location `user@host:path` into its three parts.
fn scp_repo_parts(repo: &str) -> Option<(&str, &str, &str)> {
    let (user, rest) = repo.split_once('@')?;
    if user.is_empty() || user.contains('/') || user.contains(':') {
        return None;
    }
    let (host, path) = rest.split_once(':')?;
    if host.is_empty() || host.contains('/') || path.is_empty() || path.starts_with('/') {
        return None;
    }
    Some((user, host, path))
}

/// Does this spelling name a host-bearing repository?
///
/// 只有远端写法才允许增删 `.git`: 本地路径 `/srv/pool` 与 `/srv/pool.git` 可以是
/// 同一台机器上两个不同的目录, 规范化函数也刻意没有把它们合并。
fn is_remote_repo_spelling(repo: &str) -> bool {
    if let Some(scheme_end) = repo.find("://") {
        return !repo[..scheme_end].eq_ignore_ascii_case("file");
    }
    scp_repo_parts(repo).is_some()
}

/// Rewrite one remote spelling into the other transport form git accepts for
/// the same repository (`ssh://user@host/path` <-> `user@host:path`).
fn alternate_transport_spelling(repo: &str) -> Option<String> {
    if repo.len() >= 6 && repo[..6].eq_ignore_ascii_case("ssh://") {
        let rest = &repo[6..];
        let authority_end = rest.find('/')?;
        let authority = &rest[..authority_end];
        let path = &rest[authority_end + 1..];
        if authority.is_empty() || path.is_empty() {
            return None;
        }
        // scp 写法表达不了端口, 带端口的 ssh:// 没有等价 scp 形式。
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host);
        if host.is_empty() || host.contains(':') || !authority.contains('@') {
            return None;
        }
        return Some(format!("{authority}:{path}"));
    }
    let (user, host, path) = scp_repo_parts(repo)?;
    Some(format!("ssh://{user}@{host}/{path}"))
}

fn push_unique(values: &mut Vec<String>, candidate: String) {
    if !values.contains(&candidate) {
        values.push(candidate);
    }
}

/// Every pre-canonicalization spelling of one repository.
///
/// 存量 bundle 的 pool_id 是"当年那次 push 用的那个具体写法"的裸哈希。只认字节
/// 完全一致的写法, 用户今天换成等价写法就重新锁死。这里枚举 git 自己视为同一个
/// 仓库的等价类:
///   1. 原样字符串与 trim 之后的字符串;
///   2. 远端写法的 scp 形式与 `ssh://` 形式互转;
///   3. 每种基形式再叠加 尾斜杠 与(仅远端) `.git` 后缀 的组合。
///
/// 代价是每次解析 pool 身份时多算十几个短字符串的 SHA-256, 相对一次 git clone
/// 可以忽略; 换来的是存量仓库不会因为换一种写法而永久卡死。
fn legacy_repo_spellings(repo: &str) -> Vec<String> {
    let trimmed = repo.trim();
    let mut bases = Vec::new();
    push_unique(&mut bases, repo.to_string());
    push_unique(&mut bases, trimmed.to_string());
    if let Some(alternate) = alternate_transport_spelling(trimmed) {
        push_unique(&mut bases, alternate);
    }

    let mut spellings = bases.clone();
    for base in bases {
        let stem = base.trim_end_matches('/');
        if stem.is_empty() {
            continue;
        }
        push_unique(&mut spellings, stem.to_string());
        push_unique(&mut spellings, format!("{stem}/"));
        if !is_remote_repo_spelling(stem) {
            continue;
        }
        match stem.strip_suffix(".git") {
            Some(without) if !without.is_empty() && !without.ends_with('/') => {
                push_unique(&mut spellings, without.to_string());
                push_unique(&mut spellings, format!("{without}/"));
            }
            _ => {
                push_unique(&mut spellings, format!("{stem}.git"));
                push_unique(&mut spellings, format!("{stem}.git/"));
            }
        }
    }
    spellings
}

/// The legacy pool ids a repository's stored bundle may still carry.
fn legacy_pool_ids_for_repo(repo: &str) -> Vec<String> {
    legacy_repo_spellings(repo)
        .iter()
        .map(|spelling| legacy_pool_id_for_repo(spelling))
        .collect()
}

/// The pool id a repository maps to, plus the id the stored bundle still uses.
#[derive(Debug, Clone)]
struct PoolIdentity {
    /// The id every local state map keys on from now on.
    canonical: String,
    /// The id the remote bundle currently carries; equal to `canonical` unless
    /// the bundle was written before pool ids were canonicalized.
    remote: String,
}

impl PoolIdentity {
    /// The pool id the bundle itself carries, which is what
    /// [`repo_bundle::BundleV2::check_sync_watermark`] must be given.
    fn remote_pool_id(&self) -> &str {
        &self.remote
    }

    /// `Some` only while the bundle still carries the pre-canonical id.
    fn legacy(&self) -> Option<&str> {
        (self.canonical != self.remote).then_some(self.remote.as_str())
    }
}

/// Resolve the pool identity for a repository and its stored bundle.
fn resolve_pool_identity(
    repo: &str,
    bundle: Option<&repo_bundle::BundleV2>,
    bundle_dir: &str,
) -> Result<PoolIdentity> {
    let canonical = pool_id_for_repo(repo);
    let Some(bundle) = bundle else {
        return Ok(PoolIdentity {
            remote: canonical.clone(),
            canonical,
        });
    };
    if bundle.pool_id() == canonical {
        return Ok(PoolIdentity {
            remote: canonical.clone(),
            canonical,
        });
    }
    if legacy_pool_ids_for_repo(repo)
        .iter()
        .any(|legacy| legacy == bundle.pool_id())
    {
        // 存量仓库: 接受旧 pool_id, 下一次 push 会把它 re-key 成规范形式。
        return Ok(PoolIdentity {
            remote: bundle.pool_id().to_string(),
            canonical,
        });
    }
    // 只说 "belongs to a different account pool" 对用户毫无帮助，必须给出
    // 原因和两条具体的恢复路径。
    bail!(
        "repository bundle belongs to a different account pool.\n\
         This repository location maps to pool {canonical}, but the stored bundle carries pool {}.\n\
         Cause: the bundle file was created for another repository (copied, forked or moved), \
         so its accounts do not belong to this pool.\n\
         Recovery, pick one:\n\
         1. Point sagy back at the repository this pool was created for \
         (`sagy push <original-repo>` or `sagy pull <original-repo>`).\n\
         2. Re-key this repository as a new pool: confirm every account in the bundle also \
         exists locally (`sagy list`), then delete `{bundle_dir}/{BUNDLE_FILENAME}` from the \
         repository (git rm, commit, push) and run `sagy push` again. Deleting that file \
         discards whatever it still holds.",
        bundle.pool_id()
    )
}

/// Read the watermark stored for a pool, falling back to the legacy key.
///
/// 升级前写下的水位挂在旧 pool_id 上; 找不到就当成"从未同步过", push 会误判
/// 落后于远端而拒绝。
fn watermark_for_pool<'a>(state: &'a State, identity: &PoolIdentity) -> Option<&'a SyncWatermark> {
    state.sync_watermarks.get(&identity.canonical).or_else(|| {
        identity
            .legacy()
            .and_then(|key| state.sync_watermarks.get(key))
    })
}

/// Store the watermark under the canonical key and drop the legacy one.
fn rekey_watermark(candidate: &mut State, identity: &PoolIdentity, watermark: SyncWatermark) {
    if let Some(legacy) = identity.legacy() {
        candidate.sync_watermarks.remove(legacy);
    }
    candidate
        .sync_watermarks
        .insert(identity.canonical.clone(), watermark);
}

fn metadata_for_account(account: &AccountRecord) -> Result<repo_bundle::BundleAccountMetadata> {
    repo_bundle::BundleAccountMetadata::new(
        account.email.clone(),
        account.account_type,
        account.provider_id.clone(),
        account.project_id.clone(),
        account.account_id.clone(),
        account.identity_fingerprint.clone(),
        account.plan.clone(),
        account.added_at,
        account.updated_at,
        account.last_used_at,
    )
    .map_err(anyhow::Error::new)
}

fn credential_identity_key(credential: &PortableCredential) -> String {
    format!(
        "{}:{}",
        credential.kind().as_str(),
        credential.identity_fingerprint()
    )
}

fn credential_ref_identity_key(reference: &CredentialRef, identity: &str) -> String {
    format!("{}:{identity}", credential_ref_kind_name(reference.kind))
}

const fn credential_ref_kind_name(kind: CredentialRefKind) -> &'static str {
    match kind {
        CredentialRefKind::OauthAccessToken => "oauth_access_token",
        CredentialRefKind::OauthAuthorizedUser => "oauth_authorized_user",
        CredentialRefKind::ApiKey => "api_key",
        CredentialRefKind::VertexServiceAccount => "vertex_service_account",
        CredentialRefKind::AntigravityToken => "antigravity_token",
        CredentialRefKind::GeminiOauthSession => "gemini_oauth_session",
    }
}

fn metadata_for_account_credential(
    account: &AccountRecord,
    credential: &PortableCredential,
) -> Result<repo_bundle::BundleAccountMetadata> {
    let mut metadata = metadata_for_account(account)?;
    // Older state records did not carry identity_fingerprint.  Populate it
    // only for provider-native kinds, whose domain value explicitly defines
    // an identity independent from the exact source bytes. Existing kinds
    // retain their historical metadata and fingerprint behavior.
    if metadata.identity_fingerprint.is_none()
        && matches!(
            credential.kind(),
            CredentialKind::AntigravityToken | CredentialKind::GeminiOAuthSession
        )
    {
        metadata.identity_fingerprint = Some(credential.identity_fingerprint());
    }
    Ok(metadata)
}

/// One local account that could not be exported into the bundle.
#[derive(Debug, Clone)]
struct SkippedAccount {
    id: String,
    email: String,
    reason: String,
}

impl SkippedAccount {
    fn describe(&self) -> String {
        format!("  - {} ({}): {}", self.id, self.email, self.reason)
    }
}

/// Owner of a fingerprint already claimed by an earlier account.
struct FingerprintOwner {
    id: String,
    email: String,
    added_at: i64,
}

fn duplicate_fingerprint_error(
    owner: &FingerprintOwner,
    account: &AccountRecord,
    fingerprint: &str,
) -> anyhow::Error {
    // 只说 "duplicate credential fingerprint in local state" 用户根本不知道该删哪个,
    // 必须点名两个账号并给出建议保留项。
    let (keep, drop_id) = if owner.added_at <= account.added_at {
        (owner.id.as_str(), account.id.as_str())
    } else {
        (account.id.as_str(), owner.id.as_str())
    };
    anyhow!(
        "local state holds the same credential twice: account {} ({}) and account {} ({}) share credential identity fingerprint {}.\n\
         An account pool cannot carry one credential under two account ids.\n\
         Recovery: keep {} (added first) and run `sagy rm {}`, then run `sagy push` again.",
        owner.id,
        owner.email,
        account.id,
        account.email,
        fingerprint,
        keep,
        drop_id
    )
}

/// Collect the exportable accounts and report the ones that had to be skipped.
///
/// 单个账号的凭据文件缺失或损坏不得阻断整包 push: 其余健康账号必须照常备份,
/// 被跳过的账号由调用方以 ASCII 提示列出。
fn load_v2_bundle_accounts(
    state_dir: &Path,
    state: &State,
) -> Result<(Vec<repo_bundle::BundleAccount>, Vec<SkippedAccount>)> {
    let mut accounts = state.accounts.clone();
    accounts.sort_by(|left, right| left.id.cmp(&right.id));
    let mut result = Vec::with_capacity(accounts.len());
    let mut skipped = Vec::new();
    let mut fingerprints: BTreeMap<String, FingerprintOwner> = BTreeMap::new();
    for account in accounts {
        let Some(reference) = state.credential_refs.get(&account.id) else {
            skipped.push(SkippedAccount {
                id: account.id.clone(),
                email: account.email.clone(),
                reason: "state has no credential reference".to_string(),
            });
            continue;
        };
        let store = match CredentialStore::new(state_dir, &account.id) {
            Ok(store) => store,
            Err(error) => {
                skipped.push(SkippedAccount {
                    id: account.id.clone(),
                    email: account.email.clone(),
                    reason: format!("credential store unavailable: {error}"),
                });
                continue;
            }
        };
        let stored = match store.read(reference) {
            Ok(stored) => stored,
            Err(error) => {
                skipped.push(SkippedAccount {
                    id: account.id.clone(),
                    email: account.email.clone(),
                    reason: format!("credential is missing or corrupt: {error}"),
                });
                continue;
            }
        };
        if stored.credential.fingerprint() != reference.fingerprint
            || credential_ref_kind(stored.credential.kind()) != reference.kind
        {
            skipped.push(SkippedAccount {
                id: account.id.clone(),
                email: account.email.clone(),
                reason: "credential reference is inconsistent with the stored credential"
                    .to_string(),
            });
            continue;
        }
        let identity_key = credential_identity_key(&stored.credential);
        if let Some(owner) = fingerprints.get(&identity_key) {
            // 重复凭据是歧义而不是"坏账号": 静默跳过会让用户永远不知道池子里
            // 少了一个账号, 所以这里仍然硬失败, 但必须点名两个账号。
            return Err(duplicate_fingerprint_error(
                owner,
                &account,
                &stored.credential.identity_fingerprint(),
            ));
        }
        fingerprints.insert(
            identity_key,
            FingerprintOwner {
                id: account.id.clone(),
                email: account.email.clone(),
                added_at: account.added_at,
            },
        );
        let metadata = match metadata_for_account_credential(&account, &stored.credential) {
            Ok(metadata) => metadata,
            Err(error) => {
                skipped.push(SkippedAccount {
                    id: account.id.clone(),
                    email: account.email.clone(),
                    reason: format!("account metadata is not portable: {error}"),
                });
                continue;
            }
        };
        match repo_bundle::BundleAccount::new(account.id.clone(), metadata, stored.credential) {
            Ok(bundle_account) => result.push(bundle_account),
            Err(error) => skipped.push(SkippedAccount {
                id: account.id.clone(),
                email: account.email.clone(),
                reason: format!("account cannot be represented in a bundle: {error}"),
            }),
        }
    }
    Ok((result, skipped))
}

fn make_v2_bundle(
    pool_id: &str,
    generation: u64,
    accounts: Vec<repo_bundle::BundleAccount>,
    tombstones: Vec<repo_bundle::BundleTombstone>,
) -> Result<repo_bundle::BundleV2> {
    repo_bundle::BundleV2::new_with_tombstones(
        pool_id,
        generation,
        chrono::Utc::now().timestamp(),
        accounts,
        tombstones,
    )
    .map_err(anyhow::Error::new)
}

fn bundle_semantic_hash(
    accounts: &[repo_bundle::BundleAccount],
    tombstones: &[repo_bundle::BundleTombstone],
    pool_id: &str,
) -> Result<String> {
    make_v2_bundle(pool_id, 1, accounts.to_vec(), tombstones.to_vec())?
        .semantic_sha256()
        .map_err(anyhow::Error::new)
}

/// Deletion records inherited from the remote bundle.
///
/// 过期记录被丢弃以保证列表有界; 一旦同一个 account id 又被导出, 对应的历史
/// tombstone 也要丢掉, 否则重新加回来的账号会被自己的删除记录再删一次。
fn carried_tombstones(
    remote: Option<&repo_bundle::BundleV2>,
    exported: &[repo_bundle::BundleAccount],
    now: i64,
) -> Vec<repo_bundle::BundleTombstone> {
    let exported_ids: BTreeSet<&str> = exported.iter().map(|item| item.id.as_str()).collect();
    remote
        .map(|bundle| {
            bundle
                .tombstones()
                .iter()
                .filter(|tombstone| tombstone.is_live_at(now))
                .filter(|tombstone| !exported_ids.contains(tombstone.account_id.as_str()))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Add a tombstone for every remote account that no longer exists locally.
///
/// 调用方必须先证明本地水位不落后于远端, 否则"本地没有"可能只是"还没 pull"。
fn record_local_deletions(
    tombstones: &mut Vec<repo_bundle::BundleTombstone>,
    remote: Option<&repo_bundle::BundleV2>,
    state: &State,
    now: i64,
) -> Result<()> {
    let Some(remote) = remote else {
        return Ok(());
    };
    let local_ids: BTreeSet<&str> = state
        .accounts
        .iter()
        .map(|account| account.id.as_str())
        .collect();
    let mut known: BTreeSet<String> = tombstones
        .iter()
        .map(|tombstone| tombstone.account_id.clone())
        .collect();
    for account in remote.accounts() {
        if local_ids.contains(account.id.as_str()) || known.contains(&account.id) {
            continue;
        }
        tombstones.push(
            repo_bundle::BundleTombstone::new(
                account.id.clone(),
                account.credential.fingerprint(),
                now,
            )
            .map_err(anyhow::Error::new)?,
        );
        known.insert(account.id.clone());
    }
    bound_tombstones(tombstones);
    Ok(())
}

/// Keep the repository's own copy of an account that could not be exported.
///
/// 一个损坏的本地凭据文件不应该把该账号从共享池里也删掉: 远端已经有一份完好的
/// 记录时原样带上, 池子内容保持不变。
fn retain_remote_copies_for_skipped(
    exported: &mut Vec<repo_bundle::BundleAccount>,
    remote: Option<&repo_bundle::BundleV2>,
    skipped: &[SkippedAccount],
) -> usize {
    let Some(remote) = remote else {
        return 0;
    };
    let mut present_ids: BTreeSet<String> =
        exported.iter().map(|account| account.id.clone()).collect();
    let mut present_fingerprints: BTreeSet<String> = exported
        .iter()
        .map(|account| account.credential.fingerprint())
        .collect();
    let mut retained = 0;
    for entry in skipped {
        if present_ids.contains(&entry.id) {
            continue;
        }
        let Some(account) = remote
            .accounts()
            .iter()
            .find(|account| account.id == entry.id)
        else {
            continue;
        };
        let fingerprint = account.credential.fingerprint();
        if present_fingerprints.contains(&fingerprint) {
            continue;
        }
        present_ids.insert(account.id.clone());
        present_fingerprints.insert(fingerprint);
        exported.push(account.clone());
        retained += 1;
    }
    exported.sort_by(|left, right| left.id.cmp(&right.id));
    retained
}

/// Keep only the newest [`repo_bundle::MAX_BUNDLE_TOMBSTONES`] records.
fn bound_tombstones(tombstones: &mut Vec<repo_bundle::BundleTombstone>) {
    if tombstones.len() <= repo_bundle::MAX_BUNDLE_TOMBSTONES {
        return;
    }
    tombstones.sort_by(|left, right| {
        right
            .deleted_at
            .cmp(&left.deleted_at)
            .then_with(|| left.account_id.cmp(&right.account_id))
    });
    tombstones.truncate(repo_bundle::MAX_BUNDLE_TOMBSTONES);
}

fn prepare_incoming_accounts(bundle: &repo_bundle::BundleV2) -> Result<Vec<IncomingAccount>> {
    let mut incoming = Vec::with_capacity(bundle.accounts().len());
    for account in bundle.accounts() {
        let credential = account.credential.clone();
        let credential_ref = CredentialRef {
            kind: credential_ref_kind(credential.kind()),
            fingerprint: credential.fingerprint(),
        };
        let material = credential_material(&credential)?;
        incoming.push(IncomingAccount {
            account_id: account.id.clone(),
            metadata: account.metadata.clone(),
            credential,
            credential_ref,
            material,
        });
    }
    incoming.sort_by(|left, right| left.account_id.cmp(&right.account_id));
    Ok(incoming)
}

fn reject_active_credential_change(state: &State, incoming: &[IncomingAccount]) -> Result<()> {
    let Some(active_profile) = state.active_profile.as_ref() else {
        return Ok(());
    };
    let Some(item) = incoming
        .iter()
        .find(|item| item.account_id == active_profile.account_id)
    else {
        return Ok(());
    };
    if state.credential_refs.get(&active_profile.account_id) != Some(&item.credential_ref) {
        bail!(
            "repository pull cannot replace the current account credential without an active-home transaction"
        );
    }
    Ok(())
}

fn account_from_metadata(id: &str, metadata: &repo_bundle::BundleAccountMetadata) -> AccountRecord {
    AccountRecord {
        id: id.to_string(),
        email: metadata.email.clone(),
        account_type: metadata.account_type,
        provider_id: metadata.provider_id.clone(),
        project_id: metadata.project_id.clone(),
        account_id: metadata.account_id.clone(),
        identity_fingerprint: metadata.identity_fingerprint.clone(),
        plan: metadata.plan.clone(),
        // v2 state carries no runtime paths; launch resolves fixed locations
        // from the account id and its credential reference.
        auth_path: String::new(),
        config_path: None,
        oauth_token: None,
        refresh_token: None,
        api_key: None,
        added_at: metadata.added_at,
        updated_at: metadata.updated_at,
        last_used_at: metadata.last_used_at,
    }
}

/// What a merge changed beyond the plain upsert of incoming accounts.
#[derive(Debug, Default)]
struct MergeOutcome {
    /// Accounts dropped from local state; their credential files must be
    /// deleted inside the same transaction.
    removed: Vec<String>,
    /// ASCII lines the caller prints so the user can see what happened.
    notices: Vec<String>,
}

/// Drop one account from every state map that keys on account id.
fn drop_account(candidate: &mut State, account_id: &str) -> Option<AccountRecord> {
    let position = candidate
        .accounts
        .iter()
        .position(|account| account.id == account_id)?;
    let removed = candidate.accounts.remove(position);
    candidate.credential_refs.remove(account_id);
    candidate.usage_cache.remove(account_id);
    Some(removed)
}

/// Does this deletion record apply to the local copy of the account?
///
/// 一条 tombstone 只有在 account id 与凭据指纹都对得上、且本地记录不是在删除
/// 之后才新建的情况下才生效, 这样机器 B 本地新增、尚未 push 的账号不会被误删。
fn tombstone_applies(
    state: &State,
    tombstone: &repo_bundle::BundleTombstone,
    incoming_ids: &BTreeSet<&str>,
) -> bool {
    let account_id = tombstone.account_id.as_str();
    if incoming_ids.contains(account_id) {
        return false;
    }
    let Some(account) = state
        .accounts
        .iter()
        .find(|account| account.id == account_id)
    else {
        return false;
    };
    if account.added_at > tombstone.deleted_at {
        return false;
    }
    state
        .credential_refs
        .get(account_id)
        .is_some_and(|reference| reference.fingerprint == tombstone.fingerprint)
}

/// The local current account, when the pool has deleted it.
///
/// pull 事务本身没有 active-home 授权, 改不了 `active_profile`, 所以这种账号必须
/// 在事务之前用完整的账号删除流程拆掉。
fn current_account_pending_deletion(
    state: &State,
    bundle: &repo_bundle::BundleV2,
    incoming_ids: &BTreeSet<&str>,
) -> Option<String> {
    let current = state.current_account_id.as_deref()?;
    bundle
        .tombstones()
        .iter()
        .find(|tombstone| {
            tombstone.account_id == current && tombstone_applies(state, tombstone, incoming_ids)
        })
        .map(|tombstone| tombstone.account_id.clone())
}

/// Are this account's credential files still on disk?
///
/// 只读探测, 不建目录、不取锁。它只用来在两条删除路径之间做选择, 两条路径都会
/// 在拿到凭据锁之后重新核对真实布局, 所以这里的判断即使被并发改写也不会放行
/// 任何未经证明的删除。
fn credential_layout_is_present(state_dir: &Path, account_id: &str) -> Result<bool> {
    let store = CredentialStore::new(state_dir, account_id).map_err(anyhow::Error::new)?;
    let layout = store.read_layout().map_err(anyhow::Error::new)?;
    Ok(layout.token.is_some() || layout.document.is_some())
}

/// Convert an active-home failure into a plain error, rolling the transaction
/// back first when the adapter handed us a reconcile token.
fn active_home_failure(error: ActiveHomeError) -> anyhow::Error {
    match error {
        ActiveHomeError::Invalid(error) => error,
        ActiveHomeError::ReconcileRequired { source, token } => match restore_reconcile(token) {
            Ok(()) => source,
            Err(restore_error) => {
                anyhow!("{source}; active-home restore failed: {restore_error}")
            }
        },
    }
}

/// Retire a pool-deleted current account whose credential files are already
/// gone.
///
/// 为什么不能直接复用完整的账号删除事务: 它走 `stage_delete`, 而空 layout 会让
/// `stage_delete` 硬失败(NotFound; CurrentExact 模式下先撞 Conflict)。凭据泄露后
/// 本机先手工删文件正是账号被池子删除的典型原因, 于是这台机器每一次 pull 都失败。
/// 清退事务(`stage_purge`)在凭据锁内复核 layout 确实为空, 写下同样可被 StateStore
/// 重新校验的 journal, 于是 credential_ref 与 active home 仍然在同一次 State CAS
/// 里被释放, 既不放宽证明要求, 也不再把 pull 卡死。
fn purge_pool_deleted_current_account(session: &mut StateSession, account_id: &str) -> Result<()> {
    let (antigravity_root, gemini_root) = active_home_roots()?;
    session
        .with_locked_exact(|transaction| {
            let snapshot = transaction.snapshot()?;
            if !snapshot
                .state
                .accounts
                .iter()
                .any(|account| account.id == account_id)
            {
                return Err(StateStoreError::Invalid(anyhow!(
                    "pool-deleted current account is no longer present in state"
                )));
            }
            if snapshot.state.current_account_id.as_deref() != Some(account_id) {
                return Err(StateStoreError::Invalid(anyhow!(
                    "pool-deleted account stopped being the current account"
                )));
            }
            let credential_permit = transaction.credential_mutation_permit(account_id)?;
            let credential_store = CredentialStore::from_permit(credential_permit)
                .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
            let credential_prepared = credential_store
                .stage_purge(Uuid::new_v4())
                .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;

            let before_ref = snapshot.state.credential_refs.get(account_id).cloned();
            let home_permit = transaction.active_home_mutation_permit_with_ref(None, before_ref)?;
            let home_store = ActiveHomeStore::from_permit_with_roots(
                home_permit,
                antigravity_root.clone(),
                gemini_root.clone(),
            )
            .map_err(StateStoreError::Invalid)?;
            let active_prepared = home_store
                .prepare(Uuid::new_v4())
                .map_err(|error| StateStoreError::Invalid(active_home_failure(error)))?;

            let credential_published = credential_store
                .publish(credential_prepared)
                .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
            let credential_proof = match credential_store.journal_proof(&credential_published) {
                Ok(proof) => proof,
                Err(error) => {
                    return Err(restore_credential_only(
                        &credential_store,
                        credential_published,
                        anyhow::Error::new(error),
                    ));
                }
            };
            let active_published = match active_prepared.publish() {
                Ok(published) => published,
                Err(error) => {
                    return Err(restore_credential_only(
                        &credential_store,
                        credential_published,
                        active_home_failure(error),
                    ));
                }
            };
            let active_proof = match active_published.journal_proof() {
                Ok(proof) => proof,
                Err(error) => {
                    let active_restore = active_published.restore().err();
                    let mut failure =
                        restore_credential_only(&credential_store, credential_published, error);
                    if let Some(restore_error) = active_restore {
                        failure = StateStoreError::Invalid(anyhow!(
                            "{failure}; active-home rollback failed: {restore_error}"
                        ));
                    }
                    return Err(failure);
                }
            };

            let mut candidate = snapshot.state;
            candidate
                .accounts
                .retain(|account| account.id != account_id);
            candidate.usage_cache.remove(account_id);
            candidate.credential_refs.remove(account_id);
            candidate.current_account_id = None;
            candidate.active_profile = None;
            let receipt = match transaction.commit_coordinated_with_active(
                &candidate,
                vec![credential_proof],
                Some(active_proof),
            ) {
                Ok(receipt) => receipt,
                Err(error) => {
                    let active_restore = active_published.restore().err();
                    let credential_restore = credential_store.restore(credential_published).err();
                    if active_restore.is_none() && credential_restore.is_none() {
                        return Err(error);
                    }
                    let mut message = error.to_string();
                    if let Some(restore_error) = active_restore {
                        message
                            .push_str(&format!("; active-home rollback failed: {restore_error}"));
                    }
                    if let Some(restore_error) = credential_restore {
                        message.push_str(&format!("; credential rollback failed: {restore_error}"));
                    }
                    return Err(StateStoreError::Invalid(anyhow!(message)));
                }
            };
            // State CAS 已经落盘, 之后的清理失败只能报 recovery-pending, 绝不能
            // 声称回滚。
            let mut pending = Vec::new();
            if let Err(error) = active_published.finalize(&receipt) {
                pending.push(error.to_string());
            }
            if let Err(error) = credential_store.finalize(credential_published, &receipt) {
                pending.push(error.to_string());
            }
            if pending.is_empty() {
                Ok(())
            } else {
                Err(StateStoreError::Invalid(anyhow!(
                    "pool-deleted current account was removed but cleanup is pending: {}",
                    pending.join("; ")
                )))
            }
        })
        .map_err(anyhow::Error::new)
}

/// Roll a published credential transaction back and fold both failures into
/// one error.
fn restore_credential_only(
    store: &CredentialStore,
    published: PublishedCredentialTxn,
    error: anyhow::Error,
) -> StateStoreError {
    match store.restore(published) {
        Ok(_) => StateStoreError::Invalid(error),
        Err(restore_error) => StateStoreError::Invalid(anyhow!(
            "{error}; credential rollback failed: {restore_error}"
        )),
    }
}

/// Apply the bundle's deletion records to local state.
fn apply_tombstones(
    candidate: &mut State,
    bundle: &repo_bundle::BundleV2,
    incoming_ids: &BTreeSet<&str>,
    outcome: &mut MergeOutcome,
) {
    for tombstone in bundle.tombstones() {
        let account_id = tombstone.account_id.as_str();
        if !tombstone_applies(candidate, tombstone, incoming_ids) {
            continue;
        }
        let email = candidate
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .map(|account| account.email.clone())
            .unwrap_or_default();
        if candidate.current_account_id.as_deref() == Some(account_id) {
            // 正常路径上 current account 已经在事务之前被 remove_account_session
            // 拆掉了。走到这里说明两步之间 state 被别的进程改过; 此时不能就地摘掉
            // 账号 —— v2 要求 current_account_id 与 active_profile 同生共死, 而这里
            // 拿不到 active-home 授权。留给下一次 pull 重试, 但必须说清楚。
            outcome.notices.push(format!(
                "[sagy] WARNING: account {account_id} ({email}) was deleted from the pool while it was becoming the current account here; run `sagy pull` again to finish applying the deletion."
            ));
            continue;
        }
        // 删除必须是无条件的: 把账号留在 state 里, 下一次 push 会既重新导出它、
        // 又因为它出现在 exported 里而丢掉 tombstone, A 的删除对全体机器被静默撤销。
        if drop_account(candidate, account_id).is_some() {
            outcome.notices.push(format!(
                "[sagy] removed account {account_id} ({email}) deleted from the pool"
            ));
            outcome.removed.push(account_id.to_string());
        }
    }
}

/// Drop local accounts whose credential material is identical to an incoming
/// pool account stored under a different id.
///
/// 不去重的话, 跨机器重复导入同一份凭据会让本机 push 永久报 duplicate
/// fingerprint; 池子是共享真相, 所以保留池子里的 account id。
fn deduplicate_by_fingerprint(
    candidate: &mut State,
    incoming: &[IncomingAccount],
    outcome: &mut MergeOutcome,
) -> Result<()> {
    for item in incoming {
        let incoming_identity_key = credential_identity_key(&item.credential);
        let duplicates: Vec<String> = candidate
            .credential_refs
            .iter()
            .filter(|(id, reference)| {
                if id.as_str() == item.account_id {
                    return false;
                }
                let identity = candidate
                    .accounts
                    .iter()
                    .find(|account| account.id.as_str() == id.as_str())
                    .and_then(|account| account.identity_fingerprint.as_deref())
                    .unwrap_or(reference.fingerprint.as_str());
                credential_ref_identity_key(reference, identity) == incoming_identity_key
            })
            .map(|(id, _)| id.clone())
            .collect();
        for duplicate in duplicates {
            let email = candidate
                .accounts
                .iter()
                .find(|account| account.id == duplicate)
                .map(|account| account.email.clone())
                .unwrap_or_default();
            if candidate.current_account_id.as_deref() == Some(duplicate.as_str()) {
                bail!(
                    "duplicate credential: local account {} ({}) holds the same credential as pool account {} ({}).\n\
                     {} is the current account here, so sagy will not remove it automatically.\n\
                     Recovery: keep the pool account {} (it is the shared identity), run `sagy use <other-account>`, then `sagy rm {}` and pull again.",
                    duplicate,
                    email,
                    item.account_id,
                    item.metadata.email,
                    duplicate,
                    item.account_id,
                    duplicate
                );
            }
            if drop_account(candidate, &duplicate).is_some() {
                outcome.notices.push(format!(
                    "[sagy] duplicate credential: local account {} ({}) is the same credential as pool account {} ({}); keeping the pool account and removing the local duplicate",
                    duplicate, email, item.account_id, item.metadata.email
                ));
                outcome.removed.push(duplicate);
            }
        }
    }
    Ok(())
}

fn merge_bundle_state(
    candidate: &mut State,
    bundle: &repo_bundle::BundleV2,
    incoming: &[IncomingAccount],
    identity: &PoolIdentity,
) -> Result<MergeOutcome> {
    candidate.version = STATE_V2_VERSION;
    let incoming_ids: BTreeSet<&str> = incoming
        .iter()
        .map(|item| item.account_id.as_str())
        .collect();
    let mut outcome = MergeOutcome::default();
    apply_tombstones(candidate, bundle, &incoming_ids, &mut outcome);
    for item in incoming {
        let account = account_from_metadata(&item.account_id, &item.metadata);
        if let Some(existing) = candidate
            .accounts
            .iter_mut()
            .find(|existing| existing.id == item.account_id)
        {
            *existing = account;
        } else {
            candidate.accounts.push(account);
        }
        candidate
            .credential_refs
            .insert(item.account_id.clone(), item.credential_ref.clone());
        candidate
            .usage_cache
            .entry(item.account_id.clone())
            .or_insert_with(|| UsageSnapshot {
                plan: item.metadata.plan.clone(),
                ..UsageSnapshot::default()
            });
    }
    deduplicate_by_fingerprint(candidate, incoming, &mut outcome)?;
    candidate
        .accounts
        .sort_by(|left, right| left.id.cmp(&right.id));
    rekey_watermark(
        candidate,
        identity,
        SyncWatermark {
            generation: bundle.generation(),
            semantic_sha256: bundle.semantic_sha256().map_err(anyhow::Error::new)?,
        },
    );
    Ok(outcome)
}

fn restore_published_transactions(
    published: Vec<(String, CredentialStore, PublishedCredentialTxn)>,
) -> std::result::Result<(), StateStoreError> {
    let mut first_error = None;
    for (_, store, transaction) in published.into_iter().rev() {
        if let Err(error) = store.restore(transaction) {
            if first_error.is_none() {
                first_error = Some(StateStoreError::Invalid(anyhow::Error::new(error)));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn recover_staged_transactions(
    stores: &BTreeMap<String, CredentialStore>,
    authority: &crate::core::state_store::RecoveryAuthority,
) -> std::result::Result<(), StateStoreError> {
    let mut first_error = None;
    for store in stores.values() {
        if let Err(error) = store.recover_pending(authority.clone()) {
            if first_error.is_none() {
                first_error = Some(StateStoreError::Invalid(anyhow::Error::new(error)));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn rollback_credential_transactions(
    published: Vec<(String, CredentialStore, PublishedCredentialTxn)>,
    stores: &BTreeMap<String, CredentialStore>,
    authority: &crate::core::state_store::RecoveryAuthority,
) -> std::result::Result<(), StateStoreError> {
    let restore_result = restore_published_transactions(published);
    let recover_result = recover_staged_transactions(stores, authority);
    match (restore_result, recover_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[derive(Debug, Clone)]
pub struct PushOutcome {
    pub changed: bool,
    pub exported_accounts: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PushOptions<'a> {
    pub bundle_dir: Option<&'a str>,
    pub identity_file: Option<&'a Path>,
    pub insecure_host_key: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PullOptions<'a> {
    pub bundle_dir: Option<&'a str>,
    pub identity_file: Option<&'a Path>,
    pub insecure_host_key: bool,
}

#[derive(Debug, Clone)]
pub struct PullOutcome {
    pub imported_accounts: usize,
    /// Accounts removed locally because the pool deleted them or because they
    /// duplicated a pool credential.
    pub removed_accounts: usize,
}

const CHECKOUT_PREFIX: &str = "repo-sync-";
const CHECKOUT_LOCK_SUFFIX: &str = ".lock";

struct TempCheckout {
    checkout_dir: PathBuf,
    lock_path: PathBuf,
    // 锁在整个 checkout 生命周期内持有: 回收逻辑靠"能否拿到独占锁"来判断某个
    // 残留目录是否还在被其它进程使用。
    _lock: fs::File,
}

impl Drop for TempCheckout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.checkout_dir);
        let _ = fs::remove_file(&self.lock_path);
        // 共享的 tmp/ 根目录绝不能被删除: 并发进程"先 create_secure_dir_all 再
        // 写入"的窗口里删掉它会让对方拿到 ENOENT。
    }
}

/// Reclaim `tmp/repo-sync-*` leftovers from processes that were killed.
///
/// 只有拿得到独占锁的目录才是真正的残留; 仍被其它进程持有的 checkout 会跳过。
fn reclaim_stale_checkouts(tmp_root: &Path) {
    let Ok(entries) = fs::read_dir(tmp_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(rest) = name.strip_prefix(CHECKOUT_PREFIX) else {
            continue;
        };
        let (token, is_lock) = match rest.strip_suffix(CHECKOUT_LOCK_SUFFIX) {
            Some(token) => (token, true),
            None => (rest, false),
        };
        if token.is_empty() {
            continue;
        }
        let checkout_dir = tmp_root.join(format!("{CHECKOUT_PREFIX}{token}"));
        let lock_path = tmp_root.join(format!("{CHECKOUT_PREFIX}{token}{CHECKOUT_LOCK_SUFFIX}"));
        if is_lock && checkout_dir.exists() {
            // 目录条目自己会处理这一对, 避免重复工作。
            continue;
        }
        let Ok(lock) = open_checkout_lock(&lock_path) else {
            continue;
        };
        if fs2::FileExt::try_lock_exclusive(&lock).is_err() {
            continue;
        }
        // 同样的 inode 判据: open 与 try_lock 之间锁文件可能已经被换掉, 那把锁
        // 就保护不了路径上的新文件, 此时删除 checkout 会踩到仍在运行的进程。
        if !checkout_lock_is_current(&lock, &lock_path) {
            continue;
        }
        let _ = fs::remove_dir_all(&checkout_dir);
        let _ = fs::remove_file(&lock_path);
        drop(lock);
    }
}

fn open_checkout_lock(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open checkout lock {}", path.display()))
}

/// Is the open lock file still the file that lives at `path`?
///
/// `flock` 作用在 inode 上, 不在路径上。open 与 flock 之间存在一个窗口: 并发的
/// reclaim 可以拿到这个还没上锁的文件的独占锁并把它 unlink 掉, 之后我们锁住的
/// 只是一个已被删除的 inode, 路径上却空空如也——下一个 reclaim 会新建同名锁文件、
/// 一锁就中, 然后把仍在使用的 checkout 目录删掉。所以拿到锁之后必须确认路径仍
/// 指向同一个 inode。
fn checkout_lock_is_current(lock: &fs::File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (Ok(held), Ok(current)) = (lock.metadata(), fs::metadata(path)) else {
            return false;
        };
        held.dev() == current.dev() && held.ino() == current.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = lock;
        // Windows 不允许删除仍被打开的文件, 路径存在即可证明是同一个文件。
        path.exists()
    }
}

/// Open the checkout lock and hold it, proving the locked file is still the
/// file at `path`.
fn acquire_checkout_lock(path: &Path) -> Result<fs::File> {
    // 极端情况下可能反复输给并发的 reclaim, 所以重试次数有界。
    for _ in 0..8 {
        let lock = open_checkout_lock(path)?;
        fs2::FileExt::lock_exclusive(&lock)
            .with_context(|| format!("failed to acquire checkout lock {}", path.display()))?;
        if checkout_lock_is_current(&lock, path) {
            return Ok(lock);
        }
        drop(lock);
    }
    bail!(
        "failed to acquire a stable checkout lock at {}; another sagy process keeps reclaiming it",
        path.display()
    )
}

impl super::AntigravityAdapter {
    pub fn push_account_pool(
        &self,
        state_dir: &Path,
        state: &State,
        repo: &str,
        opts: PushOptions<'_>,
    ) -> Result<PushOutcome> {
        let _ = state;
        let mut session = StateSession::open(state_dir).map_err(anyhow::Error::new)?;
        self.push_account_pool_v2(state_dir, &mut session, repo, opts)
    }

    pub fn pull_account_pool(
        &self,
        state_dir: &Path,
        state: &mut State,
        repo: &str,
        opts: PullOptions<'_>,
    ) -> Result<PullOutcome> {
        self.pull_account_pool_v2(state_dir, state, repo, opts)
    }

    /// Push the strict v2 bundle using one StateSession.  The legacy public
    /// wrapper above is retained for source compatibility, while all new CLI
    /// callers should use this method so the watermark CAS advances the same
    /// session that selected the accounts.
    pub(crate) fn push_account_pool_v2(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        repo: &str,
        opts: PushOptions<'_>,
    ) -> Result<PushOutcome> {
        let state = session.state().clone();
        validate_v2_state(&state)?;
        if state.accounts.is_empty() {
            bail!("No accounts to push in local state");
        }

        let git_bin = find_git_bin().ok_or_else(|| anyhow!("git binary not found in PATH"))?;
        let bundle_key = resolve_bundle_key()?;
        let bundle_dir_str = opts.bundle_dir.unwrap_or(DEFAULT_BUNDLE_DIR);
        validate_bundle_dir(bundle_dir_str)?;

        // CredentialStore::new is read-only. It checks the state reference and
        // fixed slot without creating account directories or taking a lock.
        let (mut current_credentials, skipped) = load_v2_bundle_accounts(state_dir, &state)?;
        if current_credentials.is_empty() {
            // 只有在一个账号都导不出来时才允许失败, 并说明每个账号的具体原因。
            let reasons = skipped
                .iter()
                .map(SkippedAccount::describe)
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "no account could be exported, so there is nothing to push:\n{reasons}\n\
                 Fix or remove the accounts listed above (`sagy rm <id>`), or re-import their credentials, then push again."
            );
        }
        let checkout = clone_repo(
            &git_bin,
            state_dir,
            repo,
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        let (bundle_root, bundle_path) =
            prepare_bundle_paths(&checkout.checkout_dir, bundle_dir_str, false)?;

        let remote = read_remote_bundle(&bundle_path, &bundle_key, bundle_dir_str)?;
        // The repository argument is the canonical pool identity. Never adopt an
        // unrelated remote pool id: doing so would let a replaced bundle bypass
        // an existing local watermark under the derived id. A bundle written
        // before canonicalization is the one accepted exception, and this push
        // re-keys it.
        let identity = resolve_pool_identity(repo, remote.as_ref(), bundle_dir_str)?;
        let pool_id = identity.canonical.clone();
        if !skipped.is_empty() {
            eprintln!(
                "[sagy] WARNING: {} account(s) were skipped and not exported:",
                skipped.len()
            );
            for entry in &skipped {
                eprintln!("{}", entry.describe());
            }
            // 本地读不出来的账号如果远端还有一份完好的记录, 就把远端那份原样带上,
            // 否则一个坏掉的凭据文件会顺手把该账号从共享池里也抹掉。
            let retained = retain_remote_copies_for_skipped(
                &mut current_credentials,
                remote.as_ref(),
                &skipped,
            );
            if retained > 0 {
                eprintln!(
                    "[sagy] {retained} skipped account(s) kept in the pool using the copy already stored in the repository."
                );
            }
        }
        let now = chrono::Utc::now().timestamp();
        let mut tombstones = carried_tombstones(remote.as_ref(), &current_credentials, now);
        let current_semantic = bundle_semantic_hash(&current_credentials, &tombstones, &pool_id)?;
        let remote_is_current = remote.as_ref().is_some_and(|remote| {
            remote.semantic_sha256().ok().as_deref() == Some(current_semantic.as_str())
                && watermark_for_pool(&state, &identity)
                    .is_none_or(|watermark| watermark.generation <= remote.generation())
        });
        if let Some(remote) = remote.as_ref().filter(|_| remote_is_current) {
            // The encrypted envelope is intentionally not rewritten for a
            // semantic no-op: random salt/nonce must not create Git churn.
            let remote_watermark = SyncWatermark {
                generation: remote.generation(),
                semantic_sha256: current_semantic,
            };
            if state.sync_watermarks.get(&pool_id) != Some(&remote_watermark)
                || identity.legacy().is_some()
            {
                let mut candidate = state.clone();
                rekey_watermark(&mut candidate, &identity, remote_watermark);
                session.commit(&candidate).map_err(anyhow::Error::new)?;
            }
            return Ok(PushOutcome {
                changed: false,
                exported_accounts: current_credentials.len(),
            });
        }

        let local_watermark = watermark_for_pool(&state, &identity);
        let local_generation = local_watermark
            .map(|watermark| watermark.generation)
            .unwrap_or(0);
        let remote_generation = remote
            .as_ref()
            .map(|bundle| bundle.generation())
            .unwrap_or(0);
        // Push 之前必须证明本地已经见过远端当前的 bundle。git 层拦不住这件事:
        // 每次都是全新 clone --depth 1, `push origin HEAD` 恒为 fast-forward,
        // 于是落后的机器会用只含本地账号的 bundle 整包覆盖别人刚推上去的账号。
        if let Some(remote_bundle) = remote.as_ref() {
            let remote_semantic = remote_bundle
                .semantic_sha256()
                .map_err(anyhow::Error::new)?;
            let diverged = match local_watermark {
                None => true,
                Some(watermark) => {
                    watermark.generation < remote_generation
                        || (watermark.generation == remote_generation
                            && watermark.semantic_sha256 != remote_semantic)
                }
            };
            if diverged {
                bail!(
                    "local account pool is behind the remote pool; pushing now would discard accounts other machines already published.\n\
                     local generation {}, remote generation {}.\n\
                     Recovery: run `sagy pull` first to merge the remote accounts, then run `sagy push` again.",
                    local_generation,
                    remote_generation
                );
            }
        }
        record_local_deletions(&mut tombstones, remote.as_ref(), &state, now)?;
        let generation = local_generation
            .max(remote_generation)
            .checked_add(1)
            .ok_or_else(|| anyhow!("bundle generation overflow"))?;
        let bundle = make_v2_bundle(&pool_id, generation, current_credentials, tombstones)?;
        let semantic_sha256 = bundle.semantic_sha256().map_err(anyhow::Error::new)?;
        let plaintext = bundle.encode().map_err(anyhow::Error::new)?;
        if plaintext.len() > repo_bundle::MAX_BUNDLE_PLAINTEXT_BYTES {
            bail!("bundle plaintext exceeds the 8 MiB limit");
        }
        let encrypted = encrypt_bytes(&plaintext, &bundle_key)?;
        validate_encrypted_payload(&encrypted)?;
        let encoded = serde_json::to_vec(&encrypted)?;

        storage::create_secure_dir_all(&bundle_root)?;
        validate_secret_target(&checkout.checkout_dir, &bundle_path)?;
        storage::write_secret_file(&bundle_path, &encoded)?;

        git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["add", "--", bundle_dir_str],
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        let status_out = git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["status", "--porcelain"],
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        if status_out.stdout.is_empty() {
            return Ok(PushOutcome {
                changed: false,
                exported_accounts: bundle.accounts().len(),
            });
        }
        git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &[
                "-c",
                "user.name=sagy-agent",
                "-c",
                "user.email=sagy@local",
                "commit",
                "-m",
                "chore(sagy): sync encrypted account pool",
            ],
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["push", "origin", "HEAD"],
            opts.identity_file,
            opts.insecure_host_key,
        )?;

        let mut candidate = state;
        rekey_watermark(
            &mut candidate,
            &identity,
            SyncWatermark {
                generation,
                semantic_sha256,
            },
        );
        session.commit(&candidate).map_err(anyhow::Error::new)?;
        Ok(PushOutcome {
            changed: true,
            exported_accounts: bundle.accounts().len(),
        })
    }

    /// Pull and atomically publish a strict v2 bundle.  All untrusted Git,
    /// decryption, JSON and credential validation happens before the state
    /// lock is acquired.  The transaction then follows the fixed lock order:
    /// state -> sorted credential stores -> publish -> State CAS -> finalize.
    pub(crate) fn pull_account_pool_v2(
        &self,
        state_dir: &Path,
        state: &mut State,
        repo: &str,
        opts: PullOptions<'_>,
    ) -> Result<PullOutcome> {
        let mut session = StateSession::open(state_dir).map_err(anyhow::Error::new)?;
        let result = self.pull_account_pool_v2_session(state_dir, &mut session, repo, opts);
        // A finalize failure is reported as recovery-pending after the state
        // CAS. StateSession advances its read snapshot even when the callback
        // returns that error, so never copy the caller's stale State back in.
        *state = session.state().clone();
        result
    }

    /// Pull using the caller-owned StateSession. Network, decryption, parsing
    /// and credential validation are completed before this method acquires the
    /// state lock. The same session is advanced by `with_locked_exact`,
    /// including the committed snapshot returned alongside a recovery-pending
    /// finalize error.
    pub(crate) fn pull_account_pool_v2_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        repo: &str,
        opts: PullOptions<'_>,
    ) -> Result<PullOutcome> {
        let read = session.read().clone();
        if read.recovery_pending {
            bail!("state recovery is pending; resolve it before repository pull");
        }
        if matches!(read.migration, MigrationStatus::LegacyV1) {
            bail!("legacy v1 state requires the sealed migration workflow before repository pull");
        }

        let git_bin = find_git_bin().ok_or_else(|| anyhow!("git binary not found in PATH"))?;
        let bundle_key = resolve_bundle_key()?;
        let bundle_dir_str = opts.bundle_dir.unwrap_or(DEFAULT_BUNDLE_DIR);
        validate_bundle_dir(bundle_dir_str)?;
        let checkout = clone_repo(
            &git_bin,
            state_dir,
            repo,
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        let (_, bundle_path) = prepare_bundle_paths(&checkout.checkout_dir, bundle_dir_str, false)?;
        let bundle = read_remote_bundle(&bundle_path, &bundle_key, bundle_dir_str)?
            .ok_or_else(|| anyhow!("Bundle file {BUNDLE_FILENAME} does not exist in repository"))?;
        // Release the checkout before StateStore adoption. In a completely
        // missing state root, the generated `tmp/` directory would otherwise
        // look like unrelated pre-existing state to the non-empty-root guard.
        drop(checkout);
        if matches!(read.revision.generation, RevisionGeneration::Missing) {
            // 只有"本次调用之前 state 文档还不存在"这一条路径才会删 tmp/ 根目录,
            // 而且只删空目录。TempCheckout 的清理路径与回收路径都不碰它, 避免与
            // 并发进程"先判断存在再写入"形成竞态。
            let _ = fs::remove_dir(storage::tmp_dir(state_dir));
        }
        let identity = resolve_pool_identity(repo, Some(&bundle), bundle_dir_str)?;
        // 水位比较必须用 bundle 自己携带的 pool_id, 否则存量 bundle 会被判成
        // PoolIdMismatch; 写回本地时再统一 re-key 成规范 id。
        let decision = bundle
            .check_sync_watermark(
                identity.remote_pool_id(),
                watermark_for_pool(&read.state, &identity),
            )
            .map_err(anyhow::Error::new)?;
        if matches!(decision, repo_bundle::SyncDecision::NoOp) {
            return Ok(PullOutcome {
                imported_accounts: 0,
                removed_accounts: 0,
            });
        }

        // Convert every account and material before acquiring the state lock.
        // This ensures malformed metadata or a credential-kind mismatch can
        // never leave a staged file behind.
        let incoming = prepare_incoming_accounts(&bundle)?;
        reject_active_credential_change(&read.state, &incoming)?;
        // 被 pool 删除的账号如果正好是本机 current account, 先用完整的账号删除事务
        // 把它拆掉(含把 active home 还给用户)。跳过它会让账号留在 state 里, 下一次
        // push 又把它推回池子并丢掉 tombstone, 等于把别的机器的删除静默撤销。
        let mut read = read;
        {
            let incoming_ids: BTreeSet<&str> = incoming
                .iter()
                .map(|item| item.account_id.as_str())
                .collect();
            if let Some(account_id) =
                current_account_pending_deletion(&read.state, &bundle, &incoming_ids)
            {
                // 凭据文件是否还在决定走哪条删除事务。完整删除事务需要一份真实的
                // 凭据布局才能 stage_delete; 坏账号(文件已缺失)必须走清退事务,
                // 否则这台机器每一次 pull 都会硬失败。
                if credential_layout_is_present(state_dir, &account_id)? {
                    eprintln!(
                        "[sagy] WARNING: the pool deleted account {account_id}, which is the current account here; releasing the active home and removing it. Run `sagy use <account>` before the next launch."
                    );
                    self.remove_account_session(state_dir, session, &account_id)
                        .with_context(|| {
                            format!("failed to remove pool-deleted current account {account_id}")
                        })?;
                } else {
                    eprintln!(
                        "[sagy] WARNING: the pool deleted account {account_id}, which is the current account here; its credential files are already missing, so sagy releases the active home and drops the account record only. Run `sagy use <account>` before the next launch."
                    );
                    purge_pool_deleted_current_account(session, &account_id).with_context(|| {
                        format!(
                            "failed to retire pool-deleted current account {account_id} whose credential files are missing"
                        )
                    })?;
                }
                read = session.read().clone();
            }
        }
        let mut candidate = read.state.clone();
        let merge = merge_bundle_state(&mut candidate, &bundle, &incoming, &identity)?;
        validate_v2_state(&candidate)?;
        let expected = read.revision.clone();
        let imported_count = incoming.len();
        let credential_refs_changed = candidate.credential_refs != read.state.credential_refs;
        // 导入与删除必须在同一个按 account id 排序的序列里取锁, 否则会出现
        // 跨账号的锁反转。
        let mut operations: Vec<CredentialOp<'_>> =
            incoming.iter().map(CredentialOp::Import).collect();
        operations.extend(
            merge
                .removed
                .iter()
                .map(|account_id| CredentialOp::Delete(account_id.as_str())),
        );
        operations.sort_by(|left, right| left.account_id().cmp(right.account_id()));

        session
            .with_locked_exact(|transaction| {
                let mut staged = Vec::new();
                let mut published = Vec::new();
                let mut stores = BTreeMap::<String, CredentialStore>::new();
                let recovery_authority = transaction.recovery_authority()?;

                // Account ids are sorted before any credential lock is
                // acquired, preventing cross-account lock inversions.
                for operation in &operations {
                    let account_id = operation.account_id();
                    let permit = match transaction.credential_mutation_permit(account_id) {
                        Ok(permit) => permit,
                        Err(error) => {
                            drop(staged);
                            recover_staged_transactions(&stores, &recovery_authority)?;
                            return Err(error);
                        }
                    };
                    let store = match CredentialStore::from_permit(permit) {
                        Ok(store) => store,
                        Err(error) => {
                            drop(staged);
                            recover_staged_transactions(&stores, &recovery_authority)?;
                            return Err(StateStoreError::Invalid(anyhow::Error::new(error)));
                        }
                    };
                    stores.insert(account_id.to_string(), store.clone());
                    let prepared = match operation {
                        CredentialOp::Import(item) => {
                            // "unchanged" 必须同时覆盖磁盘与 state: 只比磁盘的话,
                            // state 里缺失/过期的引用会在没有任何 proof 的情况下
                            // 被这次 pull 补上, 等于一次无证明的引用变更。
                            let unchanged = !matches!(
                                expected.generation,
                                RevisionGeneration::Missing
                            ) && read.state.credential_refs.get(&item.account_id)
                                == Some(&item.credential_ref)
                                && store
                                    .read(&item.credential_ref)
                                    .map(|stored| stored.credential == item.credential)
                                    .unwrap_or(false);
                            if unchanged {
                                continue;
                            }
                            store.stage_with_material(
                                Uuid::new_v4(),
                                &item.credential,
                                &item.material,
                            )
                        }
                        CredentialOp::Delete(_) => {
                            // 池子里已经删除的账号, 其明文凭据文件必须一并删除,
                            // 只从 state 摘掉会把凭据留在磁盘上。
                            let layout = match store.read_layout() {
                                Ok(layout) => layout,
                                Err(error) => {
                                    let message = error.to_string();
                                    drop(error);
                                    drop(staged);
                                    recover_staged_transactions(&stores, &recovery_authority)?;
                                    return Err(StateStoreError::Invalid(anyhow!(message)));
                                }
                            };
                            if layout.token.is_none() && layout.document.is_none() {
                                // 坏账号: 凭据文件本来就不在磁盘上, 没有字节可删,
                                // 但 state 里的 credential_ref 仍然要摘掉。协调提交
                                // 要求每一处引用变更都拿得出证明, 所以这里落一笔
                                // 清退事务: 它在凭据锁内复核 layout 确实为空, 再写
                                // 下一份可被 StateStore 重新校验的 journal, 证明
                                // "before_ref -> None" 这次变更。跳过它(continue)
                                // 会让"同一次 pull 既有 import 又有坏账号删除"的
                                // 混合场景撞上覆盖率校验而硬失败。
                                store.stage_purge(Uuid::new_v4())
                            } else {
                                store.stage_delete(Uuid::new_v4(), &layout.expected_layout())
                            }
                        }
                    };
                    let prepared = match prepared {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            let message = error.to_string();
                            drop(error);
                            drop(staged);
                            recover_staged_transactions(&stores, &recovery_authority)?;
                            return Err(StateStoreError::Invalid(anyhow!(message)));
                        }
                    };
                    staged.push((account_id.to_string(), store, prepared));
                }

                for (account_id, store, prepared) in staged {
                    match store.publish(prepared) {
                        Ok(published_txn) => published.push((account_id, store, published_txn)),
                        Err(error) => {
                            let message = error.to_string();
                            drop(error);
                            rollback_credential_transactions(
                                published,
                                &stores,
                                &recovery_authority,
                            )?;
                            return Err(StateStoreError::Invalid(anyhow!(message)));
                        }
                    }
                }

                let mut proofs = Vec::with_capacity(published.len());
                for (_, store, published_txn) in &published {
                    match store.journal_proof(published_txn) {
                        Ok(proof) => proofs.push(proof),
                        Err(error) => {
                            let message = error.to_string();
                            drop(error);
                            rollback_credential_transactions(
                                published,
                                &stores,
                                &recovery_authority,
                            )?;
                            return Err(StateStoreError::Invalid(anyhow!(message)));
                        }
                    }
                }

                // A changed credential reference must have a matching durable
                // journal proof. Unchanged credentials deliberately produce no
                // mutation or proof.
                let receipt = match if matches!(expected.generation, RevisionGeneration::Missing) {
                    // A completely fresh directory crosses the missing -> v2
                    // boundary only through the sealed migration permit. The
                    // permit is still validated against every durable journal
                    // before any state bytes are published.
                    match transaction.migration_commit_permit(proofs) {
                        Ok(permit) => transaction.commit_migration(&candidate, permit),
                        Err(error) => Err(error),
                    }
                } else if !proofs.is_empty() {
                    transaction.commit_coordinated(&candidate, proofs)
                } else if credential_refs_changed {
                    // 引用变了却一条 proof 都没有, 说明上面漏掉了某个账号。
                    // 绝不能退到 commit_exact_receipt: 那等于把一次毫无证明的
                    // 凭据引用变更直接写进 state。fail-closed。
                    Err(StateStoreError::Invalid(anyhow!(
                        "repository pull changed credential references without a durable journal proof"
                    )))
                } else {
                    // 一条 proof 都没有且引用没变 = 纯 metadata / watermark 的
                    // pull, 不需要凭据 finalize 授权。坏账号删除已经由清退事务
                    // (stage_purge) 提供 proof, 不再走这条分支。
                    transaction.commit_exact_receipt(&candidate)
                } {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        rollback_credential_transactions(
                            published,
                            &stores,
                            &recovery_authority,
                        )?;
                        return Err(error);
                    }
                };
                for (_, store, published_txn) in published {
                    if let Err(error) = store.finalize(published_txn, &receipt) {
                        // The state CAS has already committed. Retain the
                        // exact committed snapshot in StateSession so the
                        // caller cannot accidentally reuse its old state.
                        // The journal is intentionally retained for sealed
                        // restart recovery; never claim the operation rolled
                        // back after the State CAS succeeded.
                        return Err(StateStoreError::Invalid(anyhow!(
                            "repository pull committed state but credential cleanup is pending: {error}"
                        )));
                    }
                }
                Ok(())
            })
            .map_err(anyhow::Error::new)?;
        for notice in &merge.notices {
            eprintln!("{notice}");
        }
        Ok(PullOutcome {
            imported_accounts: imported_count,
            removed_accounts: merge.removed.len(),
        })
    }
}

/// One credential-store mutation planned by a pull.
enum CredentialOp<'a> {
    Import(&'a IncomingAccount),
    Delete(&'a str),
}

impl CredentialOp<'_> {
    fn account_id(&self) -> &str {
        match self {
            Self::Import(item) => item.account_id.as_str(),
            Self::Delete(account_id) => account_id,
        }
    }
}

fn resolve_bundle_key() -> Result<String> {
    if let Ok(key) = env::var(BUNDLE_KEY_ENV) {
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    bail!("Environment variable `{BUNDLE_KEY_ENV}` is not set. Please provide an encryption key.")
}

fn validate_encrypted_payload(payload: &EncryptedBundlePayload) -> Result<()> {
    if payload.algorithm != BUNDLE_ALGORITHM {
        bail!("unsupported encrypted bundle algorithm");
    }
    let salt_text = payload
        .salt
        .as_deref()
        .ok_or_else(|| anyhow!("encrypted bundle salt is missing"))?;
    if salt_text.len() != 24 {
        bail!("encrypted bundle salt must be canonical 16-byte base64");
    }
    let salt = BASE64_STANDARD
        .decode(salt_text)
        .map_err(|_| anyhow!("invalid encrypted bundle salt"))?;
    if salt.len() != 16 || BASE64_STANDARD.encode(&salt) != salt_text {
        bail!("encrypted bundle salt must be canonical 16-byte base64");
    }
    if payload.nonce.len() != 32 {
        bail!("encrypted bundle nonce must be canonical 24-byte base64");
    }
    let nonce = BASE64_STANDARD
        .decode(&payload.nonce)
        .map_err(|_| anyhow!("invalid encrypted bundle nonce"))?;
    if nonce.len() != 24 || BASE64_STANDARD.encode(&nonce) != payload.nonce {
        bail!("encrypted bundle nonce must be canonical 24-byte base64");
    }
    if payload.ciphertext.len() > MAX_BUNDLE_CIPHERTEXT_BASE64_BYTES {
        bail!("encrypted bundle ciphertext exceeds the size limit");
    }
    let ciphertext = BASE64_STANDARD
        .decode(&payload.ciphertext)
        .map_err(|_| anyhow!("invalid encrypted bundle ciphertext"))?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_BUNDLE_CIPHERTEXT_BYTES {
        bail!("encrypted bundle ciphertext exceeds the size or authentication-tag limit");
    }
    if BASE64_STANDARD.encode(&ciphertext) != payload.ciphertext {
        bail!("encrypted bundle ciphertext must use canonical base64");
    }
    Ok(())
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        bail!("bundle file cannot be a symlink");
    }
    if !metadata.is_file() {
        bail!("bundle file is not a regular file");
    }
    read_external_regular_file_bounded(path, max_bytes)
        .map(Some)
        .with_context(|| format!("failed to read bundle file {}", path.display()))
}

/// Build the recovery instructions for a repository that still holds a bundle
/// older than [`repo_bundle::BUNDLE_VERSION`].
///
/// 老仓库不得被永久锁死: push/pull 双向都会走到这里, 所以两条路径都能拿到
/// "要执行什么、删除哪个文件" 的明确指引, 同时绝不静默覆盖远端已有账号。
fn legacy_bundle_guidance(summary: &repo_bundle::LegacyBundleSummary, bundle_dir: &str) -> String {
    let mut listing = summary
        .emails
        .iter()
        .take(16)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if summary.emails.len() > 16 {
        listing.push_str(", ...");
    }
    if listing.is_empty() {
        listing = "unknown".to_string();
    }
    format!(
        "repository holds a legacy v{} account pool bundle that this version cannot read.\n\
         It still contains {} account(s): {}.\n\
         sagy refuses to overwrite it, so nothing in the repository has been discarded.\n\
         Recovery, in this order:\n\
         1. Confirm every account listed above also exists on this machine (`sagy list`); re-add any missing one with `sagy add` first.\n\
         2. Delete the legacy bundle from the repository:\n\
         \x20    git clone <repo> pool-reset && cd pool-reset\n\
         \x20    git rm -r -- {}\n\
         \x20    git commit -m \"reset sagy account pool\" && git push\n\
         3. Run `sagy push` again to publish a fresh v{} bundle.\n\
         Step 2 discards whatever the legacy bundle still holds, which is why step 1 is not optional.",
        summary.version,
        summary.account_count,
        listing,
        bundle_dir,
        repo_bundle::BUNDLE_VERSION
    )
}

fn read_remote_bundle(
    path: &Path,
    password: &str,
    bundle_dir: &str,
) -> Result<Option<repo_bundle::BundleV2>> {
    let Some(encoded) = read_bounded_file(path, MAX_ENCRYPTED_PAYLOAD_BYTES)? else {
        return Ok(None);
    };
    let payload = EncryptedBundlePayload::decode_strict(&encoded)?;
    let decrypted = decrypt_bytes(&payload, password)?;
    match repo_bundle::BundleV2::decode(&decrypted) {
        Ok(bundle) => Ok(Some(bundle)),
        Err(error) => {
            if let Some(summary) = repo_bundle::inspect_legacy_bundle(&decrypted) {
                bail!("{}", legacy_bundle_guidance(&summary, bundle_dir));
            }
            Err(anyhow::Error::new(error))
        }
    }
}

fn derive_key_argon2id(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params =
        Params::new(19456, 2, 1, Some(32)).map_err(|e| anyhow!("Argon2 params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("KDF failed: {e}"))?;
    Ok(key_bytes)
}

fn encrypt_bytes(data: &[u8], password: &str) -> Result<EncryptedBundlePayload> {
    if data.len() > repo_bundle::MAX_BUNDLE_PLAINTEXT_BYTES {
        bail!("bundle plaintext exceeds the 8 MiB limit");
    }
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    let key_bytes = derive_key_argon2id(password, &salt_bytes)?;
    let key = Key::from_slice(&key_bytes);

    let cipher = XChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let payload = EncryptedBundlePayload {
        algorithm: BUNDLE_ALGORITHM.to_string(),
        salt: Some(BASE64_STANDARD.encode(salt_bytes)),
        nonce: BASE64_STANDARD.encode(nonce_bytes),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    };
    validate_encrypted_payload(&payload)?;
    Ok(payload)
}

fn decrypt_bytes(payload: &EncryptedBundlePayload, password: &str) -> Result<Vec<u8>> {
    validate_encrypted_payload(payload)?;
    let salt_b64 = payload
        .salt
        .as_deref()
        .ok_or_else(|| anyhow!("Missing salt in encrypted bundle payload"))?;
    let salt_bytes = BASE64_STANDARD
        .decode(salt_b64)
        .context("Invalid base64 salt")?;
    let key_bytes = derive_key_argon2id(password, &salt_bytes)?;

    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_bytes = BASE64_STANDARD
        .decode(&payload.nonce)
        .context("Invalid base64 nonce")?;
    let ciphertext = BASE64_STANDARD
        .decode(&payload.ciphertext)
        .context("Invalid base64 ciphertext")?;

    if nonce_bytes.len() != 24 {
        bail!("Invalid nonce length: expected 24 bytes");
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed: incorrect key or corrupted bundle"))?;
    if plaintext.len() > repo_bundle::MAX_BUNDLE_PLAINTEXT_BYTES {
        bail!("bundle plaintext exceeds the 8 MiB limit");
    }
    Ok(plaintext)
}

fn clone_repo(
    git_bin: &Path,
    state_dir: &Path,
    repo: &str,
    identity_file: Option<&Path>,
    insecure_host_key: bool,
) -> Result<TempCheckout> {
    validate_repo_source(repo)?;
    storage::create_secure_dir_all(state_dir)?;
    validate_path_under_root(state_dir, state_dir)?;
    let tmp_root = storage::tmp_dir(state_dir);
    storage::create_secure_dir_all(&tmp_root)?;
    validate_path_under_root(state_dir, &tmp_root)?;
    // SIGKILL 之后 Drop 不会运行, 残留目录只能由下一次 repo sync 回收。
    reclaim_stale_checkouts(&tmp_root);
    let token = Uuid::new_v4().to_string();
    let checkout_dir = tmp_root.join(format!("{CHECKOUT_PREFIX}{token}"));
    validate_path_under_root(state_dir, &checkout_dir)?;
    let lock_path = tmp_root.join(format!("{CHECKOUT_PREFIX}{token}{CHECKOUT_LOCK_SUFFIX}"));
    validate_path_under_root(state_dir, &lock_path)?;
    // 锁必须在 checkout 目录出现之前就拿到, 否则回收逻辑可能看到一个还没上锁的
    // 目录并把它当成残留删掉。
    let lock = match acquire_checkout_lock(&lock_path) {
        Ok(lock) => lock,
        Err(_) => {
            // 全新 state root 的 pull 会在认领之前删掉自己生成的空 tmp/。并发
            // 进程可能正好撞上这一瞬间, 重建后重试一次即可。
            storage::create_secure_dir_all(&tmp_root)?;
            acquire_checkout_lock(&lock_path)?
        }
    };

    let checkout_str = checkout_dir.to_string_lossy();
    // `--` is deliberately before every user-controlled positional argument. Git clone
    // accepts this form and therefore cannot interpret a repository named like `-A` as an
    // option; the destination is generated under our validated temporary root.
    let args = ["clone", "--depth", "1", "--", repo, checkout_str.as_ref()];

    if let Err(error) = git_cmd(git_bin, state_dir, &args, identity_file, insecure_host_key) {
        let _ = fs::remove_dir_all(&checkout_dir);
        let _ = fs::remove_file(&lock_path);
        return Err(error);
    }
    let checkout = TempCheckout {
        checkout_dir,
        lock_path,
        _lock: lock,
    };
    validate_path_under_root(state_dir, &checkout.checkout_dir)?;
    let checkout_metadata = fs::metadata(&checkout.checkout_dir).with_context(|| {
        format!(
            "git clone did not create {}",
            checkout.checkout_dir.display()
        )
    })?;
    if !checkout_metadata.is_dir() {
        bail!(
            "git clone destination is not a directory: {}",
            checkout.checkout_dir.display()
        );
    }

    Ok(checkout)
}

fn git_cmd(
    git_bin: &Path,
    cwd: &Path,
    args: &[&str],
    identity_file: Option<&Path>,
    insecure_host_key: bool,
) -> Result<Output> {
    let mut cmd = Command::new(git_bin);
    cmd.current_dir(cwd);
    cmd.args(args);

    if let Some(ssh_cmd) = build_ssh_command(identity_file, insecure_host_key)? {
        if insecure_host_key {
            eprintln!(
                "[sagy] WARNING: StrictHostKeyChecking is disabled (--insecure-host-key). This connection is vulnerable to MITM attacks."
            );
        }
        cmd.env("GIT_SSH_COMMAND", ssh_cmd);
    }

    let safe_args = args
        .iter()
        .map(|arg| redact_git_text(arg))
        .collect::<Vec<_>>();
    let output = cmd
        .output()
        .with_context(|| format!("failed to execute git command: {:?}", safe_args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = redact_git_text(stderr.trim());
        if detail.is_empty() {
            bail!("git {:?} failed", safe_args);
        }
        bail!("git {:?} failed: {}", safe_args, detail);
    }

    Ok(output)
}

fn build_ssh_command(
    identity_file: Option<&Path>,
    insecure_host_key: bool,
) -> Result<Option<String>> {
    if identity_file.is_none() && !insecure_host_key {
        return Ok(None);
    }
    let mut ssh_cmd = String::from("ssh");
    if let Some(id_file) = identity_file {
        let identity_path = id_file.to_str().ok_or_else(|| {
            anyhow!(
                "SSH identity path is not valid UTF-8: {}",
                id_file.display()
            )
        })?;
        ssh_cmd.push_str(&format!(
            " -i {} -o IdentitiesOnly=yes",
            shell_quote_for_git(identity_path)
        ));
    }
    if insecure_host_key {
        ssh_cmd.push_str(" -o StrictHostKeyChecking=no");
    }
    Ok(Some(ssh_cmd))
}

fn prepare_bundle_paths(
    checkout_dir: &Path,
    bundle_dir: &str,
    create_root: bool,
) -> Result<(PathBuf, PathBuf)> {
    validate_bundle_dir(bundle_dir)?;
    validate_path_under_root(checkout_dir, checkout_dir)?;

    let bundle_root = checkout_dir.join(bundle_dir);
    validate_path_under_root(checkout_dir, &bundle_root)?;
    if create_root {
        storage::create_secure_dir_all(&bundle_root)?;
        validate_path_under_root(checkout_dir, &bundle_root)?;
    }

    let bundle_path = bundle_root.join(BUNDLE_FILENAME);
    validate_path_under_root(checkout_dir, &bundle_path)?;
    Ok((bundle_root, bundle_path))
}

fn validate_secret_target(account_dir: &Path, target: &Path) -> Result<()> {
    validate_path_under_root(account_dir, target)?;
    if let Ok(metadata) = fs::symlink_metadata(target) {
        if metadata.file_type().is_symlink() {
            bail!(
                "credential target cannot be a symlink: {}",
                target.display()
            );
        }
    }
    Ok(())
}

fn shell_quote_for_git(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// The single trust boundary for a repository location.
///
/// 两侧（CLI 落盘前、adapter 进 argv 前）必须调用同一个函数，否则任一侧单独
/// 加固都会静默失配。`cli::repo_sync` 直接委托到这里。
pub fn validate_repo_source(repo: &str) -> Result<()> {
    if repo.is_empty() || repo.chars().any(|ch| ch.is_control()) {
        bail!("repository location is empty or contains control characters");
    }

    let Some(scheme_end) = repo.find("://") else {
        if let Some(at) = repo.find('@') {
            let user = &repo[..at];
            let Some(colon_offset) = repo[at + 1..].find(':') else {
                bail!("invalid SCP-like SSH repository location");
            };
            let host = &repo[at + 1..at + 1 + colon_offset];
            if user.is_empty() || user.contains(':') || host.is_empty() {
                bail!("SCP-like SSH repository location cannot contain credentials");
            }
        }
        return Ok(());
    };

    let scheme = &repo[..scheme_end];
    if scheme.is_empty()
        || !scheme.chars().enumerate().all(|(index, ch)| {
            (index == 0 && ch.is_ascii_alphabetic())
                || (index > 0 && (ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')))
        })
    {
        bail!("invalid repository URL scheme");
    }
    let tail = &repo[scheme_end + 3..];
    if tail.contains(['?', '#']) {
        bail!("repository URL cannot contain a query or fragment");
    }
    let authority_end = tail.find('/').unwrap_or(tail.len());
    let authority = &tail[..authority_end];
    if authority.is_empty() {
        bail!("repository URL must contain a host");
    }
    if let Some((userinfo, host)) = authority.rsplit_once('@') {
        if authority[..authority.len() - host.len() - 1].contains('@')
            || userinfo.is_empty()
            || host.is_empty()
            || !scheme.eq_ignore_ascii_case("ssh")
            || userinfo.contains(':')
        {
            bail!("repository URL cannot contain credentials");
        }
    }
    Ok(())
}

fn redact_git_text(text: &str) -> String {
    text.split_whitespace()
        .map(redact_git_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_git_token(token: &str) -> String {
    let Some(scheme_end) = token.find("://") else {
        let Some(at) = token.find('@') else {
            return token.to_string();
        };
        let prefix = &token[..at];
        let Some(separator) = prefix.rfind(':') else {
            return token.to_string();
        };
        if separator == 0 {
            return token.to_string();
        }
        let redacted = format!("{}***@{}", &token[..separator + 1], &token[at + 1..]);
        return redact_git_url_query(&redacted);
    };

    let scheme_start = token[..scheme_end]
        .rfind(|ch: char| !ch.is_ascii_alphanumeric() && ch != '+' && ch != '-' && ch != '.')
        .map(|index| index + 1)
        .unwrap_or(0);
    if scheme_start == scheme_end {
        return token.to_string();
    }

    let authority_start = scheme_end + 3;
    let authority_end = token[authority_start..]
        .find(['/', '?', '#', '"', '\'', ')', ']', ','])
        .map(|offset| authority_start + offset)
        .unwrap_or(token.len());
    let authority = &token[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return redact_git_url_query(token);
    };

    let redacted = format!(
        "{}***@{}{}",
        &token[..authority_start],
        &authority[at + 1..],
        &token[authority_end..]
    );
    redact_git_url_query(&redacted)
}

fn redact_git_url_query(token: &str) -> String {
    let query_start = token.find('?');
    let fragment_start = token.find('#');
    let Some(query_start) = query_start else {
        return fragment_start
            .map(|fragment| format!("{}#***", &token[..fragment]))
            .unwrap_or_else(|| token.to_string());
    };
    let fragment_start = token[query_start..]
        .find('#')
        .map(|offset| query_start + offset);
    let query_end = fragment_start.unwrap_or(token.len());
    let query = &token[query_start + 1..query_end];
    let redacted_query = query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.find('=').map_or_else(
                || "***".to_string(),
                |equals| format!("{}=***", &part[..equals]),
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let fragment = fragment_start.map(|_| "#***").unwrap_or_default();
    format!("{}?{}{}", &token[..query_start], redacted_query, fragment)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 整个 lib test 二进制共用一把常量 key。每个测试各设一把随机 key 会让并发
    /// 运行的另一个测试读到别人的 key, push/pull 随机解密失败。
    const TEST_BUNDLE_KEY: &str = "repo-sync-unit-test-pool-key";

    fn ensure_test_bundle_key() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| unsafe { std::env::set_var(BUNDLE_KEY_ENV, TEST_BUNDLE_KEY) });
    }

    fn run_git(cwd: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(cwd)
            .args(args)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn init_bare(path: &Path) -> String {
        fs::create_dir_all(path).expect("bare repo dir");
        run_git(path, &["init", "--bare", "."]);
        path.to_str().expect("utf-8 repo path").to_string()
    }

    /// Publish a hand-built bundle as the repository's only commit.
    fn seed_remote_bundle(temp: &Path, remote: &str, bundle: &repo_bundle::BundleV2) {
        let seed = temp.join(format!("seed-{}", Uuid::new_v4()));
        fs::create_dir_all(seed.join(DEFAULT_BUNDLE_DIR)).expect("seed bundle dir");
        let encrypted = encrypt_bytes(&bundle.encode().unwrap(), TEST_BUNDLE_KEY).unwrap();
        fs::write(
            seed.join(DEFAULT_BUNDLE_DIR).join(BUNDLE_FILENAME),
            serde_json::to_vec(&encrypted).unwrap(),
        )
        .unwrap();
        run_git(&seed, &["init"]);
        run_git(&seed, &["config", "user.email", "test@example.test"]);
        run_git(&seed, &["config", "user.name", "repo-test"]);
        run_git(&seed, &["add", "--", DEFAULT_BUNDLE_DIR]);
        run_git(&seed, &["commit", "-m", "bundle"]);
        run_git(&seed, &["remote", "add", "origin", remote]);
        run_git(&seed, &["push", "origin", "HEAD"]);
    }

    /// Read back whatever the repository currently stores.
    fn remote_bundle(temp: &Path, remote: &str) -> repo_bundle::BundleV2 {
        let output = std::process::Command::new("git")
            .current_dir(remote)
            .args([
                "show",
                &format!("HEAD:{DEFAULT_BUNDLE_DIR}/{BUNDLE_FILENAME}"),
            ])
            .output()
            .expect("git show");
        assert!(output.status.success(), "no bundle in {remote}");
        let scratch = temp.join(format!("readback-{}", Uuid::new_v4()));
        fs::create_dir_all(&scratch).expect("scratch dir");
        let path = scratch.join(BUNDLE_FILENAME);
        fs::write(&path, &output.stdout).expect("scratch bundle");
        read_remote_bundle(&path, TEST_BUNDLE_KEY, DEFAULT_BUNDLE_DIR)
            .expect("decode remote bundle")
            .expect("remote bundle present")
    }

    #[test]
    fn test_encryption_roundtrip() {
        let password = "test_super_secret_pool_key_123456";
        let original_data = b"{\"email\":\"user@google.com\",\"token\":\"sample_token_data\"}";

        let encrypted = encrypt_bytes(original_data, password).expect("encryption should succeed");
        assert_eq!(encrypted.algorithm, BUNDLE_ALGORITHM);

        let decrypted = decrypt_bytes(&encrypted, password).expect("decryption should succeed");
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_decryption_wrong_key() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let original_data = b"secret payload";

        let encrypted = encrypt_bytes(original_data, password).expect("encryption should succeed");
        let result = decrypt_bytes(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_git_identity_path_is_single_shell_argument() {
        let path = "/tmp/key with spaces; touch /tmp/pwned '$HOME'";
        let quoted = shell_quote_for_git(path);
        assert_eq!(
            quoted,
            "'/tmp/key with spaces; touch /tmp/pwned '\\''$HOME'\\'''"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_git_identity_path_cannot_execute_shell_metacharacters() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let fake_git = temp.path().join("fake-git");
        fs::write(
            &fake_git,
            "#!/bin/sh\nsh -c \"$GIT_SSH_COMMAND\" >/dev/null 2>&1 || true\nexit 0\n",
        )
        .expect("fake git");
        let mut permissions = fs::metadata(&fake_git)
            .expect("fake git metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&fake_git, permissions).expect("fake git permissions");

        let marker = temp.path().join("injected");
        let identity = temp
            .path()
            .join(format!("key with spaces; touch {}", marker.display()));
        git_cmd(&fake_git, temp.path(), &["status"], Some(&identity), false)
            .expect("fake git should exit successfully");
        assert!(!marker.exists(), "identity path enabled shell injection");
    }

    #[test]
    fn test_git_error_redacts_url_userinfo() {
        let text = "fatal: https://alice:s3cret@example.test/pool.git: denied";
        let redacted = redact_git_text(text);
        assert!(!redacted.contains("s3cret"));
        assert!(redacted.contains("***@example.test"));
    }

    #[test]
    fn test_git_error_redacts_url_query_and_fragment() {
        let text =
            "fatal: https://example.test/pool.git?token=s3cret&x=also-secret#fragment-secret";
        let redacted = redact_git_text(text);
        assert!(!redacted.contains("s3cret"));
        assert!(!redacted.contains("also-secret"));
        assert!(!redacted.contains("fragment-secret"));
        assert!(redacted.contains("token=***"));
        assert_eq!(
            redact_git_text("https://example.test/pool.git#fragment-secret"),
            "https://example.test/pool.git#***"
        );
        assert_eq!(
            redact_git_text("git:password@host:path?token=fragment-secret"),
            "git:***@host:path?token=***"
        );
    }

    #[test]
    fn test_insecure_host_key_is_effective_without_identity_file() {
        let ssh = build_ssh_command(None, true).expect("SSH command should be built");
        let ssh = ssh.expect("SSH command should be present");
        assert!(ssh.contains("StrictHostKeyChecking=no"));
        assert!(!ssh.contains("-i "));
    }

    #[test]
    fn test_repo_source_rejects_credentials_but_allows_option_like_path_for_dash() {
        assert!(validate_repo_source("https://alice:secret@example.test/pool.git").is_err());
        assert!(validate_repo_source("ssh://alice:secret@example.test/pool.git").is_err());
        assert!(validate_repo_source("ssh://git@example.test/user/pool.git").is_ok());
        assert!(validate_repo_source("git@github.com:user/pool.git").is_ok());
        assert!(validate_repo_source("-A").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_clone_separates_option_like_repository_source() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let fake_git = temp.path().join("fake-git");
        let argv_file = temp.path().join("argv");
        fs::write(
            &fake_git,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nlast=''\nfor arg do last=\"$arg\"; done\nmkdir -p \"$last\"\n",
                shell_quote_for_git(argv_file.to_str().expect("argv path"))
            ),
        )
        .expect("fake git");
        let mut permissions = fs::metadata(&fake_git)
            .expect("fake git metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&fake_git, permissions).expect("fake git permissions");

        let state_dir = temp.path().join("state");
        let _checkout = clone_repo(&fake_git, &state_dir, "-A", None, false)
            .expect("option-like repository source should be positional");
        let args = fs::read_to_string(argv_file)
            .expect("captured git argv")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(args.first().map(String::as_str), Some("clone"));
        assert_eq!(args.get(3).map(String::as_str), Some("--"));
        assert_eq!(args.get(4).map(String::as_str), Some("-A"));
    }

    #[test]
    fn test_encrypted_envelope_rejects_unknown_and_duplicate_fields() {
        let encrypted = encrypt_bytes(b"payload", "secret-key").unwrap();
        let encoded = serde_json::to_string(&encrypted).unwrap();
        let unknown = encoded.replacen("\"algorithm\":", "\"unknown\":1,\"algorithm\":", 1);
        assert!(EncryptedBundlePayload::decode_strict(unknown.as_bytes()).is_err());
        let duplicate = encoded.replacen(
            "\"algorithm\":",
            "\"algorithm\":\"xchacha20poly1305-argon2id\",\"algorithm\":",
            1,
        );
        assert!(EncryptedBundlePayload::decode_strict(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn test_encrypted_envelope_rejects_oversized_ciphertext_before_decode() {
        let payload = EncryptedBundlePayload {
            algorithm: BUNDLE_ALGORITHM.to_string(),
            salt: Some(BASE64_STANDARD.encode([0_u8; 16])),
            nonce: BASE64_STANDARD.encode([0_u8; 24]),
            ciphertext: "A".repeat(MAX_BUNDLE_CIPHERTEXT_BASE64_BYTES + 4),
        };
        assert!(validate_encrypted_payload(&payload).is_err());
    }

    #[test]
    fn active_credential_change_is_rejected_without_state_mutation() {
        let old = PortableCredential::oauth_access_token("old-token").unwrap();
        let replacement = PortableCredential::oauth_access_token("replacement-token").unwrap();
        let mut state = State {
            version: STATE_V2_VERSION,
            accounts: vec![AccountRecord {
                id: "active".to_string(),
                email: "active@example.test".to_string(),
                account_type: crate::core::state::AccountType::OAuth,
                ..AccountRecord::default()
            }],
            current_account_id: Some("active".to_string()),
            active_profile: Some(crate::core::state::ActiveProfile {
                account_id: "active".to_string(),
                credential_fingerprint: old.fingerprint(),
                home_scope_id: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                managed_layout: Default::default(),
            }),
            ..State::default()
        };
        state.credential_refs.insert(
            "active".to_string(),
            CredentialRef {
                kind: CredentialRefKind::OauthAccessToken,
                fingerprint: old.fingerprint(),
            },
        );
        let before = state.clone();
        let metadata = repo_bundle::BundleAccountMetadata::new(
            "active@example.test",
            crate::core::state::AccountType::OAuth,
            None,
            None,
            None,
            None,
            None,
            1,
            1,
            None,
        )
        .unwrap();
        let incoming = vec![IncomingAccount {
            account_id: "active".to_string(),
            metadata,
            credential_ref: CredentialRef {
                kind: CredentialRefKind::OauthAccessToken,
                fingerprint: replacement.fingerprint(),
            },
            material: b"replacement-token".to_vec(),
            credential: replacement,
        }];

        let error = reject_active_credential_change(&state, &incoming).unwrap_err();
        assert!(error.to_string().contains("active-home transaction"));
        assert_eq!(state, before);
    }

    #[test]
    fn remote_pool_id_must_match_canonical_repository_identity() {
        let repo = "/tmp/canonical-repo.git";
        let account = repo_bundle::BundleAccount::new(
            "account",
            repo_bundle::BundleAccountMetadata::new(
                "account@example.test",
                crate::core::state::AccountType::OAuth,
                None,
                None,
                None,
                None,
                None,
                1,
                1,
                None,
            )
            .unwrap(),
            PortableCredential::oauth_access_token("token").unwrap(),
        )
        .unwrap();
        let replacement_pool = Uuid::new_v4().to_string();
        let bundle = repo_bundle::BundleV2::new(&replacement_pool, 1, 1, vec![account]).unwrap();
        assert!(resolve_pool_identity(repo, Some(&bundle), DEFAULT_BUNDLE_DIR).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_bundle_target_symlink_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let checkout = temp.path().join("checkout");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&checkout).expect("checkout");
        fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, checkout.join(".sagy-account-pool"))
            .expect("bundle symlink");

        let result = prepare_bundle_paths(&checkout, ".sagy-account-pool", false);
        assert!(result.is_err());
    }

    fn sample_metadata(email: &str) -> repo_bundle::BundleAccountMetadata {
        repo_bundle::BundleAccountMetadata::new(
            email,
            crate::core::state::AccountType::OAuth,
            None,
            None,
            None,
            None,
            None,
            1,
            1,
            None,
        )
        .unwrap()
    }

    fn oauth_account(id: &str, email: &str, token: &str) -> repo_bundle::BundleAccount {
        repo_bundle::BundleAccount::new(
            id,
            sample_metadata(email),
            PortableCredential::oauth_access_token(token).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn equivalent_repository_spellings_derive_one_pool_id() {
        // AC-4.1: 四种写法必须指向同一个 pool。
        let spellings = [
            "https://host.example/u/r.git",
            "https://host.example/u/r",
            "git@host.example:u/r.git",
            "ssh://git@host.example/u/r.git",
        ];
        let expected = pool_id_for_repo(spellings[0]);
        for spelling in spellings {
            assert_eq!(
                pool_id_for_repo(spelling),
                expected,
                "spelling {spelling:?} derived a different pool"
            );
        }
        // 大小写主机名、尾斜杠与冗余路径段同样只是写法差异。
        for spelling in [
            "https://HOST.example/u/r/",
            "https://host.example//u/./r.git",
            "ssh://git@host.example/u/r",
        ] {
            assert_eq!(pool_id_for_repo(spelling), expected, "{spelling:?}");
        }
    }

    #[test]
    fn genuinely_different_repositories_stay_separate_pools() {
        // AC-4.2
        let base = pool_id_for_repo("https://host.example/u/r.git");
        for other in [
            "https://host.example/u/other.git",
            "https://other.example/u/r.git",
            "https://host.example/team/u/r.git",
            "/srv/u/r.git",
        ] {
            assert_ne!(pool_id_for_repo(other), base, "{other:?} collided");
        }
        assert_ne!(
            pool_id_for_repo("/srv/pool"),
            pool_id_for_repo("/srv/pool.git"),
            "local directories differing only by a .git suffix are distinct"
        );
        assert_eq!(
            pool_id_for_repo("/srv/pool.git"),
            pool_id_for_repo("file:///srv/pool.git"),
            "file:// is only another spelling of a local path"
        );
    }

    #[test]
    fn pool_mismatch_explains_the_cause_and_the_way_out() {
        // AC-4.3
        let bundle = repo_bundle::BundleV2::new(
            Uuid::new_v4().to_string(),
            1,
            1,
            vec![oauth_account("foreign", "foreign@example.test", "token")],
        )
        .unwrap();
        let error =
            resolve_pool_identity("/srv/pool.git", Some(&bundle), DEFAULT_BUNDLE_DIR).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("different account pool"), "{text}");
        assert!(text.contains("Cause:"), "{text}");
        assert!(text.contains("Recovery"), "{text}");
        assert!(text.contains(DEFAULT_BUNDLE_DIR), "{text}");
        assert!(text.contains(BUNDLE_FILENAME), "{text}");
        assert!(text.is_ascii(), "console output must be ASCII: {text}");
    }

    #[test]
    fn legacy_bundle_is_reported_instead_of_being_overwritten() {
        // AC-5.1 / AC-5.2
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join(BUNDLE_FILENAME);
        let key = "legacy-guidance-key";
        let legacy = serde_json::json!({
            "version": 1,
            "exported_at": 1_700_000_000_i64,
            "accounts": [
                {"id": "a", "email": "first@example.test"},
                {"id": "b", "email": "second@example.test"}
            ]
        });
        let plaintext = serde_json::to_vec(&legacy).unwrap();
        let encrypted = encrypt_bytes(&plaintext, key).unwrap();
        fs::write(&path, serde_json::to_vec(&encrypted).unwrap()).unwrap();

        let error = read_remote_bundle(&path, key, DEFAULT_BUNDLE_DIR)
            .expect_err("a legacy bundle must not be silently treated as absent");
        let text = format!("{error:#}");
        assert!(text.contains("legacy v1"), "{text}");
        assert!(text.contains("first@example.test"), "{text}");
        assert!(text.contains("second@example.test"), "{text}");
        assert!(text.contains("git rm"), "{text}");
        assert!(text.contains(DEFAULT_BUNDLE_DIR), "{text}");
        assert!(text.contains("sagy push"), "{text}");
        assert!(text.is_ascii(), "console output must be ASCII: {text}");
    }

    #[test]
    fn tombstones_expire_and_stay_bounded() {
        // AC-3.2
        let now = 2_000_000_000_i64;
        let fingerprint = PortableCredential::oauth_access_token("token")
            .unwrap()
            .fingerprint();
        let fresh =
            repo_bundle::BundleTombstone::new("fresh", fingerprint.clone(), now - 60).unwrap();
        let expired = repo_bundle::BundleTombstone::new(
            "expired",
            fingerprint.clone(),
            now - repo_bundle::BUNDLE_TOMBSTONE_TTL_SECONDS - 1,
        )
        .unwrap();
        assert!(fresh.is_live_at(now));
        assert!(!expired.is_live_at(now));

        let remote = repo_bundle::BundleV2::new_with_tombstones(
            pool_id_for_repo("/srv/pool.git"),
            1,
            1,
            vec![oauth_account("kept", "kept@example.test", "other-token")],
            vec![fresh.clone(), expired],
        )
        .unwrap();
        let carried = carried_tombstones(Some(&remote), &[], now);
        assert_eq!(carried.len(), 1, "expired tombstone was not dropped");
        assert_eq!(carried[0].account_id, "fresh");

        // 一旦同名账号被重新导出，它自己的历史删除记录必须消失。
        let resurrected = oauth_account("fresh", "fresh@example.test", "token");
        assert!(carried_tombstones(Some(&remote), &[resurrected], now).is_empty());

        let mut many = (0..repo_bundle::MAX_BUNDLE_TOMBSTONES + 8)
            .map(|index| {
                repo_bundle::BundleTombstone::new(
                    format!("acct-{index}"),
                    fingerprint.clone(),
                    now - index as i64,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        bound_tombstones(&mut many);
        assert_eq!(many.len(), repo_bundle::MAX_BUNDLE_TOMBSTONES);
        assert!(
            many.iter().any(|item| item.account_id == "acct-0"),
            "bounding dropped the newest records"
        );
    }

    #[test]
    fn duplicate_credentials_name_both_accounts_and_a_survivor() {
        // AC-2.3
        let owner = FingerprintOwner {
            id: "older".to_string(),
            email: "older@example.test".to_string(),
            added_at: 100,
        };
        let newer = AccountRecord {
            id: "newer".to_string(),
            email: "newer@example.test".to_string(),
            added_at: 200,
            ..AccountRecord::default()
        };
        let text = format!(
            "{:#}",
            duplicate_fingerprint_error(&owner, &newer, "sha256:aa")
        );
        assert!(
            text.contains("older") && text.contains("older@example.test"),
            "{text}"
        );
        assert!(
            text.contains("newer") && text.contains("newer@example.test"),
            "{text}"
        );
        assert!(
            text.contains("keep older"),
            "no survivor recommended: {text}"
        );
        assert!(
            text.contains("sagy rm newer"),
            "no concrete command: {text}"
        );
        assert!(text.is_ascii(), "console output must be ASCII: {text}");
    }

    #[test]
    fn pull_deduplication_reports_both_sides() {
        // AC-2.1 / AC-2.3 on the pull path.
        let credential = PortableCredential::oauth_access_token("shared-token").unwrap();
        let reference = CredentialRef {
            kind: CredentialRefKind::OauthAccessToken,
            fingerprint: credential.fingerprint(),
        };
        let mut state = State {
            version: STATE_V2_VERSION,
            accounts: vec![AccountRecord {
                id: "local-copy".to_string(),
                email: "local@example.test".to_string(),
                account_type: crate::core::state::AccountType::OAuth,
                ..AccountRecord::default()
            }],
            ..State::default()
        };
        state
            .credential_refs
            .insert("local-copy".to_string(), reference.clone());
        let incoming = vec![IncomingAccount {
            account_id: "pool-copy".to_string(),
            metadata: sample_metadata("pool@example.test"),
            credential_ref: reference,
            material: b"shared-token".to_vec(),
            credential,
        }];

        let mut outcome = MergeOutcome::default();
        deduplicate_by_fingerprint(&mut state, &incoming, &mut outcome).expect("dedupe");
        assert_eq!(outcome.removed, vec!["local-copy".to_string()]);
        assert!(state.accounts.is_empty());
        assert!(!state.credential_refs.contains_key("local-copy"));
        let notice = outcome.notices.join("\n");
        assert!(
            notice.contains("local-copy") && notice.contains("local@example.test"),
            "{notice}"
        );
        assert!(
            notice.contains("pool-copy") && notice.contains("pool@example.test"),
            "{notice}"
        );
        assert!(notice.contains("keeping the pool account"), "{notice}");
        assert!(notice.is_ascii(), "console output must be ASCII: {notice}");
    }

    #[test]
    fn skipped_accounts_are_listed_in_ascii() {
        // AC-6.1: 被跳过的账号必须以 ASCII 列出，且带上具体原因。
        let entry = SkippedAccount {
            id: "0a1b2c3d".to_string(),
            email: "broken@example.test".to_string(),
            reason: "credential is missing or corrupt: credential file not found".to_string(),
        };
        let line = entry.describe();
        assert!(line.is_ascii(), "console output must be ASCII: {line}");
        assert!(line.contains("0a1b2c3d"), "{line}");
        assert!(line.contains("broken@example.test"), "{line}");
        assert!(line.contains("missing or corrupt"), "{line}");
    }

    #[test]
    fn reclaim_removes_only_unlocked_checkouts() {
        // AC-7.1 / AC-7.2 / AC-7.3
        let temp = tempfile::tempdir().expect("tempdir");
        let tmp_root = temp.path().join("tmp");
        fs::create_dir_all(&tmp_root).expect("tmp root");

        let stale = tmp_root.join(format!("{CHECKOUT_PREFIX}stale"));
        fs::create_dir_all(stale.join("nested")).expect("stale checkout");
        fs::write(stale.join("nested").join("file"), b"leftover").expect("stale file");

        let busy = tmp_root.join(format!("{CHECKOUT_PREFIX}busy"));
        fs::create_dir_all(&busy).expect("busy checkout");
        let busy_lock_path = tmp_root.join(format!("{CHECKOUT_PREFIX}busy{CHECKOUT_LOCK_SUFFIX}"));
        let busy_lock = open_checkout_lock(&busy_lock_path).expect("busy lock");
        fs2::FileExt::lock_exclusive(&busy_lock).expect("hold the busy lock");

        let unrelated = tmp_root.join("unrelated");
        fs::create_dir_all(&unrelated).expect("unrelated dir");

        reclaim_stale_checkouts(&tmp_root);

        assert!(!stale.exists(), "unlocked leftover was not reclaimed");
        assert!(
            busy.exists(),
            "a checkout held by another process was removed"
        );
        assert!(unrelated.exists(), "reclaim touched an unrelated entry");
        assert!(tmp_root.exists(), "reclaim removed the shared tmp root");
        drop(busy_lock);
    }

    #[cfg(unix)]
    #[test]
    fn fresh_pull_preserves_all_four_credential_kinds() {
        use std::process::Command;

        let temp = tempfile::tempdir().expect("tempdir");
        let remote = temp.path().join("remote.git");
        let seed = temp.path().join("seed");
        let state_dir = temp.path().join("fresh-state");
        ensure_test_bundle_key();
        let key = TEST_BUNDLE_KEY;

        let run = |cwd: &Path, args: &[&str]| {
            let output = Command::new("git")
                .current_dir(cwd)
                .args(args)
                .output()
                .expect("git command");
            assert!(
                output.status.success(),
                "git command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        fs::create_dir_all(&remote).expect("remote dir");
        run(temp.path(), &["init", "--bare", remote.to_str().unwrap()]);
        fs::create_dir_all(seed.join(DEFAULT_BUNDLE_DIR)).expect("seed bundle dir");

        let credentials = vec![
            (
                "raw-oauth",
                repo_bundle::BundleAccountMetadata::new(
                    "raw@example.test",
                    crate::core::state::AccountType::OAuth,
                    None,
                    None,
                    None,
                    None,
                    None,
                    1,
                    1,
                    None,
                )
                .unwrap(),
                PortableCredential::oauth_access_token("raw-token").unwrap(),
            ),
            (
                "authorized-oauth",
                repo_bundle::BundleAccountMetadata::new(
                    "authorized@example.test",
                    crate::core::state::AccountType::OAuth,
                    None,
                    None,
                    None,
                    None,
                    None,
                    1,
                    1,
                    None,
                )
                .unwrap(),
                PortableCredential::oauth_authorized_user(serde_json::json!({
                    "type": "authorized_user",
                    "client_id": "client",
                    "client_secret": "client-secret",
                    "refresh_token": "refresh-secret",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }))
                .unwrap(),
            ),
            (
                "api-key",
                repo_bundle::BundleAccountMetadata::new(
                    "api@example.test",
                    crate::core::state::AccountType::ApiKey,
                    None,
                    Some("project".to_string()),
                    None,
                    None,
                    None,
                    1,
                    1,
                    None,
                )
                .unwrap(),
                PortableCredential::api_key_document(serde_json::json!({
                    "api_key": "api-secret",
                    "project_id": "project"
                }))
                .unwrap(),
            ),
            (
                "vertex",
                repo_bundle::BundleAccountMetadata::new(
                    "vertex@example.test",
                    crate::core::state::AccountType::Vertex,
                    None,
                    Some("project".to_string()),
                    None,
                    None,
                    None,
                    1,
                    1,
                    None,
                )
                .unwrap(),
                PortableCredential::vertex_service_account(serde_json::json!({
                    "type": "service_account",
                    "project_id": "project",
                    "private_key": "private-key-secret",
                    "client_email": "vertex@example.test",
                    "token_uri": "https://oauth.example.test/token"
                }))
                .unwrap(),
            ),
        ];
        let accounts = credentials
            .into_iter()
            .map(|(id, metadata, credential)| {
                repo_bundle::BundleAccount::new(id, metadata, credential).unwrap()
            })
            .collect();
        let pool_id = pool_id_for_repo(remote.to_str().unwrap());
        let bundle = repo_bundle::BundleV2::new(&pool_id, 1, 1, accounts).unwrap();
        let plaintext = bundle.encode().unwrap();
        let encrypted = encrypt_bytes(&plaintext, key).unwrap();
        fs::write(
            seed.join(DEFAULT_BUNDLE_DIR).join(BUNDLE_FILENAME),
            serde_json::to_vec(&encrypted).unwrap(),
        )
        .unwrap();
        run(&seed, &["init"]);
        run(&seed, &["config", "user.email", "test@example.test"]);
        run(&seed, &["config", "user.name", "repo-test"]);
        run(&seed, &["add", "--", DEFAULT_BUNDLE_DIR]);
        run(&seed, &["commit", "-m", "bundle"]);
        run(
            &seed,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        run(&seed, &["push", "origin", "HEAD"]);

        let mut state = State::default();
        let adapter = super::super::AntigravityAdapter;
        let outcome = adapter
            .pull_account_pool_v2(
                &state_dir,
                &mut state,
                remote.to_str().unwrap(),
                PullOptions::default(),
            )
            .expect("fresh pull");
        assert_eq!(outcome.imported_accounts, 4);
        assert_eq!(state.version, STATE_V2_VERSION);
        assert_eq!(state.accounts.len(), 4);
        for account in &state.accounts {
            let reference = state.credential_refs.get(&account.id).unwrap();
            let store = CredentialStore::new(&state_dir, &account.id).unwrap();
            let stored = store.read(reference).unwrap();
            assert_eq!(stored.credential.fingerprint(), reference.fingerprint);
        }
    }

    // -----------------------------------------------------------------
    // R4-1: bundles written before pool ids were canonicalized must keep
    // working, and the next push must re-key them.
    // -----------------------------------------------------------------

    #[test]
    fn legacy_pool_id_bundle_is_adopted_and_rekeyed_by_the_next_push() {
        ensure_test_bundle_key();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = init_bare(&temp.path().join("legacy-pool.git"));

        // 旧算法: 直接哈希原始 repo 字符串。
        let legacy_pool = legacy_pool_id_for_repo(&repo);
        assert_ne!(legacy_pool, pool_id_for_repo(&repo));
        let carried = repo_bundle::BundleTombstone::new(
            "deleted-elsewhere",
            PortableCredential::oauth_access_token("gone-token")
                .unwrap()
                .fingerprint(),
            chrono::Utc::now().timestamp() - 60,
        )
        .unwrap();
        let seeded = repo_bundle::BundleV2::new_with_tombstones(
            &legacy_pool,
            3,
            chrono::Utc::now().timestamp(),
            vec![oauth_account(
                "legacy-account",
                "legacy@example.test",
                "legacy-token",
            )],
            vec![carried.clone()],
        )
        .unwrap();
        seed_remote_bundle(temp.path(), &repo, &seeded);

        // AC-R4-1.1: 旧 pool_id 的 bundle 必须被接受。
        let adapter = super::super::AntigravityAdapter;
        let first = temp.path().join("first");
        let mut first_state = State::default();
        let outcome = adapter
            .pull_account_pool(&first, &mut first_state, &repo, PullOptions::default())
            .expect("a legacy pool id must not lock the repository");
        assert_eq!(outcome.imported_accounts, 1);
        assert_eq!(first_state.accounts.len(), 1);

        // AC-R4-1.2: 下一次 push 必须 re-key, 且不丢账号、不丢 tombstone。
        adapter
            .push_account_pool(&first, &first_state, &repo, PushOptions::default())
            .expect("push after adopting a legacy pool id");
        let rekeyed = remote_bundle(temp.path(), &repo);
        assert_eq!(rekeyed.pool_id(), pool_id_for_repo(&repo));
        assert_eq!(rekeyed.accounts().len(), 1);
        assert_eq!(rekeyed.accounts()[0].id, "legacy-account");
        assert!(
            rekeyed
                .tombstones()
                .iter()
                .any(|tombstone| tombstone.account_id == carried.account_id),
            "re-keying dropped the inherited tombstone"
        );
        // 本地水位也必须迁到规范 key 上, 旧 key 不能留下。
        assert!(
            first_state
                .sync_watermarks
                .contains_key(&pool_id_for_repo(&repo))
        );
        assert!(!first_state.sync_watermarks.contains_key(&legacy_pool));

        // AC-R4-1.3: 换一种等价写法仍然能 pull。
        let equivalent = format!("{repo}/");
        let second = temp.path().join("second");
        let mut second_state = State::default();
        adapter
            .pull_account_pool(
                &second,
                &mut second_state,
                &equivalent,
                PullOptions::default(),
            )
            .expect("an equivalent spelling must resolve to the re-keyed pool");
        assert_eq!(
            second_state
                .accounts
                .iter()
                .map(|account| account.email.clone())
                .collect::<Vec<_>>(),
            vec!["legacy@example.test".to_string()]
        );
    }

    // -----------------------------------------------------------------
    // R10-3: legacy compatibility covers the whole equivalence class of a
    // repository spelling, not one exact byte string.
    // -----------------------------------------------------------------

    #[test]
    fn legacy_pool_ids_cover_the_equivalent_spellings_of_one_repository() {
        // 同一个远端仓库的等价写法集合: 尾斜杠 / `.git` 后缀 / scp 与 ssh:// 互转。
        let spellings = [
            "https://host.example.test/team/pool.git",
            "https://host.example.test/team/pool",
            "https://host.example.test/team/pool/",
            "https://host.example.test/team/pool.git/",
        ];
        for current in spellings {
            let accepted = legacy_pool_ids_for_repo(current);
            for stored in spellings {
                assert!(
                    accepted.contains(&legacy_pool_id_for_repo(stored)),
                    "spelling {current} does not accept a bundle stored under {stored}"
                );
            }
        }

        let ssh = "ssh://git@host.example.test/team/pool.git";
        let scp = "git@host.example.test:team/pool.git";
        assert!(
            legacy_pool_ids_for_repo(ssh).contains(&legacy_pool_id_for_repo(scp)),
            "the ssh:// spelling does not accept an scp-form legacy bundle"
        );
        assert!(
            legacy_pool_ids_for_repo(scp).contains(&legacy_pool_id_for_repo(ssh)),
            "the scp spelling does not accept an ssh:// legacy bundle"
        );
        assert!(
            legacy_pool_ids_for_repo(scp)
                .contains(&legacy_pool_id_for_repo("git@host.example.test:team/pool")),
            "the scp spelling does not accept the .git-less legacy bundle"
        );

        // 本地路径刻意不做 `.git` 增删: /srv/pool 与 /srv/pool.git 可以是两个
        // 不同的目录, 规范化函数也是这么定的。
        assert!(
            !legacy_pool_ids_for_repo("/srv/pool.git")
                .contains(&legacy_pool_id_for_repo("/srv/pool")),
            "a local path must not be conflated with its .git-less sibling"
        );
        assert!(
            legacy_pool_ids_for_repo("/srv/pool.git/")
                .contains(&legacy_pool_id_for_repo("/srv/pool.git")),
            "a trailing slash must not hide a local legacy bundle"
        );

        // 不同仓库绝不能互相接受。
        assert!(
            !legacy_pool_ids_for_repo("https://host.example.test/team/pool").contains(
                &legacy_pool_id_for_repo("https://host.example.test/team/other")
            ),
            "two different repositories share a legacy pool id"
        );
    }

    #[test]
    fn a_legacy_bundle_is_adopted_through_an_equivalent_repo_spelling() {
        ensure_test_bundle_key();
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = init_bare(&temp.path().join("legacy-spelling.git"));

        // 存量 bundle 的 pool_id 来自"当年那次 push 用的写法"。
        let seeded = repo_bundle::BundleV2::new(
            legacy_pool_id_for_repo(&repo),
            2,
            chrono::Utc::now().timestamp(),
            vec![oauth_account(
                "legacy-account",
                "legacy@example.test",
                "legacy-token",
            )],
        )
        .unwrap();
        seed_remote_bundle(temp.path(), &repo, &seeded);

        // AC-R10-3.1: 今天换成等价写法(尾斜杠)仍然必须认得出这个 pool。
        let equivalent = format!("{repo}/");
        let adapter = super::super::AntigravityAdapter;
        let state_dir = temp.path().join("machine");
        let mut state = State::default();
        adapter
            .pull_account_pool(&state_dir, &mut state, &equivalent, PullOptions::default())
            .expect("an equivalent spelling must still adopt the legacy pool id");
        assert_eq!(state.accounts.len(), 1);
        assert_eq!(state.accounts[0].email, "legacy@example.test");
    }

    // -----------------------------------------------------------------
    // R4-4.1: the checkout lock must protect the path, not a deleted inode.
    // -----------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn checkout_lock_survives_a_concurrent_reclaim_of_the_lock_file() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let lock_path = temp
            .path()
            .join(format!("{CHECKOUT_PREFIX}race{CHECKOUT_LOCK_SUFFIX}"));

        // 先占住锁, 让被测线程停在 flock 上, 从而稳定复现 open 与 flock 之间的窗口。
        let blocker = open_checkout_lock(&lock_path).expect("blocking lock");
        fs2::FileExt::lock_exclusive(&blocker).expect("hold the lock");

        let racing_path = lock_path.clone();
        let worker = std::thread::spawn(move || {
            let lock = acquire_checkout_lock(&racing_path).expect("checkout lock");
            lock.metadata().expect("lock metadata").ino()
        });

        std::thread::sleep(std::time::Duration::from_millis(500));
        // 并发 reclaim 的效果: 把这个尚未上锁的锁文件删掉, 路径上换成新文件。
        fs::remove_file(&lock_path).expect("reclaim the lock file");
        drop(open_checkout_lock(&lock_path).expect("replacement lock file"));
        drop(blocker);

        let held = worker.join().expect("worker thread");
        let on_disk = fs::metadata(&lock_path).expect("lock file").ino();
        assert_eq!(
            held, on_disk,
            "the checkout lock protects a deleted inode, so the checkout is unprotected"
        );
    }
}
