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
use crate::adapters::antigravity::paths::{
    find_git_bin, validate_bundle_dir, validate_path_under_root,
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
    }
}

fn credential_material(credential: &PortableCredential) -> Result<Vec<u8>> {
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

fn pool_id_for_repo(repo: &str) -> String {
    // The state schema stores watermarks by pool UUID, not by a repository
    // path. Deriving a stable UUID keeps separate repositories isolated while
    // avoiding another secret-bearing state field.
    let digest = Sha256::digest(repo.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Mark this deterministic identifier as a UUIDv4-shaped value so every
    // platform uses the same canonical textual representation.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn canonical_pool_id_for_bundle(repo: &str, bundle: &repo_bundle::BundleV2) -> Result<String> {
    let pool_id = pool_id_for_repo(repo);
    if bundle.pool_id() != pool_id {
        bail!("repository bundle belongs to a different account pool");
    }
    Ok(pool_id)
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

fn load_v2_bundle_accounts(
    state_dir: &Path,
    state: &State,
) -> Result<Vec<repo_bundle::BundleAccount>> {
    let mut accounts = state.accounts.clone();
    accounts.sort_by(|left, right| left.id.cmp(&right.id));
    let mut result = Vec::with_capacity(accounts.len());
    let mut fingerprints = BTreeSet::new();
    for account in accounts {
        let reference = state
            .credential_refs
            .get(&account.id)
            .ok_or_else(|| anyhow!("account {} has no credential reference", account.id))?;
        let store = CredentialStore::new(state_dir, &account.id)
            .map_err(anyhow::Error::new)
            .with_context(|| format!("failed to open credential store for {}", account.id))?;
        let stored = store
            .read(reference)
            .map_err(anyhow::Error::new)
            .with_context(|| {
                format!(
                    "credential for account {} is missing or mismatched",
                    account.id
                )
            })?;
        if stored.credential.fingerprint() != reference.fingerprint
            || credential_ref_kind(stored.credential.kind()) != reference.kind
        {
            bail!(
                "credential reference for account {} is inconsistent",
                account.id
            );
        }
        let fingerprint = stored.credential.fingerprint();
        if !fingerprints.insert(fingerprint) {
            bail!("duplicate credential fingerprint in local state");
        }
        let metadata = metadata_for_account(&account)?;
        result.push(
            repo_bundle::BundleAccount::new(account.id, metadata, stored.credential)
                .map_err(anyhow::Error::new)?,
        );
    }
    Ok(result)
}

fn make_v2_bundle(
    pool_id: &str,
    generation: u64,
    accounts: Vec<repo_bundle::BundleAccount>,
) -> Result<repo_bundle::BundleV2> {
    repo_bundle::BundleV2::new(
        pool_id,
        generation,
        chrono::Utc::now().timestamp(),
        accounts,
    )
    .map_err(anyhow::Error::new)
}

fn bundle_semantic_hash(accounts: &[repo_bundle::BundleAccount], pool_id: &str) -> Result<String> {
    make_v2_bundle(pool_id, 1, accounts.to_vec())?
        .semantic_sha256()
        .map_err(anyhow::Error::new)
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

fn merge_bundle_state(
    candidate: &mut State,
    bundle: &repo_bundle::BundleV2,
    incoming: &[IncomingAccount],
    pool_id: &str,
) -> Result<()> {
    candidate.version = STATE_V2_VERSION;
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
    candidate
        .accounts
        .sort_by(|left, right| left.id.cmp(&right.id));
    candidate.sync_watermarks.insert(
        pool_id.to_string(),
        SyncWatermark {
            generation: bundle.generation(),
            semantic_sha256: bundle.semantic_sha256().map_err(anyhow::Error::new)?,
        },
    );
    Ok(())
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
    pub include_all: bool,
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
}

struct TempCheckout {
    checkout_dir: PathBuf,
}

impl Drop for TempCheckout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.checkout_dir);
        // A missing state root must remain empty until the sealed migration
        // transaction claims it. Only remove the generated temp parent when
        // it is empty; concurrent checkouts are left untouched.
        if let Some(parent) = self.checkout_dir.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
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
        let derived_pool_id = pool_id_for_repo(repo);

        // CredentialStore::new is read-only. It checks the state reference and
        // fixed slot without creating account directories or taking a lock.
        let current_credentials = load_v2_bundle_accounts(state_dir, &state)?;
        let checkout = clone_repo(
            &git_bin,
            state_dir,
            repo,
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        let (bundle_root, bundle_path) =
            prepare_bundle_paths(&checkout.checkout_dir, bundle_dir_str, false)?;

        let remote = read_remote_bundle(&bundle_path, &bundle_key)?;
        let pool_id = if let Some(remote) = remote.as_ref() {
            // The repository argument is the canonical pool identity. Never
            // adopt a remote pool id: doing so would let a replaced bundle
            // bypass an existing local watermark under the derived id.
            canonical_pool_id_for_bundle(repo, remote)?
        } else {
            derived_pool_id
        };
        let current_semantic = bundle_semantic_hash(&current_credentials, &pool_id)?;
        let remote_is_current = remote.as_ref().is_some_and(|remote| {
            remote.semantic_sha256().ok().as_deref() == Some(current_semantic.as_str())
                && state
                    .sync_watermarks
                    .get(&pool_id)
                    .is_none_or(|watermark| watermark.generation <= remote.generation())
        });
        if let Some(remote) = remote.as_ref().filter(|_| remote_is_current) {
            // The encrypted envelope is intentionally not rewritten for a
            // semantic no-op: random salt/nonce must not create Git churn.
            let remote_watermark = SyncWatermark {
                generation: remote.generation(),
                semantic_sha256: current_semantic,
            };
            if state.sync_watermarks.get(&pool_id) != Some(&remote_watermark) {
                let mut candidate = state.clone();
                candidate.sync_watermarks.insert(pool_id, remote_watermark);
                session.commit(&candidate).map_err(anyhow::Error::new)?;
            }
            return Ok(PushOutcome {
                changed: false,
                exported_accounts: current_credentials.len(),
            });
        }

        let local_generation = state
            .sync_watermarks
            .get(&pool_id)
            .map(|watermark| watermark.generation)
            .unwrap_or(0);
        let remote_generation = remote
            .as_ref()
            .map(|bundle| bundle.generation())
            .unwrap_or(0);
        let generation = local_generation
            .max(remote_generation)
            .checked_add(1)
            .ok_or_else(|| anyhow!("bundle generation overflow"))?;
        let bundle = make_v2_bundle(&pool_id, generation, current_credentials)?;
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
        candidate.sync_watermarks.insert(
            pool_id,
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
        let bundle = read_remote_bundle(&bundle_path, &bundle_key)?
            .ok_or_else(|| anyhow!("Bundle file {BUNDLE_FILENAME} does not exist in repository"))?;
        // Release the checkout before StateStore adoption. In a completely
        // missing state root, the generated `tmp/` directory would otherwise
        // look like unrelated pre-existing state to the non-empty-root guard.
        drop(checkout);
        let pool_id = canonical_pool_id_for_bundle(repo, &bundle)?;
        let decision = bundle
            .check_sync_watermark(&pool_id, read.state.sync_watermarks.get(&pool_id))
            .map_err(anyhow::Error::new)?;
        if matches!(decision, repo_bundle::SyncDecision::NoOp) {
            return Ok(PullOutcome {
                imported_accounts: 0,
            });
        }

        // Convert every account and material before acquiring the state lock.
        // This ensures malformed metadata or a credential-kind mismatch can
        // never leave a staged file behind.
        let incoming = prepare_incoming_accounts(&bundle)?;
        reject_active_credential_change(&read.state, &incoming)?;
        let mut candidate = read.state.clone();
        merge_bundle_state(&mut candidate, &bundle, &incoming, &pool_id)?;
        validate_v2_state(&candidate)?;
        let expected = read.revision.clone();
        let imported_count = incoming.len();
        let credential_refs_changed = candidate.credential_refs != read.state.credential_refs;

        session
            .with_locked_exact(|transaction| {
                let mut staged = Vec::new();
                let mut published = Vec::new();
                let mut stores = BTreeMap::<String, CredentialStore>::new();
                let recovery_authority = transaction.recovery_authority()?;

                // Account ids are sorted before any credential lock is
                // acquired, preventing cross-account lock inversions.
                for item in &incoming {
                    let permit = match transaction.credential_mutation_permit(&item.account_id) {
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
                    let unchanged = !matches!(expected.generation, RevisionGeneration::Missing)
                        && store
                            .read(&item.credential_ref)
                            .map(|stored| stored.credential == item.credential)
                            .unwrap_or(false);
                    stores.insert(item.account_id.clone(), store.clone());
                    if !unchanged {
                        let prepared = match store.stage_with_material(
                            Uuid::new_v4(),
                            &item.credential,
                            &item.material,
                        ) {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                let message = error.to_string();
                                drop(error);
                                drop(staged);
                                recover_staged_transactions(&stores, &recovery_authority)?;
                                return Err(StateStoreError::Invalid(anyhow!(message)));
                            }
                        };
                        staged.push((item.account_id.clone(), store, prepared));
                    }
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
                } else if credential_refs_changed {
                    transaction.commit_coordinated(&candidate, proofs)
                } else {
                    // Metadata and watermark-only pulls do not need a
                    // credential-finalize authority.
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
        Ok(PullOutcome {
            imported_accounts: imported_count,
        })
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

fn read_remote_bundle(path: &Path, password: &str) -> Result<Option<repo_bundle::BundleV2>> {
    let Some(encoded) = read_bounded_file(path, MAX_ENCRYPTED_PAYLOAD_BYTES)? else {
        return Ok(None);
    };
    let payload = EncryptedBundlePayload::decode_strict(&encoded)?;
    let decrypted = decrypt_bytes(&payload, password)?;
    repo_bundle::BundleV2::decode(&decrypted)
        .map(Some)
        .map_err(anyhow::Error::new)
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
    let checkout_dir = tmp_root.join(format!("repo-sync-{}", Uuid::new_v4()));
    validate_path_under_root(state_dir, &checkout_dir)?;

    let checkout_str = checkout_dir.to_string_lossy();
    // `--` is deliberately before every user-controlled positional argument. Git clone
    // accepts this form and therefore cannot interpret a repository named like `-A` as an
    // option; the destination is generated under our validated temporary root.
    let args = ["clone", "--depth", "1", "--", repo, checkout_str.as_ref()];

    if let Err(error) = git_cmd(git_bin, state_dir, &args, identity_file, insecure_host_key) {
        let _ = fs::remove_dir(&tmp_root);
        return Err(error);
    }
    let checkout = TempCheckout { checkout_dir };
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

fn validate_repo_source(repo: &str) -> Result<()> {
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
        assert!(canonical_pool_id_for_bundle(repo, &bundle).is_err());
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

    #[cfg(unix)]
    #[test]
    fn fresh_pull_preserves_all_four_credential_kinds() {
        use std::process::Command;

        let temp = tempfile::tempdir().expect("tempdir");
        let remote = temp.path().join("remote.git");
        let seed = temp.path().join("seed");
        let state_dir = temp.path().join("fresh-state");
        let key = format!("repo-test-key-{}", Uuid::new_v4());
        unsafe { std::env::set_var(BUNDLE_KEY_ENV, &key) };

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
                    "token_uri": "https://oauth.example.test/token"
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
        let encrypted = encrypt_bytes(&plaintext, &key).unwrap();
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
        unsafe { std::env::remove_var(BUNDLE_KEY_ENV) };
    }
}
