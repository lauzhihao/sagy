use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

pub mod credential_store;
use credential_store::CredentialStore;

use crate::adapters::antigravity::active_home::{
    ActiveHomeError, ActiveHomeStore, PreparedActiveHomeTxn, PublishedActiveHomeTxn,
    restore_reconcile,
};
use crate::adapters::antigravity::paths::{
    account_token_file, active_home_roots, active_home_scope_id, default_antigravity_cli_home,
    default_gemini_home,
};
use crate::core::atomic_io::read_external_regular_file_bounded;
use crate::core::credential::{CredentialKind, PortableCredential};
use crate::core::health::HealthStatus;
use crate::core::state::{
    AccountRecord, AccountType, ActiveProfile, CredentialRef, CredentialRefKind, ManagedLayout,
    SlotState, State, UsageSnapshot,
};
use crate::core::state_store::{
    MigrationStatus, StateRead, StateSession, StateStore, StateStoreError,
};

/// 账户 mutation 的结果。State commit 即使在后续 evidence cleanup/finalize
/// 失败时也已经持久化；此时必须携带 committed snapshot，避免调用方继续使用旧状态。
#[derive(Debug)]
pub(crate) enum MutationResult<T> {
    Committed {
        value: T,
        state: StateRead,
    },
    CommittedRecoveryPending {
        value: T,
        state: StateRead,
        message: String,
    },
}

impl<T> MutationResult<T> {
    pub(crate) fn into_value(self) -> T {
        match self {
            Self::Committed { value, .. } | Self::CommittedRecoveryPending { value, .. } => value,
        }
    }

    pub(crate) fn state(&self) -> &StateRead {
        match self {
            Self::Committed { state, .. } | Self::CommittedRecoveryPending { state, .. } => state,
        }
    }

    pub(crate) fn recovery_pending(&self) -> bool {
        matches!(self, Self::CommittedRecoveryPending { .. })
    }

    pub(crate) fn recovery_message(&self) -> Option<&str> {
        match self {
            Self::Committed { .. } => None,
            Self::CommittedRecoveryPending { message, .. } => Some(message),
        }
    }
}

/// active-home adoption 必须显式选择。首次 profile 遇到 unmanaged fixed slot
/// 时，普通账户切换保持 fail-closed。
///
/// - `Strict`：只接受空 active home 或与 State before profile 完全一致的现场。
/// - `Adopt`：CLI 默认。磁盘上的凭据**就是**目标账号那一份（逐字节一致）时直接
///   接管；只要不一致就自动降级回 `Strict`，绝不覆盖。
/// - `Takeover`：`--takeover` 显式 opt-in，覆盖前把原文件留成同目录备份。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActiveHomeAdoption {
    Strict,
    Adopt,
    Takeover,
}

pub fn is_valid_oauth_credential(json: &Value) -> bool {
    PortableCredential::from_native_json_str(&json.to_string())
        .map(|credential| matches!(credential.kind(), CredentialKind::OAuthAuthorizedUser))
        .unwrap_or(false)
}

pub fn is_valid_api_key_credential(json: &Value) -> bool {
    PortableCredential::from_native_json_str(&json.to_string())
        .map(|credential| credential.kind() == CredentialKind::ApiKey)
        .unwrap_or(false)
}

impl super::AntigravityAdapter {
    /// 使用精确 State snapshot 导入一个显式 credential source。调用方不提供
    /// mutable state，避免 stale runtime copy 充当 migration 或 credential authority。
    pub(crate) fn import_auth_path_transaction(
        &self,
        state_dir: &Path,
        raw_path: &Path,
    ) -> Result<MutationResult<AccountRecord>> {
        self.import_auth_path_transaction_with_email(state_dir, raw_path, None)
    }

    fn import_auth_path_transaction_with_email(
        &self,
        state_dir: &Path,
        raw_path: &Path,
        email_override: Option<&str>,
    ) -> Result<MutationResult<AccountRecord>> {
        let source = read_import_source(raw_path)?;
        let (credential, source_material) = parse_import_source(&source)?;
        let email = credential_email(&credential)
            .or_else(|| {
                email_override
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| {
                raw_path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(|stem| {
                        if stem == "oauth_creds" {
                            "google-oauth-user@gemini".to_string()
                        } else {
                            format!("{stem}@gemini")
                        }
                    })
                    .unwrap_or_else(|| "imported-account@gemini".to_string())
            });
        if email.trim().is_empty() {
            bail!("credential email cannot be empty")
        }
        run_credential_import(
            state_dir,
            credential,
            source_material,
            &email,
            None,
            ImportMatch::IdentityOrEmail,
            true,
        )
    }

    pub(crate) fn import_or_update_token_transaction(
        &self,
        state_dir: &Path,
        email: &str,
        token: &str,
        plan_label: Option<&str>,
    ) -> Result<MutationResult<AccountRecord>> {
        let token = token.trim();
        let credential =
            PortableCredential::oauth_access_token(token).map_err(anyhow::Error::new)?;
        run_credential_import(
            state_dir,
            credential,
            token.as_bytes().to_vec(),
            email,
            plan_label,
            ImportMatch::IdentityOrEmail,
            true,
        )
    }

    pub(crate) fn import_or_update_api_key_transaction(
        &self,
        state_dir: &Path,
        api_key: &str,
        email: &str,
        project_id: Option<&str>,
    ) -> Result<MutationResult<AccountRecord>> {
        let api_key = api_key.trim();
        let email = email.trim();
        if api_key.is_empty() {
            bail!("API key cannot be empty")
        }
        if email.is_empty() {
            bail!("credential email cannot be empty")
        }
        let credential = api_key_credential(api_key, project_id)?;
        let material = credential_material(&credential)?;
        run_credential_import(
            state_dir,
            credential,
            material,
            email,
            None,
            ImportMatch::IdentityOnly,
            false,
        )
    }

    /// CLI 使用的 session 变体。整个操作只由同一 session 持有 revision，
    /// 并由 StateSession 的 lock callback 推进 snapshot。
    pub(crate) fn import_auth_path_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        raw_path: &Path,
    ) -> Result<MutationResult<AccountRecord>> {
        let source = read_import_source(raw_path)?;
        let (credential, source_material) = parse_import_source(&source)?;
        let email = credential_email(&credential).unwrap_or_else(|| {
            raw_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(|stem| {
                    if stem == "oauth_creds" {
                        "google-oauth-user@gemini".to_string()
                    } else {
                        format!("{stem}@gemini")
                    }
                })
                .unwrap_or_else(|| "imported-account@gemini".to_string())
        });
        run_credential_import_session(
            state_dir,
            session,
            credential,
            source_material,
            &email,
            None,
            ImportMatch::IdentityOrEmail,
            true,
        )
    }

    pub(crate) fn import_or_update_token_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        email: &str,
        token: &str,
        plan_label: Option<&str>,
    ) -> Result<MutationResult<AccountRecord>> {
        let token = token.trim();
        let credential =
            PortableCredential::oauth_access_token(token).map_err(anyhow::Error::new)?;
        run_credential_import_session(
            state_dir,
            session,
            credential,
            token.as_bytes().to_vec(),
            email,
            plan_label,
            ImportMatch::IdentityOrEmail,
            true,
        )
    }

    pub(crate) fn import_or_update_api_key_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        api_key: &str,
        email: &str,
        project_id: Option<&str>,
    ) -> Result<MutationResult<AccountRecord>> {
        let api_key = api_key.trim();
        let email = email.trim();
        if api_key.is_empty() {
            bail!("API key cannot be empty")
        }
        if email.is_empty() {
            bail!("credential email cannot be empty")
        }
        let credential = api_key_credential(api_key, project_id)?;
        let material = credential_material(&credential)?;
        run_credential_import_session(
            state_dir,
            session,
            credential,
            material,
            email,
            None,
            ImportMatch::IdentityOnly,
            false,
        )
    }

    /// Migrate a legacy v1 state using only the fixed account credential
    /// slots.  No caller `State`, arbitrary `auth_path`, or ambient home scan
    /// participates in this transaction.
    /// Run the sealed v1 -> v2 migration on the caller-owned session. The
    /// planner reads only fixed account slots and never manufactures a new
    /// credential from ambient user-home files.
    pub(crate) fn migrate_legacy_state_transaction(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
    ) -> Result<MutationResult<()>> {
        run_legacy_migration_session(state_dir, session)
    }

    pub(crate) fn migrate_legacy_state_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
    ) -> Result<MutationResult<()>> {
        self.migrate_legacy_state_transaction(state_dir, session)
    }

    /// Recover credential and active-home journals using the caller's one
    /// StateSession. This is the startup entry point for current v2 state;
    /// neither helper opens a second snapshot owner.
    pub(crate) fn recover_account_transactions_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
    ) -> Result<()> {
        if !matches!(session.migration(), MigrationStatus::None) {
            bail!("account transaction recovery requires current v2 state")
        }
        recover_active_home_journals(state_dir, session, None)?;
        recover_credential_journals_session(state_dir, session)
    }

    /// Explicit missing-store bootstrap used by CLI startup.  It is separate
    /// from import-known so a normal launch/list/use/rm path cannot scan user
    /// home files as a side effect of opening state.
    pub(crate) fn bootstrap_empty_v2_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
    ) -> Result<MutationResult<()>> {
        if !matches!(session.migration(), MigrationStatus::Missing) {
            bail!("empty v2 bootstrap requires a missing state")
        }
        recover_active_home_journals(state_dir, session, None)?;
        recover_credential_journals_session(state_dir, session)?;
        let committed = session.bootstrap_empty_v2().map_err(anyhow::Error::new)?;
        Ok(MutationResult::Committed {
            value: (),
            state: committed.after().clone(),
        })
    }

    /// Explicit, single-CAS discovery of the two fixed OAuth sources.  The
    /// local token and authorized-user document are merged before staging so
    /// import-known cannot leave a half-imported pair behind.
    pub(crate) fn import_known_sources_transaction(
        &self,
        state_dir: &Path,
    ) -> Result<MutationResult<Vec<AccountRecord>>> {
        let store = StateStore::open(state_dir).map_err(anyhow::Error::new)?;
        let mut session = StateSession::bootstrap_exact(&store).map_err(anyhow::Error::new)?;
        self.import_known_sources_session(state_dir, &mut session)
    }

    pub(crate) fn import_known_sources_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
    ) -> Result<MutationResult<Vec<AccountRecord>>> {
        let Some((credential, material, email)) = scan_known_oauth_source()? else {
            if matches!(session.migration(), MigrationStatus::Missing) {
                recover_active_home_journals(state_dir, session, None)?;
                recover_credential_journals_session(state_dir, session)?;
                let committed = session.bootstrap_empty_v2().map_err(anyhow::Error::new)?;
                return Ok(MutationResult::Committed {
                    value: Vec::new(),
                    state: committed.after().clone(),
                });
            }
            return Ok(MutationResult::Committed {
                value: Vec::new(),
                state: session.read().clone(),
            });
        };
        let imported = run_credential_import_session(
            state_dir,
            session,
            credential,
            material,
            &email,
            Some("Antigravity OAuth"),
            ImportMatch::IdentityOrEmail,
            true,
        )?;
        let pending = imported.recovery_pending();
        let state = imported.state().clone();
        let value = vec![imported.into_value()];
        if pending {
            // The original mutation already carries the exact recovery error;
            // retain it through a bounded user-facing message.
            Ok(MutationResult::CommittedRecoveryPending {
                value,
                state,
                message: "import-known credential evidence cleanup is pending".to_string(),
            })
        } else {
            Ok(MutationResult::Committed { value, state })
        }
    }

    pub fn import_known_sources(&self, state_dir: &Path, state: &mut State) -> Vec<AccountRecord> {
        match self.import_known_sources_transaction(state_dir) {
            Ok(outcome) => {
                apply_compat_state(state, &outcome);
                outcome.into_value()
            }
            Err(error) => {
                eprintln!("warning: known credential import failed: {error}");
                Vec::new()
            }
        }
    }

    pub fn import_auth_path(
        &self,
        state_dir: &Path,
        state: &mut State,
        raw_path: &Path,
    ) -> Result<AccountRecord> {
        let outcome = self.import_auth_path_transaction(state_dir, raw_path)?;
        apply_compat_state(state, &outcome);
        if let Some(message) = outcome.recovery_message() {
            bail!("account import committed; recovery pending: {message}")
        }
        Ok(outcome.into_value())
    }

    pub fn import_or_update_token(
        &self,
        state_dir: &Path,
        state: &mut State,
        email: &str,
        token: &str,
        plan_label: Option<&str>,
    ) -> Result<AccountRecord> {
        let outcome =
            self.import_or_update_token_transaction(state_dir, email, token, plan_label)?;
        apply_compat_state(state, &outcome);
        if let Some(message) = outcome.recovery_message() {
            bail!("account import committed; recovery pending: {message}")
        }
        Ok(outcome.into_value())
    }

    /// Import or update an API-key credential through the same strict
    /// PortableCredential/credential-store path used by file imports.  The
    /// lower layer rejects blank keys and reuses an id for an exact material
    /// duplicate, even when the caller supplies a different email hint.
    pub fn import_or_update_api_key(
        &self,
        state_dir: &Path,
        state: &mut State,
        api_key: &str,
        email: &str,
        project_id: Option<&str>,
    ) -> Result<AccountRecord> {
        let outcome =
            self.import_or_update_api_key_transaction(state_dir, api_key, email, project_id)?;
        apply_compat_state(state, &outcome);
        if let Some(message) = outcome.recovery_message() {
            bail!("API-key import committed; recovery pending: {message}")
        }
        Ok(outcome.into_value())
    }

    pub fn find_account_by_email<'a>(
        &self,
        state: &'a State,
        email_or_id: &str,
    ) -> Option<&'a AccountRecord> {
        let needle = email_or_id.trim();
        state
            .accounts
            .iter()
            .find(|a| a.email.eq_ignore_ascii_case(needle) || a.id == needle)
    }

    pub(crate) fn switch_account_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        account_id: &str,
        adoption: ActiveHomeAdoption,
    ) -> Result<MutationResult<AccountRecord>> {
        self.switch_account_session_inner(state_dir, session, account_id, adoption, None)
    }

    #[cfg(test)]
    fn switch_account_transaction_with_roots(
        &self,
        state_dir: &Path,
        account_id: &str,
        adoption: ActiveHomeAdoption,
        roots: (
            crate::core::atomic_io::NormalizedStoreRoot,
            crate::core::atomic_io::NormalizedStoreRoot,
        ),
    ) -> Result<MutationResult<AccountRecord>> {
        let store = StateStore::open(state_dir).map_err(anyhow::Error::new)?;
        let mut session = StateSession::bootstrap_exact(&store).map_err(anyhow::Error::new)?;
        self.switch_account_session_inner(
            state_dir,
            &mut session,
            account_id,
            adoption,
            Some(roots),
        )
    }

    fn switch_account_session_inner(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        account_id: &str,
        adoption: ActiveHomeAdoption,
        roots: Option<(
            crate::core::atomic_io::NormalizedStoreRoot,
            crate::core::atomic_io::NormalizedStoreRoot,
        )>,
    ) -> Result<MutationResult<AccountRecord>> {
        recover_active_home_journals(state_dir, session, roots.clone())?;
        recover_credential_journals_session(state_dir, session)?;
        let disk = session.read().clone();
        if disk.recovery_pending {
            bail!("state recovery is pending; recover before account switch")
        }
        if !matches!(disk.migration, MigrationStatus::None) {
            bail!("account switch requires a current v2 state")
        }
        session
            .with_locked_exact(|transaction| {
                let snapshot = transaction.snapshot().map_err(anyhow::Error::new)?;
                let account = snapshot
                    .state
                    .accounts
                    .iter()
                    .find(|account| account.id == account_id)
                    .cloned()
                    .ok_or_else(|| StateStoreError::Invalid(anyhow!("account not found")))?;
                let reference = snapshot
                    .state
                    .credential_refs
                    .get(account_id)
                    .cloned()
                    .ok_or_else(|| {
                        StateStoreError::Invalid(anyhow!("account has no v2 credential reference"))
                    })?;

                // Keep the account credential lock from this exact read until
                // active-home publication, State CAS, and receipt-gated
                // finalize/restore all finish. This is the State -> account
                // credential -> active-home lock order and closes the
                // validate-then-publish TOCTOU window.
                let credential_permit = transaction
                    .credential_mutation_permit(account_id)
                    .map_err(anyhow::Error::new)?;
                let credential_store =
                    CredentialStore::from_permit(credential_permit).map_err(anyhow::Error::new)?;
                let credential_lease = credential_store
                    .read_leased(&reference)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let stored = credential_lease.stored();
                let (antigravity_root, gemini_root) = roots
                    .clone()
                    .map_or_else(active_home_roots, Ok)
                    .map_err(StateStoreError::Invalid)?;
                let profile = active_profile_for_reference(
                    account_id,
                    &reference,
                    &stored.material_digest,
                    &antigravity_root,
                    &gemini_root,
                );
                let home_permit = transaction
                    .active_home_mutation_permit_with_ref(
                        Some(profile.clone()),
                        Some(reference.clone()),
                    )
                    .map_err(anyhow::Error::new)?;
                let home_store = ActiveHomeStore::from_permit_with_roots(
                    home_permit,
                    antigravity_root,
                    gemini_root,
                )
                .map_err(StateStoreError::Invalid)?;
                let txid = Uuid::new_v4();
                let prepared = prepare_active_home(home_store, txid, adoption)
                    .map_err(StateStoreError::Invalid)?;
                let published = publish_active_home(prepared).map_err(StateStoreError::Invalid)?;
                let active_proof = match published.journal_proof() {
                    Ok(proof) => proof,
                    Err(error) => {
                        return Err(match published.restore() {
                            Ok(()) => StateStoreError::Invalid(error),
                            Err(restore_error) => StateStoreError::Invalid(anyhow!(
                                "{error}; active-home rollback failed: {restore_error}"
                            )),
                        });
                    }
                };

                let mut candidate = snapshot.state;
                candidate.current_account_id = Some(account_id.to_string());
                candidate.active_profile = Some(profile);
                if let Some(current) = candidate
                    .accounts
                    .iter_mut()
                    .find(|current| current.id == account_id)
                {
                    current.last_used_at = Some(Utc::now().timestamp());
                    current.updated_at = current.updated_at.max(Utc::now().timestamp());
                }
                let receipt = match transaction.commit_coordinated_with_active(
                    &candidate,
                    Vec::new(),
                    Some(active_proof),
                ) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        return Err(match published.restore() {
                            Ok(()) => error,
                            Err(restore_error) => StateStoreError::Invalid(anyhow!(
                                "{error}; active-home rollback failed: {restore_error}"
                            )),
                        });
                    }
                };
                let mut after = transaction.snapshot()?;
                match published.finalize(&receipt) {
                    Ok(()) => Ok(MutationResult::Committed {
                        value: account,
                        state: after,
                    }),
                    Err(error) => {
                        after.recovery_pending = true;
                        Ok(MutationResult::CommittedRecoveryPending {
                            value: account,
                            state: after,
                            message: error.to_string(),
                        })
                    }
                }
            })
            .map_err(anyhow::Error::new)
    }

    /// Delete one account and its fixed credential layout.  Deleting the
    /// current account additionally publishes an active-home tombstone and
    /// removes `current_account_id`/`active_profile` in the same State CAS.
    pub(crate) fn remove_account_transaction(
        &self,
        state_dir: &Path,
        account_id: &str,
    ) -> Result<MutationResult<()>> {
        let store = StateStore::open(state_dir).map_err(anyhow::Error::new)?;
        let mut session = StateSession::bootstrap_exact(&store).map_err(anyhow::Error::new)?;
        self.remove_account_session_inner(state_dir, &mut session, account_id, None)
    }

    pub(crate) fn remove_account_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        account_id: &str,
    ) -> Result<MutationResult<()>> {
        self.remove_account_session_inner(state_dir, session, account_id, None)
    }

    #[cfg(test)]
    fn remove_account_transaction_with_roots(
        &self,
        state_dir: &Path,
        account_id: &str,
        roots: (
            crate::core::atomic_io::NormalizedStoreRoot,
            crate::core::atomic_io::NormalizedStoreRoot,
        ),
    ) -> Result<MutationResult<()>> {
        let store = StateStore::open(state_dir).map_err(anyhow::Error::new)?;
        let mut session = StateSession::bootstrap_exact(&store).map_err(anyhow::Error::new)?;
        self.remove_account_session_inner(state_dir, &mut session, account_id, Some(roots))
    }

    fn remove_account_session_inner(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        account_id: &str,
        roots: Option<(
            crate::core::atomic_io::NormalizedStoreRoot,
            crate::core::atomic_io::NormalizedStoreRoot,
        )>,
    ) -> Result<MutationResult<()>> {
        recover_active_home_journals(state_dir, session, roots.clone())?;
        recover_credential_journals_session(state_dir, session)?;
        let disk = session.read().clone();
        if disk.recovery_pending {
            bail!("state recovery is pending; recover before account deletion")
        }
        if !matches!(disk.migration, MigrationStatus::None) {
            bail!("account deletion requires a current v2 state")
        }
        session
            .with_locked_exact(|transaction| {
                let snapshot = transaction.snapshot().map_err(anyhow::Error::new)?;
                if !snapshot
                    .state
                    .accounts
                    .iter()
                    .any(|account| account.id == account_id)
                {
                    return Err(StateStoreError::Invalid(anyhow!("account not found")));
                }
                let credential_permit = transaction
                    .credential_mutation_permit(account_id)
                    .map_err(anyhow::Error::new)?;
                let credential_store =
                    CredentialStore::from_permit(credential_permit).map_err(anyhow::Error::new)?;
                let layout = credential_store
                    .read_layout()
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let txid = Uuid::new_v4();
                let credential_prepared = credential_store
                    .stage_delete(txid, &layout.expected_layout())
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;

                let deleting_current =
                    snapshot.state.current_account_id.as_deref() == Some(account_id);
                let mut active_prepared: Option<PreparedActiveHomeTxn> = None;
                if deleting_current {
                    let (antigravity_root, gemini_root) = roots
                        .clone()
                        .map_or_else(active_home_roots, Ok)
                        .map_err(StateStoreError::Invalid)?;
                    let before_ref = snapshot.state.credential_refs.get(account_id).cloned();
                    let home_permit = transaction
                        .active_home_mutation_permit_with_ref(None, before_ref)
                        .map_err(anyhow::Error::new)?;
                    let home_store = ActiveHomeStore::from_permit_with_roots(
                        home_permit,
                        antigravity_root,
                        gemini_root,
                    )
                    .map_err(StateStoreError::Invalid)?;
                    active_prepared = Some(
                        prepare_active_home(home_store, Uuid::new_v4(), ActiveHomeAdoption::Strict)
                            .map_err(StateStoreError::Invalid)?,
                    );
                }

                let credential_published = match credential_store.publish(credential_prepared) {
                    Ok(published) => published,
                    Err(error) => {
                        return Err(StateStoreError::Invalid(anyhow::Error::new(error)));
                    }
                };
                let credential_proof = match credential_store.journal_proof(&credential_published) {
                    Ok(proof) => proof,
                    Err(error) => {
                        return Err(match credential_store.restore(credential_published) {
                            Ok(_) => StateStoreError::Invalid(anyhow::Error::new(error)),
                            Err(restore_error) => StateStoreError::Invalid(anyhow!(
                                "{error}; credential rollback failed: {restore_error}"
                            )),
                        });
                    }
                };

                let mut active_published = if let Some(prepared) = active_prepared {
                    match publish_active_home(prepared) {
                        Ok(published) => Some(published),
                        Err(error) => {
                            return Err(match credential_store.restore(credential_published) {
                                Ok(_) => StateStoreError::Invalid(error),
                                Err(restore_error) => StateStoreError::Invalid(anyhow!(
                                    "{error}; credential rollback failed: {restore_error}"
                                )),
                            });
                        }
                    }
                } else {
                    None
                };
                let active_proof = match active_published.take() {
                    Some(published) => match published.journal_proof() {
                        Ok(proof) => {
                            active_published = Some(published);
                            Some(proof)
                        }
                        Err(error) => {
                            let active_restore = published.restore().err();
                            let credential_restore =
                                credential_store.restore(credential_published).err();
                            let mut message = error.to_string();
                            if let Some(restore_error) = active_restore {
                                message.push_str(&format!(
                                    "; active-home rollback failed: {restore_error}"
                                ));
                            }
                            if let Some(restore_error) = credential_restore {
                                message.push_str(&format!(
                                    "; credential rollback failed: {restore_error}"
                                ));
                            }
                            return Err(StateStoreError::Invalid(anyhow!(message)));
                        }
                    },
                    None => None,
                };

                let mut candidate = snapshot.state;
                candidate
                    .accounts
                    .retain(|account| account.id != account_id);
                candidate.usage_cache.remove(account_id);
                candidate.credential_refs.remove(account_id);
                if deleting_current {
                    candidate.current_account_id = None;
                    candidate.active_profile = None;
                }
                let receipt = match active_proof {
                    Some(proof) => transaction.commit_coordinated_with_active(
                        &candidate,
                        vec![credential_proof],
                        Some(proof),
                    ),
                    None => transaction.commit_coordinated(&candidate, vec![credential_proof]),
                };
                let receipt = match receipt {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        let active_restore = active_published
                            .as_ref()
                            .and_then(|published| published.restore().err());
                        let credential_restore =
                            credential_store.restore(credential_published).err();
                        if active_restore.is_none() && credential_restore.is_none() {
                            return Err(error);
                        }
                        let mut message = error.to_string();
                        if let Some(restore_error) = active_restore {
                            message.push_str(&format!(
                                "; active-home rollback failed: {restore_error}"
                            ));
                        }
                        if let Some(restore_error) = credential_restore {
                            message.push_str(&format!(
                                "; credential rollback failed: {restore_error}"
                            ));
                        }
                        return Err(StateStoreError::Invalid(anyhow!(message)));
                    }
                };
                let mut after = transaction.snapshot()?;
                let mut recovery = Vec::new();
                if let Some(published) = active_published {
                    if let Err(error) = published.finalize(&receipt) {
                        recovery.push(error.to_string());
                    }
                }
                if let Err(error) = credential_store.finalize(credential_published, &receipt) {
                    recovery.push(error.to_string());
                }
                if recovery.is_empty() {
                    Ok(MutationResult::Committed {
                        value: (),
                        state: after,
                    })
                } else {
                    after.recovery_pending = true;
                    Ok(MutationResult::CommittedRecoveryPending {
                        value: (),
                        state: after,
                        message: recovery.join("; "),
                    })
                }
            })
            .map_err(anyhow::Error::new)
    }

    pub fn remove_account(&self, state_dir: &Path, state: &mut State, id: &str) -> Result<()> {
        let outcome = self.remove_account_transaction(state_dir, id)?;
        apply_compat_state(state, &outcome);
        if let Some(message) = outcome.recovery_message() {
            bail!("account deletion committed; recovery pending: {message}")
        }
        Ok(())
    }
}

pub fn compute_credential_fingerprint(secret: &str) -> String {
    PortableCredential::oauth_access_token(secret.trim())
        .map(|credential| credential.fingerprint())
        .unwrap_or_else(|_| "sha256:invalid".to_string())
}

fn apply_compat_state<T>(state: &mut State, outcome: &MutationResult<T>) {
    *state = outcome.state().state.clone();
    if let Some(message) = outcome.recovery_message() {
        // Legacy wrappers cannot carry the typed result, but must still move
        // their runtime snapshot forward and tell the user recovery is needed.
        eprintln!("warning: account mutation committed; recovery pending: {message}");
    }
}

fn active_profile_for_reference(
    account_id: &str,
    reference: &CredentialRef,
    material_digest: &str,
    antigravity_root: &crate::core::atomic_io::NormalizedStoreRoot,
    gemini_root: &crate::core::atomic_io::NormalizedStoreRoot,
) -> ActiveProfile {
    // CredentialStore evidence labels digests as `sha256:<hex>`, while the
    // managed home layout stores the raw 64-character hex digest.
    let material_digest = material_digest
        .strip_prefix("sha256:")
        .unwrap_or(material_digest)
        .to_string();
    let managed_layout = match reference.kind {
        CredentialRefKind::OauthAccessToken => ManagedLayout {
            antigravity_token: SlotState::Exact {
                sha256: material_digest.clone(),
            },
            gemini_authorized_user: SlotState::Absent,
        },
        CredentialRefKind::OauthAuthorizedUser => ManagedLayout {
            antigravity_token: SlotState::Absent,
            gemini_authorized_user: SlotState::Exact {
                sha256: material_digest,
            },
        },
        CredentialRefKind::ApiKey | CredentialRefKind::VertexServiceAccount => {
            ManagedLayout::default()
        }
    };
    ActiveProfile {
        account_id: account_id.to_string(),
        credential_fingerprint: reference.fingerprint.clone(),
        home_scope_id: active_home_scope_id(antigravity_root, gemini_root),
        managed_layout,
    }
}

fn prepare_active_home(
    store: ActiveHomeStore,
    txid: Uuid,
    adoption: ActiveHomeAdoption,
) -> Result<PreparedActiveHomeTxn> {
    let prepared = match adoption {
        ActiveHomeAdoption::Strict => store.prepare(txid),
        ActiveHomeAdoption::Adopt => store.prepare_adopt(txid),
        ActiveHomeAdoption::Takeover => store.prepare_takeover(txid),
    };
    prepared.map_err(|error| match error {
        ActiveHomeError::Invalid(error) => error,
        ActiveHomeError::ReconcileRequired { source, token } => match restore_reconcile(token) {
            Ok(()) => source,
            Err(restore_error) => {
                anyhow!("{source}; active-home restore failed: {restore_error}")
            }
        },
    })
}

fn publish_active_home(prepared: PreparedActiveHomeTxn) -> Result<PublishedActiveHomeTxn> {
    match prepared.publish() {
        Ok(published) => Ok(published),
        Err(ActiveHomeError::Invalid(error)) => Err(error),
        Err(ActiveHomeError::ReconcileRequired { source, token }) => {
            match restore_reconcile(token) {
                Ok(()) => Err(source),
                Err(restore_error) => Err(anyhow!(
                    "{source}; active-home restore failed: {restore_error}"
                )),
            }
        }
    }
}

fn scan_known_oauth_source() -> Result<Option<(PortableCredential, Vec<u8>, String)>> {
    let active_email = default_gemini_home()
        .map(|home| home.join("google_accounts.json"))
        .filter(|path| path.exists())
        .map(|path| -> Result<Option<String>> {
            let bytes = read_external_regular_file_bounded(
                &path,
                credential_store::MAX_CREDENTIAL_FILE_BYTES,
            )?;
            let value: Value = serde_json::from_slice(&bytes)
                .context("known google_accounts.json is not valid JSON")?;
            Ok(value
                .get("active")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string))
        })
        .transpose()?
        .flatten();

    let local_token = default_antigravity_cli_home()
        .map(|home| home.join("antigravity-oauth-token"))
        .filter(|path| path.exists())
        .map(|path| -> Result<Option<String>> {
            let bytes = read_external_regular_file_bounded(
                &path,
                credential_store::MAX_CREDENTIAL_FILE_BYTES,
            )?;
            let token = std::str::from_utf8(&bytes)
                .context("known OAuth token is not UTF-8")?
                .trim()
                .to_string();
            if token.is_empty() {
                return Ok(None);
            }
            Ok(Some(token))
        })
        .transpose()?
        .flatten();

    let authorized = default_gemini_home()
        .map(|home| home.join("oauth_creds.json"))
        .filter(|path| path.exists())
        .map(|path| {
            let bytes = read_import_source(&path)?;
            if is_provider_managed_session(&bytes) {
                return Err(anyhow::Error::new(ProviderManagedSession));
            }
            let (credential, _) = parse_import_source(&bytes)?;
            if credential.kind() != CredentialKind::OAuthAuthorizedUser {
                bail!("known oauth_creds.json is not an authorized-user credential")
            }
            Ok((credential, bytes))
        })
        .transpose()?;

    let (credential, material) = match (local_token, authorized) {
        (None, None) => return Ok(None),
        (Some(token), None) => {
            let credential =
                PortableCredential::oauth_access_token(&token).map_err(anyhow::Error::new)?;
            (credential, token.into_bytes())
        }
        (None, Some((credential, bytes))) => (credential, bytes),
        (Some(token), Some((credential, _))) => {
            let merged = credential
                .with_access_token(&token)
                .map_err(anyhow::Error::new)?;
            let material = merged
                .to_native_json_string()
                .map_err(anyhow::Error::new)?
                .into_bytes();
            (merged, material)
        }
    };
    let email = credential_email(&credential)
        .or(active_email)
        .unwrap_or_else(|| "antigravity-user@gemini".to_string());
    Ok(Some((credential, material, email)))
}

/// A provider-native Gemini session is not an authorized-user document.  Its
/// refresh lifecycle may be owned by the provider's system credential store,
/// so treating it as portable OAuth would either lose the owner metadata or
/// make sagy responsible for refreshing a credential it cannot safely manage.
/// Keep this error private: callers only need the actionable, secret-free
/// message and the public credential schema must not grow for an unsupported
/// provider format.
#[derive(Debug, Clone, Copy)]
struct ProviderManagedSession;

impl fmt::Display for ProviderManagedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "known oauth_creds.json is a provider-managed session; sagy cannot safely import or switch it because its credential may be managed by the system credential store; run `agy` directly",
        )
    }
}

impl std::error::Error for ProviderManagedSession {}

/// Recognize only the provider's six-field session shape.  This deliberately
/// does not return a credential or copy any field into an error.  Empty
/// `id_token` and `scope` are accepted because the provider emits them that
/// way for some sessions; access/refresh tokens remain required and bounded.
fn is_provider_managed_session(bytes: &[u8]) -> bool {
    const FIELDS: [&str; 6] = [
        "access_token",
        "expiry_date",
        "id_token",
        "refresh_token",
        "scope",
        "token_type",
    ];

    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    let Some(document) = value.as_object() else {
        return false;
    };
    if document.len() != FIELDS.len()
        || document
            .keys()
            .any(|field| !FIELDS.contains(&field.as_str()))
    {
        return false;
    }

    let bounded_nonempty = |field: &str| {
        document
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| {
                !value.trim().is_empty()
                    && value.len() <= crate::core::credential::MAX_CREDENTIAL_FIELD_BYTES
            })
    };
    let bounded_maybe_empty = |field: &str| {
        document
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| value.len() <= crate::core::credential::MAX_CREDENTIAL_FIELD_BYTES)
    };

    bounded_nonempty("access_token")
        && document
            .get("expiry_date")
            .and_then(Value::as_u64)
            .is_some()
        && bounded_maybe_empty("id_token")
        && bounded_nonempty("refresh_token")
        && bounded_maybe_empty("scope")
        && document
            .get("token_type")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "Bearer")
}

fn read_import_source(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        read_external_regular_file_bounded(path, credential_store::MAX_CREDENTIAL_FILE_BYTES)
            .with_context(|| format!("failed to inspect auth file {}", path.display()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        bail!("auth credential file is blank")
    }
    Ok(bytes)
}

fn parse_import_source(bytes: &[u8]) -> Result<(PortableCredential, Vec<u8>)> {
    let text = std::str::from_utf8(bytes).context("auth credential file is not UTF-8")?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("auth credential input cannot be blank")
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let (credential, portable_envelope) = match PortableCredential::from_json_str(trimmed) {
            Ok(credential) => (credential, true),
            Err(_) => (
                PortableCredential::from_native_json_str(trimmed).map_err(anyhow::Error::new)?,
                false,
            ),
        };
        let material = if credential.kind() == CredentialKind::OAuthAccessToken {
            credential
                .access_token()
                .ok_or_else(|| anyhow::anyhow!("raw OAuth credential has no access token"))?
                .as_bytes()
                .to_vec()
        } else if portable_envelope {
            credential.to_native_json_string()?.into_bytes()
        } else {
            bytes.to_vec()
        };
        return Ok((credential, material));
    }

    let credential = PortableCredential::oauth_access_token(trimmed).map_err(anyhow::Error::new)?;
    Ok((credential, trimmed.as_bytes().to_vec()))
}

fn credential_email(credential: &PortableCredential) -> Option<String> {
    credential.native_document().and_then(|document| {
        ["email", "client_email", "account", "user"]
            .into_iter()
            .find_map(|field| {
                document
                    .get(field)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
            })
    })
}

fn credential_material(credential: &PortableCredential) -> Result<Vec<u8>> {
    if credential.kind() == CredentialKind::OAuthAccessToken {
        return Ok(credential
            .access_token()
            .ok_or_else(|| anyhow::anyhow!("raw OAuth credential has no access token"))?
            .as_bytes()
            .to_vec());
    }
    Ok(credential.to_native_json_string()?.into_bytes())
}

fn merge_oauth_import(
    store: &CredentialStore,
    credential: PortableCredential,
    existing: Option<&AccountRecord>,
) -> Result<PortableCredential> {
    match credential.kind() {
        CredentialKind::OAuthAccessToken => {
            let existing_authorized = store
                .read_kind(crate::core::state::CredentialRefKind::OauthAuthorizedUser)
                .map_err(anyhow::Error::new)?;
            if let Some(authorized) = existing_authorized {
                return authorized
                    .credential
                    .with_access_token(
                        credential
                            .access_token()
                            .ok_or_else(|| anyhow::anyhow!("raw OAuth credential has no token"))?,
                    )
                    .map_err(anyhow::Error::new);
            }
            if existing.is_some_and(|account| {
                account
                    .refresh_token
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
            }) {
                bail!(
                    "account has refresh material but no complete authorized-user credential document"
                );
            }
            Ok(credential)
        }
        CredentialKind::OAuthAuthorizedUser if credential.access_token().is_none() => {
            let existing_raw = store
                .read_kind(crate::core::state::CredentialRefKind::OauthAccessToken)
                .map_err(anyhow::Error::new)?;
            if let Some(raw) = existing_raw {
                return credential
                    .with_access_token(
                        raw.credential
                            .access_token()
                            .ok_or_else(|| anyhow::anyhow!("raw OAuth credential has no token"))?,
                    )
                    .map_err(anyhow::Error::new);
            }
            Ok(credential)
        }
        _ => Ok(credential),
    }
}

/// Report whether the account's stored credential is an API key with exactly
/// this secret.
///
/// 只看磁盘上真实的 `api_key` 值，不看指纹：旧版本把 `email` / `project_id`
/// 一起写进了凭据文档，指纹因此跨版本改变。读失败（缺文件、类型不符、损坏）
/// 一律当作"不匹配"，绝不因为一个无关账号的坏凭据阻断本次导入。
fn stored_api_key_matches(state_dir: &Path, account_id: &str, api_key: &str) -> bool {
    let Ok(store) = CredentialStore::new(state_dir, account_id) else {
        return false;
    };
    matches!(
        store.read_kind(CredentialRefKind::ApiKey),
        Ok(Some(stored)) if stored.credential.api_key_value() == Some(api_key)
    )
}

#[derive(Clone, Copy)]
enum ImportMatch {
    IdentityOrEmail,
    IdentityOnly,
}

fn credential_ref_kind_for(credential: &PortableCredential) -> CredentialRefKind {
    match credential.kind() {
        CredentialKind::OAuthAccessToken => CredentialRefKind::OauthAccessToken,
        CredentialKind::OAuthAuthorizedUser => CredentialRefKind::OauthAuthorizedUser,
        CredentialKind::ApiKey => CredentialRefKind::ApiKey,
        CredentialKind::VertexServiceAccount => CredentialRefKind::VertexServiceAccount,
    }
}

#[cfg(test)]
fn recover_credential_journals(state_dir: &Path, state: &StateRead) -> Result<()> {
    // A completely absent root cannot contain a credential journal.  Avoid
    // claiming it merely to perform an empty recovery pass; this keeps pure
    // first-import setup side-effect free while still scanning a present root
    // that has accounts but no state.json below.
    if matches!(state.migration, MigrationStatus::Missing)
        && matches!(
            fs::symlink_metadata(state_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    {
        return Ok(());
    }
    let store = StateStore::open(state_dir).map_err(anyhow::Error::new)?;
    let mut session = StateSession::bootstrap_exact(&store).map_err(anyhow::Error::new)?;
    if session.revision() != &state.revision {
        bail!("credential recovery snapshot is stale")
    }
    recover_credential_journals_session(state_dir, &mut session)
}

fn recover_credential_journals_session(state_dir: &Path, session: &mut StateSession) -> Result<()> {
    // A completely absent root cannot contain a credential journal. Avoid
    // claiming it merely to perform an empty recovery pass during bootstrap.
    if matches!(session.migration(), MigrationStatus::Missing)
        && matches!(
            fs::symlink_metadata(state_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    {
        return Ok(());
    }
    session
        .with_locked_exact::<(), StateStoreError, _>(|transaction| {
            let snapshot = transaction.snapshot()?;
            // Include account directories that are not yet in state.json: a
            // crash may happen after credential publish but before its State
            // commit. Both sets are sorted before account locks are acquired.
            let mut account_ids = transaction.account_ids()?;
            account_ids.extend(
                snapshot
                    .state
                    .accounts
                    .iter()
                    .map(|account| account.id.clone()),
            );
            account_ids.sort();
            account_ids.dedup();
            let authority = transaction.recovery_authority()?;
            for account_id in account_ids {
                let permit = transaction.credential_mutation_permit(&account_id)?;
                let credential_store = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                credential_store
                    .recover_pending(authority.clone())
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
            }
            Ok(())
        })
        .map_err(anyhow::Error::new)
}

fn recover_active_home_journals(
    state_dir: &Path,
    session: &mut StateSession,
    roots: Option<(
        crate::core::atomic_io::NormalizedStoreRoot,
        crate::core::atomic_io::NormalizedStoreRoot,
    )>,
) -> Result<()> {
    // Active-home journals live below account capabilities. A missing root
    // has no account directory and must remain a pure empty-v2 bootstrap.
    if matches!(session.migration(), MigrationStatus::Missing)
        && matches!(
            fs::symlink_metadata(state_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    {
        return Ok(());
    }
    session
        .with_locked_exact::<(), StateStoreError, _>(|transaction| {
            let mut account_ids = transaction.account_ids()?;
            account_ids.sort();
            account_ids.dedup();
            if account_ids.is_empty() {
                return Ok(());
            }
            // Normalizing roots does not claim or lock them. ActiveHomeStore
            // acquires account then sorted home locks for each account below.
            let (antigravity_root, gemini_root) = roots
                .clone()
                .map_or_else(active_home_roots, Ok)
                .map_err(StateStoreError::Invalid)?;
            let authority = transaction.active_home_recovery_authority()?;
            for account_id in account_ids {
                let permit = transaction.active_home_recovery_permit(&account_id)?;
                let mut pending = permit
                    .account_capability()
                    .artifact_locators()
                    .map_err(StateStoreError::Invalid)?
                    .into_iter()
                    .filter_map(|locator| {
                        let name = locator.as_path().file_name()?.to_str()?;
                        let raw = name
                            .strip_prefix(".sagy-active-home-")?
                            .strip_suffix(".journal")?;
                        let txid = Uuid::parse_str(raw).ok()?;
                        (txid.to_string() == raw).then_some(txid)
                    })
                    .collect::<Vec<_>>();
                pending.sort_unstable();
                pending.dedup();
                for txid in pending {
                    let permit = transaction.active_home_recovery_permit(&account_id)?;
                    let store = ActiveHomeStore::from_permit_with_roots(
                        permit,
                        antigravity_root.clone(),
                        gemini_root.clone(),
                    )
                    .map_err(StateStoreError::Invalid)?;
                    crate::adapters::antigravity::active_home::recover_pending(
                        store,
                        authority.clone(),
                        txid,
                    )
                    .map_err(StateStoreError::Invalid)?;
                }
            }
            Ok(())
        })
        .map_err(anyhow::Error::new)
}

fn run_legacy_migration_session(
    state_dir: &Path,
    session: &mut StateSession,
) -> Result<MutationResult<()>> {
    recover_active_home_journals(state_dir, session, None)?;
    recover_credential_journals_session(state_dir, session)?;
    if matches!(session.migration(), MigrationStatus::Missing) {
        let committed = session.bootstrap_empty_v2().map_err(anyhow::Error::new)?;
        return Ok(MutationResult::Committed {
            value: (),
            state: committed.after().clone(),
        });
    }
    if matches!(session.migration(), MigrationStatus::None) {
        return Err(anyhow!("state is already current v2"));
    }
    let disk = session.read().clone();
    if disk.recovery_pending {
        bail!("state recovery is pending; recover before legacy migration")
    }
    let mut reported = Vec::new();
    // 隔离改名发生在事务的 staging 阶段，而且是非事务性的：事务回滚不会把它移
    // 回去。必须在闭包外面留一份"已经真的改了名"的清单，回滚时告诉用户
    // （AC-R12-1.1）。
    let mut quarantined: Vec<QuarantinedFiles> = Vec::new();
    let outcome = session
        .with_locked_exact(|transaction| {
            let base = transaction.snapshot()?.state;
            let plan = credential_store::MigrationPlanner::plan(state_dir, &base)
                .map_err(anyhow::Error::new)?;
            let mut planned = plan.entries;
            let skipped = plan.skipped;
            planned.sort_by(|left, right| left.account_id.cmp(&right.account_id));
            reported.clone_from(&skipped);

            let mut staged = Vec::with_capacity(planned.len() + skipped.len());
            for entry in planned {
                let permit = transaction
                    .credential_mutation_permit(&entry.account_id)
                    .map_err(anyhow::Error::new)?;
                let (store, prepared) =
                    prepare_credential_with_permit(permit, &entry.credential, entry.material())?;
                staged.push((
                    entry.account_id,
                    Some(entry.credential_ref),
                    store,
                    prepared,
                ));
            }
            for skip in &skipped {
                let permit = transaction
                    .credential_mutation_permit(&skip.account_id)
                    .map_err(anyhow::Error::new)?;
                let (store, prepared, moved) = purge_unmigratable_account(permit, &base, skip)?;
                if !moved.is_empty() {
                    quarantined.push(QuarantinedFiles {
                        account_id: skip.account_id.clone(),
                        files: moved,
                    });
                }
                staged.push((skip.account_id.clone(), None, store, prepared));
            }
            staged.sort_by(|left, right| left.0.cmp(&right.0));

            let mut published = Vec::with_capacity(staged.len());
            for (account_id, reference, store, prepared) in staged {
                match store.publish(prepared) {
                    Ok(published_txn) => {
                        published.push((account_id, reference, store, published_txn))
                    }
                    Err(error) => {
                        restore_published_transactions(published)?;
                        return Err(StateStoreError::Invalid(anyhow::Error::new(error)));
                    }
                }
            }
            let mut proofs = Vec::with_capacity(published.len());
            for (_, _, store, published_txn) in &published {
                match store.journal_proof(published_txn) {
                    Ok(proof) => proofs.push(proof),
                    Err(error) => {
                        restore_published_transactions(published)?;
                        return Err(StateStoreError::Invalid(anyhow::Error::new(error)));
                    }
                }
            }

            let mut candidate = base;
            candidate.version = 2;
            candidate.current_account_id = None;
            candidate.active_profile = None;
            candidate.credential_refs.clear();
            for proof in &proofs {
                if let Some(reference) = proof.after_ref() {
                    candidate
                        .credential_refs
                        .insert(proof.account_id().to_string(), reference.clone());
                }
            }
            // 被跳过的账号在 v2 里没有凭据引用，必须一并从账号表和用量缓存移除，
            // 否则 encode_v2 会因为缺 credential_ref 而拒绝写出。原始数据已经隔离
            // 到 accounts/<id>/ 的 quarantine 文件里，不随之销毁。
            retain_migratable_accounts(&mut candidate, &skipped);
            let permit = transaction.migration_commit_permit(proofs)?;
            let receipt = match transaction.commit_migration(&candidate, permit) {
                Ok(receipt) => receipt,
                Err(error) => {
                    restore_published_transactions(published)?;
                    return Err(error);
                }
            };
            let mut after = transaction.snapshot()?;
            let mut recovery = Vec::new();
            for (_, _, store, published_txn) in published {
                if let Err(error) = store.finalize(published_txn, &receipt) {
                    recovery.push(error.to_string());
                }
            }
            if recovery.is_empty() {
                Ok(MutationResult::Committed {
                    value: (),
                    state: after,
                })
            } else {
                after.recovery_pending = true;
                Ok(MutationResult::CommittedRecoveryPending {
                    value: (),
                    state: after,
                    message: recovery.join("; "),
                })
            }
        })
        .map_err(anyhow::Error::new);
    // 提示必须在事务外打印：事务内打印会在回滚时留下与最终结果矛盾的输出。
    // 同理，只有事务真的提交成功才可以报告跳过——整笔回滚时数据仍是 v1，
    // 打印 "was skipped / 原始数据已保留" 与实际结果矛盾。
    match outcome {
        Ok(value) => {
            report_migration_skips(&reported);
            Ok(value)
        }
        // 回滚了，但隔离改名已经落盘且不会被撤销。以前这条路径什么都不说，
        // 用户只看到一个与文件系统状态无关的错误。
        Err(error) => Err(annotate_rollback_quarantine(error, &quarantined)),
    }
}

/// One account's already-performed quarantine renames.
struct QuarantinedFiles {
    account_id: String,
    files: Vec<String>,
}

/// Attach the quarantine renames that a rolled-back migration left on disk.
///
/// 为什么选"让它可见"而不是"撤销"：撤销要再做一次同样非事务性的反向改名，
/// 反向改名自身失败时磁盘会停在"既不是隔离前也不是隔离后"的第三种状态，比
/// 如实报告更糟。隔离只改名、不销毁数据，v1 state 仍然完整，因此可见即足够。
fn annotate_rollback_quarantine(
    error: anyhow::Error,
    quarantined: &[QuarantinedFiles],
) -> anyhow::Error {
    let paths: Vec<String> = quarantined
        .iter()
        .flat_map(|entry| {
            entry
                .files
                .iter()
                .map(move |name| format!("accounts/{}/{}", entry.account_id, name))
        })
        .collect();
    if paths.is_empty() {
        return error;
    }
    error.context(format!(
        "legacy migration rolled back and the state is still v1, but {} credential file(s) \
had already been moved aside and were NOT moved back: {}. Nothing was deleted; move them \
back by hand or leave them in place, then rerun.",
        paths.len(),
        paths.join(", ")
    ))
}

/// Print one ASCII notice per account that legacy migration could not carry
/// into v2, plus an actionable hint for what the user can do next.
fn report_migration_skips(skipped: &[credential_store::MigrationSkip]) {
    for skip in skipped {
        eprintln!(
            "warning: legacy account {} (id {}) was skipped during v1 migration: {}",
            ascii_console(&skip.email),
            skip.account_id,
            ascii_console(&skip.reason)
        );
        eprintln!(
            "warning: its original data is preserved under accounts/{}/ with the \
'.sagy-credential-quarantine.' prefix; nothing was deleted",
            skip.account_id
        );
    }
    if !skipped.is_empty() {
        eprintln!(
            "warning: {} legacy account(s) were skipped. Register a working credential with \
`sagy add`, or re-import a quarantined credential with `sagy import-auth <file>`.",
            skipped.len()
        );
    }
}

/// Drop the accounts that migration could not carry, together with their usage
/// cache entries, so the v2 document stays internally consistent.
fn retain_migratable_accounts(state: &mut State, skipped: &[credential_store::MigrationSkip]) {
    if skipped.is_empty() {
        return;
    }
    let dropped: std::collections::BTreeSet<&str> = skipped
        .iter()
        .map(|skip| skip.account_id.as_str())
        .collect();
    state
        .accounts
        .retain(|account| !dropped.contains(account.id.as_str()));
    state
        .usage_cache
        .retain(|account_id, _| !dropped.contains(account_id.as_str()));
    if state
        .current_account_id
        .as_deref()
        .is_some_and(|current| dropped.contains(current))
    {
        state.current_account_id = None;
        state.active_profile = None;
    }
}

/// Isolate an unmigratable legacy account and stage the empty transaction that
/// retires it.
fn purge_unmigratable_account(
    permit: crate::core::state_store::CredentialMutationPermit,
    base: &State,
    skip: &credential_store::MigrationSkip,
) -> Result<(
    CredentialStore,
    credential_store::PreparedCredentialTxn,
    Vec<String>,
)> {
    let store = CredentialStore::from_permit(permit).map_err(anyhow::Error::new)?;
    let evidence = quarantine_evidence(base, skip)?;
    let moved = store
        .quarantine_unmigratable(&evidence)
        .map_err(anyhow::Error::new)?;
    let prepared = store
        .stage_purge(Uuid::new_v4())
        .map_err(anyhow::Error::new)?;
    Ok((store, prepared, moved))
}

/// Serialize the untouched v1 account record plus the skip reason.
fn quarantine_evidence(base: &State, skip: &credential_store::MigrationSkip) -> Result<Vec<u8>> {
    let record = base
        .accounts
        .iter()
        .find(|account| account.id == skip.account_id)
        .ok_or_else(|| anyhow!("skipped account is not part of the legacy state"))?;
    let document = serde_json::json!({
        "quarantined_from": "sagy-v1-state",
        "reason": skip.reason,
        "account": record,
    });
    serde_json::to_vec_pretty(&document).context("failed to encode quarantine evidence")
}

/// Coordinate one credential mutation with the exact StateStore transaction.
/// The state lock is acquired first; every account credential lock is then
/// acquired in sorted account-id order.  A staged journal is published before
/// the matching state reference is committed, and only the receipt returned by
/// that commit may finalize evidence.
#[allow(clippy::too_many_arguments)]
fn run_credential_import(
    state_dir: &Path,
    incoming: PortableCredential,
    source_material: Vec<u8>,
    email: &str,
    plan_label: Option<&str>,
    matching: ImportMatch,
    merge_oauth: bool,
) -> Result<MutationResult<AccountRecord>> {
    let store = StateStore::open(state_dir).map_err(anyhow::Error::new)?;
    let mut session = StateSession::bootstrap_exact(&store).map_err(anyhow::Error::new)?;
    run_credential_import_session(
        state_dir,
        &mut session,
        incoming,
        source_material,
        email,
        plan_label,
        matching,
        merge_oauth,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_credential_import_session(
    state_dir: &Path,
    session: &mut StateSession,
    incoming: PortableCredential,
    source_material: Vec<u8>,
    email: &str,
    plan_label: Option<&str>,
    matching: ImportMatch,
    merge_oauth: bool,
) -> Result<MutationResult<AccountRecord>> {
    recover_active_home_journals(state_dir, session, None)?;
    recover_credential_journals_session(state_dir, session)?;
    if matches!(session.migration(), MigrationStatus::Missing) {
        // A missing store bootstraps only an empty v2 document.  In particular,
        // no caller state or ambient ~/.gemini files are allowed to seed it.
        session.bootstrap_empty_v2().map_err(anyhow::Error::new)?;
    }
    let disk = session.read().clone();
    if disk.recovery_pending {
        bail!("state recovery is pending; recover before account import")
    }
    let migration = matches!(
        disk.migration,
        MigrationStatus::Missing | MigrationStatus::LegacyV1
    );
    // 冲突检测必须在写任何东西之前完成，这样交互式录入也能在读取 secret 之前
    // 用同一个函数拦下来（见 `ensure_import_kind_compatible`）。
    if matches!(matching, ImportMatch::IdentityOrEmail) {
        ensure_import_kind_compatible(&disk.state, email, incoming.kind())?;
    }
    let mut reported = Vec::new();
    // 与 legacy 迁移同理：隔离改名不在事务内，回滚不会撤销它（AC-R12-1.1）。
    let mut quarantined: Vec<QuarantinedFiles> = Vec::new();
    let outcome = session
        .with_locked_exact(|transaction| {
            let transaction_state = transaction.snapshot().map_err(anyhow::Error::new)?;
            let mut base = transaction_state.state;
            base.version = base.version.max(1);

            let incoming_fingerprint = incoming.fingerprint();
            // 升级前写出的 API key 文档还带着 `email` / `project_id`，指纹与现在
            // 只含 `api_key` 的文档不同。ApiKey 导入按 IdentityOnly 只比指纹，
            // 于是升级后重跑同一条 `sagy add --api-key` 会新建第二个账号、写出
            // 第二份明文 key，policy 再把它们当两个候选调度。这里按磁盘上真实的
            // api_key 值兜底匹配，跨版本仍然复用同一个账号。
            let incoming_api_key = incoming.api_key_value().map(ToString::to_string);
            let existing = base.accounts.iter().find(|account| match matching {
                ImportMatch::IdentityOnly => {
                    account.identity_fingerprint.as_deref() == Some(incoming_fingerprint.as_str())
                        || base
                            .credential_refs
                            .get(&account.id)
                            .is_some_and(|reference| reference.fingerprint == incoming_fingerprint)
                        || incoming_api_key.as_deref().is_some_and(|api_key| {
                            stored_api_key_matches(state_dir, &account.id, api_key)
                        })
                }
                ImportMatch::IdentityOrEmail => {
                    account.identity_fingerprint.as_deref() == Some(incoming_fingerprint.as_str())
                        || base
                            .credential_refs
                            .get(&account.id)
                            .is_some_and(|reference| reference.fingerprint == incoming_fingerprint)
                        || account.email.eq_ignore_ascii_case(email)
                }
            });
            let account_id = existing
                .map(|account| account.id.clone())
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            let read_store =
                CredentialStore::new(state_dir, &account_id).map_err(anyhow::Error::new)?;
            let original = incoming.clone();
            let credential = if merge_oauth {
                merge_oauth_import(&read_store, incoming, existing)?
            } else {
                incoming
            };
            let material = if credential == original {
                source_material.clone()
            } else {
                credential_material(&credential)?
            };
            let now = Utc::now().timestamp();
            let mut record =
                record_from_credential(&account_id, email, &credential, &read_store, now)?;
            if let Some(existing) = existing {
                preserve_account_metadata(&mut record, existing, now);
                if credential.kind() == CredentialKind::OAuthAccessToken
                    && existing.is_oauth()
                    && record.refresh_token.is_none()
                {
                    record.refresh_token = existing.refresh_token.clone();
                }
                if plan_label.is_none() {
                    record.plan = existing.plan.clone();
                }
            }
            if let Some(plan_label) = plan_label {
                record.plan = Some(plan_label.to_string());
            }

            let mut work = Vec::<(String, PortableCredential, Vec<u8>, CredentialRef)>::new();
            let mut skipped = Vec::new();
            if migration {
                let plan = credential_store::MigrationPlanner::plan(state_dir, &base)
                    .map_err(anyhow::Error::new)?;
                let mut planned = plan.entries;
                skipped = plan.skipped;
                skipped.retain(|skip| skip.account_id != account_id);
                planned.sort_by(|left, right| left.account_id.cmp(&right.account_id));
                for entry in planned {
                    if entry.account_id == account_id {
                        continue;
                    }
                    let entry_account_id = entry.account_id.clone();
                    work.push((
                        entry_account_id,
                        entry.credential.clone(),
                        entry.material().to_vec(),
                        entry.credential_ref,
                    ));
                }
            }
            reported.clone_from(&skipped);
            let target_ref = CredentialRef {
                kind: credential_ref_kind_for(&credential),
                fingerprint: credential.fingerprint(),
            };
            work.push((
                account_id.clone(),
                credential.clone(),
                material,
                target_ref.clone(),
            ));
            work.sort_by(|left, right| left.0.cmp(&right.0));

            let mut staged = Vec::with_capacity(work.len() + skipped.len());
            for (id, credential, material, reference) in work {
                let permit = transaction
                    .credential_mutation_permit(&id)
                    .map_err(anyhow::Error::new)?;
                let (store, stage) =
                    prepare_credential_with_permit(permit, &credential, &material)?;
                staged.push((id, Some(reference), store, stage));
            }
            for skip in &skipped {
                let permit = transaction
                    .credential_mutation_permit(&skip.account_id)
                    .map_err(anyhow::Error::new)?;
                let (store, stage, moved) = purge_unmigratable_account(permit, &base, skip)?;
                if !moved.is_empty() {
                    quarantined.push(QuarantinedFiles {
                        account_id: skip.account_id.clone(),
                        files: moved,
                    });
                }
                staged.push((skip.account_id.clone(), None, store, stage));
            }
            staged.sort_by(|left, right| left.0.cmp(&right.0));

            let mut published = Vec::with_capacity(staged.len());
            for (id, reference, store, prepared) in staged {
                match store.publish(prepared) {
                    Ok(published_txn) => published.push((id, reference, store, published_txn)),
                    Err(error) => {
                        restore_published_transactions(published)?;
                        return Err(StateStoreError::Invalid(anyhow::Error::new(error)));
                    }
                }
            }
            let mut proofs = Vec::with_capacity(published.len());
            let mut proof_error = None;
            for (_, _, store, published_txn) in &published {
                match store.journal_proof(published_txn) {
                    Ok(proof) => proofs.push(proof),
                    Err(error) => {
                        proof_error = Some(error);
                        break;
                    }
                }
            }
            if let Some(error) = proof_error {
                restore_published_transactions(published)?;
                return Err(StateStoreError::Invalid(anyhow::Error::new(error)));
            }

            let mut candidate = base.clone();
            upsert_account(&mut candidate, record.clone(), now);
            if migration {
                for proof in &proofs {
                    if let Some(reference) = proof.after_ref() {
                        candidate
                            .credential_refs
                            .insert(proof.account_id().to_string(), reference.clone());
                    }
                }
            }
            candidate
                .credential_refs
                .insert(account_id.clone(), target_ref);
            if migration {
                candidate.current_account_id = None;
                candidate.active_profile = None;
                retain_migratable_accounts(&mut candidate, &skipped);
            }

            let receipt = if migration {
                match transaction
                    .migration_commit_permit(proofs)
                    .and_then(|permit| transaction.commit_migration(&candidate, permit))
                {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        restore_published_transactions(published)?;
                        return Err(error);
                    }
                }
            } else {
                match transaction.commit_coordinated(&candidate, proofs) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        restore_published_transactions(published)?;
                        return Err(error);
                    }
                }
            };
            let mut after = transaction.snapshot()?;
            let mut recovery = Vec::new();
            for (_, _, store, published_txn) in published {
                if let Err(error) = store.finalize(published_txn, &receipt) {
                    recovery.push(error.to_string());
                }
            }
            if recovery.is_empty() {
                Ok(MutationResult::Committed {
                    value: record,
                    state: after,
                })
            } else {
                after.recovery_pending = true;
                Ok(MutationResult::CommittedRecoveryPending {
                    value: record,
                    state: after,
                    message: recovery.join("; "),
                })
            }
        })
        .map_err(anyhow::Error::new);
    // 与 legacy 迁移同理：回滚后不得报告"已跳过并保留"，但已经发生的隔离改名
    // 必须如实告诉用户。
    match outcome {
        Ok(value) => {
            report_migration_skips(&reported);
            Ok(value)
        }
        Err(error) => Err(annotate_rollback_quarantine(error, &quarantined)),
    }
}

/// Reject an import that would replace an account's credential with a
/// different credential family.
///
/// 这个检查是纯函数且只读 state：交互式录入路径可以在 prompt secret 之前调用它，
/// 用户不必先把 token 粘贴完才发现自己撞了一个 API key 账号。
pub fn ensure_import_kind_compatible(
    state: &State,
    email: &str,
    incoming: CredentialKind,
) -> Result<()> {
    let email = email.trim();
    let Some(existing) = state
        .accounts
        .iter()
        .find(|account| account.email.eq_ignore_ascii_case(email))
    else {
        return Ok(());
    };
    let incoming_type = account_type_for(incoming);
    if existing.account_type == incoming_type {
        return Ok(());
    }
    // v1 state 里的 email 完全由用户控制，直接内插会破坏项目的 console
    // ASCII-only 约束，也可能夹带控制字符污染终端。
    let existing_email = ascii_console(&existing.email);
    bail!(
        "account '{}' (id {}) already holds a {} credential and cannot be replaced by a {} \
credential. Remove it first with `sagy rm {}`, or import this credential under a different \
--email.",
        existing_email,
        existing.id,
        existing.account_type.as_str(),
        incoming_type.as_str(),
        existing_email
    )
}

/// Fold an arbitrary user-controlled string into printable ASCII.
///
/// 为什么需要它：账号 email 来自用户（v1 state 或 `--email`），而项目要求
/// 控制台输出必须是纯 ASCII。非 ASCII 字符与控制字符一律转成 `\u{...}`
/// 转义，既保持 ASCII 又不丢信息。
///
/// 这是全项目**唯一**的控制台转义出口：任何要把用户提供的字符串打到 stdout /
/// stderr 的地方都必须先过它（AC-R12-4.1），CLI 层通过 `crate::cli` 复用。
pub(crate) fn ascii_console(value: &str) -> String {
    use std::fmt::Write as _;
    let mut rendered = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_graphic() || character == ' ' {
            rendered.push(character);
        } else {
            let _ = write!(rendered, "\\u{{{:04x}}}", character as u32);
        }
    }
    rendered
}

/// Build the API-key credential from the key material alone.
///
/// 为什么不再把 `email` / `project_id` 写进凭据文档：它们会进入 fingerprint，
/// 于是同一把 key 换个 `--email` 或 `--project-id` 就变成第二个账号、第二份明文
/// 副本，而 policy 会把它们当两个候选调度。`--project-id` 对 API key 账号在启动
/// 时本来就是 no-op（launcher 对 ApiKey 不导出 GOOGLE_CLOUD_PROJECT），
/// 所以这里显式告警并忽略，而不是让它静默参与去重指纹。
fn api_key_credential(api_key: &str, project_id: Option<&str>) -> Result<PortableCredential> {
    if let Some(warning) = api_key_project_id_warning(project_id) {
        eprintln!("{warning}");
    }
    PortableCredential::api_key(api_key).map_err(anyhow::Error::new)
}

/// Return the ASCII warning for a `--project-id` that an API-key account
/// cannot use, or `None` when no project id was supplied.
pub fn api_key_project_id_warning(project_id: Option<&str>) -> Option<String> {
    let project_id = project_id
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(format!(
        "warning: --project-id '{project_id}' is ignored for API-key accounts; the API key is \
the complete authentication input. Use an OAuth or Vertex account if you need a project id."
    ))
}

const fn account_type_for(kind: CredentialKind) -> AccountType {
    match kind {
        CredentialKind::OAuthAccessToken | CredentialKind::OAuthAuthorizedUser => {
            AccountType::OAuth
        }
        CredentialKind::ApiKey => AccountType::ApiKey,
        CredentialKind::VertexServiceAccount => AccountType::Vertex,
    }
}

fn restore_published_transactions(
    staged: Vec<(
        String,
        Option<CredentialRef>,
        CredentialStore,
        credential_store::PublishedCredentialTxn,
    )>,
) -> std::result::Result<(), StateStoreError> {
    let mut first_error = None;
    for (_, _, store, stage) in staged.into_iter().rev() {
        if let Err(error) = store.restore(stage) {
            if first_error.is_none() {
                first_error = Some(StateStoreError::Invalid(anyhow::Error::new(error)));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Prepare a credential under the state transaction's sealed capability. The
/// caller must keep the returned staged value alive while it commits the
/// matching State v2 reference, then call publish and finally finalize on the
/// same lock order.
pub(crate) fn prepare_credential_with_permit(
    permit: crate::core::state_store::CredentialMutationPermit,
    credential: &PortableCredential,
    material: &[u8],
) -> Result<(CredentialStore, credential_store::PreparedCredentialTxn)> {
    let store = CredentialStore::from_permit(permit).map_err(anyhow::Error::new)?;
    let staged = store
        .stage_with_material(Uuid::new_v4(), credential, material)
        .map_err(anyhow::Error::new)?;
    Ok((store, staged))
}

fn record_from_credential(
    account_id: &str,
    email: &str,
    credential: &PortableCredential,
    store: &CredentialStore,
    now: i64,
) -> Result<AccountRecord> {
    let (account_type, auth_path, provider_id, plan) = match credential.kind() {
        CredentialKind::OAuthAccessToken => (
            AccountType::OAuth,
            account_token_file(store.account_dir()),
            Some("antigravity-oauth".to_string()),
            Some("Antigravity OAuth".to_string()),
        ),
        CredentialKind::OAuthAuthorizedUser => (
            AccountType::OAuth,
            store.account_dir().join("credentials.json"),
            Some("google".to_string()),
            Some("Antigravity OAuth".to_string()),
        ),
        CredentialKind::ApiKey => (
            AccountType::ApiKey,
            store.account_dir().join("credentials.json"),
            Some("google-ai-studio".to_string()),
            Some("Gemini API Key".to_string()),
        ),
        CredentialKind::VertexServiceAccount => (
            AccountType::Vertex,
            store.account_dir().join("credentials.json"),
            Some("google".to_string()),
            Some("Vertex AI".to_string()),
        ),
    };
    let document = credential.native_document();
    Ok(AccountRecord {
        id: account_id.to_string(),
        email: email.to_string(),
        account_type,
        provider_id,
        project_id: document
            .and_then(|value| value.get("project_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        account_id: document
            .and_then(|value| value.get("account_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        identity_fingerprint: Some(credential.fingerprint()),
        plan,
        auth_path: auth_path.to_string_lossy().into_owned(),
        config_path: None,
        oauth_token: credential.access_token().map(ToString::to_string),
        refresh_token: credential.refresh_token().map(ToString::to_string),
        api_key: credential.api_key_value().map(ToString::to_string),
        added_at: now,
        updated_at: now,
        last_used_at: None,
    })
}

fn preserve_account_metadata(record: &mut AccountRecord, existing: &AccountRecord, now: i64) {
    record.added_at = existing.added_at;
    record.updated_at = now.max(existing.updated_at);
    record.last_used_at = existing.last_used_at;
    record.config_path = existing.config_path.clone();
    if existing
        .provider_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        record.provider_id = existing.provider_id.clone();
    }
}

fn upsert_account(state: &mut State, record: AccountRecord, now: i64) {
    if let Some(existing_idx) = state
        .accounts
        .iter()
        .position(|account| account.id == record.id)
    {
        state.accounts[existing_idx] = record.clone();
    } else {
        state.accounts.push(record.clone());
    }
    if !state.usage_cache.contains_key(&record.id) {
        state.usage_cache.insert(
            record.id.clone(),
            UsageSnapshot {
                plan: record.plan.clone(),
                health: HealthStatus::Unverified,
                last_probe_at: Some(now),
                ..Default::default()
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::antigravity::account::credential_store::MigrationPlanner;

    fn account_of(email: &str, account_type: AccountType) -> AccountRecord {
        AccountRecord {
            id: "acc-1".to_string(),
            email: email.to_string(),
            account_type,
            ..AccountRecord::default()
        }
    }

    #[test]
    fn cross_kind_email_conflict_names_the_conflict_and_the_next_step() {
        let state = State {
            version: 2,
            accounts: vec![account_of("user@example.test", AccountType::ApiKey)],
            ..State::default()
        };
        // AC-4.2: 这个检查是纯读，交互式录入可以在 prompt secret 之前调用它。
        let error = ensure_import_kind_compatible(
            &state,
            "user@example.test",
            CredentialKind::OAuthAccessToken,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("user@example.test"), "{error}");
        assert!(error.contains("acc-1"), "{error}");
        assert!(error.contains("api_key"), "{error}");
        assert!(error.contains("sagy rm user@example.test"), "{error}");
        assert!(error.is_ascii(), "{error}");

        assert!(
            ensure_import_kind_compatible(&state, "user@example.test", CredentialKind::ApiKey)
                .is_ok()
        );
        assert!(
            ensure_import_kind_compatible(
                &state,
                "other@example.test",
                CredentialKind::OAuthAccessToken
            )
            .is_ok()
        );
    }

    #[test]
    fn api_key_credential_ignores_email_and_project_id() {
        // AC-2/AC-3: 同一把 key 无论配什么 email / project-id，凭据材料与指纹都必须相同。
        let plain = api_key_credential("shared-key", None).unwrap();
        let with_project = api_key_credential("shared-key", Some("proj-a")).unwrap();
        assert_eq!(plain, with_project);
        assert_eq!(plain.fingerprint(), with_project.fingerprint());
        assert_eq!(
            credential_material(&plain).unwrap(),
            credential_material(&with_project).unwrap()
        );
        assert!(plain.native_document().unwrap().get("email").is_none());
        assert!(plain.native_document().unwrap().get("project_id").is_none());

        let warning = api_key_project_id_warning(Some("proj-a")).expect("warning");
        assert!(warning.is_ascii(), "{warning}");
        assert!(warning.contains("proj-a"), "{warning}");
        assert!(warning.contains("ignored"), "{warning}");
        assert!(api_key_project_id_warning(None).is_none());
        assert!(api_key_project_id_warning(Some("  ")).is_none());
    }

    use crate::core::state::{CredentialRefKind, State};
    use crate::core::state_store::RevisionGeneration;
    use fs2::FileExt;
    use sha2::{Digest, Sha256};
    use std::fs::{self, OpenOptions};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_is_valid_oauth_credential() {
        let valid_oauth = serde_json::json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "access_token": "ya29.sample",
            "refresh_token": "1//sample",
            "token_uri": "https://oauth2.googleapis.com/token"
        });
        assert!(is_valid_oauth_credential(&valid_oauth));

        let google_accounts_json = serde_json::json!({
            "active": "user@gmail.com",
            "old": []
        });
        assert!(!is_valid_oauth_credential(&google_accounts_json));

        let random_json = serde_json::json!({
            "foo": "bar"
        });
        assert!(!is_valid_oauth_credential(&random_json));
    }

    #[test]
    fn test_is_valid_api_key_credential() {
        let valid_api = serde_json::json!({
            "api_key": "AIzaSySampleKey123"
        });
        assert!(is_valid_api_key_credential(&valid_api));

        let invalid_api = serde_json::json!({
            "api_key": "   "
        });
        assert!(!is_valid_api_key_credential(&invalid_api));
    }

    #[test]
    fn test_import_auth_path_rejects_google_accounts_json() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();
        let ga_file = state_dir.join("google_accounts.json");
        fs::write(&ga_file, r#"{"active":"test@gmail.com","old":[]}"#).expect("write ga");

        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let result = adapter.import_auth_path(state_dir, &mut state, &ga_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_fingerprint_deduplication() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();

        let raw_token = "eyJh.sample_jwt_payload_1.sig";
        let rec1 = adapter
            .import_or_update_token(state_dir, &mut state, "acc1@gmail.com", raw_token, None)
            .unwrap();
        assert_eq!(state.accounts.len(), 1);

        // Import same token with different email -> deduplicates to same account ID
        let rec2 = adapter
            .import_or_update_token(state_dir, &mut state, "acc2@gmail.com", raw_token, None)
            .unwrap();
        assert_eq!(state.accounts.len(), 1);
        assert_eq!(rec1.id, rec2.id);
    }

    #[test]
    fn api_key_import_rejects_blank_and_deduplicates_exact_material() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        assert!(
            adapter
                .import_or_update_api_key(
                    temp_dir.path(),
                    &mut state,
                    "   ",
                    "user@example.com",
                    None,
                )
                .is_err()
        );
        let first = adapter
            .import_or_update_api_key(
                temp_dir.path(),
                &mut state,
                "api-key-1",
                "user@example.com",
                Some("project-a"),
            )
            .unwrap();
        let second = adapter
            .import_or_update_api_key(
                temp_dir.path(),
                &mut state,
                "api-key-1",
                "user@example.com",
                Some("project-a"),
            )
            .unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(state.accounts.len(), 1);
    }

    #[test]
    fn missing_store_bootstraps_empty_v2_and_ignores_stale_caller_state() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut caller = State {
            accounts: vec![AccountRecord {
                id: "stale-account".to_string(),
                email: "stale@example.com".to_string(),
                ..Default::default()
            }],
            current_account_id: Some("stale-account".to_string()),
            ..State::default()
        };
        let imported = adapter
            .import_or_update_token(
                &state_dir,
                &mut caller,
                "fresh@example.com",
                "fresh-token",
                None,
            )
            .expect("import into missing store");
        assert_eq!(caller.version, 2);
        assert_eq!(caller.accounts.len(), 1);
        assert_eq!(caller.accounts[0].id, imported.id);
        assert_ne!(caller.accounts[0].id, "stale-account");
        assert_eq!(caller.current_account_id, None);
        assert!(state_dir.join("state.json").is_file());
    }

    #[test]
    fn session_mutations_advance_one_state_session_owner() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut session = StateSession::open(&state_dir).expect("open missing session");
        let first = adapter
            .import_or_update_token_session(
                &state_dir,
                &mut session,
                "session@example.com",
                "session-token-1",
                None,
            )
            .expect("first session import");
        assert_eq!(session.state().accounts.len(), 1);
        assert_eq!(session.revision(), &first.state().revision);
        let second = adapter
            .import_or_update_token_session(
                &state_dir,
                &mut session,
                "session@example.com",
                "session-token-2",
                None,
            )
            .expect("second session import");
        assert_eq!(session.state().accounts.len(), 1);
        assert_eq!(session.revision(), &second.state().revision);
        assert_ne!(first.state().revision, second.state().revision);
    }

    #[test]
    fn importing_new_account_stays_inactive_and_preserves_current_profile() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let antigravity_path = temp.path().join("ag");
        let gemini_path = temp.path().join("gemini");
        fs::create_dir_all(&antigravity_path).expect("create antigravity root");
        fs::create_dir_all(&gemini_path).expect("create gemini root");
        let roots = (
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&antigravity_path)
                .expect("normalize antigravity root"),
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&gemini_path)
                .expect("normalize gemini root"),
        );
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let current = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "current@example.com",
                "current-token",
                None,
            )
            .expect("import current account");
        let activated = adapter
            .switch_account_transaction_with_roots(
                &state_dir,
                &current.id,
                ActiveHomeAdoption::Strict,
                roots.clone(),
            )
            .expect("activate current account");
        state = activated.state().state.clone();
        let before_profile = state
            .active_profile
            .clone()
            .expect("current profile after activation");
        let before_token = fs::read(antigravity_path.join("antigravity-oauth-token"))
            .expect("active token after activation");

        let imported = adapter
            .import_or_update_token(&state_dir, &mut state, "new@example.com", "new-token", None)
            .expect("import inactive account");
        assert_ne!(imported.id, current.id);
        assert_eq!(
            state.current_account_id.as_deref(),
            Some(current.id.as_str())
        );
        assert_eq!(state.active_profile, Some(before_profile));
        assert!(
            state
                .accounts
                .iter()
                .any(|account| account.id == imported.id)
        );
        assert_eq!(
            fs::read(antigravity_path.join("antigravity-oauth-token"))
                .expect("active token after inactive import"),
            before_token
        );
    }

    #[test]
    fn import_accepts_raw_portable_and_native_credentials() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let raw = temp.path().join("token.txt");
        fs::write(&raw, "raw-token\n").expect("write raw token");
        let raw_record = adapter
            .import_auth_path(&state_dir, &mut State::default(), &raw)
            .expect("import raw token");
        assert!(raw_record.auth_path.ends_with("antigravity-oauth-token"));

        let portable = temp.path().join("portable.json");
        let portable_bytes = PortableCredential::oauth_access_token("portable-token")
            .unwrap()
            .to_json_string()
            .unwrap();
        fs::write(&portable, portable_bytes).expect("write portable credential");
        let portable_record = adapter
            .import_auth_path(&state_dir, &mut State::default(), &portable)
            .expect("import portable credential");
        assert!(
            portable_record
                .auth_path
                .ends_with("antigravity-oauth-token")
        );

        let native = temp.path().join("authorized.json");
        fs::write(
            &native,
            r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","token_uri":"https://oauth2.googleapis.com/token","unknown":"keep"}"#,
        )
        .expect("write native credential");
        let native_record = adapter
            .import_auth_path(&state_dir, &mut State::default(), &native)
            .expect("import native credential");
        assert!(native_record.auth_path.ends_with("credentials.json"));
        assert_eq!(native_record.refresh_token.as_deref(), Some("r"));
    }

    #[test]
    fn raw_import_then_authorized_merge_retains_refresh_and_unknown_fields() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let raw = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "user@example.com",
                "raw-access",
                None,
            )
            .expect("raw import");
        let authorized_path = temp.path().join("authorized.json");
        fs::write(
            &authorized_path,
            r#"{"type":"authorized_user","email":"user@example.com","client_id":"client","client_secret":"secret","refresh_token":"refresh","token_uri":"https://oauth2.googleapis.com/token","unknown":"keep"}"#,
        )
        .expect("write authorized credential");
        let merged = adapter
            .import_auth_path(&state_dir, &mut state, &authorized_path)
            .expect("authorized merge");
        assert_eq!(raw.id, merged.id);
        assert_eq!(state.accounts.len(), 1);
        assert_eq!(merged.refresh_token.as_deref(), Some("refresh"));
        let bytes = fs::read(
            state_dir
                .join("accounts")
                .join(&merged.id)
                .join("credentials.json"),
        )
        .expect("read merged credential");
        let document: Value = serde_json::from_slice(&bytes).expect("parse merged credential");
        assert_eq!(
            document.get("access_token").and_then(Value::as_str),
            Some("raw-access")
        );
        assert_eq!(
            document.get("unknown").and_then(Value::as_str),
            Some("keep")
        );
        let restarted = StateStore::read_from_path(&state_dir).expect("reload state after restart");
        let persisted = restarted
            .state
            .accounts
            .iter()
            .find(|account| account.id == merged.id)
            .expect("persisted merged account");
        assert_eq!(persisted.id, merged.id);
        let persisted_ref = restarted
            .state
            .credential_refs
            .get(&merged.id)
            .expect("persisted credential ref");
        let persisted_credential = CredentialStore::new(&state_dir, &merged.id)
            .expect("open persisted credential store")
            .read(persisted_ref)
            .expect("read persisted credential after restart");
        assert_eq!(
            persisted_credential.credential.refresh_token(),
            Some("refresh")
        );
        let mut restarted_state = restarted.state.clone();
        let resumed = adapter
            .import_or_update_token(
                &state_dir,
                &mut restarted_state,
                "user@example.com",
                "raw-access",
                None,
            )
            .expect("resume raw token import after restart");
        assert_eq!(resumed.refresh_token.as_deref(), Some("refresh"));
    }

    #[test]
    fn legacy_import_publishes_all_journals_before_sealed_migration_commit() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let account_dir = state_dir.join("accounts").join("a-1");
        fs::create_dir_all(&account_dir).expect("create legacy account directory");
        fs::write(
            account_dir.join("credentials.json"),
            r#"{"type":"authorized_user","email":"legacy@example.com","client_id":"client","client_secret":"secret","refresh_token":"refresh","token_uri":"https://oauth2.googleapis.com/token","access_token":"old-access","unknown":"keep"}"#,
        )
        .expect("write legacy credential");
        fs::write(
            state_dir.join("state.json"),
            r#"{"version":1,"accounts":[{"id":"a-1","email":"legacy@example.com","account_type":"oauth","oauth_token":"old-access"}],"usage_cache":{},"current_account_id":"a-1"}"#,
        )
        .expect("write legacy state");

        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut caller_state = State::default();
        let record = adapter
            .import_or_update_token(
                &state_dir,
                &mut caller_state,
                "legacy@example.com",
                "new-access",
                None,
            )
            .expect("legacy migration import");
        assert_eq!(record.id, "a-1");
        assert_eq!(caller_state.version, 2);
        assert_eq!(caller_state.accounts.len(), 1);
        assert_eq!(caller_state.current_account_id, None);
        assert_eq!(caller_state.active_profile, None);
        let disk = StateStore::read_from_path(&state_dir).expect("read migrated state");
        assert_eq!(disk.revision.generation, RevisionGeneration::Current(1));
        let bytes = fs::read(account_dir.join("credentials.json")).expect("read migrated doc");
        let document: Value = serde_json::from_slice(&bytes).expect("parse migrated doc");
        assert_eq!(
            document.get("access_token").and_then(Value::as_str),
            Some("new-access")
        );
        assert_eq!(
            document.get("unknown").and_then(Value::as_str),
            Some("keep")
        );
        assert_eq!(
            document.get("refresh_token").and_then(Value::as_str),
            Some("refresh")
        );
    }

    #[test]
    fn explicit_legacy_migration_session_needs_no_new_credential() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let account_dir = state_dir.join("accounts").join("legacy-only");
        fs::create_dir_all(&account_dir).expect("create legacy account directory");
        fs::write(
            account_dir.join("credentials.json"),
            r#"{"type":"authorized_user","email":"legacy-only@example.com","client_id":"client","client_secret":"secret","refresh_token":"refresh-only","access_token":"old-access","token_uri":"https://oauth2.googleapis.com/token"}"#,
        )
        .expect("write legacy credential");
        fs::write(
            state_dir.join("state.json"),
            r#"{"version":1,"accounts":[{"id":"legacy-only","email":"legacy-only@example.com","account_type":"oauth","oauth_token":"old-access"}],"usage_cache":{},"current_account_id":"legacy-only"}"#,
        )
        .expect("write legacy state");

        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut session = StateSession::open(&state_dir).expect("open legacy session");
        let outcome = adapter
            .migrate_legacy_state_transaction(&state_dir, &mut session)
            .expect("migrate legacy state without import");
        assert!(!outcome.recovery_pending());
        assert_eq!(session.state().version, 2);
        assert_eq!(session.state().current_account_id, None);
        assert_eq!(session.state().active_profile, None);
        assert_eq!(
            session
                .state()
                .credential_refs
                .get("legacy-only")
                .map(|reference| reference.kind),
            Some(CredentialRefKind::OauthAuthorizedUser)
        );
        let bytes = fs::read(account_dir.join("credentials.json"))
            .expect("read migrated legacy credential");
        let document: Value = serde_json::from_slice(&bytes).expect("parse migrated credential");
        assert_eq!(
            document.get("refresh_token").and_then(Value::as_str),
            Some("refresh-only")
        );
        assert_eq!(
            document.get("access_token").and_then(Value::as_str),
            Some("old-access")
        );
    }

    /// AC-R12-1.1 / AC-R12-1.2: 隔离改名已经发生、迁移事务却整笔回滚时，
    /// 用户必须能看到磁盘上到底动了哪些文件。
    ///
    /// 构造方式：两个都无法迁移的账号。第一个正常隔离（credentials.json 被改
    /// 名），第二个把 17 个隔离候选名全部占满，于是 `quarantine_destination`
    /// 抛 Conflict，整笔迁移回滚——第一个账号的改名不会被撤销。
    #[test]
    fn a_rolled_back_migration_reports_the_quarantine_renames_it_left_on_disk() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        for account_id in ["broken-a", "broken-b"] {
            let account_dir = state_dir.join("accounts").join(account_id);
            fs::create_dir_all(&account_dir).expect("create legacy account directory");
            // account_type 是 oauth，但文件里是 api key -> 迁移只能跳过 + 隔离。
            fs::write(
                account_dir.join("credentials.json"),
                br#"{"api_key":"wrong-kind-key"}"#,
            )
            .expect("write legacy credential");
        }
        // 把 broken-b 的隔离候选名占满。
        let blocked = state_dir.join("accounts").join("broken-b");
        fs::write(
            blocked.join(".sagy-credential-quarantine.credentials.json"),
            b"an-earlier-attempt",
        )
        .expect("write blocker");
        for index in 1..=16 {
            fs::write(
                blocked.join(format!(
                    ".sagy-credential-quarantine.{index}.credentials.json"
                )),
                b"an-earlier-attempt",
            )
            .expect("write blocker");
        }
        fs::write(
            state_dir.join("state.json"),
            br#"{"version":1,"accounts":[{"id":"broken-a","email":"a@example.test","account_type":"oauth"},{"id":"broken-b","email":"b@example.test","account_type":"oauth"}],"usage_cache":{},"current_account_id":null}"#,
        )
        .expect("write legacy state");

        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut session = StateSession::open(&state_dir).expect("open legacy session");
        let error = adapter
            .migrate_legacy_state_transaction(&state_dir, &mut session)
            .expect_err("an unquarantinable account must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.is_ascii(),
            "console output must be ASCII: {message}"
        );

        // 改名真的发生了，而且没有被撤销——所以它必须出现在错误里。
        let moved = state_dir
            .join("accounts")
            .join("broken-a")
            .join(".sagy-credential-quarantine.credentials.json");
        assert!(moved.is_file(), "broken-a was not quarantined at all");
        assert!(
            !state_dir
                .join("accounts")
                .join("broken-a")
                .join("credentials.json")
                .exists(),
            "the quarantine rename did not happen, so this test proves nothing"
        );
        assert!(
            message.contains("accounts/broken-a/.sagy-credential-quarantine.credentials.json"),
            "a rolled-back migration hid the quarantine rename it left behind: {message}"
        );
        assert!(
            message.contains("rolled back"),
            "the notice must say the migration rolled back: {message}"
        );

        // 事务确实回滚了：磁盘上还是 v1。
        let disk: Value = serde_json::from_slice(
            &fs::read(state_dir.join("state.json")).expect("read state after rollback"),
        )
        .expect("parse state after rollback");
        assert_eq!(disk["version"], serde_json::json!(1));
    }

    /// 没有发生任何隔离改名时，错误必须原样透传，不得凭空多出一段提示。
    #[test]
    fn a_rollback_without_quarantine_leaves_the_error_untouched() {
        let error = anyhow!("original failure");
        let annotated = annotate_rollback_quarantine(error, &[]);
        assert_eq!(format!("{annotated:#}"), "original failure");
    }

    #[test]
    fn import_rejects_blank_ambiguous_and_incomplete_credentials() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        for (name, bytes) in [
            ("blank", b"   \n".as_slice()),
            (
                "ambiguous",
                br#"{"api_key":"key","access_token":"other"}"#.as_slice(),
            ),
            (
                "incomplete",
                br#"{"type":"authorized_user","client_id":"c"}"#.as_slice(),
            ),
        ] {
            let path = temp.path().join(name);
            fs::write(&path, bytes).expect("write invalid credential");
            assert!(
                adapter
                    .import_auth_path(&state_dir, &mut State::default(), &path)
                    .is_err()
            );
        }
    }

    #[test]
    fn migration_reads_only_fixed_layout_and_folds_raw_access_token() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let account_dir = state_dir.join("accounts").join("a-1");
        fs::create_dir_all(&account_dir).expect("create account dir");
        fs::write(
            account_dir.join("credentials.json"),
            r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","token_uri":"https://oauth2.googleapis.com/token"}"#,
        )
        .expect("write authorized credential");
        fs::write(account_dir.join("antigravity-oauth-token"), "new-access")
            .expect("write raw access token");

        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"this must never be read").expect("write outside marker");
        let state = State {
            accounts: vec![AccountRecord {
                id: "a-1".to_string(),
                account_type: AccountType::OAuth,
                auth_path: outside.to_string_lossy().into_owned(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let plan = MigrationPlanner::plan(&state_dir, &state).expect("plan migration");
        assert_eq!(plan.entries.len(), 1);
        let credential = &plan.entries[0].credential;
        assert_eq!(credential.access_token(), Some("new-access"));
        assert_eq!(credential.refresh_token(), Some("r"));
        assert_eq!(
            plan.entries[0].credential_ref.kind,
            CredentialRefKind::OauthAuthorizedUser
        );
        assert!(outside.exists());
    }

    #[test]
    fn migration_rejects_isolated_refresh_token() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let state = State {
            accounts: vec![AccountRecord {
                id: "a-1".to_string(),
                account_type: AccountType::OAuth,
                refresh_token: Some("refresh-only".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        // 语义未放宽：孤立 refresh token 仍然不会被当作可用凭据迁移。变化在于它现在
        // 被记录成 skip 而不是让整笔迁移失败，否则一个坏账号会锁死所有命令。
        let plan = MigrationPlanner::plan(&state_dir, &state).expect("plan must not abort");
        assert!(plan.entries.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert_eq!(plan.skipped[0].account_id, "a-1");
        assert!(plan.skipped[0].reason.is_ascii());
        assert!(!plan.skipped[0].reason.is_empty());
        assert!(!state_dir.exists());
    }

    #[test]
    fn switch_transaction_covers_all_four_credential_targets_and_delete() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(temp.path().join("ag")).expect("create antigravity root");
        fs::create_dir_all(temp.path().join("gemini")).expect("create gemini root");
        let antigravity_root =
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&temp.path().join("ag"))
                .expect("normalize antigravity root");
        let gemini_root =
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&temp.path().join("gemini"))
                .expect("normalize gemini root");
        let roots = (antigravity_root, gemini_root);
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();

        let raw = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "raw@example.com",
                "raw-switch-token",
                None,
            )
            .expect("import raw account");
        let authorized_path = temp.path().join("authorized.json");
        fs::write(
            &authorized_path,
            r#"{"type":"authorized_user","email":"authorized@example.com","client_id":"client","client_secret":"secret","refresh_token":"refresh","access_token":"authorized-access","token_uri":"https://oauth2.googleapis.com/token"}"#,
        )
        .expect("write authorized credential");
        let authorized = adapter
            .import_auth_path(&state_dir, &mut state, &authorized_path)
            .expect("import authorized account");
        let api = adapter
            .import_or_update_api_key(
                &state_dir,
                &mut state,
                "api-switch-key",
                "api@example.com",
                Some("project-a"),
            )
            .expect("import api account");
        let vertex_path = temp.path().join("vertex.json");
        fs::write(
            &vertex_path,
            r#"{"type":"service_account","project_id":"vertex-project","private_key_id":"key-id","private_key":"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n","client_email":"vertex@example.com","client_id":"123","auth_uri":"https://accounts.example.test/o/oauth2/auth","token_uri":"https://oauth2.example.test/token","auth_provider_x509_cert_url":"https://www.example.test/cert","client_x509_cert_url":"https://www.example.test/client-cert"}"#,
        )
        .expect("write vertex credential");
        let vertex = adapter
            .import_auth_path(&state_dir, &mut state, &vertex_path)
            .expect("import vertex account");

        for (account, expected_kind) in [
            (&raw, CredentialRefKind::OauthAccessToken),
            (&authorized, CredentialRefKind::OauthAuthorizedUser),
            (&api, CredentialRefKind::ApiKey),
            (&vertex, CredentialRefKind::VertexServiceAccount),
        ] {
            assert_eq!(
                state
                    .credential_refs
                    .get(&account.id)
                    .map(|reference| reference.kind),
                Some(expected_kind)
            );
        }

        let matrix = [&raw, &authorized, &api, &vertex];
        for from in matrix {
            let activated = adapter
                .switch_account_transaction_with_roots(
                    &state_dir,
                    &from.id,
                    ActiveHomeAdoption::Strict,
                    roots.clone(),
                )
                .expect("activate matrix source");
            assert!(!activated.recovery_pending());
            state = activated.state().state.clone();
            assert_active_layout(&state, from, &roots);
            for to in matrix {
                let outcome = adapter
                    .switch_account_transaction_with_roots(
                        &state_dir,
                        &to.id,
                        ActiveHomeAdoption::Strict,
                        roots.clone(),
                    )
                    .expect("switch account matrix cell");
                assert!(!outcome.recovery_pending());
                state = outcome.state().state.clone();
                assert_eq!(state.current_account_id.as_deref(), Some(to.id.as_str()));
                assert_eq!(
                    state
                        .active_profile
                        .as_ref()
                        .map(|profile| &profile.account_id),
                    Some(&to.id)
                );
                assert_active_layout(&state, to, &roots);
            }
        }

        let _raw_active = adapter
            .switch_account_transaction_with_roots(
                &state_dir,
                &raw.id,
                ActiveHomeAdoption::Strict,
                roots.clone(),
            )
            .expect("activate raw before non-current delete");
        let noncurrent_delete = adapter
            .remove_account_transaction_with_roots(&state_dir, &api.id, roots.clone())
            .expect("delete non-current account");
        assert!(!noncurrent_delete.recovery_pending());
        state = noncurrent_delete.state().state.clone();
        assert!(!state.accounts.iter().any(|account| account.id == api.id));
        assert_eq!(state.current_account_id.as_deref(), Some(raw.id.as_str()));

        let raw_delete = adapter
            .remove_account_transaction_with_roots(&state_dir, &raw.id, roots.clone())
            .expect("delete current raw account");
        assert!(!raw_delete.recovery_pending());
        state = raw_delete.state().state.clone();
        assert_eq!(state.current_account_id, None);
        assert_eq!(state.active_profile, None);
        let active_token = temp.path().join("ag").join("antigravity-oauth-token");
        let active_document = temp.path().join("gemini").join("oauth_creds.json");
        assert!(!active_token.exists());
        assert!(!active_document.exists());

        let _auth_active = adapter
            .switch_account_transaction_with_roots(
                &state_dir,
                &authorized.id,
                ActiveHomeAdoption::Strict,
                roots.clone(),
            )
            .expect("activate authorized before delete");
        let auth_delete = adapter
            .remove_account_transaction_with_roots(&state_dir, &authorized.id, roots.clone())
            .expect("delete current authorized account");
        assert!(!auth_delete.recovery_pending());
        state = auth_delete.state().state.clone();
        assert_eq!(state.current_account_id, None);
        assert_eq!(state.active_profile, None);
        assert!(!active_token.exists());
        assert!(!active_document.exists());

        let _vertex_active = adapter
            .switch_account_transaction_with_roots(
                &state_dir,
                &vertex.id,
                ActiveHomeAdoption::Strict,
                roots.clone(),
            )
            .expect("activate vertex before delete");
        let vertex_delete = adapter
            .remove_account_transaction_with_roots(&state_dir, &vertex.id, roots)
            .expect("delete current vertex account");
        assert!(!vertex_delete.recovery_pending());
        state = vertex_delete.state().state.clone();
        assert_eq!(state.current_account_id, None);
        assert_eq!(state.active_profile, None);
        assert!(!state.accounts.iter().any(|account| account.id == vertex.id));
        assert!(!active_token.exists());
        assert!(!active_document.exists());
    }

    #[test]
    fn switch_waits_for_external_credential_lock_and_succeeds_after_release() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let antigravity_path = temp.path().join("ag");
        let gemini_path = temp.path().join("gemini");
        fs::create_dir_all(&antigravity_path).expect("create antigravity root");
        fs::create_dir_all(&gemini_path).expect("create gemini root");
        let roots = (
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&antigravity_path)
                .expect("normalize antigravity root"),
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&gemini_path)
                .expect("normalize gemini root"),
        );
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let account = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "lease@example.com",
                "lease-original-token",
                None,
            )
            .expect("import account");
        let account_dir = state_dir.join("accounts").join(&account.id);
        let lock_path = account_dir.join(".sagy-credential.lock");

        let external_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open credential lock");
        external_lock
            .lock_exclusive()
            .expect("hold external credential lock");

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let switch_state_dir = state_dir.clone();
        let switch_account_id = account.id.clone();
        let switch_roots = roots.clone();
        let switch_thread = thread::spawn(move || {
            started_tx.send(()).expect("signal switch start");
            let result = adapter.switch_account_transaction_with_roots(
                &switch_state_dir,
                &switch_account_id,
                ActiveHomeAdoption::Strict,
                switch_roots,
            );
            done_tx.send(result.is_ok()).expect("signal switch result");
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("switch thread started");

        // The switch must still be waiting on the account credential lease;
        // state and both active-home slots therefore remain untouched.
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(
            StateStore::read_from_path(&state_dir)
                .expect("read unchanged state")
                .state
                .current_account_id,
            None
        );
        assert!(!antigravity_path.join("antigravity-oauth-token").exists());
        assert!(!gemini_path.join("oauth_creds.json").exists());

        external_lock.unlock().expect("release credential lock");
        drop(external_lock);
        assert!(
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("switch result")
        );
        switch_thread.join().expect("join switch thread");

        let activated = StateStore::read_from_path(&state_dir).expect("read final state");
        assert_eq!(
            activated.state.current_account_id.as_deref(),
            Some(account.id.as_str())
        );
        assert_eq!(
            fs::read(antigravity_path.join("antigravity-oauth-token"))
                .expect("read activated token"),
            b"lease-original-token"
        );
        assert!(!gemini_path.join("oauth_creds.json").exists());
    }

    #[test]
    fn switch_rejects_replaced_credential_after_lease_release() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let antigravity_path = temp.path().join("ag");
        let gemini_path = temp.path().join("gemini");
        fs::create_dir_all(&antigravity_path).expect("create antigravity root");
        fs::create_dir_all(&gemini_path).expect("create gemini root");
        let roots = (
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&antigravity_path)
                .expect("normalize antigravity root"),
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&gemini_path)
                .expect("normalize gemini root"),
        );
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let account = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "replacement@example.com",
                "replacement-original-token",
                None,
            )
            .expect("import account");
        let account_dir = state_dir.join("accounts").join(&account.id);
        let lock_path = account_dir.join(".sagy-credential.lock");
        let token_path = account_dir.join("antigravity-oauth-token");
        let external_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open credential lock");
        external_lock
            .lock_exclusive()
            .expect("hold external credential lock");

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let switch_state_dir = state_dir.clone();
        let switch_account_id = account.id.clone();
        let switch_roots = roots.clone();
        let switch_thread = thread::spawn(move || {
            started_tx.send(()).expect("signal switch start");
            let result = adapter.switch_account_transaction_with_roots(
                &switch_state_dir,
                &switch_account_id,
                ActiveHomeAdoption::Strict,
                switch_roots,
            );
            done_tx.send(result.is_ok()).expect("signal switch result");
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("switch thread started");
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(
            StateStore::read_from_path(&state_dir)
                .expect("read unchanged state")
                .state
                .current_account_id,
            None
        );
        assert!(!antigravity_path.join("antigravity-oauth-token").exists());
        assert!(!gemini_path.join("oauth_creds.json").exists());

        // An external writer that ignores the lock cannot make a different
        // valid material satisfy the sealed State credential reference.
        fs::write(&token_path, b"replacement-new-token").expect("replace credential");
        external_lock.unlock().expect("release credential lock");
        drop(external_lock);
        assert!(
            !done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("switch result")
        );
        switch_thread.join().expect("join switch thread");

        let unchanged = StateStore::read_from_path(&state_dir).expect("read final state");
        assert_eq!(unchanged.state.current_account_id, None);
        assert!(unchanged.state.active_profile.is_none());
        assert!(!antigravity_path.join("antigravity-oauth-token").exists());
        assert!(!gemini_path.join("oauth_creds.json").exists());
    }

    #[test]
    fn strict_switch_rejects_unmanaged_first_home_and_adopt_is_explicit() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let ag_path = temp.path().join("ag");
        let gemini_path = temp.path().join("gemini");
        fs::create_dir_all(&ag_path).expect("create antigravity root");
        fs::create_dir_all(&gemini_path).expect("create gemini root");
        let roots = (
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&ag_path)
                .expect("normalize antigravity root"),
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&gemini_path)
                .expect("normalize gemini root"),
        );
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let account = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "adopt@example.com",
                "adopt-token",
                None,
            )
            .expect("import adopt account");
        fs::write(ag_path.join("antigravity-oauth-token"), b"unmanaged-token")
            .expect("write unmanaged token");
        assert!(
            adapter
                .switch_account_transaction_with_roots(
                    &state_dir,
                    &account.id,
                    ActiveHomeAdoption::Strict,
                    roots.clone(),
                )
                .is_err()
        );
        assert_eq!(state.current_account_id, None);
        assert_eq!(
            fs::read(ag_path.join("antigravity-oauth-token")).expect("read unmanaged token"),
            b"unmanaged-token"
        );

        // Replacing the unmanaged slot with exact target material permits an
        // explicit adopt without taking ownership of another layout.
        fs::write(ag_path.join("antigravity-oauth-token"), b"adopt-token")
            .expect("write adoptable token");
        let adopted = adapter
            .switch_account_transaction_with_roots(
                &state_dir,
                &account.id,
                ActiveHomeAdoption::Adopt,
                roots,
            )
            .expect("explicit adopt");
        assert_eq!(
            adopted.state().state.current_account_id.as_deref(),
            Some(account.id.as_str())
        );
    }

    fn assert_active_layout(
        state: &State,
        account: &AccountRecord,
        roots: &(
            crate::core::atomic_io::NormalizedStoreRoot,
            crate::core::atomic_io::NormalizedStoreRoot,
        ),
    ) {
        let profile = state
            .active_profile
            .as_ref()
            .expect("matrix switch has active profile");
        assert_eq!(profile.account_id, account.id);
        let token_path = roots.0.as_path().join("antigravity-oauth-token");
        let document_path = roots.1.as_path().join("oauth_creds.json");
        let token = fs::read(&token_path).ok();
        let document = fs::read(&document_path).ok();
        match state
            .credential_refs
            .get(&account.id)
            .expect("matrix account ref")
            .kind
        {
            CredentialRefKind::OauthAccessToken => {
                let bytes = token.expect("raw target token slot");
                assert!(document.is_none(), "raw target must clear document slot");
                assert_eq!(
                    profile.managed_layout.antigravity_token,
                    SlotState::Exact {
                        sha256: digest_bytes(&bytes)
                    }
                );
                assert!(matches!(
                    profile.managed_layout.gemini_authorized_user,
                    SlotState::Absent
                ));
            }
            CredentialRefKind::OauthAuthorizedUser => {
                let bytes = document.expect("authorized target document slot");
                assert!(token.is_none(), "authorized target must clear token slot");
                assert_eq!(
                    profile.managed_layout.gemini_authorized_user,
                    SlotState::Exact {
                        sha256: digest_bytes(&bytes)
                    }
                );
                assert!(matches!(
                    profile.managed_layout.antigravity_token,
                    SlotState::Absent
                ));
            }
            CredentialRefKind::ApiKey | CredentialRefKind::VertexServiceAccount => {
                assert!(token.is_none(), "non-OAuth target must clear token slot");
                assert!(
                    document.is_none(),
                    "non-OAuth target must clear document slot"
                );
                assert_eq!(profile.managed_layout, ManagedLayout::default());
            }
        }
    }

    fn digest_bytes(bytes: &[u8]) -> String {
        let mut digest = Sha256::new();
        digest.update(bytes);
        format!("{:x}", digest.finalize())
    }

    #[test]
    fn active_home_restart_recovery_rolls_back_precommit_and_finalizes_postcommit() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(temp.path().join("ag")).expect("create antigravity root");
        fs::create_dir_all(temp.path().join("gemini")).expect("create gemini root");
        let antigravity_root =
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&temp.path().join("ag"))
                .expect("normalize antigravity root");
        let gemini_root =
            crate::core::atomic_io::NormalizedStoreRoot::normalize(&temp.path().join("gemini"))
                .expect("normalize gemini root");
        let roots = (antigravity_root, gemini_root);
        let adapter = crate::adapters::antigravity::AntigravityAdapter;
        let mut state = State::default();
        let account = adapter
            .import_or_update_token(
                &state_dir,
                &mut state,
                "recovery@example.com",
                "recovery-token",
                None,
            )
            .expect("import recovery account");
        let reference = state
            .credential_refs
            .get(&account.id)
            .cloned()
            .expect("recovery credential ref");
        let stored = CredentialStore::new(&state_dir, &account.id)
            .expect("open recovery credential store")
            .read(&reference)
            .expect("read recovery credential");
        let profile = active_profile_for_reference(
            &account.id,
            &reference,
            &stored.material_digest,
            &roots.0,
            &roots.1,
        );

        // Publish without the State commit. Restart recovery must use the
        // current State proof and restore the before layout.
        let store = StateStore::open(&state_dir).expect("open state store");
        let snapshot = store.read().expect("read state");
        store
            .with_locked_exact(&snapshot.revision, |transaction| {
                let permit = transaction
                    .active_home_mutation_permit_with_ref(
                        Some(profile.clone()),
                        Some(reference.clone()),
                    )
                    .map_err(anyhow::Error::new)
                    .map_err(StateStoreError::Invalid)?;
                let home_store = ActiveHomeStore::from_permit_with_roots(
                    permit,
                    roots.0.clone(),
                    roots.1.clone(),
                )
                .map_err(StateStoreError::Invalid)?;
                let prepared =
                    prepare_active_home(home_store, Uuid::new_v4(), ActiveHomeAdoption::Strict)
                        .map_err(StateStoreError::Invalid)?;
                let _published = publish_active_home(prepared).map_err(StateStoreError::Invalid)?;
                Ok(())
            })
            .expect("publish precommit active-home journal");
        assert!(roots.0.as_path().join("antigravity-oauth-token").exists());

        let mut recovery_session = StateSession::open(&state_dir).expect("open recovery session");
        recover_active_home_journals(&state_dir, &mut recovery_session, Some(roots.clone()))
            .expect("rollback precommit active-home journal");
        assert!(!roots.0.as_path().join("antigravity-oauth-token").exists());
        assert!(!active_journal_exists(&state_dir, &account.id));

        // Commit a second published journal but deliberately skip finalize.
        let store = StateStore::open(&state_dir).expect("reopen state store");
        let snapshot = store.read().expect("read rollback state");
        store
            .with_locked_exact(&snapshot.revision, |transaction| {
                let permit = transaction
                    .active_home_mutation_permit_with_ref(
                        Some(profile.clone()),
                        Some(reference.clone()),
                    )
                    .map_err(anyhow::Error::new)
                    .map_err(StateStoreError::Invalid)?;
                let home_store = ActiveHomeStore::from_permit_with_roots(
                    permit,
                    roots.0.clone(),
                    roots.1.clone(),
                )
                .map_err(StateStoreError::Invalid)?;
                let prepared =
                    prepare_active_home(home_store, Uuid::new_v4(), ActiveHomeAdoption::Strict)
                        .map_err(StateStoreError::Invalid)?;
                let published = publish_active_home(prepared).map_err(StateStoreError::Invalid)?;
                let proof = published
                    .journal_proof()
                    .map_err(StateStoreError::Invalid)?;
                let mut candidate = transaction.snapshot()?.state;
                candidate.current_account_id = Some(account.id.clone());
                candidate.active_profile = Some(profile.clone());
                let _receipt = transaction.commit_coordinated_with_active(
                    &candidate,
                    Vec::new(),
                    Some(proof),
                )?;
                // Simulate process death before native finalize by dropping
                // the opaque published transaction after the State commit.
                drop(published);
                Ok(())
            })
            .expect("commit postcommit active-home journal");
        assert!(active_journal_exists(&state_dir, &account.id));
        let mut recovery_session = StateSession::open(&state_dir).expect("open final session");
        recover_active_home_journals(&state_dir, &mut recovery_session, Some(roots.clone()))
            .expect("finalize postcommit active-home journal");
        assert!(roots.0.as_path().join("antigravity-oauth-token").exists());
        assert!(!active_journal_exists(&state_dir, &account.id));
        assert_eq!(
            recovery_session.state().current_account_id.as_deref(),
            Some(account.id.as_str())
        );
    }

    fn active_journal_exists(state_dir: &Path, account_id: &str) -> bool {
        fs::read_dir(state_dir.join("accounts").join(account_id))
            .map(|entries| {
                entries.flatten().any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".sagy-active-home-")
                })
            })
            .unwrap_or(false)
    }

    #[test]
    fn restart_recovery_scans_new_account_not_yet_in_state() {
        let temp = tempfile::tempdir().expect("temp dir");
        let state_dir = temp.path().join("state");
        let store = StateStore::open(&state_dir).expect("open state store");
        let missing = store.read().expect("read missing state");
        assert!(matches!(missing.migration, MigrationStatus::Missing));

        // Simulate the crash window after credential publish and before the
        // new account has entered state.json.  The published transaction is
        // intentionally dropped with its journal/evidence still present.
        store
            .with_locked_exact(&missing.revision, |transaction| {
                let permit = transaction.credential_mutation_permit("new-account")?;
                let credential_store = CredentialStore::from_permit(permit)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let credential = PortableCredential::oauth_access_token("crash-token")
                    .map_err(anyhow::Error::new)
                    .map_err(StateStoreError::Invalid)?;
                let prepared = credential_store
                    .stage(Uuid::new_v4(), &credential)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                let _published = credential_store
                    .publish(prepared)
                    .map_err(|error| StateStoreError::Invalid(anyhow::Error::new(error)))?;
                Ok(())
            })
            .expect("publish before simulated crash");

        let account_dir = state_dir.join("accounts").join("new-account");
        assert!(account_dir.join("antigravity-oauth-token").exists());
        assert!(fs::read_dir(&account_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".journal")
        }));

        recover_credential_journals(&state_dir, &missing).expect("restart recovery");
        assert!(!account_dir.join("antigravity-oauth-token").exists());
        assert!(!fs::read_dir(&account_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".journal")
        }));
    }
}
