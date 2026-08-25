use std::collections::BTreeSet;
use std::path::Path;

use crate::adapters::antigravity::account::credential_store::CredentialStore;
use crate::core::policy;
use crate::core::state::{AccountRecord, State, UsageSnapshot};

/// Select only from credentials whose fixed v2 slot can be read and verified.
/// A State reference is metadata, not proof that the credential still exists.
pub(crate) fn select_launch_account(
    state_dir: &Path,
    state: &State,
    now: i64,
) -> Option<(AccountRecord, UsageSnapshot)> {
    let validated = locally_validated_account_ids(state_dir, state);
    policy::select_best_account_with_validation(state, &state.accounts, &validated, now)
        .map(|(account, usage)| (account.clone(), usage))
}

fn locally_validated_account_ids(state_dir: &Path, state: &State) -> BTreeSet<String> {
    state
        .credential_refs
        .iter()
        .filter_map(|(account_id, reference)| {
            let store = CredentialStore::new(state_dir, account_id).ok()?;
            store.read(reference).ok()?;
            Some(account_id.clone())
        })
        .collect()
}

pub fn print_selection(prefix: &str, account: &AccountRecord, usage: &UsageSnapshot) {
    let plan = account.plan.as_deref().unwrap_or("Antigravity");
    let status = usage.health.to_string();
    eprintln!(
        "[sagy] {prefix}: {} ({}, plan: {}, status: {})",
        account.email,
        account.account_type.as_str(),
        plan,
        status
    );
}
