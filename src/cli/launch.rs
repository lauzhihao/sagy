use std::path::Path;

use anyhow::Result;

use crate::adapters::antigravity::AntigravityAdapter;
use crate::core::state::{AccountRecord, State, UsageSnapshot};

pub fn ensure_launch_account(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    state: &mut State,
    no_import_known: bool,
    no_login: bool,
    perform_switch: bool,
) -> Result<Option<(AccountRecord, UsageSnapshot, bool)>> {
    let result =
        adapter.ensure_best_account(state_dir, state, no_import_known, no_login, perform_switch)?;

    Ok(result.map(|(acc, usage)| (acc, usage, false)))
}

pub fn print_selection(prefix: &str, account: &AccountRecord, usage: &UsageSnapshot) {
    let plan = account.plan.as_deref().unwrap_or("Antigravity");
    let status = &usage.status;
    eprintln!(
        "[sagy] {prefix}: {} ({}, plan: {}, status: {})",
        account.email,
        account.account_type.as_str(),
        plan,
        status
    );
}
