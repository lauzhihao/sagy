use std::collections::BTreeSet;
use std::io::{self, Write};
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
    // 不能用 eprintln!: 它在写失败时 panic。父进程 stderr 不可写
    // (`sagy ... 2>&1 | head -c 0`、fd 已关闭) 是本进程的输出问题, 与 agy 的
    // 结果无关; 让它 panic 会把整次 launch 变成退出码 101, agy 根本不会被
    // spawn, 已解析出的限流证据也一并丢掉。这里显式忽略写失败。
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "[sagy] {prefix}: {} ({}, plan: {}, status: {})",
        account.email,
        account.account_type.as_str(),
        plan,
        status
    );
    let _ = stderr.flush();
}
