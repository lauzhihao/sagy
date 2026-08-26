use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use chrono::Utc;
use clap::{Parser, Subcommand};

use crate::adapters::antigravity::account::{
    ActiveHomeAdoption, MutationResult, ascii_console, has_provider_managed_session,
};
use crate::adapters::antigravity::native_session;
use crate::adapters::antigravity::{AntigravityAdapter, LaunchDiagnostic, ProcessTermination};
use crate::core::atomic_io::NormalizedStoreRoot;
use crate::core::health::{ProbeOutcome, ProbeSubject, reduce_usage_observed};
use crate::core::state::{AccountRecord, CredentialRef, CredentialRefKind};
use crate::core::state_store::{MigrationStatus, StateSession, StateStore};
use crate::core::storage;
use crate::core::ui;
use crate::core::update;

pub mod args;
pub mod help;
pub mod launch;
pub mod repo_sync;
pub mod router;

pub use args::{
    AddArgs, AutoArgs, ImportAuthArgs, LaunchArgs, LoginArgs, RepoSyncArgs, RmArgs, UpdateArgs,
    UseArgs,
};

use args::resolve_login_mode;
use launch::{print_selection, select_launch_account};
use repo_sync::resolve_repo_sync_repo;
use router::{Route, route};

#[derive(Debug, Parser)]
#[command(
    name = "sagy",
    version = env!("CARGO_PKG_VERSION"),
    about = "Google Antigravity CLI (agy) smart multi-account manager & launcher"
)]
pub struct Cli {
    #[arg(
        long,
        value_name = "PATH",
        help = "Override the state and account directory (default: ~/.sagy or $SAGY_HOME)"
    )]
    pub state_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Launch(LaunchArgs),
    Auto(AutoArgs),
    Add(AddArgs),
    Login(LoginArgs),
    #[command(about = "Encrypt and push the local account pool to a Git repository")]
    Push(RepoSyncArgs),
    #[command(about = "Pull and decrypt an account pool from a Git repository")]
    Pull(RepoSyncArgs),
    Use(UseArgs),
    Rm(RmArgs),
    #[command(about = "List every known account with its health and quota")]
    List,
    #[command(about = "Force a health and quota probe for every account")]
    Refresh,
    #[command(visible_alias = "upgrade")]
    Update(UpdateArgs),
    ImportAuth(ImportAuthArgs),
    #[command(about = "Discover and import existing local Gemini credentials")]
    ImportKnown,
    #[command(external_subcommand)]
    Passthrough(Vec<OsString>),
}

impl Cli {
    pub fn parse_args() -> Self {
        let raw_args = env::args_os().collect::<Vec<_>>();
        match route(&raw_args) {
            Route::Clap(args) => Self::parse_from(args),
            Route::Passthrough { state_dir, args } => Self {
                state_dir,
                command: Some(Command::Passthrough(args)),
            },
        }
    }
}

pub fn run(cli: Cli) -> Result<i32> {
    run_with_update(cli, |state_dir, force| {
        update::self_update(state_dir, force)
    })
}

fn run_with_update<F>(cli: Cli, update_fn: F) -> Result<i32>
where
    F: Fn(&Path, bool) -> Result<update::UpdateOutcome>,
{
    let ui = ui::messages();
    let adapter = AntigravityAdapter;
    let requested_state_dir = storage::resolve_state_dir(cli.state_dir.as_deref())?;
    let state_dir = NormalizedStoreRoot::normalize(&requested_state_dir)?
        .as_path()
        .to_path_buf();
    let command = cli.command.unwrap_or(Command::Launch(LaunchArgs {
        no_import_known: false,
        dry_run: false,
        no_resume: false,
        no_launch: false,
        takeover: false,
        extra_args: Vec::new(),
    }));

    // Update 只依赖 updater 自身，不应被损坏的账号 state 阻断恢复路径。
    if let Command::Update(args) = &command {
        return run_update(&state_dir, args.force, ui, &update_fn);
    }

    if let Some(code) = maybe_run_native_session(&state_dir, &command)? {
        return Ok(code);
    }

    let mut session = StateSession::open(&state_dir)?;
    match command {
        Command::Launch(args) => run_launch(
            &adapter,
            &state_dir,
            &mut session,
            &args.extra_args,
            !args.no_resume,
            args.no_import_known,
            args.dry_run,
            args.no_launch,
            adoption(args.takeover),
            ui,
        ),
        Command::Auto(args) => run_auto(
            &adapter,
            &state_dir,
            &mut session,
            args.no_import_known,
            args.dry_run,
            adoption(args.takeover),
            ui,
        ),
        Command::Login(args) => {
            if let Some(code) = prepare_existing_session(&adapter, &state_dir, &mut session)? {
                return Ok(code);
            }
            let outcome = adapter.run_login_mode_session(
                &state_dir,
                &mut session,
                resolve_login_mode(&args)?,
            )?;
            let Some(record) = finalized_value(outcome) else {
                return Ok(2);
            };
            let usage = refresh_one_and_commit(&adapter, &state_dir, &mut session, &record, true)?;
            println!("{}", ui.added_account(&ascii_console(&record.email)));
            let outcome = adapter.switch_account_session(
                &state_dir,
                &mut session,
                &record.id,
                adoption(args.takeover),
            )?;
            let Some(record) = finalized_value(outcome) else {
                return Ok(2);
            };
            print_selection(ui.selection_switched(), &record, &usage);
            Ok(0)
        }
        Command::Add(args) => {
            if let Some(code) = prepare_existing_session(&adapter, &state_dir, &mut session)? {
                return Ok(code);
            }
            let outcome = adapter.run_login_mode_session(
                &state_dir,
                &mut session,
                resolve_login_mode(&args.login)?,
            )?;
            let Some(record) = finalized_value(outcome) else {
                return Ok(2);
            };
            let usage = refresh_one_and_commit(&adapter, &state_dir, &mut session, &record, true)?;
            println!("{}", ui.added_account(&ascii_console(&record.email)));
            if args.switch {
                let outcome = adapter.switch_account_session(
                    &state_dir,
                    &mut session,
                    &record.id,
                    adoption(args.login.takeover),
                )?;
                let Some(record) = finalized_value(outcome) else {
                    return Ok(2);
                };
                print_selection(ui.selection_switched(), &record, &usage);
            }
            Ok(0)
        }
        Command::Use(args) => {
            if let Some(code) = ensure_current_session(&adapter, &state_dir, &mut session, false)? {
                return Ok(code);
            }
            let Some(record) = adapter
                .find_account_by_email(session.state(), &args.email)
                .cloned()
            else {
                println!("{}", ui.unknown_account(&ascii_console(&args.email)));
                return Ok(1);
            };
            let outcome = adapter.switch_account_session(
                &state_dir,
                &mut session,
                &record.id,
                adoption(args.takeover),
            )?;
            let Some(record) = finalized_value(outcome) else {
                return Ok(2);
            };
            let usage = session
                .state()
                .usage_cache
                .get(&record.id)
                .cloned()
                .unwrap_or_default();
            print_selection(ui.selection_switched(), &record, &usage);
            Ok(0)
        }
        Command::Rm(args) => {
            if let Some(code) = ensure_current_session(&adapter, &state_dir, &mut session, false)? {
                return Ok(code);
            }
            let Some((id, email)) = adapter
                .find_account_by_email(session.state(), &args.email)
                .map(|record| (record.id.clone(), record.email.clone()))
            else {
                println!("{}", ui.unknown_account(&ascii_console(&args.email)));
                return Ok(1);
            };
            if !args.assume_yes {
                if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                    println!("{}", ui.rm_requires_tty());
                    return Ok(1);
                }
                if !confirm_remove(&ascii_console(&email), ui)? {
                    return Ok(0);
                }
            }
            let outcome = adapter.remove_account_session(&state_dir, &mut session, &id)?;
            if finalized_value(outcome).is_none() {
                return Ok(2);
            }
            println!("{}", ui.removed_account(&ascii_console(&email)));
            Ok(0)
        }
        Command::Push(args) => {
            if let Some(code) = ensure_current_session(&adapter, &state_dir, &mut session, false)? {
                return Ok(code);
            }
            let repo = resolve_repo_sync_repo(&state_dir, args.repo.as_deref())?;
            let outcome = adapter.push_account_pool_v2(
                &state_dir,
                &mut session,
                &repo,
                crate::adapters::antigravity::PushOptions {
                    bundle_dir: args.path.as_deref(),
                    identity_file: args.identity_file.as_deref(),
                    insecure_host_key: args.insecure_host_key,
                },
            )?;
            if outcome.changed {
                println!(
                    "{}",
                    ui.repo_push_completed(&ascii_console(&repo), outcome.exported_accounts)
                );
            } else {
                println!("{}", ui.repo_push_no_changes(&ascii_console(&repo)));
            }
            Ok(0)
        }
        Command::Pull(args) => {
            if let Some(code) = prepare_existing_session(&adapter, &state_dir, &mut session)? {
                return Ok(code);
            }
            let repo = resolve_repo_sync_repo(&state_dir, args.repo.as_deref())?;
            let result = adapter.pull_account_pool_v2_session(
                &state_dir,
                &mut session,
                &repo,
                crate::adapters::antigravity::PullOptions {
                    bundle_dir: args.path.as_deref(),
                    identity_file: args.identity_file.as_deref(),
                    insecure_host_key: args.insecure_host_key,
                },
            );
            let outcome = match result {
                Ok(outcome) => outcome,
                Err(_) if session.read().recovery_pending => {
                    print_recovery_pending();
                    return Ok(2);
                }
                Err(error) => return Err(error),
            };
            println!(
                "{}",
                ui.repo_pull_completed(&ascii_console(&repo), outcome.imported_accounts)
            );
            refresh_all_and_commit(&adapter, &state_dir, &mut session, false)?;
            print_account_table(&adapter, session.state());
            Ok(0)
        }
        Command::List => {
            if let Some(code) = ensure_current_session(&adapter, &state_dir, &mut session, false)? {
                return Ok(code);
            }
            refresh_all_and_commit(&adapter, &state_dir, &mut session, false)?;
            print_account_table(&adapter, session.state());
            Ok(0)
        }
        Command::Refresh => {
            if let Some(code) = ensure_current_session(&adapter, &state_dir, &mut session, false)? {
                return Ok(code);
            }
            refresh_all_and_commit(&adapter, &state_dir, &mut session, true)?;
            print_account_table(&adapter, session.state());
            println!("{}", ui.refreshed_accounts(session.state().accounts.len()));
            Ok(0)
        }
        Command::Update(args) => run_update(&state_dir, args.force, ui, &update_fn),
        Command::ImportAuth(args) => {
            if let Some(code) = prepare_existing_session(&adapter, &state_dir, &mut session)? {
                return Ok(code);
            }
            let outcome = adapter.import_auth_path_session(&state_dir, &mut session, &args.path)?;
            let Some(record) = finalized_value(outcome) else {
                return Ok(2);
            };
            println!(
                "{}",
                ui.imported_account(&ascii_console(&record.email), &ascii_console(&record.id))
            );
            Ok(0)
        }
        Command::ImportKnown => {
            if let Some(code) = prepare_existing_session(&adapter, &state_dir, &mut session)? {
                return Ok(code);
            }
            let outcome = adapter.import_known_sources_session(&state_dir, &mut session)?;
            let Some(imported) = finalized_value(outcome) else {
                return Ok(2);
            };
            if imported.is_empty() {
                println!("{}", ui.no_importable_accounts());
                return Ok(1);
            }
            for account in imported {
                println!(
                    "{}",
                    ui.imported_account(
                        &ascii_console(&account.email),
                        &ascii_console(&account.id)
                    )
                );
            }
            Ok(0)
        }
        // Passthrough 与显式 launch 必须共用同一条 resume 规则：只有 --no-resume
        // 能关闭续接。否则多带一个与会话无关的 sagy flag 就会改变会话续接行为。
        Command::Passthrough(args) => run_launch(
            &adapter,
            &state_dir,
            &mut session,
            &args,
            true,
            false,
            false,
            false,
            adoption(false),
            ui,
        ),
    }
}

fn prepare_existing_session(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    session: &mut StateSession,
) -> Result<Option<i32>> {
    if matches!(session.migration(), MigrationStatus::LegacyV1) {
        let outcome = adapter.migrate_legacy_state_session(state_dir, session)?;
        if finalized_value(outcome).is_none() {
            return Ok(Some(2));
        }
    }
    if matches!(session.migration(), MigrationStatus::None) {
        adapter.recover_account_transactions_session(state_dir, session)?;
        if session.read().recovery_pending {
            print_recovery_pending();
            return Ok(Some(2));
        }
    }
    Ok(None)
}

/// Route provider-native launches before `StateSession::open`. Opening a
/// session hardens legacy permissions, which is a state-side effect even when
/// the eventual command only wants to run the provider runtime.
fn maybe_run_native_session(state_dir: &Path, command: &Command) -> Result<Option<i32>> {
    let (extra_args, resume, no_import_known, dry_run, no_launch) = match command {
        Command::Launch(args) => (
            args.extra_args.as_slice(),
            !args.no_resume,
            args.no_import_known,
            args.dry_run,
            args.no_launch,
        ),
        Command::Passthrough(args) => (args.as_slice(), true, false, false, false),
        _ => return Ok(None),
    };
    if no_import_known
        || dry_run
        || no_launch
        || !native_session::has_noninteractive_prompt(extra_args)
    {
        return Ok(None);
    }

    let read = StateStore::open(state_dir)?.read()?;
    if read.recovery_pending
        || !read.state.accounts.is_empty()
        || !matches!(
            read.migration,
            MigrationStatus::Missing | MigrationStatus::None
        )
        || !has_provider_managed_session()?
    {
        return Ok(None);
    }

    Ok(Some(
        match native_session::launch_native_session(extra_args, resume) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("[sagy] {error}");
                1
            }
        },
    ))
}

fn ensure_current_session(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    session: &mut StateSession,
    discover_if_empty: bool,
) -> Result<Option<i32>> {
    if let Some(code) = prepare_existing_session(adapter, state_dir, session)? {
        return Ok(Some(code));
    }
    if matches!(session.migration(), MigrationStatus::Missing) {
        let pending = if discover_if_empty {
            adapter
                .import_known_sources_session(state_dir, session)?
                .recovery_pending()
        } else {
            adapter
                .bootstrap_empty_v2_session(state_dir, session)?
                .recovery_pending()
        };
        if pending {
            print_recovery_pending();
            return Ok(Some(2));
        }
    } else if discover_if_empty && session.state().accounts.is_empty() {
        let outcome = adapter.import_known_sources_session(state_dir, session)?;
        if outcome.recovery_pending() {
            print_recovery_pending();
            return Ok(Some(2));
        }
    }
    Ok(None)
}

/// CLI 默认 `Adopt`：active home 里的凭据只要与目标账号逐字节一致就直接接管，
/// 否则 `prepare_inner` 会自动降级回 `Strict` 并 fail-closed。`--takeover` 是
/// 唯一能覆盖陌生凭据的显式逃生口，与 `--insecure-host-key` 同形状。
const fn adoption(takeover: bool) -> ActiveHomeAdoption {
    if takeover {
        ActiveHomeAdoption::Takeover
    } else {
        ActiveHomeAdoption::Adopt
    }
}

fn finalized_value<T>(outcome: MutationResult<T>) -> Option<T> {
    if outcome.recovery_pending() {
        print_recovery_pending();
        None
    } else {
        Some(outcome.into_value())
    }
}

fn print_recovery_pending() {
    eprintln!("[sagy] A committed change still needs recovery; rerun before another mutation.");
}

fn refresh_all_and_commit(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    session: &mut StateSession,
    force: bool,
) -> Result<()> {
    let mut candidate = session.state().clone();
    adapter.refresh_all_accounts(state_dir, &mut candidate, force);
    session.commit(&candidate)?;
    Ok(())
}

fn refresh_one_and_commit(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    session: &mut StateSession,
    account: &AccountRecord,
    force: bool,
) -> Result<crate::core::state::UsageSnapshot> {
    let mut candidate = session.state().clone();
    let usage = adapter.refresh_account_usage(state_dir, &mut candidate, account, force);
    session.commit(&candidate)?;
    Ok(usage)
}

fn run_auto(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    session: &mut StateSession,
    no_import_known: bool,
    dry_run: bool,
    adoption: ActiveHomeAdoption,
    ui: ui::Messages,
) -> Result<i32> {
    if let Some(code) = ensure_current_session(adapter, state_dir, session, !no_import_known)? {
        return Ok(code);
    }
    refresh_all_and_commit(adapter, state_dir, session, false)?;
    let Some((account, usage)) =
        select_launch_account(state_dir, session.state(), Utc::now().timestamp())
    else {
        println!("{}", ui.no_usable_account_hint());
        return Ok(1);
    };
    if dry_run {
        print_selection(ui.selection_would_select(), &account, &usage);
        return Ok(0);
    }
    let outcome = adapter.switch_account_session(state_dir, session, &account.id, adoption)?;
    let Some(account) = finalized_value(outcome) else {
        return Ok(2);
    };
    print_selection(ui.selection_switched(), &account, &usage);
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
fn run_launch(
    adapter: &AntigravityAdapter,
    state_dir: &Path,
    session: &mut StateSession,
    extra_args: &[OsString],
    resume: bool,
    no_import_known: bool,
    dry_run: bool,
    no_launch: bool,
    adoption: ActiveHomeAdoption,
    ui: ui::Messages,
) -> Result<i32> {
    if let Some(code) = ensure_current_session(adapter, state_dir, session, !no_import_known)? {
        return Ok(code);
    }
    refresh_all_and_commit(adapter, state_dir, session, false)?;
    if dry_run {
        let Some((account, usage)) =
            select_launch_account(state_dir, session.state(), Utc::now().timestamp())
        else {
            println!("{}", ui.no_usable_account_hint());
            return Ok(1);
        };
        print_selection(ui.selection_would_select(), &account, &usage);
        return Ok(0);
    }

    let mut last_rate_limit_code = None;
    for attempt in 0..3 {
        let Some((account, usage)) =
            select_launch_account(state_dir, session.state(), Utc::now().timestamp())
        else {
            if last_rate_limit_code.is_none() {
                println!("{}", ui.no_usable_account_hint());
            }
            return Ok(last_rate_limit_code.unwrap_or(1));
        };
        let outcome = adapter.switch_account_session(state_dir, session, &account.id, adoption)?;
        let Some(account) = finalized_value(outcome) else {
            return Ok(2);
        };
        print_selection(ui.selection_switched(), &account, &usage);
        if no_launch {
            return Ok(0);
        }

        let reference = session
            .state()
            .credential_refs
            .get(&account.id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("selected account has no credential reference"))?;
        let credential = adapter
            .resolve_launch_credential(state_dir, session, &account.id)
            .map_err(anyhow::Error::new)?;
        let observed_at = Utc::now().timestamp();
        let outcome = adapter
            .launch_agy_observed_resolved(state_dir, &credential, extra_args, resume)
            .map_err(anyhow::Error::new)?;
        // 账号与 active-home lease 必须在任何 State CAS 或 fallback 切换前释放。
        drop(credential);

        let exit_code = termination_exit_code(outcome.termination);
        let rate_limited = matches!(outcome.diagnostic, LaunchDiagnostic::RateLimited { .. });
        if !matches!(outcome.diagnostic, LaunchDiagnostic::None) {
            record_launch_diagnostic(
                session,
                &account.id,
                &reference,
                &outcome.diagnostic,
                observed_at,
            )?;
        } else if exit_code != 0 {
            let _ = refresh_one_and_commit(adapter, state_dir, session, &account, true)?;
        }

        if rate_limited && attempt < 2 {
            last_rate_limit_code = Some(exit_code.max(1));
            continue;
        }
        return Ok(exit_code);
    }
    Ok(last_rate_limit_code.unwrap_or(1))
}

fn record_launch_diagnostic(
    session: &mut StateSession,
    account_id: &str,
    reference: &CredentialRef,
    diagnostic: &LaunchDiagnostic,
    observed_at: i64,
) -> Result<()> {
    if session.state().credential_refs.get(account_id) != Some(reference) {
        bail!("selected credential changed before launch observation could be committed");
    }
    let subject = probe_subject(reference.kind);
    let observation = match diagnostic {
        LaunchDiagnostic::None => return Ok(()),
        LaunchDiagnostic::RateLimited {
            retry_after_seconds,
        } => ProbeOutcome::Http429 {
            subject,
            retry_after_secs: i64::try_from(*retry_after_seconds).ok(),
        },
        LaunchDiagnostic::AuthRejected => ProbeOutcome::Http401 { subject },
        LaunchDiagnostic::PermissionDenied => ProbeOutcome::Http403 { subject },
    };
    let now = Utc::now().timestamp();
    let previous = session
        .state()
        .usage_cache
        .get(account_id)
        .cloned()
        .unwrap_or_default();
    let next = reduce_usage_observed(&previous, &observation, observed_at, now);
    let mut candidate = session.state().clone();
    candidate.usage_cache.insert(account_id.to_string(), next);
    session.commit(&candidate)?;
    Ok(())
}

const fn probe_subject(kind: CredentialRefKind) -> ProbeSubject {
    match kind {
        CredentialRefKind::OauthAccessToken => ProbeSubject::RawToken,
        CredentialRefKind::OauthAuthorizedUser => ProbeSubject::AuthorizedUser,
        CredentialRefKind::ApiKey => ProbeSubject::ApiKey,
        CredentialRefKind::VertexServiceAccount => ProbeSubject::Vertex,
    }
}

fn termination_exit_code(termination: ProcessTermination) -> i32 {
    match termination {
        ProcessTermination::Exited { code } => code,
        ProcessTermination::Signaled { signal } => 128_i32
            .saturating_add(signal.saturating_abs())
            .clamp(1, 255),
        ProcessTermination::SpawnFailed | ProcessTermination::WaitFailed => 1,
    }
}

/// 参数名带 `_ascii` 后缀是硬约定：这里是一个 stdout 出口，调用方必须先过
/// `ascii_console`，`console_outlets_never_print_a_raw_user_string` 依赖这个
/// 命名来区分"已转义"和"生字符串"。
fn confirm_remove(email_ascii: &str, ui: ui::Messages) -> Result<bool> {
    loop {
        print!("{}", ui.confirm_rm(email_ascii));
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "" | "n" | "no" => {
                println!("{}", ui.rm_cancelled());
                return Ok(false);
            }
            _ => println!("{}", ui.invalid_yes_no()),
        }
    }
}

fn print_account_table(adapter: &AntigravityAdapter, state: &crate::core::state::State) {
    let active = adapter.active_identity_from_state(state);
    println!("{}", adapter.render_account_table(state, active.as_ref()));
}

fn run_update<F>(state_dir: &Path, force: bool, ui: ui::Messages, update_fn: &F) -> Result<i32>
where
    F: Fn(&Path, bool) -> Result<update::UpdateOutcome>,
{
    let outcome = update_fn(state_dir, force)?;
    match outcome.status {
        update::UpdateStatus::AlreadyCurrent => {
            println!(
                "{}",
                ui.update_already_current(&outcome.installed_version, &outcome.executable_path)
            );
        }
        update::UpdateStatus::Updated => {
            println!(
                "{}",
                ui.update_completed(
                    &outcome.previous_version,
                    &outcome.installed_version,
                    &outcome.executable_path,
                )
            );
            if cfg!(windows) {
                println!("{}", ui.restart_terminal_hint());
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 用户可控字符串在控制台出口的标识符黑名单。
    const RAW_USER_IDENTIFIERS: [&str; 3] = ["email", "repo", "id"];

    /// 取出 `text` 中从 `open` 位置起的一对平衡括号内的文本。
    fn balanced_args(text: &str, open: usize) -> (String, usize) {
        let bytes = text.as_bytes();
        let mut depth = 0_i32;
        let mut start = open;
        for (index, byte) in bytes.iter().enumerate().skip(open) {
            match byte {
                b'(' => {
                    if depth == 0 {
                        start = index + 1;
                    }
                    depth += 1;
                }
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return (text[start..index].to_string(), index + 1);
                    }
                }
                _ => {}
            }
        }
        (text[start..].to_string(), text.len())
    }

    /// 把 `ascii_console(...)` 调用整段抠掉，剩下的就是"没有经过转义"的部分。
    fn strip_escaped_calls(mut text: String) -> String {
        while let Some(index) = text.find("ascii_console(") {
            let open = index + "ascii_console".len();
            let (_, end) = balanced_args(&text, open);
            text.replace_range(index..end, "");
        }
        text
    }

    /// AC-R12-4.1 / AC-R12-4.2: 遗漏检查的方法。
    ///
    /// 这条测试就是"我怎么确认没有遗漏出口"的答案：它在编译期把本文件的源码
    /// 整份读进来，枚举**每一个** `print!` / `println!` / `eprintln!` 调用，
    /// 抠掉其中 `ascii_console(..)` 包住的部分，然后要求剩下的实参里不再出现
    /// 任何用户可控标识符（`email` / `repo` / `id`，含 `x.email` 这类字段访问）。
    /// 新写一个直接打印 `record.email` 的出口会立刻让它变红。
    ///
    /// 已知边界：本扫描只覆盖 `src/cli/mod.rs` 自己的出口。`print_selection`
    /// （src/cli/launch.rs）与 `render_account_table`（adapters/antigravity/ui.rs）
    /// 也会打印 email，但不在本工单的归属文件里。
    #[test]
    fn console_outlets_never_print_a_raw_user_string() {
        let source = include_str!("mod.rs");
        // 只扫描测试模块之前的产品代码，避免把本测试自己的字面量算进去。
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map(|(head, _)| head)
            .expect("cli::mod must keep its test module last");

        let mut checked = 0_usize;
        for macro_name in ["println!", "eprintln!", "print!"] {
            let mut cursor = 0_usize;
            while let Some(found) = production[cursor..].find(macro_name) {
                let open = cursor + found + macro_name.len() - 1;
                let (args, end) = balanced_args(production, open);
                cursor = end;
                checked += 1;
                let remainder = strip_escaped_calls(args.clone());
                for token in remainder.split(|c: char| !c.is_alphanumeric() && c != '_') {
                    assert!(
                        !RAW_USER_IDENTIFIERS.contains(&token),
                        "console outlet prints a raw user-controlled value `{token}`; \
wrap it in ascii_console(..): {macro_name}({args})"
                    );
                }
            }
        }
        assert!(
            checked >= 20,
            "the scanner found only {checked} console outlets; it is no longer scanning the file"
        );
    }

    #[test]
    fn update_dispatch_does_not_load_corrupt_state() {
        use std::cell::Cell;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        fs::write(temp_dir.path().join("state.json"), b"not-json").expect("write state");

        let called = Cell::new(false);
        let cli = Cli {
            state_dir: Some(temp_dir.path().to_path_buf()),
            command: Some(Command::Update(UpdateArgs { force: false })),
        };
        let result = run_with_update(cli, |state_dir, force| {
            called.set(true);
            assert_eq!(
                state_dir,
                fs::canonicalize(temp_dir.path())
                    .expect("canonical temp dir")
                    .as_path()
            );
            assert!(!force);
            Ok(update::UpdateOutcome {
                status: update::UpdateStatus::AlreadyCurrent,
                previous_version: env!("CARGO_PKG_VERSION").to_string(),
                installed_version: env!("CARGO_PKG_VERSION").to_string(),
                executable_path: temp_dir.path().join("sagy"),
            })
        });

        assert!(result.is_ok());
        assert!(called.get());
    }

    #[test]
    fn production_cli_never_uses_legacy_state_load_or_save() {
        let source = include_str!("mod.rs");
        for forbidden in [
            ["storage::", "load_state("].concat(),
            ["storage::", "save_state("].concat(),
        ] {
            assert!(!source.contains(&forbidden));
        }
    }
}
