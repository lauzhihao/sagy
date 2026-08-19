use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::adapters::antigravity::AntigravityAdapter;
use crate::core::storage;
use crate::core::ui;
use crate::core::update;

pub mod args;
pub mod help;
pub mod launch;
pub mod repo_sync;

pub use args::{
    AddArgs, AutoArgs, ImportAuthArgs, LaunchArgs, LoginArgs, RepoSyncArgs, RmArgs, UpdateArgs,
    UseArgs,
};

use args::resolve_login_mode;
use help::{render_help, requested_help_topic};
use launch::{ensure_launch_account, print_selection};
use repo_sync::resolve_repo_sync_repo;

#[derive(Debug, Parser)]
#[command(name = "sagy")]
pub struct Cli {
    #[arg(long)]
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
    Push(RepoSyncArgs),
    Pull(RepoSyncArgs),
    Use(UseArgs),
    Rm(RmArgs),
    List,
    Refresh,
    #[command(visible_alias = "upgrade")]
    Update(UpdateArgs),
    ImportAuth(ImportAuthArgs),
    ImportKnown,
    #[command(external_subcommand)]
    Passthrough(Vec<OsString>),
}

impl Cli {
    pub fn parse_args() -> Self {
        let args = env::args_os().collect::<Vec<_>>();
        if let Some(topic) = requested_help_topic(&args) {
            print!("{}", render_help(topic));
            std::process::exit(0);
        }
        Self::parse()
    }
}

pub fn run(cli: Cli) -> Result<i32> {
    let ui = ui::messages();
    let adapter = AntigravityAdapter::default();
    let state_dir = storage::resolve_state_dir(cli.state_dir.as_deref())?;
    let mut state = storage::load_state(&state_dir)?;
    let command = cli.command.unwrap_or(Command::Launch(LaunchArgs {
        no_import_known: false,
        no_login: false,
        dry_run: false,
        no_resume: false,
        no_launch: false,
        extra_args: Vec::new(),
    }));

    let exit_code = match command {
        Command::Launch(args) => {
            match ensure_launch_account(
                &adapter,
                &state_dir,
                &mut state,
                args.no_import_known,
                args.no_login,
                !args.dry_run,
            )? {
                Some((account, usage, _pulled)) => {
                    if args.dry_run {
                        print_selection(ui.selection_would_select(), &account, &usage);
                        storage::save_state(&state_dir, &state)?;
                        0
                    } else {
                        print_selection(ui.selection_switched(), &account, &usage);
                        storage::save_state(&state_dir, &state)?;
                        if args.no_launch {
                            0
                        } else {
                            adapter.launch_agy(
                                &state_dir,
                                &account,
                                &args.extra_args,
                                !args.no_resume,
                            )?
                        }
                    }
                }
                None => {
                    println!("{}", ui.no_usable_account_hint());
                    storage::save_state(&state_dir, &state)?;
                    1
                }
            }
        }
        Command::Auto(args) => {
            match ensure_launch_account(
                &adapter,
                &state_dir,
                &mut state,
                args.no_import_known,
                args.no_login,
                !args.dry_run,
            )? {
                Some((account, usage, _pulled)) => {
                    if args.dry_run {
                        print_selection(ui.selection_would_select(), &account, &usage);
                    } else {
                        print_selection(ui.selection_switched(), &account, &usage);
                    }
                    storage::save_state(&state_dir, &state)?;
                    0
                }
                None => {
                    println!("{}", ui.no_usable_account_hint());
                    storage::save_state(&state_dir, &state)?;
                    1
                }
            }
        }
        Command::Login(args) => {
            let mode = resolve_login_mode(&args)?;
            let record = adapter.run_login_mode(&state_dir, &mut state, mode)?;
            let usage = adapter.refresh_account_usage(&state_dir, &mut state, &record);
            println!("{}", ui.added_account(&record.email));
            adapter.switch_account(&record)?;
            state.current_account_id = Some(record.id.clone());
            print_selection(ui.selection_switched(), &record, &usage);
            storage::save_state(&state_dir, &state)?;
            0
        }
        Command::Add(args) => {
            let mode = resolve_login_mode(&args.login)?;
            let record = adapter.run_login_mode(&state_dir, &mut state, mode)?;
            let usage = adapter.refresh_account_usage(&state_dir, &mut state, &record);
            println!("{}", ui.added_account(&record.email));
            if args.switch {
                adapter.switch_account(&record)?;
                state.current_account_id = Some(record.id.clone());
                print_selection(ui.selection_switched(), &record, &usage);
            }
            storage::save_state(&state_dir, &state)?;
            0
        }
        Command::Use(args) => {
            let _ = adapter.import_known_sources(&state_dir, &mut state);
            let Some(record) = adapter.find_account_by_email(&state, &args.email).cloned() else {
                println!("{}", ui.unknown_account(&args.email));
                storage::save_state(&state_dir, &state)?;
                return Ok(1);
            };
            adapter.switch_account(&record)?;
            state.current_account_id = Some(record.id.clone());
            let usage = state
                .usage_cache
                .get(&record.id)
                .cloned()
                .unwrap_or_default();
            print_selection(ui.selection_switched(), &record, &usage);
            storage::save_state(&state_dir, &state)?;
            0
        }
        Command::Rm(args) => {
            let _ = adapter.import_known_sources(&state_dir, &mut state);
            let Some((id, email)) = adapter
                .find_account_by_email(&state, &args.email)
                .map(|record| (record.id.clone(), record.email.clone()))
            else {
                println!("{}", ui.unknown_account(&args.email));
                storage::save_state(&state_dir, &state)?;
                return Ok(1);
            };
            if !args.assume_yes {
                use std::io::{self, IsTerminal, Write};
                if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                    println!("{}", ui.rm_requires_tty());
                    return Ok(1);
                }
                loop {
                    print!("{}", ui.confirm_rm(&email));
                    let _ = io::stdout().flush();
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    let trimmed = line.trim().to_ascii_lowercase();
                    if trimmed == "y" || trimmed == "yes" {
                        break;
                    } else if trimmed == "n" || trimmed == "no" || trimmed.is_empty() {
                        println!("{}", ui.rm_cancelled());
                        return Ok(0);
                    } else {
                        println!("{}", ui.invalid_yes_no());
                    }
                }
            }
            adapter.remove_account(&state_dir, &mut state, &id)?;
            storage::save_state(&state_dir, &state)?;
            println!("{}", ui.removed_account(&email));
            0
        }
        Command::Push(args) => {
            let repo = resolve_repo_sync_repo(&state_dir, args.repo.as_deref())?;
            let outcome = adapter.push_account_pool(
                &state_dir,
                &state,
                &repo,
                args.path.as_deref(),
                args.identity_file.as_deref(),
                args.all,
            )?;
            if outcome.changed {
                println!(
                    "{}",
                    ui.repo_push_completed(&repo, outcome.exported_accounts)
                );
            } else {
                println!("{}", ui.repo_push_no_changes(&repo));
            }
            0
        }
        Command::Pull(args) => {
            let repo = resolve_repo_sync_repo(&state_dir, args.repo.as_deref())?;
            let outcome = adapter.pull_account_pool(
                &state_dir,
                &mut state,
                &repo,
                args.path.as_deref(),
                args.identity_file.as_deref(),
            )?;
            storage::save_state(&state_dir, &state)?;
            println!(
                "{}",
                ui.repo_pull_completed(&repo, outcome.imported_accounts)
            );
            adapter.refresh_all_accounts(&state_dir, &mut state);
            storage::save_state(&state_dir, &state)?;
            let active = adapter.active_identity_from_state(&state);
            println!("{}", adapter.render_account_table(&state, active.as_ref()));
            0
        }
        Command::List => {
            adapter.refresh_all_accounts(&state_dir, &mut state);
            storage::save_state(&state_dir, &state)?;
            let active = adapter.active_identity_from_state(&state);
            println!("{}", adapter.render_account_table(&state, active.as_ref()));
            0
        }
        Command::Refresh => {
            adapter.refresh_all_accounts(&state_dir, &mut state);
            storage::save_state(&state_dir, &state)?;
            let active = adapter.active_identity_from_state(&state);
            println!("{}", adapter.render_account_table(&state, active.as_ref()));
            println!("{}", ui.refreshed_accounts(state.accounts.len()));
            0
        }
        Command::Update(args) => {
            let outcome = update::self_update(&state_dir, args.force)?;
            match outcome.status {
                update::UpdateStatus::AlreadyCurrent => {
                    println!(
                        "{}",
                        ui.update_already_current(
                            &outcome.installed_version,
                            &outcome.executable_path
                        )
                    );
                }
                update::UpdateStatus::Updated => {
                    println!(
                        "{}",
                        ui.update_completed(
                            &outcome.previous_version,
                            &outcome.installed_version,
                            &outcome.executable_path
                        )
                    );
                    if cfg!(windows) {
                        println!("{}", ui.restart_terminal_hint());
                    }
                }
            }
            0
        }
        Command::ImportAuth(args) => {
            let record = adapter.import_auth_path(&state_dir, &mut state, &args.path)?;
            if state.current_account_id.is_none() {
                state.current_account_id = Some(record.id.clone());
            }
            storage::save_state(&state_dir, &state)?;
            println!("{}", ui.imported_account(&record.email, &record.id));
            0
        }
        Command::ImportKnown => {
            let imported = adapter.import_known_sources(&state_dir, &mut state);
            if imported.is_empty() {
                println!("{}", ui.no_importable_accounts());
                storage::save_state(&state_dir, &state)?;
                return Ok(1);
            }
            if state.current_account_id.is_none() {
                state.current_account_id = Some(imported[0].id.clone());
            }
            storage::save_state(&state_dir, &state)?;
            for account in imported {
                println!("{}", ui.imported_account(&account.email, &account.id));
            }
            0
        }
        Command::Passthrough(args) => {
            match ensure_launch_account(&adapter, &state_dir, &mut state, false, false, true)? {
                Some((account, usage, _pulled)) => {
                    print_selection(ui.selection_switched(), &account, &usage);
                    storage::save_state(&state_dir, &state)?;
                    adapter.run_passthrough(&state_dir, &account, &args)?
                }
                None => {
                    println!("{}", ui.no_usable_account_hint());
                    storage::save_state(&state_dir, &state)?;
                    1
                }
            }
        }
    };

    Ok(exit_code)
}
