use std::path::Path;

use anyhow::Result;

pub mod account;
pub mod auth;
pub mod launcher;
pub mod paths;
pub mod repo_sync;
pub mod ui;
pub mod usage;

pub use auth::LoginMode;
pub use repo_sync::{PullOptions, PullOutcome, PushOptions, PushOutcome};

use crate::core::policy;
use crate::core::state::{AccountRecord, LiveIdentity, State, UsageSnapshot};

#[derive(Debug, Default, Clone)]
pub struct AntigravityAdapter;

impl AntigravityAdapter {
    pub fn active_identity_from_state(&self, state: &State) -> Option<LiveIdentity> {
        let current_id = state.current_account_id.as_ref()?;
        let account = state
            .accounts
            .iter()
            .find(|account| &account.id == current_id)?;
        Some(LiveIdentity {
            email: account.email.clone(),
            account_id: account.account_id.clone(),
        })
    }

    pub fn ensure_best_account(
        &self,
        state_dir: &Path,
        state: &mut State,
        no_import_known: bool,
        perform_switch: bool,
    ) -> Result<Option<(AccountRecord, UsageSnapshot)>> {
        if !no_import_known && state.accounts.is_empty() {
            self.import_known_sources(state_dir, state);
        }

        if state.accounts.is_empty() {
            return Ok(None);
        }

        self.refresh_all_accounts(state_dir, state, false);

        if let Some((best_acc, usage)) = policy::select_best_account(state, &state.accounts) {
            let record = best_acc.clone();
            if perform_switch {
                self.switch_account(&record)?;
                state.current_account_id = Some(record.id.clone());
            }
            return Ok(Some((record, usage)));
        }

        Ok(None)
    }
}
