pub mod account;
pub(crate) mod active_home;
pub mod auth;
pub mod launch_observation;
pub mod launcher;
pub(crate) mod native_session;
pub mod paths;
pub mod repo_bundle;
pub mod repo_sync;
pub mod ui;
pub mod usage;

pub use auth::LoginMode;
pub use launch_observation::{
    LaunchDiagnostic, LaunchDiagnosticParseError, LaunchDiagnosticParser, LaunchOutcome,
    ProcessTermination,
};
pub use repo_sync::{PullOptions, PullOutcome, PushOptions, PushOutcome};

use crate::core::state::{LiveIdentity, State};

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
}
