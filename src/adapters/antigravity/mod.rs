use std::fs;
use std::path::Path;

use anyhow::Result;
use serde_json::Value;

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
    pub fn read_live_identity(&self) -> Option<LiveIdentity> {
        // 1. Check ~/.gemini/google_accounts.json
        if let Some(gemini_home) = paths::default_gemini_home() {
            let ga_file = gemini_home.join("google_accounts.json");
            if ga_file.is_file() {
                if let Ok(content) = fs::read_to_string(&ga_file) {
                    if let Ok(json) = serde_json::from_str::<Value>(&content) {
                        if let Some(active) = json.get("active").and_then(Value::as_str) {
                            let trimmed = active.trim();
                            if !trimmed.is_empty() {
                                return Some(LiveIdentity {
                                    email: trimmed.to_string(),
                                    account_id: None,
                                });
                            }
                        }
                    }
                }
            }

            // 2. Check ~/.gemini/oauth_creds.json
            let oauth_file = gemini_home.join("oauth_creds.json");
            if oauth_file.is_file() {
                if let Ok(content) = fs::read_to_string(&oauth_file) {
                    if let Ok(json) = serde_json::from_str::<Value>(&content) {
                        if let Some(email) = json.get("email").and_then(Value::as_str) {
                            let trimmed = email.trim();
                            if !trimmed.is_empty() {
                                return Some(LiveIdentity {
                                    email: trimmed.to_string(),
                                    account_id: None,
                                });
                            }
                        }
                    }
                }
            }
        }

        // 3. Check ~/.gemini/antigravity-cli/antigravity-oauth-token
        if let Some(cli_home) = paths::default_antigravity_cli_home() {
            let token_file = cli_home.join("antigravity-oauth-token");
            if token_file.is_file() {
                if let Ok(token_str) = fs::read_to_string(&token_file) {
                    if !token_str.trim().is_empty() {
                        return Some(LiveIdentity {
                            email: "antigravity-cli-session".to_string(),
                            account_id: None,
                        });
                    }
                }
            }
        }

        None
    }

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
        _no_login: bool,
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
