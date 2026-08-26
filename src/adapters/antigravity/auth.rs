use std::fmt;
use std::path::Path;

use anyhow::{Result, bail};

use crate::adapters::antigravity::account::{MutationResult, ensure_import_kind_compatible};
use crate::core::credential::CredentialKind;
use crate::core::state::{AccountRecord, State};
use crate::core::state_store::StateSession;

#[derive(Clone)]
pub enum LoginMode<'a> {
    OAuth {
        email_hint: Option<&'a str>,
    },
    Token {
        token: &'a str,
        email: Option<&'a str>,
    },
    ApiKey {
        api_key: &'a str,
        email: Option<&'a str>,
        project_id: Option<&'a str>,
    },
}

// Authentication material must never be exposed by a diagnostic formatter.
impl fmt::Debug for LoginMode<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("LoginMode");
        match self {
            Self::OAuth { email_hint } => {
                debug
                    .field("mode", &"oauth")
                    .field("email_hint", email_hint);
            }
            Self::Token { email, .. } => {
                debug.field("mode", &"token").field("token", &"<redacted>");
                debug.field("email", email);
            }
            Self::ApiKey {
                email, project_id, ..
            } => {
                debug
                    .field("mode", &"api_key")
                    .field("api_key", &"<redacted>")
                    .field("email", email)
                    .field("project_id", project_id);
            }
        }
        debug.finish()
    }
}

fn validate_secret_input(input: &str) -> Result<&str> {
    let token = input.trim();
    if token.is_empty() {
        bail!("Token cannot be empty");
    }
    Ok(token)
}

impl super::AntigravityAdapter {
    /// Execute one login/import against the CLI's exact v2 session.
    ///
    /// The compatibility API below remains temporarily available to older
    /// callers, but new command paths must keep the same `StateSession` so a
    /// post-commit recovery warning cannot make them continue from stale
    /// state.
    pub(crate) fn run_login_mode_session(
        &self,
        state_dir: &Path,
        session: &mut StateSession,
        mode: LoginMode<'_>,
    ) -> Result<MutationResult<AccountRecord>> {
        match mode {
            LoginMode::OAuth { email_hint } => {
                let email = email_hint.unwrap_or("antigravity-user@google.com");
                let token =
                    acquire_hidden_token(session.state(), email, rpassword::prompt_password)?;
                self.import_or_update_token_session(
                    state_dir,
                    session,
                    email,
                    &token,
                    Some("Antigravity OAuth"),
                )
            }
            LoginMode::Token { token, email } => {
                let email = email.unwrap_or("token-user@gemini");
                self.import_or_update_token_session(
                    state_dir,
                    session,
                    email,
                    validate_secret_input(token)?,
                    Some("Antigravity Token"),
                )
            }
            LoginMode::ApiKey {
                api_key,
                email,
                project_id,
            } => self.import_or_update_api_key_session(
                state_dir,
                session,
                validate_secret_input(api_key)?,
                email.unwrap_or("api-key-user@gemini"),
                project_id,
            ),
        }
    }
}

/// Acquire a token through the hidden-input path with an injectable prompt seam.
///
/// The ordering here is security-sensitive: reject a cross-kind email
/// collision before printing or reading any secret, then keep the product
/// prompt and validation around the one production hidden-input call.
fn acquire_hidden_token<P>(state: &State, email: &str, prompt_secret: P) -> Result<String>
where
    P: FnOnce(&'static str) -> std::io::Result<String>,
{
    ensure_import_kind_compatible(state, email, CredentialKind::OAuthAccessToken)?;
    println!("Paste your Antigravity OAuth Token (or Google Token):");
    let token_input = prompt_secret("> ")?;
    Ok(validate_secret_input(&token_input)?.to_owned())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{LoginMode, acquire_hidden_token, validate_secret_input};
    use crate::core::state::{AccountRecord, AccountType, State};

    #[test]
    fn secret_input_rejects_empty_and_whitespace() {
        assert!(validate_secret_input("").is_err());
        assert!(validate_secret_input(" \t\n").is_err());
        assert_eq!(
            validate_secret_input("  token-value  ").unwrap(),
            "token-value"
        );
    }

    #[test]
    fn login_mode_debug_redacts_authentication_material() {
        let token_debug = format!(
            "{:?}",
            LoginMode::Token {
                token: "do-not-print",
                email: Some("user@example.com"),
            }
        );
        assert!(!token_debug.contains("do-not-print"));
        assert!(token_debug.contains("<redacted>"));

        let api_key_debug = format!(
            "{:?}",
            LoginMode::ApiKey {
                api_key: "also-do-not-print",
                email: None,
                project_id: None,
            }
        );
        assert!(!api_key_debug.contains("also-do-not-print"));
        assert!(api_key_debug.contains("<redacted>"));
    }

    #[test]
    fn hidden_token_conflict_rejects_before_secret_prompt() {
        let state = State {
            accounts: vec![AccountRecord {
                id: "occupying-account".to_string(),
                email: "clash@example.test".to_string(),
                account_type: AccountType::ApiKey,
                ..AccountRecord::default()
            }],
            ..State::default()
        };

        let result = acquire_hidden_token(&state, "clash@example.test", |_| {
            panic!("hidden token prompt must not run on a kind conflict")
        });
        let error = result
            .expect_err("cross-kind conflict must fail")
            .to_string();
        assert!(error.contains("clash@example.test"));
        assert!(error.contains("api_key"));
    }

    #[test]
    fn hidden_token_prompt_seam_runs_once_with_the_product_prompt() {
        let state = State::default();
        let calls = Cell::new(0);
        let mut prompt_seen = String::new();

        let result = acquire_hidden_token(&state, "fresh@example.test", |prompt| {
            calls.set(calls.get() + 1);
            prompt_seen.push_str(prompt);
            Ok(String::from("synthetic-token"))
        });

        let token = result.expect("the injected token must pass validation");
        assert_eq!(token, "synthetic-token");
        assert_eq!(calls.get(), 1);
        assert_eq!(prompt_seen, "> ");
    }
}
