use std::fs;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::adapters::antigravity::paths::{
    default_antigravity_cli_home, default_gemini_home,
};
use crate::core::state::{AccountRecord, AccountType, State};

#[derive(Debug, Clone)]
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

impl super::AntigravityAdapter {
    pub fn switch_account(&self, account: &AccountRecord) -> Result<()> {
        let auth_path = Path::new(&account.auth_path);
        if !auth_path.exists() {
            bail!("Account credentials not found at {}", auth_path.display());
        }

        // 1. If it's a token file, copy to default antigravity-oauth-token location
        if let Some(cli_home) = default_antigravity_cli_home() {
            fs::create_dir_all(&cli_home)
                .with_context(|| format!("failed to create {}", cli_home.display()))?;

            if let Some(token) = &account.oauth_token {
                let target_token = cli_home.join("antigravity-oauth-token");
                let temp_token = cli_home.join(".antigravity-oauth-token.tmp");
                fs::write(&temp_token, token)?;
                fs::rename(&temp_token, &target_token)?;
            }
        }

        // 2. If it's an oauth_creds / general credentials json, copy to ~/.gemini/
        if let Some(gemini_home) = default_gemini_home() {
            fs::create_dir_all(&gemini_home)
                .with_context(|| format!("failed to create {}", gemini_home.display()))?;

            if auth_path.extension().and_then(|s| s.to_str()) == Some("json") {
                let target_creds = gemini_home.join("oauth_creds.json");
                let temp_creds = gemini_home.join(".oauth_creds.json.tmp");
                let content = fs::read_to_string(auth_path)?;
                fs::write(&temp_creds, content)?;
                fs::rename(&temp_creds, &target_creds)?;
            }
        }

        Ok(())
    }

    pub fn run_login_mode(
        &self,
        state_dir: &Path,
        state: &mut State,
        mode: LoginMode<'_>,
    ) -> Result<AccountRecord> {
        match mode {
            LoginMode::OAuth { email_hint } => {
                let email = email_hint.unwrap_or("antigravity-user@google.com");
                println!("Paste your Antigravity OAuth Token (or Google Token):");
                print!("> ");
                io::stdout().flush()?;
                let mut token_input = String::new();
                io::stdin().read_line(&mut token_input)?;
                let token = token_input.trim();
                if token.is_empty() {
                    bail!("Token cannot be empty");
                }
                self.import_or_update_token(state_dir, state, email, token, Some("Antigravity OAuth"))
            }
            LoginMode::Token { token, email } => {
                let email_str = email.unwrap_or("token-user@gemini");
                self.import_or_update_token(state_dir, state, email_str, token, Some("Antigravity Token"))
            }
            LoginMode::ApiKey {
                api_key,
                email,
                project_id,
            } => {
                let email_str = email.unwrap_or("api-key-user@gemini");
                let acc_id = uuid::Uuid::new_v4().to_string();
                let acc_dir = super::paths::account_dir(state_dir, &acc_id);
                fs::create_dir_all(&acc_dir)?;
                let cred_file = super::paths::account_credentials_file(&acc_dir);

                let creds_json = serde_json::json!({
                    "api_key": api_key,
                    "email": email_str,
                    "project_id": project_id,
                });
                fs::write(&cred_file, serde_json::to_string_pretty(&creds_json)?)?;

                let now = chrono::Utc::now().timestamp();
                let record = AccountRecord {
                    id: acc_id.clone(),
                    email: email_str.to_string(),
                    account_type: AccountType::ApiKey,
                    provider_id: Some("google-ai-studio".to_string()),
                    project_id: project_id.map(ToString::to_string),
                    account_id: None,
                    identity_fingerprint: None,
                    plan: Some("Gemini API Key".to_string()),
                    auth_path: cred_file.to_string_lossy().into_owned(),
                    config_path: None,
                    oauth_token: None,
                    refresh_token: None,
                    api_key: Some(api_key.to_string()),
                    added_at: now,
                    updated_at: now,
                    last_used_at: None,
                };

                state.accounts.push(record.clone());
                state.usage_cache.insert(
                    acc_id,
                    crate::core::state::UsageSnapshot {
                        plan: record.plan.clone(),
                        status: "Ready".to_string(),
                        cooldown_until: None,
                        remaining_quota_percent: Some(100),
                        last_synced_at: Some(now),
                        last_sync_error: None,
                        needs_relogin: false,
                    },
                );

                Ok(record)
            }
        }
    }
}
