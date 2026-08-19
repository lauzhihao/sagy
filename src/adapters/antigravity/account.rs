use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::adapters::antigravity::paths::{
    account_credentials_file, account_dir, account_token_file,
    default_antigravity_cli_home, default_gemini_home,
};
use crate::core::state::{AccountRecord, AccountType, State, UsageSnapshot};
use crate::core::storage;

impl super::AntigravityAdapter {
    pub fn import_known_sources(&self, state_dir: &Path, state: &mut State) -> Vec<AccountRecord> {
        let mut imported = Vec::new();

        // 1. Try importing existing ~/.gemini/antigravity-cli/antigravity-oauth-token
        if let Some(cli_home) = default_antigravity_cli_home() {
            let token_path = cli_home.join("antigravity-oauth-token");
            if token_path.is_file() {
                if let Ok(token_str) = fs::read_to_string(&token_path) {
                    let trimmed = token_str.trim();
                    if !trimmed.is_empty() {
                        let record = self.import_or_update_token(
                            state_dir,
                            state,
                            "default-antigravity-user@gemini",
                            trimmed,
                            Some("Antigravity OAuth"),
                        );
                        if let Ok(record) = record {
                            imported.push(record);
                        }
                    }
                }
            }
        }

        // 2. Try importing ~/.gemini/oauth_creds.json or google_accounts.json
        if let Some(gemini_home) = default_gemini_home() {
            let oauth_path = gemini_home.join("oauth_creds.json");
            if oauth_path.is_file() {
                if let Ok(record) = self.import_auth_path(state_dir, state, &oauth_path) {
                    imported.push(record);
                }
            }

            let accounts_path = gemini_home.join("google_accounts.json");
            if accounts_path.is_file() {
                if let Ok(record) = self.import_auth_path(state_dir, state, &accounts_path) {
                    imported.push(record);
                }
            }
        }

        imported
    }

    pub fn import_auth_path(
        &self,
        state_dir: &Path,
        state: &mut State,
        raw_path: &Path,
    ) -> Result<AccountRecord> {
        storage::ensure_exists(raw_path, "Auth credential file")?;
        let content = fs::read_to_string(raw_path)
            .with_context(|| format!("failed to read auth file {}", raw_path.display()))?;

        let json_val: Value = serde_json::from_str(&content)
            .with_context(|| format!("invalid JSON in {}", raw_path.display()))?;

        // Extract email or identify account
        let email = json_val
            .get("email")
            .or_else(|| json_val.get("client_email"))
            .or_else(|| json_val.get("account"))
            .or_else(|| json_val.get("user"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                if let Some(stem) = raw_path.file_stem().and_then(|s| s.to_str()) {
                    stem
                } else {
                    "imported-account@gemini"
                }
            })
            .trim()
            .to_string();

        let account_id = self
            .find_account_by_email(state, &email)
            .map(|a| a.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let acc_dir = account_dir(state_dir, &account_id);
        fs::create_dir_all(&acc_dir)
            .with_context(|| format!("failed to create account dir {}", acc_dir.display()))?;

        let target_cred = account_credentials_file(&acc_dir);
        fs::write(&target_cred, &content)
            .with_context(|| format!("failed to write {}", target_cred.display()))?;

        let now = Utc::now().timestamp();
        let record = AccountRecord {
            id: account_id.clone(),
            email: email.clone(),
            account_type: if json_val.get("api_key").is_some() {
                AccountType::ApiKey
            } else if json_val.get("type").and_then(Value::as_str) == Some("service_account") {
                AccountType::Vertex
            } else {
                AccountType::OAuth
            },
            provider_id: Some("google".to_string()),
            project_id: json_val
                .get("project_id")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            account_id: json_val
                .get("account_id")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            identity_fingerprint: None,
            plan: Some("Antigravity".to_string()),
            auth_path: target_cred.to_string_lossy().into_owned(),
            config_path: None,
            oauth_token: json_val
                .get("token")
                .or_else(|| json_val.get("access_token"))
                .and_then(Value::as_str)
                .map(ToString::to_string),
            refresh_token: json_val
                .get("refresh_token")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            api_key: json_val
                .get("api_key")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            added_at: now,
            updated_at: now,
            last_used_at: None,
        };

        if let Some(existing_idx) = state.accounts.iter().position(|a| a.id == record.id) {
            state.accounts[existing_idx] = record.clone();
        } else {
            state.accounts.push(record.clone());
        }

        if !state.usage_cache.contains_key(&record.id) {
            state.usage_cache.insert(
                record.id.clone(),
                UsageSnapshot {
                    plan: record.plan.clone(),
                    status: "Ready".to_string(),
                    cooldown_until: None,
                    remaining_quota_percent: Some(100),
                    last_synced_at: Some(now),
                    last_sync_error: None,
                    needs_relogin: false,
                },
            );
        }

        Ok(record)
    }

    pub fn import_or_update_token(
        &self,
        state_dir: &Path,
        state: &mut State,
        email: &str,
        token: &str,
        plan_label: Option<&str>,
    ) -> Result<AccountRecord> {
        let account_id = self
            .find_account_by_email(state, email)
            .map(|a| a.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let acc_dir = account_dir(state_dir, &account_id);
        fs::create_dir_all(&acc_dir)
            .with_context(|| format!("failed to create account dir {}", acc_dir.display()))?;

        let token_path = account_token_file(&acc_dir);
        fs::write(&token_path, token)
            .with_context(|| format!("failed to write {}", token_path.display()))?;

        let now = Utc::now().timestamp();
        let record = AccountRecord {
            id: account_id.clone(),
            email: email.to_string(),
            account_type: AccountType::OAuth,
            provider_id: Some("antigravity-oauth".to_string()),
            project_id: None,
            account_id: None,
            identity_fingerprint: None,
            plan: plan_label.map(ToString::to_string).or_else(|| Some("Antigravity".to_string())),
            auth_path: token_path.to_string_lossy().into_owned(),
            config_path: None,
            oauth_token: Some(token.to_string()),
            refresh_token: None,
            api_key: None,
            added_at: now,
            updated_at: now,
            last_used_at: None,
        };

        if let Some(existing_idx) = state.accounts.iter().position(|a| a.id == record.id) {
            state.accounts[existing_idx] = record.clone();
        } else {
            state.accounts.push(record.clone());
        }

        if !state.usage_cache.contains_key(&record.id) {
            state.usage_cache.insert(
                record.id.clone(),
                UsageSnapshot {
                    plan: record.plan.clone(),
                    status: "Ready".to_string(),
                    cooldown_until: None,
                    remaining_quota_percent: Some(100),
                    last_synced_at: Some(now),
                    last_sync_error: None,
                    needs_relogin: false,
                },
            );
        }

        Ok(record)
    }

    pub fn find_account_by_email<'a>(
        &self,
        state: &'a State,
        email_or_id: &str,
    ) -> Option<&'a AccountRecord> {
        let needle = email_or_id.trim();
        state
            .accounts
            .iter()
            .find(|a| a.email.eq_ignore_ascii_case(needle) || a.id == needle)
    }

    pub fn remove_account(&self, state_dir: &Path, state: &mut State, id: &str) -> Result<()> {
        let acc_dir = account_dir(state_dir, id);
        if acc_dir.exists() {
            let _ = fs::remove_dir_all(&acc_dir);
        }
        state.accounts.retain(|a| a.id != id);
        state.usage_cache.remove(id);
        if state.current_account_id.as_deref() == Some(id) {
            state.current_account_id = None;
        }
        Ok(())
    }
}
