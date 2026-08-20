use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::adapters::antigravity::paths::{
    account_credentials_file, account_dir, account_token_file,
    default_antigravity_cli_home, default_gemini_home,
};
use crate::core::state::{AccountRecord, AccountType, State, UsageSnapshot};
use crate::core::storage;

pub fn is_valid_oauth_credential(json: &Value) -> bool {
    if !json.is_object() {
        return false;
    }
    json.get("access_token").is_some()
        || json.get("refresh_token").is_some()
        || json.get("token").is_some()
        || json.get("client_secret").is_some()
        || json.get("type").and_then(Value::as_str) == Some("authorized_user")
        || json.get("type").and_then(Value::as_str) == Some("service_account")
}

pub fn is_valid_api_key_credential(json: &Value) -> bool {
    if !json.is_object() {
        return false;
    }
    json.get("api_key").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).is_some()
}

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

        // 2. Try importing ~/.gemini/oauth_creds.json
        if let Some(gemini_home) = default_gemini_home() {
            let oauth_path = gemini_home.join("oauth_creds.json");
            if oauth_path.is_file() {
                if let Ok(record) = self.import_auth_path(state_dir, state, &oauth_path) {
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

        // Validate that this JSON actually contains recognizable credentials
        let is_api = is_valid_api_key_credential(&json_val);
        let is_service_account = json_val.get("type").and_then(Value::as_str) == Some("service_account");
        let is_oauth = is_valid_oauth_credential(&json_val);

        if !is_api && !is_service_account && !is_oauth {
            bail!(
                "File {} does not contain valid Antigravity or Gemini credentials (must contain token, oauth keys, or api_key)",
                raw_path.display()
            );
        }

        // Try reading active email from google_accounts.json if not present in the cred file
        let mut email_opt = json_val
            .get("email")
            .or_else(|| json_val.get("client_email"))
            .or_else(|| json_val.get("account"))
            .or_else(|| json_val.get("user"))
            .and_then(Value::as_str)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if email_opt.is_none() {
            if let Some(gemini_home) = default_gemini_home() {
                let google_accounts_path = gemini_home.join("google_accounts.json");
                if google_accounts_path.is_file() {
                    if let Ok(ga_content) = fs::read_to_string(&google_accounts_path) {
                        if let Ok(ga_json) = serde_json::from_str::<Value>(&ga_content) {
                            if let Some(active_email) = ga_json.get("active").and_then(Value::as_str) {
                                let trimmed = active_email.trim();
                                if !trimmed.is_empty() {
                                    email_opt = Some(trimmed.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        let email = email_opt.unwrap_or_else(|| {
            if let Some(stem) = raw_path.file_stem().and_then(|s| s.to_str()) {
                if stem == "oauth_creds" {
                    "google-oauth-user@gemini".to_string()
                } else {
                    format!("{stem}@gemini")
                }
            } else {
                "imported-account@gemini".to_string()
            }
        });

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
            account_type: if is_api {
                AccountType::ApiKey
            } else if is_service_account {
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
            plan: if is_api {
                Some("Gemini API Key".to_string())
            } else if is_service_account {
                Some("Vertex AI".to_string())
            } else {
                Some("Antigravity OAuth".to_string())
            },
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
            plan: plan_label.map(ToString::to_string).or_else(|| Some("Antigravity OAuth".to_string())),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_oauth_credential() {
        let valid_oauth = serde_json::json!({
            "access_token": "ya29.sample",
            "refresh_token": "1//sample",
            "token_type": "Bearer"
        });
        assert!(is_valid_oauth_credential(&valid_oauth));

        let google_accounts_json = serde_json::json!({
            "active": "user@gmail.com",
            "old": []
        });
        assert!(!is_valid_oauth_credential(&google_accounts_json));

        let random_json = serde_json::json!({
            "foo": "bar"
        });
        assert!(!is_valid_oauth_credential(&random_json));
    }

    #[test]
    fn test_is_valid_api_key_credential() {
        let valid_api = serde_json::json!({
            "api_key": "AIzaSySampleKey123"
        });
        assert!(is_valid_api_key_credential(&valid_api));

        let invalid_api = serde_json::json!({
            "api_key": "   "
        });
        assert!(!is_valid_api_key_credential(&invalid_api));
    }

    #[test]
    fn test_import_auth_path_rejects_google_accounts_json() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();
        let ga_file = state_dir.join("google_accounts.json");
        fs::write(&ga_file, r#"{"active":"test@gmail.com","old":[]}"#).expect("write ga");

        let adapter = crate::adapters::antigravity::AntigravityAdapter::default();
        let mut state = State::default();
        let result = adapter.import_auth_path(state_dir, &mut state, &ga_file);
        assert!(result.is_err());
    }
}

