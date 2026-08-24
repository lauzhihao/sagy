use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::adapters::antigravity::paths::{
    account_dir_checked, find_git_bin, validate_account_id, validate_bundle_dir,
    validate_path_under_root,
};
use crate::core::state::{AccountRecord, STATE_VERSION, State};
use crate::core::storage;

const DEFAULT_BUNDLE_DIR: &str = ".sagy-account-pool";
const BUNDLE_FILENAME: &str = "bundle.enc.json";
const BUNDLE_KEY_ENV: &str = "SAGY_POOL_KEY";
const BUNDLE_ALGORITHM: &str = "xchacha20poly1305-argon2id";
const LEGACY_ALGORITHM: &str = "xchacha20poly1305-sha256";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBundlePayload {
    pub algorithm: String,
    #[serde(default)]
    pub salt: Option<String>,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountPoolBundle {
    pub version: u32,
    pub exported_at: i64,
    pub accounts: Vec<AccountRecord>,
}

#[derive(Debug, Clone)]
pub struct PushOutcome {
    pub changed: bool,
    pub exported_accounts: usize,
}

#[derive(Debug, Clone, Default)]
pub struct PushOptions<'a> {
    pub bundle_dir: Option<&'a str>,
    pub identity_file: Option<&'a Path>,
    pub include_all: bool,
    pub insecure_host_key: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PullOptions<'a> {
    pub bundle_dir: Option<&'a str>,
    pub identity_file: Option<&'a Path>,
    pub insecure_host_key: bool,
}

#[derive(Debug, Clone)]
pub struct PullOutcome {
    pub imported_accounts: usize,
}

struct TempCheckout {
    checkout_dir: PathBuf,
}

impl Drop for TempCheckout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.checkout_dir);
    }
}

impl super::AntigravityAdapter {
    pub fn push_account_pool(
        &self,
        state_dir: &Path,
        state: &State,
        repo: &str,
        opts: PushOptions<'_>,
    ) -> Result<PushOutcome> {
        if state.accounts.is_empty() {
            bail!("No accounts to push in local state");
        }

        let git_bin = find_git_bin().ok_or_else(|| anyhow!("git binary not found in PATH"))?;
        let bundle_key = resolve_bundle_key()?;
        let bundle_dir_str = opts.bundle_dir.unwrap_or(DEFAULT_BUNDLE_DIR);
        validate_bundle_dir(bundle_dir_str)?;
        validate_bundle_accounts(&state.accounts)?;

        let checkout = clone_repo(
            &git_bin,
            state_dir,
            repo,
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        let (bundle_root, _) = prepare_bundle_paths(&checkout.checkout_dir, bundle_dir_str, false)?;

        let accounts_to_export: Vec<AccountRecord> = if opts.include_all {
            state.accounts.clone()
        } else {
            state
                .accounts
                .iter()
                .filter(|a| {
                    a.oauth_token.is_some() || a.api_key.is_some() || a.refresh_token.is_some()
                })
                .cloned()
                .collect()
        };

        if accounts_to_export.is_empty() {
            bail!("No exportable accounts with active credentials to push (use --all to force)");
        }
        let exported_count = accounts_to_export.len();

        let pool_bundle = AccountPoolBundle {
            version: STATE_VERSION,
            exported_at: chrono::Utc::now().timestamp(),
            accounts: accounts_to_export,
        };

        let raw_json = serde_json::to_vec_pretty(&pool_bundle)?;
        let encrypted_payload = encrypt_bytes(&raw_json, &bundle_key)?;
        let enc_json = serde_json::to_vec_pretty(&encrypted_payload)?;

        storage::create_secure_dir_all(&bundle_root)?;
        let (_, bundle_path) = prepare_bundle_paths(&checkout.checkout_dir, bundle_dir_str, false)?;
        fs::write(&bundle_path, enc_json)?;

        git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["add", "--", bundle_dir_str],
            opts.identity_file,
            opts.insecure_host_key,
        )?;

        let status_out = git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["status", "--porcelain"],
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        if status_out.stdout.is_empty() {
            return Ok(PushOutcome {
                changed: false,
                exported_accounts: exported_count,
            });
        }

        git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &[
                "-c",
                "user.name=sagy-agent",
                "-c",
                "user.email=sagy@local",
                "commit",
                "-m",
                "chore(sagy): sync encrypted account pool",
            ],
            opts.identity_file,
            opts.insecure_host_key,
        )?;

        git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["push", "origin", "HEAD"],
            opts.identity_file,
            opts.insecure_host_key,
        )?;

        Ok(PushOutcome {
            changed: true,
            exported_accounts: exported_count,
        })
    }

    pub fn pull_account_pool(
        &self,
        state_dir: &Path,
        state: &mut State,
        repo: &str,
        opts: PullOptions<'_>,
    ) -> Result<PullOutcome> {
        let git_bin = find_git_bin().ok_or_else(|| anyhow!("git binary not found in PATH"))?;
        let bundle_key = resolve_bundle_key()?;
        let bundle_dir_str = opts.bundle_dir.unwrap_or(DEFAULT_BUNDLE_DIR);
        validate_bundle_dir(bundle_dir_str)?;

        let checkout = clone_repo(
            &git_bin,
            state_dir,
            repo,
            opts.identity_file,
            opts.insecure_host_key,
        )?;
        let (_, bundle_path) = prepare_bundle_paths(&checkout.checkout_dir, bundle_dir_str, false)?;

        if !bundle_path.exists() {
            bail!(
                "Bundle file {} does not exist in repository {}",
                BUNDLE_FILENAME,
                redact_git_text(repo)
            );
        }

        let enc_content = fs::read(&bundle_path)?;
        let payload: EncryptedBundlePayload = serde_json::from_slice(&enc_content)
            .context("failed to parse encrypted bundle payload JSON")?;

        let decrypted_bytes = decrypt_bytes(&payload, &bundle_key)?;
        let bundle: AccountPoolBundle = serde_json::from_slice(&decrypted_bytes)
            .context("failed to decode decrypted account pool bundle JSON")?;
        validate_bundle_accounts(&bundle.accounts)?;
        let mut imported_count = 0;
        for mut account in bundle.accounts {
            let acc_dir = account_dir_checked(state_dir, &account.id)?;
            storage::create_secure_dir_all(&acc_dir)?;
            let acc_dir = account_dir_checked(state_dir, &account.id)?;

            if let Some(token) = &account.oauth_token {
                let token_file = super::paths::account_token_file(&acc_dir);
                validate_secret_target(&acc_dir, &token_file)?;
                storage::write_secret_file(&token_file, token.as_bytes())?;
                account.auth_path = token_file.to_string_lossy().into_owned();
            } else if let Some(api_key) = &account.api_key {
                let cred_file = super::paths::account_credentials_file(&acc_dir);
                validate_secret_target(&acc_dir, &cred_file)?;
                let creds_json = serde_json::json!({
                    "api_key": api_key,
                    "email": account.email,
                    "project_id": account.project_id,
                });
                storage::write_secret_file(
                    &cred_file,
                    serde_json::to_string_pretty(&creds_json)
                        .unwrap_or_default()
                        .as_bytes(),
                )?;
                account.auth_path = cred_file.to_string_lossy().into_owned();
            } else {
                let cred_file = super::paths::account_credentials_file(&acc_dir);
                validate_secret_target(&acc_dir, &cred_file)?;
                if !cred_file.exists() && account.refresh_token.is_some() {
                    let creds_json = serde_json::json!({
                        "email": account.email,
                        "refresh_token": account.refresh_token,
                        "project_id": account.project_id,
                    });
                    storage::write_secret_file(
                        &cred_file,
                        serde_json::to_string_pretty(&creds_json)
                            .unwrap_or_default()
                            .as_bytes(),
                    )?;
                }
                account.auth_path = cred_file.to_string_lossy().into_owned();
            }

            if !state.usage_cache.contains_key(&account.id) {
                state.usage_cache.insert(
                    account.id.clone(),
                    crate::core::state::UsageSnapshot {
                        plan: account.plan.clone(),
                        status: "Ready".to_string(),
                        cooldown_until: None,
                        remaining_quota_percent: Some(100),
                        last_synced_at: Some(chrono::Utc::now().timestamp()),
                        last_sync_error: None,
                        needs_relogin: false,
                    },
                );
            }

            if let Some(idx) = state.accounts.iter().position(|a| a.id == account.id) {
                state.accounts[idx] = account;
            } else {
                state.accounts.push(account);
            }
            imported_count += 1;
        }

        Ok(PullOutcome {
            imported_accounts: imported_count,
        })
    }
}

fn resolve_bundle_key() -> Result<String> {
    if let Ok(key) = env::var(BUNDLE_KEY_ENV) {
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    bail!("Environment variable `{BUNDLE_KEY_ENV}` is not set. Please provide an encryption key.")
}

fn derive_key_argon2id(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params =
        Params::new(19456, 2, 1, Some(32)).map_err(|e| anyhow!("Argon2 params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("KDF failed: {e}"))?;
    Ok(key_bytes)
}

fn encrypt_bytes(data: &[u8], password: &str) -> Result<EncryptedBundlePayload> {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);

    let key_bytes = derive_key_argon2id(password, &salt_bytes)?;
    let key = Key::from_slice(&key_bytes);

    let cipher = XChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    Ok(EncryptedBundlePayload {
        algorithm: BUNDLE_ALGORITHM.to_string(),
        salt: Some(BASE64_STANDARD.encode(salt_bytes)),
        nonce: BASE64_STANDARD.encode(nonce_bytes),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    })
}

fn decrypt_bytes(payload: &EncryptedBundlePayload, password: &str) -> Result<Vec<u8>> {
    let key_bytes = if payload.algorithm == BUNDLE_ALGORITHM {
        let salt_b64 = payload
            .salt
            .as_deref()
            .ok_or_else(|| anyhow!("Missing salt in encrypted bundle payload"))?;
        let salt_bytes = BASE64_STANDARD
            .decode(salt_b64)
            .context("Invalid base64 salt")?;
        derive_key_argon2id(password, &salt_bytes)?
    } else if payload.algorithm == LEGACY_ALGORITHM {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        arr
    } else {
        bail!("Unsupported encryption algorithm: {}", payload.algorithm);
    };

    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let nonce_bytes = BASE64_STANDARD
        .decode(&payload.nonce)
        .context("Invalid base64 nonce")?;
    let ciphertext = BASE64_STANDARD
        .decode(&payload.ciphertext)
        .context("Invalid base64 ciphertext")?;

    if nonce_bytes.len() != 24 {
        bail!("Invalid nonce length: expected 24 bytes");
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed: incorrect key or corrupted bundle"))
}

fn clone_repo(
    git_bin: &Path,
    state_dir: &Path,
    repo: &str,
    identity_file: Option<&Path>,
    insecure_host_key: bool,
) -> Result<TempCheckout> {
    storage::create_secure_dir_all(state_dir)?;
    validate_path_under_root(state_dir, state_dir)?;
    let tmp_root = storage::tmp_dir(state_dir);
    storage::create_secure_dir_all(&tmp_root)?;
    validate_path_under_root(state_dir, &tmp_root)?;
    let checkout_dir = tmp_root.join(format!("repo-sync-{}", Uuid::new_v4()));
    validate_path_under_root(state_dir, &checkout_dir)?;

    let mut args = vec!["clone", "--depth", "1", "--", repo];
    let checkout_str = checkout_dir.to_string_lossy();
    args.push(&checkout_str);

    git_cmd(git_bin, state_dir, &args, identity_file, insecure_host_key)?;
    validate_path_under_root(state_dir, &checkout_dir)?;
    let checkout_metadata = fs::metadata(&checkout_dir)
        .with_context(|| format!("git clone did not create {}", checkout_dir.display()))?;
    if !checkout_metadata.is_dir() {
        bail!(
            "git clone destination is not a directory: {}",
            checkout_dir.display()
        );
    }

    Ok(TempCheckout { checkout_dir })
}

fn git_cmd(
    git_bin: &Path,
    cwd: &Path,
    args: &[&str],
    identity_file: Option<&Path>,
    insecure_host_key: bool,
) -> Result<Output> {
    let mut cmd = Command::new(git_bin);
    cmd.current_dir(cwd);
    cmd.args(args);

    if let Some(id_file) = identity_file {
        let identity_path = id_file.to_str().ok_or_else(|| {
            anyhow!(
                "SSH identity path is not valid UTF-8: {}",
                id_file.display()
            )
        })?;
        let mut ssh_cmd = format!(
            "ssh -i {} -o IdentitiesOnly=yes",
            shell_quote_for_git(identity_path)
        );
        if insecure_host_key {
            eprintln!(
                "[sagy] WARNING: StrictHostKeyChecking is disabled (--insecure-host-key). This connection is vulnerable to MITM attacks."
            );
            ssh_cmd.push_str(" -o StrictHostKeyChecking=no");
        }
        cmd.env("GIT_SSH_COMMAND", ssh_cmd);
    }

    let safe_args = args
        .iter()
        .map(|arg| redact_git_text(arg))
        .collect::<Vec<_>>();
    let output = cmd
        .output()
        .with_context(|| format!("failed to execute git command: {:?}", safe_args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = redact_git_text(stderr.trim());
        if detail.is_empty() {
            bail!("git {:?} failed", safe_args);
        }
        bail!("git {:?} failed: {}", safe_args, detail);
    }

    Ok(output)
}

fn prepare_bundle_paths(
    checkout_dir: &Path,
    bundle_dir: &str,
    create_root: bool,
) -> Result<(PathBuf, PathBuf)> {
    validate_bundle_dir(bundle_dir)?;
    validate_path_under_root(checkout_dir, checkout_dir)?;

    let bundle_root = checkout_dir.join(bundle_dir);
    validate_path_under_root(checkout_dir, &bundle_root)?;
    if create_root {
        storage::create_secure_dir_all(&bundle_root)?;
        validate_path_under_root(checkout_dir, &bundle_root)?;
    }

    let bundle_path = bundle_root.join(BUNDLE_FILENAME);
    validate_path_under_root(checkout_dir, &bundle_path)?;
    Ok((bundle_root, bundle_path))
}

fn validate_secret_target(account_dir: &Path, target: &Path) -> Result<()> {
    validate_path_under_root(account_dir, target)?;
    if let Ok(metadata) = fs::symlink_metadata(target) {
        if metadata.file_type().is_symlink() {
            bail!(
                "credential target cannot be a symlink: {}",
                target.display()
            );
        }
    }
    Ok(())
}

fn validate_bundle_accounts(accounts: &[AccountRecord]) -> Result<()> {
    let mut ids = HashSet::with_capacity(accounts.len());
    for account in accounts {
        validate_account_id(&account.id)
            .with_context(|| format!("invalid account id in bundle: {:?}", account.id))?;
        if !ids.insert(account.id.as_str()) {
            bail!("duplicate account id in bundle: {:?}", account.id);
        }
    }
    Ok(())
}

fn shell_quote_for_git(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

fn redact_git_text(text: &str) -> String {
    text.split_whitespace()
        .map(redact_git_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_git_token(token: &str) -> String {
    let Some(scheme_end) = token.find("://") else {
        let Some(at) = token.find('@') else {
            return token.to_string();
        };
        let prefix = &token[..at];
        let Some(separator) = prefix.rfind(':') else {
            return token.to_string();
        };
        if separator == 0 {
            return token.to_string();
        }
        return format!("{}***@{}", &token[..separator + 1], &token[at + 1..]);
    };

    let scheme_start = token[..scheme_end]
        .rfind(|ch: char| !ch.is_ascii_alphanumeric() && ch != '+' && ch != '-' && ch != '.')
        .map(|index| index + 1)
        .unwrap_or(0);
    if scheme_start == scheme_end {
        return token.to_string();
    }

    let authority_start = scheme_end + 3;
    let authority_end = token[authority_start..]
        .find(['/', '?', '#', '"', '\'', ')', ']', ','])
        .map(|offset| authority_start + offset)
        .unwrap_or(token.len());
    let authority = &token[authority_start..authority_end];
    let Some(at) = authority.rfind('@') else {
        return token.to_string();
    };

    format!(
        "{}***@{}{}",
        &token[..authority_start],
        &authority[at + 1..],
        &token[authority_end..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let password = "test_super_secret_pool_key_123456";
        let original_data = b"{\"email\":\"user@google.com\",\"token\":\"sample_token_data\"}";

        let encrypted = encrypt_bytes(original_data, password).expect("encryption should succeed");
        assert_eq!(encrypted.algorithm, BUNDLE_ALGORITHM);

        let decrypted = decrypt_bytes(&encrypted, password).expect("decryption should succeed");
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_decryption_wrong_key() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let original_data = b"secret payload";

        let encrypted = encrypt_bytes(original_data, password).expect("encryption should succeed");
        let result = decrypt_bytes(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_git_identity_path_is_single_shell_argument() {
        let path = "/tmp/key with spaces; touch /tmp/pwned '$HOME'";
        let quoted = shell_quote_for_git(path);
        assert_eq!(
            quoted,
            "'/tmp/key with spaces; touch /tmp/pwned '\\''$HOME'\\'''"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_git_identity_path_cannot_execute_shell_metacharacters() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let fake_git = temp.path().join("fake-git");
        fs::write(
            &fake_git,
            "#!/bin/sh\nsh -c \"$GIT_SSH_COMMAND\" >/dev/null 2>&1 || true\nexit 0\n",
        )
        .expect("fake git");
        let mut permissions = fs::metadata(&fake_git)
            .expect("fake git metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&fake_git, permissions).expect("fake git permissions");

        let marker = temp.path().join("injected");
        let identity = temp
            .path()
            .join(format!("key with spaces; touch {}", marker.display()));
        git_cmd(&fake_git, temp.path(), &["status"], Some(&identity), false)
            .expect("fake git should exit successfully");
        assert!(!marker.exists(), "identity path enabled shell injection");
    }

    #[test]
    fn test_git_error_redacts_url_userinfo() {
        let text = "fatal: https://alice:s3cret@example.test/pool.git: denied";
        let redacted = redact_git_text(text);
        assert!(!redacted.contains("s3cret"));
        assert!(redacted.contains("***@example.test"));
    }

    #[test]
    fn test_duplicate_bundle_ids_fail_closed() {
        let account = AccountRecord {
            id: "account-1".to_string(),
            ..AccountRecord::default()
        };
        let result = validate_bundle_accounts(&[account.clone(), account]);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_bundle_target_symlink_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let checkout = temp.path().join("checkout");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&checkout).expect("checkout");
        fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, checkout.join(".sagy-account-pool"))
            .expect("bundle symlink");

        let result = prepare_bundle_paths(&checkout, ".sagy-account-pool", false);
        assert!(result.is_err());
    }
}
