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

use crate::adapters::antigravity::paths::{account_dir, find_git_bin};
use crate::core::state::{AccountRecord, STATE_VERSION, State};
use crate::core::storage;

const DEFAULT_BUNDLE_DIR: &str = ".sagy-account-pool";
const BUNDLE_FILENAME: &str = "bundle.enc.json";
const BUNDLE_KEY_ENV: &str = "SAGY_POOL_KEY";
const BUNDLE_ALGORITHM: &str = "xchacha20poly1305-sha256";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBundlePayload {
    pub algorithm: String,
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
        bundle_dir: Option<&str>,
        identity_file: Option<&Path>,
        _include_all: bool,
    ) -> Result<PushOutcome> {
        if state.accounts.is_empty() {
            bail!("No accounts to push in local state");
        }

        let git_bin = find_git_bin().ok_or_else(|| anyhow!("git binary not found in PATH"))?;
        let bundle_key = resolve_bundle_key()?;
        let bundle_dir_str = bundle_dir.unwrap_or(DEFAULT_BUNDLE_DIR);

        let checkout = clone_repo(&git_bin, state_dir, repo, identity_file)?;
        let bundle_root = checkout.checkout_dir.join(bundle_dir_str);
        let bundle_path = bundle_root.join(BUNDLE_FILENAME);

        let pool_bundle = AccountPoolBundle {
            version: STATE_VERSION,
            exported_at: chrono::Utc::now().timestamp(),
            accounts: state.accounts.clone(),
        };

        let raw_json = serde_json::to_vec_pretty(&pool_bundle)?;
        let encrypted_payload = encrypt_bytes(&raw_json, &bundle_key)?;
        let enc_json = serde_json::to_vec_pretty(&encrypted_payload)?;

        fs::create_dir_all(&bundle_root)?;
        fs::write(&bundle_path, enc_json)?;

        git_cmd(&git_bin, &checkout.checkout_dir, &["add", bundle_dir_str], identity_file)?;

        let status_out = git_cmd(
            &git_bin,
            &checkout.checkout_dir,
            &["status", "--porcelain"],
            identity_file,
        )?;
        if status_out.stdout.is_empty() {
            return Ok(PushOutcome {
                changed: false,
                exported_accounts: state.accounts.len(),
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
            identity_file,
        )?;

        git_cmd(&git_bin, &checkout.checkout_dir, &["push", "origin", "HEAD"], identity_file)?;

        Ok(PushOutcome {
            changed: true,
            exported_accounts: state.accounts.len(),
        })
    }

    pub fn pull_account_pool(
        &self,
        state_dir: &Path,
        state: &mut State,
        repo: &str,
        bundle_dir: Option<&str>,
        identity_file: Option<&Path>,
    ) -> Result<PullOutcome> {
        let git_bin = find_git_bin().ok_or_else(|| anyhow!("git binary not found in PATH"))?;
        let bundle_key = resolve_bundle_key()?;
        let bundle_dir_str = bundle_dir.unwrap_or(DEFAULT_BUNDLE_DIR);

        let checkout = clone_repo(&git_bin, state_dir, repo, identity_file)?;
        let bundle_path = checkout.checkout_dir.join(bundle_dir_str).join(BUNDLE_FILENAME);

        if !bundle_path.exists() {
            bail!(
                "Bundle file {} does not exist in repository {}",
                BUNDLE_FILENAME,
                repo
            );
        }

        let enc_content = fs::read(&bundle_path)?;
        let payload: EncryptedBundlePayload = serde_json::from_slice(&enc_content)
            .context("failed to parse encrypted bundle payload JSON")?;

        let decrypted_bytes = decrypt_bytes(&payload, &bundle_key)?;
        let bundle: AccountPoolBundle = serde_json::from_slice(&decrypted_bytes)
            .context("failed to decode decrypted account pool bundle JSON")?;

        let mut imported_count = 0;
        for account in bundle.accounts {
            let acc_dir = account_dir(state_dir, &account.id);
            fs::create_dir_all(&acc_dir)?;

            if let Some(token) = &account.oauth_token {
                let token_file = super::paths::account_token_file(&acc_dir);
                fs::write(&token_file, token)?;
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
    bail!(
        "Environment variable `{BUNDLE_KEY_ENV}` is not set. Please provide an encryption key."
    )
}

fn encrypt_bytes(data: &[u8], password: &str) -> Result<EncryptedBundlePayload> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();
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
        nonce: BASE64_STANDARD.encode(nonce_bytes),
        ciphertext: BASE64_STANDARD.encode(ciphertext),
    })
}

fn decrypt_bytes(payload: &EncryptedBundlePayload, password: &str) -> Result<Vec<u8>> {
    if payload.algorithm != BUNDLE_ALGORITHM {
        bail!("Unsupported encryption algorithm: {}", payload.algorithm);
    }

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key_bytes = hasher.finalize();
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
) -> Result<TempCheckout> {
    let tmp_root = storage::tmp_dir(state_dir);
    fs::create_dir_all(&tmp_root)?;
    let checkout_dir = tmp_root.join(format!("repo-sync-{}", Uuid::new_v4()));

    let mut args = vec!["clone", "--depth", "1", repo];
    let checkout_str = checkout_dir.to_string_lossy();
    args.push(&checkout_str);

    git_cmd(git_bin, state_dir, &args, identity_file)?;

    Ok(TempCheckout { checkout_dir })
}

fn git_cmd(
    git_bin: &Path,
    cwd: &Path,
    args: &[&str],
    identity_file: Option<&Path>,
) -> Result<Output> {
    let mut cmd = Command::new(git_bin);
    cmd.current_dir(cwd);
    cmd.args(args);

    if let Some(id_file) = identity_file {
        cmd.env(
            "GIT_SSH_COMMAND",
            format!(
                "ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no",
                id_file.display()
            ),
        );
    }

    let output = cmd
        .output()
        .with_context(|| format!("failed to execute git command: {:?}", args))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {:?} failed: {}", args, stderr.trim());
    }

    Ok(output)
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
}

