#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use fs2::FileExt;
use sagy::core::credential::{GOOGLE_AUTH_ENV_VARS, PortableCredential};
use sagy::core::state::{AccountType, CredentialRefKind, ManagedLayout, SlotState};
use sagy::core::storage;
use serde_json::json;
use sha2::{Digest, Sha256};

const PARENT_API_KEY: &str = "parent-api-key";
const PARENT_CREDENTIALS: &str = "/parent/stale-credentials.json";
const PARENT_PROJECT: &str = "parent-stale-project";

struct Harness {
    _temp: tempfile::TempDir,
    state_dir: PathBuf,
    home_dir: PathBuf,
    fake_agy: PathBuf,
    observed_env: PathBuf,
    observed_dump: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let home_dir = temp.path().join("home");
        let fake_agy = temp.path().join("fake-agy");
        let observed_env = temp.path().join("observed-env");
        let observed_dump = temp.path().join("observed-google-auth-env");
        fs::create_dir_all(&home_dir).expect("create isolated home");
        write_fake_agy(&fake_agy);
        Self {
            _temp: temp,
            state_dir,
            home_dir,
            fake_agy,
            observed_env,
            observed_dump,
        }
    }

    fn account_credentials_path(&self, account_id: &str, filename: &str) -> PathBuf {
        self.state_dir
            .join("accounts")
            .join(account_id)
            .join(filename)
    }

    fn write_credentials(&self, account_id: &str, filename: &str, content: &str) -> PathBuf {
        let path = self.account_credentials_path(account_id, filename);
        storage::write_secret_file(&path, content.as_bytes()).expect("write credentials fixture");
        path
    }

    #[allow(clippy::too_many_arguments)]
    fn save_v2_account(
        &self,
        account_id: &str,
        email: &str,
        account_type: AccountType,
        project_id: Option<&str>,
        reference_kind: CredentialRefKind,
        credential: &PortableCredential,
        managed_layout: ManagedLayout,
    ) {
        let state = json!({
            "version": 2,
            "revision": 1,
            "accounts": [{
                "id": account_id,
                "email": email,
                "account_type": account_type,
                "provider_id": null,
                "project_id": project_id,
                "account_id": null,
                "plan": null,
                "added_at": 1,
                "updated_at": 1,
                "last_used_at": null,
                "credential_ref": {
                    "kind": reference_kind,
                    "fingerprint": credential.fingerprint()
                }
            }],
            "usage_cache": {
                (account_id): {
                    "health": "ready",
                    "remaining_quota_percent": 100,
                    "last_probe_at": Utc::now().timestamp()
                }
            },
            "current_account_id": account_id,
            "active_profile": {
                "account_id": account_id,
                "credential_fingerprint": credential.fingerprint(),
                "home_scope_id": self.home_scope_id(),
                "managed_layout": managed_layout
            },
            "sync_watermarks": {}
        });
        let bytes = serde_json::to_vec_pretty(&state).expect("serialize v2 state fixture");
        storage::write_secret_file(&self.state_dir.join("state.json"), &bytes)
            .expect("save v2 state fixture");
    }

    fn home_scope_id(&self) -> String {
        let antigravity = self.home_dir.join("antigravity");
        let gemini = self.home_dir.join("gemini");
        fs::create_dir_all(&antigravity).expect("create antigravity home");
        fs::create_dir_all(&gemini).expect("create gemini home");
        let antigravity = fs::canonicalize(antigravity).expect("canonicalize antigravity home");
        let gemini = fs::canonicalize(gemini).expect("canonicalize gemini home");
        let representation = format!(
            "{}\0{}",
            antigravity.to_string_lossy().replace('\\', "/"),
            gemini.to_string_lossy().replace('\\', "/")
        );
        let mut digest = Sha256::new();
        digest.update(b"sagy/active-home/v1\0");
        digest.update(representation.as_bytes());
        format!("{:x}", digest.finalize())
    }

    fn run(&self) -> Output {
        self.run_with_parent_env(&[])
    }

    /// `parent_env` 是父进程额外注入的变量, 用来验证 deny-list 的清理范围。
    fn run_with_parent_env(&self, parent_env: &[(&str, &str)]) -> Output {
        let _ = fs::remove_file(&self.observed_env);
        let _ = fs::remove_file(&self.observed_dump);
        let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
        for (name, value) in parent_env {
            command.env(name, value);
        }
        command
            .env("HOME", &self.home_dir)
            .env("SAGY_HOME", &self.state_dir)
            .env("ANTIGRAVITY_CONFIG_DIR", self.home_dir.join("antigravity"))
            .env("GEMINI_HOME", self.home_dir.join("gemini"))
            .env("AGY_BIN", &self.fake_agy)
            .env("FAKE_AGY_OUTPUT", &self.observed_env)
            .env("FAKE_AGY_ENV_DUMP", &self.observed_dump)
            .env("GEMINI_API_KEY", PARENT_API_KEY)
            .env("GOOGLE_APPLICATION_CREDENTIALS", PARENT_CREDENTIALS)
            .env("GOOGLE_CLOUD_PROJECT", PARENT_PROJECT)
            .args([
                "--state-dir",
                self.state_dir.to_str().expect("UTF-8 state path"),
                "launch",
                "--no-import-known",
                "--no-resume",
            ])
            .output()
            .expect("run sagy")
    }

    fn observed(&self) -> String {
        fs::read_to_string(&self.observed_env).expect("fake agy should record environment")
    }

    /// `NAME=value` / `NAME=<unset>` for every Google authentication variable.
    fn observed_google_auth_env(&self) -> Vec<String> {
        fs::read_to_string(&self.observed_dump)
            .expect("fake agy should dump the Google auth environment")
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[test]
fn child_auth_environment_is_rebuilt_for_each_account_type() {
    let vertex = Harness::new();
    let vertex_document = r#"{"type":"service_account","project_id":"selected-vertex-project","private_key":"-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n","client_email":"vertex@example.test","token_uri":"https://oauth2.example.test/token"}"#;
    let vertex_path =
        vertex.write_credentials("vertex-account", "credentials.json", vertex_document);
    let vertex_credential =
        PortableCredential::from_native_json_str(vertex_document).expect("parse Vertex fixture");
    vertex.save_v2_account(
        "vertex-account",
        "vertex@example.test",
        AccountType::Vertex,
        Some("selected-vertex-project"),
        CredentialRefKind::VertexServiceAccount,
        &vertex_credential,
        ManagedLayout::default(),
    );
    assert_success(vertex.run(), "Vertex launch");
    let vertex_path = fs::canonicalize(vertex_path).expect("canonicalize Vertex path");
    assert_eq!(
        vertex.observed(),
        expected_env(None, Some(&vertex_path), Some("selected-vertex-project"))
    );

    let api_key = Harness::new();
    let api_document = r#"{"api_key":"selected-api-key","label":"fixture"}"#;
    api_key.write_credentials("api-account", "credentials.json", api_document);
    let api_credential =
        PortableCredential::from_native_json_str(api_document).expect("parse API fixture");
    api_key.save_v2_account(
        "api-account",
        "api@example.test",
        AccountType::ApiKey,
        Some("ignored-api-project"),
        CredentialRefKind::ApiKey,
        &api_credential,
        ManagedLayout::default(),
    );
    assert_success(api_key.run(), "API key launch");
    assert_eq!(
        api_key.observed(),
        expected_env(Some("selected-api-key"), None, None)
    );

    let oauth = Harness::new();
    let oauth_token = "oauth-access-token";
    let oauth_path =
        oauth.write_credentials("oauth-account", "antigravity-oauth-token", oauth_token);
    let oauth_credential =
        PortableCredential::oauth_access_token(oauth_token).expect("parse OAuth fixture");
    let active_path = oauth
        .home_dir
        .join("antigravity")
        .join("antigravity-oauth-token");
    if let Some(parent) = active_path.parent() {
        fs::create_dir_all(parent).expect("create active token parent");
    }
    storage::write_secret_file(&active_path, oauth_token.as_bytes())
        .expect("write active OAuth token");
    oauth.save_v2_account(
        "oauth-account",
        "oauth@example.test",
        AccountType::OAuth,
        Some("selected-oauth-project"),
        CredentialRefKind::OauthAccessToken,
        &oauth_credential,
        ManagedLayout {
            antigravity_token: SlotState::Exact {
                sha256: sha256_hex(oauth_token.as_bytes()),
            },
            gemini_authorized_user: SlotState::Absent,
        },
    );
    assert_success(oauth.run(), "OAuth launch");
    assert_eq!(
        oauth.observed(),
        expected_env(None, None, Some("selected-oauth-project"))
    );
    assert!(oauth_path.exists());

    let authorized = Harness::new();
    let authorized_document = r#"{"type":"authorized_user","client_id":"client-id","client_secret":"client-secret","refresh_token":"refresh-token","token_uri":"https://oauth2.googleapis.com/token"}"#;
    authorized.write_credentials(
        "authorized-account",
        "credentials.json",
        authorized_document,
    );
    let authorized_credential = PortableCredential::from_native_json_str(authorized_document)
        .expect("parse authorized-user fixture");
    let active_document = authorized.home_dir.join("gemini").join("oauth_creds.json");
    if let Some(parent) = active_document.parent() {
        fs::create_dir_all(parent).expect("create active authorized-user parent");
    }
    storage::write_secret_file(&active_document, authorized_document.as_bytes())
        .expect("write active authorized-user document");
    authorized.save_v2_account(
        "authorized-account",
        "authorized@example.test",
        AccountType::OAuth,
        Some("selected-authorized-project"),
        CredentialRefKind::OauthAuthorizedUser,
        &authorized_credential,
        ManagedLayout {
            antigravity_token: SlotState::Absent,
            gemini_authorized_user: SlotState::Exact {
                sha256: sha256_hex(authorized_document.as_bytes()),
            },
        },
    );
    assert_success(authorized.run(), "authorized-user launch");
    assert_eq!(
        authorized.observed(),
        expected_env(None, None, Some("selected-authorized-project"))
    );
}

/// AC-R5-4.2: 父进程设置整张 Google 认证 deny-list 后启动, 子进程只能看到
/// 当前账号类型重建出来的那几个, 其余一律 `<unset>`。
#[test]
fn the_parent_google_auth_environment_never_reaches_the_child() {
    let harness = Harness::new();
    let document = valid_vertex_document();
    harness.write_credentials("vertex-account", "credentials.json", document);
    let credential =
        PortableCredential::from_native_json_str(document).expect("parse Vertex fixture");
    harness.save_v2_account(
        "vertex-account",
        "vertex@example.test",
        AccountType::Vertex,
        Some("selected-project"),
        CredentialRefKind::VertexServiceAccount,
        &credential,
        ManagedLayout::default(),
    );

    // 工单点名的三个之外, 整张表都由父进程注入, 一个都不能漏。
    let parent_env = GOOGLE_AUTH_ENV_VARS
        .iter()
        .map(|name| (*name, "parent-inherited-value"))
        .collect::<Vec<_>>();
    assert!(parent_env.iter().any(|(name, _)| *name == "GOOGLE_API_KEY"));
    assert!(
        parent_env
            .iter()
            .any(|(name, _)| *name == "GOOGLE_GENAI_USE_VERTEXAI")
    );
    assert!(
        parent_env
            .iter()
            .any(|(name, _)| *name == "GOOGLE_CLOUD_LOCATION")
    );

    assert_success(
        harness.run_with_parent_env(&parent_env),
        "Vertex launch with a fully populated parent auth environment",
    );

    // 这次 launch 只应重建 GOOGLE_APPLICATION_CREDENTIALS 与 GOOGLE_CLOUD_PROJECT。
    let credentials_path =
        fs::canonicalize(harness.account_credentials_path("vertex-account", "credentials.json"))
            .expect("canonicalize Vertex path");
    let expected = GOOGLE_AUTH_ENV_VARS
        .iter()
        .map(|name| match *name {
            "GOOGLE_APPLICATION_CREDENTIALS" => {
                format!(
                    "GOOGLE_APPLICATION_CREDENTIALS={}",
                    credentials_path.display()
                )
            }
            "GOOGLE_CLOUD_PROJECT" => "GOOGLE_CLOUD_PROJECT=selected-project".to_string(),
            other => format!("{other}=<unset>"),
        })
        .collect::<Vec<_>>();
    assert_eq!(harness.observed_google_auth_env(), expected);
}

#[test]
fn invalid_vertex_configuration_never_spawns_agy() {
    let cases = [
        "missing-path",
        "directory-path",
        "symlink-path",
        "missing-project",
        "empty-project",
        "active-home-mismatch",
    ];

    for case in cases {
        let harness = Harness::new();
        let account_id = "vertex-account";
        let credentials = harness.account_credentials_path(account_id, "credentials.json");
        let project_id = match case {
            "missing-path" => Some("selected-project".to_string()),
            "directory-path" => {
                fs::create_dir_all(&credentials).expect("create invalid credential directory");
                Some("selected-project".to_string())
            }
            "symlink-path" => {
                let outside = harness._temp.path().join("outside-credentials.json");
                fs::write(&outside, valid_vertex_document()).expect("write outside fixture");
                fs::create_dir_all(credentials.parent().expect("credential parent"))
                    .expect("create credential parent");
                std::os::unix::fs::symlink(&outside, &credentials)
                    .expect("create credential symlink");
                Some("selected-project".to_string())
            }
            "missing-project" => {
                harness.write_credentials(account_id, "credentials.json", valid_vertex_document());
                None
            }
            "empty-project" => {
                harness.write_credentials(account_id, "credentials.json", valid_vertex_document());
                Some("   ".to_string())
            }
            "active-home-mismatch" => {
                harness.write_credentials(account_id, "credentials.json", valid_vertex_document());
                let active = harness.home_dir.join("antigravity");
                fs::create_dir_all(&active).expect("create active home");
                fs::write(active.join("antigravity-oauth-token"), b"unexpected-token")
                    .expect("write mismatched active token");
                Some("selected-project".to_string())
            }
            _ => unreachable!(),
        };

        let credential = if credentials.is_file() {
            PortableCredential::from_native_json_str(
                &fs::read_to_string(&credentials).expect("read Vertex fixture"),
            )
            .expect("parse Vertex fixture")
        } else {
            PortableCredential::vertex_service_account(json!({
                "type": "service_account",
                "project_id": "selected-project",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nprivate\\n-----END PRIVATE KEY-----\\n",
                "client_email": "vertex@example.test",
                "token_uri": "https://oauth2.example.test/token"
            }))
            .expect("create Vertex fixture")
        };
        harness.save_v2_account(
            account_id,
            "vertex@example.test",
            AccountType::Vertex,
            project_id.as_deref(),
            CredentialRefKind::VertexServiceAccount,
            &credential,
            ManagedLayout::default(),
        );

        let output = harness.run();
        assert!(
            !output.status.success(),
            "invalid Vertex case {case} unexpectedly succeeded"
        );
        assert!(
            !harness.observed_env.exists(),
            "invalid Vertex case {case} spawned agy"
        );
    }
}

#[test]
fn account_lease_blocks_switch_until_launcher_releases_it() {
    let harness = Harness::new();
    let document = valid_vertex_document();
    harness.write_credentials("blocked-account", "credentials.json", document);
    let credential =
        PortableCredential::from_native_json_str(document).expect("parse Vertex fixture");
    harness.save_v2_account(
        "blocked-account",
        "blocked@example.test",
        AccountType::Vertex,
        Some("selected-project"),
        CredentialRefKind::VertexServiceAccount,
        &credential,
        ManagedLayout::default(),
    );

    let lock_path = harness.account_credentials_path("blocked-account", ".sagy-credential.lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open account lease");
    lock_file.lock_exclusive().expect("hold account lease");
    let observed = harness.observed_env.clone();
    let runner = thread::spawn(move || {
        let output = harness.run();
        (harness, output)
    });
    thread::sleep(Duration::from_millis(250));
    assert!(
        !observed.exists(),
        "agy spawned while the selected account lease was held"
    );
    lock_file.unlock().expect("release account lease");
    let (_harness, output) = runner.join().expect("join launcher process runner");
    assert_success(output.clone(), "launch after account lease release");
    assert!(
        observed.exists(),
        "agy did not run after account lease release: stdout={} stderr={} path={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        observed.display()
    );
}

fn assert_success(output: Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn expected_env(
    api_key: Option<&str>,
    credentials: Option<&Path>,
    project: Option<&str>,
) -> String {
    format!(
        "GEMINI_API_KEY={}\nGOOGLE_APPLICATION_CREDENTIALS={}\nGOOGLE_CLOUD_PROJECT={}\n",
        api_key.unwrap_or("<unset>"),
        credentials
            .map(|path| path.to_string_lossy().into_owned())
            .as_deref()
            .unwrap_or("<unset>"),
        project.unwrap_or("<unset>")
    )
}

fn write_fake_agy(path: &Path) {
    // deny-list 的清理范围只能由子进程亲眼所见来证明, 所以 fake agy 把整张表
    // 的实际可见性 dump 出来, 而不是由测试去读 launcher 的内部函数。
    let dump = GOOGLE_AUTH_ENV_VARS
        .iter()
        .map(|name| {
            format!(
                "if [ \"${{{name}+x}}\" = x ]; then\n    printf '{name}=%s\\n' \"${name}\"\nelse\n    printf '{name}=<unset>\\n'\nfi\n"
            )
        })
        .collect::<String>();
    let script = format!(
        r#"#!/bin/sh
set -eu
if [ "${{FAKE_AGY_ENV_DUMP+x}}" = x ]; then
(
{dump}) > "$FAKE_AGY_ENV_DUMP"
fi
exec > "$FAKE_AGY_OUTPUT"
if [ "${{GEMINI_API_KEY+x}}" = x ]; then
    printf 'GEMINI_API_KEY=%s\n' "$GEMINI_API_KEY"
else
    printf 'GEMINI_API_KEY=<unset>\n'
fi
if [ "${{GOOGLE_APPLICATION_CREDENTIALS+x}}" = x ]; then
    printf 'GOOGLE_APPLICATION_CREDENTIALS=%s\n' "$GOOGLE_APPLICATION_CREDENTIALS"
else
    printf 'GOOGLE_APPLICATION_CREDENTIALS=<unset>\n'
fi
if [ "${{GOOGLE_CLOUD_PROJECT+x}}" = x ]; then
    printf 'GOOGLE_CLOUD_PROJECT=%s\n' "$GOOGLE_CLOUD_PROJECT"
else
    printf 'GOOGLE_CLOUD_PROJECT=<unset>\n'
fi
"#
    );
    fs::write(path, script).expect("write fake agy");
    make_executable(path);
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("stat fake agy").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("chmod fake agy");
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn valid_vertex_document() -> &'static str {
    r#"{"type":"service_account","project_id":"selected-project","private_key":"-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n","client_email":"vertex@example.test","token_uri":"https://oauth2.example.test/token"}"#
}
