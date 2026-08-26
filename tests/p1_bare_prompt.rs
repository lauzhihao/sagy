#![cfg(unix)]

//! End-to-end argv coverage for the bare prompt shorthand.

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use chrono::Utc;
use sagy::core::state::{AccountRecord, AccountType};
use sagy::core::storage;
use tempfile::TempDir;

const JWT_WITH_FUTURE_EXPIRY: &str = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.fake_signature";

struct Fixture {
    root: TempDir,
    state_dir: PathBuf,
    agy_bin: PathBuf,
    argv_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create fixture root");
        let state_dir = root.path().join("state");
        for path in [
            root.path().join("home"),
            root.path().join("gemini"),
            root.path().join("antigravity"),
        ] {
            fs::create_dir_all(path).expect("create isolated home");
        }
        let account_dir = state_dir.join("accounts").join("bare-prompt-account");
        fs::create_dir_all(&account_dir).expect("create account dir");
        let token_path = account_dir.join("antigravity-oauth-token");
        storage::write_secret_file(&token_path, JWT_WITH_FUTURE_EXPIRY.as_bytes())
            .expect("write token");

        let now = Utc::now().timestamp();
        let account = AccountRecord {
            id: "bare-prompt-account".to_string(),
            email: "bare-prompt@example.test".to_string(),
            account_type: AccountType::OAuth,
            auth_path: token_path.to_string_lossy().into_owned(),
            oauth_token: Some(JWT_WITH_FUTURE_EXPIRY.to_string()),
            added_at: now,
            updated_at: now,
            ..Default::default()
        };
        let state = serde_json::json!({
            "version": 1,
            "accounts": [account],
            "usage_cache": {
                "bare-prompt-account": {
                    "status": "Ready",
                    "remaining_quota_percent": 100,
                    "last_synced_at": now,
                    "needs_relogin": false
                }
            },
            "current_account_id": "bare-prompt-account"
        });
        storage::write_secret_file(
            &state_dir.join("state.json"),
            &serde_json::to_vec_pretty(&state).expect("encode state"),
        )
        .expect("write state");

        let argv_log = root.path().join("agy-argv.log");
        let agy_bin = root.path().join("fake-agy");
        fs::write(
            &agy_bin,
            "#!/bin/sh\n: > \"$AGY_ARGV_LOG\"\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\" >> \"$AGY_ARGV_LOG\"; done\nexit 0\n",
        )
        .expect("write fake agy");
        let mut permissions = fs::metadata(&agy_bin).expect("stat fake agy").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agy_bin, permissions).expect("chmod fake agy");

        Self {
            root,
            state_dir,
            agy_bin,
            argv_log,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
        command
            .arg("--state-dir")
            .arg(&self.state_dir)
            .env("HOME", self.root.path().join("home"))
            .env("SAGY_HOME", self.root.path().join("sagy-home"))
            .env("GEMINI_HOME", self.root.path().join("gemini"))
            .env(
                "ANTIGRAVITY_CONFIG_DIR",
                self.root.path().join("antigravity"),
            )
            .env("AGY_BIN", &self.agy_bin)
            .env("AGY_ARGV_LOG", &self.argv_log)
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("run sagy")
    }

    fn run_os(&self, args: &[OsString]) -> Output {
        self.command().args(args).output().expect("run sagy")
    }

    fn argv(&self) -> Vec<Vec<u8>> {
        fs::read(&self.argv_log)
            .expect("fake agy was not spawned")
            .split(|byte| *byte == b'\n')
            .filter(|arg| !arg.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn bytes(values: &[&str]) -> Vec<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

#[test]
fn bare_prompt_is_compacted_and_does_not_resume() {
    let fixture = Fixture::new();
    let output = fixture.run(&["say", "hi"]);
    assert_success(&output);
    assert_eq!(
        fixture.argv(),
        bytes(&["--model", "gemini-3.7-flash-high", "-p", "say hi"])
    );
}

#[test]
fn unknown_flag_tail_is_preserved_without_guessing_its_value() {
    let fixture = Fixture::new();
    let output = fixture.run(&["say", "hi", "--foo", "bar"]);
    assert_success(&output);
    assert_eq!(
        fixture.argv(),
        bytes(&[
            "--model",
            "gemini-3.7-flash-high",
            "-p",
            "say hi",
            "--foo",
            "bar",
        ])
    );
}

#[test]
fn flag_leading_and_explicit_prompt_inputs_are_forwarded_verbatim() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--foo", "say", "hi"]);
    assert_success(&output);
    assert_eq!(
        fixture.argv(),
        bytes(&["--model", "gemini-3.7-flash-high", "--foo", "say", "hi"])
    );

    let fixture = Fixture::new();
    let output = fixture.run(&["-p", "say hi"]);
    assert_success(&output);
    assert_eq!(
        fixture.argv(),
        bytes(&["--model", "gemini-3.7-flash-high", "-p", "say hi"])
    );
}

#[test]
fn router_delimiter_list_shorthand_becomes_a_new_print_prompt() {
    let fixture = Fixture::new();
    let output = fixture.run(&["--", "list"]);
    assert_success(&output);
    assert_eq!(
        fixture.argv(),
        bytes(&["--model", "gemini-3.7-flash-high", "-p", "list"])
    );
}

#[test]
fn non_utf8_unix_prompt_bytes_survive_compaction() {
    let fixture = Fixture::new();
    let output = fixture.run_os(&[
        OsString::from_vec(b"say\x80".to_vec()),
        OsString::from_vec(b"hi\xff".to_vec()),
    ]);
    assert_success(&output);
    assert_eq!(
        fixture.argv(),
        vec![
            b"--model".to_vec(),
            b"gemini-3.7-flash-high".to_vec(),
            b"-p".to_vec(),
            b"say\x80 hi\xff".to_vec(),
        ]
    );
}
