#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use sagy::core::state::{AccountRecord, AccountType};
use sagy::core::storage;

struct Fixture {
    _temp: tempfile::TempDir,
    state_dir: PathBuf,
    home: PathBuf,
    gemini_home: PathBuf,
    antigravity_home: PathBuf,
    fake_agy: PathBuf,
    launch_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let home = temp.path().join("home");
        let gemini_home = temp.path().join("gemini");
        let antigravity_home = temp.path().join("antigravity");
        let fake_agy = temp.path().join("fake-agy");
        let launch_log = temp.path().join("launch.log");
        for path in [&home, &gemini_home, &antigravity_home] {
            fs::create_dir_all(path).expect("create isolated home");
        }
        write_fake_agy(&fake_agy);
        write_legacy_pool(&state_dir);
        Self {
            _temp: temp,
            state_dir,
            home,
            gemini_home,
            antigravity_home,
            fake_agy,
            launch_log,
        }
    }

    fn run(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .args([
                "--state-dir",
                self.state_dir.to_str().expect("UTF-8 state path"),
                "launch",
                "--no-import-known",
                "--no-resume",
            ])
            .env("HOME", &self.home)
            .env("GEMINI_HOME", &self.gemini_home)
            .env("ANTIGRAVITY_CONFIG_DIR", &self.antigravity_home)
            .env("AGY_BIN", &self.fake_agy)
            .env("FAKE_AGY_LAUNCH_LOG", &self.launch_log)
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT")
            .output()
            .expect("run sagy")
    }
}

#[test]
fn canonical_child_429_enters_cooldown_and_falls_back_once() {
    let fixture = Fixture::new();
    let output = fixture.run();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let launches = fs::read_to_string(&fixture.launch_log).expect("read launch order");
    assert_eq!(
        launches.lines().collect::<Vec<_>>(),
        ["token-one", "token-two"]
    );

    let state: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.state_dir.join("state.json")).expect("read v2 state"),
    )
    .expect("parse v2 state");
    assert_eq!(state["version"], 2);
    assert_eq!(state["current_account_id"], "fallback-two");
    assert_eq!(
        state["usage_cache"]["fallback-one"]["health"],
        "rate_limited"
    );
    assert!(state["usage_cache"]["fallback-one"]["cooldown"].is_object());
}

fn write_legacy_pool(state_dir: &Path) {
    let now = Utc::now().timestamp();
    let accounts = [
        ("fallback-one", "one@example.test", "token-one"),
        ("fallback-two", "two@example.test", "token-two"),
    ]
    .into_iter()
    .map(|(id, email, token)| {
        let path = state_dir
            .join("accounts")
            .join(id)
            .join("antigravity-oauth-token");
        storage::write_secret_file(&path, token.as_bytes()).expect("write fixed token");
        AccountRecord {
            id: id.to_string(),
            email: email.to_string(),
            account_type: AccountType::OAuth,
            auth_path: path.to_string_lossy().into_owned(),
            oauth_token: Some(token.to_string()),
            added_at: now,
            updated_at: now,
            ..Default::default()
        }
    })
    .collect::<Vec<_>>();
    let usage = serde_json::json!({
        "status": "Ready",
        "remaining_quota_percent": 50,
        "last_synced_at": now,
        "needs_relogin": false
    });
    let state = serde_json::json!({
        "version": 1,
        "accounts": accounts,
        "usage_cache": {
            "fallback-one": usage.clone(),
            "fallback-two": usage
        },
        "current_account_id": "fallback-one"
    });
    storage::write_secret_file(
        &state_dir.join("state.json"),
        &serde_json::to_vec_pretty(&state).expect("encode legacy state"),
    )
    .expect("write legacy state");
}

fn write_fake_agy(path: &Path) {
    fs::write(
        path,
        r#"#!/bin/sh
set -eu
token=$(cat "$ANTIGRAVITY_CONFIG_DIR/antigravity-oauth-token")
printf '%s\n' "$token" >> "$FAKE_AGY_LAUNCH_LOG"
if [ "$token" = "token-one" ]; then
    printf '%s\n' '{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","Retry-After":45}}' >&2
    exit 1
fi
exit 0
"#,
    )
    .expect("write fake agy");
    let mut permissions = fs::metadata(path).expect("stat fake agy").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("chmod fake agy");
}
