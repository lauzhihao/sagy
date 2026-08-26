//! Provider-managed Gemini sessions must remain outside sagy's portable store.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::SystemTime;

use serde_json::json;
use tempfile::TempDir;

const ACCESS_TOKEN: &str = "provider-access-token-fixture";
const REFRESH_TOKEN: &str = "provider-refresh-token-fixture";

struct Fixture {
    _temp: TempDir,
    home: PathBuf,
    gemini: PathBuf,
    antigravity: PathBuf,
    state: PathBuf,
    fake_agy: PathBuf,
    spawn_marker: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create fixture");
        let root = temp.path().to_path_buf();
        let fixture = Self {
            _temp: temp,
            home: root.join("home"),
            gemini: root.join("gemini"),
            antigravity: root.join("antigravity"),
            state: root.join("state"),
            fake_agy: root.join("fake-agy"),
            spawn_marker: root.join("agy-spawned"),
        };
        for directory in [&fixture.home, &fixture.gemini, &fixture.antigravity] {
            fs::create_dir_all(directory).expect("create fixture directory");
        }
        fixture.write_fake_agy();
        fixture.write_empty_state();
        fixture
    }

    fn write_fake_agy(&self) {
        fs::write(
            &self.fake_agy,
            format!(
                "#!/bin/sh\nprintf spawned > '{}'\nexit 0\n",
                self.spawn_marker.display()
            ),
        )
        .expect("write fake agy");
        let mut permissions = fs::metadata(&self.fake_agy)
            .expect("stat fake agy")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&self.fake_agy, permissions).expect("make fake agy executable");
    }

    fn write_empty_state(&self) {
        fs::create_dir_all(&self.state).expect("create state directory");
        fs::write(
            self.state.join("state.json"),
            serde_json::to_vec_pretty(&json!({
                "version": 2,
                "revision": 1,
                "accounts": [],
                "usage_cache": {},
                "current_account_id": null,
                "active_profile": null,
                "sync_watermarks": {}
            }))
            .expect("serialize empty state"),
        )
        .expect("write empty state");
    }

    fn oauth_creds(&self, body: &str) -> PathBuf {
        let path = self.gemini.join("oauth_creds.json");
        fs::write(&path, body).expect("write oauth_creds.json");
        path
    }

    fn companion_token(&self) -> PathBuf {
        let path = self.antigravity.join("antigravity-oauth-token");
        fs::write(&path, b"companion-token-fixture").expect("write companion token");
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .args(args)
            .env("HOME", &self.home)
            .env("SAGY_HOME", &self.state)
            .env("GEMINI_HOME", &self.gemini)
            .env("ANTIGRAVITY_CONFIG_DIR", &self.antigravity)
            .env("AGY_BIN", &self.fake_agy)
            .output()
            .expect("run sagy")
    }
}

fn provider_session() -> String {
    serde_json::to_string(&json!({
        "access_token": ACCESS_TOKEN,
        "expiry_date": 4_102_444_800u64,
        "id_token": "",
        "refresh_token": REFRESH_TOKEN,
        "scope": "",
        "token_type": "Bearer"
    }))
    .expect("serialize provider session")
}

fn legacy_authorized_user() -> &'static str {
    r#"{"type":"authorized_user","client_id":"client-fixture","client_secret":"secret-fixture","refresh_token":"legacy-refresh-fixture","token_uri":"https://oauth2.googleapis.com/token"}"#
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .expect("stat fixture file")
        .modified()
        .expect("read fixture mtime")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn import_known_rejects_provider_session_without_mutation() {
    let fixture = Fixture::new();
    let oauth_path = fixture.oauth_creds(&provider_session());
    let companion_path = fixture.companion_token();
    let state_path = fixture.state.join("state.json");
    let oauth_before = fs::read(&oauth_path).expect("read oauth fixture");
    let companion_before = fs::read(&companion_path).expect("read companion fixture");
    let state_before = fs::read(&state_path).expect("read state fixture");
    let mtimes_before = (
        mtime(&oauth_path),
        mtime(&companion_path),
        mtime(&state_path),
    );

    let output = fixture.run(&["import-known"]);
    let text = combined(&output);
    assert!(
        !output.status.success(),
        "provider session was imported: {text}"
    );
    assert!(
        text.contains("provider-managed session"),
        "unexpected error: {text}"
    );
    assert!(
        text.contains("system credential store"),
        "unexpected error: {text}"
    );
    assert!(
        text.contains("run `agy` directly"),
        "unexpected error: {text}"
    );
    assert!(
        !text.contains(ACCESS_TOKEN),
        "access token leaked in error: {text}"
    );
    assert!(
        !text.contains(REFRESH_TOKEN),
        "refresh token leaked in error: {text}"
    );
    assert_eq!(
        fs::read(&oauth_path).expect("read oauth after import"),
        oauth_before
    );
    assert_eq!(
        fs::read(&companion_path).expect("read companion after import"),
        companion_before
    );
    assert_eq!(
        fs::read(&state_path).expect("read state after import"),
        state_before
    );
    assert_eq!(
        (
            mtime(&oauth_path),
            mtime(&companion_path),
            mtime(&state_path)
        ),
        mtimes_before,
        "provider session rejection changed a managed file"
    );
}

#[test]
fn launch_auto_discovery_fails_before_spawning_agy() {
    let fixture = Fixture::new();
    fixture.oauth_creds(&provider_session());
    fixture.companion_token();

    let output = fixture.run(&["say", "hi"]);
    let text = combined(&output);
    assert!(
        !output.status.success(),
        "launch unexpectedly succeeded: {text}"
    );
    assert!(
        text.contains("provider-managed session"),
        "unexpected error: {text}"
    );
    assert!(
        !fixture.spawn_marker.exists(),
        "fake agy was spawned despite provider-session rejection"
    );
}

#[test]
fn legacy_authorized_user_remains_importable() {
    let fixture = Fixture::new();
    fixture.oauth_creds(legacy_authorized_user());

    let output = fixture.run(&["import-known"]);
    let text = combined(&output);
    assert!(output.status.success(), "legacy import failed: {text}");
    assert!(
        text.contains("Imported account"),
        "unexpected output: {text}"
    );
    assert!(fixture.state.join("accounts").is_dir());
}
