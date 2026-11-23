#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    agy: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profiles");
        let agy = temp.path().join("fake-agy");
        fs::write(
            &agy,
            r#"#!/usr/bin/env python3
import json, os, pathlib, sys
if "/usage" in sys.argv:
    print(json.dumps({"status":"SUCCESS","command":{"name":"usage","data":{"groups":[]}}}))
    raise SystemExit(0)
with open(os.environ["SAGY_ADD_LOG"], "a") as log:
    log.write(os.environ["HOME"] + "\n")
if os.environ.get("SAGY_ADD_FAIL"):
    raise SystemExit(17)
path = pathlib.Path(os.environ["HOME"]) / ".gemini/antigravity-cli/antigravity-oauth-token"
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps({"token":{"refresh_token":os.environ["SAGY_ADD_TOKEN"]}}))
path.chmod(0o600)
"#,
        )
        .unwrap();
        fs::set_permissions(&agy, fs::Permissions::from_mode(0o700)).unwrap();
        Self { temp, root, agy }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
        command
            .args(args)
            .env("SAGY_PROFILE_ROOT", &self.root)
            .env("AGY_BIN", &self.agy)
            .env("SAGY_ADD_LOG", self.temp.path().join("calls"))
            .env("SAGY_ADD_TOKEN", "synthetic-add-token")
            .env_remove("SAGY_ADD_FAIL");
        command
    }

    fn token(&self, label: &str) -> PathBuf {
        self.root
            .join("profiles")
            .join(label)
            .join("home/.gemini/antigravity-cli/antigravity-oauth-token")
    }
}

#[test]
fn add_enrolls_an_email_and_login_reuses_the_same_native_registry() {
    let fixture = Fixture::new();
    for (action, label, token) in [
        ("add", "first@example.test", "synthetic-first"),
        ("login", "second@example.test", "synthetic-second"),
    ] {
        let output = fixture
            .command(&[action, label])
            .env("SAGY_ADD_TOKEN", token)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stored: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.token(label)).unwrap()).unwrap();
        assert_eq!(stored["token"]["refresh_token"], token);
    }
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("state.json")).unwrap()).unwrap();
    assert_eq!(
        state["profiles"],
        serde_json::json!(["first@example.test", "second@example.test"])
    );
    let first: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.token("first@example.test")).unwrap()).unwrap();
    assert_eq!(first["token"]["refresh_token"], "synthetic-first");
    let homes = fs::read_to_string(fixture.temp.path().join("calls")).unwrap();
    let homes: Vec<_> = homes.lines().collect();
    assert_eq!(homes.len(), 2);
    assert_ne!(homes[0], homes[1]);
}

#[test]
fn add_help_and_invalid_arguments_do_not_start_sign_in() {
    let fixture = Fixture::new();
    for args in [&["add", "--help"][..], &["help", "add"]] {
        let output = fixture.command(args).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("sagy add NAME"));
    }
    for args in [&["add"][..], &["add", "../bad"], &["add", "one", "extra"]] {
        assert!(!fixture.command(args).output().unwrap().status.success());
    }
    assert!(!fixture.temp.path().join("calls").exists());
    assert!(!fixture.root.exists());
}

#[test]
fn failed_add_does_not_register_an_unfinished_account() {
    let fixture = Fixture::new();
    let output = fixture
        .command(&["add", "failed@example.test"])
        .env("SAGY_ADD_FAIL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(17));
    let state_path = fixture.root.join("state.json");
    if state_path.exists() {
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(state_path).unwrap()).unwrap();
        assert!(
            !state["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|name| name == "failed@example.test")
        );
    }
    assert!(!fixture.token("failed@example.test").exists());
}
