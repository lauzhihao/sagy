use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use tempfile::TempDir;

use sagy::core::storage;

fn account(id: &str) -> Value {
    json!({
        "id": id,
        "email": "account@example.test",
        "account_type": "oauth",
        "oauth_token": "synthetic-secret-token"
    })
}

fn state_json(accounts: Vec<Value>) -> Value {
    json!({ "accounts": accounts })
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .expect("inspect victim file")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .expect("inspect fixture file")
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).expect("set fixture file mode");
}

fn write_state(state_dir: &Path, state: &Value) {
    fs::create_dir_all(state_dir).expect("create state dir");
    fs::write(
        state_dir.join("state.json"),
        serde_json::to_vec_pretty(state).expect("serialize state fixture"),
    )
    .expect("write state fixture");
}

struct Fixture {
    _temp: TempDir,
    state_dir: PathBuf,
    outside_dir: PathBuf,
    state_marker: PathBuf,
    state_credentials: PathBuf,
    outside_marker: PathBuf,
    outside_credentials: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let outside_dir = temp.path().join("outside");
        fs::create_dir_all(&state_dir).expect("create state dir");
        fs::create_dir_all(&outside_dir).expect("create outside dir");

        let state_marker = state_dir.join("outside-marker");
        let state_credentials = state_dir.join("credentials.json");
        let outside_marker = outside_dir.join("outside-marker");
        let outside_credentials = outside_dir.join("credentials.json");
        fs::write(&state_marker, b"state-marker-before").expect("write state marker");
        fs::write(&state_credentials, b"state-credential-before").expect("write state credential");
        fs::write(&outside_marker, b"outside-marker-before").expect("write outside marker");
        fs::write(&outside_credentials, b"outside-credential-before")
            .expect("write outside credential");

        Self {
            _temp: temp,
            state_dir,
            outside_dir,
            state_marker,
            state_credentials,
            outside_marker,
            outside_credentials,
        }
    }

    fn assert_outside_unchanged(&self) {
        assert_eq!(
            fs::read(&self.state_marker).expect("read state marker"),
            b"state-marker-before"
        );
        assert_eq!(
            fs::read(&self.state_credentials).expect("read state credential"),
            b"state-credential-before"
        );
        assert_eq!(
            fs::read(&self.outside_marker).expect("read outside marker"),
            b"outside-marker-before"
        );
        assert_eq!(
            fs::read(&self.outside_credentials).expect("read outside credential"),
            b"outside-credential-before"
        );
    }

    fn assert_rejected(&self) {
        let error =
            storage::load_state(&self.state_dir).expect_err("unsafe state unexpectedly loaded");
        let rendered = error.to_string();
        assert!(
            !rendered.contains("synthetic-secret-token"),
            "state error leaked secret: {rendered}"
        );
        self.assert_outside_unchanged();
    }
}

#[test]
fn load_state_rejects_unsafe_account_ids_before_normalization() {
    let fixture = Fixture::new();
    let absolute_id = fixture.outside_dir.to_string_lossy().into_owned();
    write_state(&fixture.state_dir, &state_json(vec![account(&absolute_id)]));
    fixture.assert_rejected();
    assert!(
        !fixture.outside_dir.join("antigravity-oauth-token").exists(),
        "absolute account id created a credential outside the state directory"
    );

    let fixture = Fixture::new();
    write_state(&fixture.state_dir, &state_json(vec![account("..")]));
    fixture.assert_rejected();
    assert!(
        !fixture.state_dir.join("antigravity-oauth-token").exists(),
        "parent account id created a credential in the state directory"
    );
}

#[test]
fn load_state_rejects_duplicate_and_dangling_references() {
    let fixture = Fixture::new();
    write_state(
        &fixture.state_dir,
        &state_json(vec![account("duplicate"), account("duplicate")]),
    );
    fixture.assert_rejected();

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["current_account_id"] = json!("missing");
    write_state(&fixture.state_dir, &state);
    fixture.assert_rejected();

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["current_account_id"] = json!("../invalid");
    write_state(&fixture.state_dir, &state);
    fixture.assert_rejected();

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["usage_cache"] = json!({ "missing": { "status": "Ready" } });
    write_state(&fixture.state_dir, &state);
    fixture.assert_rejected();

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["usage_cache"] = json!({ "../invalid": { "status": "Ready" } });
    write_state(&fixture.state_dir, &state);
    fixture.assert_rejected();
}

#[cfg(unix)]
#[test]
fn load_state_rejects_symlinked_account_directory_before_normalization() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let accounts_dir = fixture.state_dir.join("accounts");
    fs::create_dir_all(&accounts_dir).expect("create accounts dir");
    symlink(&fixture.outside_dir, accounts_dir.join("safe-account"))
        .expect("create account symlink");
    write_state(
        &fixture.state_dir,
        &state_json(vec![account("safe-account")]),
    );

    fixture.assert_rejected();
    assert!(
        !fixture.outside_dir.join("antigravity-oauth-token").exists(),
        "symlinked account directory created a credential outside the state directory"
    );
}

#[cfg(unix)]
#[test]
fn load_state_rejects_state_root_symlink_before_touching_target() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let victim_state = fixture.outside_dir.join("state.json");
    let victim_bytes = br#"{"accounts":[]}"#;
    fs::write(&victim_state, victim_bytes).expect("write victim state");
    set_file_mode(&victim_state, 0o644);
    let mode_before = file_mode(&victim_state);
    let state_root_link = fixture
        .state_dir
        .parent()
        .expect("fixture parent")
        .join("state-root-link");
    symlink(&fixture.outside_dir, &state_root_link).expect("create state root symlink");

    let error = storage::load_state(&state_root_link).expect_err("state root symlink accepted");
    assert!(!error.to_string().contains("synthetic-secret-token"));
    assert_eq!(
        fs::read(&victim_state).expect("read victim state"),
        victim_bytes
    );
    assert_eq!(file_mode(&victim_state), mode_before);
}

#[cfg(unix)]
#[test]
fn load_state_rejects_state_file_symlink_before_touching_target() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let victim_state = fixture.outside_dir.join("victim-state.json");
    let victim_bytes = br#"{"accounts":[]}"#;
    fs::write(&victim_state, victim_bytes).expect("write victim state");
    set_file_mode(&victim_state, 0o644);
    let mode_before = file_mode(&victim_state);
    symlink(&victim_state, fixture.state_dir.join("state.json"))
        .expect("create state file symlink");

    let error = storage::load_state(&fixture.state_dir).expect_err("state file symlink accepted");
    assert!(!error.to_string().contains("synthetic-secret-token"));
    assert_eq!(
        fs::read(&victim_state).expect("read victim state"),
        victim_bytes
    );
    assert_eq!(file_mode(&victim_state), mode_before);
}

#[test]
fn load_state_cleans_legacy_placeholder_before_validating_references() {
    let fixture = Fixture::new();
    let placeholder_id = "../legacy-placeholder";
    let state = json!({
        "accounts": [{
            "id": placeholder_id,
            "email": "google_accounts"
        }],
        "current_account_id": placeholder_id,
        "usage_cache": {
            (placeholder_id): { "health": "unverified" }
        }
    });
    write_state(&fixture.state_dir, &state);

    let loaded = storage::load_state(&fixture.state_dir)
        .expect("legacy placeholder should be cleaned before validation");
    assert!(loaded.accounts.is_empty());
    assert!(loaded.current_account_id.is_none());
    assert!(loaded.usage_cache.is_empty());
    assert!(!fixture.state_dir.join("accounts").exists());
}

#[test]
fn load_state_accepts_legacy_state_without_version() {
    let fixture = Fixture::new();
    write_state(
        &fixture.state_dir,
        &state_json(vec![account("legacy-account")]),
    );

    let loaded = storage::load_state(&fixture.state_dir).expect("load legacy state");
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.accounts.len(), 1);
    assert_eq!(loaded.accounts[0].id, "legacy-account");
    assert_eq!(
        fs::read_to_string(
            fixture
                .state_dir
                .join("accounts/legacy-account/antigravity-oauth-token")
        )
        .expect("normalized legacy token"),
        "synthetic-secret-token"
    );
}

#[test]
fn cli_rejects_invalid_state_with_isolated_home() {
    let fixture = Fixture::new();
    let absolute_id = fixture.outside_dir.to_string_lossy().into_owned();
    write_state(&fixture.state_dir, &state_json(vec![account(&absolute_id)]));
    let home = fixture.state_dir.join("isolated-home");
    fs::create_dir_all(&home).expect("create isolated home");
    let home_marker = home.join("marker");
    fs::write(&home_marker, b"home-marker-before").expect("write home marker");

    let output = Command::new(env!("CARGO_BIN_EXE_sagy"))
        .env("HOME", &home)
        .env("SAGY_HOME", &fixture.state_dir)
        .env("ANTIGRAVITY_CONFIG_DIR", home.join("antigravity"))
        .env("GEMINI_HOME", home.join("gemini"))
        .args([
            "--state-dir",
            fixture.state_dir.to_str().expect("UTF-8 state path"),
            "list",
        ])
        .output()
        .expect("run sagy");

    assert!(
        !output.status.success(),
        "invalid state unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("synthetic-secret-token"),
        "CLI error leaked secret: {stderr}"
    );
    assert_eq!(
        fs::read(&home_marker).expect("read home marker"),
        b"home-marker-before"
    );
    fixture.assert_outside_unchanged();
}
