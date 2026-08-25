//! P0 boundaries for the production state read path.
//!
//! 这些用例过去打在 legacy 的 `storage::load_state` 上，而生产路径早已不再走它。
//! 现在全部改为驱动真实二进制（`StateSession` -> `StateStore` -> atomic 层），
//! 让每一条安全断言重新守在用户实际会走的那条路上。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

/// 读取端愿意读的最大 state 文档；与 `state_store::MAX_STATE_BYTES` 保持一致。
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
const SECRET: &str = "synthetic-secret-token";

fn account(id: &str) -> Value {
    json!({
        "id": id,
        "email": "account@example.test",
        "account_type": "oauth",
        "oauth_token": SECRET
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

/// 顶层条目里被隔离改名的损坏文档（`state.json.corrupt-<uuid>`）。
fn quarantined_documents(state_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(state_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("state.json.corrupt-"))
        })
        .collect()
}

struct Fixture {
    _temp: TempDir,
    state_dir: PathBuf,
    home_dir: PathBuf,
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
        let home_dir = temp.path().join("home");
        fs::create_dir_all(&state_dir).expect("create state dir");
        fs::create_dir_all(&outside_dir).expect("create outside dir");
        fs::create_dir_all(&home_dir).expect("create isolated home");

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
            home_dir,
            outside_dir,
            state_marker,
            state_credentials,
            outside_marker,
            outside_credentials,
        }
    }

    /// 驱动真实生产读路径：`sagy list` 是最短的一条"打开 state 并读完"的命令。
    fn run_list_in(&self, state_dir: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .env("HOME", &self.home_dir)
            .env("SAGY_HOME", state_dir)
            .env("ANTIGRAVITY_CONFIG_DIR", self.home_dir.join("antigravity"))
            .env("GEMINI_HOME", self.home_dir.join("gemini"))
            .args([
                "--state-dir",
                state_dir.to_str().expect("UTF-8 state path"),
                "list",
            ])
            .output()
            .expect("run sagy")
    }

    fn run_list(&self) -> Output {
        self.run_list_in(&self.state_dir)
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

    /// 拒绝一份不安全/不合法的 state：命令必须失败、不得泄漏 secret、
    /// 不得触碰 state root 之外的任何东西，而且——按 R1-1——不得把一份
    /// 语义失败但语法完好的文档改名隔离。
    fn assert_rejected(&self) -> String {
        let before = fs::read(self.state_dir.join("state.json")).expect("read state fixture");
        let output = self.run_list();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            !output.status.success(),
            "unsafe state unexpectedly loaded: {stderr}"
        );
        assert!(
            !stderr.contains(SECRET),
            "state error leaked secret: {stderr}"
        );
        assert_eq!(
            fs::read(self.state_dir.join("state.json")).expect("state document disappeared"),
            before,
            "a semantic failure rewrote or moved state.json"
        );
        assert!(
            quarantined_documents(&self.state_dir).is_empty(),
            "a semantic failure quarantined state.json"
        );
        self.assert_outside_unchanged();
        stderr
    }
}

#[test]
fn production_read_rejects_unsafe_account_ids_before_normalization() {
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
fn production_read_rejects_duplicate_and_dangling_references() {
    let fixture = Fixture::new();
    write_state(
        &fixture.state_dir,
        &state_json(vec![account("duplicate"), account("duplicate")]),
    );
    let stderr = fixture.assert_rejected();
    assert!(
        stderr.contains("duplicate account ids"),
        "unexpected rejection reason: {stderr}"
    );

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["current_account_id"] = json!("missing");
    write_state(&fixture.state_dir, &state);
    let stderr = fixture.assert_rejected();
    assert!(
        stderr.contains("current account does not exist"),
        "unexpected rejection reason: {stderr}"
    );

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["current_account_id"] = json!("../invalid");
    write_state(&fixture.state_dir, &state);
    fixture.assert_rejected();

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["usage_cache"] = json!({ "missing": { "status": "Ready" } });
    write_state(&fixture.state_dir, &state);
    let stderr = fixture.assert_rejected();
    assert!(
        stderr.contains("usage cache refers to a missing account"),
        "unexpected rejection reason: {stderr}"
    );

    let fixture = Fixture::new();
    let mut state = state_json(vec![account("present")]);
    state["usage_cache"] = json!({ "../invalid": { "status": "Ready" } });
    write_state(&fixture.state_dir, &state);
    fixture.assert_rejected();
}

#[cfg(unix)]
#[test]
fn production_read_rejects_symlinked_account_directory_before_normalization() {
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

    let stderr = fixture.assert_rejected();
    // R1-6.1: 只读校验必须先于权限收紧跑，否则这里报的会是一句笼统的
    // "cannot tighten permissions through a symlink"。
    assert!(
        stderr.contains("account directory cannot be a symlink: safe-account"),
        "layout validation did not run before permission hardening: {stderr}"
    );
    assert!(
        !fixture.outside_dir.join("antigravity-oauth-token").exists(),
        "symlinked account directory created a credential outside the state directory"
    );
}

#[cfg(unix)]
#[test]
fn production_read_rejects_state_root_symlink_before_touching_target() {
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

    let output = fixture.run_list_in(&state_root_link);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "state root symlink accepted");
    assert!(!stderr.contains(SECRET));
    assert!(
        stderr.contains("symlink or reparse point"),
        "unexpected rejection reason: {stderr}"
    );
    assert_eq!(
        fs::read(&victim_state).expect("read victim state"),
        victim_bytes
    );
    assert_eq!(file_mode(&victim_state), mode_before);
    assert!(quarantined_documents(&fixture.outside_dir).is_empty());
}

#[cfg(unix)]
#[test]
fn production_read_rejects_state_file_symlink_before_touching_target() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let victim_state = fixture.outside_dir.join("victim-state.json");
    let victim_bytes = br#"{"accounts":[]}"#;
    fs::write(&victim_state, victim_bytes).expect("write victim state");
    set_file_mode(&victim_state, 0o644);
    let mode_before = file_mode(&victim_state);
    symlink(&victim_state, fixture.state_dir.join("state.json"))
        .expect("create state file symlink");

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "state file symlink accepted");
    assert!(!stderr.contains(SECRET));
    assert!(
        stderr.contains("symlink or reparse point"),
        "unexpected rejection reason: {stderr}"
    );
    assert_eq!(
        fs::read(&victim_state).expect("read victim state"),
        victim_bytes
    );
    assert_eq!(file_mode(&victim_state), mode_before);
    // 隔离绝不能顺着 symlink 把用户 state root 之外的文档改名。
    assert!(
        fixture
            .state_dir
            .join("state.json")
            .symlink_metadata()
            .is_ok(),
        "the state.json symlink was moved aside"
    );
    assert!(quarantined_documents(&fixture.state_dir).is_empty());
}

#[test]
fn production_read_cleans_legacy_placeholder_before_validating_references() {
    let fixture = Fixture::new();
    let placeholder_id = "../legacy-placeholder";
    let state = json!({
        "accounts": [{
            "id": placeholder_id,
            "email": "google_accounts"
        }],
        "current_account_id": placeholder_id,
        "usage_cache": {
            (placeholder_id): { "status": "Ready" }
        }
    });
    write_state(&fixture.state_dir, &state);

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "legacy placeholder should be cleaned before validation: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No accounts registered"),
        "unexpected listing: {stdout}"
    );
    assert!(!fixture.state_dir.join("accounts").exists());
}

#[test]
fn production_read_accepts_legacy_state_without_version() {
    let fixture = Fixture::new();
    write_state(
        &fixture.state_dir,
        &state_json(vec![account("legacy-account")]),
    );

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "legacy state rejected: {stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("account@example.test"),
        "legacy account was not listed: {stdout}"
    );
    // v1 -> v2 迁移会把内嵌 token 落到凭据存储里。落点必须在 state root 之内、
    // 必须是 0600，而且新文档里不得再出现明文 token。
    let credential = fixture
        .state_dir
        .join("accounts/legacy-account/antigravity-oauth-token");
    assert!(
        credential.is_file(),
        "migration did not store the credential"
    );
    #[cfg(unix)]
    assert_eq!(
        file_mode(&credential),
        0o600,
        "credential is world readable"
    );
    let migrated = fs::read_to_string(fixture.state_dir.join("state.json"))
        .expect("read migrated state document");
    assert!(
        !migrated.contains(SECRET),
        "the migrated state document still embeds the plaintext token"
    );
    assert!(
        !fixture.outside_dir.join("antigravity-oauth-token").exists(),
        "migration wrote a credential outside the state directory"
    );
}

/// AC-R1-1.1: 只有 JSON 语法层坏掉的文档才被改名隔离，而且原始字节必须完整保留。
#[test]
fn syntactically_broken_document_is_quarantined_with_its_bytes_intact() {
    let fixture = Fixture::new();
    let broken = br#"{"version":2,"revision":1,"accounts":["#;
    fs::write(fixture.state_dir.join("state.json"), broken).expect("write broken state");

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "a broken document was accepted");
    assert!(
        stderr.contains("was preserved as state.json.corrupt-"),
        "no recovery guidance: {stderr}"
    );
    assert!(
        !fixture.state_dir.join("state.json").exists(),
        "the broken document was left in place"
    );
    let quarantined = quarantined_documents(&fixture.state_dir);
    assert_eq!(
        quarantined.len(),
        1,
        "expected exactly one quarantined file"
    );
    assert_eq!(
        fs::read(&quarantined[0]).expect("read quarantined document"),
        broken,
        "quarantine rewrote the user's bytes"
    );
}

/// AC-R1-1.2 / AC-R1-1.3: 用新版写出的 state.json 被旧二进制读到时，必须原样
/// 上抛"版本不支持"，文件留在原位且逐字节不变。改名隔离会让用户下一条 `login`
/// 提交一份全新的空 state，旧文档永久变成孤儿。
#[test]
fn a_newer_state_version_is_refused_without_moving_the_document() {
    let fixture = Fixture::new();
    let document = serde_json::to_vec_pretty(&json!({
        "version": 3,
        "revision": 7,
        "accounts": [],
        "usage_cache": {},
        "sync_watermarks": {}
    }))
    .expect("serialize v3 state");
    let state_path = fixture.state_dir.join("state.json");
    fs::write(&state_path, &document).expect("write v3 state");

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an unknown state version was accepted"
    );
    assert!(
        stderr.contains("unsupported state version 3"),
        "unexpected rejection reason: {stderr}"
    );
    assert!(state_path.exists(), "state.json was moved aside");
    assert_eq!(
        fs::read(&state_path).expect("read state document"),
        document,
        "state.json was rewritten"
    );
    assert!(
        quarantined_documents(&fixture.state_dir).is_empty(),
        "a readable, hand-fixable document was quarantined"
    );

    // 第二次运行必须给出同一个错误，而不是"从空 state 起步"。
    let again = fixture.run_list();
    assert!(!again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("unsupported state version 3"),
        "the document silently became an orphan on the second run"
    );
}

/// AC-R1-1.2: v2 语义校验失败（revision 非法）同样只上抛，不隔离。
#[test]
fn an_invalid_v2_revision_is_refused_without_moving_the_document() {
    let fixture = Fixture::new();
    let document = serde_json::to_vec_pretty(&json!({
        "version": 2,
        "revision": 0,
        "accounts": [],
        "usage_cache": {},
        "sync_watermarks": {}
    }))
    .expect("serialize v2 state");
    fs::write(fixture.state_dir.join("state.json"), &document).expect("write v2 state");

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("revision must be positive"),
        "unexpected rejection reason: {stderr}"
    );
    assert_eq!(
        fs::read(fixture.state_dir.join("state.json")).expect("read state document"),
        document
    );
    assert!(quarantined_documents(&fixture.state_dir).is_empty());
}

/// AC-R1-6.2: 超过读取上限的 state.json 不隔离，但必须给出可操作的恢复指引。
#[test]
fn an_oversized_state_document_reports_actionable_recovery() {
    let fixture = Fixture::new();
    let state_path = fixture.state_dir.join("state.json");
    let mut document = Vec::with_capacity(MAX_STATE_BYTES + 64);
    document.extend_from_slice(br#"{"version":2,"revision":1,"padding":""#);
    document.resize(MAX_STATE_BYTES + 32, b'p');
    document.extend_from_slice(br#""}"#);
    fs::write(&state_path, &document).expect("write oversized state");

    let output = fixture.run_list();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an oversized document was accepted"
    );
    assert!(
        stderr.contains("Move ") && stderr.contains("import-known"),
        "oversized state gave no recovery guidance: {stderr}"
    );
    assert!(
        stderr.is_ascii(),
        "console output must stay ASCII: {stderr}"
    );
    assert_eq!(
        fs::read(&state_path).expect("read state document").len(),
        document.len(),
        "the oversized document was rewritten"
    );
    assert!(quarantined_documents(&fixture.state_dir).is_empty());
}

#[test]
fn cli_rejects_invalid_state_with_isolated_home() {
    let fixture = Fixture::new();
    let absolute_id = fixture.outside_dir.to_string_lossy().into_owned();
    write_state(&fixture.state_dir, &state_json(vec![account(&absolute_id)]));
    let home_marker = fixture.home_dir.join("marker");
    fs::write(&home_marker, b"home-marker-before").expect("write home marker");

    let output = fixture.run_list();

    assert!(
        !output.status.success(),
        "invalid state unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(SECRET),
        "CLI error leaked secret: {stderr}"
    );
    assert_eq!(
        fs::read(&home_marker).expect("read home marker"),
        b"home-marker-before"
    );
    fixture.assert_outside_unchanged();
}
