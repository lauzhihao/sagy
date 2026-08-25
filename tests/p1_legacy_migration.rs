//! Regression coverage for T2: legacy v1 migration must never be all-or-nothing,
//! and the account/credential lifecycle must not silently duplicate or discard
//! credential material.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sagy::core::credential::PortableCredential;
use sagy::core::storage;
use serde_json::{Value, json};

struct Harness {
    _temp: tempfile::TempDir,
    state_dir: PathBuf,
    home_dir: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let home_dir = temp.path().join("home");
        fs::create_dir_all(home_dir.join("antigravity")).expect("antigravity home");
        fs::create_dir_all(home_dir.join("gemini")).expect("gemini home");
        Self {
            _temp: temp,
            state_dir,
            home_dir,
        }
    }

    fn account_dir(&self, account_id: &str) -> PathBuf {
        self.state_dir.join("accounts").join(account_id)
    }

    fn write_state(&self, document: &Value) {
        let bytes = serde_json::to_vec_pretty(document).expect("serialize state fixture");
        storage::write_secret_file(&self.state_dir.join("state.json"), &bytes)
            .expect("write state fixture");
    }

    fn write_account_file(&self, account_id: &str, filename: &str, contents: &str) -> PathBuf {
        let path = self.account_dir(account_id).join(filename);
        storage::write_secret_file(&path, contents.as_bytes()).expect("write account fixture");
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .env("HOME", &self.home_dir)
            .env("SAGY_HOME", &self.state_dir)
            .env("ANTIGRAVITY_CONFIG_DIR", self.home_dir.join("antigravity"))
            .env("GEMINI_HOME", self.home_dir.join("gemini"))
            .env_remove("GOOGLE_API_KEY")
            .env_remove("GEMINI_API_KEY")
            .arg("--state-dir")
            .arg(&self.state_dir)
            .args(args)
            .output()
            .expect("run sagy")
    }

    fn state_document(&self) -> Value {
        let bytes = fs::read(self.state_dir.join("state.json")).expect("read state");
        serde_json::from_slice(&bytes).expect("parse state")
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_exit_zero(output: &Output, label: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{label} must exit 0\nstdout:\n{}\nstderr:\n{}",
        stdout_of(output),
        stderr_of(output)
    );
}

fn legacy_account(id: &str, email: &str, account_type: &str) -> Value {
    json!({
        "id": id,
        "email": email,
        "account_type": account_type,
        "added_at": 1,
        "updated_at": 1
    })
}

fn legacy_state(accounts: Vec<Value>, current: Option<&str>) -> Value {
    json!({
        "version": 1,
        "accounts": accounts,
        "usage_cache": {},
        "current_account_id": current
    })
}

/// One healthy OAuth account plus one account whose credential file was deleted
/// and whose embedded token is empty.
fn mixed_legacy_fixture() -> Harness {
    let harness = Harness::new();
    let mut good = legacy_account("good-account", "good@example.test", "oauth");
    good["oauth_token"] = json!("good-access-token");
    let broken = legacy_account("broken-account", "broken@example.test", "oauth");
    harness.write_state(&legacy_state(vec![good, broken], Some("good-account")));
    harness
}

fn account_emails(state: &Value) -> Vec<String> {
    state["accounts"]
        .as_array()
        .expect("accounts array")
        .iter()
        .map(|account| account["email"].as_str().unwrap_or_default().to_string())
        .collect()
}

// -------------------------------------------------------------------------
// AC-1: legacy migration must be able to skip an unmigratable account.

#[test]
fn list_survives_an_unmigratable_legacy_account_and_reports_it() {
    let harness = mixed_legacy_fixture();
    let output = harness.run(&["list"]);
    assert_exit_zero(&output, "sagy list on a partially broken v1 state");

    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("good@example.test"),
        "the healthy account must still be listed\n{stdout}"
    );
    assert!(
        !stdout.contains("broken@example.test"),
        "the skipped account must not appear as a usable account\n{stdout}"
    );

    // AC-1.3: the skip must be visible, in ASCII, and name the account.
    let stderr = stderr_of(&output);
    assert!(stderr.is_ascii(), "notices must be ASCII only\n{stderr}");
    assert!(
        stderr.contains("broken@example.test") && stderr.contains("broken-account"),
        "the notice must identify the skipped account\n{stderr}"
    );
    assert!(
        stderr.contains("skipped"),
        "the notice must say the account was skipped\n{stderr}"
    );

    // The migration itself must be durable: a second run is a plain v2 read.
    let second = harness.run(&["list"]);
    assert_exit_zero(&second, "second sagy list");
    assert_eq!(
        account_emails(&harness.state_document()),
        ["good@example.test"]
    );
}

#[test]
fn rm_still_works_when_another_account_is_unmigratable() {
    let harness = mixed_legacy_fixture();
    // AC-1.2: 用户必须始终能用 CLI 管理账号，不能被另一个坏账号锁死。
    let output = harness.run(&["rm", "--yes", "good@example.test"]);
    assert_exit_zero(&output, "sagy rm with an unmigratable sibling account");
    assert!(
        account_emails(&harness.state_document()).is_empty(),
        "the named account must actually be removed"
    );
}

#[test]
fn skipped_account_data_is_quarantined_not_destroyed() {
    let harness = Harness::new();
    let mut good = legacy_account("good-account", "good@example.test", "oauth");
    good["oauth_token"] = json!("good-access-token");
    // 声明成 OAuth，但目录里放的是 API-key 文档：旧实现在这里直接炸掉整笔迁移。
    let broken = legacy_account("broken-account", "broken@example.test", "oauth");
    let wrong_kind = r#"{"api_key":"quarantined-key"}"#;
    harness.write_account_file("broken-account", "credentials.json", wrong_kind);
    harness.write_state(&legacy_state(vec![good, broken], Some("good-account")));

    let output = harness.run(&["list"]);
    assert_exit_zero(&output, "sagy list with a wrong-kind credential file");
    assert!(stdout_of(&output).contains("good@example.test"));

    let account_dir = harness.account_dir("broken-account");
    // AC-1.4: 原始凭据字节必须仍在磁盘上，只是被改名隔离。
    let quarantined = account_dir.join(".sagy-credential-quarantine.credentials.json");
    assert!(
        quarantined.is_file(),
        "the original credential file must be preserved under a quarantine name"
    );
    assert_eq!(
        fs::read_to_string(&quarantined).expect("read quarantined credential"),
        wrong_kind
    );
    assert!(
        !account_dir.join("credentials.json").exists(),
        "the quarantined credential must not stay live"
    );

    // The v1 account record itself is preserved too.
    let record: Value = serde_json::from_slice(
        &fs::read(account_dir.join(".sagy-credential-quarantine.account.json"))
            .expect("read quarantine record"),
    )
    .expect("parse quarantine record");
    assert_eq!(record["account"]["email"], json!("broken@example.test"));
    // 隔离之后不得留下任何未完成的事务证据（journal / stage）。
    let leftovers: Vec<String> = fs::read_dir(&account_dir)
        .expect("read account dir")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".journal") || name.ends_with(".stage"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "unexpected transaction evidence: {leftovers:?}"
    );
    assert!(
        record["reason"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[test]
fn every_account_unmigratable_still_exits_zero_with_an_actionable_hint() {
    let harness = Harness::new();
    let first = legacy_account("broken-one", "one@example.test", "oauth");
    let second = legacy_account("broken-two", "two@example.test", "api_key");
    harness.write_state(&legacy_state(vec![first, second], None));

    let output = harness.run(&["list"]);
    // AC-1.5: 全部不可迁移也必须 exit 0 并给出可操作提示。
    assert_exit_zero(&output, "sagy list when nothing can be migrated");
    assert!(stdout_of(&output).contains("No accounts registered"));

    let stderr = stderr_of(&output);
    assert!(stderr.is_ascii(), "{stderr}");
    assert!(stderr.contains("one@example.test") && stderr.contains("two@example.test"));
    assert!(
        stderr.contains("sagy add"),
        "the hint must name a command the user can run\n{stderr}"
    );
    assert!(account_emails(&harness.state_document()).is_empty());
}

// -------------------------------------------------------------------------
// AC-2 / AC-3: one credential material must yield exactly one account.

#[test]
fn one_api_key_yields_one_account_regardless_of_email_or_project_id() {
    let harness = Harness::new();
    let first = harness.run(&[
        "add",
        "--api-key",
        "shared-key",
        "--email",
        "one@example.test",
    ]);
    assert_exit_zero(&first, "first API-key import");
    let second = harness.run(&[
        "add",
        "--api-key",
        "shared-key",
        "--email",
        "two@example.test",
    ]);
    assert_exit_zero(&second, "second API-key import with a different email");
    let third = harness.run(&[
        "add",
        "--api-key",
        "shared-key",
        "--email",
        "one@example.test",
        "--project-id",
        "project-x",
    ]);
    assert_exit_zero(&third, "third API-key import with a project id");

    // AC-2.1 / AC-3.2: one account, one credential copy.
    let accounts = harness.state_document()["accounts"]
        .as_array()
        .expect("accounts array")
        .len();
    assert_eq!(
        accounts, 1,
        "the same API key must not create extra accounts"
    );
    let account_dirs = fs::read_dir(harness.state_dir.join("accounts"))
        .expect("read accounts dir")
        .count();
    assert_eq!(
        account_dirs, 1,
        "only one credential copy may exist on disk"
    );

    // AC-2.2: `sagy list` shows a single candidate.
    let listed = harness.run(&["list"]);
    assert_exit_zero(&listed, "sagy list after repeated API-key imports");
    let stdout = stdout_of(&listed);
    assert_eq!(
        stdout.matches("api_key").count(),
        1,
        "only one API-key row may be shown\n{stdout}"
    );

    // AC-3.1: the ignored --project-id must be reported, never silent.
    let warning = stderr_of(&third);
    assert!(warning.is_ascii(), "{warning}");
    assert!(
        warning.contains("--project-id") && warning.contains("project-x"),
        "the ignored project id must be reported\n{warning}"
    );
    // ...and it must not have been recorded as if it took effect.
    assert_eq!(
        harness.state_document()["accounts"][0]["project_id"],
        json!(null)
    );
}

// -------------------------------------------------------------------------
// AC-4: a cross-kind email collision must explain the way out.

#[test]
fn cross_kind_email_collision_names_the_conflict_and_the_next_step() {
    let harness = Harness::new();
    let added = harness.run(&[
        "add",
        "--api-key",
        "some-key",
        "--email",
        "clash@example.test",
    ]);
    assert_exit_zero(&added, "API-key import");

    let output = harness.run(&[
        "add",
        "--token",
        "oauth-token",
        "--email",
        "clash@example.test",
    ]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "importing a different credential kind onto the same email must fail"
    );
    let message = format!("{}{}", stdout_of(&output), stderr_of(&output));
    assert!(message.is_ascii(), "{message}");
    assert!(
        message.contains("clash@example.test"),
        "the conflicting account must be named\n{message}"
    );
    assert!(
        message.contains("api_key"),
        "the conflicting credential kind must be named\n{message}"
    );
    assert!(
        message.contains("sagy rm clash@example.test"),
        "the error must name an executable next step\n{message}"
    );

    // The failed import must not have created a second account.
    assert_eq!(
        harness.state_document()["accounts"]
            .as_array()
            .expect("accounts array")
            .len(),
        1
    );
}

// -------------------------------------------------------------------------
// AC-5: crash-orphaned plaintext stage files must be cleaned up.

#[test]
fn ownerless_credential_stage_is_removed_by_the_next_command() {
    let harness = Harness::new();
    let added = harness.run(&[
        "add",
        "--api-key",
        "stage-key",
        "--email",
        "stage@example.test",
    ]);
    assert_exit_zero(&added, "API-key import");
    let account_id = harness.state_document()["accounts"][0]["id"]
        .as_str()
        .expect("account id")
        .to_string();

    // stage 先于 journal 落盘，崩在这个窗口就会留下这份明文孤儿文件。
    let orphan = harness.write_account_file(
        &account_id,
        ".sagy-credential-11111111-1111-4111-8111-111111111111.stage",
        r#"{"api_key":"leaked-from-a-crash"}"#,
    );
    // 与任何事务无关的其它工件必须被原样保留。
    let unrelated = harness.write_account_file(
        &account_id,
        ".sagy-credential-22222222-2222-4222-8222-222222222222.token.backup",
        "unrelated-evidence",
    );
    assert!(orphan.is_file());

    let output = harness.run(&["list"]);
    assert_exit_zero(&output, "sagy list after a crash-orphaned stage");
    assert!(
        !orphan.exists(),
        "an ownerless stage file must not survive the next command"
    );
    // AC-5.2: 清理必须是窄的，只针对无主 stage。
    assert!(
        unrelated.is_file(),
        "non-stage evidence must not be collected by the stage cleanup"
    );
    assert!(
        Path::new(&harness.account_dir(&account_id).join("credentials.json")).is_file(),
        "the live credential must be untouched"
    );

    // The credential itself is still readable, so the account stays usable.
    let credential = fs::read_to_string(harness.account_dir(&account_id).join("credentials.json"))
        .expect("read live credential");
    assert_eq!(
        PortableCredential::from_native_json_str(credential.trim())
            .expect("parse live credential")
            .api_key_value(),
        Some("stage-key")
    );
}

// -------------------------------------------------------------------------
// AC-R2-1: an API-key account created before the credential-document change
// must be reused, not duplicated, when the same key is imported again.

/// Reproduce the pre-upgrade on-disk layout: the API-key credential document
/// still carries `email` / `project_id`, so its fingerprint differs from the
/// one the current binary derives from `{"api_key": K}` alone.
fn legacy_api_key_fixture(account_id: &str, api_key: &str, email: &str, project: &str) -> Harness {
    let harness = Harness::new();
    let document = json!({
        "api_key": api_key,
        "email": email,
        "project_id": project,
    });
    let legacy =
        PortableCredential::api_key_document(document.clone()).expect("legacy api key credential");
    harness.write_account_file(
        account_id,
        "credentials.json",
        &serde_json::to_string(&document).expect("serialize legacy credential"),
    );
    harness.write_state(&json!({
        "version": 2,
        "revision": 1,
        "accounts": [{
            "id": account_id,
            "email": email,
            "account_type": "api_key",
            "provider_id": "google-ai-studio",
            "project_id": null,
            "account_id": null,
            "plan": "Gemini API Key",
            "added_at": 1,
            "updated_at": 1,
            "last_used_at": null,
            "credential_ref": {
                "kind": "api_key",
                "fingerprint": legacy.fingerprint(),
            }
        }],
        "usage_cache": {},
        "current_account_id": null,
        "active_profile": null,
        "sync_watermarks": {}
    }));
    harness
}

#[test]
fn upgraded_api_key_account_is_reused_instead_of_duplicated() {
    // AC-R2-1.2: 从旧格式的磁盘现场起步，而不是空 state。
    let harness = legacy_api_key_fixture(
        "11111111-1111-4111-8111-111111111111",
        "upgrade-key",
        "upgrade@example.test",
        "legacy-project",
    );

    // 升级后重跑升级前用过的同一条命令。
    let output = harness.run(&[
        "add",
        "--api-key",
        "upgrade-key",
        "--email",
        "upgrade@example.test",
    ]);
    assert_exit_zero(&output, "re-importing the same API key after an upgrade");

    // AC-R2-1.1: 必须复用原账号，不得新建第二个。
    let state = harness.state_document();
    let accounts = state["accounts"].as_array().expect("accounts array");
    assert_eq!(
        accounts.len(),
        1,
        "the upgraded API key must not create a second account\n{state}"
    );
    assert_eq!(
        accounts[0]["id"],
        json!("11111111-1111-4111-8111-111111111111"),
        "the original account id must be reused\n{state}"
    );

    // ...and there must be exactly one plaintext credential copy on disk.
    let account_dirs: Vec<String> = fs::read_dir(harness.state_dir.join("accounts"))
        .expect("read accounts dir")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        account_dirs,
        ["11111111-1111-4111-8111-111111111111"],
        "a second credential copy must not be written"
    );
    let live = fs::read_to_string(
        harness
            .account_dir("11111111-1111-4111-8111-111111111111")
            .join("credentials.json"),
    )
    .expect("read live credential");
    assert_eq!(
        PortableCredential::from_native_json_str(live.trim())
            .expect("parse live credential")
            .api_key_value(),
        Some("upgrade-key")
    );

    // `sagy list` must show a single schedulable candidate.
    let listed = harness.run(&["list"]);
    assert_exit_zero(&listed, "sagy list after the upgrade re-import");
    assert_eq!(stdout_of(&listed).matches("api_key").count(), 1);
}

#[test]
fn upgraded_api_key_account_is_reused_even_with_a_different_email() {
    // 旧文档把 email 也写进了指纹，所以"换个 --email"是同一个 blocker 的另一面。
    let harness = legacy_api_key_fixture(
        "22222222-2222-4222-8222-222222222222",
        "shared-upgrade-key",
        "old@example.test",
        "legacy-project",
    );
    let output = harness.run(&[
        "add",
        "--api-key",
        "shared-upgrade-key",
        "--email",
        "new@example.test",
    ]);
    assert_exit_zero(&output, "re-importing the same key under a new email");
    let state = harness.state_document();
    assert_eq!(
        state["accounts"].as_array().expect("accounts array").len(),
        1,
        "one API key must still mean one account\n{state}"
    );
    assert_eq!(
        state["accounts"][0]["id"],
        json!("22222222-2222-4222-8222-222222222222")
    );
}

// -------------------------------------------------------------------------
// AC-R2-2: the interactive branch must fail before it asks for the secret.

const OAUTH_SECRET_PROMPT: &str = "Paste your Antigravity OAuth Token";

#[test]
fn interactive_add_reports_a_cross_kind_conflict_before_prompting_for_a_secret() {
    let harness = Harness::new();
    let added = harness.run(&[
        "add",
        "--api-key",
        "occupying-key",
        "--email",
        "clash@example.test",
    ]);
    assert_exit_zero(&added, "API-key import");

    // 真实的交互路径：不带 --token/--api-key 的 `sagy add` 会走 rpassword 提示。
    // Command::output() 把 stdin 接到 /dev/null，等价于用户还没来得及输入。
    let output = harness.run(&["add", "--email", "clash@example.test"]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "the cross-kind collision must fail the command"
    );
    let stdout = stdout_of(&output);
    // AC-R2-2.1: 提示语一次都不能出现。
    assert!(
        !stdout.contains(OAUTH_SECRET_PROMPT),
        "the secret prompt must never be shown for a conflicting email\n{stdout}"
    );
    // AC-R2-2.2: 错误必须点名冲突对象与下一步。
    let message = format!("{stdout}{}", stderr_of(&output));
    assert!(message.is_ascii(), "{message}");
    assert!(
        message.contains("clash@example.test") && message.contains("api_key"),
        "the conflict must be named\n{message}"
    );
    assert!(
        message.contains("sagy rm clash@example.test"),
        "the error must name an executable next step\n{message}"
    );
    assert_eq!(
        harness.state_document()["accounts"]
            .as_array()
            .expect("accounts array")
            .len(),
        1
    );
}

#[test]
fn interactive_add_still_reaches_the_prompt_without_a_conflict() {
    // 反面对照：没有冲突时前置检查不得吃掉正常的交互路径。
    let harness = Harness::new();
    let output = harness.run(&["add", "--email", "fresh@example.test"]);
    assert!(
        stdout_of(&output).contains(OAUTH_SECRET_PROMPT),
        "a conflict-free interactive add must still ask for the secret\n{}",
        stdout_of(&output)
    );
}

// -------------------------------------------------------------------------
// AC-R2-4: recovery and reporting must not turn a recoverable situation into
// a hard failure, and must not report an outcome the transaction rolled back.

/// A v1 state with one healthy account and one account whose credential file
/// is of the wrong kind, so migration has to skip and quarantine it.
fn quarantine_fixture(extra_quarantine_names: &[String]) -> Harness {
    let harness = Harness::new();
    harness.write_account_file(
        "broken-account",
        "credentials.json",
        r#"{"api_key":"wrong-kind-key"}"#,
    );
    for name in extra_quarantine_names {
        harness.write_account_file("broken-account", name, "an-earlier-attempt");
    }
    let mut good = legacy_account("good-account", "good@example.test", "oauth");
    good["oauth_token"] = json!("good-access-token");
    let broken = legacy_account("broken-account", "broken@example.test", "oauth");
    harness.write_state(&legacy_state(vec![good, broken], Some("good-account")));
    harness
}

#[test]
fn quarantine_target_collision_does_not_hard_fail_the_cli() {
    // 用户按提示把凭据手工恢复回 credentials.json 后重跑：隔离目标已经存在。
    let harness = quarantine_fixture(&[".sagy-credential-quarantine.credentials.json".to_string()]);
    let output = harness.run(&["list"]);
    // AC-R2-4.4: 必须唯一化，而不是又一次硬失败。
    assert_exit_zero(
        &output,
        "sagy list when the quarantine target already exists",
    );
    assert!(stdout_of(&output).contains("good@example.test"));

    let account_dir = harness.account_dir("broken-account");
    assert_eq!(
        fs::read_to_string(account_dir.join(".sagy-credential-quarantine.credentials.json"))
            .expect("read the pre-existing quarantine file"),
        "an-earlier-attempt",
        "the earlier quarantine evidence must not be overwritten"
    );
    assert_eq!(
        fs::read_to_string(account_dir.join(".sagy-credential-quarantine.1.credentials.json"))
            .expect("read the uniquified quarantine file"),
        r#"{"api_key":"wrong-kind-key"}"#,
        "the newly quarantined credential must be preserved under a unique name"
    );
    assert!(!account_dir.join("credentials.json").exists());
}

#[test]
fn a_rolled_back_migration_does_not_report_skips() {
    // 隔离目标名被彻底占满 -> 迁移在 plan 之后失败并整体回滚。
    let mut blockers = vec![".sagy-credential-quarantine.credentials.json".to_string()];
    for index in 1..=16 {
        blockers.push(format!(
            ".sagy-credential-quarantine.{index}.credentials.json"
        ));
    }
    let harness = quarantine_fixture(&blockers);

    let output = harness.run(&["list"]);
    assert_ne!(
        output.status.code(),
        Some(0),
        "an unquarantinable account must fail closed"
    );
    let message = format!("{}{}", stdout_of(&output), stderr_of(&output));
    // AC-R2-4.3: 回滚时不得声称账号"已被跳过 / 原始数据已保留"。
    assert!(
        !message.contains("was skipped"),
        "a rolled-back migration must not report a skip\n{message}"
    );
    assert!(
        !message.contains("nothing was deleted"),
        "a rolled-back migration must not claim quarantine succeeded\n{message}"
    );
    // ...and the store must really still be v1.
    assert_eq!(harness.state_document()["version"], json!(1));
}

#[test]
fn an_oversized_orphan_stage_does_not_block_the_next_command() {
    let harness = Harness::new();
    let added = harness.run(&[
        "add",
        "--api-key",
        "huge-stage-key",
        "--email",
        "huge@example.test",
    ]);
    assert_exit_zero(&added, "API-key import");
    let account_id = harness.state_document()["accounts"][0]["id"]
        .as_str()
        .expect("account id")
        .to_string();

    // 超过 256 KiB 的孤儿 stage：旧实现的 bounded read 会硬失败，
    // 于是每一条命令都失败，永远清理不掉。
    let orphan = harness.write_account_file(
        &account_id,
        ".sagy-credential-33333333-3333-4333-8333-333333333333.stage",
        &"A".repeat(300 * 1024),
    );
    assert!(orphan.is_file());

    let output = harness.run(&["list"]);
    // AC-R2-4.2: CLI 必须照常工作。
    assert_exit_zero(&output, "sagy list after an oversized orphan stage");
    assert!(
        !orphan.exists(),
        "an oversized ownerless stage must be cleaned up, not left to block the CLI"
    );
    assert!(
        harness
            .account_dir(&account_id)
            .join("credentials.json")
            .is_file(),
        "the live credential must be untouched"
    );
}

// -------------------------------------------------------------------------
// AC-R2-4.5: user-controlled emails must never break the ASCII-only console.

const NON_ASCII_EMAIL: &str = "caf\u{e9}\u{2603}@example.test";

#[test]
fn a_non_ascii_email_is_escaped_in_the_migration_skip_notice() {
    let harness = Harness::new();
    let mut good = legacy_account("good-account", "good@example.test", "oauth");
    good["oauth_token"] = json!("good-access-token");
    let broken = legacy_account("broken-account", NON_ASCII_EMAIL, "oauth");
    harness.write_state(&legacy_state(vec![good, broken], Some("good-account")));

    let output = harness.run(&["list"]);
    assert_exit_zero(&output, "sagy list with a non-ASCII legacy email");
    let stderr = stderr_of(&output);
    assert!(
        stderr.is_ascii(),
        "console notices must stay ASCII only\n{stderr}"
    );
    assert!(
        !stderr.contains(NON_ASCII_EMAIL),
        "the raw non-ASCII email must not be interpolated\n{stderr}"
    );
    assert!(
        stderr.contains("caf\\u{00e9}") && stderr.contains("broken-account"),
        "the notice must still identify the skipped account\n{stderr}"
    );
}

#[test]
fn a_non_ascii_email_is_escaped_in_the_cross_kind_conflict_error() {
    let harness = Harness::new();
    let added = harness.run(&["add", "--api-key", "some-key", "--email", NON_ASCII_EMAIL]);
    assert_exit_zero(&added, "API-key import with a non-ASCII email");

    let output = harness.run(&["add", "--token", "oauth-token", "--email", NON_ASCII_EMAIL]);
    assert_ne!(output.status.code(), Some(0));
    let message = format!("{}{}", stdout_of(&output), stderr_of(&output));
    assert!(
        message.is_ascii(),
        "the conflict error must stay ASCII only\n{message}"
    );
    assert!(
        message.contains("caf\\u{00e9}") && message.contains("api_key"),
        "the conflict must still be identifiable\n{message}"
    );
}
