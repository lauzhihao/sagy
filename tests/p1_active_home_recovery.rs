//! HOME-001 回归：active-home publish 在任意崩溃点被打断后必须自愈。
//!
//! 这些用例不调用任何内部函数，而是**直接在磁盘上造出真实的崩溃现场**
//! （真实凭据已被 move 成 tombstone + `prepared` journal 还留在账号目录里），
//! 然后运行真实二进制，断言退出码与用户凭据的逐字节内容。
//!
//! 与 `cli_routing.rs` 一样限定在 unix：Windows 的 rename/删除语义无法在本机验证。
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const JWT_A: &str = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.fake_signature";
const JWT_B: &str = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDF9.fake_signature_b";
const CREDS_C: &str = concat!(
    r#"{"type":"authorized_user","client_id":"cid.apps.googleusercontent.com","#,
    r#""client_secret":"secret","refresh_token":"1//refresh-c","#,
    r#""token_uri":"https://oauth2.googleapis.com/token","email":"c@example.com"}"#,
);
const JOURNAL_PREFIX: &str = ".sagy-active-home-";
const TOKEN_FILENAME: &str = "antigravity-oauth-token";
const DOCUMENT_FILENAME: &str = "oauth_creds.json";

/// publish_inner 的两个崩溃窗口。
#[derive(Clone, Copy, PartialEq, Eq)]
enum CrashPoint {
    /// tombstone 循环跑完第一个 slot 之后、stage 尚未 move 到位。
    AfterFirstTombstone,
    /// stage 已经 move 到位，但 `published` journal 还没写出来。
    AfterStageMove,
}

struct Fixture {
    root: TempDir,
}

impl Fixture {
    /// 建一个真实的 v2 state：账号 A 是 raw OAuth token（占 token slot），
    /// 账号 C 是 authorized-user 文档（占 document slot），当前激活 A。
    fn new() -> Self {
        let fixture = Self::bootstrap();
        let creds = fixture.root.path().join("creds-c.json");
        fs::write(&creds, CREDS_C).expect("write authorized-user document");

        fixture.run_ok(&["add", "--token", JWT_A, "--email", "a@example.com"]);
        fixture.run_ok(&["import-auth", &creds.to_string_lossy()]);
        fixture.run_ok(&["use", "a@example.com"]);
        assert_eq!(
            fixture.live_token(),
            Some(JWT_A.as_bytes().to_vec()),
            "fixture did not publish the raw OAuth token"
        );
        fixture
    }

    fn bootstrap() -> Self {
        let root = tempfile::tempdir().expect("create fixture root");
        for directory in ["home", "gemini", "antigravity", "sagy-home"] {
            fs::create_dir_all(root.path().join(directory)).expect("create fixture directory");
        }
        Self { root }
    }

    /// 同槽位 fixture：账号 A 与 B 同为 raw OAuth token，两者都只占 token 槽，
    /// 当前激活 A。这是最常见的真实切号形态，也是跨槽位 fixture 覆盖不到的那一支：
    /// 跨槽位切换时两个槽位在 `slot_digest_matches` 下就已经成立，松弛判据被绕过。
    fn new_same_slot() -> Self {
        let fixture = Self::bootstrap();
        fixture.run_ok(&["add", "--token", JWT_A, "--email", "a@example.com"]);
        fixture.run_ok(&["add", "--token", JWT_B, "--email", "b@example.com"]);
        fixture.run_ok(&["use", "a@example.com"]);
        assert_eq!(
            fixture.live_token(),
            Some(JWT_A.as_bytes().to_vec()),
            "same-slot fixture did not publish account A's raw OAuth token"
        );
        assert_eq!(
            fixture.live_document(),
            None,
            "same-slot fixture must leave the document slot empty"
        );
        fixture
    }

    fn state_dir(&self) -> PathBuf {
        self.root.path().join("sagy-home")
    }

    fn accounts_dir(&self) -> PathBuf {
        self.state_dir().join("accounts")
    }

    fn gemini(&self) -> PathBuf {
        self.root.path().join("gemini")
    }

    fn antigravity(&self) -> PathBuf {
        self.root.path().join("antigravity")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .args(args)
            .env("HOME", self.root.path().join("home"))
            .env("SAGY_HOME", self.state_dir())
            .env("GEMINI_HOME", self.gemini())
            .env("ANTIGRAVITY_CONFIG_DIR", self.antigravity())
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT")
            .output()
            .expect("run sagy")
    }

    fn run_ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "sagy {args:?} failed: status={:?}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn state(&self) -> (Value, Vec<u8>) {
        let bytes = fs::read(self.state_dir().join("state.json")).expect("read state.json");
        let value = serde_json::from_slice(&bytes).expect("state.json is valid JSON");
        (value, bytes)
    }

    fn live_token(&self) -> Option<Vec<u8>> {
        fs::read(self.antigravity().join(TOKEN_FILENAME)).ok()
    }

    fn live_document(&self) -> Option<Vec<u8>> {
        fs::read(self.gemini().join(DOCUMENT_FILENAME)).ok()
    }

    /// 把磁盘搬到 `publish_inner` 被 SIGKILL 打断后的样子。
    ///
    /// 返回被中断事务的 txid 和崩溃前用户真实凭据的字节。
    fn crash_mid_publish(&self, crash: CrashPoint) -> (Uuid, Vec<u8>) {
        // 旧二进制只会写 `prepared`，HOME-001 的现场就是这个相位。
        self.crash_mid_publish_with_phase(crash, "prepared")
    }

    fn crash_mid_publish_with_phase(&self, crash: CrashPoint, phase: &str) -> (Uuid, Vec<u8>) {
        let (state, state_bytes) = self.state();
        let before_profile = state["active_profile"].clone();
        let active_id = before_profile["account_id"].as_str().expect("active id");
        let target = state["accounts"]
            .as_array()
            .expect("accounts array")
            .iter()
            .find(|account| account["id"].as_str() != Some(active_id))
            .expect("second account")
            .clone();
        let target_id = target["id"].as_str().expect("target id").to_string();
        let target_document = fs::read(
            self.accounts_dir()
                .join(&target_id)
                .join("credentials.json"),
        )
        .expect("read target authorized-user credential");

        let txid = Uuid::new_v4();
        let after_profile = json!({
            "account_id": target_id,
            "credential_fingerprint": target["credential_ref"]["fingerprint"],
            "home_scope_id": before_profile["home_scope_id"],
            "managed_layout": {
                "antigravity_token": "absent",
                "gemini_authorized_user": {"exact": {"sha256": sha256(&target_document)}},
            },
        });
        let journal = json!({
            "journal_version": 1,
            "txid": txid.to_string(),
            "phase": phase,
            "account_id": target_id,
            "base_revision": {
                "generation": "current",
                "revision": state["revision"],
                "document_sha256": sha256(&state_bytes),
            },
            "before_profile": before_profile,
            "after_profile": after_profile,
            "target_ref": target["credential_ref"],
            "mode": "strict",
            "state_before_layout": before_profile["managed_layout"],
            "before_layout": before_profile["managed_layout"],
            "after_layout": after_profile["managed_layout"],
            "token_stage": artifact(txid, ".token.stage"),
            "token_stage_digest": "",
            "token_tombstone": artifact(txid, ".token.tombstone"),
            "token_tombstone_digest": before_profile["managed_layout"]["antigravity_token"]["exact"]["sha256"],
            "document_stage": artifact(txid, ".document.stage"),
            "document_stage_digest": sha256(&target_document),
            "document_tombstone": artifact(txid, ".document.tombstone"),
            "document_tombstone_digest": "",
        });
        fs::write(
            self.accounts_dir()
                .join(&target_id)
                .join(format!("{JOURNAL_PREFIX}{txid}.journal")),
            serde_json::to_vec_pretty(&journal).expect("encode journal"),
        )
        .expect("write prepared journal");

        // publish_inner 第一步：用户真实凭据被 move 成 tombstone。
        let live = self.antigravity().join(TOKEN_FILENAME);
        let original = fs::read(&live).expect("read live credential");
        fs::rename(
            &live,
            self.antigravity().join(artifact(txid, ".token.tombstone")),
        )
        .expect("tombstone the live credential");

        // publish_inner 第二步：stage 已经写在 home root 里等待 move。
        let stage = self.gemini().join(artifact(txid, ".document.stage"));
        fs::write(&stage, &target_document).expect("write document stage");
        if crash == CrashPoint::AfterStageMove {
            fs::rename(&stage, self.gemini().join(DOCUMENT_FILENAME)).expect("publish the stage");
        }

        (txid, original)
    }

    /// 把磁盘搬到一次**同槽位** publish 被打断后的样子。
    ///
    /// A -> B 两个账号同为 raw OAuth token，baseline 与 target 都落在 token 槽上。
    /// 崩在 tombstone 之后、stage move 之前时，token 槽的现场是"文件不存在"，
    /// 它既不等于 baseline digest 也不等于 target digest —— 只有 tombstone 松弛
    /// 判据能解释它。
    fn crash_same_slot_publish(&self, crash: CrashPoint, phase: &str) -> (Uuid, Vec<u8>) {
        let (state, state_bytes) = self.state();
        let before_profile = state["active_profile"].clone();
        let active_id = before_profile["account_id"].as_str().expect("active id");
        let target = state["accounts"]
            .as_array()
            .expect("accounts array")
            .iter()
            .find(|account| account["id"].as_str() != Some(active_id))
            .expect("second account")
            .clone();
        let target_id = target["id"].as_str().expect("target id").to_string();
        let target_token = fs::read(self.accounts_dir().join(&target_id).join(TOKEN_FILENAME))
            .expect("read target raw OAuth credential");

        let txid = Uuid::new_v4();
        let after_profile = json!({
            "account_id": target_id,
            "credential_fingerprint": target["credential_ref"]["fingerprint"],
            "home_scope_id": before_profile["home_scope_id"],
            "managed_layout": {
                "antigravity_token": {"exact": {"sha256": sha256(&target_token)}},
                "gemini_authorized_user": "absent",
            },
        });
        let journal = json!({
            "journal_version": 1,
            "txid": txid.to_string(),
            "phase": phase,
            "account_id": target_id,
            "base_revision": {
                "generation": "current",
                "revision": state["revision"],
                "document_sha256": sha256(&state_bytes),
            },
            "before_profile": before_profile,
            "after_profile": after_profile,
            "target_ref": target["credential_ref"],
            "mode": "strict",
            "state_before_layout": before_profile["managed_layout"],
            "before_layout": before_profile["managed_layout"],
            "after_layout": after_profile["managed_layout"],
            "token_stage": artifact(txid, ".token.stage"),
            "token_stage_digest": sha256(&target_token),
            "token_tombstone": artifact(txid, ".token.tombstone"),
            "token_tombstone_digest": before_profile["managed_layout"]["antigravity_token"]["exact"]["sha256"],
            "document_stage": artifact(txid, ".document.stage"),
            "document_stage_digest": "",
            "document_tombstone": artifact(txid, ".document.tombstone"),
            "document_tombstone_digest": "",
        });
        fs::write(
            self.accounts_dir()
                .join(&target_id)
                .join(format!("{JOURNAL_PREFIX}{txid}.journal")),
            serde_json::to_vec_pretty(&journal).expect("encode journal"),
        )
        .expect("write same-slot journal");

        // publish_inner 第一步：A 的真实凭据被 move 成 tombstone。
        let live = self.antigravity().join(TOKEN_FILENAME);
        let original = fs::read(&live).expect("read live credential");
        fs::rename(
            &live,
            self.antigravity().join(artifact(txid, ".token.tombstone")),
        )
        .expect("tombstone the live credential");

        // publish_inner 第二步：B 的凭据以 stage 形态等在同一个 home root 里。
        let stage = self.antigravity().join(artifact(txid, ".token.stage"));
        fs::write(&stage, &target_token).expect("write token stage");
        if crash == CrashPoint::AfterStageMove {
            fs::rename(&stage, &live).expect("publish the stage");
        }

        (txid, original)
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn artifact(txid: Uuid, suffix: &str) -> String {
    format!("{JOURNAL_PREFIX}{txid}{suffix}")
}

fn entries_with_suffix(directory: &Path, suffix: &str) -> Vec<String> {
    fs::read_dir(directory)
        .expect("read directory")
        .map(|entry| entry.expect("directory entry").file_name())
        .filter_map(|name| name.to_str().map(str::to_string))
        .filter(|name| name.starts_with(JOURNAL_PREFIX) && name.ends_with(suffix))
        .collect()
}

/// AC-1.1 / AC-2.1 / AC-2.2 / AC-2.3：崩在 tombstone 之后、stage move 之前。
#[test]
fn crash_between_tombstone_and_stage_move_restores_the_real_credential() {
    let fixture = Fixture::new();
    let (txid, original) = fixture.crash_mid_publish(CrashPoint::AfterFirstTombstone);
    assert!(
        fixture.live_token().is_none(),
        "crash fixture must leave the real credential tombstoned"
    );

    let output = fixture.run(&["list"]);
    assert!(
        output.status.success(),
        "recovery did not succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(original.as_slice()),
        "the real credential was not restored byte for byte"
    );
    assert!(
        fixture
            .antigravity()
            .join(artifact(txid, ".token.tombstone"))
            .symlink_metadata()
            .is_err(),
        "the tombstone was left behind after a successful restore"
    );
}

/// AC-1.2 / AC-2.3：崩在 stage 已经 move 到位、`published` journal 还没写出来时。
#[test]
fn crash_after_stage_move_rolls_every_slot_back_to_the_baseline() {
    let fixture = Fixture::new();
    let (_, original) = fixture.crash_mid_publish(CrashPoint::AfterStageMove);
    assert!(
        fixture.live_token().is_none() && fixture.live_document().is_some(),
        "crash fixture must leave the two slots in a mixed state"
    );

    let output = fixture.run(&["list"]);
    assert!(
        output.status.success(),
        "recovery did not succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // 自洽 = 两个 slot 一起回到 baseline：token 回来了，半发布的 document 不再留下。
    assert_eq!(fixture.live_token().as_deref(), Some(original.as_slice()));
    assert_eq!(fixture.live_document(), None);
    let (state, _) = fixture.state();
    assert_eq!(
        state["active_profile"]["managed_layout"]["antigravity_token"]["exact"]["sha256"]
            .as_str()
            .expect("token slot digest"),
        sha256(&original),
        "state active profile no longer matches the on-disk layout"
    );
}

/// AC-1.3：恢复之后每条常规命令都必须还能跑。
#[test]
fn every_command_works_after_recovery() {
    for crash in [CrashPoint::AfterFirstTombstone, CrashPoint::AfterStageMove] {
        let fixture = Fixture::new();
        let (_, original) = fixture.crash_mid_publish(crash);

        fixture.run_ok(&["list"]);
        fixture.run_ok(&["use", "c@example.com"]);
        fixture.run_ok(&["use", "a@example.com"]);
        fixture.run_ok(&["rm", "-y", "c@example.com"]);
        fixture.run_ok(&["list"]);
        assert_eq!(
            fixture.live_token().as_deref(),
            Some(original.as_slice()),
            "switching back to the restored account lost the credential"
        );
    }
}

/// AC-1.4：恢复过程不得删掉任何一份用户凭据。
#[test]
fn recovery_never_deletes_credential_bearing_files() {
    let fixture = Fixture::new();
    let (txid, original) = fixture.crash_mid_publish(CrashPoint::AfterFirstTombstone);
    let accounts = fs::read_dir(fixture.accounts_dir())
        .expect("read accounts")
        .map(|entry| entry.expect("account entry").path())
        .collect::<Vec<_>>();
    let stored = accounts
        .iter()
        .map(|account| {
            let token = fs::read(account.join(TOKEN_FILENAME)).ok();
            let document = fs::read(account.join("credentials.json")).ok();
            (account.clone(), token, document)
        })
        .collect::<Vec<_>>();

    fixture.run_ok(&["list"]);

    // tombstone 只能被移回，不能被删：真实凭据必须逐字节回到原位。
    assert_eq!(fixture.live_token().as_deref(), Some(original.as_slice()));
    assert!(
        fixture
            .antigravity()
            .join(artifact(txid, ".token.tombstone"))
            .symlink_metadata()
            .is_err()
    );
    for (account, token, document) in stored {
        assert_eq!(
            fs::read(account.join(TOKEN_FILENAME)).ok(),
            token,
            "account store token changed during recovery: {}",
            account.display()
        );
        assert_eq!(
            fs::read(account.join("credentials.json")).ok(),
            document,
            "account store document changed during recovery: {}",
            account.display()
        );
    }
}

/// AC-3.1：恢复路径必须清掉 `~/.gemini` 及其子目录下无主的 stage 明文。
#[test]
fn recovery_removes_orphan_stage_plaintext() {
    let fixture = Fixture::new();
    let (_, original) = fixture.crash_mid_publish(CrashPoint::AfterFirstTombstone);

    // 崩在 stage 写出与 journal 写出之间会留下永远扫不到的孤儿。
    let orphan = Uuid::new_v4();
    let gemini_orphan = fixture.gemini().join(artifact(orphan, ".document.stage"));
    let antigravity_orphan = fixture.antigravity().join(artifact(orphan, ".token.stage"));
    fs::write(&gemini_orphan, b"orphan-document-plaintext").expect("write orphan document stage");
    fs::write(&antigravity_orphan, b"orphan-token-plaintext").expect("write orphan token stage");

    fixture.run_ok(&["list"]);

    assert_eq!(fixture.live_token().as_deref(), Some(original.as_slice()));
    assert!(
        gemini_orphan.symlink_metadata().is_err(),
        "orphan document stage plaintext survived recovery"
    );
    assert!(
        antigravity_orphan.symlink_metadata().is_err(),
        "orphan token stage plaintext survived recovery"
    );
    assert!(entries_with_suffix(&fixture.gemini(), ".stage").is_empty());
    assert!(entries_with_suffix(&fixture.antigravity(), ".stage").is_empty());
}

/// 新二进制在动用户凭据之前会先落 `publishing` 相位，恢复方必须同样能收敛。
#[test]
fn publishing_phase_journal_is_recovered_the_same_way() {
    let fixture = Fixture::new();
    let (txid, original) =
        fixture.crash_mid_publish_with_phase(CrashPoint::AfterFirstTombstone, "publishing");
    assert!(fixture.live_token().is_none());

    fixture.run_ok(&["list"]);

    assert_eq!(fixture.live_token().as_deref(), Some(original.as_slice()));
    assert!(
        fixture
            .antigravity()
            .join(artifact(txid, ".token.tombstone"))
            .symlink_metadata()
            .is_err()
    );
}

/// AC-R3-1.1：同槽位 A -> B 切换，崩在 tombstone 已生成、stage 未就位的那一点。
///
/// 这是旧判据 `slot_digest_matches` 唯一会 bail 的形态：token 槽的现场是"文件不
/// 存在"，而 baseline（A）与 target（B）都是具体 digest。把松弛判据改回
/// `slot_digest_matches`，恢复会以 `unknown live digest` 失败，整条命令 rc=1。
#[test]
fn same_slot_switch_crash_restores_the_baseline_credential() {
    let fixture = Fixture::new_same_slot();
    let (txid, original) =
        fixture.crash_same_slot_publish(CrashPoint::AfterFirstTombstone, "prepared");
    assert_eq!(original, JWT_A.as_bytes());
    assert!(
        fixture.live_token().is_none(),
        "same-slot crash fixture must leave the token slot empty"
    );

    let output = fixture.run(&["list"]);
    assert!(
        output.status.success(),
        "same-slot recovery did not succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(original.as_slice()),
        "the baseline credential was not restored byte for byte"
    );
    assert!(
        fixture
            .antigravity()
            .join(artifact(txid, ".token.tombstone"))
            .symlink_metadata()
            .is_err(),
        "the tombstone was left behind after a successful same-slot restore"
    );
    assert!(
        entries_with_suffix(&fixture.antigravity(), ".stage").is_empty(),
        "the interrupted stage plaintext survived the same-slot restore"
    );
    // 恢复完成后 State 与磁盘必须自洽：仍然停在 A。
    let (state, _) = fixture.state();
    assert_eq!(
        state["active_profile"]["managed_layout"]["antigravity_token"]["exact"]["sha256"]
            .as_str()
            .expect("token slot digest"),
        sha256(&original)
    );
}

/// AC-R3-1.3：`published` 相位的预检同样要接受"tombstone 在场 + 目标缺失"。
///
/// 现场是一次同槽位切换崩在 restore 自己的 target->recovery / tombstone->target
/// 窗口里：journal 已经是 `published`，但 State 还停在 before profile。恢复方在
/// 走 restore 之前的那次预检必须用同一套松弛判据，否则 CLI 被永久锁死。
#[test]
fn same_slot_published_journal_precheck_accepts_the_tombstoned_slot() {
    let fixture = Fixture::new_same_slot();
    let (txid, original) =
        fixture.crash_same_slot_publish(CrashPoint::AfterFirstTombstone, "published");
    assert!(fixture.live_token().is_none());

    let output = fixture.run(&["list"]);
    assert!(
        output.status.success(),
        "published-phase same-slot recovery did not succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(original.as_slice()),
        "the baseline credential was not rolled back byte for byte"
    );
    assert!(
        fixture
            .antigravity()
            .join(artifact(txid, ".token.tombstone"))
            .symlink_metadata()
            .is_err()
    );
    fixture.run_ok(&["use", "b@example.com"]);
    fixture.run_ok(&["use", "a@example.com"]);
    assert_eq!(fixture.live_token().as_deref(), Some(original.as_slice()));
}
