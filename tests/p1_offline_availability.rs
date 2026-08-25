#![cfg(unix)]
//! AVAIL-001 回归：探测通道不可达时 sagy 仍必须能启动 agy。
//!
//! 这些用例**不允许触网**：所有 usage 快照都带一个新鲜的 `last_probe_at`，
//! `probe_decision` 因此返回 `UseCached`，`sagy launch` / `sagy list` 全程不会
//! 发出任何 HTTP 请求。断网语义通过预置的 `transient_failure` 快照注入。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::Utc;
use sagy::core::credential::PortableCredential;
use sagy::core::health::{HealthErrorKind, HealthStatus};
use sagy::core::policy;
use sagy::core::state::{
    AccountRecord, AccountType, CredentialRef, CredentialRefKind, State, UsageSnapshot,
};
use sagy::core::storage;
use serde_json::{Value, json};

/// 一个预置账号：id + API key + 该账号最近一次探测的结论。
struct Fixture {
    id: &'static str,
    api_key: &'static str,
    health: &'static str,
    last_error: Option<&'static str>,
}

impl Fixture {
    const fn offline(id: &'static str, api_key: &'static str) -> Self {
        Self {
            id,
            api_key,
            health: "transient_failure",
            last_error: Some("network"),
        }
    }

    /// 尚未探测过：`probe_decision` 会返回 `Probe`，从而真的走一次探测路径。
    const fn unverified(id: &'static str, api_key: &'static str) -> Self {
        Self {
            id,
            api_key,
            health: "unverified",
            last_error: None,
        }
    }

    const fn rejected(id: &'static str, api_key: &'static str) -> Self {
        Self {
            id,
            api_key,
            health: "auth_invalid",
            last_error: Some("unauthorized"),
        }
    }

    const fn invalid_credential(id: &'static str, api_key: &'static str) -> Self {
        Self {
            id,
            api_key,
            health: "invalid_credential",
            last_error: Some("invalid_credential"),
        }
    }
}

/// 探测通道的注入点。`Unreachable` 把 HTTP(S) 代理指向本机 discard 端口，
/// 于是每次探测都在传输层失败——不依赖真实网络，也不需要在生产代码里开
/// 任何可以改写探测地址的环境变量（那会成为把凭据重定向出去的开关）。
#[derive(Clone, Copy)]
enum ProbeChannel {
    Cached,
    Unreachable,
}

impl ProbeChannel {
    fn apply(self, command: &mut Command) {
        match self {
            Self::Cached => {}
            Self::Unreachable => {
                command
                    .env("HTTP_PROXY", UNREACHABLE_PROXY)
                    .env("HTTPS_PROXY", UNREACHABLE_PROXY)
                    .env("http_proxy", UNREACHABLE_PROXY)
                    .env("https_proxy", UNREACHABLE_PROXY)
                    .env_remove("NO_PROXY")
                    .env_remove("no_proxy")
                    .env_remove("ALL_PROXY")
                    .env_remove("all_proxy");
            }
        }
    }
}

const UNREACHABLE_PROXY: &str = "http://127.0.0.1:9";

struct Harness {
    _temp: tempfile::TempDir,
    state_dir: PathBuf,
    home: PathBuf,
    fake_agy: PathBuf,
    launch_log: PathBuf,
}

impl Harness {
    fn new(fixtures: &[Fixture]) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let home = temp.path().join("home");
        let fake_agy = temp.path().join("fake-agy");
        let launch_log = temp.path().join("launch.log");
        for path in [home.clone(), home.join("antigravity"), home.join("gemini")] {
            fs::create_dir_all(&path).expect("create isolated home");
        }
        write_fake_agy(&fake_agy);

        let harness = Self {
            _temp: temp,
            state_dir,
            home,
            fake_agy,
            launch_log,
        };
        harness.write_state(fixtures);
        harness
    }

    fn write_state(&self, fixtures: &[Fixture]) {
        let now = Utc::now().timestamp();
        let mut accounts = Vec::new();
        let mut usage_cache = serde_json::Map::new();
        for fixture in fixtures {
            let document = format!(r#"{{"api_key":"{}"}}"#, fixture.api_key);
            storage::write_secret_file(
                &self
                    .state_dir
                    .join("accounts")
                    .join(fixture.id)
                    .join("credentials.json"),
                document.as_bytes(),
            )
            .expect("write credential fixture");
            let credential =
                PortableCredential::from_native_json_str(&document).expect("parse credential");
            accounts.push(json!({
                "id": fixture.id,
                "email": format!("{}@example.test", fixture.id),
                "account_type": AccountType::ApiKey,
                "provider_id": null,
                "project_id": null,
                "account_id": null,
                "plan": null,
                "added_at": now,
                "updated_at": now,
                "last_used_at": null,
                "credential_ref": {
                    "kind": CredentialRefKind::ApiKey,
                    "fingerprint": credential.fingerprint()
                }
            }));
            usage_cache.insert(
                fixture.id.to_string(),
                json!({
                    "health": fixture.health,
                    "last_probe_at": now,
                    "last_error": fixture.last_error
                }),
            );
        }

        let state = json!({
            "version": 2,
            "revision": 1,
            "accounts": accounts,
            "usage_cache": Value::Object(usage_cache),
            "current_account_id": null,
            "active_profile": null,
            "sync_watermarks": {}
        });
        storage::write_secret_file(
            &self.state_dir.join("state.json"),
            &serde_json::to_vec_pretty(&state).expect("encode v2 state"),
        )
        .expect("write v2 state");
    }

    fn run(&self, command: &str) -> Output {
        self.run_with_probe_channel(command, ProbeChannel::Cached)
    }

    fn run_with_probe_channel(&self, subcommand: &str, channel: ProbeChannel) -> Output {
        let mut process = Command::new(env!("CARGO_BIN_EXE_sagy"));
        process
            .args([
                "--state-dir",
                self.state_dir.to_str().expect("UTF-8 state path"),
                subcommand,
            ])
            .args(if subcommand == "launch" {
                vec!["--no-import-known", "--no-resume"]
            } else {
                Vec::new()
            })
            .env("HOME", &self.home)
            .env("SAGY_HOME", &self.state_dir)
            .env("ANTIGRAVITY_CONFIG_DIR", self.home.join("antigravity"))
            .env("GEMINI_HOME", self.home.join("gemini"))
            .env("AGY_BIN", &self.fake_agy)
            .env("FAKE_AGY_LAUNCH_LOG", &self.launch_log)
            // 断言的是英文提示，语言必须固定，不能跟着开发机 locale 漂移。
            .env("LANG", "C")
            .env_remove("LC_ALL")
            .env_remove("LC_MESSAGES")
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT");
        channel.apply(&mut process);
        process.output().expect("run sagy")
    }

    fn launched_keys(&self) -> Vec<String> {
        fs::read_to_string(&self.launch_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

fn describe(output: &Output) -> String {
    format!(
        "status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// AC-1.1 / AC-1.5：所有账号最近一次探测都是传输层失败时，本地凭据仍然有效的
/// 账号必须能被选中并真的把 agy 拉起来。
#[test]
fn transport_probe_failure_still_launches_a_locally_valid_account() {
    let harness = Harness::new(&[Fixture::offline("offline-account", "offline-key")]);
    let output = harness.run("launch");
    assert!(
        output.status.success(),
        "offline launch must succeed: {}",
        describe(&output)
    );
    assert_eq!(
        harness.launched_keys(),
        vec!["offline-key".to_string()],
        "agy was not spawned while the probe channel was down: {}",
        describe(&output)
    );
}

/// AC-1.1 / AC-1.5 的黑盒复现：隔离 HOME + 有效凭据 + 探测端点不可达 ->
/// 真的发起探测、真的失败、并且真的把 agy 拉起来。
#[test]
fn live_probe_through_an_unreachable_channel_still_launches() {
    let harness = Harness::new(&[Fixture::unverified("offline-account", "offline-key")]);
    let output = harness.run_with_probe_channel("launch", ProbeChannel::Unreachable);
    assert!(
        output.status.success(),
        "launch must survive an unreachable probe channel: {}",
        describe(&output)
    );
    assert_eq!(
        harness.launched_keys(),
        vec!["offline-key".to_string()],
        "agy was not spawned: {}",
        describe(&output)
    );
    let state: serde_json::Value = serde_json::from_slice(
        &fs::read(harness.state_dir.join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["usage_cache"]["offline-account"]["health"], "transient_failure",
        "the probe must have actually run and failed at the transport layer"
    );
}

/// AC-1.3：断网不能让一个服务端已经明确拒绝的凭据重新变得可选。
#[test]
fn server_rejection_stays_ineligible_while_the_probe_channel_is_down() {
    // id 顺序刻意让被拒绝的账号排在前面：如果拒绝态被误判为可选，
    // 确定性排序会先选中它，用例即失败。
    let mixed = Harness::new(&[
        Fixture::rejected("aaa-rejected", "rejected-key"),
        Fixture::offline("zzz-offline", "offline-key"),
    ]);
    let output = mixed.run("launch");
    assert!(
        output.status.success(),
        "mixed launch must succeed: {}",
        describe(&output)
    );
    assert_eq!(
        mixed.launched_keys(),
        vec!["offline-key".to_string()],
        "a rejected credential must never be launched: {}",
        describe(&output)
    );

    let rejected_only = Harness::new(&[Fixture::rejected("aaa-rejected", "rejected-key")]);
    let output = rejected_only.run("launch");
    assert!(
        !output.status.success(),
        "a rejected-only pool must not launch: {}",
        describe(&output)
    );
    assert!(
        rejected_only.launched_keys().is_empty(),
        "agy was spawned for a rejected credential: {}",
        describe(&output)
    );
}

/// AC-1.4 / AC-2.2：用户可见的提示必须说明真实原因（探测通道不可达、仍在使用
/// 缓存与本地校验结果），并且服务端拒绝的账号要显示成需要用户处理的状态。
#[test]
fn user_facing_output_names_the_probe_channel_and_relogin_states() {
    let harness = Harness::new(&[
        Fixture::offline("offline-account", "offline-key"),
        Fixture::invalid_credential("broken-account", "broken-key"),
    ]);
    let listing = harness.run("list");
    assert!(
        listing.status.success(),
        "list must succeed: {}",
        describe(&listing)
    );
    let stdout = String::from_utf8_lossy(&listing.stdout).to_string();
    assert!(
        stdout.contains("Relogin Required"),
        "invalid credential must be shown as user-actionable: {stdout}"
    );
    assert!(
        stdout.contains("probe"),
        "the table must explain that the probe channel is unreachable: {stdout}"
    );
    assert!(
        stdout.contains("cached"),
        "the table must state that cached/local results are still in use: {stdout}"
    );

    let rejected_only = Harness::new(&[Fixture::rejected("aaa-rejected", "rejected-key")]);
    let output = rejected_only.run("launch");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("probe"),
        "the no-usable-account hint must name the probe channel as a possible cause: {combined}"
    );
    assert!(
        combined.is_ascii(),
        "console output must stay ASCII only: {combined}"
    );
}

/// AC-1.2：全量探测故障下的选择顺序必须与账号在 state 中的排列顺序无关。
/// 规则：先按 eligibility 等级，再按打分，最后按 account id 升序。
#[test]
fn selection_is_deterministic_under_a_total_probe_outage() {
    let ids = ["b-account", "a-account", "c-account"];
    let mut orders = Vec::new();
    for rotation in 0..ids.len() {
        let mut ordered: Vec<&str> = ids.to_vec();
        ordered.rotate_left(rotation);
        let mut state = State::default();
        let mut validated = BTreeSet::new();
        for id in &ordered {
            state.accounts.push(AccountRecord {
                id: (*id).to_string(),
                email: format!("{id}@example.test"),
                account_type: AccountType::ApiKey,
                ..Default::default()
            });
            state.credential_refs.insert(
                (*id).to_string(),
                CredentialRef {
                    kind: CredentialRefKind::ApiKey,
                    fingerprint:
                        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                },
            );
            state.usage_cache.insert(
                (*id).to_string(),
                UsageSnapshot {
                    health: HealthStatus::TransientFailure,
                    last_error: Some(HealthErrorKind::Network),
                    last_probe_at: Some(1_000),
                    ..Default::default()
                },
            );
            validated.insert((*id).to_string());
        }
        let selected =
            policy::select_best_account_with_validation(&state, &state.accounts, &validated, 1_000)
                .map(|(account, _)| account.id.clone());
        orders.push(selected);
    }
    assert_eq!(
        orders,
        vec![
            Some("a-account".to_string()),
            Some("a-account".to_string()),
            Some("a-account".to_string())
        ],
        "selection under a total probe outage must be deterministic"
    );
}

/// AC-4.1 / AC-4.2 / AC-4.3：可选性判定、探测 TTL 常量各只有一份定义，且已无
/// 生产调用方的健康判定 / 限流标记 pub 项不得复活。
#[test]
fn eligibility_and_probe_ttl_have_exactly_one_definition() {
    let health = include_str!("../src/core/health.rs");
    let usage = include_str!("../src/adapters/antigravity/usage.rs");
    let policy = include_str!("../src/core/policy.rs");

    for removed in ["fn is_healthy", "fn is_eligible"] {
        assert!(
            !health.contains(removed),
            "`{removed}` duplicates policy::eligibility and must stay deleted"
        );
    }
    assert!(
        !usage.contains("fn mark_rate_limited"),
        "`fn mark_rate_limited` must live only in core::health (or not at all)"
    );
    // AC-R6-4.1：守门只禁止**重新定义**探测 TTL 常量。裸子串断言会把合法的
    // `use crate::core::health::PROBE_TTL_SECS;` 一起误杀，逼着适配器去抄一份
    // 自己的常量——正好是这条守门本来要防的事。
    assert!(
        !redefines_constant(usage, "PROBE_TTL"),
        "the probe TTL constant must be defined only in core::health"
    );
    assert!(
        !redefines_constant(
            "use crate::core::health::PROBE_TTL_SECS;\nlet window = PROBE_TTL_SECS;",
            "PROBE_TTL"
        ),
        "referencing the single definition must stay allowed"
    );
    assert!(
        redefines_constant("pub const PROBE_TTL_SECS: i64 = 300;", "PROBE_TTL"),
        "a redefinition must still be rejected"
    );
    assert!(
        redefines_constant("    static PROBE_TTL_SECS: i64 = 300;", "PROBE_TTL"),
        "a redefinition must still be rejected"
    );
    assert_eq!(
        health.matches("PROBE_TTL_SECS: i64").count(),
        1,
        "the probe TTL constant must have exactly one definition"
    );
    assert_eq!(
        policy.matches("pub fn eligibility(").count(),
        1,
        "account selectability must have exactly one definition"
    );
}

/// True only when `source` **defines** a constant whose name starts with
/// `name`; a `use` import or any other reference is not a redefinition.
fn redefines_constant(source: &str, name: &str) -> bool {
    source.lines().any(|line| {
        line.contains(&format!("const {name}")) || line.contains(&format!("static {name}"))
    })
}

fn write_fake_agy(path: &Path) {
    fs::write(
        path,
        r#"#!/bin/sh
set -eu
printf '%s\n' "${GEMINI_API_KEY:-<unset>}" >> "$FAKE_AGY_LAUNCH_LOG"
exit 0
"#,
    )
    .expect("write fake agy");
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("stat fake agy").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("chmod fake agy");
}
