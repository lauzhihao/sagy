#![cfg(unix)]

//! End-to-end coverage for T5: the 429 observation must survive real `agy`
//! stderr, the child must keep its terminal, and the injected default model
//! must yield to every spelling of the user's model flag.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use sagy::adapters::antigravity::launch_observation::MAX_DIAGNOSTIC_BYTES;
use sagy::adapters::antigravity::launcher::DEFAULT_MODEL_ID;
use sagy::core::state::{AccountRecord, AccountType};
use sagy::core::storage;

const RATE_LIMIT_JSON: &str =
    r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","Retry-After":45}}"#;
const AUTH_REJECTED_JSON: &str = r#"{"error":{"code":401,"status":"UNAUTHENTICATED"}}"#;

struct Fixture {
    _temp: tempfile::TempDir,
    state_dir: PathBuf,
    home: PathBuf,
    gemini_home: PathBuf,
    antigravity_home: PathBuf,
    fake_agy: PathBuf,
    launch_log: PathBuf,
    argv_log: PathBuf,
    tty_log: PathBuf,
    env_log: PathBuf,
}

impl Fixture {
    /// `body` runs inside the fake `agy` with `$token` already resolved.
    fn new(accounts: &[(&str, &str, &str)], body: &str) -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        let home = temp.path().join("home");
        let gemini_home = temp.path().join("gemini");
        let antigravity_home = temp.path().join("antigravity");
        let fake_agy = temp.path().join("fake-agy");
        for path in [&home, &gemini_home, &antigravity_home] {
            fs::create_dir_all(path).expect("create isolated home");
        }
        write_fake_agy(&fake_agy, body);
        write_legacy_pool(&state_dir, accounts);
        Self {
            state_dir,
            home,
            gemini_home,
            antigravity_home,
            fake_agy,
            launch_log: temp.path().join("launch.log"),
            argv_log: temp.path().join("argv.log"),
            tty_log: temp.path().join("tty.log"),
            env_log: temp.path().join("env.log"),
            _temp: temp,
        }
    }

    fn command(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env("HOME", &self.home)
            .env("GEMINI_HOME", &self.gemini_home)
            .env("ANTIGRAVITY_CONFIG_DIR", &self.antigravity_home)
            .env("AGY_BIN", &self.fake_agy)
            .env("FAKE_AGY_LAUNCH_LOG", &self.launch_log)
            .env("FAKE_AGY_ARGV_LOG", &self.argv_log)
            .env("FAKE_AGY_TTY_LOG", &self.tty_log)
            .env("FAKE_AGY_ENV_LOG", &self.env_log)
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT");
        command
    }

    fn run(&self, extra: &[&str]) -> Output {
        let mut command = self.command(Path::new(env!("CARGO_BIN_EXE_sagy")));
        command.arg("--state-dir").arg(&self.state_dir);
        command.args(extra);
        command.output().expect("run sagy")
    }

    /// `parent_env` 模拟用户父 shell 里已经导出的变量。
    fn run_with_parent_env(&self, extra: &[&str], parent_env: &[(&str, &str)]) -> Output {
        let mut command = self.command(Path::new(env!("CARGO_BIN_EXE_sagy")));
        for (name, value) in parent_env {
            command.env(name, value);
        }
        command.arg("--state-dir").arg(&self.state_dir);
        command.args(extra);
        command.output().expect("run sagy")
    }

    /// 与 [`Self::run`] 相同, 但不等待结束: 用来制造两个并发的 launch。
    fn spawn(&self, extra: &[&str]) -> Child {
        let mut command = self.command(Path::new(env!("CARGO_BIN_EXE_sagy")));
        command.arg("--state-dir").arg(&self.state_dir);
        command.args(extra);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sagy")
    }

    fn launched_tokens(&self) -> Vec<String> {
        read_log_lines(&self.launch_log)
    }

    fn state(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.state_dir.join("state.json")).expect("read v2 state"))
            .expect("parse v2 state")
    }
}

fn read_log_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(ToOwned::to_owned)
        .collect()
}

fn one_account() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![("solo-one", "solo@example.test", "token-one")]
}

fn two_accounts() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("fallback-one", "one@example.test", "token-one"),
        ("fallback-two", "two@example.test", "token-two"),
    ]
}

// ---------------------------------------------------------------------------
// AC-1: the 429 observation must be reachable through real `agy` stderr.
// ---------------------------------------------------------------------------

#[test]
fn noisy_child_429_still_enters_cooldown_and_falls_back() {
    let body = format!(
        "printf 'agy: loading workspace config\\n' >&2
printf 'agy: contacting backend\\n' >&2
if [ \"$token\" = \"token-one\" ]; then
    printf '%s\\n' '{RATE_LIMIT_JSON}' >&2
    printf 'agy: session closed\\n' >&2
    exit 1
fi
exit 0
"
    );
    let fixture = Fixture::new(&two_accounts(), &body);
    let output = fixture.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.launched_tokens(), ["token-one", "token-two"]);

    let state = fixture.state();
    assert_eq!(state["current_account_id"], "fallback-two");
    assert_eq!(
        state["usage_cache"]["fallback-one"]["health"],
        "rate_limited"
    );
    assert!(state["usage_cache"]["fallback-one"]["cooldown"].is_object());
}

#[test]
fn rate_limit_json_after_a_log_flood_beyond_the_bound_is_still_observed() {
    // 64 KiB 是诊断缓冲上限; 这里先打约 120 KiB 无关日志再打限流 JSON,
    // 早期日志绝不能把后面的证据挤掉。
    let flood = "awk 'BEGIN { for (i = 0; i < 2000; i++) \
                 printf \"agy: noise %d 0123456789012345678901234567890123456789012345\\n\", i }' >&2";
    let body = format!(
        "{flood}
if [ \"$token\" = \"token-one\" ]; then
    printf '%s\\n' '{RATE_LIMIT_JSON}' >&2
    exit 1
fi
exit 0
"
    );
    let fixture = Fixture::new(&two_accounts(), &body);
    let output = fixture.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.launched_tokens(), ["token-one", "token-two"]);
    let state = fixture.state();
    assert_eq!(
        state["usage_cache"]["fallback-one"]["health"],
        "rate_limited"
    );
    assert!(state["usage_cache"]["fallback-one"]["cooldown"].is_object());
}

/// AC-R11-2.1: 日志里出现一个不配对的 `{` 之后, 后面真实的 429 仍须被识别。
///
/// 噪声量刻意卡在诊断上限的边缘: 只要那个裸 `{` 被当成候选文档滞留, 限流 JSON
/// 到达时就会把缓冲区顶过上限, 整块被丢弃, 证据一起消失。
#[test]
fn a_stray_brace_in_a_log_line_does_not_swallow_the_rate_limit_that_follows() {
    let stray = "agy: applying overrides { model=x\n";
    let tail = RATE_LIMIT_JSON.len() + 2;
    let noise = MAX_DIAGNOSTIC_BYTES - stray.len() - tail / 2;
    let body = format!(
        "if [ \"$token\" = \"token-one\" ]; then
    printf 'agy: applying overrides {{ model=x\\n' >&2
    head -c {noise} /dev/zero | tr '\\000' 'n' >&2
    printf '\\n%s\\n' '{RATE_LIMIT_JSON}' >&2
    exit 1
fi
exit 0
"
    );
    let fixture = Fixture::new(&two_accounts(), &body);
    let output = fixture.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fixture.launched_tokens(), ["token-one", "token-two"]);
    let state = fixture.state();
    assert_eq!(
        state["usage_cache"]["fallback-one"]["health"],
        "rate_limited"
    );
    assert!(state["usage_cache"]["fallback-one"]["cooldown"].is_object());
}

/// AC-R11-3.1: 401 与 429 同时出现时必须判成"需要重新登录", 不能记成冷却。
///
/// 记成冷却的后果是静默的: 账号在 cooldown 到期后被重新选中、继续失败, 用户
/// 永远看不到重新登录的提示。
#[test]
fn a_child_cannot_hide_an_expired_token_behind_a_rate_limit_document() {
    let body = format!(
        "printf '%s\\n' '{RATE_LIMIT_JSON}' >&2
printf 'agy: retrying\\n' >&2
printf '%s\\n' '{AUTH_REJECTED_JSON}' >&2
exit 1
"
    );
    let fixture = Fixture::new(&one_account(), &body);
    let output = fixture.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(!output.status.success());
    // 认证失效不是可重试的限流, 不得触发降级重试。
    assert_eq!(fixture.launched_tokens(), ["token-one"]);
    let usage = &fixture.state()["usage_cache"]["solo-one"];
    assert_ne!(
        usage["health"], "rate_limited",
        "a 429 printed next to a 401 downgraded the account into a cooldown: {usage}"
    );
    assert!(
        !usage["cooldown"].is_object(),
        "an expired token must not be recorded as a cooldown: {usage}"
    );
}

// ---------------------------------------------------------------------------
// AC-R11-1: the lock wait notice belongs to the locking layer alone.
// ---------------------------------------------------------------------------

const LOCK_WAIT_NOTICE_MARKER: &str = "waiting for another sagy session to release";

/// AC-R11-1.2 / AC-R11-1.3: 两个 launch 争锁时提示必须恰好一条, 不争锁的那个
/// 必须完全安静。
#[test]
fn two_contending_launches_print_exactly_one_lock_wait_notice() {
    // 第一个 launch 在子进程存活期间一直持有 account/active-home lease,
    // 睡够时间让第二个 launch 越过 750ms 的提示阈值。
    let fixture = Fixture::new(&one_account(), "sleep 2\nexit 0\n");
    let holder = fixture.spawn(&["launch", "--no-import-known", "--no-resume"]);
    wait_until_child_started(&fixture);

    let waiter = fixture.spawn(&["launch", "--no-import-known", "--no-resume"]);
    let waiter = waiter
        .wait_with_output()
        .expect("wait for the second launch");
    let holder = holder
        .wait_with_output()
        .expect("wait for the first launch");

    let holder_stderr = String::from_utf8_lossy(&holder.stderr).into_owned();
    let waiter_stderr = String::from_utf8_lossy(&waiter.stderr).into_owned();
    assert!(
        holder.status.success(),
        "the uncontended launch failed: {holder_stderr}"
    );
    assert_eq!(
        holder_stderr.matches(LOCK_WAIT_NOTICE_MARKER).count(),
        0,
        "an uncontended launch must stay silent: {holder_stderr}"
    );
    assert_eq!(
        waiter_stderr.matches(LOCK_WAIT_NOTICE_MARKER).count(),
        1,
        "a contended launch must print exactly one wait notice: {waiter_stderr}"
    );
    assert!(
        waiter_stderr.is_ascii(),
        "console output must be ASCII only: {waiter_stderr}"
    );
}

/// AC-R11-1.3: 锁立刻可得时, launch 路径不得付出与提示阈值同量级的代价。
///
/// 用同一条命令的 `--dry-run` 做基准: 它跑完全部状态工作但不取 launch lease,
/// 两者之差就是"取锁 + 起子进程"的成本。提示层一旦回到关键路径上并丢掉一次
/// 唤醒, 每次 launch 都会多出一整个 750ms 阈值。
///
/// 两条命令交替计时并各取最小值: 最小值代表机器空闲时的真实成本, 不会被并行
/// 跑的其它测试带来的负载尖峰污染, 而"每次都多花 750ms"的回归无法躲过最小值。
#[test]
fn taking_an_available_lease_costs_far_less_than_the_notice_threshold() {
    const ROUNDS: usize = 5;
    let fixture = Fixture::new(&one_account(), "exit 0\n");
    let measure = |extra: &[&str], round: usize| {
        let started = Instant::now();
        let output = fixture.run(extra);
        let elapsed = started.elapsed();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(output.status.success(), "round {round} failed: {stderr}");
        assert_eq!(
            stderr.matches(LOCK_WAIT_NOTICE_MARKER).count(),
            0,
            "round {round} printed a wait notice: {stderr}"
        );
        elapsed
    };
    let mut without_leases = Duration::MAX;
    let mut with_leases = Duration::MAX;
    for round in 0..ROUNDS {
        without_leases = without_leases.min(measure(
            &["launch", "--no-import-known", "--no-resume", "--dry-run"],
            round,
        ));
        with_leases = with_leases.min(measure(
            &["launch", "--no-import-known", "--no-resume"],
            round,
        ));
    }
    let overhead = with_leases.saturating_sub(without_leases);
    assert!(
        overhead < Duration::from_millis(400),
        "acquiring an available lease cost {overhead:?} on top of the same command without \
         leases ({without_leases:?} -> {with_leases:?}); the wait notice must not be on the \
         critical path"
    );
}

/// 等到 fake agy 真正开始执行: 此刻第一个 launch 已经持有全部 lease。
fn wait_until_child_started(fixture: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if !read_log_lines(&fixture.launch_log).is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the first launch never reached the fake agy");
}

// ---------------------------------------------------------------------------
// AC-R11-4: region configuration is not a credential.
// ---------------------------------------------------------------------------

/// AC-R11-4.1 / AC-R11-4.2: 父 shell 里导出的区域必须活着到达子进程, 而同一次
/// launch 里凭据类变量一个都不能继承下去。
#[test]
fn the_parent_region_survives_while_credentials_are_still_cleared() {
    let body = "printf 'GOOGLE_CLOUD_LOCATION=%s\\n' \"${GOOGLE_CLOUD_LOCATION-<unset>}\" \
                >> \"$FAKE_AGY_ENV_LOG\"
printf 'GEMINI_API_KEY=%s\\n' \"${GEMINI_API_KEY-<unset>}\" >> \"$FAKE_AGY_ENV_LOG\"
printf 'GOOGLE_API_KEY=%s\\n' \"${GOOGLE_API_KEY-<unset>}\" >> \"$FAKE_AGY_ENV_LOG\"
printf 'GOOGLE_CLOUD_QUOTA_PROJECT=%s\\n' \"${GOOGLE_CLOUD_QUOTA_PROJECT-<unset>}\" \
                >> \"$FAKE_AGY_ENV_LOG\"
printf 'GOOGLE_GENAI_USE_VERTEXAI=%s\\n' \"${GOOGLE_GENAI_USE_VERTEXAI-<unset>}\" \
                >> \"$FAKE_AGY_ENV_LOG\"
exit 0
"
    .to_string();
    let fixture = Fixture::new(&one_account(), &body);
    let output = fixture.run_with_parent_env(
        &["launch", "--no-import-known", "--no-resume"],
        &[
            ("GOOGLE_CLOUD_LOCATION", "europe-west4"),
            ("GEMINI_API_KEY", "parent-api-key"),
            ("GOOGLE_API_KEY", "parent-google-api-key"),
            ("GOOGLE_CLOUD_QUOTA_PROJECT", "parent-quota-project"),
            ("GOOGLE_GENAI_USE_VERTEXAI", "true"),
        ],
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_log_lines(&fixture.env_log),
        [
            "GOOGLE_CLOUD_LOCATION=europe-west4",
            "GEMINI_API_KEY=<unset>",
            "GOOGLE_API_KEY=<unset>",
            "GOOGLE_CLOUD_QUOTA_PROJECT=<unset>",
            "GOOGLE_GENAI_USE_VERTEXAI=<unset>",
        ]
    );
}

/// 只有长得像 region id 的父进程值才会被写回。
#[test]
fn a_parent_value_that_is_not_a_region_is_not_reinjected() {
    let body = "printf 'GOOGLE_CLOUD_LOCATION=%s\\n' \"${GOOGLE_CLOUD_LOCATION-<unset>}\" \
                >> \"$FAKE_AGY_ENV_LOG\"
exit 0
"
    .to_string();
    let fixture = Fixture::new(&one_account(), &body);
    let output = fixture.run_with_parent_env(
        &["launch", "--no-import-known", "--no-resume"],
        &[("GOOGLE_CLOUD_LOCATION", "parent-inherited-value")],
    );
    assert!(output.status.success());
    assert_eq!(
        read_log_lines(&fixture.env_log),
        ["GOOGLE_CLOUD_LOCATION=<unset>"]
    );
}

#[test]
fn a_canonical_auth_failure_is_not_reported_as_a_rate_limit() {
    let body = format!(
        "printf 'agy: loading workspace config\\n' >&2
printf '%s\\n' '{AUTH_REJECTED_JSON}' >&2
exit 1
"
    );
    let fixture = Fixture::new(&one_account(), &body);
    let output = fixture.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(!output.status.success());
    // 非限流失败不得触发降级重试。
    assert_eq!(fixture.launched_tokens(), ["token-one"]);

    let state = fixture.state();
    let usage = &state["usage_cache"]["solo-one"];
    assert_ne!(usage["health"], "rate_limited");
    assert!(
        !usage["cooldown"].is_object(),
        "auth failure must not create a rate-limit cooldown: {usage}"
    );
}

// ---------------------------------------------------------------------------
// AC-2: the child must keep the parent's terminal.
// ---------------------------------------------------------------------------

#[test]
fn child_stderr_is_a_terminal_exactly_when_the_sagy_stderr_is() {
    let body = "if [ -t 2 ]; then printf 'tty\\n' >> \"$FAKE_AGY_TTY_LOG\"; \
                else printf 'notty\\n' >> \"$FAKE_AGY_TTY_LOG\"; fi
exit 0
"
    .to_string();

    let piped = Fixture::new(&one_account(), &body);
    let output = piped.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(output.status.success());
    assert_eq!(read_log_lines(&piped.tty_log), ["notty"]);

    let terminal = Fixture::new(&one_account(), &body);
    let output = pty_command(&terminal)
        .output()
        .expect("run sagy under a pty");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_log_lines(&terminal.tty_log),
        ["tty"],
        "agy lost isatty(2) even though sagy stderr is a terminal"
    );
}

/// Wrap a `sagy launch` in a pty using whichever `script` dialect exists here.
fn pty_command(fixture: &Fixture) -> Command {
    let wrapper = fixture._temp.path().join("launch-under-pty.sh");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec {} --state-dir {} launch --no-import-known --no-resume\n",
            shell_quote(env!("CARGO_BIN_EXE_sagy")),
            shell_quote(&fixture.state_dir.to_string_lossy())
        ),
    )
    .expect("write pty wrapper");
    set_executable(&wrapper);

    let mut command = fixture.command(Path::new("script"));
    if util_linux_script() {
        command.arg("-qec").arg(&wrapper).arg("/dev/null");
    } else {
        command.arg("-q").arg("/dev/null").arg(&wrapper);
    }
    command.stdin(Stdio::null());
    command
}

/// util-linux `script` understands `--version`; the BSD one exits non-zero.
fn util_linux_script() -> bool {
    Command::new("script")
        .arg("--version")
        .output()
        .map(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("util-linux")
        })
        .unwrap_or(false)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

// ---------------------------------------------------------------------------
// AC-3: a failing parent mirror must not swallow the child's result.
// ---------------------------------------------------------------------------

#[test]
fn a_broken_parent_stderr_still_returns_the_child_exit_code_and_cooldown() {
    // agy 先睡一会, 让测试在它写第一行之前就关掉 sagy stderr 的读端,
    // 这样转发写入必然拿到 EPIPE。
    let body = format!(
        "sleep 1
printf 'agy: noise\\n' >&2
printf '%s\\n' '{RATE_LIMIT_JSON}' >&2
exit 7
"
    );
    let fixture = Fixture::new(&one_account(), &body);
    let mut command = fixture.command(Path::new(env!("CARGO_BIN_EXE_sagy")));
    command.arg("--state-dir").arg(&fixture.state_dir);
    command.args(["launch", "--no-import-known", "--no-resume"]);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn sagy");
    let mut stderr = child.stderr.take().expect("sagy stderr pipe");
    read_one_line(&mut stderr);
    drop(stderr);

    let status = child.wait().expect("wait sagy");
    assert_eq!(
        status.code(),
        Some(7),
        "the child exit code must survive a broken parent mirror"
    );
    let usage = &fixture.state()["usage_cache"]["solo-one"];
    assert_eq!(usage["health"], "rate_limited");
    assert!(
        usage["cooldown"].is_object(),
        "the parsed rate-limit evidence must still be committed: {usage}"
    );
}

/// AC-R5-3: `sagy ... 2>&1 | head -c 0` -- 读端在 sagy 写第一个字节之前就已经
/// 关闭。上一版在这里走的是 `eprintln!` 的 panic 路径, 退出码变成 101,
/// agy 根本不会被 spawn。
#[test]
fn an_unwritable_parent_stderr_from_the_first_byte_still_returns_the_child_exit_code() {
    let body = format!(
        "printf 'agy: noise\\n' >&2
printf '%s\\n' '{RATE_LIMIT_JSON}' >&2
exit 7
"
    );
    let fixture = Fixture::new(&one_account(), &body);
    let mut command = fixture.command(Path::new(env!("CARGO_BIN_EXE_sagy")));
    command.arg("--state-dir").arg(&fixture.state_dir);
    command.args(["launch", "--no-import-known", "--no-resume"]);
    // 两条真实的管道, 读端在 spawn sagy 之前就已经随 helper 进程退出而关闭。
    command.stdout(closed_pipe_write_end());
    command.stderr(closed_pipe_write_end());
    let status = command
        .spawn()
        .expect("spawn sagy")
        .wait()
        .expect("wait sagy");

    assert_eq!(
        status.code(),
        Some(7),
        "an unwritable parent stderr must not replace the agy exit code"
    );
    assert_eq!(
        fixture.launched_tokens(),
        ["token-one"],
        "agy must still be spawned when the parent cannot write its own output"
    );
    let usage = &fixture.state()["usage_cache"]["solo-one"];
    assert_eq!(usage["health"], "rate_limited");
    assert!(
        usage["cooldown"].is_object(),
        "the parsed rate-limit evidence must still be committed: {usage}"
    );
}

/// The write end of a pipe whose read end is already closed: every write on it
/// fails with `EPIPE`.
///
/// helper 进程先退出, 我们只保留它的 stdin 写端, 因此不存在"读端还没来得及
/// 关闭"的竞态。
fn closed_pipe_write_end() -> Stdio {
    let mut reader = Command::new("sh")
        .args(["-c", "exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pipe reader");
    let write_end = reader.stdin.take().expect("pipe write end");
    reader.wait().expect("reap pipe reader");
    Stdio::from(write_end)
}

/// Read exactly one line so the reader closes after sagy's own selection line
/// but before the mirrored child output arrives.
fn read_one_line<R: Read>(reader: &mut R) {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) | Err(_) => return,
            Ok(_) if byte[0] == b'\n' => return,
            Ok(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// AC-4: `-m` must be equivalent to `--model`.
// ---------------------------------------------------------------------------

#[test]
fn every_model_flag_spelling_replaces_the_injected_default() {
    let body = "exit 0\n".to_string();
    for spelling in [
        vec!["--model", "custom-model"],
        vec!["--model=custom-model"],
        vec!["-m", "custom-model"],
        vec!["-m=custom-model"],
    ] {
        let fixture = Fixture::new(&one_account(), &body);
        let output = fixture.run(&spelling);
        assert!(
            output.status.success(),
            "spelling={spelling:?} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let argv = read_log_lines(&fixture.argv_log);
        // 只断言本 AC 关心的部分: 用户给出的 model flag 原样透传, 且不再叠加默认模型。
        // 是否额外注入 --continue 由 resume 规则决定(T7 归属), 这里不做过约束。
        assert_eq!(argv.len(), 1, "spelling={spelling:?}");
        assert!(
            argv[0].ends_with(&spelling.join(" ")),
            "spelling={spelling:?} argv={}",
            argv[0]
        );
        assert!(
            !argv[0].contains(DEFAULT_MODEL_ID),
            "default model still injected for {spelling:?}: {}",
            argv[0]
        );
    }
}

#[test]
fn the_default_model_is_injected_when_the_user_gives_none() {
    let fixture = Fixture::new(&one_account(), "exit 0\n");
    let output = fixture.run(&["launch", "--no-import-known", "--no-resume"]);
    assert!(output.status.success());
    assert_eq!(
        read_log_lines(&fixture.argv_log),
        [format!("--model {DEFAULT_MODEL_ID}")]
    );
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn write_legacy_pool(state_dir: &Path, accounts: &[(&str, &str, &str)]) {
    let now = Utc::now().timestamp();
    let records = accounts
        .iter()
        .map(|(id, email, token)| {
            let path = state_dir
                .join("accounts")
                .join(id)
                .join("antigravity-oauth-token");
            storage::write_secret_file(&path, token.as_bytes()).expect("write fixed token");
            AccountRecord {
                id: (*id).to_string(),
                email: (*email).to_string(),
                account_type: AccountType::OAuth,
                auth_path: path.to_string_lossy().into_owned(),
                oauth_token: Some((*token).to_string()),
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
    let usage_cache = accounts
        .iter()
        .map(|(id, _, _)| ((*id).to_string(), usage.clone()))
        .collect::<serde_json::Map<_, _>>();
    let state = serde_json::json!({
        "version": 1,
        "accounts": records,
        "usage_cache": usage_cache,
        "current_account_id": accounts.first().expect("at least one account").0
    });
    storage::write_secret_file(
        &state_dir.join("state.json"),
        &serde_json::to_vec_pretty(&state).expect("encode legacy state"),
    )
    .expect("write legacy state");
}

fn write_fake_agy(path: &Path, body: &str) {
    fs::write(
        path,
        format!(
            r#"#!/bin/sh
set -eu
token=$(cat "$ANTIGRAVITY_CONFIG_DIR/antigravity-oauth-token")
printf '%s\n' "$token" >> "$FAKE_AGY_LAUNCH_LOG"
printf '%s\n' "$*" >> "$FAKE_AGY_ARGV_LOG"
{body}"#
        ),
    )
    .expect("write fake agy");
    set_executable(path);
}

fn set_executable(path: &Path) {
    let mut permissions = fs::metadata(path).expect("stat script").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("chmod script");
}
