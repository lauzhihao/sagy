//! T1 回归测试：state root 可用性与写读不变量对称。
//!
//! 全部走真实二进制，因为要证明的东西正是"按官方安装脚本布局装完之后，
//! 用户敲下的每一条命令还能不能用"，这只能在进程边界上判定。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const V2_EMPTY_STATE: &str = r#"{
  "version": 2,
  "revision": 1,
  "accounts": [],
  "usage_cache": {},
  "current_account_id": null,
  "active_profile": null,
  "sync_watermarks": {}
}"#;

struct Sandbox {
    _temp: TempDir,
    home: PathBuf,
    state_dir: PathBuf,
    antigravity: PathBuf,
    gemini: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let state_dir = home.join(".sagy");
        let antigravity = home.join("antigravity");
        let gemini = home.join("gemini");
        for path in [&home, &state_dir, &antigravity, &gemini] {
            fs::create_dir_all(path).expect("create sandbox directory");
        }
        Self {
            _temp: temp,
            home,
            state_dir,
            antigravity,
            gemini,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
        command
            .env("HOME", &self.home)
            .env("SAGY_HOME", &self.state_dir)
            .env("ANTIGRAVITY_CONFIG_DIR", &self.antigravity)
            .env("GEMINI_HOME", &self.gemini);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("run sagy")
    }

    fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command()
            .current_dir(cwd)
            .args(args)
            .output()
            .expect("run sagy")
    }

    /// 让 `import-known` 真的有东西可导入，从而走到"会写 state"的分支。
    fn seed_importable_oauth_token(&self) {
        fs::write(
            self.antigravity.join("antigravity-oauth-token"),
            "oauth-access-token",
        )
        .expect("write importable token");
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} exited with {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        stdout_of(output),
        stderr_of(output)
    );
}

fn assert_failure(output: &Output, label: &str) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded\nstdout: {}",
        stdout_of(output)
    );
}

fn modified_at(path: &Path) -> std::time::SystemTime {
    fs::symlink_metadata(path)
        .expect("inspect entry")
        .modified()
        .expect("entry mtime")
}

// ---------------------------------------------------------------------------
// AC-1: 安装器布局不得让 sagy 不可用

/// AC-1.1
#[test]
fn installer_bin_directory_does_not_break_commands() {
    let sandbox = Sandbox::new();
    fs::create_dir(sandbox.state_dir.join("bin")).expect("create bin dir");

    let output = sandbox.run(&["list"]);
    assert_success(&output, "list with bin/ present");
}

/// AC-1.2
#[test]
fn fresh_root_containing_only_tmp_dir_does_not_break_commands() {
    let sandbox = Sandbox::new();
    fs::create_dir(sandbox.state_dir.join("tmp")).expect("create tmp dir");
    assert!(!sandbox.state_dir.join("state.json").exists());

    let output = sandbox.run(&["list"]);
    assert_success(&output, "list on a state-less root that only has tmp/");
}

/// AC-1.3 与 AC-1.4
#[test]
fn foreign_entries_are_ignored_and_left_untouched() {
    let sandbox = Sandbox::new();
    sandbox.seed_importable_oauth_token();

    let notes = sandbox.state_dir.join("notes.txt");
    let ds_store = sandbox.state_dir.join(".DS_Store");
    let backup_dir = sandbox.state_dir.join("backup");
    let backup_file = backup_dir.join("keep.txt");
    fs::write(&notes, b"user notes").expect("write notes");
    fs::write(&ds_store, b"finder junk").expect("write .DS_Store");
    fs::create_dir(&backup_dir).expect("create backup dir");
    fs::write(&backup_file, b"kept payload").expect("write backup file");

    let foreign: Vec<PathBuf> = vec![
        notes.clone(),
        ds_store.clone(),
        backup_dir.clone(),
        backup_file.clone(),
    ];
    let before: Vec<std::time::SystemTime> = foreign.iter().map(|path| modified_at(path)).collect();

    assert_success(&sandbox.run(&["list"]), "list with foreign root entries");
    // import-known 是一条真的会提交 state 的命令。
    assert_success(
        &sandbox.run(&["import-known"]),
        "import-known with foreign root entries",
    );
    assert!(
        sandbox.state_dir.join("state.json").exists(),
        "import-known did not commit a state document"
    );

    // AC-1.4：内容与 mtime 都不得被 sagy 改动。
    assert_eq!(fs::read(&notes).expect("read notes"), b"user notes");
    assert_eq!(fs::read(&ds_store).expect("read .DS_Store"), b"finder junk");
    assert_eq!(
        fs::read(&backup_file).expect("read backup file"),
        b"kept payload"
    );
    let after: Vec<std::time::SystemTime> = foreign.iter().map(|path| modified_at(path)).collect();
    assert_eq!(before, after, "sagy changed a foreign entry mtime");
}

/// AC-1.5: sagy 自己纳管的名字仍然严格校验。
#[cfg(unix)]
#[test]
fn managed_state_document_symlink_is_still_rejected() {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new();
    let victim = sandbox.home.join("victim-state.json");
    fs::write(&victim, V2_EMPTY_STATE).expect("write victim state");
    symlink(&victim, sandbox.state_dir.join("state.json")).expect("symlink state.json");

    assert_failure(&sandbox.run(&["list"]), "list with symlinked state.json");
    assert_eq!(
        fs::read_to_string(&victim).expect("read victim"),
        V2_EMPTY_STATE
    );
}

/// AC-1.5
#[test]
fn managed_accounts_entry_must_be_a_directory() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.state_dir.join("state.json"), V2_EMPTY_STATE).expect("write state");
    fs::write(sandbox.state_dir.join("accounts"), b"not a directory").expect("write accounts file");

    let output = sandbox.run(&["list"]);
    assert_failure(&output, "list with accounts as a regular file");
    assert!(
        stderr_of(&output).contains("accounts must be a directory"),
        "unexpected stderr: {}",
        stderr_of(&output)
    );
}

/// AC-1.5
#[test]
fn managed_repo_sync_config_over_the_limit_is_still_rejected() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.state_dir.join("state.json"), V2_EMPTY_STATE).expect("write state");
    fs::write(
        sandbox.state_dir.join("repo-sync.json"),
        vec![b'a'; 5 * 1024 * 1024],
    )
    .expect("write oversized repo-sync.json");

    let output = sandbox.run(&["list"]);
    assert_failure(&output, "list with oversized repo-sync.json");
    assert!(
        stderr_of(&output).contains("repo-sync.json is too large"),
        "unexpected stderr: {}",
        stderr_of(&output)
    );
}

// ---------------------------------------------------------------------------
// AC-2: 当前工作目录不是安全边界

/// AC-2.1
#[test]
fn cwd_inside_the_state_root_is_not_a_boundary() {
    let sandbox = Sandbox::new();
    let output = sandbox.run_in(&sandbox.state_dir.clone(), &["list"]);
    assert_success(&output, "list from inside the state root");
}

/// AC-2.2
#[test]
fn cwd_inside_the_antigravity_config_dir_is_not_a_boundary() {
    let sandbox = Sandbox::new();
    let output = sandbox.run_in(&sandbox.antigravity.clone(), &["list"]);
    assert_success(&output, "list from inside ANTIGRAVITY_CONFIG_DIR");
}

/// AC-2.3
#[test]
fn home_itself_is_still_refused_as_a_state_root() {
    let sandbox = Sandbox::new();
    let home = sandbox.home.to_str().expect("UTF-8 home").to_string();
    let output = sandbox.run(&["--state-dir", &home, "list"]);
    assert_failure(&output, "--state-dir $HOME");
    assert!(
        stderr_of(&output).contains("protected system directory cannot be claimed"),
        "unexpected stderr: {}",
        stderr_of(&output)
    );
}

/// AC-2.3 / AC-R1-6.3
///
/// 只断言"退出码非 0"等于什么都没断言——任何原因的失败都会让它通过。
/// 这里必须连拒绝的**理由**一起断言，并且把 `temp_dir()` 这条 protected
/// 目录也覆盖上：这两条走的是不同的守卫。
#[test]
fn filesystem_root_and_shared_temp_dir_are_refused_with_their_own_reasons() {
    let sandbox = Sandbox::new();

    let filesystem_root = sandbox
        .home
        .ancestors()
        .last()
        .expect("sandbox home must have a filesystem root")
        .to_str()
        .expect("filesystem root must be UTF-8");
    let output = sandbox.run(&["--state-dir", filesystem_root, "list"]);
    assert_failure(&output, "--state-dir /");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("filesystem root cannot be used as a store root"),
        "unexpected rejection reason for the filesystem root: {stderr}"
    );

    let shared_temp = std::env::temp_dir();
    let output = sandbox.run(&[
        "--state-dir",
        shared_temp.to_str().expect("UTF-8 temp dir"),
        "list",
    ]);
    assert_failure(&output, "--state-dir <temp_dir>");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("protected system directory cannot be claimed"),
        "unexpected rejection reason for the shared temp dir: {stderr}"
    );
    // 拒绝必须在任何写之前发生：共享临时目录里不得留下 sagy 的固定条目。
    assert!(
        !shared_temp.join("state.json").exists(),
        "sagy created a state document inside the shared temp directory"
    );
}

#[cfg(windows)]
#[test]
fn windows_root_relative_separator_is_not_a_filesystem_root() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--state-dir", "\\", "list"]);
    assert_failure(&output, "root-relative --state-dir");
    assert!(
        stderr_of(&output).contains("store root must be absolute"),
        "a root-relative Windows path must not be classified as a filesystem root: {}",
        stderr_of(&output)
    );
}

#[cfg(windows)]
#[test]
fn windows_home_and_userprofile_are_both_protected() {
    let sandbox = Sandbox::new();
    let userprofile = sandbox._temp.path().join("userprofile");
    fs::create_dir(&userprofile).expect("create alternate userprofile");

    let roots = [&sandbox.home, &userprofile];
    let before = roots
        .iter()
        .map(|root| {
            let mut entries = fs::read_dir(root)
                .expect("read protected root")
                .map(|entry| entry.expect("read root entry").file_name())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        })
        .collect::<Vec<_>>();

    for root in roots {
        let root_text = root.to_str().expect("protected root must be UTF-8");
        let output = sandbox
            .command()
            .env("HOME", &sandbox.home)
            .env("USERPROFILE", &userprofile)
            .args(["--state-dir", root_text, "list"])
            .output()
            .expect("run sagy");
        assert_failure(&output, "claiming HOME or USERPROFILE");
        assert!(
            stderr_of(&output).contains("protected system directory cannot be claimed"),
            "protected home rejection lost its reason: {}",
            stderr_of(&output)
        );
    }

    let after = roots
        .iter()
        .map(|root| {
            let mut entries = fs::read_dir(root)
                .expect("read protected root")
                .map(|entry| entry.expect("read root entry").file_name())
                .collect::<Vec<_>>();
            entries.sort();
            entries
        })
        .collect::<Vec<_>>();
    assert_eq!(before, after, "protected home claim wrote state artifacts");
}

// ---------------------------------------------------------------------------
// AC-3: v1 解析要丢弃占位账号

/// AC-3.1 与 AC-3.2
#[test]
fn v1_placeholder_account_is_dropped_without_losing_healthy_accounts() {
    let sandbox = Sandbox::new();
    let account_dir = sandbox.state_dir.join("accounts").join("real-account");
    fs::create_dir_all(&account_dir).expect("create account dir");
    fs::write(
        account_dir.join("antigravity-oauth-token"),
        "synthetic-token",
    )
    .expect("write account token");
    fs::write(
        sandbox.state_dir.join("state.json"),
        r#"{
  "accounts": [
    { "id": "placeholder", "email": "google_accounts" },
    {
      "id": "real-account",
      "email": "real@example.test",
      "account_type": "oauth",
      "oauth_token": "synthetic-token"
    }
  ],
  "current_account_id": "placeholder",
  "usage_cache": { "placeholder": { "status": "Ready" } }
}"#,
    )
    .expect("write v1 state");

    let output = sandbox.run(&["list"]);
    assert_success(&output, "list over a v1 state with a placeholder account");
    let listed = stdout_of(&output);
    assert!(
        listed.contains("real@example.test"),
        "healthy account disappeared: {listed}"
    );
    assert!(
        !listed.contains("google_accounts"),
        "placeholder account survived: {listed}"
    );
}

// ---------------------------------------------------------------------------
// AC-4: 既有宽权限凭据要迁移收紧

/// AC-4.1
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::symlink_metadata(path)
        .expect("inspect entry")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod fixture");
}

#[cfg(unix)]
#[test]
fn wide_credential_permissions_are_tightened_on_state_open() {
    let sandbox = Sandbox::new();
    let accounts = sandbox.state_dir.join("accounts");
    let account = accounts.join("legacy-account");
    fs::create_dir_all(&account).expect("create account dir");
    let token = account.join("antigravity-oauth-token");
    let settings = account.join("settings.json");
    fs::write(&token, "legacy-token").expect("write token");
    fs::write(&settings, "{}").expect("write settings");
    chmod(&token, 0o644);
    chmod(&settings, 0o644);
    chmod(&account, 0o755);
    chmod(&accounts, 0o755);

    assert_success(
        &sandbox.run(&["list"]),
        "list over wide-permission accounts",
    );

    assert_eq!(mode_of(&accounts), 0o700, "accounts/ was not tightened");
    assert_eq!(mode_of(&account), 0o700, "account dir was not tightened");
    assert_eq!(mode_of(&token), 0o600, "credential was not tightened");
    assert_eq!(mode_of(&settings), 0o600, "settings was not tightened");
    assert_eq!(
        fs::read_to_string(&token).expect("read token"),
        "legacy-token"
    );
}

/// AC-4.2 / AC-R1-6.1: 布局非法时必须由布局校验报错，而不是由权限收紧报错。
///
/// 权限收紧跑在只读校验之前，会先 chmod 一批随后就要被判非法的条目，还会用
/// 一句笼统的 "cannot tighten permissions through a symlink" 顶掉
/// `validate_accounts_dir` 更精确的文案。这条用例锁死这个先后顺序。
#[cfg(unix)]
#[test]
fn layout_validation_reports_before_permission_tightening_touches_anything() {
    use std::os::unix::fs::symlink;

    let sandbox = Sandbox::new();
    let accounts = sandbox.state_dir.join("accounts");
    fs::create_dir_all(&accounts).expect("create accounts dir");
    let outside = sandbox.home.join("outside-account");
    fs::create_dir_all(&outside).expect("create outside dir");
    let victim = outside.join("antigravity-oauth-token");
    fs::write(&victim, "victim-token").expect("write victim token");
    chmod(&outside, 0o755);
    chmod(&victim, 0o644);
    symlink(&outside, accounts.join("linked-account")).expect("symlink account dir");

    let output = sandbox.run(&["list"]);
    assert_failure(&output, "list with a symlinked account directory");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("account directory cannot be a symlink: linked-account"),
        "permission hardening pre-empted the precise layout error: {stderr}"
    );
    // fail-closed 的同时不得顺着 symlink 改动 state root 之外的任何权限。
    assert_eq!(mode_of(&outside), 0o755, "hardening followed the symlink");
    assert_eq!(mode_of(&victim), 0o644, "hardening followed the symlink");
    assert_eq!(
        fs::read_to_string(&victim).expect("read victim token"),
        "victim-token"
    );
}

// ---------------------------------------------------------------------------
// AC-6: 损坏 state 的恢复路径

/// AC-6.1 与 AC-6.2
#[test]
fn corrupt_state_is_quarantined_with_actionable_guidance() {
    let sandbox = Sandbox::new();
    let state_file = sandbox.state_dir.join("state.json");
    let corrupt_bytes = br#"{"version":2,"revi"#;
    fs::write(&state_file, corrupt_bytes).expect("write corrupt state");

    let output = sandbox.run(&["list"]);
    assert_failure(&output, "list over a truncated state document");
    let stderr = stderr_of(&output);

    // AC-6.1：错误必须说明被隔离到哪个文件，以及下一步能执行什么。
    assert!(
        stderr.contains("state.json.corrupt-"),
        "error does not name the quarantine file: {stderr}"
    );
    assert!(
        stderr.contains("sagy import-known"),
        "error does not name a recovery command: {stderr}"
    );
    assert!(
        stderr.is_ascii(),
        "console output must stay ASCII: {stderr}"
    );

    // AC-6.2：原文件必须被改名保留，不得删除。
    let quarantined: Vec<PathBuf> = fs::read_dir(&sandbox.state_dir)
        .expect("read state root")
        .map(|entry| entry.expect("state root entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("state.json.corrupt-"))
        })
        .collect();
    assert_eq!(
        quarantined.len(),
        1,
        "expected exactly one quarantined file"
    );
    assert_eq!(
        fs::read(&quarantined[0]).expect("read quarantined state"),
        corrupt_bytes
    );
    assert!(!state_file.exists(), "corrupt state.json was left in place");

    // 隔离之后必须真的能继续用，而不是每次都撞同一堵墙。
    assert_success(&sandbox.run(&["list"]), "list after quarantine");
}
