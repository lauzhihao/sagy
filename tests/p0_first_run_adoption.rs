//! HOME-002 回归：已经在用 Antigravity 的机器上，首次使用 sagy 不得被 active-home 卡死。
//!
//! 这些用例不碰任何内部函数，全部驱动真实二进制 + 隔离 HOME + 假 agy，
//! 断言的是用户能观察到的东西：退出码、agy 到底有没有被 spawn、
//! `~/.gemini` / Antigravity 配置目录里的字节、以及错误信息里那条命令。
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// exp = 2100-01-01，本地校验必定判为未过期。
const FRESH_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImVtYWlsIjoiZnJlc2hAZXhhbXBsZS5jb20ifQ.sig";
/// 第二个账号的 token，exp 同样在 2100 年。
const SECOND_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDEsImVtYWlsIjoic2Vjb25kQGV4YW1wbGUuY29tIn0.sig";
/// sagy 从未见过、也无法解析成任何已登记账号的一份凭据。
const FOREIGN_CREDENTIAL: &str = "a-foreign-credential-not-managed-by-sagy";
const TOKEN_FILENAME: &str = "antigravity-oauth-token";
/// 探测端点不可达，健康判定走离线兜底，launch 在无网沙箱里可判定。
const UNREACHABLE_PROXY: &str = "http://127.0.0.1:9";

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create fixture root");
        let root = temp.path().to_path_buf();
        for directory in ["home", "gemini", "antigravity", "sagy-home"] {
            fs::create_dir_all(root.join(directory)).expect("create fixture directory");
        }
        let fixture = Self { _temp: temp, root };
        fixture.write_fake_agy();
        fixture
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("sagy-home")
    }

    fn antigravity(&self) -> PathBuf {
        self.root.join("antigravity")
    }

    fn fake_agy(&self) -> PathBuf {
        self.root.join("fake-agy")
    }

    fn agy_log(&self) -> PathBuf {
        self.root.join("agy-argv.log")
    }

    fn write_fake_agy(&self) {
        let path = self.fake_agy();
        fs::write(
            &path,
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$FAKE_AGY_ARGV_LOG\"\nexit 0\n",
        )
        .expect("write fake agy");
        let mut permissions = fs::metadata(&path).expect("stat fake agy").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("chmod fake agy");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("SAGY_HOME", self.state_dir())
            .env("GEMINI_HOME", self.root.join("gemini"))
            .env("ANTIGRAVITY_CONFIG_DIR", self.antigravity())
            .env("AGY_BIN", self.fake_agy())
            .env("FAKE_AGY_ARGV_LOG", self.agy_log())
            .env("HTTP_PROXY", UNREACHABLE_PROXY)
            .env("HTTPS_PROXY", UNREACHABLE_PROXY)
            .env("http_proxy", UNREACHABLE_PROXY)
            .env("https_proxy", UNREACHABLE_PROXY)
            .env("ALL_PROXY", UNREACHABLE_PROXY)
            .env("all_proxy", UNREACHABLE_PROXY)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT")
            .output()
            .expect("run sagy")
    }

    /// 机器上本来就在用 Antigravity：sagy 接管之前凭据文件就已经存在。
    fn seed_existing_antigravity_credential(&self, bytes: &str) {
        fs::write(self.antigravity().join(TOKEN_FILENAME), bytes)
            .expect("seed pre-existing Antigravity credential");
    }

    fn live_token(&self) -> Option<Vec<u8>> {
        fs::read(self.antigravity().join(TOKEN_FILENAME)).ok()
    }

    fn agy_was_spawned(&self) -> bool {
        fs::read_to_string(self.agy_log())
            .map(|log| !log.trim().is_empty())
            .unwrap_or(false)
    }

    fn reset_agy_log(&self) {
        let _ = fs::remove_file(self.agy_log());
    }

    /// takeover 之后同目录下留下来的备份文件（文件名带 txid）。
    fn takeover_backups(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = fs::read_dir(self.antigravity()) else {
            return found;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&format!("{TOKEN_FILENAME}.sagy-backup-")) {
                found.push(entry.path());
            }
        }
        found
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed: status={:?}\n{}",
        output.status,
        combined(output)
    );
}

/// AC-1.1：`~/.gemini` 下已有凭据的机器上，`import-known` 之后直接 `sagy launch`
/// 必须真的把 agy 拉起来。这是产品的主线上手路径。
#[test]
fn an_existing_antigravity_credential_launches_after_import_known() {
    let fixture = Fixture::new();
    fixture.seed_existing_antigravity_credential(FRESH_JWT);

    let imported = fixture.run(&["import-known"]);
    assert_success(&imported, "sagy import-known");
    assert!(
        combined(&imported).contains("Imported account"),
        "import-known did not import the pre-existing credential: {}",
        combined(&imported)
    );

    let launched = fixture.run(&["launch"]);
    assert_success(&launched, "sagy launch after import-known");
    assert!(
        !combined(&launched).contains("adopt/takeover"),
        "launch still asks for an adopt/takeover the CLI never exposed: {}",
        combined(&launched)
    );
    assert!(
        fixture.agy_was_spawned(),
        "agy was never spawned: {}",
        combined(&launched)
    );
}

/// AC-1.2：用户删掉 `~/.sagy` 重来之后，`sagy login` 与 `sagy launch` 都必须能跑通，
/// 且全程不需要手工删除 `~/.gemini` 下的任何文件（AC-1.3）。
#[test]
fn deleting_the_state_directory_still_allows_login_and_launch() {
    let fixture = Fixture::new();
    fixture.seed_existing_antigravity_credential(FRESH_JWT);
    assert_success(&fixture.run(&["import-known"]), "sagy import-known");
    assert_success(&fixture.run(&["launch"]), "sagy launch");

    // 用户删掉 ~/.sagy 重来：state 没了，active home 里还留着凭据。
    fs::remove_dir_all(fixture.state_dir()).expect("remove state directory");
    let live_before = fixture
        .live_token()
        .expect("active-home credential survives");

    let login = fixture.run(&[
        "login",
        "--token",
        FRESH_JWT,
        "--email",
        "again@example.com",
    ]);
    assert_success(&login, "sagy login after the state directory was deleted");
    assert!(
        !combined(&login).contains("adopt/takeover"),
        "login still asks for an adopt/takeover the CLI never exposed: {}",
        combined(&login)
    );

    fixture.reset_agy_log();
    let launched = fixture.run(&["launch"]);
    assert_success(&launched, "sagy launch after re-login");
    assert!(
        fixture.agy_was_spawned(),
        "agy was never spawned after re-login: {}",
        combined(&launched)
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(live_before.as_slice()),
        "re-login must not have to rewrite an already matching active-home credential"
    );
}

/// AC-2.1：active home 里的凭据**就是**已登记账号那一份时直接接管——
/// 用户不需要做任何事，而且原文件一个字节都不会被改写。
#[test]
fn a_matching_active_home_credential_is_adopted_byte_for_byte() {
    let fixture = Fixture::new();
    fixture.seed_existing_antigravity_credential(FRESH_JWT);
    assert_success(&fixture.run(&["import-known"]), "sagy import-known");

    let launched = fixture.run(&["launch"]);
    assert_success(&launched, "sagy launch");
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(FRESH_JWT.as_bytes()),
        "adopting a matching credential must not rewrite the user's file"
    );
    // 接管是就地完成的，不应该在用户目录里留下任何 takeover 备份。
    assert!(
        fixture.takeover_backups().is_empty(),
        "an adoption must not create a takeover backup: {:?}",
        fixture.takeover_backups()
    );
}

/// 接管不得把"普通切号"也一起放宽：adopt 只在磁盘内容与目标逐字节一致时成立，
/// 其余情况必须退回 Strict 的搬文件流程，否则切号会静默漏写凭据。
#[test]
fn switching_accounts_after_an_adoption_still_republishes_the_credential() {
    let fixture = Fixture::new();
    fixture.seed_existing_antigravity_credential(FRESH_JWT);
    assert_success(&fixture.run(&["import-known"]), "sagy import-known");
    assert_success(&fixture.run(&["launch"]), "sagy launch");

    assert_success(
        &fixture.run(&[
            "add",
            "--token",
            SECOND_JWT,
            "--email",
            "second@example.com",
        ]),
        "sagy add",
    );
    assert_success(&fixture.run(&["use", "second@example.com"]), "sagy use");
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(SECOND_JWT.as_bytes()),
        "switching accounts must actually rewrite the active-home credential"
    );
}

/// AC-2.2：active home 里是 sagy 不认识的凭据时不得静默覆盖，但错误信息
/// 必须说清楚发生了什么、备份会落在哪里，并给出一条真的能敲的 sagy 命令。
#[test]
fn an_unknown_active_home_credential_is_never_overwritten_silently() {
    let fixture = Fixture::new();
    assert_success(
        &fixture.run(&[
            "login",
            "--token",
            FRESH_JWT,
            "--email",
            "owner@example.com",
        ]),
        "sagy login on a clean machine",
    );

    // 用户（或别的工具）在 active home 里放了一份 sagy 不认识的凭据。
    fixture.seed_existing_antigravity_credential(FOREIGN_CREDENTIAL);
    fixture.reset_agy_log();

    let launched = fixture.run(&["launch"]);
    assert!(
        !launched.status.success(),
        "launch silently accepted an unmanaged active-home credential: {}",
        combined(&launched)
    );
    let message = combined(&launched);
    assert!(
        message.is_ascii(),
        "the active-home refusal message must be ASCII-only: {message}"
    );
    assert!(
        message.contains("sagy launch --takeover"),
        "the refusal must name a command the user can actually run: {message}"
    );
    assert!(
        message.contains(".sagy-backup-"),
        "the refusal must say where the existing credential ends up: {message}"
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(FOREIGN_CREDENTIAL.as_bytes()),
        "the unmanaged credential must be left untouched"
    );
    assert!(
        !fixture.agy_was_spawned(),
        "agy must not be launched against an unmanaged credential"
    );

    // AC-2.3 / AC-3.1：显式 opt-in 之后接管成功，被替换掉的原凭据仍然可恢复。
    fixture.reset_agy_log();
    let taken_over = fixture.run(&["launch", "--takeover"]);
    assert_success(&taken_over, "sagy launch --takeover");
    assert!(
        fixture.agy_was_spawned(),
        "agy was never spawned after an explicit takeover: {}",
        combined(&taken_over)
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(FRESH_JWT.as_bytes()),
        "takeover must publish the selected account's credential"
    );
    let backups = fixture.takeover_backups();
    assert_eq!(
        backups.len(),
        1,
        "takeover must keep exactly one recoverable backup: {backups:?}"
    );
    assert_eq!(
        fs::read(&backups[0]).expect("read takeover backup"),
        FOREIGN_CREDENTIAL.as_bytes(),
        "the replaced credential must be recoverable byte-for-byte"
    );
}

/// AC-2.2 的另一条真实路径：state 里还没有 active profile（用户刚删掉 `~/.sagy`），
/// 而 active home 里躺着一份 sagy 不认识的凭据。第一次切换同样必须被拒绝，
/// 并且给出同一条可执行的命令。
#[test]
fn an_unknown_credential_blocks_the_very_first_switch_with_an_actionable_command() {
    let fixture = Fixture::new();
    // sagy 从未接管过这台机器，active home 里先有一份陌生凭据。
    fixture.seed_existing_antigravity_credential(FOREIGN_CREDENTIAL);

    let login = fixture.run(&[
        "login",
        "--token",
        FRESH_JWT,
        "--email",
        "owner@example.com",
    ]);
    assert!(
        !login.status.success(),
        "login silently overwrote an unmanaged active-home credential: {}",
        combined(&login)
    );
    let message = combined(&login);
    assert!(
        message.is_ascii(),
        "the first-switch refusal must be ASCII-only: {message}"
    );
    assert!(
        message.contains("do not belong to any sagy-managed account"),
        "the refusal must say the credential is not sagy-managed: {message}"
    );
    assert!(
        message.contains("sagy launch --takeover"),
        "the refusal must name a command the user can actually run: {message}"
    );
    assert!(
        message.contains(".sagy-backup-"),
        "the refusal must say where the existing credential ends up: {message}"
    );
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(FOREIGN_CREDENTIAL.as_bytes()),
        "the unmanaged credential must be left untouched"
    );

    // 逃生口在 `use` 上同样可用，且同样保留可恢复的备份。
    let switched = fixture.run(&["use", "owner@example.com", "--takeover"]);
    assert_success(&switched, "sagy use --takeover");
    assert_eq!(
        fixture.live_token().as_deref(),
        Some(FRESH_JWT.as_bytes()),
        "takeover must publish the selected account's credential"
    );
    let backups = fixture.takeover_backups();
    assert_eq!(
        backups.len(),
        1,
        "takeover must keep exactly one recoverable backup: {backups:?}"
    );
    assert_eq!(
        fs::read(&backups[0]).expect("read takeover backup"),
        FOREIGN_CREDENTIAL.as_bytes(),
        "the replaced credential must be recoverable byte-for-byte"
    );
}

/// AC-3.1：逃生口必须出现在 clap 的真实 help 输出里，并有说明文字。
#[test]
fn the_takeover_escape_hatch_is_documented_in_the_real_help_output() {
    let fixture = Fixture::new();
    for command in [
        &["launch", "--help"][..],
        &["auto", "--help"][..],
        &["use", "--help"][..],
        &["login", "--help"][..],
        &["add", "--help"][..],
    ] {
        let help = fixture.run(command);
        assert_success(&help, "sagy --help");
        let text = combined(&help);
        assert!(
            text.is_ascii(),
            "sagy {command:?} help is not ASCII-only: {text}"
        );
        assert!(
            text.contains("--takeover"),
            "sagy {command:?} help does not expose --takeover: {text}"
        );
        assert!(
            text.contains("sagy-backup"),
            "sagy {command:?} help does not say where the replaced files go: {text}"
        );
    }
}

/// README 是 AC-3.2 的交付物：两份文档都必须写清 `--takeover` 何时需要、动哪些文件。
#[test]
fn both_readmes_document_the_takeover_flag() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["README.md", "README.zh-CN.md"] {
        let text = fs::read_to_string(repository.join(name)).expect("read README");
        assert!(
            text.contains("--takeover"),
            "{name} does not document --takeover"
        );
        assert!(
            text.contains("sagy-backup"),
            "{name} does not say where the replaced credentials go"
        );
    }
}
