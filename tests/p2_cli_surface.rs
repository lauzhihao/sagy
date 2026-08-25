//! T7 CLI surface acceptance tests.
//!
//! Covers dead CLI arguments (`--all`, `login --oauth`), removal of the
//! unreachable bilingual help renderer, predictable resume semantics, and the
//! router parsing matrix. Everything that observes user-visible behaviour runs
//! the real binary against a disposable state root and a fake `agy`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Split a Rust source file into `[A-Za-z0-9_]` identifier tokens so that
/// `antigravity-oauth-token` cannot be mistaken for a bare `oauth` read.
fn identifier_tokens(source: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in source.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn count_identifier(source: &str, name: &str) -> usize {
    identifier_tokens(source)
        .iter()
        .filter(|token| token.as_str() == name)
        .count()
}

/// Field names read as `<receiver>.<field>` where `receiver` passes `is_receiver`.
///
/// 判据必须是"带 receiver 的字段读取"，不能是"标识符出现次数 >= 2"：后者对
/// `email` / `path` / `force` 这类与别处同名的字段恒为真，新增一个死字段照样全绿。
/// 这里只在 receiver 是承载已解析参数的绑定时才算一次真实读取，所以
/// `record.email`、`account.path` 之类不会把死字段洗白。
fn qualified_field_reads(source: &str, is_receiver: &dyn Fn(&str) -> bool) -> BTreeSet<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut reads = BTreeSet::new();
    let mut previous_ident: Option<String> = None;
    let mut pending_dot = false;
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_ascii_alphanumeric() || ch == '_' {
            let start = index;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            let ident: String = chars[start..index].iter().collect();
            if pending_dot && previous_ident.as_deref().is_some_and(is_receiver) {
                reads.insert(ident.clone());
            }
            previous_ident = Some(ident);
            pending_dot = false;
            continue;
        }
        if ch == '.' {
            pending_dot = true;
        } else if !ch.is_whitespace() {
            // 任何别的符号都会打断 `receiver.field`；换行 / 缩进不算打断，
            // 因为 rustfmt 会把长链式读取折成 `args\n    .email`。
            previous_ident = None;
            pending_dot = false;
        }
        index += 1;
    }
    reads
}

/// `args` / `*_args` 是 CLI 层用来承载已解析参数的绑定名。
///
/// 刻意不把 `cli` 算进来：`cli.state_dir` 读的是 `Cli` 自己的字段，如果放行，
/// 一个恰好叫 `state_dir` 的死参数字段又会被洗白。
fn is_arg_binding(receiver: &str) -> bool {
    receiver == "args" || receiver.ends_with("_args")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_source(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn cli_module_sources() -> String {
    let cli_dir = repo_root().join("src").join("cli");
    let mut entries: Vec<PathBuf> = fs::read_dir(&cli_dir)
        .expect("read src/cli")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    entries.sort();
    entries
        .iter()
        .map(|path| fs::read_to_string(path).expect("read cli source"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `(field name, attribute text)` for every `pub <name>:` inside `src/cli/args.rs`.
///
/// 附带属性文本是为了区分"Rust 代码不读、但 clap 在解析期强制的字段"
/// （`conflicts_with` / `requires`）和真正的死字段。
fn declared_arg_fields(args_source: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let mut attributes = String::new();
    for line in args_source.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            attributes.push_str(trimmed);
            attributes.push('\n');
            continue;
        };
        let Some(name) = rest.split(':').next().map(str::trim) else {
            continue;
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        fields.push((name.to_string(), std::mem::take(&mut attributes)));
    }
    fields
}

/// Field names used inside the `PushOptions { .. }` / `PullOptions { .. }`
/// literals that `src/cli/mod.rs` builds from parsed CLI arguments.
fn repo_sync_option_fields(cli_mod_source: &str) -> Vec<String> {
    let mut fields = Vec::new();
    for marker in ["PushOptions {", "PullOptions {"] {
        let Some(start) = cli_mod_source.find(marker) else {
            continue;
        };
        let body_start = start + marker.len();
        let body_end = body_start
            + cli_mod_source[body_start..]
                .find('}')
                .expect("option struct literal must be closed");
        for line in cli_mod_source[body_start..body_end].lines() {
            let trimmed = line.trim();
            let Some((name, _)) = trimmed.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                fields.push(name.to_string());
            }
        }
    }
    fields
}

// ---------------------------------------------------------------------------
// AC-1.3 / AC-2.1: static surface checks (no binary required)
// ---------------------------------------------------------------------------

/// 已知残留局限：判据按字段名匹配，不按结构体作用域。若将来某个结构体新增一个
/// 与"另一个 arg 结构体里同名且仍被读取"的死字段（例如再给某个命令加一个不用的
/// `email`），本检查抓不到。要闭掉这个缺口需要类型级作用域分析，超出静态文本检查
/// 的能力范围；当前判据已经能抓住"与 src/cli 普通标识符同名"这一类真实死字段。
#[test]
fn every_declared_cli_argument_field_is_read_by_the_cli_layer() {
    let args_source = read_source("src/cli/args.rs");
    let cli_sources = cli_module_sources();
    let fields = declared_arg_fields(&args_source);
    assert!(
        fields.len() > 10,
        "arg field extraction looks broken: {fields:?}"
    );
    let reads = qualified_field_reads(&cli_sources, &is_arg_binding);

    // clap 在解析期强制的字段（conflicts_with / requires）即使 Rust 代码不读也不是
    // 死参数：它改变了 `sagy login --oauth --api-key K` 这类输入的可观察结果。
    let mut parser_enforced_only = Vec::new();
    for (field, attributes) in &fields {
        if reads.contains(field) {
            continue;
        }
        assert!(
            attributes.contains("conflicts_with") || attributes.contains("requires"),
            "CLI argument field `{field}` is declared but never read: no `args.{field}` \
             read inside src/cli and no clap constraint that would make it observable"
        );
        parser_enforced_only.push(field.clone());
    }
    // 固定豁免名单，免得以后又冒出一个"只靠豁免通过"的字段。
    assert_eq!(
        parser_enforced_only,
        vec!["oauth".to_string()],
        "unexpected set of parser-only CLI fields"
    );
}

#[test]
fn repo_sync_option_fields_built_from_cli_are_read_by_the_adapter() {
    let cli_mod_source = read_source("src/cli/mod.rs");
    let repo_sync_source = read_source("src/adapters/antigravity/repo_sync.rs");
    let fields = repo_sync_option_fields(&cli_mod_source);
    assert!(
        fields.len() >= 5,
        "option struct field extraction looks broken: {fields:?}"
    );
    let reads = qualified_field_reads(&repo_sync_source, &|receiver: &str| {
        receiver == "opts" || receiver == "options"
    });
    for field in fields {
        assert!(
            reads.contains(&field),
            "repo-sync option field `{field}` is populated from the CLI but never read \
             as `opts.{field}` inside repo_sync.rs"
        );
    }
    assert_eq!(
        count_identifier(&repo_sync_source, "include_all"),
        0,
        "include_all must be gone together with the --all flag"
    );
}

#[test]
fn unreachable_bilingual_help_renderer_is_gone() {
    let help_source = read_source("src/cli/help.rs");
    for dead in ["render_help", "render_topic_help"] {
        assert_eq!(
            count_identifier(&help_source, dead),
            0,
            "`{dead}` is unreachable from production code and must be deleted"
        );
    }
    assert!(
        help_source.contains("pub fn is_known_subcmd"),
        "is_known_subcmd is still used by the router and must be kept"
    );
    let router_source = read_source("src/cli/router.rs");
    assert!(router_source.contains("is_known_subcmd"));
}

#[cfg(unix)]
mod unix_tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Output};

    use chrono::Utc;
    use sagy::core::state::{AccountRecord, AccountType};
    use sagy::core::storage;
    use tempfile::TempDir;

    const JWT_WITH_FUTURE_EXPIRY: &str =
        "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.fake_signature";

    struct Fixture {
        root: TempDir,
        state_dir: PathBuf,
        argv_log: PathBuf,
        antigravity_home: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("create fixture root");
            let state_dir = root.path().join("state");
            let home = root.path().join("home");
            let gemini_home = root.path().join("gemini");
            let antigravity_home = root.path().join("antigravity");
            fs::create_dir_all(&home).expect("create home");
            fs::create_dir_all(&gemini_home).expect("create gemini home");
            fs::create_dir_all(&antigravity_home).expect("create antigravity home");

            let account_id = "surface-test-account";
            let account_dir = state_dir.join("accounts").join(account_id);
            fs::create_dir_all(&account_dir).expect("create account dir");
            let token_path = account_dir.join("antigravity-oauth-token");
            fs::write(&token_path, JWT_WITH_FUTURE_EXPIRY).expect("write token");

            let now = Utc::now().timestamp();
            let account = AccountRecord {
                id: account_id.to_string(),
                email: "surface@example.com".to_string(),
                account_type: AccountType::OAuth,
                auth_path: token_path.to_string_lossy().into_owned(),
                oauth_token: Some(JWT_WITH_FUTURE_EXPIRY.to_string()),
                added_at: now,
                updated_at: now,
                ..Default::default()
            };
            let mut usage_cache = serde_json::Map::new();
            usage_cache.insert(
                account_id.to_string(),
                serde_json::json!({
                    "status": "Ready",
                    "remaining_quota_percent": 100,
                    "last_synced_at": now,
                    "needs_relogin": false
                }),
            );
            let state = serde_json::json!({
                "version": 1,
                "accounts": [account],
                "usage_cache": usage_cache,
                "current_account_id": account_id
            });
            storage::write_secret_file(
                &state_dir.join("state.json"),
                &serde_json::to_vec_pretty(&state).expect("encode v1 state"),
            )
            .expect("write state");

            let argv_log = root.path().join("agy-argv.log");
            let agy_bin = root.path().join("fake-agy");
            fs::write(
                &agy_bin,
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$AGY_ARGV_LOG\"\nexit 0\n",
            )
            .expect("write fake agy");
            let mut permissions = fs::metadata(&agy_bin).expect("stat fake agy").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&agy_bin, permissions).expect("chmod fake agy");

            Self {
                root,
                state_dir,
                argv_log,
                antigravity_home,
            }
        }

        fn state_arg(&self) -> String {
            self.state_dir.to_string_lossy().into_owned()
        }

        fn run(&self, args: &[&str]) -> Output {
            let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
            command
                .args(args)
                .env("HOME", self.root.path().join("home"))
                .env("SAGY_HOME", self.root.path().join("sagy-home"))
                .env("GEMINI_HOME", self.root.path().join("gemini"))
                .env("ANTIGRAVITY_CONFIG_DIR", &self.antigravity_home)
                .env("AGY_BIN", self.root.path().join("fake-agy"))
                .env("AGY_ARGV_LOG", &self.argv_log)
                .env_remove("GEMINI_API_KEY")
                .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
                .env_remove("GOOGLE_CLOUD_PROJECT");
            command.output().expect("run sagy")
        }

        fn agy_args(&self) -> Vec<String> {
            fs::read_to_string(&self.argv_log)
                .expect("fake agy was not spawned")
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn state_bytes(&self) -> Vec<u8> {
            fs::read(self.state_dir.join("state.json")).expect("read state")
        }
    }

    fn assert_success(output: &Output) {
        assert!(
            output.status.success(),
            "status={:?}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn stdout_of(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr_of(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    fn dir_is_empty(path: &Path) -> bool {
        fs::read_dir(path)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true)
    }

    // -----------------------------------------------------------------------
    // AC-1.1: --all is gone from push/pull
    // -----------------------------------------------------------------------

    #[test]
    fn push_and_pull_reject_the_removed_all_flag() {
        for subcommand in ["push", "pull"] {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let output = fixture.run(&[
                "--state-dir",
                &state_arg,
                subcommand,
                "--all",
                "/tmp/does-not-exist.git",
            ]);
            assert!(
                !output.status.success(),
                "`sagy {subcommand} --all` was silently accepted"
            );
            let stderr = stderr_of(&output);
            assert!(
                stderr.contains("unexpected argument") && stderr.contains("--all"),
                "`sagy {subcommand} --all` must fail as an unknown argument, got: {stderr}"
            );
            assert!(!fixture.argv_log.exists());
        }
    }

    #[test]
    fn push_and_pull_help_no_longer_advertise_the_all_flag() {
        // push 与 pull 共用 RepoSyncArgs，但只验证 push 的话，给 pull 单独加回
        // 一个 --all 就抓不到；两条 help 都要断言。
        for subcommand in ["push", "pull"] {
            let fixture = Fixture::new();
            let output = fixture.run(&[subcommand, "--help"]);
            assert_success(&output);
            let stdout = stdout_of(&output);
            assert!(
                !stdout.contains("--all"),
                "{subcommand} help still advertises --all: {stdout}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // AC-1.2: login/add --oauth is real and conflicts with the key/token modes
    // -----------------------------------------------------------------------

    #[test]
    fn oauth_flag_conflicts_with_every_non_interactive_credential_mode() {
        let cases: [(&str, Vec<&str>); 6] = [
            ("login", vec!["--oauth", "--api-key", "key-value"]),
            ("login", vec!["--oauth", "--token", "token-value"]),
            ("login", vec!["--oauth", "--api"]),
            ("add", vec!["--oauth", "--api-key", "key-value"]),
            ("add", vec!["--oauth", "--token", "token-value"]),
            ("add", vec!["--oauth", "--api"]),
        ];
        for (subcommand, flags) in cases {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str(), subcommand];
            args.extend(flags.iter().copied());
            let output = fixture.run(&args);
            assert!(
                !output.status.success(),
                "`sagy {subcommand} {flags:?}` was accepted instead of reporting a conflict"
            );
            let stderr = stderr_of(&output);
            assert!(
                stderr.contains("--oauth") && stderr.contains("cannot be used with"),
                "`sagy {subcommand} {flags:?}` must report an argument conflict, got: {stderr}"
            );
        }
    }

    #[test]
    fn login_help_documents_the_oauth_flag() {
        let fixture = Fixture::new();
        let output = fixture.run(&["login", "--help"]);
        assert_success(&output);
        let stdout = stdout_of(&output);
        assert!(stdout.contains("--oauth"), "login help lost --oauth");
        assert!(
            stdout.contains("--api-key <API_KEY>"),
            "login help lost --api-key: {stdout}"
        );
    }

    // -----------------------------------------------------------------------
    // AC-2.2 / AC-2.3 / AC-2.4: real help output and the `--` boundary
    // -----------------------------------------------------------------------

    #[test]
    fn real_help_output_describes_commands_and_arguments() {
        let fixture = Fixture::new();

        let root = fixture.run(&["--help"]);
        assert_success(&root);
        let root_stdout = stdout_of(&root);
        assert!(root_stdout.contains("Usage: sagy"));
        for subcommand in ["launch", "auto", "push", "pull", "list", "refresh"] {
            assert!(
                root_stdout.contains(subcommand),
                "root help lost `{subcommand}`: {root_stdout}"
            );
        }

        let topic = fixture.run(&["help", "launch"]);
        assert_success(&topic);
        let topic_stdout = stdout_of(&topic);
        assert!(topic_stdout.contains("Usage: sagy launch"));
        assert!(topic_stdout.contains("--no-resume"));
        assert!(topic_stdout.contains("--dry-run"));

        let push = fixture.run(&["push", "--help"]);
        assert_success(&push);
        let push_stdout = stdout_of(&push);
        assert!(push_stdout.contains("Usage: sagy push"));
        assert!(push_stdout.contains("--path <REPO_PATH>"));
        assert!(push_stdout.contains("-i <IDENTITY_FILE>"));
        assert!(push_stdout.contains("--insecure-host-key"));
    }

    #[test]
    fn state_dir_global_option_has_help_text() {
        let fixture = Fixture::new();
        let output = fixture.run(&["--help"]);
        assert_success(&output);
        let stdout = stdout_of(&output);
        let line = stdout
            .lines()
            .find(|line| line.contains("--state-dir"))
            .unwrap_or_else(|| panic!("--state-dir missing from root help:\n{stdout}"));
        let description = line
            .split_once("--state-dir")
            .map(|(_, rest)| rest)
            .unwrap_or_default();
        // clap 把 value_name 之后的说明文字放在同一行，去掉 value_name 后必须还有内容。
        let after_value = description
            .split_once('>')
            .map(|(_, rest)| rest.trim())
            .unwrap_or_default();
        assert!(
            !after_value.is_empty(),
            "--state-dir has no help text in the real help output:\n{stdout}"
        );
    }

    #[test]
    fn double_dash_arguments_reach_agy_untouched() {
        let fixture = Fixture::new();
        let state_arg = fixture.state_arg();
        let output = fixture.run(&["--state-dir", &state_arg, "launch", "--", "--help"]);
        assert_success(&output);
        let agy_args = fixture.agy_args();
        assert_eq!(
            agy_args.last().map(String::as_str),
            Some("--help"),
            "`launch -- --help` was intercepted by sagy: {agy_args:?}"
        );
        assert!(
            !stdout_of(&output).contains("Usage: sagy launch"),
            "sagy printed its own help for `launch -- --help`"
        );
    }

    // -----------------------------------------------------------------------
    // AC-3: resume must depend only on --no-resume and on the agy arguments
    // -----------------------------------------------------------------------

    #[test]
    fn resume_decision_ignores_unrelated_sagy_flags() {
        let session_neutral_args: [Vec<&str>; 2] =
            [vec!["--model", "custom"], vec!["--model=custom"]];

        for agy_args in &session_neutral_args {
            // 不带任何额外 sagy flag：必须续接。
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str()];
            args.extend(agy_args.iter().copied());
            let output = fixture.run(&args);
            assert_success(&output);
            let logged = fixture.agy_args();
            assert!(
                logged.iter().any(|arg| arg == "--continue"),
                "bare `{agy_args:?}` did not resume: {logged:?}"
            );

            // 加一个与会话无关的 flag：结果必须完全一致。
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str(), "--no-import-known"];
            args.extend(agy_args.iter().copied());
            let output = fixture.run(&args);
            assert_success(&output);
            let logged_with_flag = fixture.agy_args();
            assert!(
                logged_with_flag.iter().any(|arg| arg == "--continue"),
                "`--no-import-known {agy_args:?}` did not resume: {logged_with_flag:?}"
            );
        }
    }

    #[test]
    fn no_resume_suppresses_continue_regardless_of_other_flags() {
        for extra in [
            vec!["--no-resume"],
            vec!["--no-resume", "--no-import-known"],
        ] {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str()];
            args.extend(extra.iter().copied());
            args.extend(["--model", "custom"]);
            let output = fixture.run(&args);
            assert_success(&output);
            let logged = fixture.agy_args();
            assert!(
                !logged.iter().any(|arg| arg == "--continue"),
                "`{extra:?}` still injected --continue: {logged:?}"
            );
        }
    }

    #[test]
    fn prompt_bearing_invocations_start_a_new_session() {
        for agy_args in [vec!["--prompt", "list"], vec!["a naked prompt"]] {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str()];
            args.extend(agy_args.iter().copied());
            let output = fixture.run(&args);
            assert_success(&output);
            let logged = fixture.agy_args();
            assert!(
                !logged.iter().any(|arg| arg == "--continue"),
                "prompt invocation `{agy_args:?}` resumed instead of starting fresh: {logged:?}"
            );
        }
    }

    /// Every subcommand's one-line `about` text, exactly as it must appear in
    /// `sagy --help`.
    ///
    /// clap 的 `#[command(about = ..)]` 只在真实 help 输出里可见，源码里断言
    /// 属性存在等于什么都没测；这里比对真实 stdout，删掉任何一条 about 都会红。
    const SUBCOMMAND_ABOUT_LINES: [(&str, &str); 13] = [
        (
            "launch",
            "Select the healthiest account, switch credentials, and launch Antigravity CLI",
        ),
        (
            "auto",
            "Select and switch to the healthiest account without launching the CLI",
        ),
        ("add", "Add a new account credential to the local pool"),
        ("login", "Configure or log in with new account credentials"),
        (
            "push",
            "Encrypt and push the local account pool to a Git repository",
        ),
        (
            "pull",
            "Pull and decrypt an account pool from a Git repository",
        ),
        (
            "use",
            "Switch manually to a specified account by email or ID",
        ),
        ("rm", "Remove an account credential from the local pool"),
        ("list", "List every known account with its health and quota"),
        (
            "refresh",
            "Force a health and quota probe for every account",
        ),
        (
            "update",
            "Check and self-update to the latest release from GitHub",
        ),
        (
            "import-auth",
            "Import an account from a JSON credential or token file",
        ),
        (
            "import-known",
            "Discover and import existing local Gemini credentials",
        ),
    ];

    #[test]
    fn root_help_describes_every_subcommand_with_its_about_text() {
        let fixture = Fixture::new();
        let output = fixture.run(&["--help"]);
        assert_success(&output);
        let stdout = stdout_of(&output);
        // clap 可能按宽度折行，比较前先把空白压成单个空格。
        let flattened = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
        for (subcommand, about) in SUBCOMMAND_ABOUT_LINES {
            let expected = format!("{subcommand} {about}");
            assert!(
                flattened.contains(&expected),
                "root help is missing the about text of `{subcommand}`\n\
                 expected: {expected}\nactual help:\n{stdout}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // AC-R9-1: the `--` boundary starts a new agy session on every reachable path
    // -----------------------------------------------------------------------

    #[test]
    fn double_dash_boundary_starts_a_new_session_on_every_reachable_path() {
        // 四条真实可达的边界输入：裸边界、显式 launch、root shortcut 之后、
        // launch shortcut 之后。四者的结果必须一致，否则规则又变成"看你多传了
        // 哪个无关 flag"。
        let cases: [Vec<&str>; 4] = [
            vec!["--", "--version"],
            vec!["launch", "--", "--version"],
            vec!["--no-import-known", "--", "--version"],
            vec!["launch", "--no-import-known", "--", "--version"],
        ];
        let own_version = format!("sagy {}", env!("CARGO_PKG_VERSION"));
        for case in cases {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str()];
            args.extend(case.iter().copied());
            let output = fixture.run(&args);
            assert_success(&output);
            assert!(
                !stdout_of(&output).contains(&own_version),
                "`{case:?}` was intercepted by sagy instead of reaching agy"
            );
            let logged = fixture.agy_args();
            assert_eq!(
                logged.last().map(String::as_str),
                Some("--version"),
                "`{case:?}` did not pass the boundary arguments through: {logged:?}"
            );
            assert!(
                !logged.iter().any(|arg| arg == "--"),
                "`{case:?}` leaked the boundary token to agy: {logged:?}"
            );
            assert!(
                !logged.iter().any(|arg| arg == "--continue"),
                "`{case:?}` resumed the previous session despite the `--` boundary: {logged:?}"
            );
        }
    }

    #[test]
    fn mid_argv_boundary_also_starts_a_new_session() {
        // 第四条路径：未知 option 开头的整体 passthrough，`--` 落在 argv 中间。
        // 这里 router 不会改写，边界原样交给 agy，会话决策由 launcher 的边界规则
        // 完成——三条 router 路径加这一条，"`--` 即新会话"在所有输入上都成立。
        let fixture = Fixture::new();
        let state_arg = fixture.state_arg();
        let output = fixture.run(&[
            "--state-dir",
            &state_arg,
            "--model",
            "custom",
            "--",
            "--version",
        ]);
        assert_success(&output);
        let logged = fixture.agy_args();
        assert_eq!(
            logged,
            vec!["--model", "custom", "--", "--version"],
            "mid-argv passthrough was rewritten: {logged:?}"
        );
        assert!(
            !logged.iter().any(|arg| arg == "--continue"),
            "mid-argv `--` boundary still resumed the previous session: {logged:?}"
        );
    }

    #[test]
    fn launch_without_a_boundary_still_resumes() {
        // 对照组：同样是 launch，同样带一个无关 flag，只是没有 `--`，必须续接。
        // 没有这一条，把 --no-resume 无条件注入也能让上面那个用例变绿。
        let fixture = Fixture::new();
        let state_arg = fixture.state_arg();
        let output = fixture.run(&["--state-dir", &state_arg, "launch", "--no-import-known"]);
        assert_success(&output);
        let logged = fixture.agy_args();
        assert!(
            logged.iter().any(|arg| arg == "--continue"),
            "launch without a boundary stopped resuming: {logged:?}"
        );
    }

    // -----------------------------------------------------------------------
    // AC-4.1: help/version never touch state, credentials or subprocesses
    // -----------------------------------------------------------------------

    #[test]
    fn help_and_version_never_load_state_switch_credentials_or_spawn() {
        let cases: [Vec<&str>; 8] = [
            vec!["--version"],
            vec!["-V"],
            vec!["--help"],
            vec!["-h"],
            vec!["--version", "--prompt", "list"],
            vec!["--help", "list"],
            vec!["list", "--help"],
            vec!["push", "--help"],
        ];
        for case in cases {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let before = fixture.state_bytes();
            let mut args = vec!["--state-dir", state_arg.as_str()];
            args.extend(case.iter().copied());
            let output = fixture.run(&args);
            assert_success(&output);
            assert_eq!(
                fixture.state_bytes(),
                before,
                "`{case:?}` mutated the state document"
            );
            assert!(
                dir_is_empty(&fixture.antigravity_home),
                "`{case:?}` switched credentials into the active home"
            );
            assert!(
                !fixture.argv_log.exists(),
                "`{case:?}` spawned the agy subprocess"
            );
        }
    }

    // -----------------------------------------------------------------------
    // AC-4.2: the six-way routing matrix
    // -----------------------------------------------------------------------

    #[test]
    fn router_matrix_is_pinned_for_all_six_input_shapes() {
        // (extra argv, expected trailing agy argv, expect agy to be spawned)
        let passthrough_cases: [(Vec<&str>, Vec<&str>); 5] = [
            (vec!["--prompt", "list"], vec!["--prompt", "list"]),
            (vec!["--model", "custom"], vec!["--model", "custom"]),
            (vec!["--model=custom"], vec!["--model=custom"]),
            (vec!["a naked prompt"], vec!["a naked prompt"]),
            (vec!["--", "--version"], vec!["--version"]),
        ];
        for (input, expected_suffix) in passthrough_cases {
            let fixture = Fixture::new();
            let state_arg = fixture.state_arg();
            let mut args = vec!["--state-dir", state_arg.as_str()];
            args.extend(input.iter().copied());
            let output = fixture.run(&args);
            assert_success(&output);
            let logged = fixture.agy_args();
            let tail: Vec<&str> = logged
                .iter()
                .rev()
                .take(expected_suffix.len())
                .rev()
                .map(String::as_str)
                .collect();
            assert_eq!(
                tail, expected_suffix,
                "routing changed for {input:?}: {logged:?}"
            );
        }

        // Known subcommand: sagy handles it and never spawns agy.
        let fixture = Fixture::new();
        let state_arg = fixture.state_arg();
        let output = fixture.run(&["--state-dir", &state_arg, "list"]);
        assert_success(&output);
        assert!(stdout_of(&output).contains("surface@example.com"));
        assert!(
            !fixture.argv_log.exists(),
            "known subcommand `list` spawned agy"
        );
    }
}
