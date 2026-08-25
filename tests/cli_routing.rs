//! CLI router acceptance tests.
//!
//! These tests invoke the real binary with a disposable state/home and a fake agy
//! executable so routing regressions cannot be hidden by unit-only parser tests.

#[cfg(unix)]
mod unix_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
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
        agy_bin: PathBuf,
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

            let account_id = "router-test-account";
            let account_dir = state_dir.join("accounts").join(account_id);
            fs::create_dir_all(&account_dir).expect("create account dir");
            let token_path = account_dir.join("antigravity-oauth-token");
            fs::write(&token_path, JWT_WITH_FUTURE_EXPIRY).expect("write token");

            let now = Utc::now().timestamp();
            let account = AccountRecord {
                id: account_id.to_string(),
                email: "router@example.com".to_string(),
                account_type: AccountType::OAuth,
                auth_path: token_path.to_string_lossy().into_owned(),
                oauth_token: Some(JWT_WITH_FUTURE_EXPIRY.to_string()),
                added_at: now,
                updated_at: now,
                ..Default::default()
            };
            // 使用真实 v1 wire 字段验证 CLI 的 sealed migration；不能用当前
            // UsageSnapshot 序列化后伪装成 v1，否则 strict decoder 会正确拒绝。
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
                agy_bin,
            }
        }

        fn command(&self, args: &[&str]) -> Command {
            let home = self.root.path().join("home");
            let gemini_home = self.root.path().join("gemini");
            let antigravity_home = self.root.path().join("antigravity");
            let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
            command
                .args(args)
                .env("HOME", home)
                .env("SAGY_HOME", self.root.path().join("sagy-home"))
                .env("GEMINI_HOME", gemini_home)
                .env("ANTIGRAVITY_CONFIG_DIR", antigravity_home)
                .env("AGY_BIN", &self.agy_bin)
                .env("AGY_ARGV_LOG", &self.argv_log)
                .env_remove("GEMINI_API_KEY")
                .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
                .env_remove("GOOGLE_CLOUD_PROJECT");
            command
        }

        fn run(&self, args: &[&str]) -> Output {
            self.command(args).output().expect("run sagy")
        }

        fn agy_args(&self) -> Vec<String> {
            fs::read_to_string(&self.argv_log)
                .expect("fake agy was not spawned")
                .lines()
                .map(str::to_string)
                .collect()
        }

        fn state_file(&self) -> PathBuf {
            self.state_dir.join("state.json")
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

    fn has_suffix(all: &[String], suffix: &[&str]) -> bool {
        all.len() >= suffix.len()
            && all[all.len() - suffix.len()..]
                .iter()
                .map(String::as_str)
                .eq(suffix.iter().copied())
    }

    #[test]
    fn root_help_and_version_are_state_and_spawn_free() {
        let root = tempfile::tempdir().expect("create root");
        let state_dir = root.path().join("state");
        let fake_log = root.path().join("fake-argv.log");
        let command = |args: &[&str]| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
            command
                .args(args)
                .env("HOME", root.path().join("home"))
                .env("SAGY_HOME", root.path().join("sagy-home"))
                .env("GEMINI_HOME", root.path().join("gemini"))
                .env("ANTIGRAVITY_CONFIG_DIR", root.path().join("antigravity"))
                .env("AGY_ARGV_LOG", &fake_log)
                .output()
                .expect("run sagy")
        };

        let state_arg = state_dir.to_string_lossy().into_owned();
        let version = command(&["--state-dir", &state_arg, "--version"]);
        assert_success(&version);
        assert_eq!(
            String::from_utf8_lossy(&version.stdout).trim(),
            format!("sagy {}", env!("CARGO_PKG_VERSION"))
        );
        assert!(!state_dir.exists());
        assert!(!fake_log.exists());

        let help = command(&["--state-dir", &state_arg, "--help"]);
        assert_success(&help);
        assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: sagy"));
        assert!(!state_dir.exists());
        assert!(!fake_log.exists());
    }

    #[test]
    fn unknown_agy_options_keep_values_and_prompt_tokens_together() {
        for (args, suffix) in [
            (vec!["--prompt", "list"], vec!["--prompt", "list"]),
            (vec!["--model", "custom"], vec!["--model", "custom"]),
            (vec!["--model=custom"], vec!["--model=custom"]),
            (vec!["a naked prompt"], vec!["a naked prompt"]),
        ] {
            let fixture = Fixture::new();
            let state_arg = fixture.state_dir.to_string_lossy().into_owned();
            let mut command_args = vec!["--state-dir", state_arg.as_str()];
            command_args.extend(args.iter().copied());
            let output = fixture.run(&command_args);
            assert_success(&output);
            let agy_args = fixture.agy_args();
            assert!(
                has_suffix(&agy_args, &suffix),
                "agy args={agy_args:?}, expected suffix={suffix:?}"
            );
        }
    }

    #[test]
    fn explicit_model_forms_do_not_inject_default_or_misread_value_as_prompt() {
        for model_args in [vec!["--model", "custom"], vec!["--model=custom"]] {
            let fixture = Fixture::new();
            let state_arg = fixture.state_dir.to_string_lossy().into_owned();
            let mut command_args = vec!["--state-dir", state_arg.as_str(), "--no-import-known"];
            command_args.extend(model_args.iter().copied());
            let output = fixture.run(&command_args);
            assert_success(&output);
            let agy_args = fixture.agy_args();
            assert_eq!(
                agy_args
                    .iter()
                    .filter(|arg| arg.as_str() == "--model" || arg.starts_with("--model="))
                    .count(),
                1,
                "default model leaked into explicit model args: {agy_args:?}"
            );
            assert!(
                agy_args.iter().any(|arg| arg == "--continue"),
                "model option value was mistaken for a prompt: {agy_args:?}"
            );
        }
    }

    #[test]
    fn signal_terminated_agy_is_reported_as_failure() {
        let fixture = Fixture::new();
        fs::write(&fixture.agy_bin, "#!/bin/sh\nkill -TERM $$\n").expect("replace fake agy");
        let mut permissions = fs::metadata(&fixture.agy_bin)
            .expect("stat fake agy")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&fixture.agy_bin, permissions).expect("chmod fake agy");

        let state_arg = fixture.state_dir.to_string_lossy().into_owned();
        let output = fixture.run(&[
            "--state-dir",
            &state_arg,
            "launch",
            "--no-import-known",
            "--no-resume",
        ]);
        assert!(
            !output.status.success(),
            "signal termination was reported as success"
        );
        assert_eq!(output.status.code(), Some(143));
    }

    #[test]
    fn launch_shortcuts_keep_their_sagy_semantics() {
        for shortcut in ["--no-launch", "--dry-run"] {
            let fixture = Fixture::new();
            let state_arg = fixture.state_dir.to_string_lossy().into_owned();
            let output = fixture.run(&["--state-dir", &state_arg, shortcut]);
            assert_success(&output);
            assert!(
                !fixture.argv_log.exists(),
                "{shortcut} unexpectedly spawned agy"
            );
        }

        let fixture = Fixture::new();
        let state_arg = fixture.state_dir.to_string_lossy().into_owned();
        let output = fixture.run(&[
            "--state-dir",
            &state_arg,
            "--no-resume",
            "--no-import-known",
            "--prompt",
            "list",
        ]);
        assert_success(&output);
        let agy_args = fixture.agy_args();
        assert!(has_suffix(&agy_args, &["--prompt", "list"]));
        assert!(
            !agy_args.iter().any(|arg| arg == "--continue"),
            "--no-resume still injected --continue: {agy_args:?}"
        );

        let fixture = Fixture::new();
        let state_arg = fixture.state_dir.to_string_lossy().into_owned();
        let output = fixture.run(&[
            "--state-dir",
            &state_arg,
            "--no-resume",
            "--no-import-known",
            "--",
            "--help",
        ]);
        assert_success(&output);
        let agy_args = fixture.agy_args();
        assert!(has_suffix(&agy_args, &["--help"]));
        assert!(
            !agy_args.iter().any(|arg| arg == "--"),
            "shortcut rewrite leaked a duplicate boundary: {agy_args:?}"
        );
    }

    #[test]
    fn known_command_stays_with_sagy_and_does_not_spawn_agy() {
        let fixture = Fixture::new();
        let state_arg = fixture.state_dir.to_string_lossy().into_owned();
        let output = fixture.run(&["--state-dir", &state_arg, "list"]);
        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("router@example.com"));
        assert!(!fixture.argv_log.exists());
    }

    #[test]
    fn launch_delimiter_passes_help_to_agy_unchanged() {
        let fixture = Fixture::new();
        let state_arg = fixture.state_dir.to_string_lossy().into_owned();
        let output = fixture.run(&[
            "--state-dir",
            &state_arg,
            "launch",
            "--no-import-known",
            "--no-resume",
            "--",
            "--help",
        ]);
        assert_success(&output);
        assert!(has_suffix(&fixture.agy_args(), &["--help"]));
    }

    #[test]
    fn add_help_uses_clap_command_arguments() {
        let fixture = Fixture::new();
        let state_before = fs::read(fixture.state_file()).expect("read initial state");
        let output = fixture.run(&["add", "--help"]);
        assert_success(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Usage: sagy add"));
        assert!(stdout.contains("--api-key <API_KEY>"));
        assert!(stdout.contains("--switch"));
        assert_eq!(
            fs::read(fixture.state_file()).expect("read state"),
            state_before
        );
        assert!(!fixture.argv_log.exists());
    }

    #[test]
    fn clap_builtin_help_subcommand_replaces_topic_help_intercept() {
        let fixture = Fixture::new();
        let output = fixture.run(&["help", "launch"]);
        assert_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: sagy launch"));
        assert!(!fixture.argv_log.exists());
    }
}
