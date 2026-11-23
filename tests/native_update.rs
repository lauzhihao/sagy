#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    root: tempfile::TempDir,
    alias: PathBuf,
    profile_state: PathBuf,
    legacy_state: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let alias = root.path().join("sagy-profile");
        #[cfg(unix)]
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_sagy"), &alias).unwrap();

        let profile_state = root.path().join("broken-profile-root");
        fs::write(&profile_state, b"not a profile directory").unwrap();

        let legacy_home = root.path().join("legacy-home");
        fs::create_dir_all(&legacy_home).unwrap();
        let legacy_state = legacy_home.join("state.json");
        fs::write(&legacy_state, b"{ definitely not json").unwrap();

        Self {
            root,
            alias,
            profile_state,
            legacy_state,
        }
    }

    fn command(&self, executable: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(executable);
        command
            .args(args)
            .current_dir(self.root.path())
            .env("HOME", self.root.path().join("home"))
            .env("SAGY_HOME", self.legacy_state.parent().unwrap())
            .env("SAGY_PROFILE_ROOT", &self.profile_state)
            .env("SAGY_UPDATE_REPO", "bad/repo/extra")
            .env("AGY_BIN", self.root.path().join("missing-agy"))
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS");
        command
    }

    fn run(&self, executable: &Path, args: &[&str]) -> Output {
        self.command(executable, args).output().unwrap()
    }

    fn assert_profile_state_untouched(&self) {
        assert_eq!(
            fs::read(&self.profile_state).unwrap(),
            b"not a profile directory"
        );
        assert_eq!(
            fs::read(&self.legacy_state).unwrap(),
            b"{ definitely not json"
        );
        assert_eq!(
            fs::read_dir(self.legacy_state.parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }
}

#[test]
fn update_and_upgrade_help_are_available_from_both_native_entrypoints() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_sagy"));

    for executable in [binary, fixture.alias.as_path()] {
        for args in [
            &(["update", "--help"][..]),
            &["update", "-f", "--help"],
            &["upgrade", "--help"],
            &["upgrade", "--force", "--help"],
            &["help", "upgrade"],
        ] {
            let output = fixture.run(executable, args);
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let help = String::from_utf8_lossy(&output.stderr);
            assert!(help.contains("sagy update"), "{args:?}: {help}");
            assert!(help.contains("--force"), "{args:?}: {help}");
            fixture.assert_profile_state_untouched();
        }
    }
}

#[test]
fn update_routes_to_the_shared_updater_and_accepts_force_aliases() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_sagy"));

    for executable in [binary, fixture.alias.as_path()] {
        for args in [
            &(["update"][..]),
            &["update", "-f"],
            &["update", "--force"],
            &["upgrade"],
            &["upgrade", "-f"],
            &["upgrade", "--force"],
        ] {
            let output = fixture.run(executable, args);
            assert!(!output.status.success(), "{args:?} unexpectedly succeeded");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("invalid update repository name"),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            fixture.assert_profile_state_untouched();
        }
    }
}

#[test]
fn update_rejects_unknown_options_with_clap_exit_code() {
    let fixture = Fixture::new();
    for executable in [
        Path::new(env!("CARGO_BIN_EXE_sagy")),
        fixture.alias.as_path(),
    ] {
        let output = fixture.run(executable, &["update", "--unexpected"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected"));
        fixture.assert_profile_state_untouched();
    }
}
