use std::fs;
use std::path::Path;
use std::process::Command;

use sagy::adapters::antigravity::AntigravityAdapter;
use sagy::adapters::antigravity::paths::{
    MAX_BUNDLE_DIR_BYTES, MAX_BUNDLE_DIR_COMPONENTS, account_dir_checked, validate_account_id,
    validate_bundle_dir,
};
use sagy::core::state::{AccountRecord, State};
use sagy::core::storage;

#[test]
fn bundle_path_is_a_safe_relative_path() {
    for path in [
        "/tmp/outside",
        "../outside",
        "pool/../../outside",
        "pool//nested",
        r"pool\nested",
        "-option",
        "",
        ".",
        "pool/./nested",
    ] {
        assert!(
            validate_bundle_dir(path).is_err(),
            "accepted unsafe path {path:?}"
        );
    }

    for path in [
        ".sagy-account-pool",
        "nested/pool",
        "有凭据/pool",
        "pool/-option",
    ] {
        assert!(
            validate_bundle_dir(path).is_ok(),
            "rejected safe path {path:?}"
        );
    }

    assert!(validate_bundle_dir(&"x".repeat(MAX_BUNDLE_DIR_BYTES)).is_ok());
    assert!(validate_bundle_dir(&"x".repeat(MAX_BUNDLE_DIR_BYTES + 1)).is_err());

    let within_components = std::iter::repeat_n("x", MAX_BUNDLE_DIR_COMPONENTS)
        .collect::<Vec<_>>()
        .join("/");
    let over_components = std::iter::repeat_n("x", MAX_BUNDLE_DIR_COMPONENTS + 1)
        .collect::<Vec<_>>()
        .join("/");
    assert!(validate_bundle_dir(&within_components).is_ok());
    assert!(validate_bundle_dir(&over_components).is_err());
}

#[test]
fn account_ids_are_strict_safe_filenames() {
    for id in [
        "",
        ".",
        "..",
        "../escape",
        r"..\escape",
        "/absolute",
        "UpperCase",
        "has.dot",
        "has space",
        "-leading-dash",
        &"a".repeat(65),
    ] {
        assert!(
            validate_account_id(id).is_err(),
            "accepted unsafe account id {id:?}"
        );
    }

    for id in ["a", "0", "account_1", "account-1", &"a".repeat(64)] {
        assert!(
            validate_account_id(id).is_ok(),
            "rejected safe account id {id:?}"
        );
    }
}

#[test]
fn account_path_rejects_symlink_and_remove_propagates_validation_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(state_dir.join("accounts")).expect("accounts dir");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&outside).expect("outside dir");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, state_dir.join("accounts").join("safe-id"))
        .expect("symlink");

    #[cfg(unix)]
    assert!(account_dir_checked(&state_dir, "safe-id").is_err());

    let marker = state_dir.join("marker");
    fs::write(&marker, b"must survive").expect("marker");
    let adapter = AntigravityAdapter;
    let mut state = State::default();
    assert!(
        adapter
            .remove_account(&state_dir, &mut state, "..")
            .is_err()
    );
    assert!(marker.exists(), "invalid account id escaped state root");
}

#[cfg(unix)]
#[test]
fn account_credential_target_symlink_is_rejected_before_write() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let account_dir = state_dir.join("accounts").join("safe-id");
    fs::create_dir_all(&account_dir).expect("account dir");
    let outside = temp.path().join("outside-token");
    fs::write(&outside, b"original").expect("outside token");
    std::os::unix::fs::symlink(&outside, account_dir.join("antigravity-oauth-token"))
        .expect("credential symlink");

    let adapter = AntigravityAdapter;
    let mut state = State::default();
    state.accounts.push(AccountRecord {
        id: "safe-id".to_string(),
        email: "safe@example.test".to_string(),
        ..AccountRecord::default()
    });
    let result = adapter.import_or_update_token(
        &state_dir,
        &mut state,
        "safe@example.test",
        "new-token",
        None,
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&outside).expect("outside token"), b"original");
}

#[test]
fn push_round_trip_uses_a_disposable_local_bare_repository() {
    let git_bin =
        sagy::adapters::antigravity::paths::find_git_bin().expect("integration test requires git");
    let sagy_bin = env!("CARGO_BIN_EXE_sagy");

    let temp = tempfile::tempdir().expect("tempdir");
    let remote = temp.path().join("remote.git");
    run_git(
        &git_bin,
        None,
        &["init", "--bare", remote.to_str().unwrap()],
    );

    let seed = temp.path().join("seed");
    run_git(&git_bin, None, &["init", seed.to_str().unwrap()]);
    fs::write(seed.join("README.md"), b"seed").expect("seed file");
    run_git(&git_bin, Some(&seed), &["config", "user.name", "test"]);
    run_git(
        &git_bin,
        Some(&seed),
        &["config", "user.email", "test@example.test"],
    );
    run_git(&git_bin, Some(&seed), &["add", "--", "README.md"]);
    run_git(&git_bin, Some(&seed), &["commit", "-m", "seed"]);
    run_git(
        &git_bin,
        Some(&seed),
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    run_git(&git_bin, Some(&seed), &["push", "origin", "HEAD"]);

    let state_dir = temp.path().join("state");
    let mut state = State::default();
    state.accounts.push(AccountRecord {
        id: "safe-account".to_string(),
        email: "safe@example.test".to_string(),
        oauth_token: Some("token".to_string()),
        ..AccountRecord::default()
    });
    storage::save_state(&state_dir, &state).expect("state");

    let output = Command::new(sagy_bin)
        .env("SAGY_POOL_KEY", "test-pool-key")
        .env("HOME", temp.path().join("home"))
        .env("ANTIGRAVITY_CONFIG_DIR", temp.path().join("gemini"))
        .env("GEMINI_HOME", temp.path().join("gemini"))
        .env("GIT_AUTHOR_NAME", "sagy-test")
        .env("GIT_AUTHOR_EMAIL", "sagy-test@example.test")
        .env("GIT_COMMITTER_NAME", "sagy-test")
        .env("GIT_COMMITTER_EMAIL", "sagy-test@example.test")
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "push",
            remote.to_str().unwrap(),
        ])
        .output()
        .expect("sagy push");
    assert!(
        output.status.success(),
        "push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let verify = Command::new(&git_bin)
        .args([
            "--git-dir",
            remote.to_str().unwrap(),
            "ls-tree",
            "-r",
            "--name-only",
            "HEAD",
        ])
        .output()
        .expect("git ls-tree");
    assert!(verify.status.success());
    let tree = String::from_utf8_lossy(&verify.stdout);
    assert!(tree.contains(".sagy-account-pool/bundle.enc.json"));
}

#[test]
fn black_box_unsafe_path_does_not_modify_victim() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let victim = temp.path().join("victim");
    fs::write(&victim, b"unchanged").expect("victim");
    let nonexistent_repo = temp.path().join("not-a-repository");

    let output = Command::new(env!("CARGO_BIN_EXE_sagy"))
        .env("SAGY_POOL_KEY", "test-pool-key")
        .env("HOME", temp.path().join("home"))
        .env("ANTIGRAVITY_CONFIG_DIR", temp.path().join("gemini"))
        .env("GEMINI_HOME", temp.path().join("gemini"))
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "pull",
            "--path",
            victim.to_str().unwrap(),
            nonexistent_repo.to_str().unwrap(),
        ])
        .output()
        .expect("sagy pull");

    assert!(
        !output.status.success(),
        "unsafe --path unexpectedly succeeded"
    );
    assert_eq!(fs::read(&victim).expect("victim"), b"unchanged");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bundle path must be relative"),
        "unexpected error: {stderr}"
    );
}

fn run_git(git_bin: &Path, cwd: Option<&Path>, args: &[&str]) {
    let mut command = Command::new(git_bin);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.args(args).output().expect("git command");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
}
