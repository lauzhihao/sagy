use std::fs;

#[test]
fn pull_request_and_main_quality_workflow_is_isolated_and_complete() {
    let workflow = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ))
    .expect("read CI workflow");

    for required in [
        "pull_request:",
        "branches:",
        "- main",
        "HOME:",
        "SAGY_HOME:",
        "GEMINI_HOME:",
        "ANTIGRAVITY_CONFIG_DIR:",
        "cargo fmt --all -- --check",
        "cargo check --all-targets --locked",
        "cargo clippy --all-targets --locked -- -D warnings",
        "cargo test --all-targets --locked",
        "cargo build --release --locked",
        "runs-on: windows-latest",
        "cargo test --test windows_runtime --locked",
    ] {
        assert!(
            workflow.contains(required),
            "CI workflow misses {required:?}"
        );
    }
    assert!(workflow.contains("permissions:\n  contents: read"));
}

#[test]
fn release_workflow_has_version_guard_minimal_permissions_and_single_quality_job() {
    let workflow = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .expect("read release workflow");

    for required in [
        "version-guard:",
        "cargo metadata --no-deps --format-version 1 --locked",
        "expected_tag=\"v${package_version}\"",
        "needs: [version-guard, quality, windows-runtime]",
        "permissions:\n      contents: write",
        "HOME:",
        "SAGY_HOME:",
        "GEMINI_HOME:",
        "ANTIGRAVITY_CONFIG_DIR:",
        "cargo fmt --all -- --check",
        "cargo check --all-targets --locked",
        "cargo test --all-targets --locked",
        "cargo test --test windows_runtime --locked",
    ] {
        assert!(
            workflow.contains(required),
            "release workflow misses {required:?}"
        );
    }
    assert_eq!(
        workflow
            .matches("cargo clippy --all-targets --locked -- -D warnings")
            .count(),
        1,
        "host clippy should run once outside the release target matrix"
    );
}
