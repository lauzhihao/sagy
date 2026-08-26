use std::fs;

const CI_WORKFLOW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.github/workflows/ci.yml"
));
const RELEASE_WORKFLOW: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.github/workflows/release.yml"
));
const SANDBOX_ACTION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.github/actions/setup-sagy-sandbox/action.yml"
));

fn job_block<'a>(workflow: &'a str, job: &str) -> &'a str {
    let marker = format!("  {job}:");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("workflow misses job {job:?}"));
    let remainder = &workflow[start..];
    let after_marker = &remainder[marker.len()..];
    let end = after_marker
        .match_indices("\n  ")
        .find_map(|(offset, _)| {
            (after_marker.as_bytes().get(offset + 3) != Some(&b' '))
                .then_some(marker.len() + offset)
        })
        .unwrap_or(remainder.len());
    &remainder[..end]
}

fn assert_sandbox_is_wired_before_cargo(workflow: &str, job: &str) {
    let block = job_block(workflow, job);
    let checkout = block
        .find("actions/checkout@")
        .unwrap_or_else(|| panic!("{job} does not check out the repository"));
    let sandbox = block
        .find("- uses: ./.github/actions/setup-sagy-sandbox")
        .unwrap_or_else(|| panic!("{job} does not configure the sagy sandbox"));
    assert!(
        checkout < sandbox,
        "{job} configures sandbox before checkout"
    );
    let toolchain = block
        .find("dtolnay/rust-toolchain@")
        .unwrap_or_else(|| panic!("{job} does not configure the Rust toolchain"));
    assert!(
        sandbox < toolchain,
        "{job} configures the Rust toolchain before the sandbox"
    );
    let cargo = block
        .find("cargo ")
        .unwrap_or_else(|| panic!("{job} does not contain a cargo command"));
    assert!(
        sandbox < cargo,
        "{job} runs cargo before configuring sandbox"
    );
}

/// 校验 workflow 里的每一个 `uses:` 都固定到 40 位 commit SHA，
/// 并在同一行保留人类可读的版本 tag 注释。
fn assert_actions_are_sha_pinned(workflow: &str, label: &str) {
    let mut pinned = 0;
    for line in workflow.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix("- uses: ")
            .or_else(|| trimmed.strip_prefix("uses: "))
        else {
            continue;
        };
        let reference = rest.split_whitespace().next().unwrap_or_default();
        if reference.starts_with("./") {
            continue;
        }
        let Some((action, pin)) = reference.rsplit_once('@') else {
            panic!("{label} action {reference:?} carries no version reference");
        };
        assert!(
            pin.len() == 40 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{label} action {action:?} is pinned to {pin:?} instead of a 40 character commit SHA"
        );
        assert!(
            rest.contains(" # "),
            "{label} action {action:?} lost its human readable version tag comment"
        );
        pinned += 1;
    }
    assert!(pinned > 0, "{label} declares no third-party actions");
}

#[test]
fn pull_request_and_main_quality_workflow_is_isolated_and_complete() {
    let workflow = CI_WORKFLOW;

    for required in [
        "pull_request:",
        "branches:",
        "- main",
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
    assert_sandbox_is_wired_before_cargo(workflow, "quality");
    assert_sandbox_is_wired_before_cargo(workflow, "windows-runtime");
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
    // AC-5.2：只有发布 job 允许写 contents，其余 job 继承顶层的只读权限。
    let write_scopes = workflow
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.trim() == "contents: write")
        .count();
    assert_eq!(write_scopes, 1, "more than one job requests write access");
    let declared_scopes = workflow
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.contains(": write") || line.contains(": admin"))
        .count();
    assert_eq!(
        declared_scopes, 1,
        "the publish job requests scopes beyond contents: write"
    );
    for job in ["version-guard", "quality", "windows-runtime", "build"] {
        assert_sandbox_is_wired_before_cargo(&workflow, job);
    }
    assert!(
        !job_block(&workflow, "publish").contains("setup-sagy-sandbox"),
        "publish must not configure a cargo sandbox"
    );
}

/// GitHub evaluates runner context only after a job has been assigned a runner;
/// it is therefore invalid in a job-level env expression. The composite action
/// is the only place where these paths may be derived from RUNNER_TEMP.
#[test]
fn workflows_do_not_use_runner_temp_in_job_environment() {
    for (label, workflow) in [("ci.yml", CI_WORKFLOW), ("release.yml", RELEASE_WORKFLOW)] {
        assert!(
            !workflow.contains(concat!("$", "{{ runner.temp }}")),
            "{label} evaluates runner.temp before a runner is assigned"
        );
    }
}

#[test]
fn sandbox_action_sets_all_isolated_homes_on_both_platforms() {
    for variable in [
        "HOME=",
        "SAGY_HOME=",
        "GEMINI_HOME=",
        "ANTIGRAVITY_CONFIG_DIR=",
        "CARGO_HOME=",
    ] {
        assert!(
            SANDBOX_ACTION.contains(variable),
            "sandbox action does not export {variable:?}"
        );
    }
    assert!(SANDBOX_ACTION.contains("RUNNER_TEMP"));
    assert!(SANDBOX_ACTION.contains("GITHUB_ENV"));
    assert!(SANDBOX_ACTION.contains("if: runner.os != 'Windows'"));
    assert!(SANDBOX_ACTION.contains("if: runner.os == 'Windows'"));
    assert!(
        SANDBOX_ACTION.contains("shell: bash"),
        "sandbox action misses the Unix branch"
    );
    assert!(
        SANDBOX_ACTION.contains("shell: pwsh"),
        "sandbox action misses the Windows branch"
    );
    assert!(
        SANDBOX_ACTION.contains("umask 077") && SANDBOX_ACTION.contains("mkdir -p --"),
        "sandbox action does not create private Unix directories"
    );
    assert!(
        SANDBOX_ACTION.contains("New-Item -ItemType Directory -Force"),
        "sandbox action does not create Windows directories"
    );
}

/// AC-2.1 / AC-R7-3.1：Windows 侧的 fail-closed harness 必须被 CI 真正执行，
/// 而且它的失败必须能把 job 变红。
///
/// 本机没有 pwsh，harness 的行为无法在提交前执行验证，所以 CI 是**唯一**证据来源；
/// 这条测试守住的就是"这条证据链没有断":
/// 脚本被调用 -> 有真实二进制可用 -> 子进程退出码被显式转成 step 失败。
#[test]
fn windows_jobs_execute_the_powershell_checksum_harness() {
    let release = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .expect("read release workflow");

    for (label, workflow) in [("ci.yml", CI_WORKFLOW), ("release.yml", release.as_str())] {
        assert!(
            workflow
                .contains("pwsh -NoProfile -ExecutionPolicy Bypass -File tests/p0_checksum.ps1"),
            "{label} never executes tests/p0_checksum.ps1"
        );
        assert!(
            workflow.contains("shell: pwsh"),
            "{label} does not run the checksum harness through pwsh"
        );
        // harness 的断言是 throw，只体现在子进程退出码上；step 必须显式检查它，
        // 否则 harness 失败时 job 仍然是绿的。
        assert!(
            workflow.contains("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"),
            "{label} does not propagate the checksum harness exit code"
        );
        // harness 只有拿到真实 sagy.exe 才算完整覆盖；路径必须是绝对路径，
        // 且必须有一个显式的构建步骤保证它存在。
        assert!(
            workflow.contains("SAGY_TEST_BINARY: ${{ github.workspace }}\\target\\debug\\sagy.exe"),
            "{label} does not point SAGY_TEST_BINARY at an absolute built binary"
        );
        assert!(
            workflow.contains("name: Build the sagy binary for the installer harness"),
            "{label} does not build the binary the checksum harness needs"
        );
    }
}

/// AC-5.1：第三方 Action 一律按 commit SHA 固定。
#[test]
fn third_party_actions_are_pinned_to_commit_shas() {
    let release = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/release.yml"
    ))
    .expect("read release workflow");

    assert_actions_are_sha_pinned(CI_WORKFLOW, "ci.yml");
    assert_actions_are_sha_pinned(&release, "release.yml");
}
