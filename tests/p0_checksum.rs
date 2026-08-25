use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// 伪造的 curl：按 `-w` 请求的格式回写 metrics，因此既能模拟 HTTP 状态，
/// 也能模拟 `%{size_download}`，让安装脚本的体积上限被真正走到。
#[cfg(unix)]
const FAKE_CURL: &str = r#"#!/bin/sh
set -eu
url=""
out=""
previous=""
write_format=""
for arg in "$@"; do
    if [ "$previous" = "-o" ]; then
        out="$arg"
    elif [ "$previous" = "-w" ]; then
        write_format="$arg"
    elif printf '%s' "$arg" | grep -q '^https://'; then
        url="$arg"
    fi
    previous="$arg"
done

emit() {
    if [ -n "$out" ]; then cat > "$out"; else cat; fi
}

code=200
if printf '%s' "$url" | grep -q 'api.github.com'; then
    case "${FAKE_SUMS_MODE}" in
        metadata-timeout) exit 28 ;;
        metadata-oversize)
            awk 'BEGIN {
                printf "{\"tag_name\": \"v1.0.0\", \"body\": \""
                for (i = 0; i < 500000; i++) printf "pad"
                printf "\"}"
            }' | emit
            ;;
        *) printf '{"tag_name": "v1.0.0"}' | emit ;;
    esac
elif printf '%s' "$url" | grep -q 'SHA256SUMS.txt'; then
    case "${FAKE_SUMS_MODE}" in
        checksum-timeout) exit 28 ;;
        http-error) exit 22 ;;
        empty) : | emit ;;
        missing) printf '%s  other.tar.gz\n' "$FAKE_HASH" | emit ;;
        duplicate) printf '%s  %s\n%s  %s\n' "$FAKE_HASH" "$FAKE_ASSET" "$FAKE_HASH" "$FAKE_ASSET" | emit ;;
        malformed) printf 'not-a-hash  %s\n' "$FAKE_ASSET" | emit ;;
        mismatch) printf '%064d  %s\n' 0 "$FAKE_ASSET" | emit ;;
        unsafe-target) printf '%s  ../%s\n' "$FAKE_HASH" "$FAKE_ASSET" | emit ;;
        sums-oversize)
            awk -v h="$FAKE_HASH" -v a="$FAKE_ASSET" 'BEGIN {
                printf "%s  %s\n", h, a
                for (i = 0; i < 2000; i++) printf "%s  padding-%d.txt\n", h, i
            }' | emit
            ;;
        redirect) printf '%s  %s\n' "$FAKE_HASH" "$FAKE_ASSET" | emit; code=302 ;;
        *) printf '%s  %s\n' "$FAKE_HASH" "$FAKE_ASSET" | emit ;;
    esac
else
    if [ -n "${FAKE_TMP_LOG:-}" ] && [ -n "$out" ]; then
        dirname "$out" >> "${FAKE_TMP_LOG}"
    fi
    case "${FAKE_SUMS_MODE}" in
        archive-timeout) exit 28 ;;
        empty-archive) : | emit ;;
        interrupt)
            # 告诉测试"安装脚本此刻正卡在归档下载上"，然后等测试发完信号再返回。
            : > "${FAKE_INTERRUPT_READY}"
            i=0
            while [ ! -f "${FAKE_INTERRUPT_GO}" ] && [ "$i" -lt 600 ]; do
                sleep 0.05
                i=$((i + 1))
            done
            cat "$FAKE_ARCHIVE" | emit
            ;;
        *) cat "$FAKE_ARCHIVE" | emit ;;
    esac
fi

if [ -n "$write_format" ]; then
    size=0
    if [ -n "$out" ] && [ -f "$out" ]; then
        size=$(wc -c < "$out" | tr -d ' ')
    fi
    case "$write_format" in
        *size_download*) printf '%s %s' "$code" "$size" ;;
        *) printf '%s' "$code" ;;
    esac
fi
"#;

/// 安装成功后被 `import-known` 调用的伪 sagy：可执行，退出码由环境变量控制，
/// 用来复现"安装后动作失败"这条路径。
#[cfg(unix)]
const FAKE_SAGY_BINARY: &str = r#"#!/bin/sh
if [ "${1:-}" = "import-known" ]; then
    if [ "${FAKE_IMPORT_EXIT:-0}" -ne 0 ]; then
        echo "fake import-known failure: state root rejected" >&2
        exit "${FAKE_IMPORT_EXIT}"
    fi
fi
exit 0
"#;

#[cfg(unix)]
fn write_fake_curl(bin_dir: &Path) {
    let path = bin_dir.join("curl");
    fs::write(&path, FAKE_CURL).expect("write fake curl");
    make_executable(&path);
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).expect("stat harness file").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod harness file");
}

#[cfg(unix)]
fn sha256_of(path: &Path) -> String {
    for tool in ["shasum", "sha256sum"] {
        let mut command = Command::new(tool);
        if tool == "shasum" {
            command.args(["-a", "256"]);
        }
        let Ok(output) = command.arg(path).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        return String::from_utf8(output.stdout)
            .expect("decode hash")
            .split_whitespace()
            .next()
            .expect("hash output")
            .to_string();
    }
    panic!("neither shasum nor sha256sum is available");
}

/// 用给定的条目构造一个 tar.gz fixture，返回归档路径与它的 SHA-256。
#[cfg(unix)]
fn build_archive(root: &Path, label: &str, entries: &[(&str, &str, bool)]) -> (PathBuf, String) {
    let source_dir = root.join(format!("{label}-source"));
    fs::create_dir_all(&source_dir).expect("create archive source");
    for (relative, content, executable) in entries {
        let path = source_dir.join(relative);
        fs::create_dir_all(path.parent().expect("archive entry parent"))
            .expect("create archive entry parent");
        fs::write(&path, content).expect("write archive entry");
        if *executable {
            make_executable(&path);
        }
    }
    let archive = root.join(format!("{label}.tar.gz"));
    let mut command = Command::new("tar");
    command.arg("-czf").arg(&archive).arg("-C").arg(&source_dir);
    for (relative, _, _) in entries {
        command.arg(relative);
    }
    let status = command.status().expect("run tar");
    assert!(status.success(), "tar fixture {label} failed");
    let hash = sha256_of(&archive);
    (archive, hash)
}

#[cfg(unix)]
fn release_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-musl"),
        _ => None,
    }
}

#[cfg(unix)]
struct InstallerRun<'a> {
    home: PathBuf,
    fake_bin: &'a Path,
    mode: &'a str,
    archive: &'a Path,
    hash: &'a str,
    asset: &'a str,
    version: &'a str,
    import_exit: &'a str,
    extra_path: Option<PathBuf>,
    tmp_log: Option<PathBuf>,
    interrupt_ready: Option<PathBuf>,
    interrupt_go: Option<PathBuf>,
}

#[cfg(unix)]
impl InstallerRun<'_> {
    fn sagy_home(&self) -> PathBuf {
        self.home.join(".sagy")
    }

    fn installed_binary(&self) -> PathBuf {
        self.sagy_home().join("bin/sagy")
    }

    fn spawn(&self) -> std::process::Child {
        let mut path = format!("{}:", self.fake_bin.display());
        if let Some(extra) = &self.extra_path {
            path.push_str(&format!("{}:", extra.display()));
        }
        path.push_str(&std::env::var("PATH").expect("inherit PATH"));
        let mut command = Command::new("bash");
        command
            .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/install.sh")
            .env("HOME", &self.home)
            .env("SAGY_HOME", self.sagy_home())
            .env("SAGY_VERSION", self.version)
            .env("SAGY_REPO", "test/repo")
            .env("FAKE_SUMS_MODE", self.mode)
            .env("FAKE_HASH", self.hash)
            .env("FAKE_ASSET", self.asset)
            .env("FAKE_ARCHIVE", self.archive)
            .env("FAKE_IMPORT_EXIT", self.import_exit)
            .env("PATH", path)
            .env_remove("AGY_BIN")
            .env_remove("FAKE_TMP_LOG")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(tmp_log) = &self.tmp_log {
            command.env("FAKE_TMP_LOG", tmp_log);
        }
        if let Some(ready) = &self.interrupt_ready {
            command.env("FAKE_INTERRUPT_READY", ready);
        }
        if let Some(go) = &self.interrupt_go {
            command.env("FAKE_INTERRUPT_GO", go);
        }
        command.spawn().expect("spawn unix installer")
    }

    fn run(&self) -> Output {
        self.spawn().wait_with_output().expect("run unix installer")
    }
}

#[cfg(unix)]
fn installer_run<'a>(
    home: PathBuf,
    fake_bin: &'a Path,
    mode: &'a str,
    archive: &'a Path,
    hash: &'a str,
    asset: &'a str,
) -> InstallerRun<'a> {
    InstallerRun {
        home,
        fake_bin,
        mode,
        archive,
        hash,
        asset,
        version: "v1.0.0",
        import_exit: "0",
        extra_path: None,
        tmp_log: None,
        interrupt_ready: None,
        interrupt_go: None,
    }
}

/// 一次性临时目录的守卫：安装结束后 `${SAGY_HOME}/tmp` 不允许留下任何条目。
#[cfg(unix)]
fn assert_temp_root_is_clean(sagy_home: &Path, context: &str) {
    let tmp_root = sagy_home.join("tmp");
    if !tmp_root.exists() {
        return;
    }
    let leftovers = fs::read_dir(&tmp_root)
        .expect("read temp root")
        .map(|entry| entry.expect("temp root entry").file_name())
        .collect::<Vec<_>>();
    assert!(
        leftovers.is_empty(),
        "installer left temp entries {leftovers:?} for {context}"
    );
}

#[test]
#[cfg(unix)]
fn unix_installer_requires_checksum_before_install() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) =
        build_archive(fixture.path(), "release", &[("sagy", "test binary", true)]);
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    for mode in [
        "archive-timeout",
        "empty-archive",
        "checksum-timeout",
        "http-error",
        "redirect",
        "empty",
        "missing",
        "duplicate",
        "malformed",
        "mismatch",
        "unsafe-target",
    ] {
        let run = installer_run(
            fixture.path().join(mode),
            &fake_bin,
            mode,
            &archive,
            &hash,
            &asset,
        );
        let output = run.run();
        assert!(
            !output.status.success(),
            "installer unexpectedly succeeded for {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !run.installed_binary().exists(),
            "installer copied binary for failed checksum mode {mode}"
        );
        assert_temp_root_is_clean(&run.sagy_home(), mode);
    }

    let run = installer_run(
        fixture.path().join("valid"),
        &fake_bin,
        "valid",
        &archive,
        &hash,
        &asset,
    );
    let output = run.run();
    assert!(
        output.status.success(),
        "valid checksum was rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(run.installed_binary().exists());
    assert_temp_root_is_clean(&run.sagy_home(), "valid");
}

#[test]
#[cfg(unix)]
fn unix_installer_rejects_missing_hash_tool_before_download() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");

    for command in ["bash", "curl", "tar", "mktemp", "awk", "tr"] {
        let source = Command::new("sh")
            .args(["-c", "command -v \"$1\"", "sh", command])
            .output()
            .expect("locate dependency");
        assert!(source.status.success(), "missing test dependency {command}");
        std::os::unix::fs::symlink(
            String::from_utf8(source.stdout)
                .expect("dependency path")
                .trim(),
            fake_bin.join(command),
        )
        .expect("link dependency");
    }

    let home = fixture.path().join("missing-hash-tool");
    let output = Command::new(fake_bin.join("bash"))
        .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/install.sh")
        .env("HOME", &home)
        .env("SAGY_HOME", home.join(".sagy"))
        .env("SAGY_VERSION", "v1.0.0")
        .env("SAGY_REPO", "test/repo")
        .env("PATH", &fake_bin)
        .output()
        .expect("run installer without hash tool");
    assert!(
        !output.status.success(),
        "installer accepted missing hash tool"
    );
    assert!(
        !home.join(".sagy").exists(),
        "installer created state directory"
    );
}

/// AC-1.2：归档缺少顶层二进制时必须 fail-closed，且不得覆盖已安装的二进制。
#[test]
#[cfg(unix)]
fn unix_installer_fails_closed_when_archive_lacks_top_level_binary() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = build_archive(
        fixture.path(),
        "missing-binary",
        &[("nested/sagy", "nested binary", true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    let run = installer_run(
        fixture.path().join("missing-binary-home"),
        &fake_bin,
        "valid",
        &archive,
        &hash,
        &asset,
    );

    // 先放一份"上一版本"的二进制，确认失败路径不会把它覆盖或删除。
    fs::create_dir_all(run.sagy_home().join("bin")).expect("create install bin");
    fs::write(run.installed_binary(), "previous version").expect("seed previous binary");

    let output = run.run();
    assert!(
        !output.status.success(),
        "installer accepted an archive without a top-level binary"
    );
    assert_eq!(
        fs::read_to_string(run.installed_binary()).expect("read previous binary"),
        "previous version",
        "installer replaced the previously installed binary on a fail-closed path"
    );
    assert_temp_root_is_clean(&run.sagy_home(), "missing-binary");
}

/// AC-1.1 / AC-1.3：解压残留不得让下一次安装 fail-open。
#[test]
#[cfg(unix)]
fn unix_installer_ignores_stale_extraction_leftovers() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (good_archive, good_hash) =
        build_archive(fixture.path(), "good", &[("sagy", "test binary", true)]);
    let (bad_archive, bad_hash) = build_archive(
        fixture.path(),
        "stale-missing",
        &[("nested/sagy", "nested binary", true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    let home = fixture.path().join("stale-home");
    let sagy_home = home.join(".sagy");

    // 手工在 tmp root 下埋一份旧的解压产物，模拟上一次安装留下的残骸。
    fs::create_dir_all(sagy_home.join("tmp")).expect("create temp root");
    fs::write(sagy_home.join("tmp/sagy"), "stale binary").expect("seed stale extraction");

    let run = installer_run(
        home.clone(),
        &fake_bin,
        "valid",
        &bad_archive,
        &bad_hash,
        &asset,
    );
    let output = run.run();
    assert!(
        !output.status.success(),
        "stale extraction leftovers made the installer fail open"
    );
    assert!(
        !run.installed_binary().exists(),
        "installer installed a stale binary from a previous run"
    );

    // 干净归档仍然必须能装上，且不会留下残骸。
    let ok_run = installer_run(
        fixture.path().join("stale-home-ok"),
        &fake_bin,
        "valid",
        &good_archive,
        &good_hash,
        &asset,
    );
    let ok_output = ok_run.run();
    assert!(
        ok_output.status.success(),
        "clean archive was rejected: {}",
        String::from_utf8_lossy(&ok_output.stderr)
    );
    assert_temp_root_is_clean(&ok_run.sagy_home(), "clean install");
}

/// AC-1.3：并发执行的两个 installer 不得共用临时目录、不得互相覆盖。
#[test]
#[cfg(unix)]
fn unix_installers_do_not_share_temp_directories() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = build_archive(
        fixture.path(),
        "concurrent",
        &[("sagy", FAKE_SAGY_BINARY, true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    let home = fixture.path().join("concurrent-home");
    let tmp_log = fixture.path().join("temp-dirs.log");
    fs::write(&tmp_log, "").expect("seed temp dir log");

    // 两个 installer 指向同一个 SAGY_HOME，因此共用同一个 tmp root。
    let mut first = installer_run(home.clone(), &fake_bin, "valid", &archive, &hash, &asset);
    first.tmp_log = Some(tmp_log.clone());
    let mut second = installer_run(home.clone(), &fake_bin, "valid", &archive, &hash, &asset);
    second.tmp_log = Some(tmp_log.clone());

    let first_child = first.spawn();
    let second_child = second.spawn();
    let first_output = first_child.wait_with_output().expect("first installer");
    let second_output = second_child.wait_with_output().expect("second installer");

    for (label, output) in [("first", &first_output), ("second", &second_output)] {
        assert!(
            output.status.success(),
            "{label} concurrent installer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let recorded = fs::read_to_string(&tmp_log).expect("read temp dir log");
    let dirs = recorded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        dirs.len(),
        2,
        "expected one temp dir per installer: {dirs:?}"
    );
    assert_ne!(
        dirs[0], dirs[1],
        "concurrent installers shared the same temp directory: {dirs:?}"
    );
    assert_temp_root_is_clean(&first.sagy_home(), "concurrent installs");
}

/// AC-4.2：release metadata 与校验清单都必须有体积上限。
#[test]
#[cfg(unix)]
fn unix_installer_enforces_download_size_limits() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = build_archive(
        fixture.path(),
        "size-limits",
        &[("sagy", "test binary", true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");

    // 校验清单超限：清单里仍然含有正确条目，只有体积上限能拒绝它。
    let run = installer_run(
        fixture.path().join("sums-oversize"),
        &fake_bin,
        "sums-oversize",
        &archive,
        &hash,
        &asset,
    );
    let output = run.run();
    assert!(
        !output.status.success(),
        "installer accepted an oversized checksum manifest"
    );
    assert!(
        !run.installed_binary().exists(),
        "installer installed from an oversized checksum manifest"
    );

    // release metadata 超限：JSON 里仍然含有合法 tag_name。
    let mut metadata_run = installer_run(
        fixture.path().join("metadata-oversize"),
        &fake_bin,
        "metadata-oversize",
        &archive,
        &hash,
        &asset,
    );
    metadata_run.version = "";
    let metadata_output = metadata_run.run();
    assert!(
        !metadata_output.status.success(),
        "installer accepted oversized release metadata"
    );
    assert!(
        !metadata_run.installed_binary().exists(),
        "installer installed from oversized release metadata"
    );
}

/// AC-3.1 / AC-3.3：安装后动作失败必须可见，并且如实反映在退出码上。
#[test]
#[cfg(unix)]
fn unix_installer_surfaces_post_install_failures() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = build_archive(
        fixture.path(),
        "post-install",
        &[("sagy", FAKE_SAGY_BINARY, true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    let home = fixture.path().join("post-install-home");
    fs::create_dir_all(home.join(".gemini")).expect("create gemini home");

    let mut run = installer_run(home, &fake_bin, "valid", &archive, &hash, &asset);
    run.import_exit = "1";
    let output = run.run();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    assert!(
        !output.status.success(),
        "installer reported success after a failed post-install step:\n{stdout}"
    );
    assert!(
        stderr.contains("import-known"),
        "post-install failure did not name the failing step: {stderr}"
    );
    assert!(
        stderr.contains("fake import-known failure"),
        "post-install failure swallowed the underlying output: {stderr}"
    );
    assert!(
        !stdout.contains("Installed passthrough helper"),
        "installer kept printing the success summary after a failed step:\n{stdout}"
    );

    // 成功路径仍然必须报告导入成功。
    let ok_home = fixture.path().join("post-install-ok");
    fs::create_dir_all(ok_home.join(".gemini")).expect("create gemini home");
    let ok_run = installer_run(ok_home, &fake_bin, "valid", &archive, &hash, &asset);
    let ok_output = ok_run.run();
    assert!(
        ok_output.status.success(),
        "successful post-install step was reported as failure: {}",
        String::from_utf8_lossy(&ok_output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ok_output.stdout).contains("Imported current Antigravity"),
        "successful import was not reported"
    );
}

/// AC-R7-4.1：Ctrl-C 之后脚本必须停下来，而不是带着已删除的工作目录继续跑。
/// 判据是"进程被 SIGINT 终止"——只清理不重抛的 trap 会让脚本继续执行到
/// 下一次 I/O 失败，退出码变成普通的 1，signal 为空。
#[test]
#[cfg(unix)]
fn unix_installer_reraises_interrupt_instead_of_continuing() {
    use std::os::unix::process::ExitStatusExt;

    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = build_archive(
        fixture.path(),
        "interrupt",
        &[("sagy", FAKE_SAGY_BINARY, true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    let ready = fixture.path().join("interrupt-ready");
    let go = fixture.path().join("interrupt-go");

    let mut run = installer_run(
        fixture.path().join("interrupt-home"),
        &fake_bin,
        "interrupt",
        &archive,
        &hash,
        &asset,
    );
    run.interrupt_ready = Some(ready.clone());
    run.interrupt_go = Some(go.clone());

    let child = run.spawn();
    let pid = child.id();

    // 等安装脚本真正卡在归档下载上，再发信号：此时 bash 一定在 wait 子进程，
    // trap 会在子进程返回后立刻被处理。
    let mut waited = 0;
    while !ready.exists() && waited < 600 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        waited += 1;
    }
    assert!(
        ready.exists(),
        "fake curl never reached the archive download"
    );

    let killed = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("send SIGINT");
    assert!(killed.success(), "failed to signal the installer");
    fs::write(&go, "").expect("release the fake download");

    let output = child
        .wait_with_output()
        .expect("await interrupted installer");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert_eq!(
        output.status.signal(),
        Some(libc_sigint()),
        "installer did not re-raise SIGINT (status={:?}, stderr={stderr})",
        output.status
    );
    assert!(
        !stderr.contains("Download failed"),
        "installer kept running after the interrupt: {stderr}"
    );
    assert!(
        !run.installed_binary().exists(),
        "interrupted installer still installed a binary"
    );
    assert_temp_root_is_clean(&run.sagy_home(), "interrupt");
}

/// SIGINT 的编号在所有支持的 Unix 上都是 2；避免为了一个常量引入新依赖。
#[cfg(unix)]
fn libc_sigint() -> i32 {
    2
}

/// AC-7.1：PATH 上的 agy 与 `~/.gemini` 下的 agy 同时存在时，
/// `sagy-original` 必须选择 `~/.gemini` 这一份。
#[test]
#[cfg(unix)]
fn unix_original_wrapper_prefers_the_gemini_home_agy() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = build_archive(
        fixture.path(),
        "wrapper",
        &[("sagy", FAKE_SAGY_BINARY, true)],
    );
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let Some(target) = release_target() else {
        return;
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    let home = fixture.path().join("wrapper-home");

    let gemini_bin = home.join(".gemini/antigravity-cli/bin");
    fs::create_dir_all(&gemini_bin).expect("create gemini bin");
    let gemini_agy = gemini_bin.join("agy");
    fs::write(&gemini_agy, "#!/bin/sh\necho gemini-home-agy\n").expect("write gemini agy");
    make_executable(&gemini_agy);

    let path_dir = fixture.path().join("path-agy");
    fs::create_dir_all(&path_dir).expect("create path dir");
    let path_agy = path_dir.join("agy");
    fs::write(&path_agy, "#!/bin/sh\necho path-agy\n").expect("write path agy");
    make_executable(&path_agy);

    let mut run = installer_run(home.clone(), &fake_bin, "valid", &archive, &hash, &asset);
    run.extra_path = Some(path_dir.clone());
    let output = run.run();
    assert!(
        output.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let wrapper = run.sagy_home().join("bin/sagy-original");
    let wrapper_output = Command::new("bash")
        .arg(&wrapper)
        .env("HOME", &home)
        .env(
            "PATH",
            format!(
                "{}:{}",
                path_dir.display(),
                std::env::var("PATH").expect("inherit PATH")
            ),
        )
        .env_remove("AGY_BIN")
        .output()
        .expect("run sagy-original");
    assert!(
        String::from_utf8_lossy(&wrapper_output.stdout).contains("gemini-home-agy"),
        "sagy-original preferred the PATH agy: {}",
        String::from_utf8_lossy(&wrapper_output.stdout)
    );
}

/// AC-7.2：两个 installer 必须用同一个 `sagy-original` 解析顺序，并写明理由。
#[test]
fn both_installers_resolve_original_agy_in_the_same_order() {
    let unix_source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("read Unix installer");
    let windows_source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.ps1"))
        .expect("read PowerShell installer");

    // 锚点必须落在**真实分支**上：注释里同样写着 "AGY_BIN -> ... -> PATH agy"，
    // 用裸关键字取 find 只会命中那行注释，install.sh 的分支顺序怎么改都抓不到。
    let unix_agy_bin = unix_source
        .find(r#"if [[ -n "${AGY_BIN:-}" && -x "${AGY_BIN}" ]]; then"#)
        .expect("unix AGY_BIN branch");
    let unix_gemini = unix_source
        .find(r#"if [[ -x "${HOME}/.gemini/antigravity-cli/bin/agy" ]]; then"#)
        .expect("unix gemini branch");
    let unix_path = unix_source
        .find("if command -v agy >/dev/null 2>&1; then")
        .expect("unix PATH branch");
    assert!(
        unix_agy_bin < unix_gemini && unix_gemini < unix_path,
        "install.sh resolves sagy-original in an unexpected order"
    );

    let windows_agy_bin = windows_source
        .find("if defined AGY_BIN (")
        .expect("windows AGY_BIN branch");
    let windows_gemini = windows_source
        .find(r#"if exist "%USERPROFILE%\.gemini\antigravity-cli\bin\agy.cmd" ("#)
        .expect("windows gemini branch");
    let windows_path = windows_source
        .find("where agy >nul 2>nul")
        .expect("windows PATH branch");
    assert!(
        windows_agy_bin < windows_gemini && windows_gemini < windows_path,
        "install.ps1 resolves sagy-original in a different order than install.sh"
    );

    for (label, source) in [
        ("install.sh", &unix_source),
        ("install.ps1", &windows_source),
    ] {
        assert!(
            source.contains("sagy-original resolution order"),
            "{label} does not document the sagy-original resolution order"
        );
    }
}

/// AC-R7-3.3：install.ps1 的"空文件"守卫必须一直有锚点。
/// 第一轮把 `Downloaded archive is empty: $zipPath` / `Checksum manifest is empty: $sumsPath`
/// 两条既有断言连同旧实现一起删掉了（新实现统一走 `Assert-DownloadedFile`），
/// 这里把锚点补回来：既锚住守卫本体和三个下载点的接线，
/// 也锚住 CI 真正会执行的那两个空文件 fail-closed 场景。
#[test]
fn powershell_installer_keeps_the_empty_download_guards() {
    let installer = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.ps1"))
        .expect("read PowerShell installer");

    // 守卫本体：长度 <= 0 直接 throw。
    assert!(
        installer.contains("if ($info.Length -le 0) {"),
        "install.ps1 lost the empty-file guard"
    );
    assert!(
        installer.contains("throw \"$Label is empty: $Path\""),
        "install.ps1 lost the empty-file error message"
    );

    // 三个下载点都必须把落盘结果交给同一个守卫，并带上可辨识的 Label。
    for call in [
        "Assert-DownloadedFile -Path $metadataPath -Limit $MaxMetadataBytes -Label \"Release metadata\"",
        "Assert-DownloadedFile -Path $zipPath -Limit $MaxArchiveBytes -Label \"Downloaded archive\"",
        "Assert-DownloadedFile -Path $sumsPath -Limit $MaxSumsBytes -Label \"Checksum manifest\"",
    ] {
        assert!(installer.contains(call), "install.ps1 misses {call:?}");
    }

    // 可执行锚点：CI 的 pwsh harness 必须仍然把这两个空文件场景当作 fail-closed 用例。
    let harness = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/p0_checksum.ps1"
    ))
    .expect("read PowerShell harness");
    let list = fail_closed_mode_list(&harness);
    for mode in ["\"empty\"", "\"empty-archive\""] {
        assert!(
            list.contains(mode),
            "tests/p0_checksum.ps1 no longer exercises {mode} as a fail-closed scenario"
        );
    }
}

/// 取出 harness 里 `$failClosedModes = @( ... )` 的内容。
fn fail_closed_mode_list(harness: &str) -> &str {
    let marker = "$failClosedModes = @(";
    let start = harness
        .find(marker)
        .expect("harness lost its fail-closed mode list")
        + marker.len();
    let end = start
        + harness[start..]
            .find(')')
            .expect("fail-closed mode list is unterminated");
    &harness[start..end]
}

/// AC-R7-4.3 的前提：三条安装路径（update.rs / install.sh / install.ps1）
/// 必须使用同一组字节上限，否则同一个恶意响应在不同平台上的结局不一样。
#[test]
fn all_three_install_paths_declare_the_same_download_limits() {
    let rust = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/core/update.rs"))
        .expect("read updater source");
    let unix = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("read Unix installer");
    let windows = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.ps1"))
        .expect("read PowerShell installer");

    for (label, rust_needle, unix_needle, windows_needle) in [
        (
            "metadata",
            "const MAX_RELEASE_METADATA_BYTES: u64 =",
            "readonly MAX_METADATA_BYTES=",
            "$MaxMetadataBytes =",
        ),
        (
            "checksum manifest",
            "const MAX_CHECKSUM_MANIFEST_BYTES: u64 =",
            "readonly MAX_SUMS_BYTES=",
            "$MaxSumsBytes =",
        ),
        (
            "release archive",
            "const MAX_RELEASE_ASSET_BYTES: u64 =",
            "readonly MAX_ARCHIVE_BYTES=",
            "$MaxArchiveBytes =",
        ),
    ] {
        let from_rust = declared_number(&rust, rust_needle, "src/core/update.rs");
        let from_unix = declared_number(&unix, unix_needle, "install.sh");
        let from_windows = declared_number(&windows, windows_needle, "install.ps1");
        assert_eq!(
            from_rust, from_unix,
            "{label} limit differs between update.rs and install.sh"
        );
        assert_eq!(
            from_rust, from_windows,
            "{label} limit differs between update.rs and install.ps1"
        );
    }
}

/// 读出 `needle` 之后同一行上声明的十进制数字（允许 Rust 的 `_` 分隔符）。
fn declared_number(source: &str, needle: &str, label: &str) -> u64 {
    let start = source
        .find(needle)
        .unwrap_or_else(|| panic!("{label} misses {needle:?}"));
    let line = source[start + needle.len()..]
        .lines()
        .next()
        .unwrap_or_default();
    let digits = line
        .chars()
        .skip_while(|character| !character.is_ascii_digit())
        .take_while(|character| character.is_ascii_digit() || *character == '_')
        .filter(|character| *character != '_')
        .collect::<String>();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("{label}: no number follows {needle:?}"))
}

/// AC-6.1：更新决策只保留严格 semver 的那条路径。
#[test]
fn updater_exposes_only_the_strict_version_comparison() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/core/update.rs"))
        .expect("read updater source");
    assert!(
        !source.contains("pub fn is_newer_version"),
        "the lenient version comparison entry point is still exposed"
    );
    assert!(
        source.contains("fn update_decision("),
        "the strict update decision path is missing"
    );
}

/// AC-2.3：Windows 侧不再只依赖字符串断言。
/// 有 PowerShell 时直接执行 harness；没有时退回到源码守卫，
/// CI 的 windows job 会用真正的执行覆盖这一条（见 `.github/workflows/ci.yml`）。
#[test]
fn powershell_installer_fail_closed_harness_runs_when_powershell_is_available() {
    let Some(shell) = powershell_shell() else {
        return;
    };
    let harness = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/p0_checksum.ps1");
    let output = Command::new(&shell)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", harness])
        .env("SAGY_TEST_BINARY", env!("CARGO_BIN_EXE_sagy"))
        .output()
        .expect("run PowerShell checksum harness");
    assert!(
        output.status.success(),
        "PowerShell checksum harness failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn powershell_shell() -> Option<String> {
    for candidate in ["pwsh", "powershell"] {
        let probe = Command::new(candidate)
            .args(["-NoProfile", "-Command", "exit 0"])
            .output();
        if probe.is_ok_and(|output| output.status.success()) {
            return Some(candidate.to_string());
        }
    }
    None
}

#[test]
fn powershell_installer_has_fail_closed_checksum_guard() {
    let unix_source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("read Unix installer");
    assert!(unix_source.contains("--connect-timeout \"${CURL_CONNECT_TIMEOUT}\""));
    assert!(unix_source.contains("--max-time \"${CURL_MAX_TIME}\""));
    assert!(unix_source.contains("--max-filesize \"${limit}\""));
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.ps1"))
        .expect("read PowerShell installer");
    assert!(source.contains("-TimeoutSec $DownloadTimeoutSec"));
    assert!(source.contains("Checksum entry for $assetName is missing"));
    assert!(source.contains("Malformed checksum entry in $sumsPath"));
    assert!(source.contains("Duplicate or empty checksum target in $sumsPath"));
    assert!(source.contains("Unsafe checksum target in $sumsPath"));
    assert!(source.contains("Checksum verification requires Get-FileHash."));
    assert!(source.contains("SHA-256 checksum mismatch for $assetName"));
    assert!(source.contains("if ($actualHash -ne $expectedHash)"));
    assert!(source.contains("Release archive did not contain a top-level sagy.exe binary."));
    assert!(!source.contains("Checksum verification skipped or failed"));

    // AC-1.1：一次性工作目录 + 无条件清理。
    assert!(source.contains("[guid]::NewGuid().ToString(\"N\")"));
    assert!(source.contains("Remove-Item -LiteralPath $WorkDir -Recurse -Force"));

    // AC-4.2 / AC-4.3：体积上限必须是带注释的常量。
    for limit in ["$MaxMetadataBytes", "$MaxSumsBytes", "$MaxArchiveBytes"] {
        assert!(source.contains(limit), "install.ps1 misses {limit}");
    }
    for limit in ["MAX_METADATA_BYTES", "MAX_SUMS_BYTES", "MAX_ARCHIVE_BYTES"] {
        assert!(unix_source.contains(limit), "install.sh misses {limit}");
    }
}
