use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

#[cfg(unix)]
fn write_fake_curl(bin_dir: &Path) {
    let script = r#"#!/bin/sh
set -eu
url=""
out=""
previous=""
for arg in "$@"; do
    if [ "$previous" = "-o" ]; then
        out="$arg"
    elif printf '%s' "$arg" | grep -q '^https://'; then
        url="$arg"
    fi
    previous="$arg"
done
if printf '%s' "$url" | grep -q 'SHA256SUMS.txt'; then
    case "${FAKE_SUMS_MODE}" in
        checksum-timeout) exit 28 ;;
        http-error) exit 22 ;;
        empty) : > "$out" ;;
        missing) printf '%s  other.tar.gz\n' "$FAKE_HASH" > "$out" ;;
        duplicate) printf '%s  %s\n%s  %s\n' "$FAKE_HASH" "$FAKE_ASSET" "$FAKE_HASH" "$FAKE_ASSET" > "$out" ;;
        malformed) printf 'not-a-hash  %s\n' "$FAKE_ASSET" > "$out" ;;
        mismatch) printf '%064d  %s\n' 0 "$FAKE_ASSET" > "$out" ;;
        valid) printf '%s  %s\n' "$FAKE_HASH" "$FAKE_ASSET" > "$out" ;;
        *) exit 1 ;;
    esac
else
    if [ "${FAKE_SUMS_MODE}" = archive-timeout ]; then exit 28; fi
    cp "$FAKE_ARCHIVE" "$out"
fi
"#;
    let path = bin_dir.join("curl");
    fs::write(&path, script).expect("write fake curl");
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
fn archive_fixture(root: &Path) -> (std::path::PathBuf, String) {
    let source_dir = root.join("source");
    fs::create_dir_all(&source_dir).expect("create archive source");
    fs::write(source_dir.join("sagy"), b"test binary").expect("write archive binary");
    let archive = root.join("release.tar.gz");
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .args(["-C"])
        .arg(&source_dir)
        .arg("sagy")
        .status()
        .expect("run tar");
    assert!(status.success(), "tar fixture failed");
    let hash = String::from_utf8(
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(&archive)
            .output()
            .expect("hash archive")
            .stdout,
    )
    .expect("decode hash")
    .split_whitespace()
    .next()
    .expect("hash output")
    .to_string();
    (archive, hash)
}

#[test]
#[cfg(unix)]
fn unix_installer_requires_checksum_before_install() {
    let fixture = TempDir::new().expect("fixture tempdir");
    let (archive, hash) = archive_fixture(fixture.path());
    let fake_bin = fixture.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    write_fake_curl(&fake_bin);

    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "x86_64") => "x86_64-unknown-linux-musl",
        _ => return,
    };
    let asset = format!("sagy-v1.0.0-{target}.tar.gz");
    for mode in [
        "archive-timeout",
        "checksum-timeout",
        "http-error",
        "empty",
        "missing",
        "duplicate",
        "malformed",
        "mismatch",
    ] {
        let home = fixture.path().join(mode);
        let output = Command::new("bash")
            .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/install.sh")
            .env("HOME", &home)
            .env("SAGY_HOME", home.join(".sagy"))
            .env("SAGY_VERSION", "v1.0.0")
            .env("SAGY_REPO", "test/repo")
            .env("FAKE_SUMS_MODE", mode)
            .env("FAKE_HASH", &hash)
            .env("FAKE_ASSET", &asset)
            .env("FAKE_ARCHIVE", &archive)
            .env(
                "PATH",
                format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .expect("run unix installer");
        assert!(
            !output.status.success(),
            "installer unexpectedly succeeded for {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !home.join(".sagy/bin/sagy").exists(),
            "installer copied binary for failed checksum mode {mode}"
        );
    }

    let home = fixture.path().join("valid");
    let output = Command::new("bash")
        .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/install.sh")
        .env("HOME", &home)
        .env("SAGY_HOME", home.join(".sagy"))
        .env("SAGY_VERSION", "v1.0.0")
        .env("SAGY_REPO", "test/repo")
        .env("FAKE_SUMS_MODE", "valid")
        .env("FAKE_HASH", &hash)
        .env("FAKE_ASSET", &asset)
        .env("FAKE_ARCHIVE", &archive)
        .env(
            "PATH",
            format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .expect("run valid unix installer");
    assert!(
        output.status.success(),
        "valid checksum was rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(home.join(".sagy/bin/sagy").exists());
}

#[test]
fn powershell_installer_has_fail_closed_checksum_guard() {
    let unix_source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("read Unix installer");
    assert!(unix_source.contains("--connect-timeout \"${CURL_CONNECT_TIMEOUT}\""));
    assert!(unix_source.contains("--max-time \"${CURL_MAX_TIME}\""));
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.ps1"))
        .expect("read PowerShell installer");
    assert!(source.contains("Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec $DownloadTimeoutSec"));
    assert!(source.contains("Invoke-WebRequest -Uri $sumsUrl"));
    assert!(source.contains("-TimeoutSec $DownloadTimeoutSec"));
    assert!(source.contains("Checksum entry for $assetName is missing"));
    assert!(source.contains("Malformed checksum entry in $sumsPath"));
    assert!(source.contains("Duplicate or empty checksum target in $sumsPath"));
    assert!(source.contains("SHA-256 checksum mismatch for $assetName"));
    assert!(!source.contains("Checksum verification skipped or failed"));
}
