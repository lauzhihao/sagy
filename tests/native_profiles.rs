#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn invoke(root: &Path, args: &[&str]) -> std::process::Output {
    let output = Command::new(env!("CARGO_BIN_EXE_sagy"))
        .args(args)
        .env("SAGY_PROFILE_ROOT", root)
        .env("SAGY_POOL_KEY", "synthetic-native-cross-platform-test")
        .env("AGY_BIN", "/nonexistent/agy")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn default_entry_roundtrips_native_profiles_without_agy() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    let remote = temp.path().join("pool.git");
    let status = Command::new("git")
        .args(["init", "--bare"])
        .arg(&remote)
        .output()
        .unwrap();
    assert!(status.status.success());
    let config = source.join("profiles/demo/home/.gemini/antigravity-cli");
    fs::create_dir_all(&config).unwrap();
    for path in config.ancestors().take_while(|path| *path != temp.path()) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let token = serde_json::json!({"token":{"refresh_token":"synthetic-native-test"}});
    for (path, value) in [
        (
            source.join("state.json"),
            serde_json::json!({"version":1,"profiles":["demo"]}),
        ),
        (config.join("antigravity-oauth-token"), token.clone()),
    ] {
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    invoke(&source, &["push", remote.to_str().unwrap()]);
    invoke(&target, &["pull", remote.to_str().unwrap()]);
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(target.join("state.json")).unwrap()).unwrap();
    let slot = state["directories"]["demo"].as_str().unwrap();
    let imported = target
        .join("profiles")
        .join(slot)
        .join("home/.gemini/antigravity-cli/antigravity-oauth-token");
    let restored: serde_json::Value = serde_json::from_slice(&fs::read(imported).unwrap()).unwrap();
    assert_eq!(restored, token);
    let output = invoke(&target, &["list"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("demo"));
    invoke(&target, &["pull"]);
}

#[test]
fn native_help_uses_the_same_bundle_directory_on_linux_and_macos() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("unused");
    let output = invoke(&root, &["pull", "--help"]);
    assert!(String::from_utf8_lossy(&output.stdout).contains(".sagy-native-profiles"));
    assert!(!root.exists());
}
