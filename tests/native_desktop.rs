#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    fake_agy: PathBuf,
    fake_desktop: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profiles-root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(root).unwrap();

        let fake_agy = temp.path().join("agy");
        fs::write(
            &fake_agy,
            r##"#!/usr/bin/env python3
import json
import os
import sys

if "/usage" not in sys.argv:
    raise SystemExit(0)
token_path = os.path.join(os.environ["HOME"], ".gemini/antigravity-cli/antigravity-oauth-token")
token = json.load(open(token_path))["token"]["refresh_token"]
profile = token.removeprefix("synthetic-refresh-")
quotas = json.loads(os.environ["SAGY_FIXTURE_USAGE_MAP"])
five_hour, weekly = quotas[profile]
print(json.dumps({"status":"SUCCESS","command":{"name":"usage","data":{"groups":[{"buckets":[
    {"id":"gemini-5h","remaining_fraction":five_hour},
    {"id":"gemini-weekly","remaining_fraction":weekly}
]}]}}}))
"##,
        )
        .unwrap();
        make_executable(&fake_agy);
        let fake_agy = fs::canonicalize(fake_agy).unwrap();

        let fake_desktop = temp.path().join("Antigravity");
        fs::write(
            &fake_desktop,
            r##"#!/usr/bin/env python3
import json
import os
import pathlib
import sys

home = pathlib.Path(os.environ["HOME"])
user_data = next((arg.split("=", 1)[1] for arg in sys.argv[1:]
                  if arg.startswith("--user-data-dir=")), None)
if user_data is None:
    for index, arg in enumerate(sys.argv[1:]):
        if arg == "--user-data-dir":
            user_data = sys.argv[index + 2]
            break
token = (home / ".gemini/jetski-standalone-oauth-token").read_bytes()
(home / "fixture-capture.json").write_text(json.dumps({
    "argv": sys.argv[1:],
    "home": str(home),
    "xdg_config_home": os.environ.get("XDG_CONFIG_HOME"),
    "xdg_data_home": os.environ.get("XDG_DATA_HOME"),
    "xdg_cache_home": os.environ.get("XDG_CACHE_HOME"),
    "shell": os.environ.get("SHELL"),
    "ssh_connection": os.environ.get("SSH_CONNECTION"),
    "user_data": user_data,
    "token": token.decode(),
    "proxy": os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY"),
}))
if os.environ.get("SAGY_FIXTURE_DESKTOP_WAIT") == "1":
    (home / "fixture-ready").write_text("ready")
    while not (home / "fixture-release").exists():
        import time
        time.sleep(0.02)
"##,
        )
        .unwrap();
        make_executable(&fake_desktop);
        let fake_desktop = fs::canonicalize(fake_desktop).unwrap();

        Self {
            _temp: temp,
            root,
            fake_agy,
            fake_desktop,
        }
    }

    fn add_profile(&self, name: &str) -> serde_json::Value {
        let home = self.root.join("profiles").join(name).join("home");
        let cli_config = home.join(".gemini/antigravity-cli");
        fs::create_dir_all(&cli_config).unwrap();
        for directory in [
            self.root.join("profiles"),
            self.root.join("profiles").join(name),
            home.clone(),
            home.join(".gemini"),
            cli_config.clone(),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let token = serde_json::json!({
            "token": {
                "access_token": format!("synthetic-access-{name}"),
                "refresh_token": format!("synthetic-refresh-{name}"),
                "token_type": "Bearer",
                "expiry": "2099-01-01T00:00:00Z",
                "expires_in": 3600
            },
            "auth_method": "synthetic-test",
            "id_token_email": format!("{name}@example.test")
        });
        let token_path = cli_config.join("antigravity-oauth-token");
        fs::write(&token_path, serde_json::to_vec(&token).unwrap()).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        token
    }

    fn prepare_profiles(&self, quotas: &[(&str, f64, f64)]) {
        let mut names = Vec::new();
        for (name, _, _) in quotas {
            self.add_profile(name);
            names.push((*name).to_owned());
        }
        let state_path = self.root.join("state.json");
        fs::write(
            &state_path,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "profiles": names
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(state_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn command(&self, args: &[&str], usage_map: &str, proxy: Option<&str>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
        command
            .args(args)
            .env("SAGY_PROFILE_ROOT", &self.root)
            .env("AGY_BIN", &self.fake_agy)
            .env("SAGY_DESKTOP_BIN", &self.fake_desktop)
            .env("SAGY_FIXTURE_USAGE_MAP", usage_map)
            .env_remove("http_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("all_proxy")
            .env_remove("ALL_PROXY");
        if let Some(proxy) = proxy {
            command.env("https_proxy", proxy);
        }
        command
    }

    fn invoke(&self, args: &[&str], usage_map: &str, proxy: Option<&str>) -> Output {
        self.command(args, usage_map, proxy).output().unwrap()
    }

    fn profile_home(&self, name: &str) -> PathBuf {
        self.root.join("profiles").join(name).join("home")
    }

    fn desktop_capture(&self, name: &str) -> serde_json::Value {
        let desktop_home = self.root.join("profiles").join(name).join("desktop-home");
        serde_json::from_slice(&fs::read(desktop_home.join("fixture-capture.json")).unwrap())
            .unwrap()
    }
}

fn make_executable(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

struct RunningDesktop {
    child: std::process::Child,
    release: PathBuf,
}

impl Drop for RunningDesktop {
    fn drop(&mut self) {
        let _ = fs::write(&self.release, "release");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn desktop_uses_auto_quota_policy_and_copies_token_into_an_isolated_home() {
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[
        ("weekly-low", 1.0, 0.049),
        ("best", 0.95, 0.93),
        ("runner-up", 0.81, 0.75),
    ]);
    let best_original = fs::read(
        fixture
            .profile_home("best")
            .join(".gemini/antigravity-cli/antigravity-oauth-token"),
    )
    .unwrap();
    let usage_map = r#"{"weekly-low":[1.0,0.049],"best":[0.95,0.93],"runner-up":[0.81,0.75]}"#;
    let output = fixture.invoke(&["desktop"], usage_map, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Opening Antigravity with profile best."));
    assert!(
        !fixture
            .root
            .join("profiles/weekly-low/desktop-home")
            .exists()
    );

    let capture = fixture.desktop_capture("best");
    let desktop_home = fixture
        .root
        .join("profiles/best/desktop-home")
        .to_string_lossy()
        .into_owned();
    assert_eq!(capture["home"], desktop_home);
    assert_eq!(
        capture["token"],
        String::from_utf8(best_original.clone()).unwrap()
    );
    assert_eq!(
        capture["xdg_config_home"],
        format!("{desktop_home}/.config")
    );
    assert_eq!(
        capture["xdg_data_home"],
        format!("{desktop_home}/.local/share")
    );
    assert_eq!(capture["xdg_cache_home"], format!("{desktop_home}/.cache"));
    assert_eq!(capture["ssh_connection"], "127.0.0.1 0 127.0.0.1 0");
    assert_eq!(capture["proxy"], "http://127.0.0.1:10808");
    assert!(
        capture["user_data"]
            .as_str()
            .unwrap()
            .ends_with(".local/share/antigravity-desktop")
    );
    assert!(
        capture["shell"]
            .as_str()
            .unwrap()
            .contains(".desktop-shell")
    );
    assert_eq!(
        fs::read(
            fixture
                .profile_home("best")
                .join(".gemini/antigravity-cli/antigravity-oauth-token")
        )
        .unwrap(),
        best_original
    );
}

#[test]
fn desktop_inherits_a_configured_proxy_and_help_and_invalid_args_have_no_side_effects() {
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("one", 0.9, 0.9)]);
    let usage_map = r#"{"one":[0.9,0.9]}"#;

    let help = fixture.invoke(&["desktop", "--help"], usage_map, None);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stderr).contains("sagy desktop"));
    assert!(!fixture.root.join("profiles/one/desktop-home").exists());

    let invalid = fixture.invoke(&["desktop", "one"], usage_map, None);
    assert!(!invalid.status.success());
    assert!(!fixture.root.join("profiles/one/desktop-home").exists());

    let output = fixture.invoke(&["desktop"], usage_map, Some("http://127.0.0.1:18888"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.desktop_capture("one")["proxy"],
        "http://127.0.0.1:18888"
    );
}

#[test]
fn desktop_holds_profile_lease_allows_cli_run_and_releases_locks_on_exit() {
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("one", 0.9, 0.9)]);
    let usage_map = r#"{"one":[0.9,0.9]}"#;
    let child = fixture
        .command(&["desktop"], usage_map, None)
        .env("SAGY_FIXTURE_DESKTOP_WAIT", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let desktop_home = fixture.root.join("profiles/one/desktop-home");
    let ready = desktop_home.join("fixture-ready");
    let release = desktop_home.join("fixture-release");
    let mut desktop = RunningDesktop { child, release };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !ready.exists() {
        if let Some(status) = desktop.child.try_wait().unwrap() {
            panic!("desktop exited before ready: {status}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "desktop did not reach ready state"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let desktop_token =
        fs::read(desktop_home.join(".gemini/jetski-standalone-oauth-token")).unwrap();

    let run = fixture.invoke(&["run", "one"], usage_map, None);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let remove = fixture.invoke(&["rm", "one"], usage_map, None);
    assert!(!remove.status.success());
    assert!(String::from_utf8_lossy(&remove.stderr).contains("busy"));

    let second = fixture.invoke(&["desktop"], usage_map, None);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already running"));
    assert_eq!(
        fs::read(desktop_home.join(".gemini/jetski-standalone-oauth-token")).unwrap(),
        desktop_token
    );

    fs::write(&desktop.release, "release").unwrap();
    assert!(desktop.child.wait().unwrap().success());
    let remove_after_exit = fixture.invoke(&["rm", "one"], usage_map, None);
    assert!(
        remove_after_exit.status.success(),
        "{}",
        String::from_utf8_lossy(&remove_after_exit.stderr)
    );
}
