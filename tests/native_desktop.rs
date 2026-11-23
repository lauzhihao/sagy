#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;

// 每个场景内部已有并发进程；场景间串行，避免测试宿主负载耗尽生产 probe 的八秒预算。
static DESKTOP_TEST_LOCK: Mutex<()> = Mutex::new(());

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
log = os.environ["SAGY_FIXTURE_PROBE_LOG"]
with open(log, "a") as file:
    file.write(profile + "\n")
if os.environ.get("SAGY_FIXTURE_USAGE_DELAY") and open(log).read().splitlines().count(profile) == 1:
    import time
    time.sleep(float(os.environ["SAGY_FIXTURE_USAGE_DELAY"]))
quotas = json.loads(os.environ["SAGY_FIXTURE_USAGE_MAP"])
if quotas[profile] is None:
    raise SystemExit(2)
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
    "probes": (pathlib.Path(os.environ["SAGY_FIXTURE_PROBE_LOG"]).read_text().splitlines()
               if pathlib.Path(os.environ["SAGY_FIXTURE_PROBE_LOG"]).exists() else []),
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
if os.environ.get("SAGY_FIXTURE_DESKTOP_EXIT_CODE"):
    print("raw desktop diagnostic with https://secret.example/token", file=sys.stderr)
    raise SystemExit(int(os.environ["SAGY_FIXTURE_DESKTOP_EXIT_CODE"]))
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
        // 首次导入由注入合成源的 unit tests 覆盖，integration 不读取真实 HOME。
        let desktop_home = self.root.join("desktop-home");
        fs::create_dir(&desktop_home).unwrap();
        fs::set_permissions(&desktop_home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(desktop_home.join(".gemini")).unwrap();
        fs::set_permissions(
            desktop_home.join(".gemini"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let marker = desktop_home.join(".sagy-desktop-history-v1");
        fs::write(&marker, b"sagy desktop history v1\n").unwrap();
        fs::set_permissions(marker, fs::Permissions::from_mode(0o600)).unwrap();
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
            .env(
                "SAGY_FIXTURE_PROBE_LOG",
                self._temp.path().join("probes.log"),
            )
            .env_remove("SAGY_FIXTURE_USAGE_DELAY")
            .env_remove("SAGY_FIXTURE_DESKTOP_EXIT_CODE")
            .env_remove("http_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("all_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("SAGY_DEFAULT_PROXY");
        if let Some(proxy) = proxy {
            command.env("https_proxy", proxy);
        }
        command
    }

    fn invoke(&self, args: &[&str], usage_map: &str, proxy: Option<&str>) -> Output {
        let mut child = self
            .command(args, usage_map, proxy)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "command {args:?} did not finish: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn profile_home(&self, name: &str) -> PathBuf {
        self.root.join("profiles").join(name).join("home")
    }

    fn desktop_capture(&self, _name: &str) -> serde_json::Value {
        let desktop_home = self.root.join("desktop-home");
        serde_json::from_slice(&fs::read(desktop_home.join("fixture-capture.json")).unwrap())
            .unwrap()
    }
}

#[test]
fn desktop_reports_nonzero_exit_without_forwarding_private_app_logs() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("chosen@example.test", 0.8, 0.8)]);
    let output = fixture
        .command(&["desktop", "chosen@example.test"], "{}", None)
        .env("SAGY_FIXTURE_DESKTOP_EXIT_CODE", "23")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Antigravity desktop exited with status 23."));
    assert!(!stderr.contains("raw desktop diagnostic"));
    assert!(!stderr.contains("secret.example"));
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
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[
        ("a-weekly-low", 1.0, 0.049),
        ("z-best", 0.95, 0.93),
        ("runner-up", 0.81, 0.75),
    ]);
    let best_original = fs::read(
        fixture
            .profile_home("z-best")
            .join(".gemini/antigravity-cli/antigravity-oauth-token"),
    )
    .unwrap();
    let usage_map = r#"{"a-weekly-low":[1.0,0.049],"z-best":[0.95,0.93],"runner-up":[0.81,0.75]}"#;
    let output = fixture.invoke(&["desktop"], usage_map, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Opening Antigravity with profile z-best."));
    assert!(
        !fixture
            .root
            .join("profiles/a-weekly-low/desktop-home")
            .exists()
    );

    let capture = fixture.desktop_capture("z-best");
    let desktop_home = fixture
        .root
        .join("desktop-home")
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
    assert_eq!(capture["proxy"], serde_json::Value::Null);
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
                .profile_home("z-best")
                .join(".gemini/antigravity-cli/antigravity-oauth-token")
        )
        .unwrap(),
        best_original
    );
}

#[test]
fn desktop_inherits_a_configured_proxy_and_help_and_invalid_args_have_no_side_effects() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("one", 0.9, 0.9)]);
    let usage_map = r#"{"one":[0.9,0.9]}"#;

    let help = fixture.invoke(&["desktop", "--help"], usage_map, None);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stderr).contains("sagy desktop"));
    assert!(!fixture.root.join("profiles/one/desktop-home").exists());

    let invalid = fixture.invoke(&["desktop", "one", "extra"], usage_map, None);
    assert!(!invalid.status.success());
    assert!(!fixture.root.join("profiles/one/desktop-home").exists());

    let fallback = fixture
        .command(&["desktop"], usage_map, None)
        .env("SAGY_DEFAULT_PROXY", "http://127.0.0.1:10808")
        .output()
        .unwrap();
    assert!(
        fallback.status.success(),
        "{}",
        String::from_utf8_lossy(&fallback.stderr)
    );
    assert_eq!(
        fixture.desktop_capture("one")["proxy"],
        "http://127.0.0.1:10808"
    );

    let output = fixture
        .command(&["desktop"], usage_map, Some("http://127.0.0.1:18888"))
        .env("SAGY_DEFAULT_PROXY", "http://127.0.0.1:10808")
        .output()
        .unwrap();
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
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("one", 0.9, 0.9), ("two", 0.8, 0.8)]);
    let usage_map = r#"{"one":[0.9,0.9],"two":[0.8,0.8]}"#;
    let child = fixture
        .command(&["desktop", "one"], usage_map, None)
        .env("SAGY_FIXTURE_DESKTOP_WAIT", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let desktop_home = fixture.root.join("desktop-home");
    let ready = desktop_home.join("fixture-ready");
    let release = desktop_home.join("fixture-release");
    let mut desktop = RunningDesktop { child, release };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
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

    let second = fixture.invoke(&["desktop", "two"], usage_map, None);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("desktop instance running"));
    assert_eq!(
        fs::read(desktop_home.join(".gemini/jetski-standalone-oauth-token")).unwrap(),
        desktop_token
    );

    fs::write(&desktop.release, "release").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = desktop.child.try_wait().unwrap() {
            assert!(status.success(), "desktop failed to finish: {status}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "desktop command did not finish after the app exited"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let remove_after_exit = fixture.invoke(&["rm", "one"], usage_map, None);
    assert!(
        remove_after_exit.status.success(),
        "{}",
        String::from_utf8_lossy(&remove_after_exit.stderr)
    );
}

#[test]
fn desktop_refreshes_stale_quotas_once_and_skips_unavailable_profiles() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[
        ("exhausted", 1.0, 1.0),
        ("best", 0.1, 0.1),
        ("unknown", 0.9, 0.9),
    ]);
    let seed = fixture.invoke(
        &["refresh"],
        r#"{"exhausted":[1,1],"best":[0.1,0.1],"unknown":[0.9,0.9]}"#,
        None,
    );
    assert!(seed.status.success());
    fs::write(fixture._temp.path().join("probes.log"), "").unwrap();
    let output = fixture.invoke(
        &["desktop"],
        r#"{"exhausted":[0,0.8],"best":[0.7,0.8],"unknown":null}"#,
        None,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capture = fixture.desktop_capture("best");
    let mut probes = capture["probes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    probes.sort();
    assert_eq!(probes, ["best", "exhausted", "unknown"]);
    let snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("quota.json")).unwrap()).unwrap();
    assert_eq!(
        snapshot["profiles"]["exhausted"]["windows"],
        serde_json::json!([0.0, 0.8])
    );
    assert_eq!(snapshot["profiles"]["unknown"]["result"], "unavailable");
    for name in ["exhausted", "unknown"] {
        assert!(
            !fixture
                .root
                .join("profiles")
                .join(name)
                .join("desktop-home")
                .exists()
        );
    }
}

#[test]
fn desktop_refuses_missing_quota_windows_even_with_a_healthy_old_snapshot() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("missing", 1.0, 1.0), ("partial", 1.0, 1.0)]);
    assert!(
        fixture
            .invoke(&["refresh"], r#"{"missing":[1,1],"partial":[1,1]}"#, None)
            .status
            .success()
    );
    let output = fixture.invoke(&["desktop"], r#"{"missing":null,"partial":[1,null]}"#, None);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("No eligible profile after quota refresh")
    );
    for name in ["missing", "partial"] {
        assert!(
            !fixture
                .root
                .join("profiles")
                .join(name)
                .join("desktop-home")
                .exists()
        );
    }
}

#[test]
fn desktop_refresh_accepts_a_probe_slower_than_the_auto_timeout() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("slow", 1.0, 1.0)]);
    let output = fixture
        .command(&["desktop"], r#"{"slow":[0.9,0.9]}"#, None)
        .env("SAGY_FIXTURE_USAGE_DELAY", "9")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.desktop_capture("slow")["probes"],
        serde_json::json!(["slow"])
    );
}

#[test]
fn desktop_accepts_an_exact_email_without_auto_quota_filtering() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("chosen@example.test", 0.0, 0.01), ("other", 1.0, 1.0)]);
    let output = fixture.invoke(
        &["desktop", "chosen@example.test"],
        r#"{"chosen@example.test":[0,0.01],"other":[1,1]}"#,
        None,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let capture = fixture.desktop_capture("chosen@example.test");
    assert_eq!(capture["probes"], serde_json::json!([]));
    assert!(!fixture.root.join("profiles/other/desktop-home").exists());
    assert!(
        capture["token"]
            .as_str()
            .unwrap()
            .contains("synthetic-refresh-chosen@example.test")
    );
}

#[test]
fn desktop_index_uses_the_displayed_snapshot_order_without_refreshing_it_first() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("alphabetic-first", 0.1, 0.2), ("z-list-first", 0.9, 0.9)]);
    assert!(
        fixture
            .invoke(
                &["refresh"],
                r#"{"alphabetic-first":[0.1,0.2],"z-list-first":[0.9,0.9]}"#,
                None
            )
            .status
            .success()
    );
    fs::write(fixture._temp.path().join("probes.log"), "").unwrap();
    let output = fixture.invoke(
        &["desktop", "1"],
        r#"{"alphabetic-first":[1,1],"z-list-first":[0,0]}"#,
        None,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture.desktop_capture("z-list-first")["probes"],
        serde_json::json!([])
    );
    assert!(
        !fixture
            .root
            .join("profiles/alphabetic-first/desktop-home")
            .exists()
    );
}

#[test]
fn desktop_rejects_unknown_profiles_and_invalid_indices_without_launching() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("one", 1.0, 1.0)]);
    for argument in ["missing", "0", "2", "--unknown"] {
        let output = fixture.invoke(&["desktop", argument], r#"{"one":[1,1]}"#, None);
        assert!(!output.status.success(), "{argument}");
        assert!(!fixture.root.join("profiles/one/desktop-home").exists());
        assert!(!fixture._temp.path().join("probes.log").exists());
    }
}

#[test]
fn switching_desktop_accounts_preserves_the_shared_history_and_replaces_only_the_token() {
    let _guard = DESKTOP_TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    fixture.prepare_profiles(&[("first", 0.9, 0.9), ("second", 0.8, 0.8)]);
    let history = fixture
        .root
        .join("desktop-home/.gemini/antigravity/conversations");
    fs::create_dir_all(&history).unwrap();
    fs::write(history.join("synthetic.pb"), b"synthetic conversation").unwrap();
    for name in ["first", "second"] {
        let output = fixture.invoke(
            &["desktop", name],
            r#"{"first":[0.9,0.9],"second":[0.8,0.8]}"#,
            None,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let capture = fixture.desktop_capture(name);
        assert_eq!(
            capture["home"],
            fixture.root.join("desktop-home").to_string_lossy().as_ref()
        );
        assert!(
            capture["token"]
                .as_str()
                .unwrap()
                .contains(&format!("synthetic-refresh-{name}"))
        );
        assert_eq!(
            fs::read(history.join("synthetic.pb")).unwrap(),
            b"synthetic conversation"
        );
        assert!(
            !fixture
                .root
                .join("profiles")
                .join(name)
                .join("desktop-home")
                .exists()
        );
    }
}
