import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile
import pty
import fcntl
import termios
import time
import unittest


TEST_EXE = os.environ.get("SAGY_NATIVE_TEST_EXE")


@unittest.skipUnless(sys.platform == "darwin" and TEST_EXE, "run via cargo test profile::tests")
class SagyProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sagy-profile-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profile_root = self.root / "profiles"
        self.fake_agy = self.root / "bin" / "agy"
        self.fake_agy.parent.mkdir()
        fake_source = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import time

home = Path(os.environ["HOME"])
config_dir = home / ".gemini/antigravity-cli"
token_path = config_dir / "antigravity-oauth-token"
token_path.parent.mkdir(parents=True, exist_ok=True)
if not token_path.exists():
    token_path.write_text(json.dumps({
        "token": {"refresh_token": os.environ.get("PROFILE_FIXTURE_TOKEN", "")}
    }))
usage_path = config_dir / "profile-test-usage.json"
if "PROFILE_FIXTURE_USAGE" in os.environ:
    usage_path.write_text(os.environ["PROFILE_FIXTURE_USAGE"])
if os.environ.get("PROFILE_FIXTURE_FAIL") == "1":
    raise SystemExit(17)

token_data = json.loads(token_path.read_text())
token = token_data["token"]["refresh_token"]
arguments = sys.argv[1:]
settings = None
if "--settings" in arguments:
    offset = arguments.index("--settings")
    settings = json.loads(arguments[offset + 1])
    del arguments[offset:offset + 2]
if arguments[:1] == ["probe-read"]:
    try:
        Path(arguments[1]).read_bytes()
    except PermissionError:
        raise SystemExit(23)
    raise SystemExit(0)

if "/usage" in arguments:
    try:
        tty = os.open("/dev/tty", os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        controlling_tty = False
    else:
        os.close(tty)
        controlling_tty = True
    forbidden_read_allowed = None
    if os.environ.get("PROFILE_FIXTURE_FORBIDDEN_PROBE_READ"):
        try:
            Path(os.environ["PROFILE_FIXTURE_FORBIDDEN_PROBE_READ"]).read_bytes()
            forbidden_read_allowed = True
        except PermissionError:
            forbidden_read_allowed = False
    with open(os.environ["PROFILE_FIXTURE_USAGE_LOG"], "a") as stream:
        stream.write(json.dumps({"token": token, "started_at": time.monotonic(), "home": str(home),
                                 "forbidden_read_allowed": forbidden_read_allowed, "pid": os.getpid(),
                                 "session_id": os.getsid(0), "controlling_tty": controlling_tty}) + "\n")
    if os.environ.get("PROFILE_FIXTURE_PROBE_DELAY"):
        time.sleep(float(os.environ["PROFILE_FIXTURE_PROBE_DELAY"]))
    if os.environ.get("PROFILE_FIXTURE_WAIT_FOR_SIGNAL"):
        Path(os.environ["PROFILE_FIXTURE_WAIT_FOR_SIGNAL"]).write_text(str(os.getpid()))
        time.sleep(30)
    try:
        usage = json.loads(usage_path.read_text())
    except FileNotFoundError:
        usage = {"status": "SUCCESS", "command": {"name": "usage"}, "data": {"groups": []}}
    print(json.dumps(usage))
    raise SystemExit(0)

log_path = None
for index, argument in enumerate(arguments):
    if argument.startswith("--log-file="):
        log_path = argument.split("=", 1)[1]
    elif argument == "--log-file" and index + 1 < len(arguments):
        log_path = arguments[index + 1]
is_rate_limited = (config_dir / "profile-test-429").exists()
foreground = echo = None
if os.environ.get("PROFILE_FIXTURE_CONTROLLING_TTY") == "1" and log_path is not None:
    import termios
    foreground = os.tcgetpgrp(0) == os.getpgrp()
    attributes = termios.tcgetattr(0)
    echo = bool(attributes[3] & termios.ECHO)
    if is_rate_limited:
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attributes)
finish_marker = None
if log_path is not None:
    log_file = Path(log_path)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    diagnostic = (
        "E1101 12:34:56.123456     123 errorreport.go:224] "
        "agent executor error: generating and executing: "
        "RESOURCE_EXHAUSTED (code 429)\n"
    )
    log_file.write_text(diagnostic if is_rate_limited else "")
    finish_marker = Path(str(log_file) + ".natural-finish")
event = {
    "home": str(home),
    "gemini_home": os.environ.get("GEMINI_HOME"),
    "antigravity_config_dir": os.environ.get("ANTIGRAVITY_CONFIG_DIR"),
    "antigravity_gemini_dir": os.environ.get("ANTIGRAVITY_GEMINI_DIR"),
    "api_key": os.environ.get("GEMINI_API_KEY"),
    "adc": os.environ.get("AGY_ADC_AUTH"),
    "token": token,
    "args": arguments,
    "log_file": log_path,
    "foreground": foreground,
    "echo": echo,
    "phase": "session" if log_path is not None else ("login" if not arguments else "run"),
    "started_at": time.monotonic(),
}
with open(os.environ["PROFILE_FIXTURE_LOG"], "a") as stream:
    stream.write(json.dumps(event) + "\n")
print(token, flush=True)
if os.environ.get("PROFILE_FIXTURE_LIVE_EVENTS"):
    import subprocess
    events = json.loads(os.environ["PROFILE_FIXTURE_LIVE_EVENTS"])
    marker = Path(os.environ["PROFILE_FIXTURE_LIVE_MARKER"])
    for index, payload in enumerate(events):
        if "quota" in payload:
            buckets = [{"id": key, **value} for key, value in payload["quota"].items()]
            usage_path.write_text(json.dumps({"status": "SUCCESS", "command": {"name": "usage", "data": {"groups": [{"buckets": buckets}]}}}))
        result = subprocess.run(settings["statusLine"]["command"], shell=True,
                                input=json.dumps(payload), text=True, capture_output=True)
        marker.with_suffix(".callback").write_text(json.dumps({"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}))
        marker.write_text(str(index))
        limit = time.monotonic() + 10
        while not Path(str(marker) + ".continue." + str(index)).exists():
            if time.monotonic() > limit:
                raise SystemExit(29)
            time.sleep(0.02)
if os.environ.get("PROFILE_FIXTURE_SESSION_SIGNAL"):
    os.kill(os.getpid(), int(os.environ["PROFILE_FIXTURE_SESSION_SIGNAL"]))
if is_rate_limited:
    time.sleep(3.0)
if finish_marker is not None:
    finish_marker.write_text(str(time.monotonic()))
if is_rate_limited:
    raise SystemExit(1)
"""
        self.fake_agy.write_text(fake_source)
        self.fake_agy.chmod(0o700)
        self.log = self.root / "agy-events.jsonl"

    def clean_environment(self):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root / "parent-home"),
            "TMPDIR": str(self.root),
            "LANG": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SAGY_PROFILE_ROOT": str(self.profile_root),
            "AGY_BIN": str(self.fake_agy),
            "PROFILE_FIXTURE_LOG": str(self.log),
            "PROFILE_FIXTURE_USAGE_LOG": str(self.root / "usage-events.jsonl"),
            # These parent credentials must never reach the child process.
            "GEMINI_API_KEY": "parent-secret",
            "AGY_ADC_AUTH": "true",
            "GEMINI_HOME": str(self.root / "wrong-gemini"),
            "ANTIGRAVITY_CONFIG_DIR": str(self.root / "wrong-antigravity"),
        }
        return env

    def invoke(
        self, *arguments, expected=0, fixture_token=None, fixture_fail=False,
        fixture_usage=None, shortcut=False, check_pin=False, controlling_tty=False,
        fixture_session_signal=None, fixture_wait_probe=None,
    ):
        env = self.clean_environment()
        if fixture_token is not None:
            env["PROFILE_FIXTURE_TOKEN"] = fixture_token
        if fixture_fail:
            env["PROFILE_FIXTURE_FAIL"] = "1"
        if fixture_usage is not None:
            env["PROFILE_FIXTURE_USAGE"] = json.dumps(fixture_usage)
        if fixture_session_signal is not None:
            env["PROFILE_FIXTURE_SESSION_SIGNAL"] = str(int(fixture_session_signal))
        if fixture_wait_probe is not None:
            env["PROFILE_FIXTURE_WAIT_FOR_SIGNAL"] = str(fixture_wait_probe)
        env["SAGY_FIXTURE_ARGS"] = json.dumps(arguments)
        if shortcut:
            env["SAGY_FIXTURE_SHORTCUT"] = "1"
        if check_pin:
            env["SAGY_FIXTURE_CHECK_PIN"] = "1"
        if controlling_tty:
            env["PROFILE_FIXTURE_CONTROLLING_TTY"] = "1"

        def acquire_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        master, slave = pty.openpty()
        try:
            result = subprocess.run(
                [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"],
                cwd=self.root, env=env, stdin=slave, start_new_session=not controlling_tty,
                preexec_fn=acquire_terminal if controlling_tty else None,
                capture_output=True, text=True, timeout=20,
            )
        finally:
            os.close(slave)
            os.close(master)
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        return result

    def read_events(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def session_events(self):
        return [event for event in self.read_events() if event.get("phase") == "session"]

    def sync_invoke(self, *arguments, root=None, key="native-profile-fixture-key", expected=0, pool_repo=None):
        env = self.clean_environment()
        env["SAGY_FIXTURE_ARGS"] = json.dumps(arguments)
        if root is not None:
            env["SAGY_PROFILE_ROOT"] = str(root)
        if key is not None:
            env["SAGY_POOL_KEY"] = key
        if pool_repo is not None:
            env["SAGY_POOL_REPO"] = str(pool_repo)
        result = subprocess.run(
            [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        return result

    def sync_remote(self):
        path = self.root / "native-pool.git"
        subprocess.run(["git", "init", "--bare", str(path)], check=True, capture_output=True)
        return path

    def imported_token(self, root, name):
        state = json.loads((root / "state.json").read_text())
        directory = state.get("directories", {}).get(name, name)
        return root / "profiles" / directory / "home/.gemini/antigravity-cli/antigravity-oauth-token"

    def test_native_sync_roundtrip_preserves_logins_and_encrypts_only_bundle(self):
        remote = self.sync_remote()
        self.add_quota_profile("alice@example.com", "alice-sync-fixture", gemini=0.8)
        self.add_quota_profile("beta", "beta-sync-fixture", gemini=0.7)
        self.sync_invoke("push", str(remote))
        encrypted = subprocess.run(
            ["git", "--git-dir", str(remote), "show", "HEAD:.sagy-native-profiles/bundle.enc.json"],
            check=True, capture_output=True,
        ).stdout
        self.assertNotIn(b"alice-sync-fixture", encrypted)
        self.assertNotIn(b"alice@example.com", encrypted)
        files = subprocess.run(["git", "--git-dir", str(remote), "ls-tree", "--name-only", "-r", "HEAD"],
                               check=True, capture_output=True, text=True).stdout.splitlines()
        self.assertEqual(files, [".sagy-native-profiles/bundle.enc.json"])
        target = self.root / "restored"
        self.sync_invoke("pull", str(remote), root=target)
        credential = self.imported_token(target, "alice@example.com")
        self.assertEqual(json.loads(credential.read_text())["token"]["refresh_token"], "alice-sync-fixture")
        self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
        before = credential.read_bytes()
        result = self.sync_invoke("pull", root=target)
        self.assertIn("kept 2 existing", result.stderr)
        self.assertEqual(credential.read_bytes(), before)
        self.sync_invoke("run", "alice@example.com", "--version", root=target)
        self.assertEqual(self.read_events()[-1]["token"], "alice-sync-fixture")
        head = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "HEAD"], check=True,
                              capture_output=True, text=True).stdout
        self.sync_invoke("push")
        self.assertEqual(subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "HEAD"], check=True,
                                       capture_output=True, text=True).stdout, head)

    def test_native_sync_push_preserves_remote_only_accounts_and_rejects_conflicting_logins(self):
        remote = self.sync_remote()
        self.add_quota_profile("alpha", "alpha-sync-fixture", gemini=0.8)
        self.add_quota_profile("beta", "beta-sync-fixture", gemini=0.8)
        self.sync_invoke("push", str(remote))
        state_path = self.profile_root / "state.json"
        state = json.loads(state_path.read_text())
        state["profiles"].remove("beta")
        state_path.write_text(json.dumps(state))
        self.sync_invoke("push")
        target = self.root / "union"
        self.sync_invoke("pull", str(remote), root=target)
        self.assertEqual(set(json.loads((target / "state.json").read_text())["profiles"]), {"alpha", "beta"})
        credential = self.imported_token(self.profile_root, "alpha")
        credential.write_text(json.dumps({"refresh_token": "different-login-fixture"}))
        before = subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True).stdout
        result = self.sync_invoke("push", expected=1)
        self.assertIn("different saved login", result.stderr)
        self.assertEqual(subprocess.run(["git", "--git-dir", str(remote), "rev-parse", "HEAD"], check=True,
                                       capture_output=True, text=True).stdout, before)
        # 同名本地账号由 pull 保留，即使远端保存的是另一份授权。
        state["profiles"].append("beta")
        state_path.write_text(json.dumps(state))
        self.sync_invoke("pull")
        self.assertEqual(json.loads(credential.read_text())["refresh_token"], "different-login-fixture")

    def test_native_sync_busy_key_and_missing_bundle_fail_without_losing_profiles(self):
        remote = self.sync_remote()
        self.add_quota_profile("alpha", "alpha-sync-fixture", gemini=0.8)
        original = (self.profile_root / "state.json").read_bytes()
        with (self.profile_root / "profiles/alpha/.lock").open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.assertIn("busy", self.sync_invoke("push", str(remote), expected=1).stderr)
        self.sync_invoke("push", str(remote), key=None, expected=1)
        self.sync_invoke("push", str(remote))
        target = self.root / "wrong-key"
        self.sync_invoke("pull", str(remote), root=target, key="wrong-fixture-key", expected=1)
        self.assertFalse((target / "state.json").exists())
        self.assertEqual((self.profile_root / "state.json").read_bytes(), original)
        self.sync_invoke("pull", "--path", "../escape", str(remote), expected=1)
        self.sync_invoke("pull", str(remote), root=self.root / "missing", expected=0)
        other = self.root / "empty-pool.git"
        subprocess.run(["git", "init", "--bare", str(other)], check=True, capture_output=True)
        result = self.sync_invoke("pull", str(other), root=self.root / "empty", expected=1)
        self.assertIn("No native profile bundle", result.stderr)
        self.assertFalse((self.root / "empty/state.json").exists())

    def test_native_sync_recovers_only_manifest_directories_and_remembers_environment_repo(self):
        remote = self.sync_remote()
        self.add_quota_profile("alpha", "alpha-sync-fixture", gemini=0.8)
        self.sync_invoke("push", pool_repo=remote)
        # 显式地址会被保存，后续无需重复提供。
        self.sync_invoke("push", str(remote))
        self.sync_invoke("push")
        target = self.root / "recovery"
        self.sync_invoke("pull", str(remote), root=target)
        state = json.loads((target / "state.json").read_text())
        registered = state["directories"]["alpha"]
        orphan_id = "123456781234423492341234567890ab"
        orphan = target / "profiles" / ("sync_" + orphan_id)
        orphan.mkdir(mode=0o700)
        stage = target / (".sync-stage_" + orphan_id)
        stage.mkdir(mode=0o700)
        unrelated = target / "profiles/sync_user-owned"
        unrelated.mkdir(mode=0o700)
        manifest = target / ".sync-import.json"
        manifest.write_text(json.dumps({"version": 1, "slots": [
            {"name": "alpha", "directory": registered},
            {"name": "orphan", "directory": "sync_" + orphan_id},
        ]}))
        manifest.chmod(0o600)
        self.sync_invoke("pull", root=target)
        self.assertFalse(manifest.exists())
        self.assertFalse(orphan.exists())
        self.assertFalse(stage.exists())
        self.assertTrue(unrelated.is_dir())
        self.assertTrue((target / "profiles" / registered).is_dir())

    def test_each_profile_keeps_distinct_login_and_auto_rotates_across_processes(self):
        self.invoke("login", "alpha", fixture_token="account-alpha")
        self.invoke("login", "beta", fixture_token="account-beta")

        for expected_account in ("account-alpha", "account-beta", "account-alpha"):
            self.invoke("auto", "say", "hello")
            self.assertEqual(self.session_events()[-1]["token"], expected_account)

        state = json.loads((self.profile_root / "state.json").read_text())
        self.assertEqual(state["profiles"], ["alpha", "beta"])
        self.assertEqual(state["last_selected"], "alpha")

        events = self.read_events()
        self.assertEqual([event["token"] for event in self.session_events()], [
            "account-alpha",
            "account-beta",
            "account-alpha",
        ])
        self.assertNotEqual(events[0]["home"], events[1]["home"])
        for event in events:
            self.assertTrue(Path(event["home"]).resolve().is_relative_to(self.profile_root.resolve()))
            self.assertNotEqual(event["gemini_home"], str(self.root / "wrong-gemini"))
            self.assertNotEqual(
                event["antigravity_config_dir"],
                str(self.root / "wrong-antigravity"),
            )
            self.assertIsNone(event["api_key"])
            self.assertIsNone(event["adc"])
            self.assertIsNone(event["antigravity_gemini_dir"])
        for event in self.session_events():
            self.assertEqual(event["args"][-2:], ["say", "hello"])

    def test_failed_login_does_not_register_profile(self):
        self.invoke("login", "broken", expected=17, fixture_token="stale-fixture", fixture_fail=True)
        state_path = self.profile_root / "state.json"
        if state_path.exists():
            self.assertEqual(json.loads(state_path.read_text())["profiles"], [])

    def test_child_cannot_read_sibling_credential_or_registry(self):
        self.invoke("login", "alpha", fixture_token="alpha-fixture")
        self.invoke("login", "beta", fixture_token="beta-fixture")
        other_file = Path(self.read_events()[-1]["home"]) / ".gemini/antigravity-cli/antigravity-oauth-token"
        for path in (other_file, self.profile_root / "state.json"):
            self.invoke("run", "alpha", "probe-read", str(path), expected=23)

    @staticmethod
    def usage_document(gemini=None, third_party=None, status="SUCCESS", reverse=False):
        def model_group(model, remaining):
            if remaining is None:
                return {"id": model, "buckets": []}
            short = "gemini" if model == "gemini" else "3p"
            hourly, weekly = remaining if isinstance(remaining, tuple) else (remaining, remaining)
            buckets = [
                {"id": short + "-5h", "remaining_fraction": hourly},
                {"id": short + "-weekly", "remaining_fraction": weekly},
            ]
            if reverse:
                buckets.reverse()
            return {"id": model, "buckets": buckets}

        return {
            "status": status,
            "command": {
                "name": "usage",
                "data": {
                    "groups": [
                        model_group("gemini", gemini),
                        model_group("3p", third_party),
                    ]
                },
            },
        }

    def add_quota_profile(
        self, name, token, gemini=None, third_party=None, status="SUCCESS",
        reverse=False, rate_limited=False,
    ):
        self.invoke(
            "login",
            name,
            fixture_token=token,
            fixture_usage=self.usage_document(gemini, third_party, status, reverse),
        )
        home = Path(self.read_events()[-1]["home"])
        if rate_limited:
            marker = home / ".gemini/antigravity-cli/profile-test-429"
            marker.write_text("1")
            marker.chmod(0o600)
        return home

    def test_list_displays_both_gemini_windows_in_limiting_quota_order(self):
        self.add_quota_profile("alpha", "alpha", gemini=(0.9, 0.3))
        self.add_quota_profile("beta", "beta", gemini=(0.7, 0.8))
        self.add_quota_profile("unknown", "unknown")
        lines = self.invoke("list").stderr.splitlines()
        data = [[cell.strip() for cell in line.split("│")[1:-1]] for line in lines if line.startswith("│")]
        self.assertEqual(data[0], ["#", "Profile", "Status", "5h", "weekly", "Quota age"])
        self.assertEqual([row[:5] for row in data[1:]], [
            ["1", "beta", "ready", "70.00%", "80.00%"],
            ["2", "alpha", "ready", "90.00%", "30.00%"],
            ["3", "unknown", "ready", "--", "--"],
        ])

    def quota_snapshot(self):
        return json.loads((self.profile_root / "quota.json").read_text())["profiles"]

    def test_list_reads_snapshot_without_looking_up_agy(self):
        self.add_quota_profile("alpha", "alpha", gemini=(0.9, 0.3))
        probe_log = self.root / "usage-events.jsonl"
        before = probe_log.read_bytes()
        self.fake_agy.unlink()
        result = self.invoke("list", check_pin=True)
        self.assertIn("90.00%", result.stderr)
        self.assertIn("30.00%", result.stderr)
        self.assertIn("Quota age", result.stderr)
        self.assertEqual(probe_log.read_bytes(), before)

    def test_list_missing_and_corrupt_snapshot_remain_local_then_refresh_recovers(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8)
        path = self.profile_root / "quota.json"
        before = (self.root / "usage-events.jsonl").read_bytes()
        path.unlink()
        result = self.invoke("list", check_pin=True)
        self.assertNotIn("80.00%", result.stderr)
        self.assertNotIn("Cached Gemini quotas", result.stderr)
        path.write_text("invalid JSON")
        path.chmod(0o600)
        result = self.invoke("list", check_pin=True)
        self.assertIn("snapshot is invalid", result.stderr)
        self.assertEqual((self.root / "usage-events.jsonl").read_bytes(), before)
        self.invoke("refresh")
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.8, 0.8])

    def test_exit_hook_refreshes_only_selected_profile_and_failure_keeps_old_sample(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8)
        self.add_quota_profile("beta", "beta", gemini=0.6)
        beta = self.quota_snapshot()["beta"]
        self.invoke("run", "alpha", "hello", fixture_usage=self.usage_document(gemini=0.4))
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.4, 0.4])
        self.assertEqual(self.quota_snapshot()["beta"], beta)
        old = self.quota_snapshot()["alpha"]
        result = self.invoke("refresh", "alpha", fixture_usage=self.usage_document(status="ERROR"))
        current = self.quota_snapshot()["alpha"]
        self.assertEqual(current["windows"], old["windows"])
        self.assertEqual(current["sampled_at"], old["sampled_at"])
        self.assertEqual(current["result"], "unavailable")
        self.assertIn("unavailable", result.stderr)
        self.assertEqual(self.quota_snapshot()["beta"], beta)
        # 缓存写入失败不能把会话成功改成失败；显式 refresh 则必须报告存储失败。
        quota_path = self.profile_root / "quota.json"
        quota_path.unlink()
        quota_path.symlink_to(self.root / "unrelated")
        self.invoke("run", "alpha", "hello")
        self.invoke("refresh", "alpha", expected=1)
        self.assertFalse((self.root / "unrelated").exists())

    def test_signal_exit_skips_hook_and_third_party_selection_does_not_pollute_gemini_cache(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8, third_party=0.6)
        before = (self.root / "usage-events.jsonl").read_bytes()
        self.invoke("run", "alpha", "hello", expected=143, fixture_session_signal=signal.SIGTERM,
                    fixture_usage=self.usage_document(gemini=0.2, third_party=0.7))
        self.assertEqual((self.root / "usage-events.jsonl").read_bytes(), before)
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.8, 0.8])
        self.invoke("auto", "--model", "claude-4", expected=143, fixture_session_signal=signal.SIGTERM)
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.8, 0.8])

    def test_exit_hook_timeout_reaps_probe_and_preserves_session_exit_code(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8)
        marker = self.root / "timed-out-probe"
        started = time.monotonic()
        self.invoke("run", "alpha", "hello", fixture_wait_probe=marker)
        self.assertLess(time.monotonic() - started, 11)
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.8, 0.8])
        self.assertEqual(self.quota_snapshot()["alpha"]["result"], "unavailable")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)

    def test_auto_still_queries_live_quota_instead_of_cached_ranking(self):
        alpha = self.add_quota_profile("alpha", "alpha", gemini=0.9)
        beta = self.add_quota_profile("beta", "beta", gemini=0.4)
        (alpha / ".gemini/antigravity-cli/profile-test-usage.json").write_text(json.dumps(self.usage_document(gemini=0.1)))
        (beta / ".gemini/antigravity-cli/profile-test-usage.json").write_text(json.dumps(self.usage_document(gemini=0.7)))
        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "beta")
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.1, 0.1])
        self.assertEqual(self.quota_snapshot()["beta"]["windows"], [0.7, 0.7])

    def test_busy_refresh_preserves_last_values_and_directory_mismatch_hides_snapshot(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8)
        with (self.profile_root / "profiles/alpha/.lock").open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            result = self.invoke("refresh", "alpha")
            self.assertIn("busy", result.stderr)
            self.assertIn("80.00%", result.stderr)
        self.assertEqual(self.quota_snapshot()["alpha"]["windows"], [0.8, 0.8])
        path = self.profile_root / "quota.json"
        document = json.loads(path.read_text())
        document["profiles"]["alpha"]["directory"] = "different"
        path.write_text(json.dumps(document))
        self.assertNotIn("80.00%", self.invoke("list").stderr)

    def test_failed_relogin_clears_old_identity_snapshot(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8)
        self.invoke("login", "alpha", expected=17, fixture_fail=True)
        entry = self.quota_snapshot()["alpha"]
        self.assertEqual(entry["windows"], [None, None])
        self.assertIsNone(entry["sampled_at"])
        self.assertNotIn("80.00%", self.invoke("list").stderr)

    def test_quota_probes_detach_from_the_interactive_controlling_terminal(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9)
        usage_log = self.root / "usage-events.jsonl"
        baseline = len(usage_log.read_text().splitlines())
        self.invoke("auto", controlling_tty=True)
        self.assertTrue(self.session_events()[-1]["foreground"])
        rows = [json.loads(line) for line in usage_log.read_text().splitlines()][baseline:]
        self.assertGreaterEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["pid"], row["session_id"])
            self.assertFalse(row["controlling_tty"])

    def test_live_native_callbacks_refresh_snapshot_while_session_stays_open(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9)
        self.add_quota_profile("beta", "beta", gemini=0.95)
        baseline_usage = (self.root / "usage-events.jsonl").read_text()
        marker = self.root / "live-marker"
        env = self.clean_environment()
        payloads = [{
            "agent_state": "idle", "conversation_id": "fixture-conversation",
            "context_window": {"total_input_tokens": 10 + index, "total_output_tokens": 5 + index,
                               "remaining_percentage": 99},
            "quota": {"gemini-5h": {"remaining_fraction": short},
                      "gemini-weekly": {"remaining_fraction": weekly}},
            "email": "must-not-be-in-event@example.com", "profile": "beta", "root": str(self.root),
        } for index, (short, weekly) in enumerate([(0.8, 0.7), (0.6, 0.5)])]
        env.update(SAGY_FIXTURE_ARGS='["run", "alpha"]',
                   PROFILE_FIXTURE_LIVE_EVENTS=json.dumps(payloads),
                   PROFILE_FIXTURE_LIVE_MARKER=str(marker),
                   PROFILE_FIXTURE_FORBIDDEN_PROBE_READ=str(self.profile_root / "profiles/alpha/home/.gemini/antigravity-cli/antigravity-oauth-token"))
        command = [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"]
        with subprocess.Popen(command, cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                for index, expected in enumerate([("80.00%", "70.00%"), ("60.00%", "50.00%")]):
                    deadline = time.monotonic() + 8
                    shown = ""
                    while time.monotonic() < deadline:
                        self.assertIsNone(process.poll())
                        if marker.exists() and marker.read_text() == str(index):
                            shown = self.invoke("list").stderr
                            if all(value in shown for value in expected):
                                break
                        time.sleep(0.03)
                    self.assertTrue(all(value in shown for value in expected), shown)
                    self.assertIn("busy", shown)
                    self.assertIn("95.00%", shown)
                    usage_rows = [json.loads(line) for line in (self.root / "usage-events.jsonl").read_text().splitlines()]
                    new_rows = usage_rows[len(baseline_usage.splitlines()):]
                    self.assertEqual(len(new_rows), index + 1)
                    self.assertTrue(all(".sagy-quota-probe-" in row["home"] for row in new_rows))
                    self.assertTrue(all(row["forbidden_read_allowed"] is False for row in new_rows))
                    self.assertTrue(all(row["home"] != str(self.profile_root / "profiles/alpha/home") for row in new_rows))
                    bridge_files = list((self.profile_root / "profiles/alpha/home").glob(".sagy-statusline-*/event.json"))
                    self.assertEqual(len(bridge_files), 1)
                    raw = bridge_files[0].read_text()
                    self.assertNotIn("email", raw)
                    self.assertNotIn("must-not-be-in-event", raw)
                    Path(str(marker) + ".continue." + str(index)).touch()
                self.assertEqual(process.wait(timeout=5), 0)
                self.assertEqual(list((self.profile_root / "profiles/alpha/home").glob(".sagy-statusline-*")), [])
                self.assertEqual(list((self.profile_root / "profiles").glob(".sagy-quota-probe-*")), [])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_live_probe_is_cancelled_and_private_copy_removed_when_session_is_signalled(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9)
        marker, probe_pid = self.root / "cancel-marker", self.root / "live-probe-pid"
        payload = {"agent_state": "idle", "conversation_id": "cancel-turn",
                   "context_window": {"total_input_tokens": 1, "total_output_tokens": 1}}
        env = self.clean_environment()
        env.update(SAGY_FIXTURE_ARGS='["run", "alpha"]', PROFILE_FIXTURE_LIVE_EVENTS=json.dumps([payload]),
                   PROFILE_FIXTURE_LIVE_MARKER=str(marker), PROFILE_FIXTURE_WAIT_FOR_SIGNAL=str(probe_pid),
                   PROFILE_FIXTURE_SESSION_SIGNAL=str(int(signal.SIGTERM)))
        command = [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"]
        with subprocess.Popen(command, cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 5
                while not probe_pid.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(probe_pid.exists())
                pid = int(probe_pid.read_text())
                self.assertEqual(len(list((self.profile_root / "profiles").glob(".sagy-quota-probe-*"))), 1)
                started = time.monotonic()
                Path(str(marker) + ".continue.0").touch()
                self.assertEqual(process.wait(timeout=2), 143)
                self.assertLess(time.monotonic() - started, 2)
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
                self.assertEqual(list((self.profile_root / "profiles").glob(".sagy-quota-probe-*")), [])
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()

    def test_rapid_turn_events_coalesce_while_one_isolated_probe_is_running(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9)
        marker = self.root / "coalesce-marker"
        payloads = [{"agent_state": "idle", "conversation_id": "coalesce-turn",
                     "context_window": {"total_input_tokens": 10 + index, "total_output_tokens": 5 + index}}
                    for index in range(3)]
        env = self.clean_environment()
        baseline = len((self.root / "usage-events.jsonl").read_text().splitlines())
        env.update(SAGY_FIXTURE_ARGS='["run", "alpha"]', PROFILE_FIXTURE_LIVE_EVENTS=json.dumps(payloads),
                   PROFILE_FIXTURE_LIVE_MARKER=str(marker), PROFILE_FIXTURE_PROBE_DELAY="2")
        command = [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"]
        with subprocess.Popen(command, cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                for index in range(3):
                    deadline = time.monotonic() + 5
                    while (not marker.exists() or marker.read_text() != str(index)) and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertEqual(marker.read_text(), str(index))
                    if index < 2:
                        time.sleep(0.15)
                        Path(str(marker) + ".continue." + str(index)).touch()
                deadline = time.monotonic() + 6
                while time.monotonic() < deadline:
                    rows = [json.loads(line) for line in (self.root / "usage-events.jsonl").read_text().splitlines()][baseline:]
                    if len(rows) == 2 and not list((self.profile_root / "profiles").glob(".sagy-quota-probe-*")):
                        break
                    time.sleep(0.03)
                self.assertEqual(len(rows), 2)
                self.assertTrue(all(".sagy-quota-probe-" in row["home"] for row in rows))
                self.assertIsNone(process.poll())
                self.assertEqual(list((self.profile_root / "profiles").glob(".sagy-quota-probe-*")), [])
                Path(str(marker) + ".continue.2").touch()
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()

    def test_live_callback_preserves_custom_statusline_input_output_and_settings(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9)
        home = self.profile_root / "profiles/alpha/home"
        received = home / "original-status-input.json"
        settings_path = home / ".gemini/antigravity-cli/settings.json"
        settings_raw = json.dumps({"statusLine": {"command": f"cat > '{received}'; printf CUSTOM_STATUS; exit 7",
                                                 "padding": 2, "stack_with_default": False}})
        settings_path.write_text(settings_raw)
        settings_path.chmod(0o600)
        marker = self.root / "custom-marker"
        payload = {"agent_state": "idle", "quota": {"gemini-5h": {"remaining_fraction": 0.42}}}
        env = self.clean_environment()
        env.update(SAGY_FIXTURE_ARGS='["run", "alpha"]', PROFILE_FIXTURE_LIVE_EVENTS=json.dumps([payload]),
                   PROFILE_FIXTURE_LIVE_MARKER=str(marker))
        command = [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"]
        with subprocess.Popen(command, cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 8
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.03)
                self.assertTrue(marker.exists())
                callback = json.loads(marker.with_suffix(".callback").read_text())
                self.assertEqual(callback["code"], 7, callback)
                self.assertTrue(callback["stdout"].endswith("CUSTOM_STATUS"), callback)
                self.assertEqual(json.loads(received.read_text()), payload)
                self.assertEqual(settings_path.read_text(), settings_raw)
                Path(str(marker) + ".continue.0").touch()
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()

    def test_auto_selects_highest_minimum_remaining_quota(self):
        self.add_quota_profile("alpha", "alpha", gemini=(0.9, 0.3), third_party=0.3)
        self.add_quota_profile("beta", "beta", gemini=0.7, third_party=0.6)

        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "beta")

    def test_model_selection_reverses_account_ranking(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8, third_party=0.2)
        self.add_quota_profile("beta", "beta", gemini=0.4, third_party=0.7)

        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "alpha")
        self.invoke("auto", "--model", "claude-4")
        self.assertEqual(self.session_events()[-1]["token"], "beta")

    def test_equal_quota_profiles_rotate_instead_of_starving_one_account(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.8, third_party=0.6)
        self.add_quota_profile("beta", "beta", gemini=0.8, third_party=0.6)

        for _ in range(3):
            self.invoke("auto")
        self.assertEqual(
            [event["token"] for event in self.session_events()],
            ["alpha", "beta", "alpha"],
        )

    def test_unknown_quota_is_fallback_when_known_quota_is_zero(self):
        self.add_quota_profile("alpha", "alpha")
        self.add_quota_profile("beta", "beta", gemini=0.0, third_party=0.0)

        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "alpha")

    def test_interrupted_refresh_reaps_inflight_probe(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9)
        marker = self.root / "probe-pid"
        env = self.clean_environment()
        env.update(SAGY_FIXTURE_ARGS='["refresh"]', PROFILE_FIXTURE_WAIT_FOR_SIGNAL=str(marker))
        command = [TEST_EXE, "--exact", "profile::tests::fixture_dispatch", "--ignored", "--nocapture"]
        with subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            try:
                deadline = time.monotonic() + 8
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.03)
                self.assertTrue(marker.exists())
                process.send_signal(signal.SIGINT)
                self.assertEqual(process.wait(timeout=3), 130)
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(marker.read_text()), 0)
            finally:
                if process.poll() is None:
                    process.kill()

    def test_all_zero_quota_starts_no_session(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.0)
        self.invoke("auto", expected=1)
        self.assertEqual(self.session_events(), [])

    def test_exhausted_window_with_unknown_weekly_quota_is_skipped(self):
        self.add_quota_profile("alpha", "alpha", gemini=(0.0, None))
        self.invoke("auto", expected=1)
        self.assertEqual(self.session_events(), [])

    def test_429_without_a_spare_leaves_current_session_running(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9, rate_limited=True)
        self.invoke("auto", expected=1)
        events = self.session_events()
        self.assertEqual([event["token"] for event in events], ["alpha"])
        self.assertTrue(Path(events[0]["log_file"] + ".natural-finish").exists())

    def test_auto_excludes_weekly_below_five_percent_even_with_unknown_short_window(self):
        home = self.add_quota_profile("alpha", "alpha", gemini=(1.0, 0.049999))
        self.invoke("auto", expected=1)
        usage = home / ".gemini/antigravity-cli/profile-test-usage.json"
        usage.write_text(json.dumps(self.usage_document(gemini=(None, 0.04))))
        self.invoke("auto", expected=1)
        self.assertEqual(self.session_events(), [])
        usage.write_text(json.dumps(self.usage_document(gemini=(1.0, 0.05))))
        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "alpha")

    def test_auto_weekly_floor_uses_selected_model_group(self):
        self.add_quota_profile("alpha", "alpha", gemini=(1.0, 0.04), third_party=(1.0, 0.9))
        self.add_quota_profile("beta", "beta", gemini=(0.02, 0.05), third_party=(1.0, 0.04))
        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "beta")
        self.invoke("auto", "--model", "claude-4")
        self.assertEqual(self.session_events()[-1]["token"], "alpha")

    def test_429_does_not_switch_to_a_profile_below_weekly_floor(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.9, rate_limited=True)
        self.add_quota_profile("beta", "beta", gemini=(1.0, 0.04))
        self.invoke("auto", expected=1, controlling_tty=True)
        events = self.session_events()
        self.assertEqual([event["token"] for event in events], ["alpha"])
        self.assertTrue(Path(events[0]["log_file"] + ".natural-finish").exists())

    def test_use_number_matches_cached_list_order_including_low_quota_and_busy_accounts(self):
        self.add_quota_profile("alpha", "alpha", gemini=(1.0, 0.01))
        self.add_quota_profile("beta", "beta", gemini=0.8)
        listed = self.invoke("list").stderr
        self.assertLess(listed.index("beta"), listed.index("alpha"))
        self.invoke("use", "1", shortcut=True)
        self.assertEqual(self.read_events()[-1]["token"], "beta")
        self.invoke("use", "2", "-p", "literal prompt", shortcut=True)
        self.assertEqual(self.read_events()[-1]["token"], "alpha")
        self.assertEqual(self.read_events()[-1]["args"][-2:], ["-p", "literal prompt"])
        count = len(self.read_events())
        for index in ["0", "3", "999999999999999999999999999999999999"]:
            self.invoke("use", index, expected=1)
        with (self.profile_root / "profiles/beta/.lock").open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.invoke("use", "1", expected=1)
        self.assertEqual(len(self.read_events()), count)
        # 没有快照时仍与 list 保持相同的注册顺序。
        (self.profile_root / "quota.json").unlink()
        self.invoke("use", "1")
        self.assertEqual(self.read_events()[-1]["token"], "alpha")

    def test_use_number_rejects_empty_list_and_takes_precedence_over_numeric_labels(self):
        self.invoke("use", "1", expected=1)
        self.assertEqual(self.read_events(), [])
        self.add_quota_profile("1", "numeric-label", gemini=0.1)
        self.add_quota_profile("beta", "beta", gemini=0.9)
        self.invoke("use", "1")
        self.assertEqual(self.read_events()[-1]["token"], "beta")
        self.invoke("run", "1")
        self.assertEqual(self.read_events()[-1]["token"], "numeric-label")

    def test_use_opens_named_account_with_defaults_and_preserves_arguments(self):
        self.add_quota_profile("alice@example.com", "alice", gemini=(1.0, 0.01))
        self.add_quota_profile("beta", "beta", gemini=0.9)
        self.invoke("use", "Alice@Example.COM", shortcut=True)
        event = self.read_events()[-1]
        self.assertEqual(event["token"], "alice")
        defaults = ["--model", "gemini-3.8-flash-high", "--dangerously-skip-permissions"]
        self.assertEqual(event["args"], defaults)
        self.invoke("use", "alice@example.com", "--", "-p", "literal prompt", shortcut=True)
        self.assertEqual(self.read_events()[-1]["args"], defaults + ["-p", "literal prompt"])
        count = len(self.read_events())
        self.invoke("use", "missing@example.com", expected=1)
        self.invoke("use", "alice@example.com", "--gemini-dir=/tmp/unsafe", expected=1)
        with (self.profile_root / "profiles/alice@example.com/.lock").open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.invoke("use", "alice@example.com", expected=1)
        self.assertEqual(len(self.read_events()), count)

    def test_zero_remaining_quota_is_skipped_for_a_positive_profile(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.0, third_party=0.0)
        self.add_quota_profile("beta", "beta", gemini=0.1, third_party=0.2)

        self.invoke("auto")
        self.assertEqual(self.session_events()[-1]["token"], "beta")

    def test_real_429_log_switches_bare_auto_and_persists_cooldown_once(self):
        alpha_home = self.add_quota_profile(
            "alpha", "alpha", gemini=0.95, third_party=0.9, rate_limited=True,
        )
        self.add_quota_profile("beta", "beta", gemini=0.8, third_party=0.7)
        before = time.time()

        self.invoke(shortcut=True, controlling_tty=True)
        events = self.session_events()
        self.assertEqual([event["token"] for event in events], ["alpha", "beta"])
        self.assertTrue(all(event["foreground"] and event["echo"] for event in events))
        first_session = events[0]
        self.assertIsNotNone(first_session["log_file"])
        self.assertFalse(Path(first_session["log_file"]).exists())
        self.assertFalse(Path(first_session["log_file"] + ".natural-finish").exists())

        state = json.loads((self.profile_root / "state.json").read_text())
        cooldown_until = state["cooldowns"]["alpha"]
        after = time.time()
        self.assertGreater(cooldown_until, before)
        self.assertLessEqual(cooldown_until, after + 300.0)
        self.assertGreaterEqual(cooldown_until, before + 299.0)

        self.invoke("auto")
        self.assertEqual(
            [event["token"] for event in self.session_events()],
            ["alpha", "beta", "beta"],
        )
        self.assertTrue(alpha_home.exists())

    def test_explicit_print_prompt_is_not_replayed_after_429(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.95, third_party=0.9, rate_limited=True)
        self.add_quota_profile("beta", "beta", gemini=0.8, third_party=0.7)

        result = self.invoke("-p", "change production config", expected=1, shortcut=True)
        events = self.session_events()
        self.assertEqual([event["token"] for event in events], ["alpha"])
        self.assertEqual(events[-1]["args"][-5:], ["--model", "gemini-3.8-flash-high", "--dangerously-skip-permissions", "-p", "change production config"])
        state = json.loads((self.profile_root / "state.json").read_text())
        self.assertIn("alpha", state["cooldowns"])

    def test_bare_text_prompt_is_not_replayed_after_429(self):
        self.add_quota_profile("alpha", "alpha", gemini=0.95, third_party=0.9, rate_limited=True)
        self.add_quota_profile("beta", "beta", gemini=0.8, third_party=0.7)

        self.invoke("auto", "change", "production", "config", expected=1)
        events = self.session_events()
        self.assertEqual([event["token"] for event in events], ["alpha"])
        self.assertEqual(events[-1]["args"][-3:], ["change", "production", "config"])
        state = json.loads((self.profile_root / "state.json").read_text())
        self.assertIn("alpha", state["cooldowns"])

    def test_auto_skips_a_busy_profile(self):
        import fcntl
        self.invoke("login", "alpha", fixture_token="alpha-fixture")
        self.invoke("login", "beta", fixture_token="beta-fixture")
        with (self.profile_root / "profiles/alpha/.lock").open("r+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.invoke("auto")
            self.assertEqual(self.session_events()[-1]["token"], "beta-fixture")

    def test_zero_exit_without_refresh_token_does_not_enroll(self):
        self.invoke("login", "incomplete", expected=1)
        self.assertFalse((self.profile_root / "state.json").exists())

    def test_unknown_binary_does_not_start(self):
        result = self.invoke("login", "alpha", expected=1, check_pin=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has not been verified", result.stderr)
        self.assertFalse(self.log.exists())

    def test_profile_name_validation_rejects_path_traversal(self):
        result = self.invoke("login", "../outside", expected=1)
        self.assertFalse((self.root / "outside").exists())
        self.assertFalse((self.profile_root / "profiles" / "outside").exists())
        self.assertTrue(result.stderr)


    def test_email_identifiers_normalize_case_and_preserve_dots_and_plus(self):
        email = "alice+tag.first@example.com"
        self.invoke("login", "Alice+Tag.First@Example.COM", fixture_token="email-account")
        state = json.loads((self.profile_root / "state.json").read_text())
        self.assertEqual(state["profiles"], [email])
        storage_label = state.get("directories", {}).get(email, email)
        expected_home = self.profile_root / "profiles" / storage_label / "home"

        self.invoke("run", "ALICE+TAG.FIRST@EXAMPLE.COM", "say", "hello")
        self.invoke("auto", "say", "again")

        sessions = self.read_events()
        self.assertEqual([event["token"] for event in sessions], [
            "email-account",
            "email-account",
            "email-account",
        ])
        self.assertEqual(len({event["home"] for event in sessions}), 1)
        self.assertEqual(Path(sessions[0]["home"]).resolve(), expected_home.resolve())

    def test_email_directory_mapping_preserves_legacy_home_without_alias_access(self):
        email = "alice@example.com"
        legacy_label = "alpha"
        self.invoke("login", legacy_label, fixture_token="legacy-account")
        home = Path(self.read_events()[0]["home"])
        registry = self.profile_root / "state.json"
        state = json.loads(registry.read_text())
        state.update(profiles=[email], directories={email: legacy_label})
        registry.write_text(json.dumps(state))

        self.invoke("run", email, "say", "mapped")
        self.assertEqual(self.read_events()[-1]["token"], "legacy-account")
        self.invoke("auto", "say", "automatic")
        self.assertEqual(self.session_events()[-1]["token"], "legacy-account")

        original_token = (home / ".gemini/antigravity-cli/antigravity-oauth-token").read_bytes()
        event_count = len(self.read_events())
        self.invoke("run", legacy_label, "say", "must-not-open", expected=1)
        self.invoke("login", legacy_label, expected=1)
        self.assertEqual(len(self.read_events()), event_count)
        self.assertEqual(
            (home / ".gemini/antigravity-cli/antigravity-oauth-token").read_bytes(),
            original_token,
        )
        events = self.read_events()
        self.assertTrue(all(Path(event["home"]).resolve() == home.resolve() for event in events))

if __name__ == "__main__":
    unittest.main()
