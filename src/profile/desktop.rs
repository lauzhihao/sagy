//! 将已登录 profile 的凭据副本交给独立的 Antigravity 桌面实例。
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use sha2::{Digest, Sha256};

use super::{
    desktop_history, desktop_sync, observer, runtime, store,
    util::{bounded_read, shell_quote, write_stderr_line},
};
use crate::core::credential::StrictValue;

const MAX_TOKEN_BYTES: u64 = 1024 * 1024;
const TOKEN_SOURCE: &str = ".gemini/antigravity-cli/antigravity-oauth-token";
const TOKEN_TARGET: &str = ".gemini/jetski-standalone-oauth-token";
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const STOP_GRACE: Duration = Duration::from_secs(3);
const GROUP_SETTLE: Duration = Duration::from_millis(250);

fn resolve_binary() -> Result<runtime::Binary> {
    if let Some(path) = std::env::var_os("SAGY_DESKTOP_BIN") {
        return runtime::Binary::from_path(PathBuf::from(path)).context(
            "SAGY_DESKTOP_BIN must identify the absolute executable path of Antigravity App.",
        );
    }
    #[cfg(target_os = "macos")]
    {
        for path in [
            PathBuf::from("/Applications/Antigravity.app/Contents/MacOS/Antigravity"),
            store::real_home()?.join("Applications/Antigravity.app/Contents/MacOS/Antigravity"),
        ] {
            if let Ok(binary) = runtime::Binary::from_path(path) {
                return Ok(binary);
            }
        }
    }
    bail!(
        "Antigravity App was not found. Install the desktop app or set SAGY_DESKTOP_BIN to its absolute executable path."
    )
}

fn read_token(profile_home: &Path) -> Result<Vec<u8>> {
    for path in [
        profile_home.to_path_buf(),
        profile_home.join(".gemini"),
        profile_home.join(".gemini/antigravity-cli"),
    ] {
        store::check_private_dir(&path)?;
    }
    let file = store::open_private_file(&profile_home.join(TOKEN_SOURCE), false)?;
    let bytes = bounded_read(file, MAX_TOKEN_BYTES)
        .context("Could not read the selected profile credentials.")?;
    let StrictValue(document) = serde_json::from_slice::<StrictValue>(&bytes)
        .map_err(|_| anyhow!("The selected profile credentials are invalid."))?;
    let token = document.get("token").unwrap_or(&document);
    if !token
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
    {
        bail!("The selected profile has no resumable login. Run sagy login again.");
    }
    Ok(bytes)
}

fn check_replace_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            store::open_private_file(path, false)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Could not inspect a desktop profile file."),
    }
}

fn replace_private(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    check_replace_target(path)?;
    let directory = path
        .parent()
        .context("A desktop profile file has no parent.")?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    // 原子替换副本；不能与 CLI 凭据硬链接，否则桌面刷新会覆盖正在运行的 CLI。
    check_replace_target(path)?;
    temporary
        .persist(path)
        .context("Could not save a desktop profile file.")?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn shell_script(home: &Path) -> Result<Vec<u8>> {
    let mut script = String::from("#!/bin/sh\nunset BASH_ENV ENV ZDOTDIR PROMPT_COMMAND\n");
    for (key, path) in [
        ("HOME", home.to_path_buf()),
        ("XDG_CONFIG_HOME", home.join(".config")),
        ("XDG_DATA_HOME", home.join(".local/share")),
        ("XDG_CACHE_HOME", home.join(".cache")),
        ("SHELL", home.join(".desktop-shell")),
    ] {
        script.push_str(&format!(
            "export {key}={}\n",
            shell_quote(path.as_os_str())?
        ));
    }
    #[cfg(target_os = "macos")]
    script.push_str(&format!(
        "export CFFIXED_USER_HOME={}\n",
        shell_quote(home.as_os_str())?
    ));
    script.push_str("export SSH_CONNECTION='127.0.0.1 0 127.0.0.1 0'\nexec /bin/bash --noprofile --norc \"$@\"\n");
    Ok(script.into_bytes())
}

struct Prepared {
    home: PathBuf,
    user_data: PathBuf,
    baseline: [u8; 32],
    _lock: File,
}

fn prepare(root: &Path, profile_home: &Path) -> Result<Prepared> {
    prepare_with(root, profile_home, || desktop_history::initialize(root))
}

fn prepare_with(
    root: &Path,
    profile_home: &Path,
    initialize: impl FnOnce() -> Result<PathBuf>,
) -> Result<Prepared> {
    if !profile_home.is_absolute() {
        bail!("The selected profile home must be absolute.");
    }
    let profile = profile_home
        .parent()
        .context("The selected profile has no directory.")?;
    store::check_private_dir(profile)?;
    store::check_private_dir(root)?;
    let lock = store::open_private_file(&root.join(".desktop.lock"), true)?;
    match lock.try_lock_exclusive() {
        Ok(()) => (),
        Err(error)
            if error.kind() == fs2::lock_contended_error().kind()
                || error.kind() == io::ErrorKind::WouldBlock =>
        {
            bail!(
                "There is already a sagy desktop instance running. Quit it before switching accounts."
            );
        }
        Err(error) => return Err(error).context("Could not lock the desktop profile."),
    }
    let bytes = read_token(profile_home)?;
    let home = initialize()?;
    for path in [
        home.clone(),
        home.join(".gemini"),
        home.join(".config"),
        home.join(".local"),
        home.join(".local/share"),
        home.join(".cache"),
        home.join(".local/share/antigravity-desktop"),
    ] {
        store::ensure_private_dir(&path)?;
    }
    replace_private(&home.join(TOKEN_TARGET), &bytes, 0o600)?;
    replace_private(&home.join(".desktop-shell"), &shell_script(&home)?, 0o700)?;
    Ok(Prepared {
        user_data: home.join(".local/share/antigravity-desktop"),
        home,
        baseline: Sha256::digest(&bytes).into(),
        _lock: lock,
    })
}

fn desktop_command(binary: &runtime::Binary, prepared: &Prepared) -> Result<Command> {
    let mut command = runtime::desktop_command(binary, &prepared.home)?;
    // 桌面会重新读取 login shell 环境，私有 shim 防止真实 shell 配置将 HOME 改回去。
    command.env("SHELL", prepared.home.join(".desktop-shell"));
    #[cfg(target_os = "macos")]
    command.env("CFFIXED_USER_HOME", &prepared.home);
    for name in [
        "SAGY_DESKTOP_BIN",
        "DEV_URL",
        "CODEIUM_LANGUAGE_SERVER_BIN",
        "JETSKI_LS_PORT",
        "NODE_OPTIONS",
        "NODE_PATH",
        "ELECTRON_RUN_AS_NODE",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "SHELLOPTS",
        "BASHOPTS",
        "PROMPT_COMMAND",
    ] {
        command.env_remove(name);
    }
    let mut user_data = std::ffi::OsString::from("--user-data-dir=");
    user_data.push(&prepared.user_data);
    command.arg(user_data);
    // 认证失败时桌面日志可能含授权链接，默认不向终端或磁盘复制。
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.process_group(0);
    Ok(command)
}

fn signal_group(group: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    if unsafe { libc::kill(-group, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

fn group_exists(group: libc::pid_t) -> bool {
    (unsafe { libc::kill(-group, 0) }) == 0
        || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

fn settle_group(group: libc::pid_t) {
    let deadline = Instant::now() + GROUP_SETTLE;
    // SIGKILL 返回时后代还可能在退出；短时等待后再释放锁。kill(0) 也会看到
    // 等待系统收割的 zombie，因此这里只能有界等待，不能把“仍存在”当作仍在工作。
    while group_exists(group) && Instant::now() < deadline {
        thread::sleep(POLL_INTERVAL);
    }
}

struct DesktopProcess {
    child: Child,
    status: Option<ExitStatus>,
    cleaned: bool,
}

impl DesktopProcess {
    fn stop(&mut self, grace: Duration) -> Result<()> {
        let group = self.child.id() as libc::pid_t;
        let termination = signal_group(group, libc::SIGTERM);
        let deadline = Instant::now() + grace;
        let mut wait_error = None;
        loop {
            if self.status.is_none() {
                match self.child.try_wait() {
                    Ok(status) => self.status = status,
                    Err(error) => {
                        wait_error = Some(error);
                        break;
                    }
                }
            }
            if (self.status.is_some() && !group_exists(group)) || Instant::now() >= deadline {
                break;
            }
            thread::sleep(POLL_INTERVAL);
        }
        // 主窗口退出后 LS 仍可能在清理；结束本次启动的整个进程组后才释放 profile 锁。
        let force = signal_group(group, libc::SIGKILL);
        let waited = if self.status.is_none() {
            self.child.wait().map(|status| self.status = Some(status))
        } else {
            Ok(())
        };
        if force.is_ok() {
            settle_group(group);
        }
        self.cleaned = force.is_ok() && waited.is_ok();
        termination.context("Could not stop the Antigravity desktop process group.")?;
        force.context("Could not clean up the Antigravity desktop process group.")?;
        waited.context("Could not reap the Antigravity desktop process.")?;
        if let Some(error) = wait_error {
            return Err(error).context("Could not observe the Antigravity desktop process.");
        }
        Ok(())
    }
}

impl Drop for DesktopProcess {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = signal_group(self.child.id() as libc::pid_t, libc::SIGKILL);
            let _ = self.child.kill();
            let _ = self.child.wait();
            settle_group(self.child.id() as libc::pid_t);
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

fn wait_for_desktop(
    child: Child,
    grace: Duration,
    mut check: impl FnMut() -> Result<()>,
) -> Result<i32> {
    let mut process = DesktopProcess {
        child,
        status: None,
        cleaned: false,
    };
    let result = loop {
        if let Err(error) = check() {
            break Err(error);
        }
        match process.child.try_wait() {
            Ok(Some(status)) => {
                process.status = Some(status);
                break Ok(exit_code(status));
            }
            Ok(None) => thread::sleep(POLL_INTERVAL),
            Err(error) => break Err(error).context("Could not wait for Antigravity desktop."),
        }
    };
    process.stop(grace)?;
    result
}

fn wait_for_desktop_and_finish(
    child: Child,
    grace: Duration,
    check: impl FnMut() -> Result<()>,
    finish: impl FnOnce(),
) -> Result<i32> {
    let result = wait_for_desktop(child, grace, check);
    // 即使等待返回中断或错误，子进程回收完成后也要收尾账号同步。
    finish();
    result
}

pub(super) fn launch(root: &Path, profile_home: &Path) -> Result<i32> {
    let binary = resolve_binary()?;
    observer::check_interrupted()?;
    let prepared = prepare(root, profile_home)?;
    let mut command = desktop_command(&binary, &prepared)?;
    observer::check_interrupted()?;
    let child = command
        .spawn()
        .context("Could not start Antigravity desktop.")?;
    // 基线来自启动前写入的确切字节；不能在 spawn 后重读，以免漏掉快速完成的新登录。
    let mut sync = match desktop_sync::Watcher::start(
        root.to_path_buf(),
        prepared.home.join(TOKEN_TARGET),
        prepared.baseline,
    ) {
        Ok(watcher) => Some(watcher),
        Err(_) => {
            write_stderr_line("[sagy] Desktop account synchronization could not start.");
            None
        }
    };
    // prepared 持有桌面锁，调用方另持 profile 共享锁；二者都覆盖整个子进程生命周期。
    let result =
        wait_for_desktop_and_finish(child, STOP_GRACE, observer::check_interrupted, || {
            // 桌面及其后代已停止后才做最后一次读取；线程 join 后才能交还共享桌面锁。
            if let Some(watcher) = sync.as_mut() {
                watcher.finish();
            }
        });
    let code = result?;
    if code != 0 {
        super::note(format_args!(
            "Antigravity desktop exited with status {code}."
        ));
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::fs::symlink;

    const SYNTHETIC_TOKEN: &[u8] = br#"{
  "token":{"refresh_token":"sagy-test-refresh", "access_token":"sagy-test-access", "expiry":"2099-01-01T00:00:00Z"},
  "id_token_email":"synthetic@example.invalid", "future_field": [1, 2]
}
"#;

    fn profile(root: &Path) -> PathBuf {
        if root.exists() {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let home = store::profile_home(root, &store::State::default(), "demo", true).unwrap();
        fs::write(home.join(TOKEN_SOURCE), SYNTHETIC_TOKEN).unwrap();
        fs::set_permissions(home.join(TOKEN_SOURCE), fs::Permissions::from_mode(0o600)).unwrap();
        home
    }

    fn test_prepare(root: &Path, home: &Path) -> Result<Prepared> {
        prepare_with(root, home, || {
            desktop_history::initialize_from(root, &root.join("absent-source"), || Ok(()))
        })
    }

    #[test]
    fn credentials_are_copied_byte_for_byte_to_the_desktop_root_and_kept_private() {
        let temp = tempfile::tempdir().unwrap();
        let home = profile(temp.path());
        let prepared = test_prepare(temp.path(), &home).unwrap();
        let target = prepared.home.join(TOKEN_TARGET);
        assert_eq!(fs::read(&target).unwrap(), SYNTHETIC_TOKEN);
        assert_eq!(
            prepared.baseline,
            <[u8; 32]>::from(Sha256::digest(SYNTHETIC_TOKEN))
        );
        assert_eq!(fs::read(home.join(TOKEN_SOURCE)).unwrap(), SYNTHETIC_TOKEN);
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&prepared.home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(prepared.home.join(".desktop-shell"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(prepared.user_data.starts_with(&prepared.home));
    }

    #[test]
    fn an_active_desktop_lock_prevents_overwriting_its_refreshed_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let home = profile(temp.path());
        let first = test_prepare(temp.path(), &home).unwrap();
        let target = first.home.join(TOKEN_TARGET);
        fs::write(&target, b"desktop-refreshed-synthetic-token").unwrap();
        let error = test_prepare(temp.path(), &home).err().unwrap().to_string();
        assert!(error.contains("already a sagy desktop"));
        assert_eq!(
            fs::read(&target).unwrap(),
            b"desktop-refreshed-synthetic-token"
        );
        drop(first);
        let second = test_prepare(temp.path(), &home).unwrap();
        assert_eq!(
            fs::read(second.home.join(TOKEN_TARGET)).unwrap(),
            SYNTHETIC_TOKEN
        );
    }

    #[test]
    fn unsafe_source_links_and_invalid_tokens_are_rejected_before_creating_a_desktop_home() {
        let temp = tempfile::tempdir().unwrap();
        let home = profile(temp.path());
        let source = home.join(TOKEN_SOURCE);
        let original = home.join(".gemini/original-token");
        fs::rename(&source, &original).unwrap();
        symlink(&original, &source).unwrap();
        assert!(test_prepare(temp.path(), &home).is_err());
        fs::remove_file(&source).unwrap();
        fs::hard_link(&original, &source).unwrap();
        assert!(test_prepare(temp.path(), &home).is_err());
        fs::remove_file(&source).unwrap();
        fs::rename(&original, &source).unwrap();
        for invalid in [
            br#"{"token":{"refresh_token":""}}"#.as_slice(),
            br#"{"token":{"access_token":"no-refresh"}}"#,
            br#"{"token":{"refresh_token":"one","refresh_token":"two"}}"#,
            b"not-json",
        ] {
            fs::write(&source, invalid).unwrap();
            assert!(test_prepare(temp.path(), &home).is_err());
            assert!(!temp.path().join("desktop-home").exists());
        }
        fs::write(&source, vec![b' '; MAX_TOKEN_BYTES as usize + 1]).unwrap();
        assert!(test_prepare(temp.path(), &home).is_err());
        assert!(!temp.path().join("desktop-home").exists());
    }

    #[test]
    fn target_links_and_shared_directory_permissions_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let home = profile(temp.path());
        let prepared = test_prepare(temp.path(), &home).unwrap();
        let target = prepared.home.join(TOKEN_TARGET);
        let desktop_home = prepared.home.clone();
        drop(prepared);
        fs::remove_file(&target).unwrap();
        symlink(home.join(TOKEN_SOURCE), &target).unwrap();
        assert!(test_prepare(temp.path(), &home).is_err());
        assert_eq!(fs::read(home.join(TOKEN_SOURCE)).unwrap(), SYNTHETIC_TOKEN);
        fs::remove_file(&target).unwrap();
        fs::hard_link(home.join(TOKEN_SOURCE), &target).unwrap();
        assert!(test_prepare(temp.path(), &home).is_err());
        fs::remove_file(&target).unwrap();
        fs::set_permissions(&desktop_home, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(test_prepare(temp.path(), &home).is_err());
    }

    #[test]
    fn controlled_shell_preserves_isolation_with_spaces_and_quotes_in_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("a 'quoted' root");
        let home = profile(&root);
        let prepared = test_prepare(&root, &home).unwrap();
        let output = Command::new(prepared.home.join(".desktop-shell"))
            .args(["-ilc", "/usr/bin/env"])
            .env("HOME", "/unrelated/home")
            .env("XDG_CONFIG_HOME", "/unrelated/config")
            .env("SSH_CONNECTION", "unrelated")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let environment = String::from_utf8(output.stdout).unwrap();
        assert!(
            environment
                .lines()
                .any(|line| line == format!("HOME={}", prepared.home.display()))
        );
        assert!(environment.lines().any(|line| line
            == format!(
                "XDG_CONFIG_HOME={}",
                prepared.home.join(".config").display()
            )));
        assert!(
            environment
                .lines()
                .any(|line| line == "SSH_CONNECTION=127.0.0.1 0 127.0.0.1 0")
        );
    }

    #[test]
    fn desktop_command_uses_its_own_user_data_and_discards_engine_overrides() {
        let temp = tempfile::tempdir().unwrap();
        let home = profile(temp.path());
        let prepared = test_prepare(temp.path(), &home).unwrap();
        let binary = runtime::Binary::from_path(PathBuf::from("/bin/sh")).unwrap();
        let command = desktop_command(&binary, &prepared).unwrap();
        assert_eq!(command.get_program(), OsStr::new("/bin/sh"));
        let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        assert_eq!(env[OsStr::new("HOME")], Some(prepared.home.as_os_str()));
        assert_eq!(
            env[OsStr::new("SHELL")],
            Some(prepared.home.join(".desktop-shell").as_os_str())
        );
        for key in [
            "DEV_URL",
            "CODEIUM_LANGUAGE_SERVER_BIN",
            "NODE_OPTIONS",
            "ELECTRON_RUN_AS_NODE",
        ] {
            assert!(env.get(OsStr::new(key)).copied().flatten().is_none());
        }
        let arguments: Vec<_> = command.get_args().collect();
        let mut user_data = std::ffi::OsString::from("--user-data-dir=");
        user_data.push(&prepared.user_data);
        assert!(arguments.contains(&user_data.as_os_str()));
    }

    #[test]
    fn a_desktop_exit_cleans_up_its_remaining_process_group() {
        let temp = tempfile::tempdir().unwrap();
        let heartbeat = temp.path().join("heartbeat");
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "(trap '' TERM; while :; do printf x >> \"$1\"; /bin/sleep 0.02; done) & while [ ! -s \"$1\" ]; do /bin/sleep 0.01; done; exit 0",
                "sagy-desktop-test",
            ])
            .arg(&heartbeat)
            .process_group(0)
            .spawn()
            .unwrap();
        assert_eq!(
            wait_for_desktop(child, Duration::from_millis(50), || Ok(())).unwrap(),
            0
        );
        // 返回后立即取样；后台 writer 不能在锁交还调用方后继续写入。
        let after_return = fs::read(&heartbeat).unwrap();
        assert!(!after_return.is_empty());
        thread::sleep(Duration::from_millis(100));
        assert_eq!(fs::read(&heartbeat).unwrap(), after_return);
    }

    #[test]
    fn desktop_wait_preserves_exit_status_and_reaps_a_process_that_ignores_termination() {
        let exited = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .process_group(0)
            .spawn()
            .unwrap();
        assert_eq!(
            wait_for_desktop(exited, Duration::from_millis(50), || Ok(())).unwrap(),
            7
        );
        let child = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; exec /bin/sleep 30"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        // 确保 fixture 已安装忽略 SIGTERM 的处理，再检查有界强制回收。
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        let error = wait_for_desktop(child, Duration::from_millis(50), || {
            bail!("synthetic interruption")
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "synthetic interruption");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn desktop_finalization_runs_after_reaping_and_preserves_the_exit_result() {
        let temp = tempfile::tempdir().unwrap();
        let home = profile(temp.path());
        let prepared = test_prepare(temp.path(), &home).unwrap();
        let final_login = temp.path().join("final-login");
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "printf finished > \"$1\"; exit 7",
                "desktop-final-sync",
            ])
            .arg(&final_login)
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let mut finished = false;
        let code = wait_for_desktop_and_finish(
            child,
            Duration::from_millis(50),
            || Ok(()),
            || {
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                assert_eq!(fs::read(&final_login).unwrap(), b"finished");
                assert!(test_prepare(temp.path(), &home).is_err());
                finished = true;
            },
        )
        .unwrap();
        assert!(finished);
        assert_eq!(code, 7);
        drop(prepared);

        let child = Command::new("/bin/sh")
            .args(["-c", "exec /bin/sleep 30"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        let mut finished = false;
        let error = wait_for_desktop_and_finish(
            child,
            Duration::from_millis(50),
            || bail!("synthetic termination"),
            || {
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                finished = true;
            },
        )
        .unwrap_err();
        assert!(finished);
        assert_eq!(error.to_string(), "synthetic termination");
    }
}
