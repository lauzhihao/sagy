use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(target_os = "macos")]
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::store;

#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

// 每次启动检查当前路径，允许 agy 独立升级后继续使用同一启动器。
pub(super) struct Binary {
    path: PathBuf,
}

impl Binary {
    pub(super) fn from_path(path: PathBuf) -> Result<Self> {
        if !path.is_absolute() {
            bail!("The executable path must be absolute.");
        }
        let binary = Self { path };
        binary.check()?;
        Ok(binary)
    }

    pub(super) fn check(&self) -> Result<()> {
        let metadata = fs::metadata(&self.path)
            .context("The executable must be a regular file with execute permission.")?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            bail!("The executable must be a regular file with execute permission.");
        }
        Ok(())
    }

    pub(super) fn try_clone(&self) -> Result<Self> {
        self.check()?;
        Ok(Self {
            path: self.path.clone(),
        })
    }

    #[cfg(test)]
    pub(super) fn fixture(path: PathBuf) -> Result<Self> {
        let binary = Self { path };
        binary.check()?;
        Ok(binary)
    }
}

pub(super) fn resolve_binary() -> Result<Binary> {
    let path = if let Some(path) = std::env::var_os("AGY_BIN") {
        PathBuf::from(path)
    } else {
        installed_binary(&store::real_home()?, std::env::var_os("PATH").as_deref())
            .context("agy was not found. Install agy or set AGY_BIN to its absolute path.")?
    };
    if !path.is_absolute() {
        bail!("AGY_BIN must be an absolute path.");
    }
    #[cfg(target_os = "macos")]
    if !Path::new(SANDBOX_EXEC).is_file() {
        bail!("The required macOS sandbox launcher is unavailable.");
    }
    let binary = Binary { path };
    binary.check()?;
    Ok(binary)
}

fn installed_binary(home: &Path, search_path: Option<&OsStr>) -> Option<PathBuf> {
    let candidates = [
        home.join(".local/bin/agy"),
        home.join(".gemini/antigravity-cli/bin/agy"),
    ];
    candidates
        .into_iter()
        .chain(
            search_path
                .into_iter()
                .flat_map(std::env::split_paths)
                .map(|directory| directory.join("agy")),
        )
        .find_map(|path| {
            let binary = Binary { path };
            binary.check().ok()?;
            fs::canonicalize(binary.path).ok()
        })
}

fn child_environment(
    home: &Path,
    inherited: impl IntoIterator<Item = (OsString, OsString)>,
) -> BTreeMap<OsString, OsString> {
    let prefixes = [
        "AGY_",
        "ANTIGRAVITY_",
        "GEMINI_",
        "GOOGLE_",
        "GCLOUD_",
        "CLOUDSDK_",
    ];
    let excluded = [
        "CLOUD_CODE_URL",
        "BAICODE_ENDPOINT_URL",
        "SSH_TTY",
        "SSH_CLIENT",
        "SSH_CONNECTION",
        "SAGY_PROFILE_ROOT",
        "SAGY_POOL_KEY",
        "AGY_BIN",
    ];
    let mut environment = inherited
        .into_iter()
        .filter(|(key, _)| {
            let name = key.to_string_lossy();
            !prefixes.iter().any(|prefix| name.starts_with(prefix))
                && !excluded.contains(&name.as_ref())
        })
        .collect::<BTreeMap<_, _>>();
    #[cfg(target_os = "linux")]
    {
        // SSH 文件认证不继承调用方显式指定的桌面 keyring 连接。
        environment.retain(|key, _| {
            !matches!(
                key.to_str(),
                Some(
                    "DBUS_SESSION_BUS_ADDRESS"
                        | "DBUS_SESSION_BUS_PID"
                        | "GNOME_KEYRING_CONTROL"
                        | "GNOME_KEYRING_PID"
                )
            )
        });
    }
    let proxy_keys = [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ];
    if !proxy_keys.iter().any(|key| {
        environment
            .get(OsStr::new(key))
            .is_some_and(|value| !value.is_empty())
    }) {
        environment.insert("http_proxy".into(), "http://127.0.0.1:10808".into());
        environment.insert("https_proxy".into(), "http://127.0.0.1:10808".into());
    }
    for (key, path) in [
        ("HOME", home.to_path_buf()),
        ("XDG_CONFIG_HOME", home.join(".config")),
        ("XDG_DATA_HOME", home.join(".local/share")),
        ("XDG_CACHE_HOME", home.join(".cache")),
    ] {
        environment.insert(key.into(), path.into_os_string());
    }
    environment.insert("SSH_CONNECTION".into(), "127.0.0.1 0 127.0.0.1 0".into());
    environment.insert("AGY_CLI_DISABLE_AUTO_UPDATE".into(), "true".into());
    environment
}

#[cfg(target_os = "macos")]
fn resolved_path(path: &Path) -> Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let parent = path
                .parent()
                .context("A profile path must have a parent.")?;
            Ok(resolved_path(parent)?.join(
                path.file_name()
                    .context("A profile path must have a name.")?,
            ))
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "macos")]
fn sandbox_policy(home: &Path, real_home: &Path) -> Result<String> {
    let root = home
        .ancestors()
        .nth(3)
        .context("The profile home has no storage root.")?;
    let quoted = |path: &Path| -> Result<String> {
        serde_json::to_string(path.to_str().context("Profile paths must be UTF-8.")?)
            .map_err(Into::into)
    };
    Ok(format!(
        "(version 1)(allow default)\
        (deny mach-lookup (global-name \"com.apple.securityd\")\
         (global-name \"com.apple.securityd.xpc\")\
         (global-name \"com.apple.securityd.system\"))\
        (deny file-read* file-write* (subpath {}) (subpath {}))\
        (deny file-read* file-write* (require-all\
         (subpath {}) (require-not (subpath {}))))",
        quoted(&resolved_path(&real_home.join(".gemini"))?)?,
        quoted(&resolved_path(&real_home.join("Library/Keychains"))?)?,
        quoted(root)?,
        quoted(home)?,
    ))
}

pub(super) fn command(binary: &Binary, home: &Path) -> Result<Command> {
    binary.check()?;
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new(SANDBOX_EXEC);
        command
            .arg("-p")
            .arg(sandbox_policy(home, &store::real_home()?)?)
            .arg(&binary.path);
        command
    };
    #[cfg(target_os = "linux")]
    let mut command = Command::new(&binary.path);
    command
        .env_clear()
        .envs(child_environment(home, std::env::vars_os()));
    Ok(command)
}

/// 直接启动桌面 app，避免 Electron 子沙箱嵌套在 sagy 的 CLI 沙箱中初始化失败；
/// 账号仍使用独立 HOME、user-data-dir 和凭据副本，保持配置与环境隔离。
pub(super) fn desktop_command(binary: &Binary, home: &Path) -> Result<Command> {
    binary.check()?;
    let mut command = Command::new(&binary.path);
    command
        .env_clear()
        .envs(child_environment(home, std::env::vars_os()));
    Ok(command)
}

extern "C" fn interrupted(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

struct InterruptGuard(libc::sigaction);

impl InterruptGuard {
    fn install() -> Result<Self> {
        INTERRUPTED.store(false, Ordering::Relaxed);
        // handler 只写原子值，等待与回收均由正常控制流处理。
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = interrupted as *const () as usize;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
        }
        if unsafe { libc::sigaction(libc::SIGINT, &action, &mut previous) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(previous))
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGINT, &self.0, std::ptr::null_mut());
        }
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

fn wait_plain(
    child: &mut Child,
    interrupted: &AtomicBool,
    grace: Duration,
    mut poll: impl FnMut(),
) -> Result<i32> {
    let mut interrupt_deadline = None;
    loop {
        poll();
        if let Some(status) = child.try_wait()? {
            return Ok(exit_code(status));
        }
        let now = Instant::now();
        if interrupted.load(Ordering::Relaxed) && interrupt_deadline.is_none() {
            interrupt_deadline = Some(now + grace);
        }
        if interrupt_deadline.is_some_and(|deadline| now >= deadline) {
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
            let deadline = Instant::now() + grace;
            while Instant::now() < deadline {
                if let Some(status) = child.try_wait()? {
                    return Ok(exit_code(status));
                }
                thread::sleep(Duration::from_millis(20));
            }
            let _ = child.kill();
            return Ok(exit_code(child.wait()?));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(super) fn launch(binary: &Binary, home: &Path, args: &[OsString]) -> Result<i32> {
    launch_with_poll(command(binary, home)?, args, || {})
}

pub(super) fn launch_with_poll(
    mut command: Command,
    args: &[OsString],
    poll: impl FnMut(),
) -> Result<i32> {
    let _interrupt_guard = InterruptGuard::install()?;
    let mut child = command.args(args).spawn().context("Failed to start agy.")?;
    let result = wait_plain(&mut child, &INTERRUPTED, Duration::from_secs(3), poll);
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(entries: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        child_environment(
            Path::new("/profiles/a/home"),
            entries
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into())),
        )
    }

    #[test]
    fn executable_updates_are_accepted_but_invalid_paths_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("agy");
        fs::write(&path, b"first").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let verified = Binary::fixture(path.clone()).unwrap();
        verified.check().unwrap();
        let replacement = root.path().join("new-agy");
        fs::write(&replacement, b"second").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        verified.check().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verified.check().is_err());
        fs::remove_file(&path).unwrap();
        assert!(verified.check().is_err());
    }

    #[test]
    fn executable_search_prefers_local_then_vendor_then_path() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let local = home.join(".local/bin/agy");
        let vendor = home.join(".gemini/antigravity-cli/bin/agy");
        let on_path = root.path().join("path/agy");
        for path in [&local, &vendor, &on_path] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture executable").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let search_path = on_path.parent().unwrap().as_os_str();
        assert_eq!(
            installed_binary(&home, Some(search_path)),
            Some(fs::canonicalize(&local).unwrap())
        );
        fs::remove_file(&local).unwrap();
        assert_eq!(
            installed_binary(&home, Some(search_path)),
            Some(fs::canonicalize(&vendor).unwrap())
        );
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            installed_binary(&home, Some(search_path)),
            Some(fs::canonicalize(&on_path).unwrap())
        );
        assert!(installed_binary(&home, None).is_none());
    }

    #[test]
    fn credentials_are_removed_and_proxy_values_are_inherited() {
        let env = environment(&[
            ("GEMINI_API_KEY", "fixture"),
            ("AGY_ADC_AUTH", "true"),
            ("SAGY_POOL_KEY", "fixture-pool-key"),
            ("https_proxy", "http://proxy.example:3128"),
            ("no_proxy", "localhost"),
        ]);
        assert!(!env.contains_key(OsStr::new("GEMINI_API_KEY")));
        assert!(!env.contains_key(OsStr::new("AGY_ADC_AUTH")));
        assert!(!env.contains_key(OsStr::new("SAGY_POOL_KEY")));
        assert_eq!(
            env.get(OsStr::new("https_proxy")).unwrap(),
            "http://proxy.example:3128"
        );
        assert_eq!(env.get(OsStr::new("no_proxy")).unwrap(), "localhost");
        assert!(!env.contains_key(OsStr::new("http_proxy")));
        assert_eq!(env.get(OsStr::new("HOME")).unwrap(), "/profiles/a/home");
    }

    #[test]
    fn proxy_defaults_apply_only_without_a_configured_proxy() {
        let env = environment(&[("http_proxy", "")]);
        assert_eq!(
            env.get(OsStr::new("http_proxy")).unwrap(),
            "http://127.0.0.1:10808"
        );
        assert_eq!(
            env.get(OsStr::new("https_proxy")).unwrap(),
            "http://127.0.0.1:10808"
        );
        let env = environment(&[("ALL_PROXY", "socks5://localhost:1234")]);
        assert!(!env.contains_key(OsStr::new("http_proxy")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_excludes_other_profiles_and_real_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("profiles/a/home");
        let policy = sandbox_policy(&home, temp.path()).unwrap();
        let binary = Binary::fixture(PathBuf::from("/bin/sh")).unwrap();
        let command = command(&binary, &home).unwrap();
        assert_eq!(command.get_program(), OsStr::new(SANDBOX_EXEC));
        assert!(policy.contains("com.apple.securityd.xpc"));
        assert!(policy.contains("require-not (subpath"));
        assert!(policy.contains(home.to_str().unwrap()));
        assert!(policy.contains("Library/Keychains"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn desktop_command_runs_the_app_directly_so_electron_can_start_its_sandbox() {
        let binary = Binary::fixture(PathBuf::from("/bin/sh")).unwrap();
        let command = desktop_command(&binary, Path::new("/tmp/sagy-profile/home")).unwrap();
        assert_eq!(command.get_program(), OsStr::new("/bin/sh"));
        assert!(
            !command
                .get_args()
                .any(|argument| argument == OsStr::new("-p"))
        );
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == OsStr::new("HOME")
                    && value == Some(OsStr::new("/tmp/sagy-profile/home")))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn desktop_child_can_initialize_its_own_seatbelt_sandbox() {
        let temp = tempfile::tempdir().unwrap();
        let binary = Binary::fixture(PathBuf::from("/bin/sh")).unwrap();
        let mut command = desktop_command(&binary, temp.path()).unwrap();
        let status = command
            .args([
                "-c",
                "/usr/bin/sandbox-exec -p '(version 1)(allow default)' /bin/sh -c 'exit 0'",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "child sandbox initialization failed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_uses_the_profile_home_without_inheriting_desktop_keyring_connections() {
        let env = environment(&[
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("DBUS_SESSION_BUS_PID", "123"),
            ("GNOME_KEYRING_CONTROL", "/run/user/1000/keyring"),
            ("GNOME_KEYRING_PID", "456"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ]);
        for key in [
            "DBUS_SESSION_BUS_ADDRESS",
            "DBUS_SESSION_BUS_PID",
            "GNOME_KEYRING_CONTROL",
            "GNOME_KEYRING_PID",
        ] {
            assert!(!env.contains_key(OsStr::new(key)));
        }
        assert_eq!(env.get(OsStr::new("HOME")).unwrap(), "/profiles/a/home");
        assert_eq!(
            env.get(OsStr::new("SSH_CONNECTION")).unwrap(),
            "127.0.0.1 0 127.0.0.1 0"
        );
        assert_eq!(
            env.get(OsStr::new("XDG_RUNTIME_DIR")).unwrap(),
            "/run/user/1000"
        );
    }

    #[test]
    fn plain_wait_preserves_exit_status_and_bounds_interrupt_cleanup() {
        let mut exited = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        assert_eq!(
            wait_plain(
                &mut exited,
                &AtomicBool::new(false),
                Duration::from_millis(20),
                || {},
            )
            .unwrap(),
            7
        );
        let mut child = Command::new("/bin/sleep").arg("10").spawn().unwrap();
        let started = Instant::now();
        let code = wait_plain(
            &mut child,
            &AtomicBool::new(true),
            Duration::from_millis(30),
            || {},
        )
        .unwrap();
        assert!(code >= 128);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.try_wait().unwrap().is_some());
    }
}
