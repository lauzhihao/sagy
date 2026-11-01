use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use super::store;

const VERIFIED_AGY_SHA256: &str =
    "34423fc9b0af3841e7646aa72a2d40ffeab8218b22d1cb99eac7355f9eba31e3";
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

// 保留已验证文件的句柄；跨账号重启前确认路径仍然指向同一份构建。
pub(super) struct Binary {
    path: PathBuf,
    file: File,
    generation: (i64, i64, u64),
}

impl Binary {
    fn generation(meta: &fs::Metadata) -> (i64, i64, u64) {
        (meta.ctime(), meta.ctime_nsec(), meta.len())
    }

    pub(super) fn check(&self) -> Result<()> {
        let current = fs::symlink_metadata(&self.path)?;
        let original = self.file.metadata()?;
        if !current.is_file()
            || (original.dev(), original.ino()) != (current.dev(), current.ino())
            || Self::generation(&current) != self.generation
        {
            bail!("The verified agy executable changed; restart the launcher to verify it again.");
        }
        Ok(())
    }

    pub(super) fn try_clone(&self) -> Result<Self> {
        self.check()?;
        Ok(Self {
            path: self.path.clone(),
            file: self.file.try_clone()?,
            generation: self.generation,
        })
    }

    #[cfg(test)]
    pub(super) fn fixture(path: PathBuf) -> Result<Self> {
        let file = File::open(&path)?;
        let generation = Self::generation(&file.metadata()?);
        Ok(Self {
            path,
            file,
            generation,
        })
    }
}

pub(super) fn verified_binary() -> Result<Binary> {
    let binary = std::env::var_os("AGY_BIN")
        .map(PathBuf::from)
        .unwrap_or(store::real_home()?.join(".local/bin/agy"));
    if !binary.is_absolute() {
        bail!("AGY_BIN must be an absolute path.");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&binary)
        .context("AGY_BIN must identify an executable regular file.")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!("AGY_BIN must identify an executable regular file.");
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if format!("{:x}", digest.finalize()) != VERIFIED_AGY_SHA256 {
        bail!("This agy binary has not been verified for isolated profiles; launch was stopped.");
    }
    if !Path::new(SANDBOX_EXEC).is_file() {
        bail!("The required macOS sandbox launcher is unavailable.");
    }
    let binary = Binary {
        path: binary,
        file,
        generation: Binary::generation(&metadata),
    };
    binary.check()?;
    Ok(binary)
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
    let mut command = Command::new(SANDBOX_EXEC);
    command
        .arg("-p")
        .arg(sandbox_policy(home, &store::real_home()?)?)
        .arg(&binary.path);
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
    fn executable_replaced_between_profile_launches_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("agy");
        fs::write(&path, b"first").unwrap();
        let verified = Binary::fixture(path.clone()).unwrap();
        verified.check().unwrap();
        let replacement = root.path().join("new-agy");
        fs::write(&replacement, b"second").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(verified.check().is_err());
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

    #[test]
    fn sandbox_excludes_other_profiles_and_real_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("profiles/a/home");
        let policy = sandbox_policy(&home, temp.path()).unwrap();
        assert!(policy.contains("com.apple.securityd.xpc"));
        assert!(policy.contains("require-not (subpath"));
        assert!(policy.contains(home.to_str().unwrap()));
        assert!(policy.contains("Library/Keychains"));
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
