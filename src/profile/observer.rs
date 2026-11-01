use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tempfile::NamedTempFile;

const PREFIX_BYTES: usize = 1024;
const READ_BYTES: usize = 64 * 1024;
const TURN_BYTES: u64 = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const STOP_TIMEOUT: Duration = Duration::from_millis(1500);

static OBSERVER_LOCK: Mutex<()> = Mutex::new(());
static OBSERVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(Debug)]
pub(super) struct ObserverInterrupted {
    pub(super) signal: i32,
}

impl std::fmt::Display for ObserverInterrupted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "profile launch interrupted by signal {}",
            self.signal
        )
    }
}

impl std::error::Error for ObserverInterrupted {}

extern "C" fn observed_signal(signal: libc::c_int) {
    OBSERVED_SIGNAL.store(signal, Ordering::Relaxed);
}

pub(super) fn check_interrupted() -> Result<()> {
    let signal = OBSERVED_SIGNAL.load(Ordering::Relaxed);
    if signal != 0 {
        return Err(ObserverInterrupted { signal }.into());
    }
    Ok(())
}

pub(super) struct SignalGuard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
    _lock: MutexGuard<'static, ()>,
}

impl SignalGuard {
    pub(super) fn install() -> Result<Self> {
        let lock = OBSERVER_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("profile observer lock was poisoned"))?;
        OBSERVED_SIGNAL.store(0, Ordering::Relaxed);
        let mut guard = Self {
            previous: Vec::new(),
            _lock: lock,
        };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGTTOU] {
            // handler 仅写原子变量，回收及文件操作全部在普通执行路径中完成。
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = if signal == libc::SIGTTOU {
                libc::SIG_IGN
            } else {
                observed_signal as *const () as usize
            };
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(io::Error::last_os_error())
                    .context("failed to install profile signal handlers");
            }
            guard.previous.push((signal, previous));
        }
        Ok(guard)
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, action) in self.previous.iter().rev() {
            unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
        }
        OBSERVED_SIGNAL.store(0, Ordering::Relaxed);
    }
}

struct TerminalState {
    file: File,
    foreground: libc::pid_t,
    attributes: libc::termios,
}

struct TerminalGuard(Option<TerminalState>);

fn terminal_call(mut operation: impl FnMut() -> libc::c_int) -> io::Result<()> {
    loop {
        if operation() == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn terminal_disappeared(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENXIO | libc::ENODEV | libc::ENOENT | libc::ENOTTY | libc::EIO)
    )
}

impl TerminalGuard {
    fn capture() -> Result<Self> {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(Self(None));
        }
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/tty")
        {
            Ok(file) => file,
            Err(error) if terminal_disappeared(&error) => return Ok(Self(None)),
            Err(error) => return Err(error).context("failed to open the controlling terminal"),
        };
        let foreground = unsafe { libc::tcgetpgrp(file.as_raw_fd()) };
        if foreground < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to inspect the terminal foreground group");
        }
        if foreground != unsafe { libc::getpgrp() } {
            bail!("run profile auto in the foreground when using an interactive terminal");
        }
        let mut attributes = std::mem::MaybeUninit::uninit();
        terminal_call(|| unsafe { libc::tcgetattr(file.as_raw_fd(), attributes.as_mut_ptr()) })
            .context("failed to inspect terminal attributes")?;
        Ok(Self(Some(TerminalState {
            file,
            foreground,
            attributes: unsafe { attributes.assume_init() },
        })))
    }

    fn foreground_child(&self, child: &mut ObservedChild) -> Result<()> {
        let Some(terminal) = self.0.as_ref() else {
            return Ok(());
        };
        let result = terminal_call(|| unsafe {
            libc::tcsetpgrp(terminal.file.as_raw_fd(), child.process_group)
        });
        if let Err(error) = result {
            if matches!(error.raw_os_error(), Some(libc::ESRCH | libc::EPERM))
                && child.poll()?.is_some()
            {
                return Ok(());
            }
            return Err(error).context("failed to hand the terminal to agy");
        }
        // agy 可能在前台组交接前读 stdin 而收到 SIGTTIN，交接后继续整个组。
        child.signal_group(libc::SIGCONT)
    }

    fn restore(&mut self) -> Result<()> {
        let Some(terminal) = self.0.take() else {
            return Ok(());
        };
        let foreground = terminal_call(|| unsafe {
            libc::tcsetpgrp(terminal.file.as_raw_fd(), terminal.foreground)
        });
        let attributes = terminal_call(|| unsafe {
            libc::tcsetattr(
                terminal.file.as_raw_fd(),
                libc::TCSANOW,
                &terminal.attributes,
            )
        });
        for result in [foreground, attributes] {
            match result {
                Err(error) if !terminal_disappeared(&error) => {
                    return Err(error).context("failed to restore the terminal after agy");
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct ObservedChild {
    child: Child,
    process_group: libc::pid_t,
    stopped: bool,
    completed: bool,
    reaped: bool,
}

impl ObservedChild {
    fn spawn(command: &mut Command) -> Result<Self> {
        command
            .process_group(0)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let child = command
            .spawn()
            .context("failed to launch the selected agy profile")?;
        let process_group = child.id() as libc::pid_t;
        Ok(Self {
            child,
            process_group,
            stopped: false,
            completed: false,
            reaped: false,
        })
    }

    fn poll(&mut self) -> Result<Option<ExitStatus>> {
        let status = self
            .child
            .try_wait()
            .context("failed to inspect agy status")?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    fn exited_without_reaping(&self) -> Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(unsafe { info.si_pid() } != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("failed to inspect agy before reaping it");
            }
        }
    }

    fn signal_group(&mut self, signal: libc::c_int) -> Result<()> {
        if self.reaped {
            return Ok(());
        }
        if self.process_group <= 1 || self.process_group == unsafe { libc::getpgrp() } {
            bail!("the agy process group is unsafe to stop");
        }
        // 最后一次组信号前保留 leader 的 PID，防止 reap 后 PID 复用误伤新进程。
        if unsafe { libc::killpg(self.process_group, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(()),
            Some(libc::EPERM) if self.exited_without_reaping()? => Ok(()),
            Some(libc::EPERM) => {
                if unsafe { libc::kill(self.child.id() as libc::pid_t, signal) } == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error()).context("failed to signal agy")
                }
            }
            _ => Err(error).context("failed to signal the agy process group"),
        }
    }

    fn stop(&mut self) -> Result<ExitStatus> {
        if let Some(status) = self.poll()? {
            return Ok(status);
        }
        self.signal_group(libc::SIGTERM)?;
        let deadline = Instant::now() + STOP_TIMEOUT;
        while !self.exited_without_reaping()? && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        self.signal_group(libc::SIGKILL)?;
        let status = self
            .child
            .wait()
            .context("failed to reap agy after stopping it")?;
        self.reaped = true;
        self.stopped = true;
        Ok(status)
    }
}

impl Drop for ObservedChild {
    fn drop(&mut self) {
        if !self.completed && !self.stopped {
            let _ = self.stop();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn take_literal(bytes: &[u8], cursor: &mut usize, literal: &[u8]) -> Option<()> {
    let end = cursor.checked_add(literal.len())?;
    if bytes.get(*cursor..end)? != literal {
        return None;
    }
    *cursor = end;
    Some(())
}

fn take_digits(bytes: &[u8], cursor: &mut usize, count: usize) -> Option<()> {
    let end = cursor.checked_add(count)?;
    if !bytes.get(*cursor..end)?.iter().all(u8::is_ascii_digit) {
        return None;
    }
    *cursor = end;
    Some(())
}

fn native_limit_end(bytes: &[u8]) -> Option<usize> {
    let mut cursor = 0;
    take_literal(bytes, &mut cursor, b"E")?;
    take_digits(bytes, &mut cursor, 4)?;
    take_literal(bytes, &mut cursor, b" ")?;
    take_digits(bytes, &mut cursor, 2)?;
    take_literal(bytes, &mut cursor, b":")?;
    take_digits(bytes, &mut cursor, 2)?;
    take_literal(bytes, &mut cursor, b":")?;
    take_digits(bytes, &mut cursor, 2)?;
    take_literal(bytes, &mut cursor, b".")?;
    take_digits(bytes, &mut cursor, 6)?;
    let padding = cursor;
    while matches!(bytes.get(cursor), Some(b' ' | b'\t')) {
        cursor += 1;
    }
    if cursor == padding {
        return None;
    }
    let process_id = cursor;
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    if cursor == process_id {
        return None;
    }
    take_literal(bytes, &mut cursor, b" errorreport.go:224] ")?;
    if bytes.get(cursor..)?.starts_with(b"agent executor error: ") {
        take_literal(bytes, &mut cursor, b"agent executor error: ")?;
    }
    take_literal(
        bytes,
        &mut cursor,
        b"generating and executing: RESOURCE_EXHAUSTED (code 429)",
    )?;
    Some(cursor)
}

#[derive(Default)]
struct LogScanner {
    prefix: Vec<u8>,
    discard_line: bool,
}

impl LogScanner {
    fn matches(&self, complete: bool) -> bool {
        let Some(end) = native_limit_end(&self.prefix) else {
            return false;
        };
        let suffix = &self.prefix[end..];
        suffix.starts_with(b": ")
            || suffix.starts_with(b":\t")
            || (complete && matches!(suffix, b"" | b"\r"))
    }

    fn feed(&mut self, bytes: &[u8], final_read: bool) -> bool {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let complete = part.last() == Some(&b'\n');
            let content = if complete {
                &part[..part.len() - 1]
            } else {
                part
            };
            if !self.discard_line {
                let available = PREFIX_BYTES - self.prefix.len();
                self.prefix
                    .extend_from_slice(&content[..content.len().min(available)]);
                if self.matches(complete) {
                    return true;
                }
                self.discard_line = self.prefix.len() == PREFIX_BYTES;
            }
            if complete {
                self.prefix.clear();
                self.discard_line = false;
            }
        }
        final_read && !self.discard_line && self.matches(true)
    }
}

fn read_log(log: &mut NamedTempFile, scanner: &mut LogScanner, final_read: bool) -> Result<bool> {
    let info = log
        .as_file()
        .metadata()
        .context("failed to inspect the private agy log")?;
    let current = fs::symlink_metadata(log.path()).context("the private agy log disappeared")?;
    if !current.is_file()
        || info.ino() != current.ino()
        || info.dev() != current.dev()
        || current.uid() != unsafe { libc::geteuid() }
        || current.nlink() != 1
        || current.mode() & 0o077 != 0
    {
        bail!("the private agy observation log changed unexpectedly");
    }
    let file = log.as_file_mut();
    let position = file.stream_position()?;
    let mut remaining = info
        .len()
        .checked_sub(position)
        .context("the private agy observation log was truncated unexpectedly")?;
    if !final_read {
        remaining = remaining.min(TURN_BYTES);
    }
    let mut buffer = [0_u8; READ_BYTES];
    while remaining != 0 {
        let count = file.read(&mut buffer[..remaining.min(READ_BYTES as u64) as usize])?;
        if count == 0 {
            break;
        }
        remaining -= count as u64;
        if scanner.feed(&buffer[..count], false) {
            return Ok(true);
        }
    }
    Ok(final_read && scanner.feed(&[], true))
}

fn custom_log_file(argument: &OsStr) -> bool {
    let bytes = argument.as_bytes();
    if !bytes.starts_with(b"-") {
        return false;
    }
    let option = bytes.split(|byte| *byte == b'=').next().unwrap_or_default();
    let option = option
        .iter()
        .copied()
        .skip_while(|byte| *byte == b'-')
        .collect::<Vec<_>>();
    matches!(option.as_slice(), b"log-file" | b"log_file")
}

fn consult_limit(
    child: &mut ObservedChild,
    on_limit: &mut impl FnMut(bool) -> Result<bool>,
) -> Result<bool> {
    check_interrupted()?;
    let allow_restart = child
        .poll()?
        .is_none_or(|status| status.code().is_some_and(|code| code > 0));
    let should_stop = on_limit(allow_restart)?;
    check_interrupted()?;
    let still_restartable = child
        .poll()?
        .is_none_or(|status| status.code().is_some_and(|code| code > 0));
    Ok(allow_restart && should_stop && still_restartable)
}

#[cfg(test)]
pub(super) fn launch_observed(
    command: Command,
    home: &Path,
    args: &[OsString],
    on_limit: impl FnMut(bool) -> Result<bool>,
) -> Result<(i32, bool)> {
    launch_observed_with_poll(command, home, args, on_limit, || {})
}

pub(super) fn launch_observed_with_poll(
    mut command: Command,
    home: &Path,
    args: &[OsString],
    mut on_limit: impl FnMut(bool) -> Result<bool>,
    mut on_poll: impl FnMut(),
) -> Result<(i32, bool)> {
    if args.iter().any(|argument| custom_log_file(argument)) {
        bail!(
            "profile auto manages --log-file for quota observation; use profile run for a custom log file"
        );
    }
    let mut log = tempfile::Builder::new()
        .prefix(".sagy-observe-")
        .suffix(".log")
        .tempfile_in(home)
        .context("failed to create the private agy observation log")?;
    log.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    let _signals = SignalGuard::install()?;
    let mut terminal = TerminalGuard::capture()?;
    let mut log_argument = OsString::from("--log-file=");
    log_argument.push(log.path());
    command.arg(log_argument).args(args);
    check_interrupted()?;
    let mut child = ObservedChild::spawn(&mut command)?;
    terminal.foreground_child(&mut child)?;
    let mut scanner = LogScanner::default();
    let mut limited = false;
    let mut switched = false;
    let status = loop {
        on_poll();
        check_interrupted()?;
        if !limited && read_log(&mut log, &mut scanner, false)? {
            limited = true;
            if consult_limit(&mut child, &mut on_limit)? {
                let status = child.stop()?;
                switched = child.stopped || status.code().is_some_and(|code| code > 0);
                break status;
            }
        }
        if let Some(status) = child.poll()? {
            if !limited && read_log(&mut log, &mut scanner, true)? {
                switched = consult_limit(&mut child, &mut on_limit)?;
            }
            break status;
        }
        thread::sleep(POLL_INTERVAL);
    };
    check_interrupted()?;
    terminal.restore()?;
    check_interrupted()?;
    // 正常退出保留原生 helper 的语义，只有换号或异常路径才结束剩余进程组。
    child.completed = true;
    Ok((
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
        switched,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATIVE: &[u8] = b"E1101 06:43:49.254543       1 errorreport.go:224] agent executor error: generating and executing: RESOURCE_EXHAUSTED (code 429): quota\n";

    fn scan(bytes: &[u8], chunk_size: usize) -> bool {
        let mut scanner = LogScanner::default();
        bytes
            .chunks(chunk_size)
            .any(|chunk| scanner.feed(chunk, false))
            || scanner.feed(&[], true)
    }

    #[test]
    fn native_429_is_recognized_across_every_byte_boundary() {
        for chunk_size in 1..NATIVE.len() {
            assert!(scan(NATIVE, chunk_size));
        }
        let direct = String::from_utf8(NATIVE.to_vec())
            .unwrap()
            .replace("agent executor error: ", "");
        assert!(scan(direct.as_bytes(), 7));
        let no_suffix = NATIVE.strip_suffix(b": quota\n").unwrap();
        assert!(scan(no_suffix, 7));
    }

    #[test]
    fn user_text_and_other_log_sources_do_not_trigger_switching() {
        for bytes in [
            [b"user said ".as_slice(), NATIVE].concat(),
            String::from_utf8(NATIVE.to_vec())
                .unwrap()
                .replace("errorreport.go:224", "prompt.go:224")
                .into_bytes(),
            String::from_utf8(NATIVE.to_vec())
                .unwrap()
                .replace("(code 429):", "(code 429)0:")
                .into_bytes(),
        ] {
            assert!(!scan(&bytes, 13));
        }
    }

    #[test]
    fn huge_lines_keep_bounded_prefix_and_do_not_hide_later_native_errors() {
        let mut user_line = vec![b'x'; 4 * 1024 * 1024];
        user_line.extend_from_slice(NATIVE);
        assert!(!scan(&user_line, READ_BYTES));
        user_line.push(b'\n');
        user_line.extend_from_slice(NATIVE);
        assert!(scan(&user_line, READ_BYTES));
        let mut native_line = NATIVE[..NATIVE.len() - 1].to_vec();
        native_line.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024));
        assert!(scan(&native_line, 11));
    }

    fn fake_command(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script, "fake-agy"]);
        command
    }

    fn native_log_script(after: &str) -> String {
        format!(
            "log=${{1#--log-file=}}\nprintf '%s\\n' 'E1101 06:43:49.254543       1 errorreport.go:224] agent executor error: generating and executing: RESOURCE_EXHAUSTED (code 429): quota' >> \"$log\"\n{after}"
        )
    }

    #[test]
    fn live_429_stops_child_only_after_one_available_spare_confirmation() {
        let home = tempfile::tempdir().unwrap();
        let script = native_log_script("exec /bin/sleep 30");
        let mut calls = Vec::new();
        let started = Instant::now();
        let code = launch_observed(fake_command(&script), home.path(), &[], |allow| {
            calls.push(allow);
            Ok(true)
        })
        .unwrap();
        assert_eq!(code, (128 + libc::SIGTERM, true));
        assert_eq!(calls, vec![true]);
        assert!(started.elapsed() < Duration::from_secs(4));
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn no_spare_leaves_the_original_child_running_until_its_own_exit() {
        let home = tempfile::tempdir().unwrap();
        let script = native_log_script("/bin/sleep 0.3\nexit 0");
        let mut calls = 0;
        let started = Instant::now();
        let code = launch_observed(fake_command(&script), home.path(), &[], |_| {
            calls += 1;
            Ok(false)
        })
        .unwrap();
        assert_eq!(code, (0, false));
        assert_eq!(calls, 1);
        assert!(started.elapsed() >= Duration::from_millis(250));
    }

    #[test]
    fn completed_success_with_429_only_records_cooldown() {
        let home = tempfile::tempdir().unwrap();
        let script = native_log_script("exit 0");
        let mut calls = Vec::new();
        let code = launch_observed(fake_command(&script), home.path(), &[], |allow| {
            calls.push(allow);
            Ok(true)
        })
        .unwrap();
        assert_eq!(code, (0, false));
        assert_eq!(calls, vec![false]);
    }

    #[test]
    fn explicit_log_override_is_rejected_without_spawning() {
        let home = tempfile::tempdir().unwrap();
        for argument in ["--log-file=/tmp/fixture", "-log-file", "--log_file=x"] {
            let error = launch_observed(
                Command::new("/does-not-exist"),
                home.path(),
                &[argument.into()],
                |_| Ok(true),
            )
            .unwrap_err();
            assert!(error.to_string().contains("manages --log-file"));
        }
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn child_success_during_spare_lookup_cancels_the_reserved_switch() {
        let home = tempfile::tempdir().unwrap();
        let script = native_log_script("/bin/sleep 0.2\nexit 0");
        let mut calls = Vec::new();
        let outcome = launch_observed(fake_command(&script), home.path(), &[], |allow| {
            calls.push(allow);
            thread::sleep(Duration::from_millis(350));
            Ok(true)
        })
        .unwrap();
        assert_eq!(calls, vec![true]);
        assert_eq!(outcome, (0, false));
    }

    #[test]
    fn child_signal_during_spare_lookup_cancels_the_reserved_switch() {
        let home = tempfile::tempdir().unwrap();
        let script = native_log_script("/bin/sleep 0.2\nkill -INT $$");
        let mut calls = Vec::new();
        let outcome = launch_observed(fake_command(&script), home.path(), &[], |allow| {
            calls.push(allow);
            thread::sleep(Duration::from_millis(350));
            Ok(true)
        })
        .unwrap();
        assert_eq!(calls, vec![true]);
        assert_eq!(outcome, (128 + libc::SIGINT, false));
    }

    #[test]
    fn ignored_term_is_killed_and_reaped_before_switching() {
        let home = tempfile::tempdir().unwrap();
        let script = native_log_script("trap '' TERM\nwhile :; do /bin/sleep 1; done");
        let started = Instant::now();
        let outcome =
            launch_observed(fake_command(&script), home.path(), &[], |_| Ok(true)).unwrap();
        assert_eq!(outcome, (128 + libc::SIGKILL, true));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn lifecycle_helper() {
        let Some(mode) = std::env::var_os("SAGY_OBSERVER_LIFECYCLE_MODE") else {
            return;
        };
        let home = std::env::var_os("SAGY_OBSERVER_HOME").unwrap();
        fs::write(Path::new(&home).join("helper-ran"), b"ready").unwrap();
        assert_eq!(mode, "signal");
        let script = "printf '%s' $$ > \"$SAGY_OBSERVER_PID_FILE\"\nexec /bin/sleep 30";
        let error = launch_observed(fake_command(script), Path::new(&home), &[], |_| Ok(false))
            .unwrap_err();
        let interrupted = error.downcast_ref::<ObserverInterrupted>().unwrap();
        assert_eq!(interrupted.signal, libc::SIGTERM);
        std::process::exit(128 + interrupted.signal);
    }

    fn helper_command(home: &Path, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        let module = module_path!().split_once("::").unwrap().1;
        command
            .args([
                "--exact",
                &format!("{module}::lifecycle_helper"),
                "--nocapture",
            ])
            .env("SAGY_OBSERVER_LIFECYCLE_MODE", mode)
            .env("SAGY_OBSERVER_HOME", home);
        command
    }

    fn bounded_wait(child: &mut Child) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
                thread::sleep(Duration::from_millis(200));
                let _ = child.kill();
                let _ = child.wait();
                panic!("observer fixture did not exit in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn parent_sigterm_reaps_its_child_and_reports_the_interrupt() {
        let home = tempfile::tempdir().unwrap();
        let marker = home.path().join("pid");
        let mut command = helper_command(home.path(), "signal");
        command
            .env("SAGY_OBSERVER_PID_FILE", &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut parent = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while !marker.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(marker.exists());
        assert!(home.path().join("helper-ran").exists());
        let child_pid: libc::pid_t = fs::read_to_string(&marker).unwrap().parse().unwrap();
        assert_eq!(
            unsafe { libc::kill(parent.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
        assert_eq!(bounded_wait(&mut parent).code(), Some(128 + libc::SIGTERM));
        assert_eq!(unsafe { libc::kill(child_pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
