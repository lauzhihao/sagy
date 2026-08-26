//! Provider-native session passthrough.
//!
//! A strict six-field `oauth_creds.json` is an observation of the provider's
//! current session, not a portable credential that sagy can own.  The only
//! supported operation for that shape is a local launch after a no-UI
//! Keychain preflight.  This module deliberately communicates only a probe
//! status between processes and never requests the Keychain secret.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::launcher::{self, LaunchError};

/// The exact argv token recognized by the hidden Keychain helper.
///
/// It is intentionally not part of clap's public command vocabulary.  The
/// helper is entered before normal CLI parsing and emits only one status word.
pub(crate) const KEYCHAIN_PROBE_ARG: &str = "--__sagy-keychain-probe";

const KEYCHAIN_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const NATIVE_PREAMBLE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_NATIVE_PREAMBLE_BYTES: usize = 64 * 1024;
const NATIVE_OUTPUT_TAIL_BYTES: usize = 256;
const MAX_AUTH_SCAN_BYTES: usize = 64 * 1024;

const PROBE_AVAILABLE: &str = "available";
const PROBE_UNAVAILABLE: &str = "unavailable";
const PROBE_ERROR: &str = "error";
const PROBE_UNSUPPORTED: &str = "unsupported";

/// A Keychain result intentionally contains no OS error text and no secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeychainProbeStatus {
    Available,
    Unavailable,
    Error,
    Unsupported,
}

impl KeychainProbeStatus {
    const fn wire(self) -> &'static str {
        match self {
            Self::Available => PROBE_AVAILABLE,
            Self::Unavailable => PROBE_UNAVAILABLE,
            Self::Error => PROBE_ERROR,
            Self::Unsupported => PROBE_UNSUPPORTED,
        }
    }

    fn parse(wire: &[u8]) -> Option<Self> {
        match wire {
            value if value == PROBE_AVAILABLE.as_bytes() => Some(Self::Available),
            value if value == PROBE_UNAVAILABLE.as_bytes() => Some(Self::Unavailable),
            value if value == PROBE_ERROR.as_bytes() => Some(Self::Error),
            value if value == PROBE_UNSUPPORTED.as_bytes() => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Errors exposed by the native-session path are all secret-free and ASCII.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeSessionError {
    KeychainUnavailable,
    KeychainProbeFailed,
    UnsupportedPlatform,
    Launch(LaunchError),
    OutputRead(io::ErrorKind),
    OutputWrite(io::ErrorKind),
    ChildWait(io::ErrorKind),
    AuthRequired,
}

impl std::fmt::Display for NativeSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeychainUnavailable => formatter.write_str(
                "provider-managed session is unavailable because the system Keychain could not be read",
            ),
            Self::KeychainProbeFailed => {
                formatter.write_str("could not verify the system Keychain without user interaction")
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("provider-managed native sessions are unsupported on this platform")
            }
            Self::Launch(error) => error.fmt(formatter),
            Self::OutputRead(kind) => {
                write!(formatter, "failed to read native Antigravity output ({kind:?})")
            }
            Self::OutputWrite(kind) => {
                write!(formatter, "failed to write native Antigravity output ({kind:?})")
            }
            Self::ChildWait(kind) => {
                write!(formatter, "failed to wait for native Antigravity ({kind:?})")
            }
            Self::AuthRequired => formatter.write_str(
                "provider-managed session became unavailable; native launch was stopped before login",
            ),
        }
    }
}

impl std::error::Error for NativeSessionError {}

/// Return whether the argv requests a noninteractive prompt.
///
/// A bare positional run is compacted to `-p` by the launcher.  Explicit
/// print/prompt options are also accepted.  `--continue`, interactive mode,
/// and option-only invocations stay on the normal state-managed path.
pub(crate) fn has_noninteractive_prompt(args: &[OsString]) -> bool {
    if args.iter().any(|arg| {
        let value = arg.to_string_lossy();
        value == "--prompt-interactive" || value == "-i"
    }) {
        return false;
    }

    if args.first().is_some_and(|arg| {
        arg.as_encoded_bytes()
            .first()
            .is_some_and(|byte| *byte != b'-')
    }) {
        return true;
    }

    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let value = arg.to_string_lossy();
        if value == "-p" || value == "--print" || value == "--prompt" {
            return args
                .get(index + 1)
                .is_some_and(|next| !next.to_string_lossy().trim().is_empty());
        }
        if value.starts_with("--print=") || value.starts_with("--prompt=") {
            return value
                .split_once('=')
                .is_some_and(|(_, prompt)| !prompt.trim().is_empty());
        }
        index += 1;
    }
    false
}

/// Recognize the hidden helper invocation before normal clap/router handling.
pub(crate) fn is_probe_invocation(args: &[OsString]) -> bool {
    args.len() == 2 && args[1].as_encoded_bytes() == KEYCHAIN_PROBE_ARG.as_bytes()
}

/// Entry point used by [`crate::lib`] for the hidden helper.
pub(crate) fn run_probe_helper() -> i32 {
    let status = keychain_probe_in_process();
    // This is the only output from the helper.  It is a fixed ASCII status and
    // never contains Keychain data or an OS error string.
    println!("{}", status.wire());
    0
}

/// Probe the provider's Keychain item in a short-lived helper process.
///
/// The helper never requests the Keychain secret. The parent receives one
/// fixed status word, and a hung helper is killed and reaped before the caller
/// continues.
pub(crate) fn probe_keychain_with_helper() -> KeychainProbeStatus {
    let Ok(executable) = std::env::current_exe() else {
        return KeychainProbeStatus::Error;
    };

    let mut command = Command::new(executable);
    command.arg(KEYCHAIN_PROBE_ARG).env_clear();
    run_bounded_probe(command, KEYCHAIN_PROBE_TIMEOUT)
}

fn run_bounded_probe(mut command: Command, timeout: Duration) -> KeychainProbeStatus {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    configure_process_group(&mut command);

    let Ok(mut child) = command.spawn() else {
        return KeychainProbeStatus::Error;
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                terminate_process_group(&mut child);
                let _ = child.wait();
                return KeychainProbeStatus::Unavailable;
            }
            Err(_) => {
                terminate_process_group(&mut child);
                let _ = child.wait();
                return KeychainProbeStatus::Error;
            }
        }
    };

    let mut output = Vec::new();
    if let Some(stdout) = child.stdout.as_mut() {
        let _ = stdout.take(8 * 1024).read_to_end(&mut output);
    }
    let _ = child.wait();
    if !status.is_some_and(|status| status.success()) {
        return KeychainProbeStatus::Error;
    }
    KeychainProbeStatus::parse(trim_ascii_whitespace(&output)).unwrap_or(KeychainProbeStatus::Error)
}

/// Launch a current provider-managed session without importing or mutating
/// sagy's state, active homes, credential store, or repository metadata.
pub(crate) fn launch_native_session(
    extra_args: &[OsString],
    resume: bool,
) -> Result<i32, NativeSessionError> {
    match probe_keychain_with_helper() {
        KeychainProbeStatus::Available => {}
        KeychainProbeStatus::Unsupported => return Err(NativeSessionError::UnsupportedPlatform),
        KeychainProbeStatus::Unavailable => return Err(NativeSessionError::KeychainUnavailable),
        KeychainProbeStatus::Error => return Err(NativeSessionError::KeychainProbeFailed),
    }

    let command =
        launcher::build_native_command(extra_args, resume).map_err(NativeSessionError::Launch)?;
    run_native_command(command)
}

fn run_native_command(mut command: Command) -> Result<i32, NativeSessionError> {
    let mut stdout_writer = io::stdout();
    let mut stderr_writer = io::stderr();
    run_native_command_with_writers(&mut command, &mut stdout_writer, &mut stderr_writer)
}

fn run_native_command_with_writers<W1: Write, W2: Write>(
    command: &mut Command,
    stdout_writer: &mut W1,
    stderr_writer: &mut W2,
) -> Result<i32, NativeSessionError> {
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| NativeSessionError::Launch(LaunchError::Spawn(error.kind())))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        terminate_process_group(&mut child);
        let _ = child.wait();
        NativeSessionError::Launch(LaunchError::StderrUnavailable)
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        terminate_process_group(&mut child);
        let _ = child.wait();
        NativeSessionError::Launch(LaunchError::StderrUnavailable)
    })?;

    let (sender, receiver) = mpsc::channel();
    let stdout_thread = match spawn_output_reader(OutputStream::Stdout, stdout, sender.clone()) {
        Ok(thread) => thread,
        Err(error) => {
            terminate_process_group(&mut child);
            let _ = child.wait();
            return Err(NativeSessionError::OutputRead(error.kind()));
        }
    };
    let stderr_thread = match spawn_output_reader(OutputStream::Stderr, stderr, sender) {
        Ok(thread) => thread,
        Err(error) => {
            terminate_process_group(&mut child);
            let _ = child.wait();
            let _ = stdout_thread.join();
            return Err(NativeSessionError::OutputRead(error.kind()));
        }
    };
    let mut guard = NativeOutputGuard::new();
    let mut child_status = None;
    let mut eof_count = 0_u8;
    let mut read_error = None;

    loop {
        if child_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => child_status = Some(status),
                Ok(None) => {}
                Err(error) => {
                    read_error = Some(NativeSessionError::ChildWait(error.kind()));
                    terminate_process_group(&mut child);
                    child_status = child.wait().ok();
                }
            }
        }

        if !guard.is_open() && guard.deadline_expired() {
            guard.open(stdout_writer, stderr_writer).map_err(|kind| {
                terminate_process_group(&mut child);
                let _ = child.wait();
                NativeSessionError::OutputWrite(kind)
            })?;
        }

        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(NativeOutputEvent::Chunk(stream, bytes)) => {
                let auth_required = guard
                    .feed(stream, &bytes, stdout_writer, stderr_writer)
                    .map_err(|kind| {
                        terminate_process_group(&mut child);
                        let _ = child.wait();
                        NativeSessionError::OutputWrite(kind)
                    })?;
                if auth_required {
                    terminate_process_group(&mut child);
                    let _ = child.wait();
                    join_output_readers(stdout_thread, stderr_thread);
                    return Err(NativeSessionError::AuthRequired);
                }
            }
            Ok(NativeOutputEvent::Eof(_stream)) => {
                eof_count = eof_count.saturating_add(1);
            }
            Ok(NativeOutputEvent::ReadError(_stream, kind)) => {
                read_error.get_or_insert(NativeSessionError::OutputRead(kind));
                terminate_process_group(&mut child);
                child_status = child.wait().ok();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                eof_count = 2;
            }
        }

        if child_status.is_some() && eof_count >= 2 {
            break;
        }
    }

    // The child has exited and both pipe readers reached EOF, so no further
    // bytes can contain an authentication URL.  Flush the bounded tail now.
    guard
        .finish(stdout_writer, stderr_writer)
        .map_err(NativeSessionError::OutputWrite)?;
    join_output_readers(stdout_thread, stderr_thread);
    if let Some(error) = read_error {
        return Err(error);
    }
    let status = child_status.ok_or(NativeSessionError::ChildWait(io::ErrorKind::UnexpectedEof))?;
    Ok(status.code().unwrap_or(1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputStream {
    Stdout,
    Stderr,
}

enum NativeOutputEvent {
    Chunk(OutputStream, Vec<u8>),
    Eof(OutputStream),
    ReadError(OutputStream, io::ErrorKind),
}

fn spawn_output_reader<R>(
    stream: OutputStream,
    mut reader: R,
    sender: Sender<NativeOutputEvent>,
) -> io::Result<JoinHandle<()>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name("sagy-native-output-drain".to_owned())
        .spawn(move || {
            let mut chunk = [0_u8; 8 * 1024];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.send(NativeOutputEvent::Eof(stream));
                        return;
                    }
                    Ok(size) => {
                        if sender
                            .send(NativeOutputEvent::Chunk(stream, chunk[..size].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(NativeOutputEvent::ReadError(stream, error.kind()));
                        return;
                    }
                }
            }
        })
}

fn join_output_readers(stdout_thread: JoinHandle<()>, stderr_thread: JoinHandle<()>) {
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
}

struct NativeOutputGuard {
    opened: bool,
    deadline: Instant,
    preamble_stdout: Vec<u8>,
    preamble_stderr: Vec<u8>,
    tail_stdout: Vec<u8>,
    tail_stderr: Vec<u8>,
    auth_scan: Vec<u8>,
}

impl NativeOutputGuard {
    fn new() -> Self {
        Self {
            opened: false,
            deadline: Instant::now() + NATIVE_PREAMBLE_TIMEOUT,
            preamble_stdout: Vec::new(),
            preamble_stderr: Vec::new(),
            tail_stdout: Vec::new(),
            tail_stderr: Vec::new(),
            auth_scan: Vec::new(),
        }
    }

    const fn is_open(&self) -> bool {
        self.opened
    }

    fn deadline_expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    fn feed<W1: Write, W2: Write>(
        &mut self,
        stream: OutputStream,
        bytes: &[u8],
        stdout: &mut W1,
        stderr: &mut W2,
    ) -> Result<bool, io::ErrorKind> {
        self.auth_scan.extend_from_slice(bytes);
        if self.auth_scan.len() > MAX_AUTH_SCAN_BYTES {
            let excess = self.auth_scan.len() - MAX_AUTH_SCAN_BYTES;
            self.auth_scan.drain(..excess);
        }
        if contains_auth_marker(&self.auth_scan) {
            return Ok(true);
        }

        if !self.opened {
            let preamble = match stream {
                OutputStream::Stdout => &mut self.preamble_stdout,
                OutputStream::Stderr => &mut self.preamble_stderr,
            };
            preamble.extend_from_slice(bytes);
            if self.preamble_stdout.len() + self.preamble_stderr.len() >= MAX_NATIVE_PREAMBLE_BYTES
            {
                self.open(stdout, stderr)?;
            }
            return Ok(false);
        }

        let tail = match stream {
            OutputStream::Stdout => &mut self.tail_stdout,
            OutputStream::Stderr => &mut self.tail_stderr,
        };
        tail.extend_from_slice(bytes);
        if contains_auth_marker(tail) {
            return Ok(true);
        }
        if tail.len() > NATIVE_OUTPUT_TAIL_BYTES {
            let split = tail.len() - NATIVE_OUTPUT_TAIL_BYTES;
            let prefix = tail.drain(..split).collect::<Vec<_>>();
            match stream {
                OutputStream::Stdout => stdout.write_all(&prefix),
                OutputStream::Stderr => stderr.write_all(&prefix),
            }
            .map_err(|error| error.kind())?;
        }
        Ok(false)
    }

    fn open<W1: Write, W2: Write>(
        &mut self,
        stdout: &mut W1,
        stderr: &mut W2,
    ) -> Result<(), io::ErrorKind> {
        if self.opened {
            return Ok(());
        }
        stdout
            .write_all(&self.preamble_stdout)
            .map_err(|error| error.kind())?;
        stderr
            .write_all(&self.preamble_stderr)
            .map_err(|error| error.kind())?;
        stdout
            .write_all(&self.tail_stdout)
            .map_err(|error| error.kind())?;
        stderr
            .write_all(&self.tail_stderr)
            .map_err(|error| error.kind())?;
        stdout.flush().map_err(|error| error.kind())?;
        stderr.flush().map_err(|error| error.kind())?;
        self.preamble_stdout.clear();
        self.preamble_stderr.clear();
        self.tail_stdout.clear();
        self.tail_stderr.clear();
        self.opened = true;
        Ok(())
    }

    fn finish<W1: Write, W2: Write>(
        &mut self,
        stdout: &mut W1,
        stderr: &mut W2,
    ) -> Result<(), io::ErrorKind> {
        if !self.opened {
            return self.open(stdout, stderr);
        }
        stdout
            .write_all(&self.tail_stdout)
            .map_err(|error| error.kind())?;
        stderr
            .write_all(&self.tail_stderr)
            .map_err(|error| error.kind())?;
        stdout.flush().map_err(|error| error.kind())?;
        stderr.flush().map_err(|error| error.kind())?;
        self.tail_stdout.clear();
        self.tail_stderr.clear();
        Ok(())
    }
}

fn contains_auth_marker(bytes: &[u8]) -> bool {
    let mut lowered = Vec::with_capacity(bytes.len());
    lowered.extend(bytes.iter().map(u8::to_ascii_lowercase));
    [
        b"https://accounts.google.com/".as_slice(),
        b"http://accounts.google.com/".as_slice(),
        b"oauth2.googleapis.com/".as_slice(),
        b"authentication required".as_slice(),
        b"login required".as_slice(),
        b"not logged in".as_slice(),
        b"waiting for authentication".as_slice(),
        b"waiting for login".as_slice(),
        b"please visit".as_slice(),
        b"open the following".as_slice(),
        b"opening browser".as_slice(),
        b"sign in".as_slice(),
        b"oauth".as_slice(),
    ]
    .into_iter()
    .any(|marker| lowered.windows(marker.len()).any(|window| window == marker))
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

fn terminate_process_group(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id().try_into().unwrap_or(0);
        if pid > 0 {
            // The child is placed in its own process group before spawn, so a
            // login helper/browser descendant cannot survive an auth abort.
            unsafe {
                let _ = libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
}

fn keychain_probe_in_process() -> KeychainProbeStatus {
    #[cfg(target_os = "macos")]
    {
        keychain::probe()
    }
    #[cfg(not(target_os = "macos"))]
    {
        KeychainProbeStatus::Unsupported
    }
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::KeychainProbeStatus;
    use core_foundation::base::{CFRelease, CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
        kSecReturnAttributes,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    const ERR_SEC_USER_CANCELED: i32 = -128;
    const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
    const ERR_SEC_AUTH_FAILED: i32 = -25293;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
    const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

    // security-framework-sys 2.17 does not expose these two SDK constants,
    // but both are stable Security.framework CFString values on macOS.
    unsafe extern "C" {
        static kSecMatchLimitOne: core_foundation::string::CFStringRef;
        static kSecUseAuthenticationUI: core_foundation::string::CFStringRef;
        static kSecUseAuthenticationUIFail: core_foundation::string::CFStringRef;
        fn SecKeychainGetStatus(keychain: *mut std::ffi::c_void, status: *mut u32) -> i32;
    }

    pub(super) fn probe() -> KeychainProbeStatus {
        // Status inspection does not request or decrypt an item secret, so it
        // cannot create a new per-binary Keychain access grant.
        let mut keychain_status = 0_u32;
        let status = unsafe { SecKeychainGetStatus(std::ptr::null_mut(), &mut keychain_status) };
        const UNLOCKED: u32 = 1;
        const READABLE: u32 = 2;
        if status != errSecSuccess {
            return classify_status(status);
        }
        if keychain_status & (UNLOCKED | READABLE) != (UNLOCKED | READABLE) {
            return KeychainProbeStatus::Unavailable;
        }

        // Query only public metadata for agy's exact item. ReturnData is
        // intentionally absent: requesting it makes macOS authorize every
        // newly rebuilt sagy binary and repeatedly show a password dialog.
        let query = CFDictionary::from_CFType_pairs(&[
            (
                unsafe { CFString::wrap_under_get_rule(kSecClass) },
                unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
                CFString::from("gemini").into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
                CFString::from("antigravity").into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecReturnAttributes) },
                CFBoolean::true_value().into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimit) },
                unsafe { CFString::wrap_under_get_rule(kSecMatchLimitOne) }.into_CFType(),
            ),
            (
                unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUI) },
                unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationUIFail) }.into_CFType(),
            ),
        ]);

        let mut result: CFTypeRef = std::ptr::null();
        let item_status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if item_status != errSecSuccess {
            if !result.is_null() {
                unsafe { CFRelease(result) };
            }
            return classify_status(item_status);
        }
        if result.is_null() {
            return KeychainProbeStatus::Error;
        }
        unsafe { CFRelease(result) };
        KeychainProbeStatus::Available
    }

    fn classify_status(status: i32) -> KeychainProbeStatus {
        // Missing item and interaction/auth failures all mean the native
        // session cannot be proven usable without changing user state.  Keep
        // them fail-closed and avoid exposing a localized Security.framework
        // error string.
        if status == errSecItemNotFound
            || status == ERR_SEC_INTERACTION_NOT_ALLOWED
            || status == ERR_SEC_AUTH_FAILED
            || status == ERR_SEC_NOT_AVAILABLE
            || status == ERR_SEC_MISSING_ENTITLEMENT
            || status == ERR_SEC_USER_CANCELED
        {
            KeychainProbeStatus::Unavailable
        } else {
            KeychainProbeStatus::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_noninteractive_prompt_arguments_enable_native_passthrough() {
        assert!(has_noninteractive_prompt(&args(&["say", "hi"])));
        assert!(has_noninteractive_prompt(&args(&["-p", "say hi"])));
        assert!(has_noninteractive_prompt(&args(&["--prompt=say hi"])));
        assert!(has_noninteractive_prompt(&args(&[
            "-m", "model", "-p", "say hi"
        ])));
        assert!(!has_noninteractive_prompt(&args(&[])));
        assert!(!has_noninteractive_prompt(&args(&["--continue"])));
        assert!(!has_noninteractive_prompt(&args(&["-i"])));
        assert!(!has_noninteractive_prompt(&args(&["--yolo", "say", "hi"])));
        assert!(!has_noninteractive_prompt(&args(&[
            "-m", "model", "say", "hi"
        ])));
        assert!(!has_noninteractive_prompt(&args(&[
            "say",
            "hi",
            "--prompt-interactive",
        ])));
    }

    #[test]
    fn probe_wire_is_strict_and_secret_free() {
        for status in [
            KeychainProbeStatus::Available,
            KeychainProbeStatus::Unavailable,
            KeychainProbeStatus::Error,
            KeychainProbeStatus::Unsupported,
        ] {
            assert_eq!(
                KeychainProbeStatus::parse(status.wire().as_bytes()),
                Some(status)
            );
        }
        assert_eq!(KeychainProbeStatus::parse(b"access_token"), None);
    }

    #[test]
    fn auth_output_is_detected_without_printing_it() {
        assert!(contains_auth_marker(
            b"Please visit https://accounts.google.com/o/oauth2/auth"
        ));
        assert!(contains_auth_marker(b"waiting for authentication"));
        assert!(!contains_auth_marker(b"Hi! How can I help you today?"));
    }

    #[test]
    fn output_guard_flushes_the_normal_tail() {
        let mut guard = NativeOutputGuard::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        guard.open(&mut stdout, &mut stderr).unwrap();
        assert!(
            !guard
                .feed(
                    OutputStream::Stdout,
                    b"Hi! How can I help you today?",
                    &mut stdout,
                    &mut stderr,
                )
                .unwrap()
        );
        guard.finish(&mut stdout, &mut stderr).unwrap();
        assert_eq!(stdout, b"Hi! How can I help you today?");
        assert!(stderr.is_empty());
    }

    #[test]
    fn output_guard_suppresses_a_split_authorization_url() {
        let mut guard = NativeOutputGuard::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert!(
            !guard
                .feed(
                    OutputStream::Stderr,
                    b"https://accounts.goo",
                    &mut stdout,
                    &mut stderr,
                )
                .unwrap()
        );
        assert!(
            guard
                .feed(
                    OutputStream::Stderr,
                    b"gle.com/o/oauth2/auth?state=secret",
                    &mut stdout,
                    &mut stderr,
                )
                .unwrap()
        );
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_probe_accepts_only_the_fixed_status_wire() {
        let mut available = Command::new("/bin/sh");
        available.args(["-c", "printf available"]);
        assert_eq!(
            run_bounded_probe(available, Duration::from_millis(500)),
            KeychainProbeStatus::Available
        );

        let mut secret_like = Command::new("/bin/sh");
        secret_like.args(["-c", "printf access_token"]);
        assert_eq!(
            run_bounded_probe(secret_like, Duration::from_millis(500)),
            KeychainProbeStatus::Error
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_probe_timeout_kills_descendants_and_reaps() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("descendant-survived");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("(sleep 0.25; printf survived > \"$SAGY_TEST_MARKER\") & wait")
            .env("SAGY_TEST_MARKER", &marker);

        let started = Instant::now();
        assert_eq!(
            run_bounded_probe(command, Duration::from_millis(40)),
            KeychainProbeStatus::Unavailable
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        thread::sleep(Duration::from_millis(350));
        assert!(
            !marker.exists(),
            "probe descendant survived process-group kill"
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervised_native_child_suppresses_auth_and_returns_promptly() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf 'Please visit https://accounts.google.com/o/oauth2/auth?state=secret\\n'; sleep 5",
        ]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let started = Instant::now();
        let result = run_native_command_with_writers(&mut command, &mut stdout, &mut stderr);
        assert_eq!(result, Err(NativeSessionError::AuthRequired));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(stdout.is_empty(), "authorization URL reached stdout");
        assert!(stderr.is_empty(), "authorization URL reached stderr");
    }
}
