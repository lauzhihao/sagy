//! 原生状态回调只写当前 HOME 内的额度事件；父进程负责绑定账号并提交快照。
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::{cache, now, physical_directory, quota, runtime::Binary, store};
use crate::core::credential::StrictValue;

const HELPER: &str = "--sagy-statusline-helper";
const MAX_INPUT: u64 = 256 * 1024;
const MAX_SETTINGS: u64 = 1024 * 1024;
const MAX_EVENT: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Event {
    state: String,
    conversation: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct HelperConfig {
    original_command: Option<String>,
}

fn bounded_read(mut reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    reader.by_ref().take(limit + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > limit {
        bail!("Status callback input is too large.");
    }
    Ok(raw)
}

fn event(raw: &[u8]) -> Option<Event> {
    let StrictValue(value) = serde_json::from_slice::<StrictValue>(raw).ok()?;
    let state = value.get("agent_state")?.as_str()?;
    if !matches!(
        state,
        "idle" | "working" | "tool_use" | "reviewing" | "authenticating" | "initializing" | "error"
    ) {
        return None;
    }
    let conversation = match value.get("conversation_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) if id.len() <= 128 => Some(id.clone()),
        _ => return None,
    };
    let token_count = |key| match value.pointer(key) {
        None | Some(Value::Null) => Some(None),
        Some(value) => value.as_u64().map(Some),
    };
    Some(Event {
        state: state.into(),
        conversation,
        input_tokens: token_count("/context_window/total_input_tokens")?,
        output_tokens: token_count("/context_window/total_output_tokens")?,
    })
}

fn shell_quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("Status callback paths must be UTF-8.")?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

fn original_status_line(home: &Path) -> Result<Value> {
    let file = match store::open_private_file(
        &home.join(".gemini/antigravity-cli/settings.json"),
        false,
    ) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
        {
            return Ok(Value::Null);
        }
        Err(error) => return Err(error),
    };
    let StrictValue(settings) =
        serde_json::from_slice::<StrictValue>(&bounded_read(file, MAX_SETTINGS)?)
            .context("Could not read the existing status line settings.")?;
    Ok(settings.get("statusLine").cloned().unwrap_or(Value::Null))
}

struct ProbeSample {
    windows: [Option<f64>; 2],
    started_at: f64,
    finished_at: f64,
}

struct Flight {
    handle: JoinHandle<Result<ProbeSample>>,
    cancel: Arc<AtomicBool>,
}

fn probe_snapshot(
    root: &Path,
    home: &Path,
    binary: &Binary,
    cancel: &AtomicBool,
) -> Result<ProbeSample> {
    if cancel.load(Ordering::Relaxed) {
        bail!("Quota update cancelled.");
    }
    let started_at = now();
    // 临时 HOME 仍放在原 root/profiles 下，既有 sandbox 会拒绝读取所有真实账号。
    let directory = tempfile::Builder::new()
        .prefix(".sagy-quota-probe-")
        .tempdir_in(root.join("profiles"))?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let probe_home = directory.path().join("home");
    let config = probe_home.join(".gemini/antigravity-cli");
    fs::create_dir_all(&config)?;
    for path in [&probe_home, &probe_home.join(".gemini"), &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let token_path = Path::new(".gemini/antigravity-cli/antigravity-oauth-token");
    let token = bounded_read(
        store::open_private_file(&home.join(token_path), false)?,
        1024 * 1024,
    )?;
    let StrictValue(document) = serde_json::from_slice::<StrictValue>(&token)
        .context("The profile credential is being updated; keep the previous quota sample.")?;
    if document
        .get("token")
        .unwrap_or(&document)
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        bail!("The profile has no resumable credential.");
    }
    let mut target = store::open_private_file(&probe_home.join(token_path), true)?;
    target.write_all(&token)?;
    drop(target);
    #[cfg(test)]
    {
        // 假 agy 的额度响应保存在测试文件中，正式构建仅复制凭据。
        let fixture = home.join(".gemini/antigravity-cli/profile-test-usage.json");
        if fixture.exists() {
            let raw = bounded_read(store::open_private_file(&fixture, false)?, MAX_INPUT)?;
            let mut out = store::open_private_file(&config.join("profile-test-usage.json"), true)?;
            out.write_all(&raw)?;
        }
    }
    let windows = quota::probe_cancellable(
        binary,
        &probe_home,
        "gemini",
        Duration::from_secs(25),
        cancel,
    );
    if cancel.load(Ordering::Relaxed) {
        bail!("Quota update cancelled.");
    }
    Ok(ProbeSample {
        windows,
        started_at,
        finished_at: now(),
    })
}

fn completed_turn(before: Option<&Event>, next: &Event) -> bool {
    if next.state != "idle" || next.conversation.as_ref().is_none_or(|id| id.is_empty()) {
        return false;
    }
    if before.is_none() {
        return next.input_tokens.is_some_and(|n| n > 0)
            || next.output_tokens.is_some_and(|n| n > 0);
    }
    before.is_none_or(|previous| {
        previous.state != "idle"
            || previous.conversation != next.conversation
            || previous.input_tokens != next.input_tokens
            || previous.output_tokens != next.output_tokens
    })
}

pub(super) struct SessionBridge {
    directory: TempDir,
    root: PathBuf,
    home: PathBuf,
    name: String,
    physical: String,
    binary: Binary,
    settings: String,
    previous: Option<Event>,
    checked_at: Option<Instant>,
    flight: Option<Flight>,
    pending: bool,
    closing: bool,
    warned: bool,
}

impl SessionBridge {
    pub(super) fn prepare(root: &Path, home: &Path, name: &str, binary: &Binary) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix(".sagy-statusline-")
            .tempdir_in(home)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let original = original_status_line(home)?;
        let original_command = original
            .get("command")
            .and_then(Value::as_str)
            .filter(|command| {
                !command.is_empty()
                    && original.get("enabled").and_then(Value::as_bool) != Some(false)
            });
        let config = directory.path().join("config.json");
        let mut file = store::open_private_file(&config, true)?;
        serde_json::to_writer(
            &mut file,
            &HelperConfig {
                original_command: original_command.map(str::to_owned),
            },
        )?;
        file.sync_all()?;
        let executable = std::env::current_exe()?;
        #[cfg(not(test))]
        let command = format!(
            "{} {HELPER} {}",
            shell_quote(executable.as_os_str())?,
            shell_quote(config.as_os_str())?
        );
        #[cfg(test)]
        let command = format!(
            "SAGY_STATUSLINE_FIXTURE_CONFIG={} {} --exact profile::statusline::tests::fixture_helper_dispatch --ignored --nocapture",
            shell_quote(config.as_os_str())?,
            shell_quote(executable.as_os_str())?
        );
        let mut status = if original_command.is_some() {
            original
        } else {
            json!({"stack_with_default":true,"padding":0})
        };
        let fields = status
            .as_object_mut()
            .context("The existing status line must be an object.")?;
        fields.insert("command".into(), Value::String(command));
        fields.insert("type".into(), Value::String("command".into()));
        fields.insert("enabled".into(), Value::Bool(true));
        Ok(Self {
            directory,
            root: root.into(),
            home: home.into(),
            name: name.into(),
            physical: physical_directory(home)?,
            binary: binary.try_clone()?,
            settings: serde_json::to_string(&json!({"statusLine":status}))?,
            previous: None,
            checked_at: None,
            flight: None,
            pending: false,
            closing: false,
            warned: false,
        })
    }

    pub(super) fn configure(&self, command: &mut Command) {
        command.args(["--settings", &self.settings]);
    }

    fn warn(&mut self, error: impl std::fmt::Display) {
        if !self.warned {
            super::note(format!("Could not save a live quota update: {error}"));
            self.warned = true;
        }
    }

    fn read_event(&mut self) -> Result<()> {
        let file = match store::open_private_file(&self.directory.path().join("event.json"), false)
        {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let StrictValue(value) =
            serde_json::from_slice::<StrictValue>(&bounded_read(file, MAX_EVENT)?)?;
        let next: Event = serde_json::from_value(value)?;
        if next.state.len() > 32 || next.conversation.as_ref().is_some_and(|id| id.len() > 128) {
            bail!("Invalid quota callback event.");
        }
        if completed_turn(self.previous.as_ref(), &next) {
            self.pending = true;
        }
        self.previous = Some(next);
        Ok(())
    }

    fn poll_inner(&mut self) -> Result<()> {
        if self
            .flight
            .as_ref()
            .is_some_and(|flight| flight.handle.is_finished())
        {
            let flight = self.flight.take().unwrap();
            let sample = flight
                .handle
                .join()
                .map_err(|_| anyhow::anyhow!("Live quota worker stopped unexpectedly."))??;
            if sample.windows.iter().all(Option::is_none) {
                bail!("Live quota query was unavailable; keeping the previous sample.");
            }
            cache::merge(
                &self.root,
                [cache::Update {
                    name: self.name.clone(),
                    directory: self.physical.clone(),
                    windows: sample.windows,
                    started_at: sample.started_at,
                    finished_at: sample.finished_at,
                    result: cache::Outcome::Ready,
                }],
            )?;
        }
        if !self.closing {
            self.read_event()?;
        }
        if !self.closing && self.pending && self.flight.is_none() {
            let root = self.root.clone();
            let home = self.home.clone();
            let binary = self.binary.try_clone()?;
            let cancel = Arc::new(AtomicBool::new(false));
            let worker_cancel = cancel.clone();
            let handle =
                thread::spawn(move || probe_snapshot(&root, &home, &binary, &worker_cancel));
            self.flight = Some(Flight { handle, cancel });
            self.pending = false;
        }
        Ok(())
    }

    pub(super) fn poll(&mut self) {
        let time = Instant::now();
        if self
            .checked_at
            .is_some_and(|last| time.duration_since(last) < Duration::from_millis(100))
        {
            return;
        }
        self.checked_at = Some(time);
        if let Err(error) = self.poll_inner() {
            self.warn(error);
        }
    }

    pub(super) fn finish(&mut self) {
        self.closing = true;
        self.pending = false;
        if self
            .flight
            .as_ref()
            .is_some_and(|flight| flight.handle.is_finished())
        {
            if let Err(error) = self.poll_inner() {
                self.warn(error);
            }
        }
        if let Some(flight) = self.flight.take() {
            flight.cancel.store(true, Ordering::Relaxed);
            let _ = flight.handle.join();
        }
    }
}

impl Drop for SessionBridge {
    fn drop(&mut self) {
        self.finish();
    }
}

fn helper(config_path: &Path, raw: &[u8]) -> Result<i32> {
    let home = PathBuf::from(std::env::var_os("HOME").context("The callback HOME is missing.")?);
    // HOME 已由父进程解析；sandbox 内不能读取隔离目录的祖先路径。
    let parent = config_path
        .parent()
        .context("Invalid callback directory.")?;
    let name = parent
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let metadata = fs::symlink_metadata(parent).context("inspect callback directory")?;
    if !home.is_absolute()
        || parent.parent() != Some(home.as_path())
        || !name.starts_with(".sagy-statusline-")
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || config_path.file_name() != Some(OsStr::new("config.json"))
    {
        bail!("Invalid callback directory.");
    }
    let config: HelperConfig = serde_json::from_slice(
        &bounded_read(
            store::open_private_file(config_path, false).context("read callback configuration")?,
            MAX_SETTINGS,
        )
        .context("read callback configuration bytes")?,
    )?;
    if let Some(event) = event(raw) {
        // 桥接失败不能影响用户已有的状态栏命令。
        let _ = (|| -> Result<()> {
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            serde_json::to_writer(&mut temporary, &event)?;
            temporary.persist(parent.join("event.json"))?;
            Ok(())
        })();
    }
    let Some(command) = config.original_command else {
        return Ok(0);
    };
    let command = if let Some(suffix) = command.strip_prefix("~/") {
        format!("{}/{}", shell_quote(home.as_os_str())?, suffix)
    } else {
        command
    };
    let mut child = Command::new("/bin/sh")
        .args(["-c", &command])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn original status line")?;
    let input = child
        .stdin
        .take()
        .context("The original status line has no input.")?;
    // 原命令仍由 agy 的五秒上限约束；错误不能阻止已写好的额度事件。
    let writer = std::thread::spawn({
        let raw = raw.to_vec();
        move || {
            let mut input = input;
            input.write_all(&raw)
        }
    });
    let status = child.wait().context("wait original status line")?;
    let _ = writer.join();
    use std::os::unix::process::ExitStatusExt;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

pub(crate) fn helper_invocation(args: &[OsString]) -> Option<i32> {
    if args.get(1) != Some(&OsString::from(HELPER)) {
        return None;
    }
    let result = (|| -> Result<i32> {
        let [_, _, config] = args else {
            bail!("Invalid status callback invocation.")
        };
        let raw = bounded_read(std::io::stdin().lock(), MAX_INPUT)?;
        helper(Path::new(config), &raw)
    })();
    Some(result.unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "entry point used only by isolated status line callbacks"]
    fn fixture_helper_dispatch() {
        let path = std::env::var_os("SAGY_STATUSLINE_FIXTURE_CONFIG").unwrap();
        let raw = bounded_read(std::io::stdin().lock(), MAX_INPUT).unwrap();
        let result = helper(Path::new(&path), &raw);
        if let Err(error) = &result {
            eprintln!("{error:#}");
        }
        std::process::exit(result.unwrap_or(1));
    }

    #[test]
    fn parses_turn_metadata_without_storing_native_quota_or_identity() {
        let raw = br#"{"agent_state":"idle","quota":{"gemini-5h":{"remaining_fraction":0.8}},"context_window":{"remaining_percentage":99,"total_input_tokens":123,"total_output_tokens":45},"email":"not-stored@example.com","conversation_id":"turn-1"}"#;
        let parsed = event(raw).unwrap();
        assert_eq!(parsed.input_tokens, Some(123));
        let encoded = serde_json::to_string(&parsed).unwrap();
        assert!(!encoded.contains("email"));
        assert!(!encoded.contains("quota"));
        assert!(!encoded.contains("remaining"));
        assert!(event(br#"{"agent_state":"idle","conversation_id":"turn-1"}"#).is_some());
        for raw in [
            r#"{"agent_state":"idle","agent_state":"working"}"#,
            r#"{"agent_state":"bad"}"#,
            r#"{"agent_state":"idle","context_window":{"total_input_tokens":-1}}"#,
        ] {
            assert!(event(raw.as_bytes()).is_none());
        }
    }

    #[test]
    fn turn_detection_deduplicates_idle_and_recognizes_finished_cycles() {
        let mut payload = Event {
            state: "idle".into(),
            conversation: Some("conversation".into()),
            input_tokens: Some(1),
            output_tokens: Some(1),
        };
        assert!(completed_turn(None, &payload));
        assert!(!completed_turn(Some(&payload), &payload));
        let idle = payload.clone();
        payload.state = "working".into();
        assert!(!completed_turn(Some(&idle), &payload));
        assert!(completed_turn(Some(&payload), &idle));
        payload = idle.clone();
        payload.output_tokens = Some(2);
        assert!(completed_turn(Some(&idle), &payload));
        payload.conversation = None;
        assert!(!completed_turn(None, &payload));
    }

    #[test]
    fn shell_path_quoting_preserves_spaces_and_quotes() {
        assert_eq!(shell_quote(OsStr::new("a' b")).unwrap(), "'a'\\'' b'");
    }
}
