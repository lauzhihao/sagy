use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use super::runtime;
use crate::core::credential::StrictValue;

const MAX_OUTPUT_BYTES: usize = 256 * 1024;

pub(super) fn checked_arguments(args: &[OsString]) -> Result<&[OsString]> {
    const RESERVED: [&str; 6] = [
        "gemini_dir",
        "app_data_dir",
        "use_host_auth",
        "host_bridge_url",
        "read_host_bridge_token_from_stdin",
        "settings",
    ];
    for argument in args {
        let bytes = argument.as_bytes();
        let option = bytes.split(|byte| *byte == b'=').next().unwrap_or_default();
        let option = option
            .iter()
            .skip_while(|byte| **byte == b'-')
            .map(|byte| if *byte == b'-' { b'_' } else { *byte })
            .collect::<Vec<_>>();
        if bytes.starts_with(b"-")
            && RESERVED
                .iter()
                .any(|reserved| option == reserved.as_bytes())
        {
            bail!("An agy argument would override the isolated authentication settings.");
        }
    }
    Ok(if args.first().is_some_and(|argument| argument == "--") {
        &args[1..]
    } else {
        args
    })
}

fn takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "add-dir"
            | "agent"
            | "conversation"
            | "effort"
            | "input-format"
            | "json-schema"
            | "log-file"
            | "mode"
            | "model"
            | "output-format"
            | "p"
            | "print"
            | "print-timeout"
            | "project"
            | "prompt"
            | "prompt-interactive"
            | "i"
            | "settings"
    )
}

pub(super) fn group(args: &[OsString]) -> Option<&'static str> {
    let mut model = None;
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        let argument = argument.to_str()?;
        if argument == "--" {
            break;
        }
        if !argument.starts_with('-') {
            continue;
        }
        let (flag, inline) = argument
            .trim_start_matches('-')
            .split_once('=')
            .map_or((argument.trim_start_matches('-'), None), |(flag, value)| {
                (flag, Some(value))
            });
        if takes_value(flag) {
            let value = match inline {
                Some(value) => value,
                None => arguments.next()?.to_str()?,
            };
            if flag == "model" {
                model = Some(value.to_ascii_lowercase());
            }
        }
    }
    match model.as_deref() {
        None => Some("gemini"),
        Some(model) if model.starts_with("gemini-") => Some("gemini"),
        Some(model) if model.starts_with("claude-") || model.starts_with("gpt-") => Some("3p"),
        Some(_) => None,
    }
}

fn restart_arguments(args: &[OsString]) -> bool {
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        let Some(argument) = argument.to_str() else {
            return false;
        };
        let (option, inline) = argument
            .split_once('=')
            .map_or((argument, None), |(name, value)| (name, Some(value)));
        if option == "--dangerously-skip-permissions" && inline.is_none() {
            continue;
        }
        if !matches!(option, "--model" | "-model" | "--effort" | "-effort") {
            return false;
        }
        let value = inline.or_else(|| arguments.next()?.to_str());
        if value.is_none_or(|value| value.is_empty() || value.starts_with('-')) {
            return false;
        }
    }
    true
}

pub(super) fn can_restart_interactive(args: &[OsString]) -> bool {
    std::io::stdin().is_terminal() && restart_arguments(args)
}

fn windows(raw: &[u8], group: &str) -> [Option<f64>; 2] {
    if !matches!(group, "gemini" | "3p") || raw.len() > MAX_OUTPUT_BYTES {
        return [None; 2];
    }
    let Ok(StrictValue(value)) = serde_json::from_slice::<StrictValue>(raw) else {
        return [None; 2];
    };
    if value.get("status").and_then(|status| status.as_str()) != Some("SUCCESS")
        || value
            .pointer("/command/name")
            .and_then(|name| name.as_str())
            != Some("usage")
    {
        return [None; 2];
    }
    let Some(groups) = value
        .pointer("/command/data/groups")
        .and_then(|groups| groups.as_array())
    else {
        return [None; 2];
    };
    let expected = [format!("{group}-5h"), format!("{group}-weekly")];
    let mut seen = [false; 2];
    let mut remaining = [None; 2];
    for entry in groups {
        let Some(buckets) = entry.get("buckets").and_then(|buckets| buckets.as_array()) else {
            return [None; 2];
        };
        for bucket in buckets {
            let identity = bucket.get("id").and_then(|id| id.as_str());
            let Some(index) = expected.iter().position(|id| Some(id.as_str()) == identity) else {
                continue;
            };
            if seen[index] {
                return [None; 2];
            }
            seen[index] = true;
            let disabled = match bucket.get("disabled") {
                None => false,
                Some(serde_json::Value::Bool(value)) => *value,
                Some(_) => return [None; 2],
            };
            if disabled {
                remaining[index] = Some(0.0);
                continue;
            }
            match bucket.get("remaining_fraction") {
                None | Some(serde_json::Value::Null) => {}
                Some(fraction) => {
                    let Some(fraction) = fraction
                        .as_f64()
                        .filter(|fraction| fraction.is_finite() && (0.0..=1.0).contains(fraction))
                    else {
                        return [None; 2];
                    };
                    remaining[index] = Some(fraction);
                }
            }
        }
    }
    remaining
}

struct ProbeChild {
    child: Child,
    reaped: bool,
}

impl Drop for ProbeChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // 先清理独立进程组再回收 leader，防止 PID 复用和授权子进程残留。
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGTERM);
        }
        thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
fn bounded_output(command: &mut Command, timeout: Duration) -> Option<Vec<u8>> {
    bounded_output_cancellable(command, timeout, &AtomicBool::new(false))
}

fn bounded_output_cancellable(
    command: &mut Command,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Option<Vec<u8>> {
    if cancelled.load(Ordering::Relaxed) {
        return None;
    }
    // 原生 agy 即使 print 模式也可能探测 /dev/tty；独立 session 避免后台查询被 SIGTTIN 挂起。
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut process = ProbeChild {
        child,
        reaped: false,
    };
    let mut stdout = process.child.stdout.take()?;
    let descriptor = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return None;
    }
    let deadline = Instant::now().checked_add(timeout)?;
    let mut output = Vec::new();
    let mut buffer = [0; 16384];
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        super::observer::check_interrupted().ok()?;
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let mut polling = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, 100) as i32;
        let ready = unsafe { libc::poll(&mut polling, 1, milliseconds) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
        if ready == 0 {
            continue;
        }
        let available = (MAX_OUTPUT_BYTES + 1 - output.len()).min(buffer.len());
        match stdout.read(&mut buffer[..available]) {
            Ok(0) => break,
            Ok(count) => {
                output.extend_from_slice(&buffer[..count]);
                if output.len() > MAX_OUTPUT_BYTES {
                    return None;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return None,
        }
    }
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return None;
        }
        super::observer::check_interrupted().ok()?;
        if let Some(status) = process.child.try_wait().ok()? {
            process.reaped = true;
            return status.success().then_some(output);
        }
        let remaining = deadline.checked_duration_since(Instant::now())?;
        thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

pub(super) fn probe(
    binary: &runtime::Binary,
    home: &Path,
    group: &str,
    timeout: Duration,
) -> [Option<f64>; 2] {
    probe_cancellable(binary, home, group, timeout, &AtomicBool::new(false))
}

pub(super) fn probe_cancellable(
    binary: &runtime::Binary,
    home: &Path,
    group: &str,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> [Option<f64>; 2] {
    if !matches!(group, "gemini" | "3p") {
        return [None; 2];
    }
    let Ok(mut command) = runtime::command(binary, home) else {
        return [None; 2];
    };
    command
        .env("BROWSER", "/usr/bin/false")
        .args(["--output-format", "json", "-p", "/usage"]);
    bounded_output_cancellable(&mut command, timeout, cancelled)
        .map_or([None; 2], |raw| windows(&raw, group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn response(five_hour: serde_json::Value, weekly: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"status":"SUCCESS","command":{"name":"usage","data":{"groups":[{"buckets":[
                {"id":"gemini-5h","remaining_fraction":five_hour},
                {"id":"gemini-weekly","remaining_fraction":weekly}
            ]}]}}}),
        )
        .unwrap()
    }

    #[test]
    fn group_respects_model_flags_and_does_not_read_prompt_values_as_flags() {
        assert_eq!(group(&args(&[])), Some("gemini"));
        for flag in ["--model", "-model"] {
            assert_eq!(group(&args(&[flag, "claude-sonnet-4.5"])), Some("3p"));
            assert_eq!(
                group(&args(&[&format!("{flag}=gemini-3.7-pro-high")])),
                Some("gemini")
            );
        }
        assert_eq!(group(&args(&["--model=gpt-oss-120b"])), Some("3p"));
        assert_eq!(
            group(&args(&["-p", "--model=claude-sonnet-4.5"])),
            Some("gemini")
        );
        assert_eq!(
            group(&args(&["--", "--model=claude-sonnet-4.5"])),
            Some("gemini")
        );
        assert_eq!(group(&args(&["--model=unknown"])), None);
        assert_eq!(group(&args(&["--model"])), None);
    }

    #[test]
    fn argument_boundaries_preserve_args_and_restrict_replay() {
        use std::os::unix::ffi::OsStringExt;
        assert!(checked_arguments(&[OsString::from_vec(b"--settings=\xff".to_vec())]).is_err());
        let original = args(&["--", "--model=gemini-3.7-pro-high"]);
        assert_eq!(checked_arguments(&original).unwrap(), &original[1..]);
        for unsafe_arg in ["--settings={}", "-gemini_dir", "--app-data-dir=elsewhere"] {
            assert!(checked_arguments(&args(&[unsafe_arg])).is_err());
        }
        assert!(restart_arguments(&args(&[
            "--model=gemini-3.7-pro-high",
            "--effort",
            "high"
        ])));
        assert!(restart_arguments(&args(&[])));
        for replay in [
            args(&["-p", "hello"]),
            args(&["--continue"]),
            args(&["--conversation", "fixture"]),
            args(&["--model"]),
            args(&["--effort="]),
        ] {
            assert!(!restart_arguments(&replay));
        }
    }

    #[test]
    fn quota_keeps_separate_windows_and_zero_without_filling_unknown_values() {
        assert_eq!(
            windows(&response(json!(0), json!(0.8)), "gemini"),
            [Some(0.0), Some(0.8)]
        );
        assert_eq!(
            windows(&response(json!(null), json!(0.4)), "gemini"),
            [None, Some(0.4)]
        );
        assert_eq!(windows(&response(json!(1), json!(0.8)), "3p"), [None; 2]);
        for invalid in [json!(true), json!("0.4"), json!(-0.1), json!(1.1)] {
            assert_eq!(windows(&response(invalid, json!(1)), "gemini"), [None; 2]);
        }
        let mut unrelated: serde_json::Value =
            serde_json::from_slice(&response(json!(0.5), json!(0.8))).unwrap();
        unrelated["command"]["data"]["groups"][0]["buckets"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"unrelated", "disabled":"unexpected", "remaining_fraction":true}));
        assert_eq!(
            windows(&serde_json::to_vec(&unrelated).unwrap(), "gemini"),
            [Some(0.5), Some(0.8)]
        );
        let disabled = br#"{"status":"SUCCESS","command":{"name":"usage","data":{"groups":[{"buckets":[{"id":"gemini-5h","disabled":true}]}]}}}"#;
        assert_eq!(windows(disabled, "gemini"), [Some(0.0), None]);
        let duplicate = br#"{"status":"SUCCESS","status":"SUCCESS","command":{"name":"usage","data":{"groups":[]}}}"#;
        assert_eq!(windows(duplicate, "gemini"), [None; 2]);
        assert_eq!(
            windows(&vec![b'x'; MAX_OUTPUT_BYTES + 1], "gemini"),
            [None; 2]
        );
    }

    #[test]
    fn quota_probe_bounds_volume_time_and_checks_child_status() {
        let mut success = Command::new("/bin/sh");
        success.args(["-c", "printf fixture"]);
        assert_eq!(
            bounded_output(&mut success, Duration::from_secs(2)).unwrap(),
            b"fixture"
        );
        let mut failure = Command::new("/bin/sh");
        failure.args(["-c", "printf fixture; exit 7"]);
        assert!(bounded_output(&mut failure, Duration::from_secs(2)).is_none());
        let mut flood = Command::new("/usr/bin/head");
        flood.args(["-c", "300000", "/dev/zero"]);
        assert!(bounded_output(&mut flood, Duration::from_secs(2)).is_none());
        let mut timeout = Command::new("/bin/sleep");
        timeout.arg("10");
        let started = Instant::now();
        assert!(bounded_output(&mut timeout, Duration::from_millis(40)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
