//! 本机订阅账号池沿用 agy 的独立 HOME 和已有 v1 注册表。
mod cache;
mod observer;
mod quota;
mod repo_sync;
mod runtime;
mod statusline;
mod store;

use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use runtime::Binary;
use store::State;

const USAGE: &str = "Usage:
  sagy                         Start auto with Gemini 3.8 Flash High and auto-approved tools
  sagy -p PROMPT [options]     Print one response with those defaults
  sagy-profile login NAME
  sagy-profile run NAME [agy arguments...]
  sagy use NAME|INDEX [agy arguments...]  Open an account by label/email or list number
  sagy-profile auto [agy arguments...]
  sagy-profile list             Read the local quota snapshot
  sagy-profile refresh [NAME]   Refresh quota snapshots (parallel across accounts)
  sagy push [REPO] [options]    Push encrypted native profiles
  sagy pull [REPO] [options]    Import missing native profiles

NAME can be a short label or an email address. After sign-in in agy, enter /exit.
auto prefers the highest available model-group quota and switches fresh interactive sessions on HTTP 429.
auto excludes profiles with known weekly quota below 5%.
Quota snapshots follow live native status updates and refresh after login/normal exit (up to 8 seconds).
SAGY_PROFILE_ROOT and AGY_BIN accept absolute paths.";

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn note(message: impl std::fmt::Display) {
    eprintln!("[sagy-profile] {message}");
}

fn name(arg: &OsStr) -> Result<String> {
    store::valid_name(
        arg.to_str()
            .ok_or_else(|| anyhow!("Invalid profile name."))?,
    )
}

fn lease(home: &Path) -> Result<File> {
    store::try_lease(home)?.ok_or_else(|| anyhow!("The selected profile is already running."))
}

fn physical_directory(home: &Path) -> Result<String> {
    home.parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("The profile home has no valid directory."))
}

fn login(root: &Path, binary: &Binary, name: String) -> Result<i32> {
    let (home, _lease) = {
        let _registry = store::lock_registry(root)?;
        let state = store::read_state(root)?;
        let home = store::profile_home(root, &state, &name, true)?;
        let lock = lease(&home)?;
        (home, lock)
    };
    let reset_time = now();
    if let Err(error) = physical_directory(&home).and_then(|directory| {
        cache::merge(
            root,
            [cache::Update {
                name: name.clone(),
                directory,
                windows: [None; 2],
                started_at: reset_time,
                finished_at: reset_time,
                result: cache::Outcome::Reset,
            }],
        )
    }) {
        note(format!("Could not reset the quota snapshot: {error}"));
    }
    note(format!(
        "Authorizing profile {name}. Follow agy sign-in instructions, then enter /exit."
    ));
    let code = runtime::launch(binary, &home, &[])?;
    if code != 0 {
        note("Login did not finish successfully; profile registration was left unchanged.");
        return Ok(code);
    }
    if !store::token_ready(&home)? {
        bail!("No resumable login was saved. Run login for this profile again.");
    }
    {
        let _registry = store::lock_registry(root)?;
        let mut state = store::read_state(root)?;
        if !state.profiles.contains(&name) {
            state.profiles.push(name.clone());
            store::write_state(root, &state)?;
        }
    }
    refresh_after_exit(root, binary, &name, &home, code);
    note(format!("Profile {name} is ready."));
    Ok(0)
}

fn live_bridge(
    root: &Path,
    home: &Path,
    name: &str,
    binary: &Binary,
) -> Option<statusline::SessionBridge> {
    statusline::SessionBridge::prepare(root, home, name, binary)
        .inspect_err(|error| note(format!("Could not enable live quota updates: {error}")))
        .ok()
}

pub(crate) fn statusline_helper(args: &[OsString]) -> Option<i32> {
    statusline::helper_invocation(args)
}

fn run_named(root: &Path, binary: &Binary, name: String, args: &[OsString]) -> Result<i32> {
    let (home, _lease) = {
        let _registry = store::lock_registry(root)?;
        let state = store::read_state(root)?;
        if !state.profiles.contains(&name) {
            bail!("This profile has not completed login.");
        }
        let home = store::profile_home(root, &state, &name, false)?;
        let lock = lease(&home)?;
        (home, lock)
    };
    if !store::token_ready(&home)? {
        bail!("The selected profile needs login again.");
    }
    note(format!("Using profile {name}."));
    let mut bridge = live_bridge(root, &home, &name, binary);
    let mut command = runtime::command(binary, &home)?;
    if let Some(bridge) = &bridge {
        bridge.configure(&mut command);
    }
    let code = runtime::launch_with_poll(command, args, || {
        if let Some(bridge) = &mut bridge {
            bridge.poll();
        }
    });
    if let Some(bridge) = &mut bridge {
        bridge.finish();
    }
    let code = code?;
    refresh_after_exit(root, binary, &name, &home, code);
    Ok(code)
}

struct Measurement {
    status: &'static str,
    windows: [Option<f64>; 2],
    started_at: f64,
    finished_at: f64,
}

impl Measurement {
    fn score(&self) -> Option<f64> {
        // 任一时间窗口已耗尽时，另一个窗口缺失也不应再次选择该账号。
        if self.windows.contains(&Some(0.0)) {
            return Some(0.0);
        }
        Some(self.windows[0]?.min(self.windows[1]?))
    }
}

fn measure(
    root: &Path,
    state: &State,
    name: &str,
    binary: Option<&Binary>,
    group: Option<&str>,
    timeout: Duration,
) -> Result<Measurement> {
    let started_at = now();
    let missing = Measurement {
        status: "needs-login",
        windows: [None; 2],
        started_at,
        finished_at: started_at,
    };
    let home = match store::profile_home(root, state, name, false) {
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
        {
            return Ok(missing);
        }
        other => other?,
    };
    let Some(_lock) = store::try_lease(&home)? else {
        return Ok(Measurement {
            status: "busy",
            windows: [None; 2],
            started_at,
            finished_at: now(),
        });
    };
    if !store::token_ready(&home)? {
        return Ok(missing);
    }
    let windows = binary
        .zip(group)
        .map_or([None; 2], |(bin, g)| quota::probe(bin, &home, g, timeout));
    Ok(Measurement {
        status: "ready",
        windows,
        started_at,
        finished_at: now(),
    })
}

fn measurements(
    root: &Path,
    state: &State,
    names: Vec<String>,
    binary: Option<&Binary>,
    group: Option<&str>,
    timeout: Duration,
) -> Result<BTreeMap<String, Measurement>> {
    let count = names.len().min(8);
    let queue = Mutex::new(VecDeque::from(names));
    std::thread::scope(|scope| {
        let handles = (0..count)
            .map(|_| {
                scope.spawn(|| -> Result<Vec<_>> {
                    let mut rows = Vec::new();
                    loop {
                        observer::check_interrupted()?;
                        let next = queue.lock().expect("profile probe queue").pop_front();
                        let Some(name) = next else { break };
                        let measurement = measure(root, state, &name, binary, group, timeout)?;
                        rows.push((name, measurement));
                    }
                    Ok(rows)
                })
            })
            .collect::<Vec<_>>();
        let mut all = BTreeMap::new();
        for handle in handles {
            all.extend(
                handle
                    .join()
                    .map_err(|_| anyhow!("Profile probe worker stopped unexpectedly."))??,
            );
        }
        observer::check_interrupted()?;
        Ok(all)
    })
}

fn snapshot(root: &Path) -> Result<State> {
    let _registry = store::lock_registry(root)?;
    store::read_state(root)
}

fn record_measurements(
    root: &Path,
    state: &State,
    results: &BTreeMap<String, Measurement>,
) -> Result<()> {
    let updates = results.iter().map(|(name, data)| cache::Update {
        name: name.clone(),
        directory: state.directories.get(name).unwrap_or(name).clone(),
        windows: data.windows,
        started_at: data.started_at,
        finished_at: data.finished_at,
        result: match data.status {
            "busy" => cache::Outcome::Busy,
            "needs-login" => cache::Outcome::NeedsLogin,
            _ if data.windows.iter().any(Option::is_some) => cache::Outcome::Ready,
            _ => cache::Outcome::Unavailable,
        },
    });
    cache::merge(root, updates)
}

// 调用方仍持有原 lease，不能再次 try_lease；缓存失败不改变会话退出码。
fn refresh_after_exit(root: &Path, binary: &Binary, name: &str, home: &Path, code: i32) {
    if code >= 128 {
        return;
    }
    let result = (|| -> Result<()> {
        let _signals = observer::SignalGuard::install()?;
        let started_at = now();
        let windows = quota::probe(binary, home, "gemini", Duration::from_secs(8));
        observer::check_interrupted()?;
        let finished_at = now();
        cache::merge(
            root,
            [cache::Update {
                name: name.into(),
                directory: physical_directory(home)?,
                windows,
                started_at,
                finished_at,
                result: if windows.iter().any(Option::is_some) {
                    cache::Outcome::Ready
                } else {
                    cache::Outcome::Unavailable
                },
            }],
        )
    })();
    if let Err(error) = result {
        note(format!(
            "Could not update the quota snapshot after exit: {error}"
        ));
    }
}

fn refresh(root: &Path, binary: &Binary, name: Option<String>) -> Result<i32> {
    let state = snapshot(root)?;
    let names = if let Some(name) = name {
        if !state.profiles.contains(&name) {
            bail!("This profile has not completed login.");
        }
        vec![name]
    } else {
        state.profiles.clone()
    };
    if !names.is_empty() {
        let _signals = observer::SignalGuard::install()?;
        let results = measurements(
            root,
            &state,
            names,
            Some(binary),
            Some("gemini"),
            Duration::from_secs(25),
        )?;
        record_measurements(root, &state, &results)?;
    }
    list(root)
}

fn quota_age(entry: Option<&cache::Entry>) -> String {
    let Some(entry) = entry else {
        return "--".into();
    };
    let age = entry.sampled_at.map_or_else(
        || "--".into(),
        |time| {
            let seconds = (now() - time).max(0.0) as u64;
            if seconds < 60 {
                format!("{seconds}s")
            } else if seconds < 3600 {
                format!("{}m", seconds / 60)
            } else if seconds < 86400 {
                format!("{}h", seconds / 3600)
            } else {
                format!("{}d", seconds / 86400)
            }
        },
    );
    if entry.result == cache::Outcome::Ready {
        age
    } else {
        format!("{age} (last-attempt: {})", entry.result.label())
    }
}

// 列表与序号选择共用同一份本地排序，避免索引误用注册顺序或自动选号过滤。
fn list_accounts(root: &Path, state: &State) -> Result<Vec<(String, Measurement, String)>> {
    let cached = cache::read(root).unwrap_or_else(|error| {
        note(error);
        cache::Snapshot::default()
    });
    let mut accounts = Vec::new();
    for name in &state.profiles {
        let mut data = measure(root, state, name, None, None, Duration::ZERO)?;
        let entry = cached
            .profiles
            .get(name)
            .filter(|entry| &entry.directory == state.directories.get(name).unwrap_or(name));
        data.windows = entry.map_or([None; 2], |entry| entry.windows);
        accounts.push((name.clone(), data, quota_age(entry)));
    }
    accounts.sort_by(|a, b| {
        b.1.score()
            .partial_cmp(&a.1.score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(accounts)
}

fn use_name(root: &Path, argument: &OsStr) -> Result<String> {
    if let Some(number) = argument
        .to_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
    {
        let state = snapshot(root)?;
        let accounts = list_accounts(root, &state)?;
        if accounts.is_empty() {
            bail!("No profiles. Run sagy login NAME first.");
        }
        let index = number.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
        return index
            .and_then(|index| accounts.get(index))
            .map(|(name, _, _)| name.clone())
            .ok_or_else(|| {
                anyhow!(
                    "Invalid profile number. Run sagy list and choose a number from 1 to {}.",
                    accounts.len()
                )
            });
    }
    name(argument)
}

fn list(root: &Path) -> Result<i32> {
    let state = snapshot(root)?;
    if state.profiles.is_empty() {
        note("No profiles. Run sagy-profile login NAME for each subscription.");
        return Ok(0);
    }
    let accounts = list_accounts(root, &state)?;
    let mut rows = vec![["#", "Profile", "Status", "5h", "weekly", "Quota age"].map(str::to_owned)];
    for (i, (name, data, age)) in accounts.into_iter().enumerate() {
        let status = if data.status == "ready" && cooling(&state, &name) {
            "cooldown"
        } else {
            data.status
        };
        let [short, weekly] = data
            .windows
            .map(|w| w.map_or_else(|| "--".into(), |v| format!("{:.2}%", 100. * v)));
        rows.push([
            (i + 1).to_string(),
            name.clone(),
            status.into(),
            short,
            weekly,
            age,
        ]);
    }
    let widths: [usize; 6] =
        std::array::from_fn(|i| rows.iter().map(|r| r[i].len()).max().unwrap_or_default());
    let border = |left, joint: &str, right| {
        let line = widths.map(|w| "─".repeat(w + 2)).join(joint);
        eprintln!("{left}{line}{right}");
    };
    border('┌', "┬", '┐');
    for (i, row) in rows.iter().enumerate() {
        if i > 0 {
            border('├', "┼", '┤');
        }
        let cells = row
            .iter()
            .zip(widths)
            .map(|(v, w)| format!("{v:<w$}"))
            .collect::<Vec<_>>();
        eprintln!("│ {} │", cells.join(" │ "));
    }
    border('└', "┴", '┘');
    Ok(0)
}

fn cooling(state: &State, name: &str) -> bool {
    state
        .cooldowns
        .get(name)
        .is_some_and(|until| *until > now())
}

struct Selected {
    name: String,
    home: PathBuf,
    score: Option<f64>,
    _lease: File,
}

fn select(
    root: &Path,
    binary: &Binary,
    group: Option<&str>,
    attempted: &HashSet<String>,
) -> Result<Option<Selected>> {
    let before = snapshot(root)?;
    let names = before
        .profiles
        .iter()
        .filter(|n| !attempted.contains(*n) && !cooling(&before, n))
        .cloned()
        .collect();
    let results = measurements(
        root,
        &before,
        names,
        Some(binary),
        group,
        Duration::from_secs(8),
    )?;
    if group == Some("gemini") {
        if let Err(error) = record_measurements(root, &before, &results) {
            note(format!("Could not update the quota snapshot: {error}"));
        }
    }
    let _registry = store::lock_registry(root)?;
    let state = store::read_state(root)?;
    let mut ordered = state.profiles.clone();
    ordered.sort();
    if let Some(i) = ordered
        .iter()
        .position(|n| Some(n) == state.last_selected.as_ref())
    {
        ordered.rotate_left(i + 1);
    }
    let mut eligible = ordered
        .into_iter()
        .filter_map(|name| {
            let data = results.get(&name)?;
            (data.status == "ready"
                && data.score() != Some(0.)
                && data.windows[1].is_none_or(|weekly| weekly >= 0.05)
                && !cooling(&state, &name)
                && state.directories.get(&name) == before.directories.get(&name))
            .then(|| (name, data.score()))
        })
        .collect::<Vec<_>>();
    eligible.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    for (name, score) in eligible {
        let home = match store::profile_home(root, &state, &name, false) {
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
            {
                continue;
            }
            result => result?,
        };
        let Some(lock) = store::try_lease(&home)? else {
            continue;
        };
        if !store::token_ready(&home)? {
            continue;
        }
        return Ok(Some(Selected {
            name,
            home,
            score,
            _lease: lock,
        }));
    }
    Ok(None)
}

fn mark_limited(root: &Path, name: &str) -> Result<()> {
    let _registry = store::lock_registry(root)?;
    let mut state = store::read_state(root)?;
    let timestamp = now();
    state.cooldowns.retain(|_, until| *until > timestamp);
    state.cooldowns.insert(name.into(), timestamp + 300.);
    store::write_state(root, &state)?;
    note(format!(
        "Profile {name} reported HTTP 429; cooling down for 5 minutes."
    ));
    Ok(())
}

fn auto(root: &Path, binary: &Binary, args: &[OsString]) -> Result<i32> {
    if args.iter().any(|arg| {
        let opt = arg.to_string_lossy();
        opt.starts_with('-')
            && opt
                .split('=')
                .next()
                .unwrap_or("")
                .trim_start_matches('-')
                .replace('_', "-")
                == "log-file"
    }) {
        bail!("auto uses a private agy log to observe HTTP 429; use run for a custom --log-file.");
    }
    let group = quota::group(args);
    let mut attempted = HashSet::new();
    let mut selected = {
        let _signals = observer::SignalGuard::install()?;
        let candidate = select(root, binary, group, &attempted)?;
        observer::check_interrupted()?;
        candidate.ok_or_else(|| anyhow!("No eligible idle profile. Check login, cooldowns, exhausted quota, or weekly quota below 5%."))?
    };
    loop {
        let Selected {
            name,
            home,
            score,
            _lease,
        } = selected;
        {
            let _registry = store::lock_registry(root)?;
            let mut state = store::read_state(root)?;
            state.last_selected = Some(name.clone());
            store::write_state(root, &state)?;
        }
        attempted.insert(name.clone());
        let summary = score.map_or_else(
            || "quota unknown".into(),
            |v| format!("{} quota {:.1}%", group.unwrap_or("unknown"), v * 100.),
        );
        note(format!("Using profile {name} ({summary})."));
        let mut successor = None;
        let mut bridge = live_bridge(root, &home, &name, binary);
        let mut command = runtime::command(binary, &home)?;
        if let Some(bridge) = &bridge {
            bridge.configure(&mut command);
        }
        let code = observer::launch_observed_with_poll(
            command,
            &home,
            args,
            |allow_restart| {
                if let Err(error) = mark_limited(root, &name) {
                    note(format!(
                        "Could not save the cooldown; keeping this session: {error}"
                    ));
                    return Ok(false);
                }
                if allow_restart && quota::can_restart_interactive(args) {
                    successor = match select(root, binary, group, &attempted) {
                        Ok(candidate) => candidate,
                        Err(error) => {
                            note(format!(
                                "Could not reserve an alternate profile; keeping this session: {error}"
                            ));
                            None
                        }
                    };
                    if let Err(error) = binary.check() {
                        successor = None;
                        note(format!("Could not verify agy for another session: {error}"));
                    }
                    if successor.is_none() {
                        note(
                            "No available alternate profile; leaving the current session in control.",
                        );
                    }
                }
                Ok(successor.is_some())
            },
            || {
                if let Some(bridge) = &mut bridge {
                    bridge.poll();
                }
            },
        );
        if let Some(bridge) = &mut bridge {
            bridge.finish();
        }
        let (code, switched) = code?;
        if !switched {
            refresh_after_exit(root, binary, &name, &home, code);
            return Ok(code);
        }
        drop(_lease);
        match successor {
            Some(next) => {
                note(
                    "Starting a fresh session on the alternate profile. Previous work stays in the original session.",
                );
                selected = next;
            }
            None => return Ok(code),
        }
    }
}

pub(crate) fn run(args: &[OsString], shortcut: bool) -> Result<i32> {
    interrupt_exit(dispatch(args, shortcut, runtime::verified_binary))
}

fn interrupt_exit(result: Result<i32>) -> Result<i32> {
    match result {
        Err(error) if error.is::<observer::ObserverInterrupted>() => {
            Ok(128 + error.downcast::<observer::ObserverInterrupted>()?.signal)
        }
        result => result,
    }
}

fn dispatch(args: &[OsString], shortcut: bool, verify: fn() -> Result<Binary>) -> Result<i32> {
    // 与原启动器一致，agy 及其子工具生成的文件默认只供当前用户访问。
    unsafe {
        libc::umask(0o077);
    }
    let expanded;
    let args = if shortcut && (args.is_empty() || args.first().is_some_and(|arg| arg == "-p")) {
        expanded = [
            "auto",
            "--model",
            "gemini-3.8-flash-high",
            "--dangerously-skip-permissions",
        ]
        .map(OsString::from)
        .into_iter()
        .chain(args.iter().cloned())
        .collect::<Vec<_>>();
        &expanded
    } else {
        args
    };
    let Some((action, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return Ok(0);
    };
    if rest.is_empty() && ["-h", "--help", "help"].iter().any(|flag| action == flag) {
        eprintln!("{USAGE}");
        return Ok(0);
    }
    match (action.to_str(), rest) {
        (Some("push" | "pull"), extra) => {
            repo_sync::run(&store::root_directory()?, action == "push", extra)
        }
        (Some("list"), []) => list(&store::root_directory()?),
        (Some("refresh"), []) => refresh(&store::root_directory()?, &verify()?, None),
        (Some("refresh"), [label]) => {
            let label = name(label)?;
            refresh(&store::root_directory()?, &verify()?, Some(label))
        }
        (Some("login"), [label]) => {
            let label = name(label)?;
            let binary = verify()?;
            login(&store::root_directory()?, &binary, label)
        }
        (Some("run"), [label, extra @ ..]) => {
            let label = name(label)?;
            let args = quota::checked_arguments(extra)?;
            let binary = verify()?;
            run_named(&store::root_directory()?, &binary, label, args)
        }
        (Some("use"), [label, extra @ ..]) => {
            let root = store::root_directory()?;
            let label = use_name(&root, label)?;
            let extra = quota::checked_arguments(extra)?;
            let args: Vec<OsString> = [
                "--model",
                "gemini-3.8-flash-high",
                "--dangerously-skip-permissions",
            ]
            .map(OsString::from)
            .into_iter()
            .chain(extra.iter().cloned())
            .collect();
            let binary = verify()?;
            run_named(&root, &binary, label, &args)
        }
        (Some("auto"), extra) => {
            let args = quota::checked_arguments(extra)?;
            let binary = verify()?;
            auto(&store::root_directory()?, &binary, args)
        }
        _ => bail!("Invalid command. Run sagy-profile --help."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // 测试进程使用临时目录内的假 agy，正式二进制始终校验真实 agy 的摘要。
    #[test]
    #[ignore = "entry point used only by the isolated subprocess tests"]
    fn fixture_dispatch() {
        let Ok(raw) = std::env::var("SAGY_FIXTURE_ARGS") else {
            return;
        };
        let args: Vec<String> = serde_json::from_str(&raw).unwrap();
        let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
        let verify: fn() -> Result<Binary> = if std::env::var_os("SAGY_FIXTURE_CHECK_PIN").is_some()
        {
            runtime::verified_binary
        } else {
            || Binary::fixture(PathBuf::from(std::env::var_os("AGY_BIN").unwrap()))
        };
        match interrupt_exit(dispatch(
            &args,
            std::env::var_os("SAGY_FIXTURE_SHORTCUT").is_some(),
            verify,
        )) {
            Ok(code) => std::process::exit(code),
            Err(err) => {
                note(err);
                std::process::exit(1);
            }
        }
    }

    #[test]
    fn isolated_profile_cli() {
        let status = Command::new("/usr/bin/python3")
            .arg("-B")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/test_sagy_profile.py"
            ))
            .env("SAGY_NATIVE_TEST_EXE", std::env::current_exe().unwrap())
            .status()
            .unwrap();
        assert!(status.success());
    }
}
