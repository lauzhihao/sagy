//! 后台检测托管桌面的新登录；不让身份查询阻塞桌面进程的退出与信号处理。
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::desktop_import::{self, Candidate, ImportOutcome, Importer};
use super::util::write_stderr_line;

type Fingerprint = [u8; 32];
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const RETRY_MIN: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(30);
const COMPLETED_LIMIT: usize = 256;

trait Backend: Send + 'static {
    type Candidate;

    fn read(&mut self) -> Result<Option<Self::Candidate>>;
    fn fingerprint(candidate: &Self::Candidate) -> Fingerprint;
    fn import(&mut self, candidate: Self::Candidate) -> Result<ImportOutcome>;
}

struct FileBackend {
    token_path: PathBuf,
    importer: Importer,
}

impl Backend for FileBackend {
    type Candidate = Candidate;

    fn read(&mut self) -> Result<Option<Candidate>> {
        desktop_import::read_candidate(&self.token_path)
    }

    fn fingerprint(candidate: &Candidate) -> Fingerprint {
        candidate.fingerprint()
    }

    fn import(&mut self, candidate: Candidate) -> Result<ImportOutcome> {
        self.importer.import(candidate)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Added(String),
    AlreadyRegistered(String),
    Retry,
    ReadUnavailable,
    FinalUnavailable,
}

fn report(event: Event) {
    match event {
        Event::Added(email) => {
            write_stderr_line(format!(
                "[sagy] Added desktop account {email}. Run sagy list to view it."
            ));
        }
        Event::AlreadyRegistered(email) => {
            write_stderr_line(format!(
                "[sagy] Desktop account {email} is already registered; its existing login was preserved."
            ));
        }
        Event::Retry => {
            write_stderr_line(
                "[sagy] Desktop account synchronization is pending; retrying automatically.",
            );
        }
        Event::ReadUnavailable => {
            write_stderr_line(
                "[sagy] Desktop account credentials could not be read; waiting for a valid file.",
            );
        }
        Event::FinalUnavailable => {
            write_stderr_line(
                "[sagy] Desktop account synchronization did not complete before exit; sign in again and wait for the account confirmation.",
            );
        }
    }
}

struct Pending {
    fingerprint: Fingerprint,
    retry_at: Instant,
    retry_delay: Duration,
    reported: bool,
}

struct State {
    baseline: Fingerprint,
    completed: VecDeque<Fingerprint>,
    pending: Option<Pending>,
    read_reported: bool,
}

impl State {
    fn new(baseline: Fingerprint) -> Self {
        Self {
            baseline,
            completed: VecDeque::new(),
            pending: None,
            read_reported: false,
        }
    }

    fn tick<B: Backend>(
        &mut self,
        backend: &mut B,
        report: &mut impl FnMut(Event),
        now: Instant,
        final_read: bool,
    ) {
        let candidate = match backend.read() {
            Ok(Some(candidate)) => {
                self.read_reported = false;
                candidate
            }
            Ok(None) => {
                self.pending = None;
                self.read_reported = false;
                return;
            }
            Err(_) => {
                self.pending = None;
                if final_read {
                    report(Event::FinalUnavailable);
                } else if !self.read_reported {
                    report(Event::ReadUnavailable);
                    self.read_reported = true;
                }
                return;
            }
        };
        let fingerprint = B::fingerprint(&candidate);
        if fingerprint == self.baseline || self.completed.contains(&fingerprint) {
            self.pending = None;
            return;
        }
        let stable = self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.fingerprint == fingerprint);
        if !stable {
            self.pending = Some(Pending {
                fingerprint,
                retry_at: now,
                retry_delay: RETRY_MIN,
                reported: false,
            });
        }
        // 正常轮询至少连续两次读到同一份有效凭据；停止后文件已静止，只读一次。
        if !final_read && (!stable || now < self.pending.as_ref().unwrap().retry_at) {
            return;
        }
        match backend.import(candidate) {
            Ok(ImportOutcome::Added(email)) => {
                self.complete(fingerprint);
                report(Event::Added(email));
            }
            Ok(ImportOutcome::AlreadyRegistered(email)) => {
                self.complete(fingerprint);
                report(Event::AlreadyRegistered(email));
            }
            Ok(ImportOutcome::Superseded) => {
                self.pending = None;
                if final_read {
                    report(Event::FinalUnavailable);
                }
            }
            Ok(ImportOutcome::Busy) | Err(_) => {
                if final_read {
                    report(Event::FinalUnavailable);
                    return;
                }
                let pending = self.pending.as_mut().unwrap();
                pending.retry_at = Instant::now().max(now) + pending.retry_delay;
                pending.retry_delay = (pending.retry_delay * 2).min(RETRY_MAX);
                if !pending.reported {
                    report(Event::Retry);
                    pending.reported = true;
                }
            }
        }
    }

    fn complete(&mut self, fingerprint: Fingerprint) {
        if self.completed.len() == COMPLETED_LIMIT {
            self.completed.pop_front();
        }
        self.completed.push_back(fingerprint);
        self.pending = None;
    }
}

pub(super) struct Watcher {
    finish: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    pub(super) fn start(root: PathBuf, token_path: PathBuf, baseline: Fingerprint) -> Result<Self> {
        let importer = Importer::new(root, token_path.clone())?;
        Self::spawn(
            FileBackend {
                token_path,
                importer,
            },
            baseline,
            POLL_INTERVAL,
            report,
        )
    }

    fn spawn<B: Backend>(
        backend: B,
        baseline: Fingerprint,
        interval: Duration,
        report: impl FnMut(Event) + Send + 'static,
    ) -> Result<Self> {
        let (finish, receiver) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("sagy-desktop-account-sync".into())
            .spawn(move || run(backend, baseline, interval, receiver, report))
            .context("Could not start desktop account synchronization.")?;
        Ok(Self {
            finish: Some(finish),
            thread: Some(thread),
        })
    }

    pub(super) fn finish(&mut self) {
        if let Some(finish) = self.finish.take() {
            let _ = finish.send(());
        }
        if self
            .thread
            .take()
            .is_some_and(|thread| thread.join().is_err())
        {
            write_stderr_line("[sagy] Desktop account synchronization stopped unexpectedly.");
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.finish();
    }
}

fn run<B: Backend>(
    mut backend: B,
    baseline: Fingerprint,
    interval: Duration,
    receiver: Receiver<()>,
    mut report: impl FnMut(Event),
) {
    let mut state = State::new(baseline);
    loop {
        match receiver.recv_timeout(interval) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                // 最多等待在途请求和这里的一次最终尝试，不在退出路径继续退避重试。
                state.tick(&mut backend, &mut report, Instant::now(), true);
                return;
            }
            Err(RecvTimeoutError::Timeout) => {
                state.tick(&mut backend, &mut report, Instant::now(), false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};

    use anyhow::bail;
    use fs2::FileExt;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::profile::store;

    struct Mock {
        current: Arc<Mutex<Option<u8>>>,
        calls: Arc<Mutex<Vec<u8>>>,
        import: Box<dyn FnMut(u8) -> Result<ImportOutcome> + Send>,
    }

    impl Mock {
        fn new(current: Option<u8>) -> Self {
            Self {
                current: Arc::new(Mutex::new(current)),
                calls: Arc::new(Mutex::new(Vec::new())),
                import: Box::new(|candidate| {
                    Ok(ImportOutcome::Added(format!(
                        "account{candidate}@example.test"
                    )))
                }),
            }
        }
    }

    impl Backend for Mock {
        type Candidate = u8;

        fn read(&mut self) -> Result<Option<u8>> {
            Ok(*self.current.lock().unwrap())
        }

        fn fingerprint(candidate: &u8) -> Fingerprint {
            [*candidate; 32]
        }

        fn import(&mut self, candidate: u8) -> Result<ImportOutcome> {
            self.calls.lock().unwrap().push(candidate);
            (self.import)(candidate)
        }
    }

    #[test]
    fn baseline_partial_writes_and_completed_fingerprints_do_not_import() {
        let mut backend = Mock::new(Some(0));
        let mut state = State::new([0; 32]);
        let start = Instant::now();
        let mut events = Vec::new();
        for (tick, candidate) in [
            Some(0),
            None,
            Some(1),
            None,
            Some(1),
            Some(1),
            Some(1),
            Some(0),
            Some(1),
        ]
        .into_iter()
        .enumerate()
        {
            *backend.current.lock().unwrap() = candidate;
            state.tick(
                &mut backend,
                &mut |event| events.push(event),
                start + POLL_INTERVAL * tick as u32,
                false,
            );
        }
        assert_eq!(*backend.calls.lock().unwrap(), vec![1]);
        assert_eq!(events, vec![Event::Added("account1@example.test".into())]);
    }

    #[test]
    fn busy_and_network_errors_back_off_but_new_credentials_start_a_fresh_attempt() {
        let mut backend = Mock::new(Some(1));
        let mut attempt = 0;
        backend.import = Box::new(move |candidate| {
            attempt += 1;
            match attempt {
                1 => Ok(ImportOutcome::Busy),
                2 => bail!("synthetic private failure that must not enter events"),
                _ => Ok(ImportOutcome::AlreadyRegistered(format!(
                    "account{candidate}@example.test"
                ))),
            }
        });
        let mut state = State::new([0; 32]);
        let start = Instant::now();
        let mut events = Vec::new();
        for millis in [0, 500, 1000, 2499, 2500, 6499, 6500] {
            state.tick(
                &mut backend,
                &mut |event| events.push(event),
                start + Duration::from_millis(millis),
                false,
            );
        }
        assert_eq!(*backend.calls.lock().unwrap(), vec![1, 1, 1]);
        assert_eq!(
            events,
            vec![
                Event::Retry,
                Event::AlreadyRegistered("account1@example.test".into())
            ]
        );
        *backend.current.lock().unwrap() = Some(2);
        for millis in [6501, 7001] {
            state.tick(
                &mut backend,
                &mut |event| events.push(event),
                start + Duration::from_millis(millis),
                false,
            );
        }
        assert_eq!(*backend.calls.lock().unwrap(), vec![1, 1, 1, 2]);
    }

    #[test]
    fn a_superseded_snapshot_requires_stability_again_for_the_new_snapshot() {
        let mut backend = Mock::new(Some(1));
        let current = backend.current.clone();
        backend.import = Box::new(move |candidate| {
            if candidate == 1 {
                *current.lock().unwrap() = Some(2);
                Ok(ImportOutcome::Superseded)
            } else {
                Ok(ImportOutcome::Added("second@example.test".into()))
            }
        });
        let mut state = State::new([0; 32]);
        let start = Instant::now();
        let mut events = Vec::new();
        for tick in 0..4 {
            state.tick(
                &mut backend,
                &mut |event| events.push(event),
                start + POLL_INTERVAL * tick,
                false,
            );
        }
        assert_eq!(*backend.calls.lock().unwrap(), vec![1, 2]);
        assert_eq!(events, vec![Event::Added("second@example.test".into())]);
    }

    #[test]
    fn final_read_bypasses_debounce_and_backoff_but_does_not_retry() {
        let mut backend = Mock::new(Some(1));
        backend.import = Box::new(|_| Ok(ImportOutcome::Busy));
        let mut state = State::new([0; 32]);
        let start = Instant::now();
        state.tick(&mut backend, &mut |_| {}, start, false);
        state.tick(&mut backend, &mut |_| {}, start + POLL_INTERVAL, false);
        let mut final_events = Vec::new();
        state.tick(
            &mut backend,
            &mut |event| final_events.push(event),
            start + POLL_INTERVAL,
            true,
        );
        assert_eq!(*backend.calls.lock().unwrap(), vec![1, 1]);
        assert_eq!(final_events, vec![Event::FinalUnavailable]);

        let mut fresh = State::new([0; 32]);
        *backend.current.lock().unwrap() = Some(2);
        fresh.tick(&mut backend, &mut |_| {}, start, true);
        assert_eq!(*backend.calls.lock().unwrap(), vec![1, 1, 2]);
    }

    #[test]
    fn running_watcher_imports_a_stable_login_before_finish() {
        let backend = Mock::new(Some(0));
        let current = backend.current.clone();
        let (added, received) = mpsc::channel();
        let mut watcher =
            Watcher::spawn(backend, [0; 32], Duration::from_millis(10), move |event| {
                if let Event::Added(email) = event {
                    added.send(email).unwrap();
                }
            })
            .unwrap();
        assert!(received.recv_timeout(Duration::from_millis(50)).is_err());
        *current.lock().unwrap() = Some(1);
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            "account1@example.test"
        );
        watcher.finish();
        assert!(received.try_recv().is_err());
    }

    #[test]
    fn finish_waits_for_the_inflight_request_then_runs_one_final_snapshot() {
        let mut backend = Mock::new(Some(1));
        let current = backend.current.clone();
        let calls = backend.calls.clone();
        let (entered, request) = mpsc::channel();
        let (release, unblock) = mpsc::channel();
        backend.import = Box::new(move |candidate| {
            entered.send(candidate).unwrap();
            if candidate == 1 {
                unblock.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(ImportOutcome::Superseded)
            } else {
                Ok(ImportOutcome::Added("final@example.test".into()))
            }
        });
        let mut watcher =
            Watcher::spawn(backend, [0; 32], Duration::from_millis(10), |_| {}).unwrap();
        assert_eq!(request.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
        *current.lock().unwrap() = Some(2);
        let (finished, done) = mpsc::channel();
        let finisher = thread::spawn(move || {
            watcher.finish();
            finished.send(()).unwrap();
        });
        assert!(done.recv_timeout(Duration::from_millis(30)).is_err());
        release.send(()).unwrap();
        assert_eq!(request.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        finisher.join().unwrap();
        assert_eq!(*calls.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn final_sync_finishes_under_the_desktop_lock_and_drop_does_not_start_more_work() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("desktop.lock");
        let held = File::create(&path).unwrap();
        held.lock_exclusive().unwrap();
        let mut backend = Mock::new(Some(1));
        let calls = backend.calls.clone();
        let (confirmed, result) = mpsc::channel();
        backend.import = Box::new(move |_| {
            let other = File::open(&path).unwrap();
            assert!(other.try_lock_exclusive().is_err());
            confirmed.send(()).unwrap();
            Ok(ImportOutcome::Added("final@example.test".into()))
        });
        let mut watcher =
            Watcher::spawn(backend, [0; 32], Duration::from_secs(60), |_| {}).unwrap();
        watcher.finish();
        result.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(held);
        let other = File::open(temp.path().join("desktop.lock")).unwrap();
        other.try_lock_exclusive().unwrap();
        drop(watcher);
        assert_eq!(*calls.lock().unwrap(), vec![1]);
    }

    struct RunningDesktop(Child);

    impl RunningDesktop {
        fn stop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl Drop for RunningDesktop {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[test]
    fn live_desktop_login_reaches_the_real_registry_without_changing_the_cli_login() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut state = store::State::default();
        let original = "original@example.test";
        let original_home = store::profile_home(root, &state, original, true).unwrap();
        state.profiles.push(original.into());
        store::write_state(root, &state).unwrap();
        let original_bytes = br#"{
            "token":{"access_token":"synthetic-original-access","refresh_token":"synthetic-original-refresh"},
            "id_token_email":"original@example.test"
        }"#;
        let original_path = original_home.join(".gemini/antigravity-cli/antigravity-oauth-token");
        fs::write(&original_path, original_bytes).unwrap();
        fs::set_permissions(&original_path, fs::Permissions::from_mode(0o600)).unwrap();
        let desktop_home = root.join("desktop-home");
        store::ensure_private_dir(&desktop_home).unwrap();
        store::ensure_private_dir(&desktop_home.join(".gemini")).unwrap();
        let token_path = desktop_home.join(".gemini/jetski-standalone-oauth-token");
        fs::write(&token_path, original_bytes).unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        let desktop_lock = store::open_private_file(&root.join(".desktop.lock"), true).unwrap();
        desktop_lock.lock_exclusive().unwrap();
        let mut desktop = RunningDesktop(
            Command::new("/bin/sh")
                .args(["-c", "exec /bin/sleep 30"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let requests = Arc::new(Mutex::new(0));
        let requests_seen = requests.clone();
        let importer = Importer::with_test_verifier(
            root.to_path_buf(),
            token_path.clone(),
            move |access_token| {
                assert_eq!(access_token, "synthetic-new-access");
                *requests_seen.lock().unwrap() += 1;
                Ok("new@example.test".into())
            },
        );
        let mut watcher = Watcher::spawn(
            FileBackend {
                token_path: token_path.clone(),
                importer,
            },
            Sha256::digest(original_bytes).into(),
            Duration::from_millis(10),
            |_| {},
        )
        .unwrap();
        thread::sleep(Duration::from_millis(30));
        assert_eq!(*requests.lock().unwrap(), 0);
        fs::write(&token_path, b"{\"token\":").unwrap();
        thread::sleep(Duration::from_millis(30));
        assert_eq!(*requests.lock().unwrap(), 0);
        let new_login = serde_json::json!({
            "token": {
                "access_token": "synthetic-new-access",
                "refresh_token": "synthetic-new-refresh",
                "token_type": "Bearer"
            },
            "id_token_email": "new@example.test",
            "future": {"preserved": true}
        });
        fs::write(&token_path, serde_json::to_vec(&new_login).unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let imported = loop {
            let state = store::read_state(root).unwrap();
            if state.profiles.iter().any(|name| name == "new@example.test") {
                break state;
            }
            assert!(
                Instant::now() < deadline,
                "desktop login was not registered"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert!(desktop.0.try_wait().unwrap().is_none());
        assert_eq!(fs::read(&original_path).unwrap(), original_bytes);
        let imported_home =
            store::profile_home(root, &imported, "new@example.test", false).unwrap();
        let imported_login: serde_json::Value = serde_json::from_slice(
            &fs::read(imported_home.join(".gemini/antigravity-cli/antigravity-oauth-token"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(imported_login, new_login);
        desktop.stop();
        watcher.finish();
        assert_eq!(*requests.lock().unwrap(), 1);
        assert_eq!(fs::read(&original_path).unwrap(), original_bytes);
    }
}
