//! 额度快照独立提交，不把网络等待或缓存故障带进账号注册表事务。
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use super::store;

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Outcome {
    Ready,
    Unavailable,
    Busy,
    NeedsLogin,
    Reset,
}

impl Outcome {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::NeedsLogin => "needs-login",
            Self::Reset => "reset",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Entry {
    pub directory: String,
    pub windows: [Option<f64>; 2],
    pub sampled_at: Option<f64>,
    pub sample_started_at: Option<f64>,
    pub reset_at: f64,
    pub attempted_at: f64,
    pub result: Outcome,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Snapshot {
    version: u32,
    pub profiles: BTreeMap<String, Entry>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            version: 1,
            profiles: BTreeMap::new(),
        }
    }
}

pub(super) struct Update {
    pub name: String,
    pub directory: String,
    pub windows: [Option<f64>; 2],
    pub started_at: f64,
    pub finished_at: f64,
    pub result: Outcome,
}

#[derive(Debug)]
struct InvalidSnapshot;

impl std::fmt::Display for InvalidSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Quota snapshot is invalid; run sagy refresh to replace it.")
    }
}

impl std::error::Error for InvalidSnapshot {}

fn valid_time(value: f64) -> bool {
    value.is_finite() && (0.0..1e12).contains(&value)
}

fn valid_windows(windows: [Option<f64>; 2]) -> bool {
    windows
        .iter()
        .flatten()
        .all(|value| value.is_finite() && (0.0..=1.0).contains(value))
}

fn validate(snapshot: &Snapshot) -> Result<()> {
    if snapshot.version != 1 {
        return Err(InvalidSnapshot.into());
    }
    for (name, entry) in &snapshot.profiles {
        if store::valid_name(name).as_ref().ok() != Some(name)
            || store::valid_name(&entry.directory).as_ref().ok() != Some(&entry.directory)
            || !valid_windows(entry.windows)
            || !valid_time(entry.attempted_at)
            || entry.sampled_at.is_some_and(|time| !valid_time(time))
            || entry
                .sample_started_at
                .is_some_and(|time| !valid_time(time))
            || !valid_time(entry.reset_at)
            || entry.sampled_at.is_some() != entry.sample_started_at.is_some()
            || entry.sampled_at.is_none() && entry.windows.iter().any(Option::is_some)
        {
            return Err(InvalidSnapshot.into());
        }
    }
    Ok(())
}

pub(super) fn read(root: &Path) -> Result<Snapshot> {
    let mut file = match store::open_private_file(&root.join("quota.json"), false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            return Ok(Snapshot::default());
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("Could not read quota snapshot.")?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(InvalidSnapshot.into());
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| InvalidSnapshot)?;
    validate(&snapshot)?;
    Ok(snapshot)
}

pub(super) fn merge(root: &Path, updates: impl IntoIterator<Item = Update>) -> Result<()> {
    let lock = store::open_private_file(&root.join(".quota.lock"), true)?;
    lock.lock_exclusive()
        .context("Could not lock quota snapshot.")?;
    let mut snapshot = match read(root) {
        Ok(snapshot) => snapshot,
        // 只有格式损坏可恢复；权限和符号链接错误必须保留为错误。
        Err(error) if error.is::<InvalidSnapshot>() => Snapshot::default(),
        Err(error) => return Err(error),
    };
    for update in updates {
        if !valid_time(update.started_at)
            || !valid_time(update.finished_at)
            || !valid_windows(update.windows)
        {
            bail!("Invalid quota update.");
        }
        let entry = snapshot
            .profiles
            .entry(update.name)
            .or_insert_with(|| Entry {
                directory: update.directory.clone(),
                windows: [None; 2],
                sampled_at: None,
                sample_started_at: None,
                reset_at: 0.0,
                attempted_at: 0.0,
                result: update.result,
            });
        // 繁忙尝试不参与成功采样排序，否则会压掉仍持 lease 的在途查询。
        if entry.directory != update.directory {
            if update.started_at < entry.attempted_at.max(entry.reset_at) {
                continue;
            }
            entry.windows = [None; 2];
            entry.sampled_at = None;
            entry.sample_started_at = None;
            entry.reset_at = update.started_at;
            entry.directory = update.directory;
        }
        if update.result == Outcome::Reset {
            // 重登必须清除原身份的值，即便系统时钟已回拨。
            entry.windows = [None; 2];
            entry.sampled_at = None;
            entry.reset_at = entry
                .reset_at
                .max(entry.sample_started_at.unwrap_or(0.0))
                .max(update.started_at);
            entry.sample_started_at = None;
            entry.result = Outcome::Reset;
        }
        if update.result == Outcome::Ready
            && update.started_at >= entry.reset_at
            && entry
                .sample_started_at
                .is_none_or(|time| update.started_at >= time)
        {
            entry.windows = update.windows;
            entry.sampled_at = Some(update.finished_at);
            entry.sample_started_at = Some(update.started_at);
        }
        if update.started_at >= entry.attempted_at {
            entry.attempted_at = update.started_at;
            entry.result = update.result;
        }
    }
    validate(&snapshot)?;
    let bytes = serde_json::to_vec(&snapshot)?;
    if bytes.len() as u64 + 1 > MAX_BYTES {
        bail!("Quota snapshot is too large.");
    }
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(&bytes)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(root.join("quota.json"))
        .context("Could not replace quota snapshot.")?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn update(name: &str, time: f64, windows: [Option<f64>; 2], result: Outcome) -> Update {
        Update {
            name: name.into(),
            directory: name.into(),
            windows,
            started_at: time,
            finished_at: time + 0.5,
            result,
        }
    }

    #[test]
    fn concurrent_merges_keep_each_profile_and_newest_attempt() {
        let root = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for (name, time) in [("alpha", 10.0), ("beta", 11.0), ("gamma", 12.0)] {
                let root = root.path();
                scope.spawn(move || {
                    merge(root, [update(name, time, [Some(0.8); 2], Outcome::Ready)]).unwrap();
                });
            }
        });
        merge(
            root.path(),
            [update("alpha", 9.0, [Some(0.1); 2], Outcome::Ready)],
        )
        .unwrap();
        merge(
            root.path(),
            [update("beta", 13.0, [None; 2], Outcome::Busy)],
        )
        .unwrap();
        let snapshot = read(root.path()).unwrap();
        assert_eq!(snapshot.profiles.len(), 3);
        assert_eq!(snapshot.profiles["alpha"].windows, [Some(0.8); 2]);
        assert_eq!(snapshot.profiles["beta"].windows, [Some(0.8); 2]);
        assert_eq!(snapshot.profiles["beta"].sampled_at, Some(11.5));
        assert_eq!(snapshot.profiles["beta"].result, Outcome::Busy);
        assert_eq!(
            fs::metadata(root.path().join("quota.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn newer_busy_attempt_does_not_discard_inflight_success() {
        let root = tempfile::tempdir().unwrap();
        merge(
            root.path(),
            [update("alpha", 11.0, [None; 2], Outcome::Busy)],
        )
        .unwrap();
        let mut success = update("alpha", 10.0, [Some(0.7); 2], Outcome::Ready);
        success.finished_at = 15.0;
        merge(root.path(), [success]).unwrap();
        let snapshot = read(root.path()).unwrap();
        let entry = &snapshot.profiles["alpha"];
        assert_eq!(entry.windows, [Some(0.7); 2]);
        assert_eq!(entry.sampled_at, Some(15.0));
        assert_eq!(entry.attempted_at, 11.0);
    }

    #[test]
    fn corrupt_regular_snapshot_recovers_but_symlink_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("quota.json");
        fs::write(&path, b"broken").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read(root.path()).is_err());
        merge(
            root.path(),
            [update("alpha", 10.0, [Some(0.8); 2], Outcome::Ready)],
        )
        .unwrap();
        assert!(read(root.path()).is_ok());
        fs::remove_file(&path).unwrap();
        let other = root.path().join("other");
        fs::write(&other, b"unchanged").unwrap();
        symlink(&other, &path).unwrap();
        assert!(
            merge(
                root.path(),
                [update("alpha", 11.0, [None; 2], Outcome::Reset)]
            )
            .is_err()
        );
        assert_eq!(fs::read(other).unwrap(), b"unchanged");
    }

    #[test]
    fn failed_probe_keeps_previous_windows_and_login_reset_prevents_old_write() {
        let root = tempfile::tempdir().unwrap();
        merge(
            root.path(),
            [update("alpha", 10.0, [Some(0.8); 2], Outcome::Ready)],
        )
        .unwrap();
        merge(
            root.path(),
            [update("alpha", 12.0, [None; 2], Outcome::Unavailable)],
        )
        .unwrap();
        assert_eq!(
            read(root.path()).unwrap().profiles["alpha"].windows,
            [Some(0.8); 2]
        );
        merge(
            root.path(),
            [update("alpha", 14.0, [None; 2], Outcome::Reset)],
        )
        .unwrap();
        merge(
            root.path(),
            [update("alpha", 13.0, [Some(0.3); 2], Outcome::Ready)],
        )
        .unwrap();
        let entry = &read(root.path()).unwrap().profiles["alpha"];
        assert_eq!(entry.windows, [None; 2]);
        assert_eq!(entry.sampled_at, None);
        assert_eq!(entry.result, Outcome::Reset);
        merge(
            root.path(),
            [update("alpha", 15.0, [Some(0.5); 2], Outcome::Ready)],
        )
        .unwrap();
        merge(
            root.path(),
            [update("alpha", 12.0, [None; 2], Outcome::Reset)],
        )
        .unwrap();
        assert_eq!(
            read(root.path()).unwrap().profiles["alpha"].windows,
            [None; 2]
        );
    }
}
