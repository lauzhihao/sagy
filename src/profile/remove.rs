//! 移出账号池采用可恢复归档，注册表提交前后均保留原始登录和聊天文件。
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{cache, store};
use crate::core::credential::StrictValue;

const MANIFEST: &str = ".remove-profile.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Removal {
    version: u32,
    name: String,
    directory: String,
    archive: String,
    reset_at: f64,
}

impl Removal {
    fn validate(&self) -> Result<()> {
        let archive = Uuid::parse_str(&self.archive)
            .map_err(|_| anyhow!("Invalid profile removal manifest."))?;
        if self.version != 1
            || store::valid_name(&self.name).ok().as_ref() != Some(&self.name)
            || store::valid_name(&self.directory).ok().as_ref() != Some(&self.directory)
            || archive.simple().to_string() != self.archive
            || !self.reset_at.is_finite()
            || !(0.0..1e12).contains(&self.reset_at)
        {
            bail!("Invalid profile removal manifest.");
        }
        Ok(())
    }

    fn source(&self, root: &Path) -> PathBuf {
        root.join("profiles").join(&self.directory)
    }

    fn destination(&self, root: &Path) -> PathBuf {
        root.join("archive").join(&self.archive)
    }
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn write_manifest(root: &Path, removal: &Removal) -> Result<()> {
    removal.validate()?;
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer(&mut temporary, removal)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(root.join(MANIFEST))?;
    sync_directory(root)
}

fn read_manifest(root: &Path) -> Result<Option<Removal>> {
    if !exists(&root.join(MANIFEST))? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    store::open_private_file(&root.join(MANIFEST), false)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        bail!("Profile removal manifest exceeds its size limit.");
    }
    let StrictValue(value) = serde_json::from_slice::<StrictValue>(&bytes)
        .map_err(|_| anyhow!("Invalid profile removal manifest."))?;
    let removal: Removal =
        serde_json::from_value(value).map_err(|_| anyhow!("Invalid profile removal manifest."))?;
    removal.validate()?;
    Ok(Some(removal))
}

// 调用方持有注册表锁；此处不能再次 lock_registry。
pub(super) fn recover(root: &Path) -> Result<()> {
    let Some(removal) = read_manifest(root)? else {
        return Ok(());
    };
    finish(root, &removal, None)
}

fn finish(root: &Path, removal: &Removal, held_lease: Option<File>) -> Result<()> {
    let mut state = store::read_state(root)?;
    let registered = state.profiles.contains(&removal.name);
    if registered
        && state
            .directories
            .get(&removal.name)
            .unwrap_or(&removal.name)
            != &removal.directory
    {
        bail!("Profile removal identity changed; the archive needs manual inspection.");
    }
    if state.profiles.iter().any(|name| {
        name != &removal.name && state.directories.get(name).unwrap_or(name) == &removal.directory
    }) {
        bail!("Profile removal directory is used by another account.");
    }
    store::check_private_dir(&root.join("profiles"))?;
    store::ensure_private_dir(&root.join("archive"))?;
    let source = removal.source(root);
    let destination = removal.destination(root);
    let source_exists = exists(&source)?;
    let destination_exists = exists(&destination)?;
    if source_exists && !registered {
        bail!("An unregistered directory occupies the removed profile slot.");
    }
    if source_exists == destination_exists {
        bail!("Profile removal archive is ambiguous; no profile files were changed.");
    }
    // 所有目录组件先检查，避免归档后的恢复通过符号链接触达其他 HOME。
    let physical = if source_exists { &source } else { &destination };
    for suffix in ["", "home", "home/.gemini", "home/.gemini/antigravity-cli"] {
        store::check_private_dir(&physical.join(suffix))?;
    }
    let _lease = match held_lease {
        Some(lease) => lease,
        None => store::try_lease(&physical.join("home"))?.ok_or_else(|| {
            anyhow!(
                "Profile {} is busy; close its session before removing it.",
                removal.name
            )
        })?,
    };
    // 保留 reset 屏障，拒绝已结束探测稍后写回的旧身份额度。
    cache::merge(
        root,
        [cache::Update {
            name: removal.name.clone(),
            directory: removal.directory.clone(),
            windows: [None; 2],
            started_at: removal.reset_at,
            finished_at: removal.reset_at,
            result: cache::Outcome::Reset,
        }],
    )?;
    if source_exists {
        fs::rename(&source, &destination).context("Could not archive profile directory.")?;
        sync_directory(&root.join("profiles"))?;
        sync_directory(&root.join("archive"))?;
    }
    if registered {
        state.profiles.retain(|name| name != &removal.name);
        state.directories.remove(&removal.name);
        state.cooldowns.remove(&removal.name);
        if state.last_selected.as_ref() == Some(&removal.name) {
            state.last_selected = None;
        }
        store::write_state(root, &state)?;
    }
    fs::remove_file(root.join(MANIFEST))?;
    sync_directory(root)
}

pub(super) fn run(root: &Path, name: String) -> Result<i32> {
    let name = store::valid_name(&name)?;
    let _registry = store::lock_registry(root)?;
    let state = store::read_state(root)?;
    if !state.profiles.contains(&name) {
        bail!("Profile {name} is not registered.");
    }
    let home = store::profile_home(root, &state, &name, false)?;
    let lease = store::try_lease(&home)?
        .ok_or_else(|| anyhow!("Profile {name} is busy; close its session before removing it."))?;
    let removal = Removal {
        version: 1,
        directory: state.directories.get(&name).unwrap_or(&name).clone(),
        name,
        archive: Uuid::new_v4().simple().to_string(),
        reset_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
    };
    store::ensure_private_dir(&root.join("archive"))?;
    write_manifest(root, &removal)?;
    finish(root, &removal, Some(lease))?;
    super::note(format!(
        "Removed profile {} from the local pool. Archived files: {}",
        removal.name,
        removal.destination(root).display()
    ));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (tempfile::TempDir, store::State) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        store::ensure_private_dir(&root.path().join("profiles")).unwrap();
        let mut state = store::State::default();
        state.profiles.push("alice@example.com".into());
        state
            .directories
            .insert("alice@example.com".into(), "work".into());
        state.last_selected = Some("alice@example.com".into());
        state.cooldowns.insert("alice@example.com".into(), 50.0);
        let home = store::profile_home(root.path(), &state, "alice@example.com", true).unwrap();
        fs::write(
            home.join("conversation.txt"),
            b"synthetic preserved conversation",
        )
        .unwrap();
        store::write_state(root.path(), &state).unwrap();
        (root, state)
    }

    fn manifest(state: &store::State) -> Removal {
        Removal {
            version: 1,
            name: state.profiles[0].clone(),
            directory: "work".into(),
            archive: Uuid::new_v4().simple().to_string(),
            reset_at: 100.0,
        }
    }

    #[test]
    fn removes_mapped_profile_and_preserves_archived_home() {
        let (root, _) = fixture();
        run(root.path(), "ALICE@EXAMPLE.COM".into()).unwrap();
        let state = store::read_state(root.path()).unwrap();
        assert!(state.profiles.is_empty());
        assert!(state.directories.is_empty());
        assert!(state.cooldowns.is_empty());
        assert_eq!(state.last_selected, None);
        assert!(!root.path().join("profiles/work").exists());
        let archived = fs::read_dir(root.path().join("archive"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::read(archived.join("home/conversation.txt")).unwrap(),
            b"synthetic preserved conversation"
        );
        assert!(!root.path().join(MANIFEST).exists());
    }

    #[test]
    fn busy_profile_refuses_before_creating_manifest() {
        let (root, state) = fixture();
        let home = store::profile_home(root.path(), &state, &state.profiles[0], false).unwrap();
        let _lease = store::try_lease(&home).unwrap().unwrap();
        assert!(
            run(root.path(), state.profiles[0].clone())
                .unwrap_err()
                .to_string()
                .contains("busy")
        );
        assert!(!root.path().join(MANIFEST).exists());
        assert!(home.exists());
        assert_eq!(
            store::read_state(root.path()).unwrap().profiles,
            state.profiles
        );
    }

    #[test]
    fn recovery_finishes_before_move_after_move_and_after_registry_commit() {
        for stage in 0..3 {
            let (root, state) = fixture();
            let removal = manifest(&state);
            store::ensure_private_dir(&root.path().join("archive")).unwrap();
            write_manifest(root.path(), &removal).unwrap();
            if stage >= 1 {
                fs::rename(
                    removal.source(root.path()),
                    removal.destination(root.path()),
                )
                .unwrap();
            }
            if stage >= 2 {
                store::write_state(root.path(), &store::State::default()).unwrap();
            }
            let _registry = store::lock_registry(root.path()).unwrap();
            assert!(store::read_state(root.path()).unwrap().profiles.is_empty());
            assert!(
                removal
                    .destination(root.path())
                    .join("home/conversation.txt")
                    .exists()
            );
            assert!(!root.path().join(MANIFEST).exists());
        }
    }

    #[test]
    fn recovery_busy_archive_keeps_manifest_until_lease_released() {
        let (root, state) = fixture();
        let removal = manifest(&state);
        store::ensure_private_dir(&root.path().join("archive")).unwrap();
        write_manifest(root.path(), &removal).unwrap();
        fs::rename(
            removal.source(root.path()),
            removal.destination(root.path()),
        )
        .unwrap();
        let lease = store::try_lease(&removal.destination(root.path()).join("home"))
            .unwrap()
            .unwrap();
        assert!(store::lock_registry(root.path()).is_err());
        assert!(root.path().join(MANIFEST).exists());
        drop(lease);
        assert!(store::lock_registry(root.path()).is_ok());
        assert!(!root.path().join(MANIFEST).exists());
    }

    #[test]
    fn unsafe_directory_and_changed_identity_do_not_modify_home() {
        let (root, state) = fixture();
        let removal = manifest(&state);
        store::ensure_private_dir(&root.path().join("archive")).unwrap();
        write_manifest(root.path(), &removal).unwrap();
        let mut changed = state;
        changed
            .directories
            .insert(removal.name.clone(), "another".into());
        store::write_state(root.path(), &changed).unwrap();
        assert!(store::lock_registry(root.path()).is_err());
        assert!(
            removal
                .source(root.path())
                .join("home/conversation.txt")
                .exists()
        );
        fs::remove_file(root.path().join(MANIFEST)).unwrap();
        fs::remove_dir(root.path().join("archive")).unwrap();
        symlink(root.path().join("profiles"), root.path().join("archive")).unwrap();
        assert!(run(root.path(), removal.name).is_err());
    }

    #[test]
    fn removal_reset_blocks_late_old_quota_sample() {
        let (root, state) = fixture();
        let removal = manifest(&state);
        store::ensure_private_dir(&root.path().join("archive")).unwrap();
        write_manifest(root.path(), &removal).unwrap();
        recover(root.path()).unwrap();
        cache::merge(
            root.path(),
            [cache::Update {
                name: removal.name.clone(),
                directory: removal.directory,
                windows: [Some(0.9), Some(0.8)],
                started_at: 90.0,
                finished_at: 110.0,
                result: cache::Outcome::Ready,
            }],
        )
        .unwrap();
        let entry = &cache::read(root.path()).unwrap().profiles[&removal.name];
        assert_eq!(entry.windows, [None; 2]);
        assert_eq!(entry.sampled_at, None);
    }
}
