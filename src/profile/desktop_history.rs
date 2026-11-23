//! 在独立桌面 HOME 中一次性导入只读历史，所有账号共享同一份数据。
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use super::{observer, store};

pub(super) const READY: &str = ".sagy-desktop-history-v1";
const READY_CONTENT: &[u8] = b"sagy desktop history v1\n";
const MAX_ENTRIES: usize = 1_000_000;
const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const EXCLUDED: &[&str] = &[
    "scratch",
    "bin",
    "lib",
    "cache",
    "crashes",
    "daemon",
    "presence",
    "sidecar_data",
    "plugin_data",
    "mcp_config.json",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    directory: bool,
    device: u64,
    inode: u64,
    length: u64,
    executable: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Entry {
    fn inspect(metadata: &Metadata) -> Result<Self> {
        if !metadata.is_file() && !metadata.is_dir() {
            bail!("Desktop history contains a symbolic link or unsupported file.");
        }
        if metadata.uid() != unsafe { libc::getuid() } {
            bail!("Desktop history must be owned by the current user.");
        }
        Ok(Self {
            directory: metadata.is_dir(),
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            executable: metadata.mode() & 0o100,
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

type Snapshot = BTreeMap<PathBuf, Entry>;

fn snapshot(source: &Path) -> Result<Option<Snapshot>> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Could not inspect desktop history."),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("The original desktop history must be a real directory.");
    }
    let mut entries = BTreeMap::new();
    entries.insert(PathBuf::new(), Entry::inspect(&metadata)?);
    let mut pending = vec![PathBuf::new()];
    let mut bytes = 0u64;
    while let Some(relative) = pending.pop() {
        for item in fs::read_dir(source.join(&relative))? {
            observer::check_interrupted()?;
            let item = item?;
            if relative.as_os_str().is_empty()
                && EXCLUDED
                    .iter()
                    .any(|name| item.file_name() == OsStr::new(name))
            {
                continue;
            }
            let path = relative.join(item.file_name());
            let entry = Entry::inspect(&fs::symlink_metadata(source.join(&path))?)?;
            if entry.directory {
                pending.push(path.clone());
            } else {
                bytes = bytes
                    .checked_add(entry.length)
                    .context("Desktop history is too large.")?;
            }
            entries.insert(path, entry);
            if entries.len() > MAX_ENTRIES || bytes > MAX_BYTES {
                bail!("Desktop history exceeds the import size limit.");
            }
        }
    }
    Ok(Some(entries))
}

fn open_source(source: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(source)?)
}

fn open_relative(source: &File, relative: &Path) -> Result<File> {
    let mut directory = source.try_clone()?;
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            bail!("Invalid desktop history path.");
        };
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes())?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if index + 1 < components.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error())
                .context("Could not read desktop history safely.");
        }
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(directory)
}

fn copy_snapshot(source: &Path, target: &Path, entries: &Snapshot) -> Result<()> {
    store::ensure_private_dir(target)?;
    let source = open_source(source)?;
    for (relative, expected) in entries {
        observer::check_interrupted()?;
        let input = open_relative(&source, relative)?;
        if Entry::inspect(&input.metadata()?)? != *expected {
            bail!("Desktop history changed during import. Close Antigravity and try again.");
        }
        if relative.as_os_str().is_empty() {
            continue;
        }
        let destination = target.join(relative);
        if expected.directory {
            store::ensure_private_dir(&destination)?;
        } else {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600 | expected.executable)
                .open(destination)?;
            let copied = io::copy(
                &mut input.take(expected.length.saturating_add(1)),
                &mut output,
            )?;
            if copied != expected.length {
                bail!("Desktop history changed during import. Close Antigravity and try again.");
            }
            output.sync_all()?;
        }
    }
    // 先刷写子目录，再发布整份 HOME，避免成功标记先于历史目录项落盘。
    for (relative, entry) in entries.iter().rev() {
        if entry.directory {
            File::open(target.join(relative))?.sync_all()?;
        }
    }
    Ok(())
}

fn check_ready(home: &Path) -> Result<bool> {
    match fs::symlink_metadata(home) {
        Ok(_) => {
            store::check_private_dir(home)?;
            let mut marker = store::open_private_file(&home.join(READY), false).context(
                "Shared desktop history is incomplete. Preserve this directory before retrying.",
            )?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut marker)
                .take(128)
                .read_to_end(&mut bytes)?;
            if bytes != READY_CONTENT {
                bail!("Shared desktop history has an invalid initialization marker.");
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("Could not inspect shared desktop history."),
    }
}

fn reject_private_history(root: &Path) -> Result<()> {
    let profiles = root.join("profiles");
    let directories = match fs::read_dir(profiles) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("Could not inspect previous desktop profiles."),
    };
    for profile in directories {
        let profile = profile?;
        if !profile.file_type()?.is_dir() {
            bail!("Previous desktop profiles contain an unsafe entry.");
        }
        let old_home = profile.path().join("desktop-home");
        match fs::symlink_metadata(&old_home) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                bail!("Previous desktop history contains an unsafe directory.");
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("Could not inspect previous desktop history."),
        }
        let gemini = old_home.join(".gemini");
        match fs::symlink_metadata(&gemini) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                bail!("Previous desktop history contains an unsafe directory.");
            }
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("Could not inspect previous desktop history."),
        }
        for history in fs::read_dir(gemini)? {
            let history = history?;
            if !history
                .file_name()
                .to_string_lossy()
                .starts_with("antigravity")
            {
                continue;
            }
            let kind = history.file_type()?;
            if kind.is_symlink() {
                bail!("Previous desktop history contains an unsafe directory.");
            }
            if !kind.is_dir() {
                continue;
            }
            let conversations = history.path().join("conversations");
            match fs::symlink_metadata(&conversations) {
                Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                    bail!("Previous desktop history contains an unsafe directory.");
                }
                Ok(_) => {
                    if fs::read_dir(conversations)?.next().is_some() {
                        bail!(
                            "A previous per-profile desktop contains conversations. Choose a history source before initializing shared desktop history; all existing data was preserved."
                        );
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => {
                    return Err(error).context("Could not inspect previous conversations.");
                }
            }
        }
    }
    Ok(())
}

pub(super) fn initialize(root: &Path) -> Result<PathBuf> {
    let home = root.join("desktop-home");
    if check_ready(&home)? {
        return Ok(home);
    }
    initialize_from(
        root,
        &store::real_home()?.join(".gemini/antigravity"),
        check_desktop_idle,
    )
}

pub(super) fn initialize_from(
    root: &Path,
    source: &Path,
    mut check_idle: impl FnMut() -> Result<()>,
) -> Result<PathBuf> {
    let home = root.join("desktop-home");
    if check_ready(&home)? {
        return Ok(home);
    }
    reject_private_history(root)?;
    check_idle()?;
    let before = snapshot(source)?;
    if before.is_some() {
        super::note("Importing existing Antigravity history into the shared desktop directory.");
    }
    let staging = tempfile::Builder::new()
        .prefix(".desktop-import-")
        .tempdir_in(root)?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
    store::ensure_private_dir(&staging.path().join(".gemini"))?;
    if let Some(entries) = &before {
        copy_snapshot(source, &staging.path().join(".gemini/antigravity"), entries)?;
    }
    File::open(staging.path().join(".gemini"))?.sync_all()?;
    check_idle()?;
    if snapshot(source)? != before {
        bail!("Desktop history changed during import. Close Antigravity and try again.");
    }
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staging.path().join(READY))?;
    marker.write_all(READY_CONTENT)?;
    marker.sync_all()?;
    File::open(staging.path())?.sync_all()?;
    if fs::symlink_metadata(&home).is_ok() {
        bail!("Shared desktop history appeared during import; no data was replaced.");
    }
    observer::check_interrupted()?;
    fs::rename(staging.path(), &home).context("Could not publish shared desktop history.")?;
    File::open(root)?.sync_all()?;
    Ok(home)
}

fn is_desktop_process(path: &Path) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    name.eq_ignore_ascii_case("antigravity")
        || path
            .to_string_lossy()
            .contains("/Antigravity.app/Contents/")
        || name.starts_with("Antigravity Helper")
        || (cfg!(target_os = "linux")
            && path.components().any(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case("antigravity"))
            }))
}

fn check_desktop_idle() -> Result<()> {
    let output = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,comm="])
        .output()
        .context("Could not verify that Antigravity is closed before importing history.")?;
    if !output.status.success() {
        bail!("Could not verify that Antigravity is closed before importing history.");
    }
    let listing =
        std::str::from_utf8(&output.stdout).context("Could not inspect desktop processes.")?;
    for line in listing.lines() {
        let line = line.trim();
        let Some(split) = line.find(char::is_whitespace) else {
            continue;
        };
        let (pid, path) = line.split_at(split);
        if is_desktop_process(Path::new(path.trim())) {
            bail!("Close Antigravity desktop before importing shared history, then try again.");
        }
        #[cfg(target_os = "linux")]
        if pid.parse::<u32>().is_ok()
            && let Ok(executable) = fs::read_link(format!("/proc/{pid}/exe"))
            && (is_desktop_process(&executable)
                || (executable.file_name() == Some(OsStr::new("language_server"))
                    && executable
                        .to_string_lossy()
                        .to_lowercase()
                        .contains("antigravity")))
        {
            bail!("Close Antigravity desktop before importing shared history, then try again.");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = pid;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::symlink;

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("profiles-root");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let source = temp.path().join("original-history");
        fs::create_dir_all(source.join("conversations")).unwrap();
        fs::create_dir(source.join("brain")).unwrap();
        fs::write(source.join("conversations/synthetic.pb"), b"conversation").unwrap();
        fs::write(source.join("brain/synthetic.md"), b"artifact").unwrap();
        fs::write(
            source.join("conversation_summaries.db"),
            b"synthetic database",
        )
        .unwrap();
        fs::write(
            source.join("conversation_summaries.db-wal"),
            b"synthetic wal",
        )
        .unwrap();
        (temp, root, source)
    }

    fn assert_no_publication(root: &Path) {
        assert!(!root.join("desktop-home").exists());
        assert!(fs::read_dir(root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".desktop-import-")
        }));
    }

    #[test]
    fn imports_history_once_without_reading_credentials_or_runtime_directories() {
        let (_temp, root, source) = fixture();
        for name in EXCLUDED {
            if *name == "mcp_config.json" {
                fs::write(source.join(name), b"synthetic private MCP credential").unwrap();
            } else {
                fs::create_dir(source.join(name)).unwrap();
                // 被排除目录内的外部链接不会被遍历或复制。
                symlink("/outside/not-read", source.join(name).join("link")).unwrap();
            }
        }
        fs::write(
            source
                .parent()
                .unwrap()
                .join("jetski-standalone-oauth-token"),
            b"private credential",
        )
        .unwrap();
        fs::set_permissions(
            source.join("brain/synthetic.md"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let before = snapshot(&source).unwrap();
        let calls = Cell::new(0);
        let home = initialize_from(&root, &source, || {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(snapshot(&source).unwrap(), before);
        for (name, bytes) in [
            ("conversations/synthetic.pb", b"conversation".as_slice()),
            ("brain/synthetic.md", b"artifact"),
            ("conversation_summaries.db", b"synthetic database"),
            ("conversation_summaries.db-wal", b"synthetic wal"),
        ] {
            assert_eq!(
                fs::read(home.join(".gemini/antigravity").join(name)).unwrap(),
                bytes
            );
            assert_eq!(fs::read(source.join(name)).unwrap(), bytes);
        }
        assert_eq!(
            fs::metadata(home.join(".gemini/antigravity/brain/synthetic.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for name in EXCLUDED {
            assert!(!home.join(".gemini/antigravity").join(name).exists());
        }
        assert_eq!(
            fs::read(source.join("mcp_config.json")).unwrap(),
            b"synthetic private MCP credential"
        );
        assert!(!home.join(".gemini/jetski-standalone-oauth-token").exists());
        assert!(!home.join(".gemini/config").exists());
        assert!(!home.join(".local/share/antigravity-desktop").exists());
        fs::write(
            source.join("conversations/later.pb"),
            b"later original history",
        )
        .unwrap();
        assert_eq!(
            initialize_from(&root, &source, || panic!("already imported")).unwrap(),
            home
        );
        assert!(
            !home
                .join(".gemini/antigravity/conversations/later.pb")
                .exists()
        );
    }

    #[test]
    fn missing_source_initializes_a_clean_shared_home() {
        let temp = tempfile::tempdir().unwrap();
        let home = initialize_from(temp.path(), &temp.path().join("absent"), || Ok(())).unwrap();
        assert_eq!(fs::read(home.join(READY)).unwrap(), READY_CONTENT);
        assert!(home.join(".gemini").is_dir());
        assert!(!home.join(".gemini/antigravity").exists());
    }

    #[test]
    fn active_desktop_or_changed_source_does_not_publish_a_partial_copy() {
        let (_temp, root, source) = fixture();
        let result = initialize_from(&root, &source, || bail!("desktop running"));
        assert!(result.is_err());
        assert_no_publication(&root);
        let calls = Cell::new(0);
        let result = initialize_from(&root, &source, || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                bail!("desktop started while copying");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_no_publication(&root);
        let calls = Cell::new(0);
        let result = initialize_from(&root, &source, || {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                fs::write(
                    source.join("conversation_summaries.db"),
                    b"changed database",
                )?;
            }
            Ok(())
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("changed during import")
        );
        assert_no_publication(&root);
        assert_eq!(
            fs::read(source.join("conversations/synthetic.pb")).unwrap(),
            b"conversation"
        );
    }

    #[test]
    fn included_links_and_special_files_are_rejected_without_publication() {
        let (_temp, root, source) = fixture();
        symlink("/outside/not-read", source.join("conversations/link")).unwrap();
        assert!(initialize_from(&root, &source, || Ok(())).is_err());
        assert_no_publication(&root);
        fs::remove_file(source.join("conversations/link")).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let fifo = std::ffi::CString::new(source.join("conversations/pipe").as_os_str().as_bytes())
            .unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(initialize_from(&root, &source, || Ok(())).is_err());
        assert_no_publication(&root);
    }

    #[test]
    fn incomplete_shared_home_and_existing_private_conversations_are_preserved() {
        let (_temp, root, source) = fixture();
        let home = root.join("desktop-home");
        store::ensure_private_dir(&home).unwrap();
        fs::write(home.join("keep"), b"unfinished existing data").unwrap();
        assert!(initialize_from(&root, &source, || Ok(())).is_err());
        assert_eq!(
            fs::read(home.join("keep")).unwrap(),
            b"unfinished existing data"
        );
        fs::remove_dir_all(&home).unwrap();
        let old = root.join("profiles/old/desktop-home/.gemini/antigravity/conversations");
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("private.pb"), b"private history").unwrap();
        let error = initialize_from(&root, &source, || Ok(()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("Choose a history source"));
        assert_eq!(
            fs::read(old.join("private.pb")).unwrap(),
            b"private history"
        );
        assert_no_publication(&root);
        fs::remove_file(old.join("private.pb")).unwrap();
        assert!(initialize_from(&root, &source, || Ok(())).is_ok());
        assert!(old.is_dir());
    }

    #[test]
    fn process_detection_matches_the_vendor_app_without_matching_sagy() {
        for path in [
            "/Applications/Antigravity.app/Contents/MacOS/Antigravity",
            "/Applications/Antigravity.app/Contents/Resources/bin/language_server",
            "/opt/antigravity/Antigravity",
            "Antigravity Helper (Renderer)",
        ] {
            assert!(is_desktop_process(Path::new(path)));
        }
        for path in [
            "/tmp/agy",
            "/usr/local/bin/sagy",
            "/tmp/sagy-desktop-check",
            "/usr/bin/python3",
        ] {
            assert!(!is_desktop_process(Path::new(path)));
        }
    }
}
