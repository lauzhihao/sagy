use std::collections::{BTreeMap, HashSet};
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_TOKEN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct State {
    pub version: u32,
    pub profiles: Vec<String>,
    #[serde(default)]
    pub directories: BTreeMap<String, String>,
    #[serde(default)]
    pub last_selected: Option<String>,
    #[serde(default)]
    pub cooldowns: BTreeMap<String, f64>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: 1,
            profiles: Vec::new(),
            directories: BTreeMap::new(),
            last_selected: None,
            cooldowns: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

pub(super) fn real_home() -> Result<PathBuf> {
    // 读取 passwd 数据库，忽略 HOME 等可由调用环境伪造的变量。
    let uid = unsafe { libc::getuid() };
    let mut capacity = 16 * 1024usize;
    loop {
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; capacity];
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE {
            capacity = capacity
                .checked_mul(2)
                .ok_or_else(|| anyhow!("passwd entry is too large"))?;
            continue;
        }
        if code != 0 {
            return Err(std::io::Error::from_raw_os_error(code))
                .context("failed to resolve current user's home directory");
        }
        if result.is_null() {
            bail!("current user has no passwd entry");
        }
        let pwd = unsafe { pwd.assume_init() };
        if pwd.pw_dir.is_null() {
            bail!("current user has no home directory in passwd entry");
        }
        let home = unsafe { CStr::from_ptr(pwd.pw_dir) }
            .to_string_lossy()
            .into_owned();
        let path = PathBuf::from(home);
        if !path.is_absolute() {
            bail!("current user's home directory is not absolute");
        }
        return fs::canonicalize(&path)
            .with_context(|| format!("failed to resolve {}", path.display()));
    }
}

pub(super) fn root_directory() -> Result<PathBuf> {
    let home = real_home()?;
    let requested = std::env::var_os("SAGY_PROFILE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share/sagy-profiles"));
    if !requested.is_absolute() {
        bail!("SAGY_PROFILE_ROOT must be an absolute path");
    }
    if fs::symlink_metadata(&requested).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!("profile root cannot be a symbolic link");
    }
    let root = resolve_nonexistent_path(&requested)?;
    if root == home || home.starts_with(&root) {
        bail!("choose a dedicated directory for SAGY_PROFILE_ROOT");
    }
    for protected in [home.join(".gemini"), home.join("Library/Keychains")] {
        let protected = resolve_nonexistent_path(&protected)?;
        if root == protected || root.starts_with(&protected) {
            bail!("profile storage must be separate from current credentials");
        }
    }
    if let Some(parent) = root.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    ensure_private_dir(&root)?;
    ensure_private_dir(&root.join("profiles"))?;
    Ok(root)
}

pub(super) fn valid_name(name: &str) -> Result<String> {
    if name.is_ascii()
        && !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Ok(name.to_owned());
    }
    let email = name.to_ascii_lowercase();
    if email.len() > 254 {
        bail!("use a lowercase label or a valid email address");
    }
    let Some((local, domain)) = email.split_once('@') else {
        bail!("use a lowercase label or a valid email address");
    };
    if local.is_empty() || local.len() > 64 || domain.is_empty() || !domain.contains('.') {
        bail!("use a lowercase label or a valid email address");
    }
    let valid_atom = |atom: &str| {
        !atom.is_empty()
            && atom.bytes().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'_'
                    || b == b'+'
                    || b == b'%'
                    || b == b'-'
            })
    };
    if !local.split('.').all(valid_atom)
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        bail!("use a lowercase label or a valid email address");
    }
    Ok(email)
}

pub(super) fn lock_registry(root: &Path) -> Result<File> {
    ensure_private_dir(root)?;
    let lock = open_private_file(&root.join(".lock"), true)?;
    lock.lock_exclusive()
        .context("failed to lock profile registry")?;
    super::remove::recover(root)?;
    Ok(lock)
}

pub(super) fn read_state(root: &Path) -> Result<State> {
    let path = root.join("state.json");
    let mut file = match open_private_file(&path, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(State::default());
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read profile registry")?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        bail!("profile registry is too large");
    }
    let state: State = serde_json::from_slice(&bytes).context("profile registry is invalid")?;
    validate_state(&state)?;
    Ok(state)
}

pub(super) fn write_state(root: &Path, state: &State) -> Result<()> {
    validate_state(state)?;
    ensure_private_dir(root)?;
    let target = root.join("state.json");
    let bytes = serde_json::to_vec(state).context("failed to serialize profile registry")?;
    if bytes.len() as u64 + 1 > MAX_STATE_BYTES {
        bail!("profile registry is too large");
    }
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(&bytes)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&target)
        .context("failed to replace profile registry")?;
    File::open(root)?
        .sync_all()
        .context("failed to sync profile directory")?;
    Ok(())
}

pub(super) fn profile_home(
    root: &Path,
    state: &State,
    name: &str,
    create: bool,
) -> Result<PathBuf> {
    let name = valid_name(name)?;
    let physical = state
        .directories
        .get(&name)
        .map(String::as_str)
        .unwrap_or(&name);
    if !state.profiles.contains(&name) && state.directories.values().any(|slot| slot == &name) {
        bail!("profile directory name is reserved by an existing profile");
    }
    let profile = root.join("profiles").join(valid_name(physical)?);
    let home = profile.join("home");
    if create {
        ensure_private_dir(root)?;
        ensure_private_dir(&root.join("profiles"))?;
        ensure_private_dir(&profile)?;
        ensure_private_dir(&home)?;
        ensure_private_dir(&home.join(".gemini"))?;
        ensure_private_dir(&home.join(".gemini/antigravity-cli"))?;
    } else {
        for path in [
            &profile,
            &home,
            &home.join(".gemini"),
            &home.join(".gemini/antigravity-cli"),
        ] {
            check_private_dir(path)?;
        }
    }
    Ok(home)
}

pub(super) fn try_lease(home: &Path) -> Result<Option<File>> {
    let profile = home
        .parent()
        .ok_or_else(|| anyhow!("profile home has no parent"))?;
    let file = open_private_file(&profile.join(".lock"), true)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(file)),
        Err(error)
            if error.kind() == fs2::lock_contended_error().kind()
                || error.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("failed to lock profile"),
    }
}

pub(super) fn token_ready(home: &Path) -> Result<bool> {
    let token = home.join(".gemini/antigravity-cli/antigravity-oauth-token");
    let mut file = match open_private_file(&token, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read profile token")?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Ok(false);
    }
    let Ok(document) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(false);
    };
    let token = document.get("token").unwrap_or(&document);
    Ok(token
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty()))
}

fn validate_state(state: &State) -> Result<()> {
    if state.version != 1 {
        bail!("unsupported profile registry version");
    }
    let names: HashSet<_> = state.profiles.iter().collect();
    if names.len() != state.profiles.len() {
        bail!("profile registry contains duplicate account names");
    }
    let mut physical = HashSet::new();
    for name in &state.profiles {
        if valid_name(name)? != *name
            || !physical.insert(state.directories.get(name).unwrap_or(name))
        {
            bail!("profile name or directory mapping is invalid");
        }
    }
    for (name, slot) in &state.directories {
        if !names.contains(name) || valid_name(slot)? != *slot {
            bail!("profile directory mapping is invalid");
        }
    }
    if state
        .last_selected
        .as_ref()
        .is_some_and(|name| !names.contains(name))
    {
        bail!("last selected profile is not registered");
    }
    for (name, until) in &state.cooldowns {
        if !names.contains(name) || !until.is_finite() || *until < 0.0 || *until >= 1e12 {
            bail!("profile cooldown is invalid");
        }
    }
    Ok(())
}

fn resolve_nonexistent_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("profile paths must be absolute");
    }
    // 必须先解析左侧符号链接，再处理后续的 ..，否则旧档案会指向另一处目录。
    let mut resolved = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                resolved.pop();
            }
            std::path::Component::Normal(part) => {
                resolved.push(part);
                match fs::symlink_metadata(&resolved) {
                    Ok(metadata) if metadata.is_symlink() => {
                        resolved = fs::canonicalize(&resolved)?
                    }
                    Ok(_) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) => return Err(err.into()),
                }
            }
            std::path::Component::Prefix(_) => bail!("unsupported profile path prefix"),
        }
    }
    Ok(resolved)
}

pub(super) fn ensure_private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to create {}", path.display()));
        }
    }
    check_private_dir(path)
}

pub(super) fn check_private_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("profile directory is unsafe: {}", path.display());
    }
    Ok(())
}

pub(super) fn open_private_file(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    if create {
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    check_private_file(&file, path)?;
    Ok(file)
}

#[cfg(test)]
fn open_new_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    check_private_file(&file, path)?;
    Ok(file)
}

fn check_private_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("profile storage files must be private, regular files owned by this user");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn private_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("restrict temporary directory");
        temp
    }

    fn prepare_profile(root: &Path, name: &str) -> PathBuf {
        let home = profile_home(root, &State::default(), name, true).expect("profile home");
        fs::create_dir_all(home.join(".gemini/antigravity-cli")).expect("token directory");
        home
    }

    #[test]
    fn symlink_parent_is_resolved_before_dot_dot() {
        let dir = private_root();
        let base = dir.path().canonicalize().unwrap();
        fs::create_dir_all(base.join("other/sub")).unwrap();
        symlink(base.join("other/sub"), base.join("link")).unwrap();
        assert_eq!(
            resolve_nonexistent_path(&base.join("link/../profiles")).unwrap(),
            base.join("other/profiles")
        );
    }

    #[test]
    fn state_round_trip_preserves_unknown_fields() {
        let temp = private_root();
        let root = temp.path();
        let file = open_new_private_file(&root.join("state.json")).expect("state file");
        drop(file);
        fs::write(
            root.join("state.json"),
            br#"{"version":1,"profiles":["alpha"],"custom":{"keep":true}}"#,
        )
        .expect("write state");
        let mut state = read_state(root).expect("read state");
        assert_eq!(state.profiles, ["alpha"]);
        state.last_selected = Some("alpha".to_owned());
        write_state(root, &state).expect("write state atomically");
        let saved: Value =
            serde_json::from_slice(&fs::read(root.join("state.json")).expect("read saved state"))
                .expect("valid json");
        assert_eq!(saved["custom"]["keep"], true);
        assert_eq!(saved["last_selected"], "alpha");
    }

    #[test]
    fn account_names_validate_and_normalize_email() {
        assert_eq!(valid_name("123@example.123").unwrap(), "123@example.123");
        assert_eq!(valid_name("alpha_2-work").unwrap(), "alpha_2-work");
        assert_eq!(valid_name("2alpha").unwrap(), "2alpha");
        assert_eq!(
            valid_name("First.Last+Work@Example.COM").unwrap(),
            "first.last+work@example.com"
        );
        for invalid in [
            "../escape",
            "UPPER",
            "a..b@example.com",
            "x@localhost",
            "x@-bad.example",
        ] {
            assert!(valid_name(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn profile_names_cannot_alias_existing_directory() {
        let temp = private_root();
        let root = temp.path();
        let mut state = State::default();
        state.profiles.push("person@example.com".to_owned());
        state
            .directories
            .insert("person@example.com".to_owned(), "alpha".to_owned());
        let original = profile_home(root, &state, "person@example.com", true).unwrap();
        assert!(profile_home(root, &state, "alpha", true).is_err());
        assert!(original.ends_with("profiles/alpha/home"));
    }

    #[test]
    fn lease_is_nonblocking_and_releases_with_file() {
        let temp = private_root();
        let home = prepare_profile(temp.path(), "alpha");
        let held = try_lease(&home).unwrap().expect("first lease");
        assert!(try_lease(&home).unwrap().is_none());
        drop(held);
        assert!(try_lease(&home).unwrap().is_some());
    }

    #[test]
    fn registry_lock_and_token_checks_are_private() {
        let temp = private_root();
        let root = temp.path();
        let lock = lock_registry(root).expect("registry lock");
        assert!(root.join(".lock").is_file());
        drop(lock);

        let home = prepare_profile(root, "alpha");
        assert!(!token_ready(&home).unwrap());
        let token_path = home.join(".gemini/antigravity-cli/antigravity-oauth-token");
        let mut token = open_new_private_file(&token_path).unwrap();
        token
            .write_all(br#"{"token":{"refresh_token":"secret"}}"#)
            .unwrap();
        drop(token);
        assert!(token_ready(&home).unwrap());
    }

    #[test]
    fn registry_rejects_symlink_and_duplicate_profiles() {
        let temp = private_root();
        let root = temp.path();
        let target = root.join("outside.json");
        fs::write(&target, br#"{"version":1,"profiles":[]}"#).unwrap();
        symlink(&target, root.join("state.json")).unwrap();
        assert!(read_state(root).is_err());

        fs::remove_file(root.join("state.json")).unwrap();
        fs::write(root.join("state.json"), br#"{"version":1}"#).unwrap();
        assert!(read_state(root).is_err());
        fs::remove_file(root.join("state.json")).unwrap();
        let duplicate = State {
            profiles: vec!["alpha".into(), "alpha".into()],
            ..State::default()
        };
        assert!(write_state(root, &duplicate).is_err());
    }
}
