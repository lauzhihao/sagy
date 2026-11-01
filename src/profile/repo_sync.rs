//! 原生订阅凭据使用独立的加密协议；导入只新增目录，以注册表提交作为唯一发布点。
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::store::{self, State};
use crate::adapters::antigravity::repo_sync::EncryptedRepo;
use crate::cli::args::RepoSyncArgs;
use crate::cli::repo_sync::resolve_repo_sync_repo;
use crate::core::credential::StrictValue;

const DEFAULT_BUNDLE_DIR: &str = ".sagy-native-profiles";
const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 1024 * 1024;
const MAX_PROFILES: usize = 256;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MANIFEST: &str = ".sync-import.json";
const TOKEN: &str = "home/.gemini/antigravity-cli/antigravity-oauth-token";

#[derive(Parser)]
#[command(about = "Synchronize encrypted native subscription profiles through Git")]
#[command(mut_arg("path", |arg| arg.help("Subdirectory inside the repository (default: .sagy-native-profiles)")))]
struct Arguments {
    #[command(flatten)]
    sync: RepoSyncArgs,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    profiles: BTreeMap<String, Value>,
}

impl Bundle {
    fn new(profiles: BTreeMap<String, Value>) -> Self {
        Self {
            kind: "sagy-native-profiles".into(),
            version: 1,
            profiles,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.kind != "sagy-native-profiles" || self.version != 1 {
            bail!(
                "Unsupported native profile bundle. Portable accounts use sagy-legacy push/pull."
            );
        }
        if self.profiles.len() > MAX_PROFILES {
            bail!("Native profile bundle exceeds the 256-account limit.");
        }
        for (name, token) in &self.profiles {
            if store::valid_name(name).ok().as_ref() != Some(name) {
                bail!("Native profile bundle contains an invalid label.");
            }
            validate_token(token)?;
        }
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            bail!("Native profile bundle exceeds the 8 MiB limit.");
        }
        let StrictValue(value) = serde_json::from_slice::<StrictValue>(bytes)
            .map_err(|_| anyhow!("Invalid native profile bundle JSON."))?;
        let bundle: Self = serde_json::from_value(value)
            .map_err(|_| anyhow!("Invalid native profile bundle schema."))?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            bail!("Native profile bundle exceeds the 8 MiB limit.");
        }
        Ok(bytes)
    }
}

fn refresh_token(token: &Value) -> Result<&str> {
    let object = token
        .as_object()
        .ok_or_else(|| anyhow!("Invalid saved native credential."))?;
    let nested = object.get("token").unwrap_or(token);
    nested
        .as_object()
        .and_then(|token| token.get("refresh_token"))
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| anyhow!("Saved native credential has no resumable login."))
}

fn validate_token(token: &Value) -> Result<()> {
    refresh_token(token)?;
    if serde_json::to_vec(token)?.len() > MAX_TOKEN_BYTES {
        bail!("Saved native credential exceeds the 1 MiB limit.");
    }
    Ok(())
}

fn fingerprint(token: &Value) -> Result<[u8; 32]> {
    Ok(Sha256::digest(refresh_token(token)?.as_bytes()).into())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut file = match store::open_private_file(path, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("Native profile synchronization file exceeds its size limit.");
    }
    Ok(Some(bytes))
}

fn local_bundle(root: &Path) -> Result<Bundle> {
    let _registry = store::lock_registry(root)?;
    let state = store::read_state(root)?;
    if state.profiles.is_empty() {
        bail!("No native profiles to push. Run sagy login NAME first.");
    }
    if state.profiles.len() > MAX_PROFILES {
        bail!("Native profile bundle exceeds the 256-account limit.");
    }
    let mut leases = Vec::new();
    let mut profiles = BTreeMap::new();
    for name in &state.profiles {
        let home = store::profile_home(root, &state, name, false)?;
        leases.push(
            store::try_lease(&home)?.ok_or_else(|| {
                anyhow!("Profile {name} is busy; close its session before pushing.")
            })?,
        );
        let raw = read_bounded(
            &home.join(".gemini/antigravity-cli/antigravity-oauth-token"),
            MAX_TOKEN_BYTES,
        )?
        .ok_or_else(|| anyhow!("Profile {name} needs login before it can be pushed."))?;
        let StrictValue(token) = serde_json::from_slice::<StrictValue>(&raw)
            .map_err(|_| anyhow!("Profile {name} has an invalid saved credential."))?;
        validate_token(&token)
            .map_err(|_| anyhow!("Profile {name} has no valid resumable login."))?;
        profiles.insert(name.clone(), token);
    }
    // 凭据在租约内复制完成；网络阶段不持注册表或账号锁。
    Ok(Bundle::new(profiles))
}

fn merge_push(mut remote: Bundle, local: Bundle) -> Result<Bundle> {
    for (name, token) in local.profiles {
        if let Some(existing) = remote.profiles.get(&name)
            && fingerprint(existing)? != fingerprint(&token)?
        {
            bail!(
                "Profile {name} has a different saved login in the remote pool. Use distinct labels or a separate pool; nothing was pushed."
            );
        }
        remote.profiles.insert(name, token);
    }
    remote.validate()?;
    Ok(remote)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    slots: Vec<Slot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    name: String,
    directory: String,
}

impl Slot {
    fn id(&self) -> Result<&str> {
        let id = self
            .directory
            .strip_prefix("sync_")
            .ok_or_else(|| anyhow!("Invalid native profile import manifest."))?;
        let uuid =
            Uuid::parse_str(id).map_err(|_| anyhow!("Invalid native profile import manifest."))?;
        if uuid.simple().to_string() != id
            || store::valid_name(&self.name).ok().as_ref() != Some(&self.name)
        {
            bail!("Invalid native profile import manifest.");
        }
        Ok(id)
    }

    fn staging(&self, root: &Path) -> Result<PathBuf> {
        Ok(root.join(format!(".sync-stage_{}", self.id()?)))
    }

    fn destination(&self, root: &Path) -> Result<PathBuf> {
        self.id()?;
        Ok(root.join("profiles").join(&self.directory))
    }
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.version != 1 || manifest.slots.len() > MAX_PROFILES {
        bail!("Invalid native profile import manifest.");
    }
    let mut names = HashSet::new();
    let mut directories = HashSet::new();
    for slot in &manifest.slots {
        slot.id()?;
        if !names.insert(&slot.name) || !directories.insert(&slot.directory) {
            bail!("Invalid native profile import manifest.");
        }
    }
    Ok(())
}

fn remove_owned_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            store::check_private_dir(path)?;
            fs::remove_dir_all(path)?;
            Ok(())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn directory_is_registered(state: &State, directory: &str) -> bool {
    state
        .profiles
        .iter()
        .any(|name| state.directories.get(name).unwrap_or(name) == directory)
}

fn recover_import(root: &Path) -> Result<()> {
    let _registry = store::lock_registry(root)?;
    let Some(raw) = read_bounded(&root.join(MANIFEST), MAX_MANIFEST_BYTES)? else {
        return Ok(());
    };
    let StrictValue(value) = serde_json::from_slice::<StrictValue>(&raw)
        .map_err(|_| anyhow!("Invalid native profile import manifest."))?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|_| anyhow!("Invalid native profile import manifest."))?;
    validate_manifest(&manifest)?;
    let state = store::read_state(root)?;
    for slot in &manifest.slots {
        remove_owned_directory(&slot.staging(root)?)?;
        if !directory_is_registered(&state, &slot.directory) {
            let destination = slot.destination(root)?;
            match fs::symlink_metadata(&destination) {
                Ok(_) => {
                    store::check_private_dir(&destination)?;
                    // 未注册目录也可能正被一次尚未完成的 login 使用，恢复不能删除活跃登录。
                    let _lease = store::try_lease(&destination.join("home"))?
                        .ok_or_else(|| anyhow!("An unfinished imported profile is busy; close its session before retrying synchronization."))?;
                    remove_owned_directory(&destination)?;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
    File::open(root.join("profiles"))?.sync_all()?;
    fs::remove_file(root.join(MANIFEST))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn write_manifest(root: &Path, manifest: &Manifest) -> Result<()> {
    validate_manifest(manifest)?;
    if fs::symlink_metadata(root.join(MANIFEST)).is_ok() {
        bail!("A previous native profile import needs recovery first.");
    }
    let bytes = serde_json::to_vec(manifest)?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        bail!("Native profile import manifest exceeds its size limit.");
    }
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(root.join(MANIFEST))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn import_profiles_inner(root: &Path, bundle: &Bundle) -> Result<(usize, usize)> {
    let _registry = store::lock_registry(root)?;
    let mut state = store::read_state(root)?;
    let mut slots = Vec::new();
    let mut skipped = 0;
    for name in bundle.profiles.keys() {
        if state.profiles.contains(name) {
            skipped += 1;
            continue;
        }
        if state
            .directories
            .values()
            .any(|directory| directory == name)
            || fs::symlink_metadata(root.join("profiles").join(name)).is_ok()
        {
            bail!("Profile label {name} is reserved by an existing local directory.");
        }
        let directory = loop {
            let candidate = format!("sync_{}", Uuid::new_v4().simple());
            if !directory_is_registered(&state, &candidate)
                && !bundle.profiles.contains_key(&candidate)
                && fs::symlink_metadata(root.join("profiles").join(&candidate)).is_err()
            {
                break candidate;
            }
        };
        state.profiles.push(name.clone());
        state.directories.insert(name.clone(), directory.clone());
        slots.push(Slot {
            name: name.clone(),
            directory,
        });
    }
    if slots.is_empty() {
        return Ok((0, skipped));
    }
    // 先验证注册表大小，避免准备完所有凭据后才发现注册表不可提交。
    if serde_json::to_vec(&state)?.len() + 1 > 64 * 1024 {
        bail!("Profile registry is too large to import this bundle.");
    }
    let manifest = Manifest { version: 1, slots };
    write_manifest(root, &manifest)?;
    for slot in &manifest.slots {
        let staging = slot.staging(root)?;
        store::ensure_private_dir(&staging)?;
        for suffix in ["home", "home/.gemini", "home/.gemini/antigravity-cli"] {
            store::ensure_private_dir(&staging.join(suffix))?;
        }
        let mut file = store::open_private_file(&staging.join(TOKEN), true)?;
        serde_json::to_writer(&mut file, &bundle.profiles[&slot.name])?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        for suffix in ["home/.gemini/antigravity-cli", "home/.gemini", "home", ""] {
            File::open(staging.join(suffix))?.sync_all()?;
        }
        let destination = slot.destination(root)?;
        if fs::symlink_metadata(&destination).is_ok() {
            bail!("Native profile import directory was unexpectedly occupied.");
        }
        fs::rename(&staging, &destination)?;
    }
    File::open(root.join("profiles"))?.sync_all()?;
    store::write_state(root, &state)?;
    fs::remove_file(root.join(MANIFEST))?;
    File::open(root)?.sync_all()?;
    Ok((manifest.slots.len(), skipped))
}

fn import_profiles(root: &Path, bundle: &Bundle) -> Result<(usize, usize)> {
    bundle.validate()?;
    match import_profiles_inner(root, bundle) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            // write_state 可能在 rename 后 fsync 失败，必须重读注册表后决定哪些目录可删除。
            if let Err(cleanup) = recover_import(root) {
                return Err(error.context(format!(
                    "Native profile import cleanup is pending: {cleanup}"
                )));
            }
            Err(error)
        }
    }
}

pub(super) fn run(root: &Path, push: bool, args: &[OsString]) -> Result<i32> {
    let action = if push { "sagy push" } else { "sagy pull" };
    let args = match Arguments::try_parse_from(
        std::iter::once(OsString::from(action)).chain(args.iter().cloned()),
    ) {
        Ok(args) => args.sync,
        Err(error) => {
            let code = error.exit_code();
            error.print()?;
            return Ok(code);
        }
    };
    let _sync = store::open_private_file(&root.join(".sync.lock"), true)?;
    _sync
        .lock_exclusive()
        .context("Could not lock native profile synchronization.")?;
    recover_import(root)?;
    let local = if push {
        Some(local_bundle(root)?)
    } else {
        None
    };
    let repo = resolve_repo_sync_repo(root, args.repo.as_deref())?;
    let transport = EncryptedRepo::open(
        root,
        &repo,
        args.path.as_deref().unwrap_or(DEFAULT_BUNDLE_DIR),
        args.identity_file.as_deref(),
        args.insecure_host_key,
    )?;
    if push {
        let remote = transport
            .read()?
            .map(|bytes| Bundle::decode(&bytes))
            .transpose()?
            .unwrap_or_else(|| Bundle::new(BTreeMap::new()));
        let bundle = merge_push(remote, local.unwrap())?;
        let changed = transport.publish(
            &bundle.encode()?,
            "chore(sagy): sync encrypted native profiles",
        )?;
        super::note(format!(
            "{} {} native profile(s).",
            if changed {
                "Pushed"
            } else {
                "Already synchronized:"
            },
            bundle.profiles.len()
        ));
    } else {
        let bytes = transport.read()?.ok_or_else(|| {
            anyhow!("No native profile bundle found. Push from the source machine first; portable accounts use sagy-legacy pull.")
        })?;
        let bundle = Bundle::decode(&bytes)?;
        let (added, skipped) = import_profiles(root, &bundle)?;
        super::note(format!(
            "Imported {added} native profile(s); kept {skipped} existing local profile(s)."
        ));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        store::ensure_private_dir(&root.path().join("profiles")).unwrap();
        root
    }

    fn token(refresh: &str) -> Value {
        json!({"token":{"refresh_token":refresh,"access_token":"fixture-access","expires_at":42},"email":"fixture@example.com"})
    }

    fn bundle(name: &str, refresh: &str) -> Bundle {
        Bundle::new(BTreeMap::from([(name.into(), token(refresh))]))
    }

    fn manifest(root: &Path, name: &str) -> Manifest {
        let slot = Slot {
            name: name.into(),
            directory: format!("sync_{}", Uuid::new_v4().simple()),
        };
        let manifest = Manifest {
            version: 1,
            slots: vec![slot],
        };
        write_manifest(root, &manifest).unwrap();
        manifest
    }

    #[test]
    fn wire_rejects_duplicates_paths_non_resumable_and_unbounded_tokens() {
        let valid = bundle("alice@example.com", "refresh-a").encode().unwrap();
        assert_eq!(Bundle::decode(&valid).unwrap().profiles.len(), 1);
        for raw in [
            br#"{"type":"sagy-native-profiles","version":1,"version":1,"profiles":{}}"#.as_slice(),
            br#"{"type":"sagy-native-profiles","version":1,"profiles":{"../escape":{"refresh_token":"a"}}}"#.as_slice(),
            br#"{"type":"sagy-native-profiles","version":1,"profiles":{"a":{"token":{"access_token":"no-refresh"}}}}"#.as_slice(),
            br#"{"type":"sagy-native-profiles","version":1,"profiles":{},"path":"/tmp/escape"}"#.as_slice(),
        ] {
            assert!(Bundle::decode(raw).is_err());
        }
        let too_large = Value::String("a".repeat(MAX_TOKEN_BYTES));
        assert!(validate_token(&json!({"refresh_token":"r","extra":too_large})).is_err());
    }

    #[test]
    fn push_merges_remote_only_and_refuses_different_saved_login() {
        let mut remote = bundle("remote", "remote-refresh");
        remote.profiles.insert("same".into(), token(" exact "));
        let mut local = bundle("local", "local-refresh");
        local.profiles.insert(
            "same".into(),
            json!({"refresh_token":" exact ","access_token":"new"}),
        );
        let merged = merge_push(remote, local).unwrap();
        assert_eq!(merged.profiles.len(), 3);
        assert_eq!(merged.profiles["same"]["access_token"], "new");
        assert!(merge_push(bundle("same", "a"), bundle("same", "b")).is_err());
        assert!(merge_push(bundle("same", "a"), bundle("same", " a ")).is_err());
    }

    #[test]
    fn import_adds_private_home_and_preserves_existing_mapping_and_token() {
        let root = root();
        let first = bundle("alice@example.com", "first-refresh");
        assert_eq!(import_profiles(root.path(), &first).unwrap(), (1, 0));
        let state = store::read_state(root.path()).unwrap();
        let home = store::profile_home(root.path(), &state, "alice@example.com", false).unwrap();
        let credential = home.join(".gemini/antigravity-cli/antigravity-oauth-token");
        let original = fs::read(&credential).unwrap();
        assert_eq!(
            fs::metadata(&credential).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            import_profiles(root.path(), &bundle("alice@example.com", "other")).unwrap(),
            (0, 1)
        );
        assert_eq!(fs::read(&credential).unwrap(), original);
        assert_eq!(
            store::read_state(root.path()).unwrap().directories,
            state.directories
        );
        assert!(!root.path().join(MANIFEST).exists());
    }

    #[test]
    fn recovery_preserves_committed_slots_and_only_removes_manifest_orphans() {
        let root = root();
        import_profiles(root.path(), &bundle("published", "refresh")).unwrap();
        let state = store::read_state(root.path()).unwrap();
        let registered = state.directories["published"].clone();
        let orphan = manifest(root.path(), "unpublished");
        let destination = orphan.slots[0].destination(root.path()).unwrap();
        let stage = orphan.slots[0].staging(root.path()).unwrap();
        store::ensure_private_dir(&destination).unwrap();
        store::ensure_private_dir(&stage).unwrap();
        let unrelated = root.path().join("profiles/sync_not-an-import");
        store::ensure_private_dir(&unrelated).unwrap();
        // 模拟 state rename 成功、manifest 清理前退出：已注册目录必须保留。
        let mut entries = orphan.slots;
        entries.push(Slot {
            name: "published".into(),
            directory: registered.clone(),
        });
        fs::remove_file(root.path().join(MANIFEST)).unwrap();
        write_manifest(
            root.path(),
            &Manifest {
                version: 1,
                slots: entries,
            },
        )
        .unwrap();
        recover_import(root.path()).unwrap();
        assert!(root.path().join("profiles").join(registered).is_dir());
        assert!(!destination.exists());
        assert!(!stage.exists());
        assert!(unrelated.is_dir());
        assert!(!root.path().join(MANIFEST).exists());
    }

    #[test]
    fn recovery_keeps_an_unregistered_directory_while_login_holds_its_lease() {
        let root = root();
        let manifest = manifest(root.path(), "orphan");
        let destination = manifest.slots[0].destination(root.path()).unwrap();
        store::ensure_private_dir(&destination).unwrap();
        let lease = store::try_lease(&destination.join("home"))
            .unwrap()
            .unwrap();
        assert!(recover_import(root.path()).is_err());
        assert!(destination.is_dir());
        assert!(root.path().join(MANIFEST).exists());
        drop(lease);
        recover_import(root.path()).unwrap();
        assert!(!destination.exists());
        assert!(!root.path().join(MANIFEST).exists());
    }

    #[test]
    fn imports_fail_before_publishing_on_reserved_labels_and_recovery_rejects_symlinks() {
        let root = root();
        let mut state = State::default();
        state.profiles.push("alice@example.com".into());
        state
            .directories
            .insert("alice@example.com".into(), "work".into());
        store::profile_home(root.path(), &state, "alice@example.com", true).unwrap();
        store::write_state(root.path(), &state).unwrap();
        assert!(import_profiles(root.path(), &bundle("work", "r")).is_err());
        assert_eq!(
            store::read_state(root.path()).unwrap().profiles,
            state.profiles
        );
        let manifest = manifest(root.path(), "orphan");
        let outside = tempfile::tempdir().unwrap();
        symlink(
            outside.path(),
            manifest.slots[0].destination(root.path()).unwrap(),
        )
        .unwrap();
        assert!(recover_import(root.path()).is_err());
        assert!(outside.path().is_dir());
        assert!(root.path().join(MANIFEST).exists());
    }
}
