use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};

const DEFAULT_STATE_BASENAME: &str = "sagy";
const STATE_DIR_ENV: &str = "SAGY_HOME";
const REPO_SYNC_CONFIG_FILENAME: &str = "repo-sync.json";
const TMP_DIR_NAME: &str = "tmp";
/// 凭据文件的固定权限：必须在写入内容之前生效，不能先 rename 再 chmod。
const SECRET_FILE_MODE: u32 = 0o600;

pub fn resolve_state_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_dir {
        return Ok(expand_user_path(path));
    }

    if let Some(path) = configured_state_dir_from_env() {
        return Ok(path);
    }

    default_state_dir()
}

pub fn tmp_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(TMP_DIR_NAME)
}

fn configured_state_dir_from_env() -> Option<PathBuf> {
    env::var_os(STATE_DIR_ENV).map(|value| expand_user_path(Path::new(&value)))
}

fn default_state_dir() -> Result<PathBuf> {
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        return Ok(home.join(format!(".{DEFAULT_STATE_BASENAME}")));
    }

    let base_dirs =
        BaseDirs::new().context("unable to resolve base directories for current user")?;
    Ok(default_state_dir_for_home(None, base_dirs.data_local_dir()))
}

fn default_state_dir_for_home(home: Option<&Path>, data_local_dir: &Path) -> PathBuf {
    home.map(|home| home.join(format!(".{DEFAULT_STATE_BASENAME}")))
        .unwrap_or_else(|| data_local_dir.join(DEFAULT_STATE_BASENAME))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RepoSyncConfig {
    #[serde(default)]
    pub last_repo: Option<String>,
}

pub(crate) fn create_secure_dir_all(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        // Windows 的 `canonicalize` 会返回 `\\?\C:\...` 形式的 verbatim
        // 路径。Prefix/RootDir 只是路径锚点，不是可以创建的目录；如果把
        // Prefix 单独交给 `DirBuilder::create`，Windows 会把它解析成
        // `\\?\C:` 并返回 Access is denied。
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        if current.as_os_str().is_empty() || current.exists() {
            continue;
        }
        // 目录必须"创建时就是 0700"。先 create_dir 再 chmod 会留下一个
        // 其它用户可进入的窗口，凭据正是在这个窗口里被写进去的。
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&current)
            .with_context(|| format!("failed to create directory {}", current.display()))?;
    }
    Ok(())
}

fn write_file_atomically_with_mode(
    target: &Path,
    content: &[u8],
    #[cfg_attr(not(unix), allow(unused_variables))] mode: u32,
) -> Result<()> {
    if let Some(parent) = target.parent() {
        create_secure_dir_all(parent)?;
    }

    let file_name = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let pid = std::process::id();
    let unique_id = uuid::Uuid::new_v4();
    let temp_name = format!(".{file_name}.{pid}.{unique_id}.tmp");
    let temp_path = target
        .parent()
        .map(|p| p.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(&temp_name));

    {
        use std::io::Write;
        // 需要限权时，权限必须在**写入内容之前**就生效：先 rename 再 chmod 会留
        // 下一个其它用户可读明文凭据的窗口。
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options
            .open(&temp_path)
            .with_context(|| format!("failed to create temporary file {}", temp_path.display()))?;
        file.write_all(content)
            .with_context(|| format!("failed to write temporary file {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary file {}", temp_path.display()))?;
    }

    fs::rename(&temp_path, target).with_context(|| {
        format!(
            "failed to replace {} with {}",
            target.display(),
            temp_path.display()
        )
    })?;

    Ok(())
}

pub fn write_secret_file(target: &Path, content: &[u8]) -> Result<()> {
    write_file_atomically_with_mode(target, content, SECRET_FILE_MODE)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(target)
            .with_context(|| format!("failed to inspect secret file {}", target.display()))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(target, perms).with_context(|| {
            format!(
                "failed to restrict secret file permissions for {}",
                target.display()
            )
        })?;
    }
    Ok(())
}

pub fn load_repo_sync_config(state_dir: &Path) -> Result<RepoSyncConfig> {
    let config_path = state_dir.join(REPO_SYNC_CONFIG_FILENAME);
    let metadata = match fs::symlink_metadata(&config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RepoSyncConfig::default());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", config_path.display()));
        }
    };
    restrict_repo_sync_directory(state_dir)?;
    if metadata.file_type().is_symlink() {
        bail!("repository sync configuration cannot be a symlink");
    }
    if !metadata.is_file() {
        bail!("repository sync configuration is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&config_path, perms).with_context(|| {
                format!(
                    "failed to restrict repository sync configuration {}",
                    config_path.display()
                )
            })?;
        }
    }
    let contents = fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;
    let config: RepoSyncConfig = serde_json::from_str(&contents)
        .with_context(|| format!("invalid JSON in {}", config_path.display()))?;
    Ok(config)
}

pub fn save_repo_sync_config(state_dir: &Path, config: &RepoSyncConfig) -> Result<()> {
    create_secure_dir_all(state_dir)?;
    restrict_repo_sync_directory(state_dir)?;
    let target = state_dir.join(REPO_SYNC_CONFIG_FILENAME);
    let contents =
        serde_json::to_string_pretty(config).context("failed to serialize repo sync config")?;
    write_secret_file(&target, contents.as_bytes())
}

fn restrict_repo_sync_directory(state_dir: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(state_dir).with_context(|| {
        format!(
            "failed to inspect repository sync configuration directory {}",
            state_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        bail!("repository sync configuration directory cannot be a symlink");
    }
    if !metadata.is_dir() {
        bail!("repository sync configuration path is not a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = metadata.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(state_dir, perms).with_context(|| {
            format!(
                "failed to restrict repository sync configuration directory {}",
                state_dir.display()
            )
        })?;
    }
    Ok(())
}

pub fn expand_user_path(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str == "~" {
        if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
            return home;
        }
    } else if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
            return home.join(stripped);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// legacy `write_file_atomically` 已删除，`write_secret_file` 是唯一的
    /// 原子写入口：内容必须落盘、重复写必须整体替换、权限必须在写入前生效。
    #[test]
    fn secret_file_write_is_atomic_and_replaceable() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let target_file = temp_dir.path().join("sub").join("atomic.txt");
        write_secret_file(&target_file, b"first").expect("first atomic write");
        write_secret_file(&target_file, b"second").expect("repeated atomic write");

        assert_eq!(fs::read(&target_file).expect("read"), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target_file)
                    .expect("inspect secret file")
                    .permissions()
                    .mode()
                    & 0o777,
                SECRET_FILE_MODE
            );
        }
        let leftovers = fs::read_dir(target_file.parent().expect("parent"))
            .expect("enumerate parent")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0, "atomic write left a temporary file behind");
    }

    #[test]
    fn test_repo_sync_config_roundtrip() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();

        let cfg = RepoSyncConfig {
            last_repo: Some("git@github.com:test/pool.git".to_string()),
        };
        save_repo_sync_config(state_dir, &cfg).expect("save config");

        let loaded = load_repo_sync_config(state_dir).expect("load config");
        assert_eq!(
            loaded.last_repo,
            Some("git@github.com:test/pool.git".to_string())
        );
    }

    #[cfg(windows)]
    #[test]
    fn secure_directory_creation_handles_canonical_windows_paths() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        // Windows `canonicalize` commonly returns a `\\?\` verbatim path. Keep
        // this test on the same path shape used by the CLI after state-root
        // normalization so drive prefixes are never treated as directories.
        let canonical_root = fs::canonicalize(temp_dir.path()).expect("canonical temp dir");
        let nested = canonical_root.join("nested").join("leaf");

        create_secure_dir_all(&nested).expect("create nested canonical path");
        assert!(nested.is_dir());
    }
}
