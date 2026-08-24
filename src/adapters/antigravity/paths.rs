use std::env;
use std::fs;
use std::path::Component;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::core::storage::expand_user_path;

pub fn find_agy_bin(state_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGY_BIN") {
        let candidate = expand_user_path(Path::new(&path));
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    if let Some(state_dir) = state_dir {
        let runtime_candidate = state_dir.join("runtime").join("bin").join(bin_name("agy"));
        if runtime_candidate.is_file() {
            return Some(runtime_candidate);
        }
    }

    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        let candidates = [
            home.join(".gemini/antigravity-cli/bin")
                .join(bin_name("agy")),
            home.join(".local/bin").join(bin_name("agy")),
            home.join(".cargo/bin").join(bin_name("agy")),
        ];
        for candidate in candidates {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    find_program("agy")
}

pub fn find_git_bin() -> Option<PathBuf> {
    find_program("git")
}

pub fn find_program(name: &str) -> Option<PathBuf> {
    let name_ext = bin_name(name);
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join(&name_ext);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let well_known = [
        PathBuf::from("/usr/local/bin").join(&name_ext),
        PathBuf::from("/opt/homebrew/bin").join(&name_ext),
        PathBuf::from("/usr/bin").join(&name_ext),
    ];
    well_known.into_iter().find(|candidate| candidate.is_file())
}

pub fn default_antigravity_cli_home() -> Option<PathBuf> {
    if let Some(override_path) = env::var_os("ANTIGRAVITY_CONFIG_DIR") {
        return Some(expand_user_path(Path::new(&override_path)));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".gemini").join("antigravity-cli"))
}

pub fn default_gemini_home() -> Option<PathBuf> {
    if let Some(override_path) = env::var_os("GEMINI_HOME") {
        return Some(expand_user_path(Path::new(&override_path)));
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".gemini"))
}

pub fn account_dir(state_dir: &Path, account_id: &str) -> PathBuf {
    state_dir.join("accounts").join(account_id)
}

pub const MAX_BUNDLE_DIR_BYTES: usize = 4096;
pub const MAX_BUNDLE_DIR_COMPONENTS: usize = 64;

/// 在把账号 ID 当作文件系统组件使用前校验它。
///
/// ID 既会持久化到 state，也可能来自加密仓库 bundle；在路径边界固定
/// 不变量，避免任一来源把账号操作变成路径穿越。
pub fn validate_account_id(account_id: &str) -> Result<()> {
    let bytes = account_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        bail!("invalid account id: expected 1-64 ASCII characters");
    }

    let is_first = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let is_rest = |byte: u8| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
    };

    if !is_first(bytes[0]) || !bytes.iter().copied().skip(1).all(is_rest) {
        bail!("invalid account id: use [a-z0-9][a-z0-9_-]{{0,63}}");
    }
    Ok(())
}

/// 校验 `--path` 传入的用户可控 bundle 目录。
///
/// 路径按可移植的词法规则处理：不接受绝对路径、穿越组件、平台专用
/// 分隔符或看起来像 option 的路径开头。
pub fn validate_bundle_dir(bundle_dir: &str) -> Result<()> {
    if bundle_dir.is_empty() {
        bail!("bundle path cannot be empty");
    }
    if bundle_dir.len() > MAX_BUNDLE_DIR_BYTES {
        bail!("bundle path exceeds {} bytes", MAX_BUNDLE_DIR_BYTES);
    }
    if bundle_dir.contains('\0') {
        bail!("bundle path cannot contain NUL");
    }
    if bundle_dir.contains('\\') {
        bail!("bundle path cannot contain backslashes");
    }
    if bundle_dir.contains("//") {
        bail!("bundle path cannot contain repeated separators");
    }
    if bundle_dir.contains(':') {
        bail!("bundle path cannot contain a drive or URI prefix");
    }

    let path = Path::new(bundle_dir);
    if path.is_absolute() || bundle_dir.starts_with('-') {
        bail!("bundle path must be relative and cannot start with '-'");
    }

    // `Path::components` 会把 `.` 规范化掉，因此先检查原始分隔符，
    // 拒绝 `pool/./nested` 这样的词法别名。
    for segment in bundle_dir.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            bail!("bundle path cannot contain empty, '.' or '..' components");
        }
    }
    if bundle_dir.split('/').count() > MAX_BUNDLE_DIR_COMPONENTS {
        bail!(
            "bundle path exceeds {} components",
            MAX_BUNDLE_DIR_COMPONENTS
        );
    }

    for component in path.components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                if name.is_empty() {
                    bail!("bundle path contains an unsafe component");
                }
            }
            Component::CurDir | Component::ParentDir => {
                bail!("bundle path cannot contain '.' or '..' components");
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("bundle path must be relative");
            }
        }
    }

    Ok(())
}

/// 检查 `target` 的每个已存在组件都是真实目录/文件而非 symlink，
/// 且解析后仍位于 `root` 下。
///
/// 允许末尾组件不存在，调用方可在创建目录/文件前先校验；写入
/// checkout 或账号目录的调用方会在创建后再次校验。
pub(crate) fn validate_path_under_root(root: &Path, target: &Path) -> Result<()> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect path root {}", root.display()))?;
    if root_metadata.file_type().is_symlink() {
        bail!("path root cannot be a symlink: {}", root.display());
    }
    let canonical_root = fs::canonicalize(root)
        .with_context(|| format!("failed to resolve path root {}", root.display()))?;

    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "path {} is outside allowed root {}",
            target.display(),
            root.display()
        )
    })?;

    let mut current = root.to_path_buf();
    let mut missing_tail = false;
    for component in relative.components() {
        if missing_tail {
            break;
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    bail!("path component cannot be a symlink: {}", current.display());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing_tail = true;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect path component {}", current.display())
                });
            }
        }
    }

    let anchor = if missing_tail {
        current
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| root.to_path_buf())
    } else {
        current
    };
    let canonical_anchor = fs::canonicalize(&anchor)
        .with_context(|| format!("failed to resolve path {}", anchor.display()))?;
    if !canonical_anchor.starts_with(&canonical_root) {
        bail!(
            "path {} resolves outside allowed root {}",
            target.display(),
            root.display()
        );
    }

    if !missing_tail {
        let canonical_target = fs::canonicalize(target)
            .with_context(|| format!("failed to resolve path {}", target.display()))?;
        if !canonical_target.starts_with(&canonical_root) {
            bail!(
                "path {} resolves outside allowed root {}",
                target.display(),
                root.display()
            );
        }
    }

    Ok(())
}

pub fn account_dir_checked(state_dir: &Path, account_id: &str) -> Result<PathBuf> {
    validate_account_id(account_id)?;
    if let Err(error) = fs::symlink_metadata(state_dir) {
        if error.kind() == std::io::ErrorKind::NotFound {
            crate::core::storage::create_secure_dir_all(state_dir)?;
        } else {
            return Err(error).with_context(|| {
                format!("failed to inspect state directory {}", state_dir.display())
            });
        }
    }
    let path = account_dir(state_dir, account_id);
    validate_path_under_root(state_dir, &path)?;
    Ok(path)
}

pub fn account_credentials_file(account_dir: &Path) -> PathBuf {
    account_dir.join("credentials.json")
}

pub fn account_token_file(account_dir: &Path) -> PathBuf {
    account_dir.join("antigravity-oauth-token")
}

pub fn account_settings_file(account_dir: &Path) -> PathBuf {
    account_dir.join("settings.json")
}

fn bin_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_paths() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let state_dir = temp_dir.path();
        let acc_id = "test-acc-123";

        let acc_dir = account_dir(state_dir, acc_id);
        assert_eq!(acc_dir, state_dir.join("accounts").join(acc_id));

        let creds_file = account_credentials_file(&acc_dir);
        assert_eq!(creds_file, acc_dir.join("credentials.json"));

        let token_file = account_token_file(&acc_dir);
        assert_eq!(token_file, acc_dir.join("antigravity-oauth-token"));

        let settings_file = account_settings_file(&acc_dir);
        assert_eq!(settings_file, acc_dir.join("settings.json"));
    }
}
