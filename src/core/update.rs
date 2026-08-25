use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use semver::Version;
use serde::Deserialize;
use tar::Archive;
use uuid::Uuid;
use zip::ZipArchive;

use crate::core::storage;

const DEFAULT_REPO: &str = "lauzhihao/sagy";
const UPDATER_USER_AGENT: &str = concat!("sagy-updater/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseTarget {
    pub triple: &'static str,
    pub archive_ext: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub repo: String,
    pub tag: String,
    pub version: String,
    pub target: ReleaseTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatus {
    Updated,
    AlreadyCurrent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateOutcome {
    pub status: UpdateStatus,
    pub previous_version: String,
    pub installed_version: String,
    pub executable_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
}

pub fn is_newer_version(remote: &str, current: &str) -> bool {
    match (
        parse_release_version(remote),
        parse_release_version(current),
    ) {
        (Ok(remote), Ok(current)) => remote.cmp_precedence(&current).is_gt(),
        // 保持这个便捷判断函数的 bool API；真正更新路径使用有错误信息的
        // `update_decision`，不会把非法版本静默当成“当前版本”。
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateDecision {
    Update,
    AlreadyCurrent,
}

fn parse_release_version(tag: &str) -> Result<Version> {
    let version = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(version).with_context(|| format!("invalid release version tag: {tag:?}"))
}

fn update_decision(remote: &str, current: &str, force: bool) -> Result<UpdateDecision> {
    let remote_version = parse_release_version(remote)?;
    let current_version = parse_release_version(current)
        .with_context(|| format!("invalid installed package version: {current:?}"))?;

    match remote_version.cmp_precedence(&current_version) {
        std::cmp::Ordering::Less => {
            bail!("refusing to downgrade from {current} to {remote}; remote release is older")
        }
        std::cmp::Ordering::Equal if force => Ok(UpdateDecision::Update),
        std::cmp::Ordering::Equal => Ok(UpdateDecision::AlreadyCurrent),
        std::cmp::Ordering::Greater => Ok(UpdateDecision::Update),
    }
}

pub fn self_update(state_dir: &Path, force: bool) -> Result<UpdateOutcome> {
    let executable_path =
        env::current_exe().context("failed to resolve current executable path")?;
    let previous_version = env!("CARGO_PKG_VERSION").to_string();
    let asset = resolve_release_asset()?;

    match update_decision(&asset.version, &previous_version, force)? {
        UpdateDecision::AlreadyCurrent => {
            return Ok(UpdateOutcome {
                status: UpdateStatus::AlreadyCurrent,
                previous_version: previous_version.clone(),
                installed_version: previous_version,
                executable_path,
            });
        }
        UpdateDecision::Update => {}
    }

    let binary = download_release_binary(&asset)?;
    let temp_root = storage::tmp_dir(state_dir);
    storage::create_secure_dir_all(&temp_root)?;
    let temp_dir = temp_root.join(format!("update-{}", Uuid::new_v4()));
    storage::create_secure_dir_all(&temp_dir)?;
    let temp_binary = temp_dir.join(binary_filename_for_current_platform("sagy"));
    fs::write(&temp_binary, &binary)
        .with_context(|| format!("failed to write {}", temp_binary.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&temp_binary)
            .with_context(|| format!("failed to stat {}", temp_binary.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&temp_binary, permissions)
            .with_context(|| format!("failed to chmod {}", temp_binary.display()))?;
    }

    self_replace::self_replace(&temp_binary)
        .with_context(|| format!("failed to replace {}", executable_path.display()))?;
    let _ = fs::remove_dir_all(&temp_dir);

    Ok(UpdateOutcome {
        status: UpdateStatus::Updated,
        previous_version,
        installed_version: asset.version,
        executable_path,
    })
}

fn resolve_release_asset() -> Result<ReleaseAsset> {
    let target = current_release_target()?;
    let repo = env::var("SAGY_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string());
    validate_repository(&repo)?;
    let release = fetch_latest_release(&repo)?;
    let tag = release.tag_name;
    let version = parse_release_version(&tag)?.to_string();
    Ok(ReleaseAsset {
        repo,
        tag,
        version,
        target,
    })
}

fn validate_repository(repo: &str) -> Result<()> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || !is_safe_repository_component(owner)
        || !is_safe_repository_component(name)
    {
        bail!("invalid update repository name: {repo:?}");
    }
    Ok(())
}

fn is_safe_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn fetch_latest_release(repo: &str) -> Result<GithubRelease> {
    let client = http_client()?;
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let response = client
        .get(&url)
        .send()
        .with_context(|| format!("failed to fetch latest release from {url}"))?;
    if !response.status().is_success() {
        bail!(
            "GitHub release lookup for {repo} returned HTTP {}",
            response.status()
        );
    }
    response
        .json::<GithubRelease>()
        .with_context(|| format!("failed to decode release payload from {url}"))
}

fn download_release_binary(asset: &ReleaseAsset) -> Result<Vec<u8>> {
    validate_repository(&asset.repo)?;
    let parsed_version = parse_release_version(&asset.tag)?;
    if asset.version != parsed_version.to_string() {
        bail!(
            "release asset version does not match its tag: {} vs {}",
            asset.version,
            asset.tag
        );
    }
    let client = http_client()?;
    let asset_name = format!(
        "sagy-{}-{}.{}",
        asset.tag, asset.target.triple, asset.target.archive_ext
    );
    let download_url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        asset.repo, asset.tag, asset_name
    );
    let response = client
        .get(&download_url)
        .send()
        .with_context(|| format!("failed to download asset from {download_url}"))?;
    if !response.status().is_success() {
        bail!(
            "failed to download release asset from {download_url}: HTTP {}",
            response.status()
        );
    }

    let bytes = response
        .bytes()
        .with_context(|| format!("failed to read payload from {download_url}"))?
        .to_vec();
    if bytes.is_empty() {
        bail!("release asset from {download_url} is empty");
    }

    verify_checksum(&client, asset, &asset_name, &bytes)?;

    unpack_binary_from_archive(&bytes, asset.target.archive_ext, "sagy")
}

fn verify_checksum(
    client: &Client,
    asset: &ReleaseAsset,
    asset_name: &str,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() {
        bail!("release asset {asset_name} is empty");
    }
    let sums_url = format!(
        "https://github.com/{}/releases/download/{}/SHA256SUMS.txt",
        asset.repo, asset.tag
    );
    let response = client
        .get(&sums_url)
        .send()
        .with_context(|| format!("failed to download checksums from {sums_url}"))?;
    if !response.status().is_success() {
        bail!(
            "checksum download from {sums_url} returned HTTP {}",
            response.status()
        );
    }
    let sums_text = response
        .text()
        .with_context(|| format!("failed to read checksums from {sums_url}"))?;
    let expected_hash = parse_checksum_entry(&sums_text, asset_name)?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let calculated = format!("{:x}", hasher.finalize());
    if !calculated.eq_ignore_ascii_case(&expected_hash) {
        bail!(
            "SHA-256 checksum mismatch for {asset_name}!\nExpected: {expected_hash}\nActual:   {calculated}"
        );
    }
    Ok(())
}

fn parse_checksum_entry(sums_text: &str, asset_name: &str) -> Result<String> {
    let mut seen_files = HashSet::new();
    let mut matching_hash = None;

    for (line_number, line) in sums_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let mut fields = line.split_whitespace();
        let hash = fields.next().ok_or_else(|| {
            anyhow::anyhow!("malformed checksum entry on line {}", line_number + 1)
        })?;
        let raw_file = fields.next().ok_or_else(|| {
            anyhow::anyhow!("malformed checksum entry on line {}", line_number + 1)
        })?;
        if fields.next().is_some() {
            bail!("malformed checksum entry on line {}", line_number + 1);
        }
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid SHA-256 checksum on line {}", line_number + 1);
        }

        // `*filename` is the binary-mode spelling emitted by common checksum tools.
        let file = raw_file.strip_prefix('*').unwrap_or(raw_file);
        if !is_safe_checksum_filename(file) {
            bail!("unsafe checksum target on line {}", line_number + 1);
        }
        if !seen_files.insert(file) {
            bail!(
                "duplicate or empty checksum target on line {}",
                line_number + 1
            );
        }
        if file == asset_name {
            matching_hash = Some(hash.to_ascii_lowercase());
        }
    }

    matching_hash.ok_or_else(|| anyhow::anyhow!("checksum entry for {asset_name} is missing"))
}

fn is_safe_checksum_filename(file: &str) -> bool {
    !file.is_empty()
        && file != "."
        && file != ".."
        && file
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn unpack_binary_from_archive(bytes: &[u8], ext: &str, bin_name: &str) -> Result<Vec<u8>> {
    let expected_name = binary_filename_for_current_platform(bin_name);
    match ext {
        "tar.gz" | "tgz" => {
            let decoder = GzDecoder::new(Cursor::new(bytes));
            let mut archive = Archive::new(decoder);
            for entry in archive.entries().context("invalid tar archive")? {
                let mut entry = entry.context("invalid tar entry")?;
                let path = entry.path().context("invalid entry path")?;
                if is_safe_archive_entry_path(&path, &expected_name)
                    && entry.header().entry_type().is_file()
                {
                    let mut buffer = Vec::new();
                    entry
                        .read_to_end(&mut buffer)
                        .context("failed to read binary from archive")?;
                    if buffer.is_empty() {
                        bail!("binary {expected_name} in tar archive is empty");
                    }
                    return Ok(buffer);
                }
            }
            bail!("binary {expected_name} not found in tar archive");
        }
        "zip" => {
            let mut archive = ZipArchive::new(Cursor::new(bytes)).context("invalid zip archive")?;
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).context("invalid zip entry")?;
                if is_safe_archive_entry_path(Path::new(file.name()), &expected_name)
                    && !file.is_dir()
                    && !is_zip_symlink(file.unix_mode())
                {
                    let mut buffer = Vec::new();
                    file.read_to_end(&mut buffer)
                        .context("failed to read binary from zip archive")?;
                    if buffer.is_empty() {
                        bail!("binary {expected_name} in zip archive is empty");
                    }
                    return Ok(buffer);
                }
            }
            bail!("binary {expected_name} not found in zip archive");
        }
        _ => bail!("unsupported archive extension: {ext}"),
    }
}

fn is_zip_symlink(unix_mode: Option<u32>) -> bool {
    unix_mode.is_some_and(|mode| mode & 0o170000 == 0o120000)
}

fn is_safe_archive_entry_path(path: &Path, expected_name: &str) -> bool {
    path.file_name() == Some(OsStr::new(expected_name))
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn http_client() -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(UPDATER_USER_AGENT));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github.v3+json"),
    );
    Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("failed to construct HTTP client")
}

pub fn current_release_target() -> Result<ReleaseTarget> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok(ReleaseTarget {
            triple: "aarch64-apple-darwin",
            archive_ext: "tar.gz",
        })
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok(ReleaseTarget {
            triple: "x86_64-apple-darwin",
            archive_ext: "tar.gz",
        })
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(ReleaseTarget {
            triple: "x86_64-unknown-linux-musl",
            archive_ext: "tar.gz",
        })
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok(ReleaseTarget {
            triple: "x86_64-pc-windows-msvc",
            archive_ext: "zip",
        })
    } else {
        bail!("unsupported target platform for auto-update")
    }
}

fn binary_filename_for_current_platform(base_name: &str) -> String {
    if cfg!(windows) {
        format!("{base_name}.exe")
    } else {
        base_name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn checksum_requires_exact_target_and_strict_hash() {
        assert_eq!(
            parse_checksum_entry(&format!("{VALID_HASH}  sagy.tar.gz\n"), "sagy.tar.gz")
                .expect("valid checksum"),
            VALID_HASH
        );
        assert!(parse_checksum_entry("not-a-hash  sagy.tar.gz\n", "sagy.tar.gz").is_err());
        assert!(
            parse_checksum_entry(&format!("{VALID_HASH}  ./sagy.tar.gz\n"), "sagy.tar.gz").is_err()
        );
        assert!(
            parse_checksum_entry(&format!("{VALID_HASH}  ../sagy.tar.gz\n"), "sagy.tar.gz")
                .is_err()
        );
        assert!(
            parse_checksum_entry(
                &format!("{VALID_HASH}  sagy-1.2.3+build.tar.gz\n"),
                "sagy-1.2.3+build.tar.gz"
            )
            .is_ok()
        );
    }

    #[test]
    fn checksum_rejects_missing_and_duplicate_targets() {
        assert!(
            parse_checksum_entry(&format!("{VALID_HASH}  other.tar.gz\n"), "sagy.tar.gz").is_err()
        );
        let duplicate = format!("{VALID_HASH}  sagy.tar.gz\n{VALID_HASH}  sagy.tar.gz\n");
        assert!(parse_checksum_entry(&duplicate, "sagy.tar.gz").is_err());
    }

    #[test]
    fn archive_entry_paths_reject_escape_and_allow_safe_nested_files() {
        assert!(is_safe_archive_entry_path(Path::new("dist/sagy"), "sagy"));
        assert!(!is_safe_archive_entry_path(Path::new("../sagy"), "sagy"));
        assert!(!is_safe_archive_entry_path(
            Path::new("dist/../sagy"),
            "sagy"
        ));
        assert!(!is_safe_archive_entry_path(Path::new("sagy-link"), "sagy"));
    }

    #[test]
    fn zip_symlink_mode_is_rejected() {
        assert!(is_zip_symlink(Some(0o120777)));
        assert!(is_zip_symlink(Some(0o120000)));
        assert!(!is_zip_symlink(Some(0o100755)));
        assert!(!is_zip_symlink(None));
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.2.0", "0.1.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("0.1.1", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.2.0"));
        assert!(!is_newer_version("v0.0.9", "0.1.0"));
    }

    #[test]
    fn strict_release_tags_allow_one_v_prefix_only() {
        assert_eq!(
            parse_release_version("v1.2.3")
                .expect("v prefix")
                .to_string(),
            "1.2.3"
        );
        assert_eq!(
            parse_release_version("1.2.3-rc.1+build.7")
                .expect("pre-release and build metadata")
                .to_string(),
            "1.2.3-rc.1+build.7"
        );
        for malformed in [
            "vv1.2.3",
            "V1.2.3",
            "1.2",
            "1.2.3junk",
            " 1.2.3",
            "1.2.3 ",
            "1.2.03",
            "1.2.3/other",
        ] {
            assert!(
                parse_release_version(malformed).is_err(),
                "accepted malformed tag {malformed:?}"
            );
        }
    }

    #[test]
    fn semver_pre_release_and_build_order_is_correct() {
        assert!(is_newer_version("1.0.0", "1.0.0-rc.1"));
        assert!(is_newer_version("1.0.0-rc.2", "1.0.0-rc.1"));
        assert!(!is_newer_version("1.0.0-rc.2", "1.0.0-rc.10"));
        assert!(!is_newer_version("1.0.0+build.2", "1.0.0+build.1"));
        assert!(!is_newer_version(
            "1.0.0-rc.1+build.2",
            "1.0.0-rc.1+build.1"
        ));
    }

    #[test]
    fn update_policy_never_downgrades_and_force_only_reinstalls_same_version() {
        assert_eq!(
            update_decision("v1.1.0", "1.0.0", false).expect("newer release"),
            UpdateDecision::Update
        );
        assert_eq!(
            update_decision("v1.0.0", "1.0.0", false).expect("same release"),
            UpdateDecision::AlreadyCurrent
        );
        assert_eq!(
            update_decision("v1.0.0", "1.0.0", true).expect("forced same release"),
            UpdateDecision::Update
        );
        assert_eq!(
            update_decision("v1.0.0+build.2", "1.0.0+build.1", false)
                .expect("build metadata does not change precedence"),
            UpdateDecision::AlreadyCurrent
        );
        assert_eq!(
            update_decision("v1.0.0+build.2", "1.0.0+build.1", true)
                .expect("forced same precedence"),
            UpdateDecision::Update
        );
        assert!(update_decision("v0.9.9", "1.0.0", false).is_err());
        assert!(update_decision("v0.9.9", "1.0.0", true).is_err());
        assert!(update_decision("v1.2", "1.0.0", false).is_err());
        assert!(update_decision("v1.0.0junk", "1.0.0", false).is_err());
    }
}
