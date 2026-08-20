use std::env;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;
use tar::Archive;
use uuid::Uuid;
use zip::ZipArchive;

use crate::core::storage;

const DEFAULT_REPO: &str = "lauzhihao/sagy";

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
    let parse_semver = |v: &str| -> Vec<u64> {
        let clean = v.trim().strip_prefix('v').unwrap_or(v.trim());
        clean
            .split(['.', '-', '+'])
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };

    let remote_parts = parse_semver(remote);
    let current_parts = parse_semver(current);

    let max_len = remote_parts.len().max(current_parts.len());
    for i in 0..max_len {
        let r = remote_parts.get(i).copied().unwrap_or(0);
        let c = current_parts.get(i).copied().unwrap_or(0);
        if r > c {
            return true;
        } else if r < c {
            return false;
        }
    }
    false
}

pub fn self_update(state_dir: &Path, force: bool) -> Result<UpdateOutcome> {
    let executable_path =
        env::current_exe().context("failed to resolve current executable path")?;
    let previous_version = env!("CARGO_PKG_VERSION").to_string();
    let asset = resolve_release_asset()?;

    let is_newer = is_newer_version(&asset.version, &previous_version);
    if !is_newer && !force {
        return Ok(UpdateOutcome {
            status: UpdateStatus::AlreadyCurrent,
            previous_version: previous_version.clone(),
            installed_version: previous_version,
            executable_path,
        });
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
    sync_sibling_binaries(&executable_path);
    let _ = fs::remove_dir_all(&temp_dir);

    Ok(UpdateOutcome {
        status: UpdateStatus::Updated,
        previous_version,
        installed_version: asset.version,
        executable_path,
    })
}

fn sync_sibling_binaries(source_exe: &Path) {
    if let Some(parent) = source_exe.parent() {
        let aliases = ["flash", "pro", "think"];
        let ext = if cfg!(windows) { ".exe" } else { "" };
        let source_canon = source_exe.canonicalize().ok();

        for alias in aliases {
            let alias_name = format!("{alias}{ext}");
            let target_path = parent.join(&alias_name);
            if !target_path.exists() {
                continue;
            }

            if let Ok(target_canon) = target_path.canonicalize() {
                if Some(&target_canon) == source_canon.as_ref() {
                    continue;
                }
            } else if target_path == source_exe {
                continue;
            }

            let temp_path = parent.join(format!(".{alias_name}.{}.tmp", Uuid::new_v4()));
            if fs::copy(source_exe, &temp_path).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = fs::metadata(&temp_path) {
                        let mut perms = metadata.permissions();
                        perms.set_mode(0o755);
                        let _ = fs::set_permissions(&temp_path, perms);
                    }
                }
                let _ = fs::rename(&temp_path, &target_path);
            }
        }
    }
}

fn resolve_release_asset() -> Result<ReleaseAsset> {
    let target = current_release_target()?;
    let repo = env::var("SAGY_UPDATE_REPO").unwrap_or_else(|_| DEFAULT_REPO.to_string());
    let release = fetch_latest_release(&repo)?;
    let tag = release.tag_name.trim().to_string();
    let version = tag.strip_prefix('v').unwrap_or(&tag).trim().to_string();
    Ok(ReleaseAsset {
        repo,
        tag,
        version,
        target,
    })
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

    verify_checksum(&client, asset, &asset_name, &bytes)?;

    unpack_binary_from_archive(&bytes, asset.target.archive_ext, "sagy")
}

fn verify_checksum(
    client: &Client,
    asset: &ReleaseAsset,
    asset_name: &str,
    payload: &[u8],
) -> Result<()> {
    let sums_url = format!(
        "https://github.com/{}/releases/download/{}/SHA256SUMS.txt",
        asset.repo, asset.tag
    );
    if let Ok(resp) = client.get(&sums_url).send() {
        if resp.status().is_success() {
            let sums_text = resp.text().unwrap_or_default();
            for line in sums_text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let expected_hash = parts[0];
                    let file = parts[1].trim_start_matches('*').trim_start_matches("./");
                    if file == asset_name {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(payload);
                        let calculated = format!("{:x}", hasher.finalize());
                        if !calculated.eq_ignore_ascii_case(expected_hash) {
                            bail!(
                                "SHA-256 checksum mismatch for {asset_name}!\nExpected: {expected_hash}\nActual:   {calculated}"
                            );
                        }
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
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
                if let Some(file_name) = path.file_name() {
                    if file_name == expected_name.as_str() {
                        let mut buffer = Vec::new();
                        entry
                            .read_to_end(&mut buffer)
                            .context("failed to read binary from archive")?;
                        return Ok(buffer);
                    }
                }
            }
            bail!("binary {expected_name} not found in tar archive");
        }
        "zip" => {
            let mut archive = ZipArchive::new(Cursor::new(bytes)).context("invalid zip archive")?;
            for i in 0..archive.len() {
                let mut file = archive.by_index(i).context("invalid zip entry")?;
                if file.name().ends_with(&expected_name) {
                    let mut buffer = Vec::new();
                    file.read_to_end(&mut buffer)
                        .context("failed to read binary from zip archive")?;
                    return Ok(buffer);
                }
            }
            bail!("binary {expected_name} not found in zip archive");
        }
        _ => bail!("unsupported archive extension: {ext}"),
    }
}

fn http_client() -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("sagy-updater/0.1.0"));
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

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.2.0", "0.1.0"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(is_newer_version("0.1.1", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.2.0"));
        assert!(!is_newer_version("v0.0.9", "0.1.0"));
    }
}
