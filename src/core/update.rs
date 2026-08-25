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

// 下载体积上限（字节）。超时只能挡住"慢"，挡不住"大"：一个恶意或损坏的端点可以
// 用无限流把内存和磁盘吃光。每条下载都必须显式限量，超限一律 fail-closed。
// 数值与 install.sh / install.ps1 保持一致。
/// GitHub `releases/latest` 的 JSON 实测在 10KB 量级，1MiB 留出百倍余量。
const MAX_RELEASE_METADATA_BYTES: u64 = 1_048_576;
/// SHA256SUMS.txt 每行约 100 字节，一次 release 至多十几个 asset，64KiB 绰绰有余。
const MAX_CHECKSUM_MANIFEST_BYTES: u64 = 65_536;
/// 当前 release job 产出的最大归档在 10MB 量级；归档要整份读进内存做校验，
/// 128MiB 既覆盖可预见的增长，也给出一个明确的内存上界。
const MAX_RELEASE_ASSET_BYTES: u64 = 134_217_728;

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
    let staged = stage_release_binary(state_dir, &binary)?;

    self_replace::self_replace(&staged.binary)
        .with_context(|| format!("failed to replace {}", executable_path.display()))?;
    discard_staging_dir(&staged);

    Ok(UpdateOutcome {
        status: UpdateStatus::Updated,
        previous_version,
        installed_version: asset.version,
        executable_path,
    })
}

/// 本次自更新创建的一次性 staging 目录及其中的二进制。
///
/// 为什么要显式记住目录：清理路径以前是从二进制路径反推 `parent()`，
/// 反推不出来时退回整个 tmp root，删除范围会大于本次真正创建的目录。
/// 唯一安全的做法是把"我创建的那个目录"原样带下去。
#[derive(Debug, Clone)]
struct StagedBinary {
    dir: PathBuf,
    binary: PathBuf,
}

/// 删除且只删除本次创建的 staging 目录。
///
/// 失败不阻断自更新（二进制已经替换成功），但必须留下 ASCII 提示，
/// 否则 state root 下会悄悄堆积 update-<uuid> 目录。
fn discard_staging_dir(staged: &StagedBinary) {
    if let Err(error) = fs::remove_dir_all(&staged.dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "warning: failed to remove the update staging directory {}: {error}",
                staged.dir.display()
            );
        }
    }
}

/// 把已经通过校验的二进制写进 state root 下的一次性临时目录。
/// 这是整条自更新链路上**第一个**落盘动作：它之前的任何一步失败，
/// state root 必须保持一个字节都没被写过。
fn stage_release_binary(state_dir: &Path, binary: &[u8]) -> Result<StagedBinary> {
    let temp_root = storage::tmp_dir(state_dir);
    storage::create_secure_dir_all(&temp_root)?;
    let temp_dir = temp_root.join(format!("update-{}", Uuid::new_v4()));
    storage::create_secure_dir_all(&temp_dir)?;
    let temp_binary = temp_dir.join(binary_filename_for_current_platform("sagy"));
    fs::write(&temp_binary, binary)
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

    Ok(StagedBinary {
        dir: temp_dir,
        binary: temp_binary,
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
    fetch_release_metadata(&client, &url)
}

/// 下载点 1/3：release metadata。上限写在这里而不是调用方，
/// 这样"拼 URL"与"受限下载"无法被分开绕过。
fn fetch_release_metadata(client: &Client, url: &str) -> Result<GithubRelease> {
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to fetch latest release from {url}"))?;
    if !response.status().is_success() {
        bail!(
            "GitHub release lookup for {url} returned HTTP {}",
            response.status()
        );
    }
    let payload = read_response_within_limit(
        response,
        MAX_RELEASE_METADATA_BYTES,
        &format!("release metadata from {url}"),
    )?;
    serde_json::from_slice::<GithubRelease>(&payload)
        .with_context(|| format!("failed to decode release payload from {url}"))
}

/// 下载点 2/3：release 归档本体。
fn fetch_release_asset(client: &Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to download asset from {url}"))?;
    if !response.status().is_success() {
        bail!(
            "failed to download release asset from {url}: HTTP {}",
            response.status()
        );
    }
    let bytes = read_response_within_limit(
        response,
        MAX_RELEASE_ASSET_BYTES,
        &format!("release asset from {url}"),
    )?;
    if bytes.is_empty() {
        bail!("release asset from {url} is empty");
    }
    Ok(bytes)
}

/// 下载点 3/3：SHA256SUMS.txt 清单。
fn fetch_checksum_manifest(client: &Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to download checksums from {url}"))?;
    if !response.status().is_success() {
        bail!(
            "checksum download from {url} returned HTTP {}",
            response.status()
        );
    }
    let bytes = read_response_within_limit(
        response,
        MAX_CHECKSUM_MANIFEST_BYTES,
        &format!("checksum manifest from {url}"),
    )?;
    String::from_utf8(bytes)
        .with_context(|| format!("checksum manifest from {url} is not valid UTF-8"))
}

/// 把响应体读进内存，但绝不越过 `limit` 字节。
fn read_response_within_limit(
    response: reqwest::blocking::Response,
    limit: u64,
    what: &str,
) -> Result<Vec<u8>> {
    // Content-Length 只是提示，但它能让明显超限的响应在下载前就被拒掉。
    enforce_advertised_length(response.content_length(), limit, what)?;
    read_within_limit(response, limit, what)
}

fn enforce_advertised_length(advertised: Option<u64>, limit: u64, what: &str) -> Result<()> {
    match advertised {
        Some(length) if length > limit => {
            bail!("{what} advertises {length} bytes which exceeds the {limit} byte download limit")
        }
        _ => Ok(()),
    }
}

fn read_within_limit<R: Read>(reader: R, limit: u64, what: &str) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    // 多读 1 字节，用来把"正好等于上限"和"已经超限"区分开。
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut buffer)
        .with_context(|| format!("failed to read {what}"))?;
    if buffer.len() as u64 > limit {
        bail!("{what} exceeds the {limit} byte download limit");
    }
    Ok(buffer)
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
    let bytes = fetch_release_asset(&client, &download_url)?;

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
    let sums_text = fetch_checksum_manifest(client, &sums_url)?;
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    use super::*;

    const VALID_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // ---------------------------------------------------------------------
    // 三个真实下载点的回归保护。
    //
    // 只测 `read_within_limit` 是抓不到"某个调用点忘了限量"的：那是 helper 的
    // 单元测试，把任意一处调用换成无界读取它照样绿。所以下面三个测试各起一个
    // 本地 HTTP server，直接喂给**生产函数** `fetch_release_metadata` /
    // `fetch_checksum_manifest` / `fetch_release_asset`，并断言错误信息里带着
    // 该调用点自己的字节上限——上限一旦被删掉或调高，断言立刻变红。
    // ---------------------------------------------------------------------

    /// 一次性 HTTP server：接一个连接、回一份预先构造好的响应、然后关闭。
    fn serve_once(response: Vec<u8>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("listener address");
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // 必须先把请求头读干净，否则写响应时可能先收到 RST。
            let Ok(peer) = stream.try_clone() else {
                return;
            };
            let mut reader = BufReader::new(peer);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line == "\r\n" || line == "\n" => break,
                    Ok(_) => {}
                }
            }
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        });
        (format!("http://{address}"), handle)
    }

    /// 声明 `Content-Length` 的响应：用来走"下载前就按声明长度拒绝"这条路径。
    fn response_advertising(length: u64, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// 不声明长度、靠关连接来定界的响应：用来走"流式读到上限就截断"这条路径。
    fn response_close_delimited(body: &[u8]) -> Vec<u8> {
        let mut out = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        out.extend_from_slice(body);
        out
    }

    fn rendered_error(error: anyhow::Error) -> String {
        format!("{error:#}")
    }

    /// 断言错误确实来自"这个调用点的这个上限"，而不是别的失败（比如连接被截断）。
    fn assert_rejected_by_limit(error: anyhow::Error, limit: u64, context: &str) {
        let rendered = rendered_error(error);
        assert!(
            rendered.contains(&format!("{limit} byte download limit")),
            "{context} failed for the wrong reason: {rendered}"
        );
    }

    /// AC-R7-1.1：release metadata 调用点。
    #[test]
    fn release_metadata_call_site_is_bounded() {
        let client = http_client().expect("client");
        let oversize = MAX_RELEASE_METADATA_BYTES + 1;

        // 1) Content-Length 已经超限：连读都不该读。
        let (url, server) =
            serve_once(response_advertising(oversize, b"{\"tag_name\":\"v9.9.9\"}"));
        let error = fetch_release_metadata(&client, &url).expect_err("advertised oversize");
        assert_rejected_by_limit(error, MAX_RELEASE_METADATA_BYTES, "release metadata");
        server.join().expect("join server");

        // 2) 不声明长度、直接灌超限字节：流式读到上限必须截断并 fail-closed。
        let body = vec![b'a'; oversize as usize];
        let (url, server) = serve_once(response_close_delimited(&body));
        let error = fetch_release_metadata(&client, &url).expect_err("streamed oversize");
        assert_rejected_by_limit(error, MAX_RELEASE_METADATA_BYTES, "release metadata");
        server.join().expect("join server");

        // 3) 正常大小仍然必须被接受——否则这个测试是"恒红"，证明不了上限的存在。
        let (url, server) = serve_once(response_close_delimited(b"{\"tag_name\":\"v9.9.9\"}"));
        let release = fetch_release_metadata(&client, &url).expect("normal metadata");
        assert_eq!(release.tag_name, "v9.9.9");
        server.join().expect("join server");
    }

    /// AC-R7-1.1：checksum 清单调用点。
    #[test]
    fn checksum_manifest_call_site_is_bounded() {
        let client = http_client().expect("client");
        let oversize = MAX_CHECKSUM_MANIFEST_BYTES + 1;
        let entry = format!("{VALID_HASH}  sagy.tar.gz\n");

        let (url, server) = serve_once(response_advertising(oversize, entry.as_bytes()));
        let error = fetch_checksum_manifest(&client, &url).expect_err("advertised oversize");
        assert_rejected_by_limit(error, MAX_CHECKSUM_MANIFEST_BYTES, "checksum manifest");
        server.join().expect("join server");

        // 清单里含有完全合法的条目，只有体积上限能拒绝它。
        let mut body = entry.clone().into_bytes();
        while (body.len() as u64) <= MAX_CHECKSUM_MANIFEST_BYTES {
            body.extend_from_slice(entry.as_bytes());
        }
        let (url, server) = serve_once(response_close_delimited(&body));
        let error = fetch_checksum_manifest(&client, &url).expect_err("streamed oversize");
        assert_rejected_by_limit(error, MAX_CHECKSUM_MANIFEST_BYTES, "checksum manifest");
        server.join().expect("join server");

        let (url, server) = serve_once(response_close_delimited(entry.as_bytes()));
        assert_eq!(
            fetch_checksum_manifest(&client, &url).expect("normal manifest"),
            entry
        );
        server.join().expect("join server");
    }

    /// AC-R7-1.1：release 归档本体调用点。
    /// 除了 fail-closed，还要证明失败时 state root 一个字节都没被写过。
    #[test]
    fn release_asset_call_site_is_bounded_and_never_stages_on_failure() {
        let client = http_client().expect("client");
        let state_dir = tempfile::TempDir::new().expect("state dir");
        let oversize = MAX_RELEASE_ASSET_BYTES + 1;

        // 128MiB 的归档上限不适合真的在测试里传输，因此这里用"声明长度已超限"
        // 这条路径：它同样位于 read_response_within_limit 之内，把该调用点换成
        // 无界读取时，错误会变成连接被截断而不是超限，断言随即变红。
        let (url, server) = serve_once(response_advertising(oversize, b"not-a-real-archive"));
        let staged = fetch_release_asset(&client, &url)
            .and_then(|bytes| stage_release_binary(state_dir.path(), &bytes));
        let error = staged.expect_err("advertised oversize");
        assert_rejected_by_limit(error, MAX_RELEASE_ASSET_BYTES, "release asset");
        server.join().expect("join server");

        assert!(
            !storage::tmp_dir(state_dir.path()).exists(),
            "a rejected download still created {}",
            storage::tmp_dir(state_dir.path()).display()
        );
        assert_eq!(
            fs::read_dir(state_dir.path())
                .expect("read state root")
                .count(),
            0,
            "a rejected download wrote into the state root"
        );

        // 正对照：合法响应确实会走到落盘这一步，证明上面的"没落盘"断言有牙。
        let (url, server) = serve_once(response_close_delimited(b"archive-bytes"));
        let bytes = fetch_release_asset(&client, &url).expect("normal asset");
        assert_eq!(bytes, b"archive-bytes");
        let staged = stage_release_binary(state_dir.path(), &bytes).expect("stage binary");
        assert!(staged.binary.is_file(), "staged binary is missing");
        assert_eq!(fs::read(&staged.binary).expect("read staged binary"), bytes);
        // 反证上面的"没落盘"断言不是空断言：真的走到落盘时 tmp/ 一定会出现。
        assert!(storage::tmp_dir(state_dir.path()).is_dir());
        server.join().expect("join server");
    }

    /// AC-R12-5.1: 清理范围必须严格限定在本次创建的 staging 目录。
    ///
    /// 旧实现从二进制路径反推 `parent()`，反推不出来就退回整个 tmp root，
    /// 于是并发的另一次自更新的 staging 目录、以及 tmp root 下的其它文件
    /// 都会被一起删掉。
    #[test]
    fn staging_cleanup_only_removes_the_directory_it_created() {
        let state_dir = tempfile::TempDir::new().expect("state dir");
        let mine = stage_release_binary(state_dir.path(), b"mine").expect("stage mine");
        let other = stage_release_binary(state_dir.path(), b"other").expect("stage other");
        let tmp_root = storage::tmp_dir(state_dir.path());
        let bystander = tmp_root.join("unrelated-artifact");
        fs::write(&bystander, b"keep me").expect("write bystander");
        assert_ne!(mine.dir, other.dir, "staging directories must be unique");

        discard_staging_dir(&mine);

        assert!(!mine.dir.exists(), "the staging directory was not removed");
        assert!(
            other.binary.is_file(),
            "cleanup destroyed another update's staging directory: {}",
            other.dir.display()
        );
        assert!(
            bystander.is_file(),
            "cleanup destroyed an unrelated file under the tmp root"
        );
        assert!(tmp_root.is_dir(), "cleanup destroyed the whole tmp root");

        // 目录已经不在时再删一次不得报警：清理是幂等的。
        discard_staging_dir(&mine);
    }

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

    /// 版本比较只剩 `update_decision` 这一条严格路径：
    /// 非法或更旧的版本必须报错，不能再被静默当成"当前版本"。
    #[test]
    fn strict_version_comparison_is_the_only_update_entry_point() {
        for (remote, current) in [("0.2.0", "0.1.0"), ("1.0.0", "0.9.9"), ("0.1.1", "0.1.0")] {
            assert_eq!(
                update_decision(remote, current, false).expect("newer release"),
                UpdateDecision::Update,
                "{remote} should update over {current}"
            );
        }
        assert_eq!(
            update_decision("0.1.0", "0.1.0", false).expect("same release"),
            UpdateDecision::AlreadyCurrent
        );
        for (remote, current) in [("0.1.0", "0.2.0"), ("v0.0.9", "0.1.0")] {
            assert!(
                update_decision(remote, current, false).is_err(),
                "{remote} must not be accepted over {current}"
            );
        }
        for malformed in ["", "latest", "v1.2", "1.2.3junk"] {
            assert!(
                update_decision(malformed, "0.1.0", false).is_err(),
                "malformed remote tag {malformed:?} was silently accepted"
            );
            assert!(
                update_decision("0.2.0", malformed, false).is_err(),
                "malformed installed version {malformed:?} was silently accepted"
            );
        }
    }

    /// AC-4：每条下载都必须有明确的字节上限，超限 fail-closed。
    #[test]
    fn download_size_limits_are_fail_closed() {
        assert_eq!(
            read_within_limit(&b"12345"[..], 5, "payload").expect("payload at the limit"),
            b"12345"
        );
        assert!(read_within_limit(&b"123456"[..], 5, "payload").is_err());
        assert!(read_within_limit(&b""[..], 5, "payload").is_ok());

        assert!(enforce_advertised_length(None, 5, "payload").is_ok());
        assert!(enforce_advertised_length(Some(5), 5, "payload").is_ok());
        assert!(enforce_advertised_length(Some(6), 5, "payload").is_err());

        // 上限必须按用途分级：清单 < metadata < 归档。
        // 具体数值同时被钉死，因为 install.sh / install.ps1 里有三份同名常量，
        // 只改一处会让三条安装路径的语义悄悄分叉（见 tests/p0_checksum.rs）。
        const {
            assert!(MAX_CHECKSUM_MANIFEST_BYTES < MAX_RELEASE_METADATA_BYTES);
            assert!(MAX_RELEASE_METADATA_BYTES < MAX_RELEASE_ASSET_BYTES);
            assert!(MAX_RELEASE_METADATA_BYTES == 1_048_576);
            assert!(MAX_CHECKSUM_MANIFEST_BYTES == 65_536);
            assert!(MAX_RELEASE_ASSET_BYTES == 134_217_728);
        }
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
        assert_eq!(
            update_decision("1.0.0", "1.0.0-rc.1", false).expect("release beats pre-release"),
            UpdateDecision::Update
        );
        assert_eq!(
            update_decision("1.0.0-rc.2", "1.0.0-rc.1", false).expect("later pre-release"),
            UpdateDecision::Update
        );
        // rc.2 < rc.10：数值比较而非字典序，因此这是一次降级。
        assert!(update_decision("1.0.0-rc.2", "1.0.0-rc.10", false).is_err());
        // build metadata 不参与优先级比较。
        assert_eq!(
            update_decision("1.0.0+build.2", "1.0.0+build.1", false).expect("same precedence"),
            UpdateDecision::AlreadyCurrent
        );
        assert_eq!(
            update_decision("1.0.0-rc.1+build.2", "1.0.0-rc.1+build.1", false)
                .expect("same precedence"),
            UpdateDecision::AlreadyCurrent
        );
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
