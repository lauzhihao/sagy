use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use sha2::{Digest, Sha256};

use super::account::credential_store::CredentialStore;
use super::launch_observation::{LaunchDiagnosticParser, LaunchOutcome, ProcessTermination};
use super::paths::{account_dir_checked, active_home_roots, active_home_scope_id, find_agy_bin};
use crate::core::atomic_io::{ExternalDirectoryCapability, NormalizedStoreRoot, SafeRelativePath};
use crate::core::state::{AccountType, CredentialRefKind, ManagedLayout, SlotState};
use crate::core::state_store::{StateSession, StateStore};

// agy models 的真实标识。effort 烧在 ID 内, 不再单独传 --effort。
pub const DEFAULT_MODEL_ID: &str = "gemini-3.7-flash-high";

const CREDENTIAL_LOCK_FILENAME: &str = ".sagy-credential.lock";
const ACTIVE_HOME_LOCK_FILENAME: &str = ".sagy-active-home.lock";
const ACTIVE_TOKEN_FILENAME: &str = "antigravity-oauth-token";
const ACTIVE_DOCUMENT_FILENAME: &str = "oauth_creds.json";
const MAX_ACTIVE_CREDENTIAL_BYTES: usize = 256 * 1024;

/// Exact authentication material resolved from State v2 and its fixed slot.
/// It intentionally contains no `AccountRecord`, caller path, or legacy
/// embedded secret.
pub(crate) struct LaunchCredential {
    account_id: String,
    account_type: AccountType,
    project_id: Option<String>,
    auth: LaunchAuth,
    _leases: LaunchLeases,
}

enum LaunchAuth {
    OAuth,
    ApiKey(String),
    Vertex(PathBuf),
}

struct LaunchLeases {
    _account: ExternalDirectoryCapability,
    token_home: ExternalDirectoryCapability,
    document_home: ExternalDirectoryCapability,
    home_scope_id: String,
}

impl fmt::Debug for LaunchCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = match &self.auth {
            LaunchAuth::OAuth => "oauth",
            LaunchAuth::ApiKey(_) => "api_key",
            LaunchAuth::Vertex(_) => "vertex",
        };
        formatter
            .debug_struct("LaunchCredential")
            .field("account_id", &self.account_id)
            .field("account_type", &self.account_type)
            .field("auth", &auth)
            .finish_non_exhaustive()
    }
}

/// Safe, bounded failures from the observed launcher.
///
/// The error deliberately stores only an [`io::ErrorKind`].  OS error text can
/// include implementation-specific path fragments, while the command's
/// arguments may contain credentials.  The observed API must never make those
/// arguments part of a diagnostic value or its `Debug` output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchError {
    /// No executable could be found by the existing Antigravity lookup rules.
    BinaryNotFound,
    /// The selected account cannot be represented by the launcher environment.
    InvalidConfiguration,
    /// State changed while the fixed credential/home leases were acquired.
    StateChanged,
    /// The child could not be spawned.
    Spawn(io::ErrorKind),
    /// The child process could not be waited for.
    Wait(io::ErrorKind),
    /// The child did not expose the stderr pipe required by the observed API.
    StderrUnavailable,
    /// Reading the child stderr pipe failed.
    DrainRead(io::ErrorKind),
    /// The dedicated drain thread panicked before returning its bounded state.
    DrainJoin,
}

impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinaryNotFound => formatter.write_str("Antigravity CLI executable not found"),
            Self::InvalidConfiguration => {
                formatter.write_str("account configuration is invalid for Antigravity launch")
            }
            Self::StateChanged => {
                formatter.write_str("account state changed while preparing Antigravity launch")
            }
            Self::Spawn(kind) => write!(formatter, "failed to spawn Antigravity CLI ({kind:?})"),
            Self::Wait(kind) => write!(formatter, "failed to wait for Antigravity CLI ({kind:?})"),
            Self::StderrUnavailable => {
                formatter.write_str("Antigravity CLI stderr pipe unavailable")
            }
            Self::DrainRead(kind) => write!(
                formatter,
                "failed to drain Antigravity CLI stderr ({kind:?})"
            ),
            Self::DrainJoin => formatter.write_str("Antigravity CLI stderr drain thread failed"),
        }
    }
}

impl std::error::Error for LaunchError {}

impl super::AntigravityAdapter {
    /// Resolve and lease the exact current v2 credential.
    ///
    /// The account lease is acquired before the two active-home leases.  State
    /// is then re-read and compared with the caller's session, so a concurrent
    /// switch either remains blocked behind these leases or is observed as a
    /// revision change before a child is spawned.
    pub(crate) fn resolve_launch_credential(
        &self,
        state_dir: &Path,
        session: &StateSession,
        account_id: &str,
    ) -> std::result::Result<LaunchCredential, LaunchError> {
        let session_state = session.state();
        if session_state.version != crate::core::state::STATE_V2_VERSION
            || session.read().recovery_pending
        {
            return Err(LaunchError::InvalidConfiguration);
        }
        let session_account = session_state
            .accounts
            .iter()
            .find(|account| account.id == account_id)
            .ok_or(LaunchError::InvalidConfiguration)?;
        if session_state.current_account_id.as_deref() != Some(account_id) {
            return Err(LaunchError::InvalidConfiguration);
        }
        let session_reference = session_state
            .credential_refs
            .get(account_id)
            .ok_or(LaunchError::InvalidConfiguration)?;
        let session_profile = session_state
            .active_profile
            .as_ref()
            .filter(|profile| profile.account_id == account_id)
            .ok_or(LaunchError::InvalidConfiguration)?;
        if session_profile.credential_fingerprint != session_reference.fingerprint {
            return Err(LaunchError::InvalidConfiguration);
        }
        if !credential_kind_matches_account(session_account.account_type, session_reference.kind) {
            return Err(LaunchError::InvalidConfiguration);
        }

        // 另一个 sagy 会话持锁时这里会无限期阻塞。等待提示由加锁层
        // (core::atomic_io 的 lock_exclusive_with_wait_notice) 统一负责: 它覆盖
        // 全部锁点且进程内只打印一次, launch 路径再包一层只会让同一次争用打出
        // 两条不同的提示。
        let leases = acquire_launch_leases(state_dir, account_id)?;
        let reread =
            StateStore::read_from_path(state_dir).map_err(|_| LaunchError::InvalidConfiguration)?;
        if &reread.revision != session.revision() {
            return Err(LaunchError::StateChanged);
        }
        // Use only the caller-owned exact snapshot after the revision check.
        // The path re-read above is evidence that this snapshot is still the
        // committed one; it is not a second authority that could be mixed
        // with the caller's StateSession.
        if session_profile.home_scope_id != leases.home_scope_id {
            return Err(LaunchError::InvalidConfiguration);
        }
        verify_active_home_layout(session_profile.managed_layout.clone(), &leases)?;

        let store = CredentialStore::new(state_dir, account_id)
            .map_err(|_| LaunchError::InvalidConfiguration)?;
        let stored = store
            .read(session_reference)
            .map_err(|_| LaunchError::InvalidConfiguration)?;
        let expected_path = account_dir_checked(state_dir, account_id)
            .map_err(|_| LaunchError::InvalidConfiguration)?
            .join(fixed_credential_filename(session_reference.kind));
        if stored.path != expected_path {
            return Err(LaunchError::InvalidConfiguration);
        }
        if session_profile.managed_layout
            != managed_layout_for_credential(session_reference.kind, &stored.material_digest)
        {
            return Err(LaunchError::InvalidConfiguration);
        }

        // Provider project metadata is state-owned, not inherited from the
        // parent process. API-key launches intentionally have no project
        // variable: the key is the complete selected authentication input.
        let project_id = match session_reference.kind {
            CredentialRefKind::ApiKey => None,
            CredentialRefKind::OauthAccessToken | CredentialRefKind::OauthAuthorizedUser => {
                session_account
                    .project_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
            }
            CredentialRefKind::VertexServiceAccount => {
                let state_project = session_account
                    .project_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(LaunchError::InvalidConfiguration)?;
                let credential_project = stored
                    .credential
                    .native_document()
                    .and_then(|document| document.get("project_id"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(LaunchError::InvalidConfiguration)?;
                if state_project != credential_project {
                    return Err(LaunchError::InvalidConfiguration);
                }
                Some(state_project.to_string())
            }
        };
        let auth = match session_reference.kind {
            CredentialRefKind::OauthAccessToken | CredentialRefKind::OauthAuthorizedUser => {
                LaunchAuth::OAuth
            }
            CredentialRefKind::ApiKey => LaunchAuth::ApiKey(
                stored
                    .credential
                    .api_key_value()
                    .ok_or(LaunchError::InvalidConfiguration)?
                    .to_string(),
            ),
            CredentialRefKind::VertexServiceAccount => LaunchAuth::Vertex(stored.path),
        };

        Ok(LaunchCredential {
            account_id: account_id.to_string(),
            account_type: session_account.account_type,
            project_id,
            auth,
            _leases: leases,
        })
    }

    pub(crate) fn launch_agy_observed_resolved(
        &self,
        state_dir: &Path,
        credential: &LaunchCredential,
        extra_args: &[OsString],
        resume: bool,
    ) -> std::result::Result<LaunchOutcome, LaunchError> {
        self.launch_agy_observed_resolved_with_writer(
            state_dir,
            credential,
            extra_args,
            resume,
            io::stderr(),
        )
    }

    fn launch_agy_observed_resolved_with_writer<W>(
        &self,
        state_dir: &Path,
        credential: &LaunchCredential,
        extra_args: &[OsString],
        resume: bool,
        writer: W,
    ) -> std::result::Result<LaunchOutcome, LaunchError>
    where
        W: Write + Send + 'static,
    {
        let command = self.build_resolved_command(state_dir, credential, extra_args, resume)?;
        run_observed_command(command, writer)
    }

    fn build_resolved_command(
        &self,
        state_dir: &Path,
        credential: &LaunchCredential,
        extra_args: &[OsString],
        resume: bool,
    ) -> std::result::Result<Command, LaunchError> {
        let agy_bin = find_agy_bin(Some(state_dir)).ok_or(LaunchError::BinaryNotFound)?;
        let mut command = Command::new(agy_bin);
        // 区域配置是父进程持有的、与凭据无关的部署参数, 只能从父环境读取一次
        // 再显式写回, 不能靠子进程继承 (继承就等于放弃 deny-by-default)。
        let inherited_region = std::env::var(REGION_ENV_VAR).ok();
        configure_auth_environment(
            &mut command,
            &credential.auth,
            credential.project_id.as_deref(),
            inherited_region.as_deref(),
        );
        append_launch_args(&mut command, extra_args, resume);
        Ok(command)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HomeLeaseSlot {
    Token,
    Document,
}

fn acquire_launch_leases(
    state_dir: &Path,
    account_id: &str,
) -> std::result::Result<LaunchLeases, LaunchError> {
    let account_path = account_dir_checked(state_dir, account_id)
        .map_err(|_| LaunchError::InvalidConfiguration)?;
    let account_metadata =
        fs::symlink_metadata(&account_path).map_err(|_| LaunchError::InvalidConfiguration)?;
    if crate::core::atomic_io::is_link_or_reparse(&account_metadata) || !account_metadata.is_dir() {
        return Err(LaunchError::InvalidConfiguration);
    }
    let account_root = NormalizedStoreRoot::normalize(&account_path)
        .map_err(|_| LaunchError::InvalidConfiguration)?;
    let credential_lock = SafeRelativePath::new(Path::new(CREDENTIAL_LOCK_FILENAME))
        .map_err(|_| LaunchError::InvalidConfiguration)?;
    let account = ExternalDirectoryCapability::claim_or_adopt(account_root, credential_lock)
        .map_err(|_| LaunchError::InvalidConfiguration)?;

    let (token_root, document_root) =
        active_home_roots().map_err(|_| LaunchError::InvalidConfiguration)?;
    if token_root == document_root {
        return Err(LaunchError::InvalidConfiguration);
    }
    let home_scope_id = active_home_scope_id(&token_root, &document_root);
    let home_lock = SafeRelativePath::new(Path::new(ACTIVE_HOME_LOCK_FILENAME))
        .map_err(|_| LaunchError::InvalidConfiguration)?;
    let mut roots = vec![
        (HomeLeaseSlot::Token, token_root),
        (HomeLeaseSlot::Document, document_root),
    ];
    roots.sort_by(|left, right| left.1.as_path().cmp(right.1.as_path()));
    let mut opened = Vec::with_capacity(2);
    for (slot, root) in roots {
        let capability = ExternalDirectoryCapability::claim_or_adopt(root, home_lock.clone())
            .map_err(|_| LaunchError::InvalidConfiguration)?;
        opened.push((slot, capability));
    }
    let token_index = opened
        .iter()
        .position(|(slot, _)| *slot == HomeLeaseSlot::Token)
        .ok_or(LaunchError::InvalidConfiguration)?;
    let mut opened = opened.into_iter();
    let first = opened.next().ok_or(LaunchError::InvalidConfiguration)?;
    let second = opened.next().ok_or(LaunchError::InvalidConfiguration)?;
    let (token_home, document_home) = if token_index == 0 {
        (first.1, second.1)
    } else {
        (second.1, first.1)
    };
    Ok(LaunchLeases {
        _account: account,
        token_home,
        document_home,
        home_scope_id,
    })
}

fn verify_active_home_layout(
    layout: ManagedLayout,
    leases: &LaunchLeases,
) -> std::result::Result<(), LaunchError> {
    verify_active_slot(
        &leases.token_home,
        ACTIVE_TOKEN_FILENAME,
        &layout.antigravity_token,
    )?;
    verify_active_slot(
        &leases.document_home,
        ACTIVE_DOCUMENT_FILENAME,
        &layout.gemini_authorized_user,
    )
}

fn verify_active_slot(
    root: &ExternalDirectoryCapability,
    filename: &str,
    expected: &SlotState,
) -> std::result::Result<(), LaunchError> {
    let locator = SafeRelativePath::new(Path::new(filename))
        .map_err(|_| LaunchError::InvalidConfiguration)?;
    match expected {
        SlotState::Absent => {
            if root
                .inspect(&locator, true)
                .map_err(|_| LaunchError::InvalidConfiguration)?
                .is_some()
            {
                return Err(LaunchError::InvalidConfiguration);
            }
        }
        SlotState::Exact { sha256 } => {
            let bytes = root
                .read_bounded(&locator, MAX_ACTIVE_CREDENTIAL_BYTES)
                .map_err(|_| LaunchError::InvalidConfiguration)?
                .ok_or(LaunchError::InvalidConfiguration)?;
            let mut digest = Sha256::new();
            digest.update(&bytes);
            if format!("{:x}", digest.finalize()) != *sha256 {
                return Err(LaunchError::InvalidConfiguration);
            }
        }
    }
    Ok(())
}

fn managed_layout_for_credential(kind: CredentialRefKind, digest: &str) -> ManagedLayout {
    let digest = digest.strip_prefix("sha256:").unwrap_or(digest);
    match kind {
        CredentialRefKind::OauthAccessToken => ManagedLayout {
            antigravity_token: SlotState::Exact {
                sha256: digest.to_string(),
            },
            gemini_authorized_user: SlotState::Absent,
        },
        CredentialRefKind::OauthAuthorizedUser => ManagedLayout {
            antigravity_token: SlotState::Absent,
            gemini_authorized_user: SlotState::Exact {
                sha256: digest.to_string(),
            },
        },
        CredentialRefKind::ApiKey | CredentialRefKind::VertexServiceAccount => {
            ManagedLayout::default()
        }
    }
}

fn fixed_credential_filename(kind: CredentialRefKind) -> &'static str {
    match kind {
        CredentialRefKind::OauthAccessToken => ACTIVE_TOKEN_FILENAME,
        CredentialRefKind::OauthAuthorizedUser
        | CredentialRefKind::ApiKey
        | CredentialRefKind::VertexServiceAccount => "credentials.json",
    }
}

fn credential_kind_matches_account(account_type: AccountType, kind: CredentialRefKind) -> bool {
    match account_type {
        AccountType::OAuth => matches!(
            kind,
            CredentialRefKind::OauthAccessToken | CredentialRefKind::OauthAuthorizedUser
        ),
        AccountType::ApiKey => kind == CredentialRefKind::ApiKey,
        AccountType::Vertex => kind == CredentialRefKind::VertexServiceAccount,
    }
}

/// The single Google variable that carries no authentication authority.
///
/// deny-list 里其余变量都能改变"用哪份凭据、算到哪个项目头上":
/// `*_API_KEY` / `*_ACCESS_TOKEN` / `GOOGLE_APPLICATION_CREDENTIALS` 直接是凭据;
/// `*_PROJECT` / `*_QUOTA_PROJECT` 决定配额与账单归属;
/// `GOOGLE_GENAI_USE_VERTEXAI` / `GOOGLE_GENAI_USE_GCA` 决定走哪条认证链路,
/// 打开后 agy 会去捡 gcloud ADC, 等于绕开被选中的账号。
/// 只有 `GOOGLE_CLOUD_LOCATION` 是纯粹的区域选择: 它既不能认证身份, 也不能换
/// 一份凭据, 无条件清掉只会让父 shell 里配好的区域静默失效。
const REGION_ENV_VAR: &str = "GOOGLE_CLOUD_LOCATION";

/// Region ids are short, lowercase, and carry a numeric index unless they are
/// one of the four well-known multi-regions.
const MULTI_REGION_IDS: &[&str] = &["asia", "eu", "global", "us"];
const MAX_REGION_BYTES: usize = 32;

fn configure_auth_environment(
    command: &mut Command,
    auth: &LaunchAuth,
    project_id: Option<&str>,
    inherited_region: Option<&str>,
) {
    // Each launch starts from a clean authentication boundary. This prevents
    // a parent shell or an earlier account from contributing credentials.
    //
    // 清理表是 deny-by-default 的: 只清三个硬编码变量时, 父环境的
    // GOOGLE_API_KEY / GOOGLE_GENAI_USE_VERTEXAI 等仍会被 agy 继承,
    // 足以让子进程用一份根本没被选中的凭据去请求。
    // 表本身由 core::credential 单一维护, 这里只负责遍历, 不再自带副本。
    for name in crate::core::credential::GOOGLE_AUTH_ENV_VARS {
        command.env_remove(name);
    }
    match auth {
        LaunchAuth::OAuth => {
            if let Some(project_id) = project_id {
                command.env("GOOGLE_CLOUD_PROJECT", project_id);
            }
        }
        LaunchAuth::ApiKey(api_key) => {
            command.env("GEMINI_API_KEY", api_key);
        }
        LaunchAuth::Vertex(path) => {
            command.env("GOOGLE_APPLICATION_CREDENTIALS", path);
            if let Some(project_id) = project_id {
                command.env("GOOGLE_CLOUD_PROJECT", project_id);
            }
        }
    }
    // 区域是"重建"出来的, 不是"漏清"的: 先随 deny-list 一起清掉, 只有当父进程
    // 的值确实长得像一个 region id 时才写回。任意字符串照单全收等于给子进程留了
    // 一个可控注入点, 而区域配错只会退化成默认区域, 失败方向是安全的。
    if let Some(region) = inherited_region.and_then(sanitized_region) {
        command.env(REGION_ENV_VAR, region);
    }
}

/// Accept only a value shaped like a Google Cloud location id.
///
/// 形如 `us-central1` / `europe-west4` / `asia-northeast1-a`, 以及四个纯字母的
/// multi-region。除此之外 (空值、含空格或控制字符、非 ASCII、超长、纯字母且不在
/// multi-region 表里) 一律不写回, 行为等同于父进程没有配置区域。
fn sanitized_region(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_REGION_BYTES {
        return None;
    }
    if MULTI_REGION_IDS.contains(&value) {
        return Some(value);
    }
    let mut segments = 0_usize;
    let mut has_digit = false;
    for segment in value.split('-') {
        segments += 1;
        if segments > 3 || segment.is_empty() {
            return None;
        }
        let mut letters = 0_usize;
        let mut digits = 0_usize;
        for byte in segment.bytes() {
            match byte {
                b'a'..=b'z' if digits == 0 => letters += 1,
                b'0'..=b'9' => {
                    digits += 1;
                    has_digit = true;
                }
                _ => return None,
            }
        }
        if letters == 0 || letters > 16 || digits > 2 {
            return None;
        }
    }
    has_digit.then_some(value)
}

fn append_launch_args(command: &mut Command, extra_args: &[OsString], resume: bool) {
    command.args(final_launch_args(extra_args, resume));
}

/// Exact argv appended after the resolved `agy` executable.
fn final_launch_args(extra_args: &[OsString], resume: bool) -> Vec<OsString> {
    let mut final_args = Vec::new();
    if !has_model_override(extra_args) {
        final_args.push(OsString::from("--model"));
        final_args.push(OsString::from(DEFAULT_MODEL_ID));
    }
    if resume && !has_prompt_or_continue_args(extra_args) {
        final_args.push(OsString::from("--continue"));
    }
    final_args.extend_from_slice(extra_args);
    final_args
}

/// `-m` 是 agy 对 `--model` 的短写法。只认长写法会让 `sagy -m X` 同时收到注入的
/// 默认 `--model` 和用户的 `-m X`, 由 agy 自己决定谁生效。
fn has_model_override(args: &[OsString]) -> bool {
    contains_flag(args, "--model") || contains_flag(args, "-m")
}

/// How the child's stderr is connected to this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StderrMode {
    /// The child inherits the parent stderr descriptor unchanged.
    Inherit,
    /// The child writes into a pipe that is mirrored and observed.
    ObservePipe,
}

impl StderrMode {
    /// 父进程 stderr 是 TTY 时必须原样继承: 管道化会让 agy 的 `isatty(2)`
    /// 恒为 false, 交互式 TUI 与能力探测随之退化。此时 429 证据退化为下一次
    /// 启动时由 usage probe 发现, 交互体验优先。
    const fn for_parent(parent_stderr_is_terminal: bool) -> Self {
        if parent_stderr_is_terminal {
            Self::Inherit
        } else {
            Self::ObservePipe
        }
    }
}

fn run_observed_command<W>(
    command: Command,
    writer: W,
) -> std::result::Result<LaunchOutcome, LaunchError>
where
    W: Write + Send + 'static,
{
    run_observed_command_with_mode(
        command,
        writer,
        StderrMode::for_parent(io::stderr().is_terminal()),
    )
}

fn run_observed_command_with_mode<W>(
    mut command: Command,
    writer: W,
    mode: StderrMode,
) -> std::result::Result<LaunchOutcome, LaunchError>
where
    W: Write + Send + 'static,
{
    command.stdin(Stdio::inherit());
    command.stdout(Stdio::inherit());
    match mode {
        StderrMode::Inherit => {
            command.stderr(Stdio::inherit());
            let mut child = command
                .spawn()
                .map_err(|error| LaunchError::Spawn(error.kind()))?;
            let status = child
                .wait()
                .map_err(|error| LaunchError::Wait(error.kind()))?;
            // 没有管道就没有可采信的字节证据; 绝不从 exit code 猜测限流。
            Ok(LaunchDiagnosticParser::new().finish(process_termination(status)))
        }
        StderrMode::ObservePipe => {
            command.stderr(Stdio::piped());
            let mut child = command
                .spawn()
                .map_err(|error| LaunchError::Spawn(error.kind()))?;
            let Some(stderr) = child.stderr.take() else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LaunchError::StderrUnavailable);
            };
            let drain = std::thread::Builder::new()
                .name("sagy-agy-stderr-drain".to_owned())
                .spawn(move || drain_stderr(stderr, writer))
                .map_err(|_| LaunchError::DrainJoin);
            let Ok(drain) = drain else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LaunchError::DrainJoin);
            };
            let wait_result = child.wait();
            let drain_result = drain.join().map_err(|_| LaunchError::DrainJoin)?;
            let status = wait_result.map_err(|error| LaunchError::Wait(error.kind()))?;
            let report = drain_result?;
            // 父进程 stderr 写失败是本进程的输出问题, 与子进程的结果无关:
            // 显式丢弃, 既不能吞掉 agy 的退出码, 也不能丢掉已解析出的限流证据。
            let _ = report.writer_error;
            Ok(report.parser.finish(process_termination(status)))
        }
    }
}

struct DrainReport {
    parser: LaunchDiagnosticParser,
    writer_error: Option<io::ErrorKind>,
}

/// Drain the complete child stderr stream.  Parent mirroring is best effort,
/// but a failed write never stops reading: otherwise a child with a full pipe
/// could remain blocked forever while the launcher waits for it.
fn drain_stderr<R, W>(mut reader: R, mut writer: W) -> std::result::Result<DrainReport, LaunchError>
where
    R: Read,
    W: Write,
{
    let mut parser = LaunchDiagnosticParser::new();
    let mut writer_error = None;
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| LaunchError::DrainRead(error.kind()))?;
        if read == 0 {
            break;
        }

        // Preserve the child stream's byte order at the parent boundary.  A
        // failed write/flush is remembered but never interrupts the drain.
        if let Err(error) = writer.write_all(&chunk[..read]) {
            writer_error.get_or_insert(error.kind());
        }
        if let Err(error) = writer.flush() {
            writer_error.get_or_insert(error.kind());
        }

        // Once the 64 KiB parser bound is exceeded it rejects and discards
        // data; continue reading so the child cannot be back-pressured.
        let _ = parser.feed_chunk(&chunk[..read]);
    }

    Ok(DrainReport {
        parser,
        writer_error,
    })
}

fn process_termination(status: ExitStatus) -> ProcessTermination {
    if let Some(code) = status.code() {
        return ProcessTermination::exited(code);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ProcessTermination::signaled(signal);
        }
    }

    // On platforms without a numeric signal representation, preserve the
    // fact that the child failed without pretending to know an exit code.
    ProcessTermination::signaled(0)
}

fn contains_flag(args: &[OsString], flag: &str) -> bool {
    args.iter().any(|arg| {
        let value = arg.to_string_lossy();
        value.eq_ignore_ascii_case(flag)
            || value
                .get(..flag.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(flag))
                && value.as_bytes().get(flag.len()) == Some(&b'=')
    })
}

fn has_prompt_or_continue_args(extra_args: &[OsString]) -> bool {
    let mut skip_option_value = false;
    let mut after_boundary = false;
    for arg in extra_args {
        let s = arg.to_string_lossy();
        if after_boundary {
            return true;
        }
        if skip_option_value {
            skip_option_value = false;
            continue;
        }
        if s == "--" {
            after_boundary = true;
            continue;
        }
        if s == "--continue"
            || s == "-c"
            || s == "--prompt"
            || s == "-p"
            || s == "--print"
            || s == "-i"
            || s == "--prompt-interactive"
            || s == "--conversation"
            || s.starts_with("--prompt=")
            || s.starts_with("--print=")
            || s.starts_with("--conversation=")
        {
            return true;
        }
        // `--model custom` 中的 custom 是 option value，不是 positional prompt。
        if s == "--model" || s == "-m" {
            skip_option_value = true;
            continue;
        }
        if !s.starts_with('-') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn model_forms_suppress_default_without_becoming_prompts() {
        assert!(contains_flag(&args(&["--model", "custom"]), "--model"));
        assert!(contains_flag(&args(&["--model=custom"]), "--model"));
        assert!(!has_prompt_or_continue_args(&args(&["--model", "custom"])));
        assert!(!has_prompt_or_continue_args(&args(&["--model=custom"])));
    }

    #[test]
    fn every_model_flag_spelling_replaces_the_injected_default() {
        let spellings = [
            vec!["--model", "custom"],
            vec!["--model=custom"],
            vec!["-m", "custom"],
            vec!["-m=custom"],
        ];
        for spelling in spellings {
            let user_args = args(&spelling);
            for resume in [false, true] {
                let resolved = final_launch_args(&user_args, resume);
                assert!(
                    !resolved.contains(&OsString::from(DEFAULT_MODEL_ID)),
                    "default model injected for {spelling:?}"
                );
                let expected_tail = resolved.len() - user_args.len();
                assert_eq!(
                    &resolved[expected_tail..],
                    user_args.as_slice(),
                    "user args must be forwarded verbatim for {spelling:?}"
                );
                assert!(
                    !has_prompt_or_continue_args(&user_args),
                    "{spelling:?} must not look like a prompt"
                );
            }
        }
    }

    #[test]
    fn the_default_model_is_still_injected_without_a_user_model() {
        assert_eq!(
            final_launch_args(&args(&[]), false),
            args(&["--model", DEFAULT_MODEL_ID])
        );
        assert_eq!(
            final_launch_args(&args(&["--yolo"]), true),
            args(&["--model", DEFAULT_MODEL_ID, "--continue", "--yolo"])
        );
        // `-model` / `-mx` 不是 `-m`, 默认模型仍须注入。
        assert_eq!(
            final_launch_args(&args(&["-model"]), false),
            args(&["--model", DEFAULT_MODEL_ID, "-model"])
        );
        assert_eq!(
            final_launch_args(&args(&["-mx"]), false),
            args(&["--model", DEFAULT_MODEL_ID, "-mx"])
        );
    }

    #[test]
    fn stderr_mode_follows_the_parent_terminal_state() {
        assert_eq!(StderrMode::for_parent(true), StderrMode::Inherit);
        assert_eq!(StderrMode::for_parent(false), StderrMode::ObservePipe);
    }

    #[test]
    fn prompt_and_boundary_arguments_suppress_resume() {
        assert!(has_prompt_or_continue_args(&args(&[
            "--model", "custom", "hello"
        ])));
        assert!(has_prompt_or_continue_args(&args(&["--", "--help"])));
        assert!(has_prompt_or_continue_args(&args(&["--prompt", "hello"])));
    }

    /// 表增长时这条会跟着覆盖新变量, 不需要再改 launcher。
    #[test]
    fn every_google_auth_variable_is_removed_before_the_selected_ones_are_rebuilt() {
        let mut command = Command::new("fake-agy");
        for name in crate::core::credential::GOOGLE_AUTH_ENV_VARS {
            command.env(name, "inherited-from-parent");
        }
        configure_auth_environment(&mut command, &LaunchAuth::OAuth, None, None);
        for name in crate::core::credential::GOOGLE_AUTH_ENV_VARS {
            let entry = command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(name))
                .map(|(_, value)| value);
            assert_eq!(
                entry,
                Some(None),
                "{name} was not removed from the child environment"
            );
        }
    }

    /// AC-R11-4.1: 区域配置不是凭据, 父 shell 里配好的值必须活着到达子进程,
    /// 而同一次调用里凭据类变量仍然一个不剩。
    #[test]
    fn a_region_is_rebuilt_while_every_credential_variable_stays_cleared() {
        for (auth, project) in [
            (LaunchAuth::OAuth, Some("oauth-project")),
            (LaunchAuth::ApiKey("selected-api-key".to_string()), None),
            (
                LaunchAuth::Vertex(PathBuf::from("/state/accounts/vertex/credentials.json")),
                Some("vertex-project"),
            ),
        ] {
            let mut command = Command::new("fake-agy");
            for name in crate::core::credential::GOOGLE_AUTH_ENV_VARS {
                command.env(name, "inherited-from-parent");
            }
            configure_auth_environment(&mut command, &auth, project, Some("europe-west4"));
            assert_eq!(
                env_value(&command, REGION_ENV_VAR).as_deref(),
                Some("europe-west4"),
                "the parent region was dropped instead of being rebuilt"
            );
            for name in crate::core::credential::GOOGLE_AUTH_ENV_VARS {
                if *name == REGION_ENV_VAR {
                    continue;
                }
                let value = env_value(&command, name);
                assert!(
                    value.is_none_or(|value| value != "inherited-from-parent"),
                    "{name} survived from the parent environment"
                );
            }
        }
    }

    /// AC-R11-4.2: 区域是唯一的"非凭据"变量, 其余整张表按名字都属于凭据/账单
    /// 归属/认证链路选择, 必须无条件清除。
    #[test]
    fn the_region_is_the_only_variable_exempt_from_the_deny_list() {
        for name in crate::core::credential::GOOGLE_AUTH_ENV_VARS {
            if *name == REGION_ENV_VAR {
                continue;
            }
            assert!(
                name.contains("API_KEY")
                    || name.contains("ACCESS_TOKEN")
                    || name.contains("CREDENTIALS")
                    || name.contains("PROJECT")
                    || name.contains("USE_"),
                "{name} is neither a credential nor a project/auth-path selector; \
                 its classification must be decided explicitly"
            );
        }
        assert!(!REGION_ENV_VAR.contains("API_KEY"));
        assert!(!REGION_ENV_VAR.contains("ACCESS_TOKEN"));
        assert!(!REGION_ENV_VAR.contains("CREDENTIALS"));
        assert!(!REGION_ENV_VAR.contains("PROJECT"));
        assert!(!REGION_ENV_VAR.contains("USE_"));
    }

    /// 只有长得像 region id 的值才写回; 其余等同于父进程没有配置区域。
    #[test]
    fn only_a_region_shaped_value_can_be_reinjected_by_the_parent() {
        let accepted = [
            "us-central1",
            "europe-west4",
            "northamerica-northeast2",
            "asia-northeast1-a",
            "global",
            "us",
            "  us-east5  ",
        ];
        for value in accepted {
            assert_eq!(
                sanitized_region(value),
                Some(value.trim()),
                "{value} is a valid location id"
            );
        }
        let rejected = [
            "",
            "   ",
            "parent-inherited-value",
            "us central1",
            "us-central1;id",
            "US-CENTRAL1",
            "us-central1\u{7f}",
            "us--central1",
            "-us-central1",
            "us-central1-a-b",
            "\u{4e2d}\u{6587}",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
        ];
        for value in rejected {
            assert_eq!(sanitized_region(value), None, "{value:?} must be refused");
        }

        let mut command = Command::new("fake-agy");
        command.env(REGION_ENV_VAR, "inherited-from-parent");
        configure_auth_environment(
            &mut command,
            &LaunchAuth::OAuth,
            None,
            Some("parent-inherited-value"),
        );
        assert_eq!(env_value(&command, REGION_ENV_VAR), None);
    }

    fn env_value(command: &Command, name: &str) -> Option<String> {
        command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(name))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    #[test]
    fn auth_environment_is_an_exact_four_kind_matrix() {
        let cases = [
            (
                LaunchAuth::OAuth,
                Some("oauth-project"),
                None,
                None,
                Some("oauth-project"),
            ),
            (
                LaunchAuth::ApiKey("selected-api-key".to_string()),
                Some("ignored-parent-project"),
                Some("selected-api-key"),
                None,
                None,
            ),
            (
                LaunchAuth::Vertex(PathBuf::from("/state/accounts/vertex/credentials.json")),
                Some("vertex-project"),
                None,
                Some("/state/accounts/vertex/credentials.json"),
                Some("vertex-project"),
            ),
        ];
        for (auth, project, expected_key, expected_credentials, expected_project) in cases {
            let mut command = Command::new("fake-agy");
            command.env("GEMINI_API_KEY", "parent-key");
            command.env("GOOGLE_APPLICATION_CREDENTIALS", "/parent/stale.json");
            command.env("GOOGLE_CLOUD_PROJECT", "parent-project");
            configure_auth_environment(&mut command, &auth, project, None);
            let value = |name: &str| {
                command
                    .get_envs()
                    .find(|(key, _)| *key == OsStr::new(name))
                    .and_then(|(_, value)| value.map(OsString::from))
            };
            assert_eq!(
                value("GEMINI_API_KEY").as_deref().and_then(OsStr::to_str),
                expected_key
            );
            assert_eq!(
                value("GOOGLE_APPLICATION_CREDENTIALS")
                    .as_deref()
                    .and_then(OsStr::to_str),
                expected_credentials
            );
            assert_eq!(
                value("GOOGLE_CLOUD_PROJECT")
                    .as_deref()
                    .and_then(OsStr::to_str),
                expected_project
            );
        }
    }

    #[test]
    fn launch_credential_debug_redacts_auth_material_and_paths() {
        let temp = tempfile::tempdir().expect("temp dir");
        let account_root = temp.path().join("account");
        let token_root = temp.path().join("token-home");
        let document_root = temp.path().join("document-home");
        fs::create_dir_all(&account_root).expect("account root");
        fs::create_dir_all(&token_root).expect("token root");
        fs::create_dir_all(&document_root).expect("document root");
        let lock = |root: &Path| {
            ExternalDirectoryCapability::claim_or_adopt(
                NormalizedStoreRoot::normalize(root).expect("normalize root"),
                SafeRelativePath::new(Path::new(".test-lock")).expect("lock locator"),
            )
            .expect("claim root")
        };
        let credential = LaunchCredential {
            account_id: "api-account".to_string(),
            account_type: AccountType::ApiKey,
            project_id: None,
            auth: LaunchAuth::ApiKey("super-secret-api-key".to_string()),
            _leases: LaunchLeases {
                _account: lock(&account_root),
                token_home: lock(&token_root),
                document_home: lock(&document_root),
                home_scope_id: "scope".to_string(),
            },
        };
        let debug = format!("{credential:?}");
        assert!(!debug.contains("super-secret-api-key"));
        assert!(!debug.contains(account_root.to_string_lossy().as_ref()));
        assert!(!debug.contains(token_root.to_string_lossy().as_ref()));
        assert!(!debug.contains(document_root.to_string_lossy().as_ref()));
        assert!(debug.contains("api_key"));
    }

    #[cfg(unix)]
    mod observed {
        use super::*;
        use crate::adapters::antigravity::launch_observation::LaunchDiagnostic;
        use std::sync::mpsc::{self, Receiver, Sender};
        use std::sync::{Arc, Mutex};

        const RATE_LIMIT_JSON: &str = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"45s"}]}}"#;

        fn fake_child(script: &str) -> (std::process::Child, std::process::ChildStderr) {
            let mut child = Command::new("sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn fake child");
            let stderr = child.stderr.take().expect("fake stderr pipe");
            (child, stderr)
        }

        struct FakeRun {
            outcome: LaunchOutcome,
            buffered_len: usize,
            rejected: bool,
            writer_error: Option<io::ErrorKind>,
        }

        fn run_fake<W>(script: &str, writer: W) -> FakeRun
        where
            W: Write + Send + 'static,
        {
            let (mut child, stderr) = fake_child(script);
            let drain = std::thread::spawn(move || drain_stderr(stderr, writer));
            let status = child.wait().expect("wait fake child");
            let report = drain
                .join()
                .expect("join fake drain")
                .expect("drain fake stderr");
            let buffered_len = report.parser.buffered_len();
            let rejected = report.parser.is_rejected();
            let writer_error = report.writer_error;
            let outcome = report.parser.finish(process_termination(status));
            FakeRun {
                outcome,
                buffered_len,
                rejected,
                writer_error,
            }
        }

        #[derive(Clone)]
        struct RecordingWriter {
            bytes: Arc<Mutex<Vec<u8>>>,
            first_write: Option<Sender<()>>,
        }

        impl Write for RecordingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes
                    .lock()
                    .expect("recording writer lock")
                    .extend_from_slice(bytes);
                if let Some(sender) = self.first_write.take() {
                    let _ = sender.send(());
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        struct FailingWriter {
            writes: Arc<Mutex<usize>>,
        }

        impl Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                *self.writes.lock().expect("failing writer lock") += 1;
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer marker"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "writer marker"))
            }
        }

        fn recv_before(deadline: std::time::Duration, receiver: Receiver<()>) {
            receiver
                .recv_timeout(deadline)
                .expect("first stderr chunk was not visible in real time");
        }

        #[test]
        fn fragmented_json_from_fake_child_is_classified_after_wait() {
            let (first, second) = RATE_LIMIT_JSON.split_at(RATE_LIMIT_JSON.len() / 2);
            let script = format!(
                "printf '%s' '{}' >&2; sleep 0.05; printf '%s' '{}' >&2; exit 1",
                first.replace("'", "'\\''"),
                second.replace("'", "'\\''")
            );
            let run = run_fake(&script, Vec::<u8>::new());
            assert_eq!(
                run.outcome,
                LaunchOutcome {
                    termination: ProcessTermination::exited(1),
                    diagnostic: LaunchDiagnostic::RateLimited {
                        retry_after_seconds: 45,
                    },
                }
            );
            // 文档在扫描中被完整消费, 不再滞留在缓冲区里。
            assert_eq!(run.buffered_len, 0);
        }

        #[test]
        fn noisy_child_stderr_still_yields_the_rate_limit_diagnostic() {
            let script = format!(
                "printf 'agy: starting up\\n' >&2; printf '%s\\n' '{}' >&2; \
                 printf 'agy: session closed\\n' >&2; exit 1",
                RATE_LIMIT_JSON.replace("'", "'\\''")
            );
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let run = run_fake(
                &script,
                RecordingWriter {
                    bytes: Arc::clone(&bytes),
                    first_write: None,
                },
            );
            assert_eq!(
                run.outcome.diagnostic,
                LaunchDiagnostic::RateLimited {
                    retry_after_seconds: 45,
                }
            );
            // AC-2.4: 转发路径不得改写字节内容与顺序。
            let mirrored = String::from_utf8(bytes.lock().expect("mirror lock").clone())
                .expect("mirrored stderr is UTF-8");
            assert_eq!(
                mirrored,
                format!("agy: starting up\n{RATE_LIMIT_JSON}\nagy: session closed\n")
            );
        }

        #[test]
        fn unwritable_parent_stderr_preserves_the_child_exit_code_and_evidence() {
            let script = format!(
                "printf 'agy: noise\\n' >&2; printf '%s\\n' '{}' >&2; exit 7",
                RATE_LIMIT_JSON.replace("'", "'\\''")
            );
            let mut command = Command::new("sh");
            command.args(["-c", script.as_str()]);
            let writes = Arc::new(Mutex::new(0));
            let outcome = run_observed_command_with_mode(
                command,
                FailingWriter {
                    writes: Arc::clone(&writes),
                },
                StderrMode::ObservePipe,
            )
            .expect("a broken parent mirror must not fail the launch");
            assert_eq!(outcome.termination, ProcessTermination::exited(7));
            assert_eq!(
                outcome.diagnostic,
                LaunchDiagnostic::RateLimited {
                    retry_after_seconds: 45,
                }
            );
            assert!(*writes.lock().expect("failing writer count lock") > 0);
        }

        #[test]
        fn inherited_stderr_mode_never_guesses_a_diagnostic() {
            let mut command = Command::new("sh");
            command.args(["-c", "exit 3"]);
            let outcome =
                run_observed_command_with_mode(command, Vec::<u8>::new(), StderrMode::Inherit)
                    .expect("inherited launch");
            assert_eq!(outcome.termination, ProcessTermination::exited(3));
            assert_eq!(outcome.diagnostic, LaunchDiagnostic::None);
        }

        #[test]
        fn exit_zero_json_and_plaintext_never_become_diagnostics() {
            let success = run_fake(
                "printf '%s' '{\"error\":{\"code\":429,\"status\":\"RESOURCE_EXHAUSTED\"}}' >&2; exit 0",
                Vec::<u8>::new(),
            );
            assert_eq!(success.outcome.diagnostic, LaunchDiagnostic::None);

            let plain = run_fake(
                "printf '%s' '429 RESOURCE_EXHAUSTED' >&2; exit 1",
                Vec::<u8>::new(),
            );
            assert_eq!(plain.outcome.diagnostic, LaunchDiagnostic::None);
        }

        #[test]
        fn signal_termination_is_preserved_without_exit_code_guessing() {
            let run = run_fake("kill -TERM $$", Vec::<u8>::new());
            assert_eq!(run.outcome.termination, ProcessTermination::signaled(15));
            assert_eq!(run.outcome.diagnostic, LaunchDiagnostic::None);
        }

        #[test]
        fn oversized_stderr_is_drained_and_not_retained() {
            let writes = Arc::new(Mutex::new(Vec::new()));
            let run = run_fake(
                "head -c 65537 /dev/zero >&2; exit 1",
                RecordingWriter {
                    bytes: writes.clone(),
                    first_write: None,
                },
            );
            assert_eq!(run.outcome.diagnostic, LaunchDiagnostic::None);
            assert!(run.rejected);
            assert_eq!(run.buffered_len, 0);
            assert_eq!(writes.lock().expect("recording bytes lock").len(), 65537);
        }

        #[test]
        fn parent_mirror_is_realtime_and_each_byte_is_forwarded_once() {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let (sender, receiver) = mpsc::channel();
            let writer = RecordingWriter {
                bytes: bytes.clone(),
                first_write: Some(sender),
            };
            let (mut child, stderr) =
                fake_child("printf '%s' first >&2; sleep 0.2; printf '%s' second >&2; exit 1");
            let drain = std::thread::spawn(move || drain_stderr(stderr, writer));
            recv_before(std::time::Duration::from_secs(1), receiver);
            assert_eq!(
                &*bytes.lock().expect("first recording bytes lock"),
                b"first"
            );
            let status = child.wait().expect("wait realtime fake child");
            let report = drain
                .join()
                .expect("join realtime fake drain")
                .expect("drain realtime fake stderr");
            assert_eq!(
                &*bytes.lock().expect("recording bytes lock"),
                b"firstsecond"
            );
            assert_eq!(process_termination(status), ProcessTermination::exited(1));
            assert!(report.writer_error.is_none());
        }

        #[test]
        fn failed_parent_mirror_does_not_stop_the_drain() {
            let writes = Arc::new(Mutex::new(0));
            let run = run_fake(
                "head -c 131072 /dev/zero >&2; exit 1",
                FailingWriter {
                    writes: writes.clone(),
                },
            );
            assert_eq!(run.outcome.diagnostic, LaunchDiagnostic::None);
            assert!(run.writer_error.is_some());
            assert!(*writes.lock().expect("failing writer count lock") > 1);
        }

        #[test]
        fn launch_error_debug_contains_no_command_or_secret_marker() {
            let marker = "super-secret-command-argument";
            let debug = format!("{:?}", LaunchError::Spawn(io::ErrorKind::PermissionDenied));
            assert!(!debug.contains(marker));
        }
    }
}
