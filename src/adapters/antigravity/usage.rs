//! Account-health probes.
//!
//! Probing is deliberately split into three steps:
//!
//! 1. [`probe_decision`] decides whether an HTTP request is allowed.
//! 2. This module reads one validated credential from the fixed v2 slot and
//!    converts the response into a closed [`ProbeOutcome`].
//! 3. [`reduce_usage`] turns that outcome into the in-memory candidate.
//!
//! No response body, URL, token, or transport error is copied into state.  A
//! clock is passed through the private `*_at` helpers so all production wall
//! clock access stays at the adapter boundary and the state transition is
//! deterministic in tests.

use chrono::Utc;
use reqwest::blocking::{Client, Response};
use serde_json::Value;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use crate::adapters::antigravity::account::credential_store::CredentialStore;
use crate::core::credential::{CredentialKind, PortableCredential};
use crate::core::health::{
    HealthStatus, ProbeDecision, ProbeOutcome, ProbeSubject, UsageSnapshot, probe_decision,
    reduce_usage,
};
use crate::core::state::{
    AccountRecord, AccountType, CredentialRef, CredentialRefKind, STATE_V2_VERSION, State,
};

pub const PROBE_TIMEOUT_SECS: u64 = 3;

const API_PROBE_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models";
const OAUTH_PROBE_URL: &str = "https://www.googleapis.com/oauth2/v3/tokeninfo";
const MAX_PROBE_BODY_BYTES: usize = 1024 * 1024;

/// Runtime-only probe settings.  URLs are constants in production; tests use
/// a local endpoint through the private `*_at` helpers and never modify the
/// process environment (which could otherwise redirect secrets in production).
#[derive(Clone, Debug)]
struct ProbeConfig {
    api_url: String,
    oauth_url: String,
    timeout: Duration,
}

impl ProbeConfig {
    fn production() -> Self {
        Self {
            api_url: API_PROBE_URL.to_string(),
            oauth_url: OAUTH_PROBE_URL.to_string(),
            timeout: Duration::from_secs(PROBE_TIMEOUT_SECS),
        }
    }

    #[cfg(test)]
    fn test_endpoint(endpoint: &str, timeout: Duration) -> Self {
        Self {
            api_url: endpoint.to_string(),
            oauth_url: endpoint.to_string(),
            timeout,
        }
    }
}

#[derive(Clone)]
struct ProbeContext {
    state_dir: std::path::PathBuf,
    state_version: u32,
    credential_refs: std::collections::BTreeMap<String, CredentialRef>,
}

impl ProbeContext {
    fn from_state(state_dir: &Path, state: &State) -> Self {
        Self {
            state_dir: state_dir.to_path_buf(),
            state_version: state.version,
            credential_refs: state.credential_refs.clone(),
        }
    }
}

/// Result of one network observation. `quota_percent` is kept outside the
/// closed core outcome until reduction has succeeded, so an untrusted body
/// can never turn an authentication error into a quota claim.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeResult {
    outcome: ProbeOutcome,
    quota_percent: Option<u8>,
}

impl ProbeResult {
    const fn outcome(outcome: ProbeOutcome) -> Self {
        Self {
            outcome,
            quota_percent: None,
        }
    }

    const fn ready(outcome: ProbeOutcome, quota_percent: Option<u8>) -> Self {
        Self {
            outcome,
            quota_percent,
        }
    }
}

#[derive(Debug, Clone)]
enum LoadedCredential {
    OAuth {
        credential: PortableCredential,
        subject: ProbeSubject,
    },
    ApiKey(PortableCredential),
    Vertex(PortableCredential),
}

impl super::AntigravityAdapter {
    pub fn refresh_account_usage(
        &self,
        state_dir: &Path,
        state: &mut State,
        account: &AccountRecord,
        force: bool,
    ) -> UsageSnapshot {
        self.refresh_account_usage_at(
            state_dir,
            state,
            account,
            force,
            current_unix_seconds(),
            &ProbeConfig::production(),
        )
    }

    pub fn refresh_all_accounts(&self, state_dir: &Path, state: &mut State, force: bool) {
        self.refresh_all_accounts_at(
            state_dir,
            state,
            force,
            current_unix_seconds(),
            &ProbeConfig::production(),
        );
    }

    fn refresh_account_usage_at(
        &self,
        state_dir: &Path,
        state: &mut State,
        account: &AccountRecord,
        force: bool,
        now: i64,
        config: &ProbeConfig,
    ) -> UsageSnapshot {
        let mut usage = state
            .usage_cache
            .get(&account.id)
            .cloned()
            .unwrap_or_else(|| UsageSnapshot {
                plan: account.plan.clone(),
                ..Default::default()
            });
        if usage.plan.is_none() {
            usage.plan.clone_from(&account.plan);
        }
        // 先归一化再决策：时钟前跳留下的无效 cooldown 必须在这里被清除并写回，
        // 否则它会留在 state 里，每次读取都重建一个新窗口（永久 cooldown）。
        let usage = usage.normalized(now);

        // An active cooldown is authoritative. `force` only bypasses the
        // normal cache TTL and can never make an HTTP request during a
        // rate-limit window.
        if !matches!(probe_decision(&usage, now, force), ProbeDecision::Probe) {
            state.usage_cache.insert(account.id.clone(), usage.clone());
            return usage;
        }

        let context = ProbeContext::from_state(state_dir, state);
        let next = observe_and_reduce(&context, account, &usage, now, config);
        state.usage_cache.insert(account.id.clone(), next.clone());
        next
    }

    fn refresh_all_accounts_at(
        &self,
        state_dir: &Path,
        state: &mut State,
        force: bool,
        now: i64,
        config: &ProbeConfig,
    ) {
        let context = ProbeContext::from_state(state_dir, state);
        let accounts = state.accounts.clone();
        let existing_usage = state.usage_cache.clone();
        let config = config.clone();

        let results: Vec<(String, UsageSnapshot)> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(accounts.len());
            for account in &accounts {
                let current = existing_usage.get(&account.id).cloned();
                let context = context.clone();
                let config = config.clone();
                handles.push(scope.spawn(move || {
                    let mut usage = current.unwrap_or_else(|| UsageSnapshot {
                        plan: account.plan.clone(),
                        ..Default::default()
                    });
                    if usage.plan.is_none() {
                        usage.plan.clone_from(&account.plan);
                    }
                    let mut usage = usage.normalized(now);
                    if matches!(probe_decision(&usage, now, force), ProbeDecision::Probe) {
                        usage = observe_and_reduce(&context, account, &usage, now, &config);
                    }
                    (account.id.clone(), usage)
                }));
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().unwrap_or_else(|_| {
                        // A probe thread must never take down a refresh-all run.
                        (String::new(), UsageSnapshot::default())
                    })
                })
                .collect()
        });

        for (id, usage) in results {
            if !id.is_empty() {
                state.usage_cache.insert(id, usage);
            }
        }
    }
}

fn current_unix_seconds() -> i64 {
    Utc::now().timestamp()
}

fn observe_and_reduce(
    context: &ProbeContext,
    account: &AccountRecord,
    previous: &UsageSnapshot,
    now: i64,
    config: &ProbeConfig,
) -> UsageSnapshot {
    let observation = match load_credential(context, account) {
        Some(LoadedCredential::Vertex(credential)) => {
            // A service-account document is fully validated by
            // PortableCredential before it reaches this branch. Without a
            // token exchange there is no remote evidence of readiness, so the
            // durable result remains explicitly Unverified.
            if credential.kind() == CredentialKind::VertexServiceAccount {
                return local_vertex_snapshot(previous, now);
            }
            ProbeResult::outcome(ProbeOutcome::InvalidCredential)
        }
        Some(LoadedCredential::OAuth {
            credential,
            subject,
        }) => probe_oauth(&credential, subject, now, config),
        Some(LoadedCredential::ApiKey(credential)) => probe_api_key(&credential, config),
        None => ProbeResult::outcome(ProbeOutcome::InvalidCredential),
    };

    let mut next = reduce_usage(previous, observation.outcome, now);
    if matches!(next.health, HealthStatus::Ready) {
        // `None` is intentional when the endpoint did not expose one of the
        // explicitly trusted percentage fields.
        next.remaining_quota_percent = observation.quota_percent;
    }
    next
}

fn local_vertex_snapshot(previous: &UsageSnapshot, now: i64) -> UsageSnapshot {
    let mut next = previous.clone();
    next.health = HealthStatus::Unverified;
    next.cooldown = None;
    next.remaining_quota_percent = None;
    next.last_probe_at = Some(now);
    next.last_success_at = None;
    next.last_rate_limit_at = None;
    next.last_error = None;
    next
}

fn load_credential(context: &ProbeContext, account: &AccountRecord) -> Option<LoadedCredential> {
    let reference = if context.state_version >= STATE_V2_VERSION {
        // v2 is fail-closed: no embedded AccountRecord secret and no
        // auth_path fallback can be used when the exact ref is absent.
        context.credential_refs.get(&account.id)?.clone()
    } else {
        return load_legacy_credential(account);
    };

    let store = CredentialStore::new(&context.state_dir, &account.id).ok()?;
    let stored = store.read(&reference).ok()?;
    if stored.kind != reference.kind
        || stored.credential.fingerprint() != reference.fingerprint
        || !credential_kind_matches(account.account_type, reference.kind)
    {
        return None;
    }

    match reference.kind {
        CredentialRefKind::OauthAccessToken => Some(LoadedCredential::OAuth {
            credential: stored.credential,
            subject: ProbeSubject::RawToken,
        }),
        CredentialRefKind::OauthAuthorizedUser => Some(LoadedCredential::OAuth {
            credential: stored.credential,
            subject: ProbeSubject::AuthorizedUser,
        }),
        CredentialRefKind::ApiKey => Some(LoadedCredential::ApiKey(stored.credential)),
        CredentialRefKind::VertexServiceAccount => {
            Some(LoadedCredential::Vertex(stored.credential))
        }
    }
}

fn load_legacy_credential(account: &AccountRecord) -> Option<LoadedCredential> {
    // This is an explicit v1 compatibility path. It only consumes bounded
    // embedded values and never follows the legacy auth_path.
    match account.account_type {
        AccountType::OAuth => {
            let token = account.oauth_token.as_deref()?.trim();
            (!token.is_empty())
                .then(|| PortableCredential::oauth_access_token(token).ok())
                .flatten()
                .map(|credential| LoadedCredential::OAuth {
                    credential,
                    subject: ProbeSubject::RawToken,
                })
        }
        AccountType::ApiKey => {
            let key = account.api_key.as_deref()?.trim();
            (!key.is_empty())
                .then(|| PortableCredential::api_key(key).ok())
                .flatten()
                .map(LoadedCredential::ApiKey)
        }
        // A v1 Vertex record does not have a safe, path-free source to read;
        // refusing it is preferable to guessing a service-account path.
        AccountType::Vertex => None,
    }
}

fn credential_kind_matches(account_type: AccountType, kind: CredentialRefKind) -> bool {
    match account_type {
        AccountType::OAuth => matches!(
            kind,
            CredentialRefKind::OauthAccessToken | CredentialRefKind::OauthAuthorizedUser
        ),
        AccountType::ApiKey => matches!(kind, CredentialRefKind::ApiKey),
        AccountType::Vertex => matches!(kind, CredentialRefKind::VertexServiceAccount),
    }
}

fn build_client(config: &ProbeConfig) -> Result<Client, ProbeResult> {
    Client::builder()
        .timeout(config.timeout)
        // Redirects can otherwise turn a fixed provider request into a
        // request to an untrusted host. A redirect is a protocol failure.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| ProbeResult::outcome(ProbeOutcome::OtherTransient))
}

fn probe_api_key(credential: &PortableCredential, config: &ProbeConfig) -> ProbeResult {
    let Some(key) = credential
        .api_key_value()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return ProbeResult::outcome(ProbeOutcome::InvalidCredential);
    };
    let Ok(client) = build_client(config) else {
        return ProbeResult::outcome(ProbeOutcome::Network {
            subject: ProbeSubject::ApiKey,
        });
    };
    send_http_probe(
        &client,
        &config.api_url,
        ProbeSubject::ApiKey,
        Some(("x-goog-api-key", key)),
    )
}

fn probe_oauth(
    credential: &PortableCredential,
    subject: ProbeSubject,
    now: i64,
    config: &ProbeConfig,
) -> ProbeResult {
    let Some(token) = credential
        .access_token()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        // An authorized-user document is required to carry a refresh token;
        // without an access token it needs refresh and must not cause a
        // request with an empty bearer value.
        return ProbeResult::outcome(match subject {
            ProbeSubject::AuthorizedUser => ProbeOutcome::Http401Authorized,
            _ => ProbeOutcome::InvalidCredential,
        });
    };

    match local_token_status(token, now) {
        LocalTokenStatus::MalformedJwt => return ProbeResult::outcome(ProbeOutcome::InvalidJwt),
        LocalTokenStatus::ExpiredJwt => {
            return ProbeResult::outcome(match subject {
                ProbeSubject::AuthorizedUser => ProbeOutcome::Http401Authorized,
                _ => ProbeOutcome::Http401Raw,
            });
        }
        LocalTokenStatus::Opaque | LocalTokenStatus::ValidJwt => {}
    }

    let Ok(client) = build_client(config) else {
        return ProbeResult::outcome(ProbeOutcome::Network { subject });
    };
    let bearer = format!("Bearer {token}");
    send_http_probe(
        &client,
        &config.oauth_url,
        subject,
        Some(("authorization", bearer.as_str())),
    )
}

fn send_http_probe(
    client: &Client,
    url: &str,
    subject: ProbeSubject,
    header: Option<(&str, &str)>,
) -> ProbeResult {
    let mut request = client.get(url);
    if let Some((name, value)) = header {
        request = request.header(name, value);
    }

    let response = match request.send() {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return ProbeResult::outcome(ProbeOutcome::Timeout { subject });
        }
        Err(_) => return ProbeResult::outcome(ProbeOutcome::Network { subject }),
    };
    classify_response(response, subject)
}

fn classify_response(mut response: Response, subject: ProbeSubject) -> ProbeResult {
    let status = response.status();
    let status_code = status.as_u16();
    if status_code == 401 {
        return ProbeResult::outcome(match subject {
            ProbeSubject::AuthorizedUser => ProbeOutcome::Http401Authorized,
            ProbeSubject::RawToken => ProbeOutcome::Http401Raw,
            ProbeSubject::ApiKey => ProbeOutcome::Http401ApiKey,
            ProbeSubject::Vertex => ProbeOutcome::Http401Vertex,
        });
    }
    if status_code == 400 {
        // Google 对失效的 API key 的既定响应就是 400。落进 OtherTransient 会被
        // 当成暂时性故障，用户永远看不到"需要重新登录"。
        return ProbeResult::outcome(ProbeOutcome::Http400 { subject });
    }
    if status_code == 403 {
        return ProbeResult::outcome(ProbeOutcome::Http403 { subject });
    }
    if status_code == 429 {
        let retry_after_secs = parse_retry_after(response.headers());
        return ProbeResult::outcome(ProbeOutcome::Http429 {
            subject,
            retry_after_secs,
        });
    }
    if status.is_server_error() {
        return ProbeResult::outcome(ProbeOutcome::Http5xx {
            subject,
            status: status_code,
        });
    }
    if !status.is_success() {
        // 3xx/404/407 等既不是关于凭据的结论，也不是源站 5xx：公司代理、强制
        // 门户和错误路由就长这样。归到 OtherTransient 会被当成服务端故障，
        // 本地凭据完全有效的账号在代理故障下仍然启动不了 (AVAIL-001)。
        return ProbeResult::outcome(ProbeOutcome::HttpUnexpected {
            subject,
            status: status_code,
        });
    }

    let body = match read_bounded_body(&mut response) {
        Ok(body) => body,
        Err(_) => return ProbeResult::outcome(ProbeOutcome::OtherTransient),
    };
    let quota_percent = match parse_probe_json(&body) {
        Ok(value) => value,
        Err(_) => return ProbeResult::outcome(ProbeOutcome::OtherTransient),
    };
    ProbeResult::ready(success_outcome(subject), quota_percent)
}

fn success_outcome(subject: ProbeSubject) -> ProbeOutcome {
    match subject {
        ProbeSubject::RawToken => ProbeOutcome::Http200Raw,
        ProbeSubject::AuthorizedUser => ProbeOutcome::Http200Authorized,
        ProbeSubject::ApiKey => ProbeOutcome::Http200ApiKey,
        ProbeSubject::Vertex => ProbeOutcome::Http200Vertex,
    }
}

fn read_bounded_body(response: &mut Response) -> io::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROBE_BODY_BYTES as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe response exceeds bound",
        ));
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take((MAX_PROBE_BODY_BYTES + 1) as u64)
        .read_to_end(&mut body)?;
    if body.len() > MAX_PROBE_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "probe response exceeds bound",
        ));
    }
    Ok(body)
}

fn parse_probe_json(body: &[u8]) -> Result<Option<u8>, ()> {
    if body.iter().all(u8::is_ascii_whitespace) {
        // Empty success responses are valid authentication observations, but
        // cannot make a quota claim.
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
    if !value.is_object() {
        return Err(());
    }
    Ok(parse_trusted_quota(&value))
}

fn parse_trusted_quota(value: &Value) -> Option<u8> {
    let object = value.as_object()?;
    // Keep this allow-list deliberately narrow. Arbitrary response fields
    // must never become a durable quota assertion.
    [
        "remaining_quota_percent",
        "remainingQuotaPercent",
        "quota_percent",
        "quotaPercent",
    ]
    .into_iter()
    .find_map(|key| {
        object
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .filter(|value| *value <= 100)
    })
}

fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<i64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalTokenStatus {
    Opaque,
    ValidJwt,
    ExpiredJwt,
    MalformedJwt,
}

fn local_token_status(token: &str, now: i64) -> LocalTokenStatus {
    // Google OAuth access tokens commonly begin with `ya29.` and are opaque,
    // despite containing a dot. Other dotted values are treated as JWTs and
    // must pass structural validation before they reach the network.
    if token.starts_with("ya29.") || !token.contains('.') {
        return LocalTokenStatus::Opaque;
    }
    match extract_jwt_exp(token) {
        Some(exp) if now >= exp => LocalTokenStatus::ExpiredJwt,
        Some(_) => LocalTokenStatus::ValidJwt,
        None => LocalTokenStatus::MalformedJwt,
    }
}

fn extract_jwt_exp(jwt: &str) -> Option<i64> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part.as_bytes())
            .or_else(|_| URL_SAFE.decode(part.as_bytes()))
            .or_else(|_| STANDARD.decode(part.as_bytes()))
            .ok()
    };
    let header: Value = serde_json::from_slice(&decode(parts[0])?).ok()?;
    let payload: Value = serde_json::from_slice(&decode(parts[1])?).ok()?;
    if !header.is_object() || !payload.is_object() || decode(parts[2])?.is_empty() {
        return None;
    }
    payload.get("exp").and_then(Value::as_i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::health::{Cooldown, HealthErrorKind, HealthStatus};
    use crate::core::policy;
    use crate::core::state::{CredentialRef, STATE_V2_VERSION};
    use serde_json::json;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn account(id: &str, account_type: AccountType) -> AccountRecord {
        AccountRecord {
            id: id.to_string(),
            account_type,
            ..Default::default()
        }
    }

    fn v2_state(
        temp: &TempDir,
        account: &AccountRecord,
        credential: &PortableCredential,
        bytes: &[u8],
    ) -> State {
        let account_dir = temp.path().join("accounts").join(&account.id);
        fs::create_dir_all(&account_dir).unwrap();
        let filename = match credential.kind() {
            CredentialKind::OAuthAccessToken => "antigravity-oauth-token",
            _ => "credentials.json",
        };
        fs::write(account_dir.join(filename), bytes).unwrap();
        let mut state = State {
            version: STATE_V2_VERSION,
            accounts: vec![account.clone()],
            ..Default::default()
        };
        state.credential_refs.insert(
            account.id.clone(),
            CredentialRef {
                kind: match credential.kind() {
                    CredentialKind::OAuthAccessToken => CredentialRefKind::OauthAccessToken,
                    CredentialKind::OAuthAuthorizedUser => CredentialRefKind::OauthAuthorizedUser,
                    CredentialKind::ApiKey => CredentialRefKind::ApiKey,
                    CredentialKind::VertexServiceAccount => CredentialRefKind::VertexServiceAccount,
                },
                fingerprint: credential.fingerprint(),
            },
        );
        state
    }

    fn mock_server(
        status: u16,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let body = body.to_string();
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect::<Vec<_>>();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            // 30s 上限只为兜底回收线程；短上限在并行测试负载下会让服务器
            // 提前退出，把 200 用例变成随机的连接被拒。
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        request_count.fetch_add(1, Ordering::SeqCst);
                        // macOS 上 accept 出来的 socket 会继承 listener 的
                        // O_NONBLOCK：不切回阻塞模式，read_request 会在请求字节
                        // 到达前就返回 WouldBlock，服务器随即带着未读数据关闭连接
                        // 并发出 RST，客户端看到的是随机的 "connection reset"。
                        let _ = stream.set_nonblocking(false);
                        let _ = read_request(&mut stream);
                        let mut response = format!(
                            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                            body.len()
                        );
                        for (name, value) in headers {
                            response.push_str(&format!("{name}: {value}\r\n"));
                        }
                        response.push_str("\r\n");
                        response.push_str(&body);
                        let _ = stream.write_all(response.as_bytes());
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        (address, requests)
    }

    /// One row of the probe status matrix.  Transport failures are produced
    /// locally (a closed port, a server that never answers) so the matrix is
    /// decidable without any real network.
    enum MatrixEndpoint {
        Status(u16, Option<&'static str>),
        Timeout,
        Unreachable,
    }

    impl MatrixEndpoint {
        fn label(&self) -> String {
            match self {
                Self::Status(status, _) => status.to_string(),
                Self::Timeout => "timeout".to_string(),
                Self::Unreachable => "network".to_string(),
            }
        }

        fn build(&self) -> ProbeConfig {
            match self {
                Self::Status(status, retry_after) => {
                    let headers: Vec<(&str, &str)> = retry_after
                        .map(|value| vec![("Retry-After", value)])
                        .unwrap_or_default();
                    let body = if *status == 200 { "{}" } else { "" };
                    let (endpoint, _) = mock_server(*status, &headers, body);
                    config(&endpoint)
                }
                Self::Timeout => {
                    // 接受连接但从不响应：客户端只能超时。
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    let endpoint = format!("http://{}", listener.local_addr().unwrap());
                    std::thread::spawn(move || {
                        if let Ok((_stream, _)) = listener.accept() {
                            std::thread::sleep(Duration::from_millis(300));
                        }
                    });
                    ProbeConfig::test_endpoint(&endpoint, Duration::from_millis(20))
                }
                Self::Unreachable => {
                    // 固定的 discard 端口：本机上不会有人监听，连接必定被拒绝。
                    // 不能用"先绑再释放"的临时端口——它可能被并行用例的 mock
                    // server 抢去，导致请求被投递到别的用例。
                    config("http://127.0.0.1:9")
                }
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        while reader.read_line(&mut line)? > 0 {
            if line == "\r\n" {
                break;
            }
            line.clear();
        }
        Ok(())
    }

    fn config(address: &str) -> ProbeConfig {
        // 期待收到响应的用例必须给足超时：100ms 在并行测试负载下会随机变成
        // Timeout，把 401/403 等断言变成随机的 TransientFailure。
        ProbeConfig::test_endpoint(address, Duration::from_secs(10))
    }

    #[test]
    fn malformed_jwt_is_invalid_and_clears_old_ready_quota() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("oauth-jwt", AccountType::OAuth);
        let credential = PortableCredential::oauth_access_token("header.payload").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, b"header.payload");
        state.usage_cache.insert(
            acc.id.clone(),
            UsageSnapshot {
                health: HealthStatus::Ready,
                remaining_quota_percent: Some(100),
                last_probe_at: Some(1),
                ..Default::default()
            },
        );
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &config("http://127.0.0.1:9"),
        );
        assert_eq!(usage.health, HealthStatus::InvalidCredential);
        assert_eq!(usage.last_error, Some(HealthErrorKind::InvalidJwt));
        assert_eq!(usage.remaining_quota_percent, None);
    }

    #[test]
    fn vertex_is_locally_validated_but_not_marked_ready() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("vertex-local", AccountType::Vertex);
        let value = json!({
            "type": "service_account",
            "project_id": "project",
            "private_key": "private-key",
            "client_email": "vertex@example.com",
            "token_uri": "https://oauth2.example/token"
        });
        let credential = PortableCredential::vertex_service_account(value.clone()).unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut state = v2_state(&temp, &acc, &credential, &bytes);
        state.usage_cache.insert(
            acc.id.clone(),
            UsageSnapshot {
                health: HealthStatus::Ready,
                remaining_quota_percent: Some(100),
                ..Default::default()
            },
        );
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &config("http://127.0.0.1:9"),
        );
        assert_eq!(usage.health, HealthStatus::Unverified);
        assert_eq!(usage.remaining_quota_percent, None);
    }

    #[test]
    fn force_never_bypasses_active_cooldown() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("cooldown", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        state.usage_cache.insert(
            acc.id.clone(),
            reduce_usage(
                &UsageSnapshot::default(),
                ProbeOutcome::Http429 {
                    subject: ProbeSubject::ApiKey,
                    retry_after_secs: Some(300),
                },
                100,
            ),
        );
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            101,
            &config("http://127.0.0.1:9"),
        );
        assert_eq!(usage.health, HealthStatus::RateLimited);
        assert_eq!(usage.last_probe_at, Some(100));
    }

    #[test]
    fn fresh_cache_skips_request_and_200_does_not_claim_quota() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("fresh", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        state.usage_cache.insert(
            acc.id.clone(),
            UsageSnapshot {
                health: HealthStatus::Ready,
                remaining_quota_percent: Some(22),
                last_probe_at: Some(99),
                ..Default::default()
            },
        );
        let (endpoint, requests) = mock_server(200, &[], "{}");
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            false,
            100,
            &config(&endpoint),
        );
        assert_eq!(usage.remaining_quota_percent, Some(22));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    /// AC-2.3: the durable status matrix must cover every HTTP and transport
    /// branch a probe can observe, including the 400 Google returns for an
    /// invalidated API key.
    #[test]
    fn response_matrix_covers_200_400_401_403_429_500_timeout_and_network() {
        let cases: [(MatrixEndpoint, HealthStatus, Option<HealthErrorKind>); 8] = [
            (MatrixEndpoint::Status(200, None), HealthStatus::Ready, None),
            (
                MatrixEndpoint::Status(400, None),
                HealthStatus::InvalidCredential,
                Some(HealthErrorKind::InvalidCredential),
            ),
            (
                MatrixEndpoint::Status(401, None),
                HealthStatus::AuthInvalid,
                Some(HealthErrorKind::Unauthorized),
            ),
            (
                MatrixEndpoint::Status(403, None),
                HealthStatus::PermissionDenied,
                Some(HealthErrorKind::PermissionDenied),
            ),
            (
                MatrixEndpoint::Status(429, Some("60")),
                HealthStatus::RateLimited,
                Some(HealthErrorKind::RateLimited),
            ),
            (
                MatrixEndpoint::Status(500, None),
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::ServerFailure),
            ),
            (
                MatrixEndpoint::Timeout,
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Timeout),
            ),
            (
                MatrixEndpoint::Unreachable,
                HealthStatus::TransientFailure,
                Some(HealthErrorKind::Network),
            ),
        ];

        for (endpoint, expected, expected_error) in cases {
            let label = endpoint.label();
            let temp = tempfile::tempdir().unwrap();
            let acc = account("matrix", AccountType::ApiKey);
            let credential = PortableCredential::api_key("secret").unwrap();
            let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
            let probe_config = endpoint.build();
            let adapter = super::super::AntigravityAdapter;
            let usage = adapter.refresh_account_usage_at(
                temp.path(),
                &mut state,
                &acc,
                true,
                100,
                &probe_config,
            );
            assert_eq!(usage.health, expected, "case {label}");
            assert_eq!(usage.last_error, expected_error, "case {label}");
            assert_eq!(usage.remaining_quota_percent, None, "case {label}");
            if label == "429" {
                assert_eq!(usage.cooldown.unwrap().until, 160);
            } else {
                assert_eq!(usage.cooldown, None, "case {label}");
            }
        }
    }

    /// AC-3.1 / AC-3.2: a cooldown recorded with a future `started_at` is clock
    /// skew, not evidence.  It must be dropped from durable state and must not
    /// suppress the next probe, with or without `--force` (`sagy refresh`).
    #[test]
    fn future_cooldown_is_purged_and_the_account_is_reprobed() {
        for force in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let acc = account("skewed", AccountType::ApiKey);
            let credential = PortableCredential::api_key("secret").unwrap();
            let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
            state.usage_cache.insert(
                acc.id.clone(),
                UsageSnapshot {
                    health: HealthStatus::RateLimited,
                    cooldown: Some(Cooldown {
                        started_at: 10_000,
                        until: 11_000,
                        last_evidence_at: 10_000,
                    }),
                    last_probe_at: Some(100),
                    last_rate_limit_at: Some(100),
                    last_error: Some(HealthErrorKind::RateLimited),
                    ..Default::default()
                },
            );
            let (endpoint, requests) = mock_server(200, &[], "{}");
            let adapter = super::super::AntigravityAdapter;
            let usage = adapter.refresh_account_usage_at(
                temp.path(),
                &mut state,
                &acc,
                force,
                100,
                &config(&endpoint),
            );
            assert_eq!(usage.health, HealthStatus::Ready, "force={force}");
            assert_eq!(usage.cooldown, None, "force={force}");
            assert_eq!(requests.load(Ordering::SeqCst), 1, "force={force}");
            assert_eq!(
                state.usage_cache.get(&acc.id).unwrap().cooldown,
                None,
                "the invalid cooldown must be purged from durable state"
            );
        }
    }

    /// AC-3.3: an ordinary, unexpired cooldown must survive untouched.
    #[test]
    fn valid_cooldown_is_never_cleared_by_the_skew_guard() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("cooling", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        let cooldown = Cooldown {
            started_at: 90,
            until: 400,
            last_evidence_at: 90,
        };
        state.usage_cache.insert(
            acc.id.clone(),
            UsageSnapshot {
                health: HealthStatus::RateLimited,
                cooldown: Some(cooldown),
                last_probe_at: Some(90),
                last_rate_limit_at: Some(90),
                last_error: Some(HealthErrorKind::RateLimited),
                ..Default::default()
            },
        );
        let (endpoint, requests) = mock_server(200, &[], "{}");
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &config(&endpoint),
        );
        assert_eq!(usage.health, HealthStatus::RateLimited);
        assert_eq!(usage.cooldown, Some(cooldown));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn only_allowlisted_integer_quota_is_persisted() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("quota", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        let endpoint = mock_server(
            200,
            &[],
            r#"{"remaining_quota_percent":42,"quota":"secret"}"#,
        )
        .0;
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &config(&endpoint),
        );
        assert_eq!(usage.health, HealthStatus::Ready);
        assert_eq!(usage.remaining_quota_percent, Some(42));
    }

    #[test]
    fn timeout_becomes_typed_transient_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((_stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let temp = tempfile::tempdir().unwrap();
        let acc = account("timeout", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &ProbeConfig::test_endpoint(&endpoint, Duration::from_millis(20)),
        );
        assert_eq!(usage.health, HealthStatus::TransientFailure);
        assert_eq!(usage.last_error, Some(HealthErrorKind::Timeout));
    }

    #[test]
    fn authorized_and_raw_401_have_distinct_health() {
        let temp = tempfile::tempdir().unwrap();
        let authorized = json!({
            "type": "authorized_user",
            "client_id": "client",
            "client_secret": "secret",
            "refresh_token": "refresh",
            "token_uri": "https://oauth2.googleapis.com/token",
            "access_token": "ya29.access"
        });
        for (id, credential, expected) in [
            (
                "authorized",
                PortableCredential::oauth_authorized_user(authorized.clone()).unwrap(),
                HealthStatus::RefreshRequired,
            ),
            (
                "raw",
                PortableCredential::oauth_access_token("ya29.access").unwrap(),
                HealthStatus::AuthInvalid,
            ),
        ] {
            let acc = account(id, AccountType::OAuth);
            let bytes = if credential.kind() == CredentialKind::OAuthAccessToken {
                b"ya29.access".to_vec()
            } else {
                serde_json::to_vec(&authorized).unwrap()
            };
            let mut state = v2_state(&temp, &acc, &credential, &bytes);
            let endpoint = mock_server(401, &[], "").0;
            let adapter = super::super::AntigravityAdapter;
            let usage = adapter.refresh_account_usage_at(
                temp.path(),
                &mut state,
                &acc,
                true,
                100,
                &config(&endpoint),
            );
            assert_eq!(usage.health, expected, "credential {id}");
        }
    }

    #[test]
    fn retry_after_must_be_an_integer_and_reducer_applies_default() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("retry-default", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        let endpoint = mock_server(429, &[("Retry-After", "garbage")], "").0;
        let adapter = super::super::AntigravityAdapter;
        let usage = adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &config(&endpoint),
        );
        assert_eq!(usage.cooldown.unwrap().until, 400);
    }

    /// AC-R6-1.1 / AC-R6-1.2 / AC-R6-1.3：从注入的 HTTP 状态码一路走到可选性
    /// 结论。代理 / 网关故障最常见的 302、404、407、502、503 必须让本地校验
    /// 通过的账号仍然可被选中启动；400 / 401 / 403 是服务端对凭据的明确拒绝，
    /// 不得被这条兜底放宽。
    #[test]
    fn gateway_statuses_stay_selectable_while_credential_rejections_do_not() {
        // 期望的 last_error 一并钉住：3xx/404/407 来自中间层，5xx 来自网关或
        // 源站，两者都不是凭据结论，但用户看到的诊断必须区分得开。
        let cases: [(u16, bool, HealthStatus, HealthErrorKind); 8] = [
            (
                302,
                true,
                HealthStatus::TransientFailure,
                HealthErrorKind::Gateway,
            ),
            (
                404,
                true,
                HealthStatus::TransientFailure,
                HealthErrorKind::Gateway,
            ),
            (
                407,
                true,
                HealthStatus::TransientFailure,
                HealthErrorKind::Gateway,
            ),
            (
                502,
                true,
                HealthStatus::TransientFailure,
                HealthErrorKind::ServerFailure,
            ),
            (
                503,
                true,
                HealthStatus::TransientFailure,
                HealthErrorKind::ServerFailure,
            ),
            (
                400,
                false,
                HealthStatus::InvalidCredential,
                HealthErrorKind::InvalidCredential,
            ),
            (
                401,
                false,
                HealthStatus::AuthInvalid,
                HealthErrorKind::Unauthorized,
            ),
            (
                403,
                false,
                HealthStatus::PermissionDenied,
                HealthErrorKind::PermissionDenied,
            ),
        ];
        for (status, selectable, expected_health, expected_error) in cases {
            let temp = tempfile::tempdir().unwrap();
            let acc = account("gateway", AccountType::ApiKey);
            let credential = PortableCredential::api_key("secret").unwrap();
            let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
            let endpoint = mock_server(status, &[], "").0;
            let adapter = super::super::AntigravityAdapter;
            let usage = adapter.refresh_account_usage_at(
                temp.path(),
                &mut state,
                &acc,
                true,
                100,
                &config(&endpoint),
            );
            assert_eq!(usage.health, expected_health, "status {status}");
            assert_eq!(usage.last_error, Some(expected_error), "status {status}");
            let reference = state.credential_refs.get(&acc.id).cloned().unwrap();
            let tier = policy::eligibility(&acc, Some(&reference), Some(&usage), true, 100);
            assert_eq!(
                tier != policy::Eligibility::Ineligible,
                selectable,
                "status {status} produced {tier:?} from health {:?}/{:?}",
                usage.health,
                usage.last_error
            );

            // 端到端的"可被选中启动"：选择器本身也必须给出同样的结论。
            let validated = std::collections::BTreeSet::from([acc.id.clone()]);
            let selected = policy::select_best_account_with_validation(
                &state,
                &state.accounts,
                &validated,
                100,
            );
            assert_eq!(
                selected.is_some(),
                selectable,
                "status {status} selection disagreed with eligibility"
            );
        }
    }

    /// AC-R6-3.1：从"探测返回 400"出发，一路到 `sagy list` 打印的状态列。
    /// `sagy list` 的状态列就是 `render_account_table` 的输出（cli/mod.rs 里
    /// `print_account_table` 只是把它 println 出去），所以这里覆盖的是同一条链路。
    #[test]
    fn a_probe_400_is_rendered_as_relogin_required_in_the_account_table() {
        let temp = tempfile::tempdir().unwrap();
        let acc = account("rejected", AccountType::ApiKey);
        let credential = PortableCredential::api_key("secret").unwrap();
        let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
        let endpoint = mock_server(400, &[], "").0;
        let adapter = super::super::AntigravityAdapter;
        adapter.refresh_account_usage_at(
            temp.path(),
            &mut state,
            &acc,
            true,
            100,
            &config(&endpoint),
        );

        let rendered = adapter.render_account_table(&state, None);
        assert!(
            rendered.contains("Relogin Required"),
            "a 400 must reach the user as a relogin prompt: {rendered}"
        );
        assert!(
            !rendered.contains("probe unreachable"),
            "a 400 is a server verdict, not an unreachable probe channel: {rendered}"
        );
        assert!(rendered.is_ascii(), "{rendered}");
    }

    #[test]
    fn extract_jwt_exp_rejects_malformed_shape() {
        let fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODcxOTk5OTksImVtYWlsIjoidGVzdEBnb29nbGUuY29tIn0.fake_signature";
        assert_eq!(extract_jwt_exp(fake_jwt), None);
        assert_eq!(extract_jwt_exp("invalid_jwt_format"), None);
    }
}
