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

pub const PROBE_TTL_SECS: i64 = 300;
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

impl LoadedCredential {
    #[allow(dead_code)]
    fn subject(&self) -> ProbeSubject {
        match self {
            Self::OAuth { subject, .. } => *subject,
            Self::ApiKey(_) => ProbeSubject::ApiKey,
            Self::Vertex(_) => ProbeSubject::Vertex,
        }
    }
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

    pub fn mark_rate_limited(&self, state: &mut State, account_id: &str) {
        self.mark_rate_limited_at(state, account_id, current_unix_seconds());
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

    fn mark_rate_limited_at(&self, state: &mut State, account_id: &str, now: i64) {
        if let Some(usage) = state.usage_cache.get_mut(account_id) {
            *usage = reduce_usage(
                usage,
                ProbeOutcome::Http429 {
                    subject: ProbeSubject::ApiKey,
                    retry_after_secs: None,
                },
                now,
            );
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
        return ProbeResult::outcome(ProbeOutcome::OtherTransient);
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
    use crate::core::health::{HealthErrorKind, HealthStatus};
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
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        request_count.fetch_add(1, Ordering::SeqCst);
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
        ProbeConfig::test_endpoint(address, Duration::from_millis(100))
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

    #[test]
    fn response_matrix_maps_401_403_429_5xx_and_quota() {
        let cases = [
            (200, None, HealthStatus::Ready, None),
            (401, None, HealthStatus::AuthInvalid, None),
            (403, None, HealthStatus::PermissionDenied, None),
            (429, Some("60"), HealthStatus::RateLimited, None),
            (500, None, HealthStatus::TransientFailure, None),
        ];
        for (status, retry_after, expected, expected_quota) in cases {
            let temp = tempfile::tempdir().unwrap();
            let acc = account("matrix", AccountType::ApiKey);
            let credential = PortableCredential::api_key("secret").unwrap();
            let mut state = v2_state(&temp, &acc, &credential, br#"{"api_key":"secret"}"#);
            let endpoint = if let Some(value) = retry_after {
                mock_server(
                    status,
                    &[("Retry-After", value)],
                    if status == 200 { "{}" } else { "" },
                )
                .0
            } else {
                mock_server(status, &[], if status == 200 { "{}" } else { "" }).0
            };
            let adapter = super::super::AntigravityAdapter;
            let usage = adapter.refresh_account_usage_at(
                temp.path(),
                &mut state,
                &acc,
                true,
                100,
                &config(&endpoint),
            );
            assert_eq!(usage.health, expected, "status {status}");
            assert_eq!(usage.remaining_quota_percent, expected_quota);
            if status == 429 {
                assert_eq!(usage.cooldown.unwrap().until, 160);
            }
        }
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
            "token_uri": "https://oauth2.example/token",
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

    #[test]
    fn extract_jwt_exp_rejects_malformed_shape() {
        let fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODcxOTk5OTksImVtYWlsIjoidGVzdEBnb29nbGUuY29tIn0.fake_signature";
        assert_eq!(extract_jwt_exp(fake_jwt), None);
        assert_eq!(extract_jwt_exp("invalid_jwt_format"), None);
    }

    #[test]
    fn test_mark_rate_limited() {
        let mut state = State::default();
        let acc_id = "test-acc-usage";
        state.usage_cache.insert(
            acc_id.to_string(),
            UsageSnapshot {
                health: HealthStatus::Ready,
                ..Default::default()
            },
        );
        let adapter = super::super::AntigravityAdapter;
        adapter.mark_rate_limited_at(&mut state, acc_id, 100);
        let usage = state.usage_cache.get(acc_id).unwrap();
        assert_eq!(usage.health, HealthStatus::RateLimited);
        assert!(usage.cooldown.is_some());
    }
}
