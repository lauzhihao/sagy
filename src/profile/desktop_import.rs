//! 桌面登录由 Google 核实身份后复用原生账号导入事务。
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use reqwest::blocking::{Client, Response};
use reqwest::{NoProxy, Proxy, StatusCode, redirect};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{repo_sync, store};
use crate::core::credential::StrictValue;

const MAX_TOKEN_BYTES: u64 = 1024 * 1024;
const MAX_USERINFO_BYTES: u64 = 64 * 1024;
const USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";
const DEFAULT_PROXY: &str = "http://127.0.0.1:10808";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

// 凭据值不能实现 Debug/Display，避免错误诊断意外输出登录秘密。
pub(super) struct Candidate {
    document: Value,
    access_token: String,
    fingerprint: [u8; 32],
}

struct Identity {
    email: String,
}

type Verifier = Box<dyn FnMut(&str) -> Result<Identity> + Send>;

pub(super) struct Importer {
    root: PathBuf,
    token_path: PathBuf,
    verify: Verifier,
}

pub(super) enum ImportOutcome {
    Added(String),
    AlreadyRegistered(String),
    Superseded,
    Busy,
}

pub(super) fn read_candidate(path: &Path) -> Result<Option<Candidate>> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Desktop login file has no directory."))?;
    store::check_private_dir(parent).map_err(|_| anyhow!("Desktop login directory is unsafe."))?;
    let mut file = match store::open_private_file(path, false) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(_) => bail!("Could not safely read the desktop login file."),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("Could not read the desktop login file."))?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        bail!("Desktop login file exceeds its size limit.");
    }
    let Ok(StrictValue(document)) = serde_json::from_slice::<StrictValue>(&bytes) else {
        // 桌面可能先截断再写入；等待下一份完整内容，不能注册半份登录。
        return Ok(None);
    };
    let Some(object) = document.as_object() else {
        return Ok(None);
    };
    let token = object.get("token").unwrap_or(&document);
    let Some(access_token) = nonempty_string(token.get("access_token")) else {
        return Ok(None);
    };
    if nonempty_string(token.get("refresh_token")).is_none() {
        return Ok(None);
    }
    if token.get("token_type").is_some_and(|value| {
        !value
            .as_str()
            .is_some_and(|kind| kind.eq_ignore_ascii_case("Bearer"))
    }) {
        return Ok(None);
    }
    let access_token = access_token.to_owned();
    Ok(Some(Candidate {
        document,
        access_token,
        fingerprint: Sha256::digest(&bytes).into(),
    }))
}

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

impl Candidate {
    pub(super) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn check_saved_email(&self, email: &str) -> Result<()> {
        for name in ["id_token_email", "email"] {
            let Some(value) = self.document.get(name) else {
                continue;
            };
            let Some(value) = value.as_str() else {
                bail!("Desktop login contains an invalid saved email.");
            };
            if value.is_empty() {
                continue;
            }
            if normalized_email(value).ok().as_deref() != Some(email) {
                bail!("Desktop login identity does not match its saved email.");
            }
        }
        Ok(())
    }
}

impl Importer {
    #[cfg(test)]
    pub(super) fn with_test_verifier(
        root: PathBuf,
        token_path: PathBuf,
        mut verify: impl FnMut(&str) -> Result<String> + Send + 'static,
    ) -> Self {
        Self {
            root,
            token_path,
            verify: Box::new(move |access_token| {
                let email = verify(access_token)?;
                Ok(Identity {
                    email: normalized_email(&email)?,
                })
            }),
        }
    }

    pub(super) fn new(root: PathBuf, token_path: PathBuf) -> Result<Self> {
        if !root.is_absolute() || !token_path.is_absolute() {
            bail!("Desktop account synchronization requires absolute paths.");
        }
        let client = identity_client()?;
        Ok(Self {
            root,
            token_path,
            verify: Box::new(move |access_token| verify_identity(&client, access_token)),
        })
    }

    pub(super) fn import(&mut self, candidate: Candidate) -> Result<ImportOutcome> {
        let identity = (self.verify)(&candidate.access_token)?;
        candidate.check_saved_email(&identity.email)?;
        // 验证请求期间可能再次切号。身份和凭据必须来自同一份完整快照。
        let current = read_candidate(&self.token_path)?;
        if current.as_ref().map(Candidate::fingerprint) != Some(candidate.fingerprint()) {
            return Ok(ImportOutcome::Superseded);
        }
        let imported =
            repo_sync::try_import_profile(&self.root, &identity.email, &candidate.document)
                .map_err(|_| anyhow!("Could not register the verified desktop account."))?;
        Ok(match imported {
            Some(true) => ImportOutcome::Added(identity.email),
            Some(false) => ImportOutcome::AlreadyRegistered(identity.email),
            None => ImportOutcome::Busy,
        })
    }
}

fn has_proxy(environment: impl IntoIterator<Item = (OsString, OsString)>) -> bool {
    let environment: BTreeMap<_, _> = environment.into_iter().collect();
    [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ]
    .iter()
    .any(|name| {
        environment
            .get(std::ffi::OsStr::new(name))
            .is_some_and(|value| !value.is_empty())
    })
}

fn identity_client_builder() -> reqwest::blocking::ClientBuilder {
    Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(REQUEST_TIMEOUT)
        .redirect(redirect::Policy::none())
}

fn identity_client() -> Result<Client> {
    let mut builder = identity_client_builder();
    if !has_proxy(std::env::vars_os()) {
        let proxy = Proxy::all(DEFAULT_PROXY)
            .map_err(|_| anyhow!("Could not configure desktop identity verification."))?
            .no_proxy(NoProxy::from_env());
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|_| anyhow!("Could not initialize desktop identity verification."))
}

fn verify_identity(client: &Client, access_token: &str) -> Result<Identity> {
    let response = client
        .get(USERINFO_URL)
        .bearer_auth(access_token)
        .send()
        .map_err(identity_request_error)?;
    decode_response(response)
}

fn identity_request_error(error: reqwest::Error) -> anyhow::Error {
    // reqwest 错误可能包含响应地址或认证信息，不能把原错误挂进日志链。
    if error.is_timeout() {
        anyhow!("Desktop identity verification timed out.")
    } else {
        anyhow!("Desktop identity verification network request failed.")
    }
}

fn decode_response(mut response: Response) -> Result<Identity> {
    check_status(response.status())?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_USERINFO_BYTES)
    {
        bail!("Desktop identity response exceeds its size limit.");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut response)
        .take(MAX_USERINFO_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("Could not read the desktop identity response."))?;
    decode_identity(&bytes)
}

fn check_status(status: StatusCode) -> Result<()> {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        bail!("Desktop login is not accepted by Google.");
    }
    if status != StatusCode::OK {
        bail!("Desktop identity verification was rejected.");
    }
    Ok(())
}

fn decode_identity(bytes: &[u8]) -> Result<Identity> {
    if bytes.len() as u64 > MAX_USERINFO_BYTES {
        bail!("Desktop identity response exceeds its size limit.");
    }
    let StrictValue(document) = serde_json::from_slice::<StrictValue>(bytes)
        .map_err(|_| anyhow!("Desktop identity response is invalid."))?;
    if document.get("verified_email").and_then(Value::as_bool) != Some(true)
        || nonempty_string(document.get("id")).is_none()
    {
        bail!("Desktop identity response has no verified account.");
    }
    let email = document
        .get("email")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Desktop identity response has no valid email."))?;
    Ok(Identity {
        email: normalized_email(email)?,
    })
}

fn normalized_email(email: &str) -> Result<String> {
    let normalized = store::valid_name(email)
        .map_err(|_| anyhow!("Desktop identity response has no valid email."))?;
    if !normalized.contains('@') {
        bail!("Desktop identity response has no valid email.");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Instant;

    use serde_json::json;

    struct Fixture {
        root: tempfile::TempDir,
        token_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            store::ensure_private_dir(&root.path().join("profiles")).unwrap();
            let token_path = root.path().join("desktop-token");
            Self { root, token_path }
        }

        fn save(&self, value: &Value) -> Candidate {
            self.save_bytes(&serde_json::to_vec(value).unwrap());
            read_candidate(&self.token_path).unwrap().unwrap()
        }

        fn save_bytes(&self, bytes: &[u8]) {
            fs::write(&self.token_path, bytes).unwrap();
            fs::set_permissions(&self.token_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        fn importer<F>(&self, verify: F) -> Importer
        where
            F: FnMut(&str) -> Result<Identity> + Send + 'static,
        {
            Importer {
                root: self.root.path().to_owned(),
                token_path: self.token_path.clone(),
                verify: Box::new(verify),
            }
        }
    }

    fn token(email: &str, refresh: &str) -> Value {
        json!({
            "token": {"access_token":"synthetic-access", "refresh_token":refresh,
                      "token_type":"Bearer", "expiry":"2099-01-01T00:00:00Z"},
            "id_token_email":email,
            "auth_method":"synthetic", "writer_id":"fixture",
            "future_field":{"nested":[1,2,3]}
        })
    }

    fn identity(email: &str) -> Identity {
        Identity {
            email: email.into(),
        }
    }

    #[test]
    fn candidate_requires_complete_private_resumable_json_and_hashes_exact_bytes() {
        let fixture = Fixture::new();
        assert!(read_candidate(&fixture.token_path).unwrap().is_none());
        for bytes in [
            br#"{"token":{"access_token":"half""#.as_slice(),
            br#"{"token":{"access_token":"a"}}"#.as_slice(),
            br#"{"token":{"access_token":" ","refresh_token":"r"}}"#.as_slice(),
            br#"{"token":{"access_token":"a","refresh_token":"r","token_type":"unsupported"}}"#
                .as_slice(),
            br#"{"token":{"access_token":"a","refresh_token":"r","refresh_token":"different"}}"#
                .as_slice(),
            br#"[]"#.as_slice(),
        ] {
            fixture.save_bytes(bytes);
            assert!(read_candidate(&fixture.token_path).unwrap().is_none());
        }
        let raw = serde_json::to_vec_pretty(&token("alice@example.test", "synthetic-r")).unwrap();
        fixture.save_bytes(&raw);
        let candidate = read_candidate(&fixture.token_path).unwrap().unwrap();
        let expected: [u8; 32] = Sha256::digest(&raw).into();
        assert_eq!(candidate.fingerprint(), expected);
        fs::set_permissions(&fixture.token_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_candidate(&fixture.token_path).is_err());
        fixture.save_bytes(&vec![b' '; MAX_TOKEN_BYTES as usize + 1]);
        assert!(read_candidate(&fixture.token_path).is_err());
        fs::remove_file(&fixture.token_path).unwrap();
        let outside = fixture.root.path().join("outside");
        fs::write(&outside, &raw).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&outside, &fixture.token_path).unwrap();
        assert!(read_candidate(&fixture.token_path).is_err());
        fs::remove_file(&fixture.token_path).unwrap();
        fs::hard_link(&outside, &fixture.token_path).unwrap();
        assert!(read_candidate(&fixture.token_path).is_err());
    }

    #[test]
    fn server_requires_verified_email_and_subject_and_normalizes_the_label() {
        let identity = decode_identity(
            br#"{"id":"subject-1","email":"Alice@EXAMPLE.test","verified_email":true}"#,
        )
        .unwrap();
        assert_eq!(identity.email, "alice@example.test");
        for bytes in [
            br#"{"id":"subject","email":"a@example.test","verified_email":false}"#.as_slice(),
            br#"{"email":"a@example.test","verified_email":true}"#.as_slice(),
            br#"{"id":" ","email":"a@example.test","verified_email":true}"#.as_slice(),
            br#"{"id":"s","email":"work","verified_email":true}"#.as_slice(),
            br#"{"id":"s","email":"a@example.test","verified_email":"true"}"#.as_slice(),
            br#"{"id":"s","email":"a@example.test","email":"b@example.test","verified_email":true}"#.as_slice(),
            br#"secret-response-not-json"#.as_slice(),
        ] {
            let error = decode_identity(bytes).err().unwrap();
            assert!(!format!("{error:#}").contains("secret-response"));
        }
        assert!(decode_identity(&vec![b'x'; MAX_USERINFO_BYTES as usize + 1]).is_err());
    }

    #[test]
    fn imports_verified_snapshot_with_unknown_fields_and_keeps_existing_login() {
        let fixture = Fixture::new();
        let document = token("alice@example.test", "synthetic-first-refresh");
        let candidate = fixture.save(&document);
        let mut importer = fixture.importer(|access| {
            assert_eq!(access, "synthetic-access");
            Ok(identity("alice@example.test"))
        });
        assert!(
            matches!(importer.import(candidate).unwrap(), ImportOutcome::Added(name) if name == "alice@example.test")
        );
        let mut state = store::read_state(fixture.root.path()).unwrap();
        assert_eq!(state.profiles, ["alice@example.test"]);
        assert_eq!(state.last_selected, None);
        let home =
            store::profile_home(fixture.root.path(), &state, "alice@example.test", false).unwrap();
        let saved = home.join(".gemini/antigravity-cli/antigravity-oauth-token");
        let original_bytes = fs::read(&saved).unwrap();
        let stored: Value = serde_json::from_slice(&original_bytes).unwrap();
        assert_eq!(stored, document);
        assert!(store::token_ready(&home).unwrap());
        state.last_selected = Some("alice@example.test".into());
        state.cooldowns.insert("alice@example.test".into(), 42.0);
        store::write_state(fixture.root.path(), &state).unwrap();
        let original_state = fs::read(fixture.root.path().join("state.json")).unwrap();
        let lease = store::try_shared_lease(&home).unwrap().unwrap();
        let replacement = fixture.save(&token("alice@example.test", "synthetic-other-refresh"));
        assert!(
            matches!(importer.import(replacement).unwrap(), ImportOutcome::AlreadyRegistered(name) if name == "alice@example.test")
        );
        assert_eq!(fs::read(saved).unwrap(), original_bytes);
        assert_eq!(
            fs::read(fixture.root.path().join("state.json")).unwrap(),
            original_state
        );
        drop(lease);
        assert!(!fixture.root.path().join(".sync-import.json").exists());
    }

    #[test]
    fn rejects_forged_local_email_and_changed_snapshot_without_registering() {
        let fixture = Fixture::new();
        let candidate = fixture.save(&token("forged@example.test", "synthetic-first"));
        let mut importer = fixture.importer(|_| Ok(identity("actual@example.test")));
        let error = importer.import(candidate).err().unwrap();
        assert!(error.to_string().contains("does not match"));
        assert!(!fixture.root.path().join("state.json").exists());

        let old = fixture.save(&token("actual@example.test", "synthetic-old"));
        let next_path = fixture.token_path.clone();
        let mut importer = fixture.importer(move |_| {
            fs::write(
                &next_path,
                serde_json::to_vec(&token("next@example.test", "synthetic-next")).unwrap(),
            )
            .unwrap();
            Ok(identity("actual@example.test"))
        });
        assert!(matches!(
            importer.import(old).unwrap(),
            ImportOutcome::Superseded
        ));
        assert!(
            store::read_state(fixture.root.path())
                .unwrap()
                .profiles
                .is_empty()
        );
    }

    #[test]
    fn verification_failure_never_publishes_and_can_be_retried() {
        let fixture = Fixture::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut importer = fixture.importer(move |_| {
            if observed.fetch_add(1, Ordering::Relaxed) == 0 {
                bail!("Desktop identity verification timed out.");
            }
            Ok(identity("alice@example.test"))
        });
        let candidate = fixture.save(&token("alice@example.test", "synthetic-r"));
        assert!(importer.import(candidate).is_err());
        assert!(
            store::read_state(fixture.root.path())
                .unwrap()
                .profiles
                .is_empty()
        );
        let candidate = read_candidate(&fixture.token_path).unwrap().unwrap();
        assert!(matches!(
            importer.import(candidate).unwrap(),
            ImportOutcome::Added(_)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn busy_registry_returns_immediately_and_pending_removal_does_not_wait_for_quota() {
        let fixture = Fixture::new();
        let mut importer = fixture.importer(|_| Ok(identity("alice@example.test")));
        let lock = store::lock_registry(fixture.root.path()).unwrap();
        let started = Instant::now();
        let candidate = fixture.save(&token("alice@example.test", "synthetic-r"));
        assert!(matches!(
            importer.import(candidate).unwrap(),
            ImportOutcome::Busy
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(lock);

        let manifest = fixture.root.path().join(super::super::remove::MANIFEST);
        fs::write(
            &manifest,
            b"synthetic pending removal; must not be parsed by watcher",
        )
        .unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
        let original = fs::read(&manifest).unwrap();
        let quota_lock =
            store::open_private_file(&fixture.root.path().join(".quota.lock"), true).unwrap();
        fs2::FileExt::lock_exclusive(&quota_lock).unwrap();
        let started = Instant::now();
        let candidate = read_candidate(&fixture.token_path).unwrap().unwrap();
        assert!(matches!(
            importer.import(candidate).unwrap(),
            ImportOutcome::Busy
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(fs::read(manifest).unwrap(), original);
        assert!(!fixture.root.path().join("state.json").exists());
    }

    #[test]
    fn proxy_precedence_recognizes_every_supported_case_without_mutating_environment() {
        assert!(!has_proxy(Vec::new()));
        for key in [
            "http_proxy",
            "HTTP_PROXY",
            "https_proxy",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ] {
            assert!(has_proxy([(
                key.into(),
                "http://configured.invalid:1234".into()
            )]));
            assert!(!has_proxy([(key.into(), "".into())]));
        }
        assert!(!has_proxy([("NO_PROXY".into(), "*".into())]));
    }

    fn local_response(
        status: &str,
        headers: &str,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_owned();
        let headers = headers.to_owned();
        let thread = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0u8; 1024];
            while !bytes.ends_with(b"\r\n\r\n") {
                let count = socket.read(&mut chunk).unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes());
            let _ = socket.write_all(&body);
            String::from_utf8(bytes).unwrap()
        });
        (format!("http://{address}/userinfo"), thread)
    }

    #[test]
    fn userinfo_transport_bounds_response_rejects_redirect_and_does_not_log_body() {
        let client = identity_client_builder().no_proxy().build().unwrap();
        let (url, server) = local_response(
            "200 OK",
            "",
            br#"{"id":"subject","email":"alice@example.test","verified_email":true}"#.to_vec(),
        );
        let response = client
            .get(&url)
            .bearer_auth("synthetic-secret")
            .send()
            .unwrap();
        assert_eq!(
            decode_response(response).unwrap().email,
            "alice@example.test"
        );
        let request = server.join().unwrap();
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer synthetic-secret\r\n")
        );
        assert!(!request.lines().next().unwrap().contains("synthetic-secret"));

        for (status, headers, body) in [
            ("401 Unauthorized", "", b"secret-response-value".to_vec()),
            (
                "302 Found",
                "Location: http://127.0.0.1:1/should-not-follow\r\n",
                b"secret-response-value".to_vec(),
            ),
            ("200 OK", "", vec![b'x'; MAX_USERINFO_BYTES as usize + 1]),
        ] {
            let (url, server) = local_response(status, headers, body);
            let response = client
                .get(url)
                .bearer_auth("synthetic-secret")
                .send()
                .unwrap();
            let error = decode_response(response).err().unwrap();
            assert!(!format!("{error:#}").contains("secret-response"));
            assert!(!format!("{error:#}").contains("synthetic-secret"));
            server.join().unwrap();
        }
    }

    #[test]
    fn timeout_errors_are_classified_without_request_or_response_details() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(150));
            drop(socket);
        });
        let client = identity_client_builder()
            .no_proxy()
            .timeout(Duration::from_millis(30))
            .build()
            .unwrap();
        let error = client
            .get(format!("http://{address}/synthetic-secret"))
            .bearer_auth("synthetic-secret")
            .send()
            .err()
            .unwrap();
        let error = identity_request_error(error);
        assert!(error.to_string().contains("timed out"));
        assert!(!format!("{error:#}").contains("synthetic-secret"));
        server.join().unwrap();
    }
}
