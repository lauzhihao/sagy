#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sagy::adapters::antigravity::AntigravityAdapter;
use sagy::adapters::antigravity::repo_bundle::{BundleAccount, BundleAccountMetadata, BundleV2};
use sagy::core::credential::PortableCredential;
use sagy::core::state::{AccountType, State};
use serde_json::{Value, json};
use tempfile::TempDir;

const CANONICAL_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

fn authorized_user(token_uri: Option<Value>) -> Value {
    let mut document = json!({
        "type": "authorized_user",
        "client_id": "client-id",
        "client_secret": "client-secret",
        "refresh_token": "refresh-token",
        "unknown_nested": {"preserve": [true, 7, null]}
    });
    if let Some(token_uri) = token_uri {
        document
            .as_object_mut()
            .expect("authorized-user fixture is an object")
            .insert("token_uri".to_string(), token_uri);
    }
    document
}

#[test]
fn missing_and_canonical_token_uri_converge_without_changing_existing_fingerprint() {
    let missing = PortableCredential::from_native_json_str(
        &serde_json::to_string(&authorized_user(None)).expect("serialize missing endpoint"),
    )
    .expect("missing token_uri is a provider-valid authorized-user document");
    let canonical = PortableCredential::from_native_json_str(
        &serde_json::to_string(&authorized_user(Some(json!(CANONICAL_TOKEN_URI))))
            .expect("serialize canonical endpoint"),
    )
    .expect("canonical token_uri is accepted");

    assert_eq!(missing.fingerprint(), canonical.fingerprint());
    let native: Value = serde_json::from_str(
        &missing
            .to_native_json_string()
            .expect("serialize native authorized-user document"),
    )
    .expect("parse normalized native document");
    assert_eq!(native["token_uri"], CANONICAL_TOKEN_URI);

    let portable = PortableCredential::from_json_str(
        &missing
            .to_json_string()
            .expect("serialize normalized portable document"),
    )
    .expect("parse normalized portable document");
    assert_eq!(portable.fingerprint(), canonical.fingerprint());
}

#[test]
fn authorized_user_rejects_every_explicit_noncanonical_endpoint_without_echoing_it() {
    let candidates = [
        json!("https://oauth2.example.test/token"),
        json!("http://oauth2.googleapis.com/token"),
        json!(" https://oauth2.googleapis.com/token"),
        json!(""),
        Value::Null,
        json!(7),
        json!(true),
        json!([CANONICAL_TOKEN_URI]),
        json!({"uri": CANONICAL_TOKEN_URI}),
    ];

    for candidate in candidates {
        let encoded = serde_json::to_string(&authorized_user(Some(candidate.clone())))
            .expect("serialize endpoint matrix fixture");
        let error = PortableCredential::from_native_json_str(&encoded)
            .expect_err("noncanonical explicit endpoint must fail closed");
        let rendered = format!("{error:?} {error}");
        assert!(
            !rendered.contains(&candidate.to_string()),
            "credential error must not echo endpoint value: {rendered}"
        );
    }
}

#[test]
fn unknown_fields_survive_canonical_native_and_portable_roundtrips() {
    let credential = PortableCredential::oauth_authorized_user(authorized_user(None))
        .expect("construct authorized-user credential");
    let native: Value = serde_json::from_str(
        &credential
            .to_native_json_string()
            .expect("serialize native credential"),
    )
    .expect("parse native credential");
    assert_eq!(native["token_uri"], CANONICAL_TOKEN_URI);
    assert_eq!(
        native["unknown_nested"],
        json!({"preserve": [true, 7, null]})
    );

    let portable = PortableCredential::from_json_str(
        &credential
            .to_json_string()
            .expect("serialize portable credential"),
    )
    .expect("parse portable credential");
    assert_eq!(portable.fingerprint(), credential.fingerprint());
    assert_eq!(
        portable
            .native_document()
            .expect("authorized-user native document")["token_uri"],
        CANONICAL_TOKEN_URI
    );
}

#[test]
fn repository_bundle_roundtrip_serializes_authorized_user_with_canonical_endpoint() {
    let credential = PortableCredential::from_native_json_str(
        &serde_json::to_string(&authorized_user(None)).expect("serialize repository fixture"),
    )
    .expect("parse repository authorized-user fixture");
    let metadata = BundleAccountMetadata::new(
        "oauth@example.test",
        AccountType::OAuth,
        None,
        None,
        None,
        None,
        None,
        1,
        1,
        None,
    )
    .expect("construct bundle metadata");
    let account =
        BundleAccount::new("account-1", metadata, credential).expect("construct bundle account");
    let pool_id = uuid::Uuid::new_v4().to_string();
    let bundle = BundleV2::new(pool_id, 1, 1, vec![account]).expect("construct bundle");
    let encoded = bundle
        .canonical_json_bytes()
        .expect("encode canonical bundle");
    let decoded = BundleV2::from_json_bytes(&encoded).expect("decode canonical bundle");
    let decoded_document = decoded.accounts()[0]
        .credential
        .native_document()
        .expect("decoded authorized-user document");
    assert_eq!(decoded_document["token_uri"], CANONICAL_TOKEN_URI);
    assert_eq!(
        decoded_document["unknown_nested"],
        json!({"preserve": [true, 7, null]})
    );
}

#[test]
fn import_keeps_missing_endpoint_source_bytes_and_known_import_can_adopt_them() {
    let fixture = AuthorizedFixture::new();
    let source = fixture.root.join("source-authorized-user.json");
    let source_bytes = br#"{
  "type": "authorized_user",
  "client_id": "client-id",
  "client_secret": "client-secret",
  "refresh_token": "refresh-token",
  "unknown_nested": {"preserve": [true, 7, null]}
}
"#;
    fs::write(&source, source_bytes).expect("write original authorized-user source");
    fs::write(fixture.gemini.join("oauth_creds.json"), source_bytes)
        .expect("seed active authorized-user source");

    let adapter = AntigravityAdapter;
    let imported = adapter
        .import_auth_path(&fixture.state, &mut State::default(), &source)
        .expect("import missing-endpoint authorized-user source");
    let stored_path = fixture
        .state
        .join("accounts")
        .join(&imported.id)
        .join("credentials.json");
    assert_eq!(
        fs::read(&stored_path).expect("read imported credential material"),
        source_bytes,
        "import must retain original source bytes"
    );

    let imported_known = fixture.run(&["import-known"]);
    assert!(
        imported_known.status.success(),
        "import-known failed: {}{}",
        String::from_utf8_lossy(&imported_known.stdout),
        String::from_utf8_lossy(&imported_known.stderr)
    );
    let launched = fixture.run(&["launch", "--no-launch"]);
    assert!(
        launched.status.success(),
        "launch/adopt failed: {}{}",
        String::from_utf8_lossy(&launched.stdout),
        String::from_utf8_lossy(&launched.stderr)
    );
    assert_eq!(
        fs::read(fixture.gemini.join("oauth_creds.json")).expect("read adopted active file"),
        source_bytes,
        "adopt must not rewrite matching active authorized-user bytes"
    );
}

struct AuthorizedFixture {
    _temp: TempDir,
    root: PathBuf,
    state: PathBuf,
    gemini: PathBuf,
    antigravity: PathBuf,
    fake_agy: PathBuf,
}

impl AuthorizedFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create fixture root");
        let root = temp.path().to_path_buf();
        let state = root.join("state");
        let gemini = root.join("gemini");
        let antigravity = root.join("antigravity");
        let fake_agy = root.join("fake-agy");
        fs::create_dir_all(&state).expect("create state root");
        fs::create_dir_all(&gemini).expect("create Gemini root");
        fs::create_dir_all(&antigravity).expect("create Antigravity root");
        fs::write(&fake_agy, b"#!/bin/sh\nexit 0\n").expect("write fake agy");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&fake_agy)
                .expect("stat fake agy")
                .permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&fake_agy, permissions).expect("chmod fake agy");
        }
        Self {
            _temp: temp,
            root,
            state,
            gemini,
            antigravity,
            fake_agy,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .args(args)
            .env("HOME", self.root.join("home"))
            .env("SAGY_HOME", &self.state)
            .env("GEMINI_HOME", &self.gemini)
            .env("ANTIGRAVITY_CONFIG_DIR", &self.antigravity)
            .env("AGY_BIN", &self.fake_agy)
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .expect("run sagy")
    }
}
