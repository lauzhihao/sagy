use std::fs;

use sagy::adapters::antigravity::AntigravityAdapter;
use sagy::core::credential::PortableCredential;
use sagy::core::state::State;

#[test]
fn access_token_updates_preserve_refresh_material_across_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let source = temp.path().join("authorized-user.json");
    fs::write(
        &source,
        br#"{
  "type": "authorized_user",
  "client_id": "test-client-id",
  "client_secret": "test-client-secret",
  "refresh_token": "test-refresh-token",
  "token_uri": "https://oauth2.googleapis.com/token",
  "email": "oauth@example.test",
  "project_id": "original-project",
  "unknown": "must-survive"
}"#,
    )
    .expect("write OAuth fixture");

    let adapter = AntigravityAdapter;
    let imported = adapter
        .import_auth_path(&state_dir, &mut State::default(), &source)
        .expect("import authorized-user JSON");
    let first = adapter
        .import_or_update_token(
            &state_dir,
            &mut State::default(),
            "oauth@example.test",
            "new-access-token-1",
            None,
        )
        .expect("update access token after reopening state");
    assert_eq!(first.id, imported.id);
    assert_eq!(first.refresh_token.as_deref(), Some("test-refresh-token"));

    let credentials_path = state_dir
        .join("accounts")
        .join(&imported.id)
        .join("credentials.json");
    let first_document = fs::read_to_string(&credentials_path).expect("read updated OAuth JSON");
    let first_credential = PortableCredential::from_native_json_str(&first_document)
        .expect("updated OAuth JSON remains complete");
    assert_eq!(first_credential.access_token(), Some("new-access-token-1"));
    assert_eq!(first_credential.refresh_token(), Some("test-refresh-token"));
    let first_json: serde_json::Value =
        serde_json::from_str(&first_document).expect("parse updated OAuth JSON");
    assert_eq!(
        first_json
            .get("unknown")
            .and_then(serde_json::Value::as_str),
        Some("must-survive")
    );

    let second = adapter
        .import_or_update_token(
            &state_dir,
            &mut State::default(),
            "oauth@example.test",
            "new-access-token-2",
            Some("Updated plan"),
        )
        .expect("repeat update after another restart");
    assert_eq!(second.id, imported.id);
    assert_eq!(second.refresh_token.as_deref(), Some("test-refresh-token"));
    assert_eq!(second.oauth_token.as_deref(), Some("new-access-token-2"));
    assert_eq!(second.plan.as_deref(), Some("Updated plan"));

    let repeated = fs::read_to_string(&credentials_path).expect("read repeated OAuth JSON");
    let repeated = PortableCredential::from_native_json_str(&repeated)
        .expect("repeated OAuth JSON remains complete");
    assert_eq!(repeated.access_token(), Some("new-access-token-2"));
    assert_eq!(repeated.refresh_token(), Some("test-refresh-token"));

    // State v2 keeps only the credential reference; restart material lives in
    // the fixed credential slot and is never duplicated into state.json.
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("state.json")).expect("read v2 state"))
            .expect("parse v2 state");
    let account = &state["accounts"][0];
    for secret_or_path in [
        "auth_path",
        "oauth_token",
        "refresh_token",
        "api_key",
        "identity_fingerprint",
    ] {
        assert!(
            account.get(secret_or_path).is_none(),
            "leaked {secret_or_path}"
        );
    }
}

#[test]
fn first_access_token_import_is_idempotent_across_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let adapter = AntigravityAdapter;

    let first = adapter
        .import_or_update_token(
            &state_dir,
            &mut State::default(),
            "new@example.test",
            "first-access-token",
            None,
        )
        .expect("first access-token import");
    let second = adapter
        .import_or_update_token(
            &state_dir,
            &mut State::default(),
            "new@example.test",
            "first-access-token",
            None,
        )
        .expect("repeat access-token import");
    assert_eq!(second.id, first.id);
    assert_eq!(second.oauth_token.as_deref(), Some("first-access-token"));
    assert_eq!(
        fs::read_to_string(
            state_dir
                .join("accounts")
                .join(&first.id)
                .join("antigravity-oauth-token")
        )
        .expect("read fixed token"),
        "first-access-token"
    );

    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(state_dir.join("state.json")).expect("read v2 state"))
            .expect("parse v2 state");
    assert_eq!(state["accounts"].as_array().map(Vec::len), Some(1));
}
