use sagy::adapters::antigravity::repo_bundle::{BundleAccount, BundleAccountMetadata, BundleV2};
use sagy::core::credential::PortableCredential;
use sagy::core::state::AccountType;

const POOL_ID: &str = "00000000-0000-4000-8000-000000000000";

fn metadata(email: &str, credential: &PortableCredential) -> BundleAccountMetadata {
    BundleAccountMetadata::new(
        email,
        AccountType::OAuth,
        Some("antigravity".to_string()),
        None,
        None,
        Some(credential.identity_fingerprint()),
        None,
        1,
        1,
        None,
    )
    .expect("portable metadata")
}

#[test]
fn provider_native_bundle_roundtrip_preserves_exact_source_bytes() {
    let token_source = b"  antigravity-token\n";
    let token = PortableCredential::from_antigravity_token_source(token_source).unwrap();
    let session_source = br#"{
  "access_token": "access",
  "expiry_date": 1770000000000,
  "id_token": "id",
  "refresh_token": "refresh",
  "scope": "scope",
  "token_type": "Bearer"
}
"#;
    let session = PortableCredential::from_gemini_oauth_session_source(session_source).unwrap();

    let bundle = BundleV2::new(
        POOL_ID,
        1,
        1,
        vec![
            BundleAccount::new("antigravity", metadata("token@example.test", &token), token)
                .unwrap(),
            BundleAccount::new(
                "gemini",
                metadata("session@example.test", &session),
                session,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let encoded = bundle.canonical_json_bytes().unwrap();
    let decoded = BundleV2::from_json_bytes(&encoded).unwrap();

    let decoded_token = decoded
        .accounts()
        .iter()
        .find(|account| account.id == "antigravity")
        .unwrap();
    assert_eq!(
        decoded_token.credential.source_bytes(),
        Some(token_source.as_slice())
    );
    let decoded_session = decoded
        .accounts()
        .iter()
        .find(|account| account.id == "gemini")
        .unwrap();
    assert_eq!(
        decoded_session.credential.source_bytes(),
        Some(session_source.as_slice())
    );
}

#[test]
fn legacy_oauth_bundle_remains_compatible() {
    let credential = PortableCredential::oauth_access_token("legacy-token").unwrap();
    let account = BundleAccount::new(
        "legacy",
        BundleAccountMetadata::new(
            "legacy@example.test",
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
        .unwrap(),
        credential.clone(),
    )
    .unwrap();
    let bundle = BundleV2::new(POOL_ID, 1, 1, vec![account]).unwrap();
    let decoded = BundleV2::from_json_bytes(&bundle.canonical_json_bytes().unwrap()).unwrap();
    assert_eq!(decoded.accounts()[0].credential.kind(), credential.kind());
    assert_eq!(
        decoded.accounts()[0].credential.fingerprint(),
        credential.fingerprint()
    );
}
