const README_EN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
const README_ZH: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.zh-CN.md"));
const ARCHITECTURE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/ARCHITECTURE.md"));

const AUTH_ENV_VARS: &[&str] = &[
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "CLOUDSDK_CORE_PROJECT",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_ACCESS_TOKEN",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GOOGLE_GENAI_USE_GCA",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
];

#[test]
fn public_docs_name_the_complete_child_auth_environment_boundary() {
    for (label, document) in [
        ("README.md", README_EN),
        ("README.zh-CN.md", README_ZH),
        ("ARCHITECTURE.md", ARCHITECTURE),
    ] {
        for variable in AUTH_ENV_VARS {
            assert!(
                document.contains(variable),
                "{label} does not document {variable}"
            );
        }
    }

    for stale_claim in [
        "exactly these three names",
        "精确只有这三个名字",
        "is inherited by `agy` unchanged",
        "会被 `agy` 原样继承",
    ] {
        assert!(
            !README_EN.contains(stale_claim)
                && !README_ZH.contains(stale_claim)
                && !ARCHITECTURE.contains(stale_claim),
            "public docs retain the stale child-environment claim {stale_claim:?}"
        );
    }
}

#[test]
fn public_docs_match_authorized_user_and_degraded_selection_policy() {
    for (label, document) in [
        ("README.md", README_EN),
        ("README.zh-CN.md", README_ZH),
        ("ARCHITECTURE.md", ARCHITECTURE),
    ] {
        assert!(
            document.contains("https://oauth2.googleapis.com/token"),
            "{label} omits the canonical authorized-user endpoint"
        );
        assert!(
            document.contains("Degraded"),
            "{label} omits the probe-channel fallback tier"
        );
    }
}

#[test]
fn installation_docs_do_not_present_unpublished_artifacts_as_available() {
    assert!(README_EN.contains("No GitHub Release has been published yet"));
    assert!(README_EN.contains("build from source"));
    assert!(README_ZH.contains("尚未发布 GitHub Release"));
    assert!(README_ZH.contains("源码编译"));
    assert!(ARCHITECTURE.contains("No GitHub Release exists yet"));
}
