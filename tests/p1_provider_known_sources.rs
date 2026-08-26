//! Provider-native known-source import and first-run dual-home adoption.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;

const TOKEN: &[u8] = b"provider-token-source\n";
const GEMINI_SESSION: &[u8] = br#"{"access_token":"gemini-access","expiry_date":4102444800000,"id_token":"gemini-id","refresh_token":"gemini-refresh","scope":"scope","token_type":"Bearer"}
"#;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create fixture");
        let root = temp.path().to_path_buf();
        for directory in ["home", "gemini", "antigravity", "sagy-home"] {
            fs::create_dir_all(root.join(directory)).expect("create fixture directory");
        }
        let fixture = Self { _temp: temp, root };
        fixture.seed_known_sources();
        fixture
    }

    fn seed_known_sources(&self) {
        fs::write(self.antigravity().join("antigravity-oauth-token"), TOKEN)
            .expect("write token source");
        fs::write(self.gemini().join("oauth_creds.json"), GEMINI_SESSION)
            .expect("write Gemini session source");
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn gemini(&self) -> PathBuf {
        self.root.join("gemini")
    }

    fn antigravity(&self) -> PathBuf {
        self.root.join("antigravity")
    }

    fn state(&self) -> PathBuf {
        self.root.join("sagy-home")
    }

    fn fake_agy(&self) -> PathBuf {
        let path = self.root.join("agy");
        if !path.exists() {
            fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write fake agy");
            let mut permissions = fs::metadata(&path).expect("stat fake agy").permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).expect("chmod fake agy");
        }
        path
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sagy"))
            .args(args)
            .env("HOME", self.home())
            .env("SAGY_HOME", self.state())
            .env("GEMINI_HOME", self.gemini())
            .env("ANTIGRAVITY_CONFIG_DIR", self.antigravity())
            .env("AGY_BIN", self.fake_agy())
            .env_remove("GEMINI_API_KEY")
            .env_remove("GOOGLE_API_KEY")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("GOOGLE_CLOUD_PROJECT")
            .output()
            .expect("run sagy")
    }

    fn account_dirs(&self) -> Vec<PathBuf> {
        let mut accounts = fs::read_dir(self.state().join("accounts"))
            .expect("read account root")
            .map(|entry| entry.expect("read account entry").path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        accounts.sort();
        accounts
    }
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_success(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed: {:?}\n{}",
        output.status,
        output_text(output)
    );
}

#[test]
fn known_sources_import_independently_and_repeat_idempotently() {
    let fixture = Fixture::new();
    let first = fixture.run(&["import-known"]);
    assert_success(&first, "first known-source import");

    let accounts = fixture.account_dirs();
    assert_eq!(
        accounts.len(),
        2,
        "two provider sources must remain separate"
    );
    assert!(accounts.iter().any(|account| {
        fs::read(account.join("antigravity-oauth-token"))
            .ok()
            .as_deref()
            == Some(TOKEN)
    }));
    assert!(accounts.iter().any(|account| {
        fs::read(account.join("credentials.json")).ok().as_deref() == Some(GEMINI_SESSION)
    }));

    let second = fixture.run(&["import-known"]);
    assert_success(&second, "repeated known-source import");
    assert_eq!(
        fixture.account_dirs(),
        accounts,
        "repeat import must reuse ids"
    );
    assert!(accounts.iter().any(|account| {
        fs::read(account.join("antigravity-oauth-token"))
            .ok()
            .as_deref()
            == Some(TOKEN)
    }));
    assert!(accounts.iter().any(|account| {
        fs::read(account.join("credentials.json")).ok().as_deref() == Some(GEMINI_SESSION)
    }));
}

#[test]
fn first_launch_publishes_one_slot_and_retains_the_other_account_store() {
    let fixture = Fixture::new();
    let launched = fixture.run(&["say", "hi"]);
    assert_success(&launched, "first bare launch");

    let live_token = fixture
        .antigravity()
        .join("antigravity-oauth-token")
        .exists();
    let live_document = fixture.gemini().join("oauth_creds.json").exists();
    assert_ne!(
        live_token, live_document,
        "first adoption must publish one slot"
    );
    let accounts = fixture.account_dirs();
    assert_eq!(accounts.len(), 2);
    assert!(accounts.iter().any(|account| {
        fs::read(account.join("antigravity-oauth-token"))
            .ok()
            .as_deref()
            == Some(TOKEN)
    }));
    assert!(accounts.iter().any(|account| {
        fs::read(account.join("credentials.json")).ok().as_deref() == Some(GEMINI_SESSION)
    }));
}

#[test]
fn known_adoption_proof_failure_leaves_active_home_untouched() {
    let fixture = Fixture::new();
    let imported = fixture.run(&["import-known"]);
    assert_success(&imported, "known-source import");

    // The active file no longer matches the exact scanned source. Default
    // Adopt must fail closed before moving either live slot.
    let changed_token = b"externally-mutated-token\n";
    fs::write(
        fixture.antigravity().join("antigravity-oauth-token"),
        changed_token,
    )
    .expect("mutate live token");
    let before_document =
        fs::read(fixture.gemini().join("oauth_creds.json")).expect("read unchanged document");

    let launched = fixture.run(&["say", "hi"]);
    assert!(!launched.status.success(), "proof failure must stop launch");
    assert_eq!(
        fs::read(fixture.antigravity().join("antigravity-oauth-token"))
            .expect("read live token after rejection"),
        changed_token
    );
    assert_eq!(
        fs::read(fixture.gemini().join("oauth_creds.json"))
            .expect("read live document after rejection"),
        before_document
    );
}
