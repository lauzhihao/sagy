//! T4 regression tests: account pool synchronization must not lose data.
//!
//! Every test drives a real local bare Git repository so the push/pull round
//! trip exercises the same clone/commit/push path the CLI uses.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;

use sagy::adapters::antigravity::repo_sync::validate_repo_source;
use sagy::adapters::antigravity::{AntigravityAdapter, PullOptions, PullOutcome, PushOptions};
use sagy::cli::repo_sync::resolve_repo_sync_repo;
use sagy::core::state::State;

static POOL_KEY: Once = Once::new();

fn ensure_pool_key() {
    // 同一个进程内所有测试共用同一个常量 key，避免并发写环境变量互相打架。
    POOL_KEY.call_once(|| unsafe {
        std::env::set_var("SAGY_POOL_KEY", "p1-repo-sync-pool-regression-key");
    });
}

fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("git must be available");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_bare_repo(path: &Path) -> String {
    fs::create_dir_all(path).expect("bare repo dir");
    git(path, &["init", "--bare", "."]);
    path.to_str().expect("utf-8 repo path").to_string()
}

struct Machine {
    adapter: AntigravityAdapter,
    dir: PathBuf,
    state: State,
}

impl Machine {
    fn new(root: &Path, name: &str) -> Self {
        ensure_pool_key();
        Self {
            adapter: AntigravityAdapter,
            dir: root.join(name),
            state: State::default(),
        }
    }

    fn add(&mut self, email: &str, token: &str) -> String {
        self.adapter
            .import_or_update_token(&self.dir, &mut self.state, email, token, None)
            .expect("token import")
            .id
    }

    fn remove(&mut self, account_id: &str) {
        self.adapter
            .remove_account(&self.dir, &mut self.state, account_id)
            .expect("account removal");
    }

    fn push(&mut self, repo: &str) -> anyhow::Result<()> {
        self.adapter
            .push_account_pool(&self.dir, &self.state, repo, PushOptions::default())
            .map(|_| ())
    }

    fn pull(&mut self, repo: &str) -> anyhow::Result<PullOutcome> {
        self.adapter
            .pull_account_pool(&self.dir, &mut self.state, repo, PullOptions::default())
    }

    /// Refresh the in-memory snapshot from disk without changing anything.
    fn sync_view(&mut self, repo: &str) {
        let _ = self.pull(repo);
    }

    fn emails(&self) -> Vec<String> {
        let mut emails = self
            .state
            .accounts
            .iter()
            .map(|account| account.email.clone())
            .collect::<Vec<_>>();
        emails.sort();
        emails
    }

    fn account_dir(&self, account_id: &str) -> PathBuf {
        self.dir.join("accounts").join(account_id)
    }
}

fn bundle_bytes(repo: &str) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["show", "HEAD:.sagy-account-pool/bundle.enc.json"])
        .output()
        .expect("git show");
    output.status.success().then_some(output.stdout)
}

// ---------------------------------------------------------------------------
// AC-1: push must never overwrite accounts published by another machine.
// ---------------------------------------------------------------------------

#[test]
fn stale_push_is_rejected_and_the_pool_keeps_every_account() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("one@example.test", "token-one");
    alice.add("two@example.test", "token-two");
    alice.push(&repo).expect("first push");

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");
    bob.add("three@example.test", "token-three");
    bob.push(&repo).expect("bob push");

    let before = bundle_bytes(&repo).expect("remote bundle after bob push");

    // AC-1.1: alice never pulled bob's generation, so her push must fail.
    alice.add("four@example.test", "token-four");
    let error = alice.push(&repo).expect_err("stale push must be rejected");
    let text = format!("{error:#}");
    assert!(
        text.contains("behind the remote pool"),
        "error does not explain divergence: {text}"
    );
    assert!(
        text.contains("sagy pull"),
        "error does not tell the user how to recover: {text}"
    );
    assert_eq!(
        bundle_bytes(&repo).expect("remote bundle unchanged"),
        before,
        "rejected push still rewrote the remote bundle"
    );

    // AC-1.2: pull first, then push, and both sides survive.
    alice.pull(&repo).expect("alice pull");
    alice.push(&repo).expect("push after pull");

    // AC-1.4: a brand-new machine sees every account, including bob's.
    let mut carol = Machine::new(temp.path(), "carol");
    carol.pull(&repo).expect("carol pull");
    assert_eq!(
        carol.emails(),
        vec![
            "four@example.test".to_string(),
            "one@example.test".to_string(),
            "three@example.test".to_string(),
            "two@example.test".to_string(),
        ]
    );
}

#[test]
fn first_push_and_semantic_noop_push_are_unaffected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    // AC-1.3, path 1: no remote bundle at all.
    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("one@example.test", "token-one");
    alice
        .push(&repo)
        .expect("first push against an empty repository");
    let first = bundle_bytes(&repo).expect("bundle after first push");

    // AC-1.3, path 2: pushing the identical account set is a no-op and must
    // not rewrite the encrypted envelope.
    alice.push(&repo).expect("semantic no-op push");
    assert_eq!(
        bundle_bytes(&repo).expect("bundle after no-op push"),
        first,
        "semantic no-op push rewrote the bundle"
    );
}

// ---------------------------------------------------------------------------
// AC-2: pull must deduplicate by credential fingerprint.
// ---------------------------------------------------------------------------

#[test]
fn pull_deduplicates_identical_credentials_and_keeps_push_working() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    let pool_id = alice.add("shared@example.test", "token-shared");
    alice.push(&repo).expect("alice push");

    // Bob independently imported the same credential under his own account id.
    let mut bob = Machine::new(temp.path(), "bob");
    let local_id = bob.add("shared-alias@example.test", "token-shared");
    assert_ne!(pool_id, local_id, "test needs two distinct account ids");

    bob.pull(&repo).expect("bob pull");

    // AC-2.1: exactly one account carries that credential afterwards.
    assert_eq!(
        bob.state.accounts.len(),
        1,
        "pull inserted a duplicate account: {:?}",
        bob.emails()
    );
    assert_eq!(bob.state.accounts[0].id, pool_id);

    // AC-2.2: the pull must not create a state that can never be pushed again.
    bob.push(&repo).expect("push after a deduplicating pull");
}

// ---------------------------------------------------------------------------
// AC-3: deletions must propagate.
// ---------------------------------------------------------------------------

#[test]
fn deletions_propagate_without_touching_local_only_accounts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    let keep = alice.add("keep@example.test", "token-keep");
    let doomed = alice.add("doomed@example.test", "token-doomed");
    alice.push(&repo).expect("alice push");

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");
    let doomed_dir = bob.account_dir(&doomed);
    assert!(doomed_dir.exists(), "pull did not materialize the account");

    // AC-3.3: bob adds a local-only account that alice has never seen.
    let local_only = bob.add("local-only@example.test", "token-local-only");

    alice.remove(&doomed);
    alice.push(&repo).expect("alice push after deletion");

    bob.pull(&repo).expect("bob pull after deletion");

    // AC-3.1: the account is gone from bob's state.
    assert!(
        !bob.state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "deleted account survived the pull: {:?}",
        bob.emails()
    );
    // AC-3.1: and its credential material is not written back to disk. Only
    // the credential mutation lock may remain in the account directory.
    let leftovers = fs::read_dir(&doomed_dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name != ".sagy-credential.lock")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "deleted account still has credential files in {}: {leftovers:?}",
        doomed_dir.display()
    );

    // AC-3.3: bob's own accounts are untouched.
    assert!(bob.state.accounts.iter().any(|account| account.id == keep));
    assert!(
        bob.state
            .accounts
            .iter()
            .any(|account| account.id == local_only),
        "deletion propagation removed a local-only account"
    );

    // The deletion converges: a fresh machine never sees the removed account.
    let mut carol = Machine::new(temp.path(), "carol");
    carol.pull(&repo).expect("carol pull");
    assert_eq!(carol.emails(), vec!["keep@example.test".to_string()]);
}

// ---------------------------------------------------------------------------
// AC-4: one repository, many spellings, one pool.
// ---------------------------------------------------------------------------

#[test]
fn alternate_spellings_of_one_repository_share_a_pool() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("pool.git");
    let repo = init_bare_repo(&path);
    let with_slash = format!("{repo}/");
    let with_dot_segment = format!(
        "{}/./{}",
        path.parent().expect("parent").display(),
        path.file_name().expect("name").to_string_lossy()
    );

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("one@example.test", "token-one");
    alice.push(&repo).expect("push with the plain path");

    // AC-4.1: a different spelling of the same repository must still resolve
    // to the same pool in both directions.
    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&with_dot_segment)
        .expect("pull with an equivalent path spelling");
    assert_eq!(bob.emails(), vec!["one@example.test".to_string()]);

    bob.add("two@example.test", "token-two");
    bob.push(&with_slash).expect("push with a trailing slash");

    alice.pull(&repo).expect("alice pull");
    assert_eq!(
        alice.emails(),
        vec![
            "one@example.test".to_string(),
            "two@example.test".to_string()
        ]
    );
}

#[test]
fn a_different_repository_is_a_different_pool() {
    let temp = tempfile::tempdir().expect("tempdir");
    let first = init_bare_repo(&temp.path().join("first.git"));
    let second = init_bare_repo(&temp.path().join("second.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("one@example.test", "token-one");
    alice.push(&first).expect("push to the first repository");

    // Copy the bundle into an unrelated repository and make sure sagy refuses
    // to adopt it, with an actionable message (AC-4.2, AC-4.3).
    let seed = temp.path().join("seed");
    git(temp.path(), &["clone", &first, seed.to_str().unwrap()]);
    git(&seed, &["remote", "set-url", "origin", &second]);
    git(&seed, &["push", "origin", "HEAD"]);

    let mut bob = Machine::new(temp.path(), "bob");
    let error = bob
        .pull(&second)
        .expect_err("a foreign pool must be rejected");
    let text = format!("{error:#}");
    assert!(text.contains("different account pool"), "{text}");
    assert!(
        text.contains("Recovery"),
        "pool mismatch gives no recovery instructions: {text}"
    );
    assert!(
        text.contains("bundle.enc.json"),
        "pool mismatch does not name the file to remove: {text}"
    );
}

// ---------------------------------------------------------------------------
// AC-6: one broken account must not block the whole push.
// ---------------------------------------------------------------------------

#[test]
fn a_broken_credential_does_not_block_the_healthy_accounts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    let broken = alice.add("broken@example.test", "token-broken");
    alice.add("healthy@example.test", "token-healthy");

    // Simulate a lost or corrupt credential file for a single account.
    fs::remove_dir_all(alice.account_dir(&broken)).expect("break one credential");

    alice
        .push(&repo)
        .expect("push must survive one broken account");

    let mut carol = Machine::new(temp.path(), "carol");
    carol.pull(&repo).expect("carol pull");
    assert_eq!(carol.emails(), vec!["healthy@example.test".to_string()]);
}

#[test]
fn push_fails_with_reasons_when_nothing_can_be_exported() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    let only = alice.add("only@example.test", "token-only");
    fs::remove_dir_all(alice.account_dir(&only)).expect("break the only credential");

    let error = alice.push(&repo).expect_err("nothing to export");
    let text = format!("{error:#}");
    assert!(text.contains("no account could be exported"), "{text}");
    assert!(
        text.contains(&only) && text.contains("only@example.test"),
        "error does not name the failing account: {text}"
    );
    assert!(text.is_ascii(), "console output must be ASCII: {text}");
}

// ---------------------------------------------------------------------------
// AC-7: temp checkouts are reclaimed, the shared tmp root is not.
// ---------------------------------------------------------------------------

#[test]
fn stale_checkouts_are_reclaimed_and_the_tmp_root_survives() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("one@example.test", "token-one");
    alice.push(&repo).expect("seed push");

    // A SIGKILLed process leaves an unlocked checkout directory behind.
    let tmp_root = alice.dir.join("tmp");
    fs::create_dir_all(&tmp_root).expect("tmp root");
    let stale = tmp_root.join("repo-sync-00000000-0000-4000-8000-000000000000");
    fs::create_dir_all(stale.join("nested")).expect("stale checkout");
    fs::write(stale.join("nested").join("file"), b"leftover").expect("stale file");

    alice.sync_view(&repo);

    // AC-7.1
    assert!(
        !stale.exists(),
        "stale checkout {} was not reclaimed",
        stale.display()
    );
    // AC-7.3
    assert!(
        tmp_root.exists(),
        "the shared tmp root must not be removed by the cleanup path"
    );
}

// ---------------------------------------------------------------------------
// AC-8: the repository URL trust boundary has exactly one implementation.
// ---------------------------------------------------------------------------

#[test]
fn cli_and_adapter_share_one_repo_url_trust_boundary() {
    let rejected = [
        "https://alice:supersecret@example.test/pool.git",
        "ssh://alice:supersecret@example.test/pool.git",
        "https://example.test/pool.git?access_token=supersecret",
        "https://example.test/pool.git#supersecret",
        "HTTP://alice:supersecret@example.test/pool.git",
        "https://alice@example.test/pool.git",
        "",
    ];
    let accepted = [
        "https://example.test/user/pool.git",
        "ssh://git@example.test/user/pool.git",
        "git@github.com:user/pool.git",
        "/srv/pool.git",
    ];

    for (index, repo) in rejected.iter().enumerate() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join(format!("state-{index}"));
        fs::create_dir_all(&state_dir).expect("state dir");

        // AC-8.2: neither side may relax an existing rejection rule.
        assert!(
            validate_repo_source(repo).is_err(),
            "adapter accepted unsafe repository {repo:?}"
        );
        assert!(
            resolve_repo_sync_repo(&state_dir, Some(repo)).is_err(),
            "CLI accepted unsafe repository {repo:?}"
        );
        assert!(
            !state_dir.join("repo-sync.json").exists(),
            "unsafe repository {repo:?} was persisted"
        );
    }

    // AC-8.1: the two sides agree on every input, which only holds while they
    // call the same function.
    for repo in accepted {
        let temp = tempfile::tempdir().expect("tempdir");
        let state_dir = temp.path().join("state");
        assert!(
            validate_repo_source(repo).is_ok(),
            "adapter rejected safe repository {repo:?}"
        );
        assert_eq!(
            resolve_repo_sync_repo(&state_dir, Some(repo)).expect("safe repository"),
            repo
        );
    }
}

// ---------------------------------------------------------------------------
// R4-2: a pool deletion that lands on the local current account must not be
// silently undone.
// ---------------------------------------------------------------------------

/// Run the real `sagy` binary against one machine's state directory.
///
/// `use` 会发布 active home, 必须把 HOME / GEMINI_HOME 全部指到临时目录里,
/// 否则测试会写到开发者真实的 ~/.gemini。
fn run_sagy(state_dir: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sagy"));
    command
        .env("SAGY_POOL_KEY", "p1-repo-sync-pool-regression-key")
        .env("HOME", home)
        .env("ANTIGRAVITY_CONFIG_DIR", home.join("antigravity"))
        .env("GEMINI_HOME", home.join("gemini"))
        .env("GIT_AUTHOR_NAME", "sagy-test")
        .env("GIT_AUTHOR_EMAIL", "sagy-test@example.test")
        .env("GIT_COMMITTER_NAME", "sagy-test")
        .env("GIT_COMMITTER_EMAIL", "sagy-test@example.test")
        .arg("--state-dir")
        .arg(state_dir)
        .args(args);
    command.output().expect("sagy binary")
}

#[test]
fn a_pool_deletion_of_the_current_account_reaches_every_machine() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("keep@example.test", "token-keep");
    let doomed = alice.add("doomed@example.test", "token-doomed");
    alice.push(&repo).expect("alice push");

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");
    assert_eq!(bob.state.accounts.len(), 2);

    // Make the doomed account bob's current account through the real CLI.
    let bob_home = temp.path().join("bob-home");
    fs::create_dir_all(bob_home.join("gemini")).expect("bob gemini home");
    fs::create_dir_all(bob_home.join("antigravity")).expect("bob antigravity home");
    let selected = run_sagy(&bob.dir, &bob_home, &["use", "doomed@example.test"]);
    assert!(
        selected.status.success(),
        "sagy use failed: {}",
        String::from_utf8_lossy(&selected.stderr)
    );

    alice.remove(&doomed);
    alice.push(&repo).expect("alice push after deletion");

    // AC-R4-2.1: the deletion is unconditional; only the current pointer is
    // cleared. Releasing the active home needs the isolated homes, so this
    // pull runs through the binary as a user would.
    let applied = run_sagy(&bob.dir, &bob_home, &["pull", &repo]);
    assert!(
        applied.status.success(),
        "sagy pull failed: {}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let notice = String::from_utf8_lossy(&applied.stderr).into_owned();
    assert!(
        notice.contains("current account here"),
        "the deletion of the current account was not reported: {notice:?}"
    );
    assert!(
        notice.is_ascii(),
        "console output must be ASCII: {notice:?}"
    );
    bob.sync_view(&repo);
    assert!(
        !bob.state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "the pool deletion was undone because the account was current: {:?}",
        bob.emails()
    );
    assert_eq!(bob.state.current_account_id, None);
    assert!(bob.state.active_profile.is_none());

    // AC-R4-2.2: bob's own push must keep carrying the deletion record.
    bob.push(&repo).expect("bob push after the deletion landed");

    // AC-R4-2.3: a third, brand-new machine never sees the account.
    let mut carol = Machine::new(temp.path(), "carol");
    carol.pull(&repo).expect("carol pull");
    assert_eq!(
        carol.emails(),
        vec!["keep@example.test".to_string()],
        "a brand new machine still sees the account the pool deleted"
    );

    // And the deletion does not bounce back to the machine that made it.
    alice.pull(&repo).expect("alice pull");
    assert_eq!(alice.emails(), vec!["keep@example.test".to_string()]);
}

// ---------------------------------------------------------------------------
// R4-3: deletions must still commit when the local credential file is gone.
// ---------------------------------------------------------------------------

/// Delete the credential files while keeping the account directory.
///
/// 这正是"坏账号"现场: 目录还在, 凭据文件已经不见了。
fn remove_credential_files(account_dir: &Path) {
    let entries = fs::read_dir(account_dir).expect("account directory");
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".sagy-credential.lock" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path).expect("remove credential subdirectory");
        } else {
            fs::remove_file(&path).expect("remove credential file");
        }
    }
}

#[test]
fn a_deletion_commits_when_the_local_credential_file_is_already_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("keep@example.test", "token-keep");
    let doomed = alice.add("doomed@example.test", "token-doomed");
    alice.push(&repo).expect("alice push");

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");

    // The exact "broken account" situation: the credential files are gone, so
    // the delete stages nothing and produces no journal proof, while every
    // other account in the bundle is unchanged.
    remove_credential_files(&bob.account_dir(&doomed));

    alice.remove(&doomed);
    alice.push(&repo).expect("alice push after deletion");

    // AC-R4-3.1: this must commit, not hard-fail on a missing proof.
    bob.pull(&repo)
        .expect("a deletion without credential files must still commit");
    assert!(
        !bob.state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "the deletion did not reach local state: {:?}",
        bob.emails()
    );
    assert_eq!(bob.emails(), vec!["keep@example.test".to_string()]);

    // The state stays usable afterwards.
    bob.push(&repo).expect("push after the deletion");
}

// ---------------------------------------------------------------------------
// R4-4.2: the skipped-account report must reach the real stderr.
// ---------------------------------------------------------------------------

#[test]
fn skipped_accounts_are_reported_on_the_real_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    let broken = alice.add("broken@example.test", "token-broken");
    alice.add("healthy@example.test", "token-healthy");
    fs::remove_dir_all(alice.account_dir(&broken)).expect("break one credential");

    let home = temp.path().join("alice-home");
    fs::create_dir_all(home.join("gemini")).expect("alice gemini home");
    fs::create_dir_all(home.join("antigravity")).expect("alice antigravity home");
    let output = run_sagy(&alice.dir, &home, &["push", &repo]);
    assert!(
        output.status.success(),
        "push failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains("account(s) were skipped and not exported"),
        "push did not report the skipped account on stderr: {stderr:?}"
    );
    assert!(
        stderr.contains(&broken) && stderr.contains("broken@example.test"),
        "the skipped-account report does not name the account: {stderr:?}"
    );
    assert!(
        stderr.contains("missing or corrupt"),
        "the skipped-account report does not give a reason: {stderr:?}"
    );
    assert!(
        stderr.is_ascii(),
        "console output must be ASCII: {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// R10-1: an import and a broken-account deletion in the same pull.
// ---------------------------------------------------------------------------

#[test]
fn an_import_and_a_broken_account_deletion_commit_in_one_pull() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("keep@example.test", "token-keep");
    let doomed = alice.add("doomed@example.test", "token-doomed");
    alice.push(&repo).expect("alice push");

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");

    // bob's copy of the doomed account is the "broken account" shape: the
    // directory is there, the credential files are gone. Deleting it stages
    // nothing, so it can only be covered by a purge transaction.
    remove_credential_files(&bob.account_dir(&doomed));

    // The same alice session both adds and removes, so one pull carries an
    // import (which produces a proof) and a broken-account deletion (which
    // has no credential bytes to move).
    alice.remove(&doomed);
    let fresh = alice.add("fresh@example.test", "token-fresh");
    alice.push(&repo).expect("alice push after add + rm");

    // AC-R10-1.1: the mixed pull must commit.
    bob.pull(&repo)
        .expect("an import plus a broken-account deletion must commit in one pull");
    assert_eq!(
        bob.emails(),
        vec![
            "fresh@example.test".to_string(),
            "keep@example.test".to_string()
        ],
        "the mixed pull did not converge"
    );
    assert!(
        !bob.state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "the broken-account deletion did not reach local state"
    );
    // The import really landed on disk, not just in the state document.
    let fresh_reference = bob
        .state
        .credential_refs
        .get(&fresh)
        .expect("imported account has a credential reference");
    assert!(!fresh_reference.fingerprint.is_empty());
    let fresh_files = fs::read_dir(bob.account_dir(&fresh))
        .expect("imported account directory")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != ".sagy-credential.lock")
        .count();
    assert!(fresh_files > 0, "the import wrote no credential file");

    // And the deleted account leaves nothing behind.
    let leftovers = fs::read_dir(bob.account_dir(&doomed))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name != ".sagy-credential.lock")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "the purge left credential artifacts behind: {leftovers:?}"
    );

    // The state stays usable afterwards.
    bob.push(&repo).expect("push after the mixed pull");
}

// ---------------------------------------------------------------------------
// R10-2: the pool deleted an account that is both current here and broken.
//
// AC-R10-2.2 的三种组合:
//   current + 凭据完好  -> a_pool_deletion_of_the_current_account_reaches_every_machine
//   非 current + 凭据缺失 -> a_deletion_commits_when_the_local_credential_file_is_already_missing
//   current + 凭据缺失   -> 下面这个测试
// ---------------------------------------------------------------------------

#[test]
fn a_pool_deletion_of_a_broken_current_account_does_not_wedge_pull() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("keep@example.test", "token-keep");
    let doomed = alice.add("doomed@example.test", "token-doomed");
    alice.push(&repo).expect("alice push");

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");

    let bob_home = temp.path().join("bob-broken-home");
    fs::create_dir_all(bob_home.join("gemini")).expect("bob gemini home");
    fs::create_dir_all(bob_home.join("antigravity")).expect("bob antigravity home");
    let selected = run_sagy(&bob.dir, &bob_home, &["use", "doomed@example.test"]);
    assert!(
        selected.status.success(),
        "sagy use failed: {}",
        String::from_utf8_lossy(&selected.stderr)
    );

    // 账号被池子删除的典型原因: 凭据泄露后本机先手工删了文件。此时它既是
    // current account, 凭据文件又已经缺失。
    remove_credential_files(&bob.account_dir(&doomed));

    alice.remove(&doomed);
    alice.push(&repo).expect("alice push after deletion");

    // AC-R10-2.1: this machine must not be wedged; every later pull would
    // fail the same way otherwise.
    let applied = run_sagy(&bob.dir, &bob_home, &["pull", &repo]);
    let notice = String::from_utf8_lossy(&applied.stderr).into_owned();
    assert!(
        applied.status.success(),
        "pull is wedged on a broken current account: {notice}"
    );
    assert!(
        notice.contains("credential files are already missing"),
        "the recovery hint does not explain the situation: {notice:?}"
    );
    assert!(
        notice.contains("sagy use"),
        "the notice gives no recovery instruction: {notice:?}"
    );
    assert!(
        notice.is_ascii(),
        "console output must be ASCII: {notice:?}"
    );

    bob.sync_view(&repo);
    assert!(
        !bob.state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "the pool deletion never landed: {:?}",
        bob.emails()
    );
    assert_eq!(bob.state.current_account_id, None);
    assert!(bob.state.active_profile.is_none());
    assert_eq!(bob.emails(), vec!["keep@example.test".to_string()]);

    // A second pull must be a plain no-op, not a repeat of the failure.
    let again = run_sagy(&bob.dir, &bob_home, &["pull", &repo]);
    assert!(
        again.status.success(),
        "the follow-up pull failed: {}",
        String::from_utf8_lossy(&again.stderr)
    );
}

// ---------------------------------------------------------------------------
// R10-4: a machine that still holds the account is the only witness that can
// notice a dropped tombstone.
// ---------------------------------------------------------------------------

#[test]
fn a_relayed_push_keeps_the_tombstone_for_a_machine_that_still_holds_the_account() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = init_bare_repo(&temp.path().join("pool.git"));

    let mut alice = Machine::new(temp.path(), "alice");
    alice.add("keep@example.test", "token-keep");
    let doomed = alice.add("doomed@example.test", "token-doomed");
    alice.push(&repo).expect("alice push");

    // carol pulls first and then stops synchronizing: she still holds the
    // account and has never seen the deletion.
    let mut carol = Machine::new(temp.path(), "carol");
    carol.pull(&repo).expect("carol pull");
    assert!(
        carol
            .state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "carol did not receive the account she must later lose"
    );

    let mut bob = Machine::new(temp.path(), "bob");
    bob.pull(&repo).expect("bob pull");

    alice.remove(&doomed);
    alice.push(&repo).expect("alice push after deletion");

    // bob applies the deletion and then relays a push of his own. Everything
    // carol will ever see now comes from bob's bundle.
    bob.pull(&repo).expect("bob pull after deletion");
    bob.add("bob-only@example.test", "token-bob-only");
    bob.push(&repo).expect("bob relay push");

    // AC-R10-4.1: carol still holds the account, so she notices immediately
    // if bob's push dropped the tombstone.
    carol.pull(&repo).expect("carol pull after the relay push");
    assert!(
        !carol
            .state
            .accounts
            .iter()
            .any(|account| account.id == doomed),
        "the relayed push lost the tombstone: {:?}",
        carol.emails()
    );
    assert_eq!(
        carol.emails(),
        vec![
            "bob-only@example.test".to_string(),
            "keep@example.test".to_string()
        ]
    );
}
