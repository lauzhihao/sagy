//! First-write, repeated-save, and replacement smoke tests for the state document.
//!
//! 这些用例原来只在 Windows 上编译, 而且打的是已经没有任何生产调用方的
//! `storage::save_state` / `load_state` / `write_file_atomically`。现在改为驱动
//! 真实二进制走生产写路径, 并且在所有平台上运行——"重复保存必须整体替换而不是
//! 追加/截断"这条约束在 Windows 上最容易破, 但在哪个平台上都必须成立。

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

fn run_list(state_dir: &Path, home: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sagy"))
        .env("HOME", home)
        .env("SAGY_HOME", state_dir)
        .env("ANTIGRAVITY_CONFIG_DIR", home.join("antigravity"))
        .env("GEMINI_HOME", home.join("gemini"))
        .args([
            "--state-dir",
            state_dir.to_str().expect("UTF-8 state path"),
            "list",
        ])
        .output()
        .expect("run sagy")
}

fn read_state(state_dir: &Path) -> Value {
    let bytes = fs::read(state_dir.join("state.json")).expect("read state document");
    serde_json::from_slice(&bytes).expect("state document must stay valid JSON")
}

#[test]
fn first_and_repeated_state_save_and_file_replace_work() {
    let temp = tempfile::tempdir().expect("temp directory");
    let home = temp.path().join("home");
    fs::create_dir_all(&home).expect("create isolated home");

    // 首次写入: state root 还不存在, 生产路径必须自己把它建出来并落盘一份 v2 文档。
    let fresh = temp.path().join("fresh-state");
    let output = run_list(&fresh, &home);
    assert!(
        output.status.success(),
        "first run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = read_state(&fresh);
    assert_eq!(document["version"], 2);

    // 重复保存: 同一份文档被反复替换, 每一次都必须是完整的、可读回的文档,
    // 而不是被追加或截断出来的残片。
    let reused = temp.path().join("reused-state");
    fs::create_dir_all(&reused).expect("create state dir");
    fs::write(
        reused.join("state.json"),
        br#"{"accounts":[{"id":"repeat-save","email":"repeat@example.com","account_type":"oauth","oauth_token":"repeat-token"}]}"#,
    )
    .expect("write legacy state fixture");

    let mut revisions = Vec::new();
    for attempt in 0..3 {
        let output = run_list(&reused, &home);
        assert!(
            output.status.success(),
            "run {attempt} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document = read_state(&reused);
        assert_eq!(
            document["version"], 2,
            "run {attempt} wrote a foreign schema"
        );
        assert_eq!(
            document["accounts"][0]["id"], "repeat-save",
            "run {attempt} lost the account"
        );
        revisions.push(
            document["revision"]
                .as_u64()
                .expect("revision must be an integer"),
        );
    }
    assert!(
        revisions.windows(2).all(|pair| pair[1] > pair[0]),
        "repeated saves did not advance the revision: {revisions:?}"
    );

    // 替换必须是原子的: 不允许留下临时文件, 也不允许把文档变成目录/链接。
    let leftovers: Vec<String> = fs::read_dir(&reused)
        .expect("enumerate state root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp") || name.starts_with("state.json.corrupt-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "atomic replace left artifacts behind: {leftovers:?}"
    );
    assert!(
        fs::symlink_metadata(reused.join("state.json"))
            .expect("inspect state document")
            .is_file(),
        "state.json is no longer a regular file"
    );
}
