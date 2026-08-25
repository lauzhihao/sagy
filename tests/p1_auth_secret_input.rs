#[test]
fn auth_source_has_no_plaintext_terminal_input_or_legacy_backup() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/adapters/antigravity/auth.rs"
    ))
    .expect("read auth source");

    // Build the forbidden token without embedding it in the source under test.
    let plaintext_read_line = ["read_", "line"].concat();
    assert!(!source.contains(&plaintext_read_line));
    assert!(!source.contains("oauth_creds.json.bak"));
}
