//! Windows smoke tests for first-write, repeated-save, and replacement paths.

#[cfg(windows)]
mod windows_runtime {
    use sagy::core::state::{AccountRecord, State};
    use sagy::core::storage;

    #[test]
    fn first_and_repeated_state_save_and_file_replace_work() {
        let temp = tempfile::tempdir().expect("temp directory");
        let state_dir = temp.path().join("state");

        let mut state = State::default();
        storage::save_state(&state_dir, &state).expect("first state save");

        state.accounts.push(AccountRecord {
            id: "repeat-save".to_string(),
            email: "repeat@example.com".to_string(),
            ..Default::default()
        });
        state.current_account_id = Some("repeat-save".to_string());
        storage::save_state(&state_dir, &state).expect("repeated state save");
        assert_eq!(
            storage::load_state(&state_dir)
                .expect("load repeated state")
                .current_account_id
                .as_deref(),
            Some("repeat-save")
        );

        let replaced = state_dir.join("replace.txt");
        storage::write_file_atomically(&replaced, b"first").expect("first file write");
        storage::write_file_atomically(&replaced, b"second").expect("repeated file replace");
        assert_eq!(
            std::fs::read(replaced).expect("read replaced file"),
            b"second"
        );
    }
}
