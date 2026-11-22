//! Session-only agy `--settings` merged at launch: color scheme and title command.
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use super::statusline::SessionBridge;
use super::store;
use crate::core::credential::StrictValue;

const COLOR_SCHEME_ENV: &str = "SAGY_COLOR_SCHEME";
const TITLE_HELPER: &str = "--sagy-title-helper";
const MAX_SETTINGS: usize = 256 * 1024;
const MAX_INPUT: usize = 256 * 1024;
const MAX_TITLE: usize = 256;

pub(super) fn configure(
    command: &mut Command,
    bridge: Option<&SessionBridge>,
    home: &Path,
) -> Result<()> {
    configure_with(
        command,
        bridge.map(SessionBridge::settings_json),
        home,
        color_scheme_from_env(),
    )
}

fn configure_with(
    command: &mut Command,
    bridge_settings: Option<&str>,
    home: &Path,
    color_scheme: Option<&str>,
) -> Result<()> {
    let mut settings = match bridge_settings {
        Some(settings) => serde_json::from_str(settings)
            .context("Could not read the live status line settings.")?,
        None => json!({}),
    };
    let fields = settings
        .as_object_mut()
        .context("Session settings must be an object.")?;
    if let Some(scheme) = color_scheme {
        fields.insert("colorScheme".into(), Value::String(scheme.to_owned()));
    }
    if !title_already_configured(home)? {
        fields.insert("title".into(), default_title_block()?);
    }
    if fields.is_empty() {
        return Ok(());
    }
    command.args([
        "--settings",
        &serde_json::to_string(&settings).context("Could not write session settings.")?,
    ]);
    Ok(())
}

fn color_scheme_from_env() -> Option<&'static str> {
    match std::env::var(COLOR_SCHEME_ENV)
        .ok()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "light" => Some("light"),
        "dark" => Some("dark"),
        _ => None,
    }
}

fn title_already_configured(home: &Path) -> Result<bool> {
    Ok(existing_title(home)?
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|command| !command.trim().is_empty()))
}

fn existing_title(home: &Path) -> Result<Value> {
    let file = match store::open_private_file(
        &home.join(".gemini/antigravity-cli/settings.json"),
        false,
    ) {
        Ok(file) => file,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::NotFound) =>
        {
            return Ok(Value::Null);
        }
        Err(error) => return Err(error),
    };
    let StrictValue(settings) =
        serde_json::from_slice::<StrictValue>(&bounded_read(file, MAX_SETTINGS)?)
            .context("Could not read the existing title settings.")?;
    Ok(settings.get("title").cloned().unwrap_or(Value::Null))
}

fn default_title_block() -> Result<Value> {
    let command = format!(
        "{} {TITLE_HELPER}",
        shell_quote(std::env::current_exe()?.as_os_str())?
    );
    Ok(json!({
        "type": "command",
        "command": command,
        "enabled": true,
    }))
}

fn shell_quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("Title helper paths must be UTF-8.")?;
    Ok(format!("'{}'", value.replace('\'', r"'\''")))
}

fn bounded_read(reader: impl std::io::Read, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .context("Could not read the title helper input.")?;
    if bytes.len() > limit {
        bail!("Title helper input is too large.");
    }
    Ok(bytes)
}

pub(crate) fn helper_invocation(args: &[OsString]) -> Option<i32> {
    if args.get(1) != Some(&OsString::from(TITLE_HELPER)) {
        return None;
    }
    Some(match print_title() {
        Ok(()) => 0,
        Err(_) => 1,
    })
}

fn print_title() -> Result<()> {
    let raw = bounded_read(std::io::stdin().lock(), MAX_INPUT)?;
    let title = title_from_state(&raw);
    if title.is_empty() {
        return Ok(());
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(title.as_bytes())?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn title_from_state(raw: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(raw) else {
        return String::new();
    };
    conversation_title(&value).unwrap_or_default()
}

fn conversation_title(value: &Value) -> Option<String> {
    value
        .get("conversation_title")
        .and_then(Value::as_str)
        .map(sanitize_title)
        .filter(|title| !title.is_empty())
}

fn sanitize_title(title: &str) -> String {
    title
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_TITLE)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Resolve an intent title outside AGY's sandbox: prefer a generated
/// conversation title from statusline stdin, then the annotation or metadata
/// title AGY writes after intent extraction. Do not use the first user sentence.
pub(super) fn intent_title_for_conversation(
    home: &Path,
    conversation_id: &str,
    conversation_title: Option<&str>,
) -> String {
    if let Some(title) = conversation_title
        .map(sanitize_title)
        .filter(|title| !title.is_empty())
    {
        return title;
    }
    if !conversation_id_is_safe(conversation_id) {
        return String::new();
    }
    generated_title(home, conversation_id).unwrap_or_default()
}

fn generated_title(home: &Path, conversation_id: &str) -> Option<String> {
    annotation_title(home, conversation_id).or_else(|| metadata_title(home, conversation_id))
}

fn annotation_title(home: &Path, conversation_id: &str) -> Option<String> {
    let path = home
        .join(".gemini/antigravity-cli/annotations")
        .join(format!("{conversation_id}.pbtxt"));
    let raw = read_text_prefix(&path, 64 * 1024)?;
    parse_annotation_title(&raw)
}

fn parse_annotation_title(raw: &str) -> Option<String> {
    let rest = raw.trim_start().strip_prefix("title:")?.trim_start();
    let mut chars = rest.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut title = String::new();
    loop {
        match chars.next()? {
            character if character == quote => break,
            '\\' => match chars.next()? {
                'n' => title.push('\n'),
                't' => title.push('\t'),
                'r' => title.push('\r'),
                character => title.push(character),
            },
            character => title.push(character),
        }
    }
    let title = sanitize_title(&title);
    if title.is_empty() { None } else { Some(title) }
}

fn metadata_title(home: &Path, conversation_id: &str) -> Option<String> {
    let path = home.join(".gemini/antigravity-cli/cache/conversation_metadata.json");
    let raw = read_text_prefix(&path, 8 * 1024 * 1024)?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    value
        .pointer(&format!("/conversations/{conversation_id}/summary/Title"))
        .and_then(Value::as_str)
        .map(sanitize_title)
        .filter(|title| !title.is_empty())
}

fn read_text_prefix(path: &Path, max: usize) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut raw = Vec::new();
    file.take(max as u64).read_to_end(&mut raw).ok()?;
    String::from_utf8(raw).ok()
}

fn conversation_id_is_safe(conversation_id: &str) -> bool {
    !conversation_id.is_empty()
        && conversation_id.len() <= 128
        && conversation_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })
}

/// Atomically publish a non-empty title to an absolute path the parent process can write.
pub(super) fn publish_intent_title(path: &Path, title: &str) -> Result<()> {
    if !path.is_absolute() || title.is_empty() {
        return Ok(());
    }
    let Some(parent) = path.parent().filter(|parent| parent.is_dir()) else {
        return Ok(());
    };
    if fs::read_to_string(path).ok().as_deref().map(str::trim) == Some(title) {
        return Ok(());
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".agy-title-")
        .tempfile_in(parent)
        .context("create a temporary title file")?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .context("set title file permissions")?;
    temporary
        .write_all(title.as_bytes())
        .and_then(|_| temporary.write_all(b"\n"))
        .context("write title file")?;
    temporary.as_file().sync_all().context("sync title file")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("publish title file")?;
    Ok(())
}

pub(super) const TITLE_FILE_ENV: &str = "SAGY_TITLE_FILE";

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn settings_args(command: &Command) -> Option<Value> {
        let mut arguments = command.get_args();
        (arguments.next()? == "--settings")
            .then(|| arguments.next())
            .flatten()
            .and_then(|value| value.to_str())
            .and_then(|value| serde_json::from_str(value).ok())
    }

    fn empty_home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn home_with_title(command: &str) -> tempfile::TempDir {
        use std::io::Write as _;
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join(".gemini/antigravity-cli");
        fs::create_dir_all(&directory).unwrap();
        let mut file = store::open_private_file(&directory.join("settings.json"), true).unwrap();
        file.write_all(
            &serde_json::to_vec(&json!({
                "title": {"type": "command", "command": command, "enabled": true}
            }))
            .unwrap(),
        )
        .unwrap();
        home
    }

    #[test]
    fn a_light_or_dark_scheme_is_injected_into_session_settings() {
        let home = empty_home();
        for scheme in ["light", "dark"] {
            let mut command = Command::new("agy");
            configure_with(&mut command, None, home.path(), Some(scheme)).unwrap();
            let settings = settings_args(&command).unwrap();
            assert_eq!(settings["colorScheme"], scheme);
            assert_eq!(settings["title"]["type"], "command");
            assert_eq!(settings["title"]["enabled"], true);
            assert!(
                settings["title"]["command"]
                    .as_str()
                    .is_some_and(|command| command.contains(TITLE_HELPER))
            );
        }
    }

    #[test]
    fn an_unknown_scheme_is_ignored() {
        let home = empty_home();
        let mut command = Command::new("agy");
        configure_with(&mut command, None, home.path(), None).unwrap();
        let settings = settings_args(&command).unwrap();
        assert!(settings.get("colorScheme").is_none());
        assert!(settings.get("title").is_some());
    }

    #[test]
    fn an_existing_title_command_is_left_in_place() {
        let home = home_with_title("/usr/bin/true");
        let mut command = Command::new("agy");
        configure_with(&mut command, None, home.path(), Some("light")).unwrap();
        let settings = settings_args(&command).unwrap();
        assert_eq!(settings["colorScheme"], "light");
        assert!(settings.get("title").is_none());
    }

    #[test]
    fn status_line_settings_are_kept_when_merging() {
        let home = empty_home();
        let bridge_settings = serde_json::to_string(&json!({
            "statusLine": {"type": "command", "command": "true", "enabled": true}
        }))
        .unwrap();
        let mut command = Command::new("agy");
        configure_with(
            &mut command,
            Some(bridge_settings.as_str()),
            home.path(),
            Some("dark"),
        )
        .unwrap();
        let settings = settings_args(&command).unwrap();
        assert_eq!(settings["colorScheme"], "dark");
        assert_eq!(settings["statusLine"]["command"], "true");
        assert_eq!(settings["title"]["enabled"], true);
    }

    #[test]
    fn the_title_helper_prefers_the_conversation_title() {
        assert_eq!(
            title_from_state(
                br#"{"conversation_title":"Explain the factorial function","cwd":"/tmp/demo"}"#
            ),
            "Explain the factorial function"
        );
    }

    #[test]
    fn the_title_helper_waits_when_the_conversation_has_no_title_yet() {
        assert_eq!(
            title_from_state(br#"{"cwd":"/Users/liuzhihao/Documents/knowledge-base"}"#),
            ""
        );
        assert_eq!(
            title_from_state(br#"{"workspace":{"project_dir":"/tmp/my-project"}}"#),
            ""
        );
        assert_eq!(title_from_state(br#"{"conversation_title":"  "}"#), "");
        assert_eq!(title_from_state(b"not-json"), "");
    }

    #[test]
    fn the_title_helper_ignores_the_first_user_message_until_a_generated_title_exists() {
        let payload = serde_json::json!({
            "cwd": "/tmp/knowledge-base",
            "transcript_path": "/tmp/transcript.jsonl",
        });
        assert_eq!(title_from_state(payload.to_string().as_bytes()), "");
        let named = serde_json::json!({
            "conversation_title": "Fix login timeouts",
            "transcript_path": "/tmp/transcript.jsonl",
        });
        assert_eq!(
            title_from_state(named.to_string().as_bytes()),
            "Fix login timeouts"
        );
    }

    #[test]
    fn the_title_helper_strips_control_characters() {
        assert_eq!(
            title_from_state(b"{\"conversation_title\":\"Hello\\u0007 World\"}"),
            "Hello World"
        );
    }

    #[test]
    fn intent_title_for_conversation_reads_generated_titles_under_the_profile_home() {
        let home = tempfile::tempdir().unwrap();
        let conversation = "83a2c81e-507b-48b8-ad2e-d174a5337518";
        let transcript = home
            .path()
            .join(".gemini/antigravity-cli/brain")
            .join(conversation)
            .join(".system_generated/logs/transcript.jsonl");
        fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        fs::write(
            &transcript,
            r#"{"type":"USER_INPUT","content":"<USER_REQUEST>\nhi\n</USER_REQUEST>"}"#,
        )
        .unwrap();
        assert_eq!(
            intent_title_for_conversation(home.path(), conversation, None),
            ""
        );

        let annotations = home
            .path()
            .join(".gemini/antigravity-cli/annotations")
            .join(format!("{conversation}.pbtxt"));
        fs::create_dir_all(annotations.parent().unwrap()).unwrap();
        fs::write(&annotations, "title:\"Casual Greeting\"\n").unwrap();
        assert_eq!(
            intent_title_for_conversation(home.path(), conversation, None),
            "Casual Greeting"
        );

        let other = "e7a1caf6-e408-4039-b7e9-b8fd1a92bfea";
        let metadata = home
            .path()
            .join(".gemini/antigravity-cli/cache/conversation_metadata.json");
        fs::create_dir_all(metadata.parent().unwrap()).unwrap();
        fs::write(
            &metadata,
            r#"{"conversations":{"e7a1caf6-e408-4039-b7e9-b8fd1a92bfea":{"summary":{"Title":"涂鸦面板小程序知识与代码库","Preview":"帮我找一下涂鸦面板小程序相关的知识库和代码库"}}}}"#,
        )
        .unwrap();
        assert_eq!(
            intent_title_for_conversation(home.path(), other, None),
            "涂鸦面板小程序知识与代码库"
        );
        assert_eq!(
            parse_annotation_title(
                "title:\"涂鸦面板小程序知识与代码库\"  last_user_view_time:{seconds:1}"
            )
            .as_deref(),
            Some("涂鸦面板小程序知识与代码库")
        );
        assert_eq!(
            intent_title_for_conversation(home.path(), conversation, Some("Network latency check")),
            "Network latency check"
        );
        assert_eq!(
            intent_title_for_conversation(home.path(), "../secret", None),
            ""
        );
    }

    #[test]
    fn publish_intent_title_writes_an_absolute_path_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agy-title");
        publish_intent_title(&path, "hi").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "hi");
        publish_intent_title(Path::new("agy-title"), "nope").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "hi");
        publish_intent_title(&path, "").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "hi");
    }
}
