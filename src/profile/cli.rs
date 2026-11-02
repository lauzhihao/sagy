//! 原生 profile CLI 的帮助、兼容入口和参数解析。
use std::ffi::OsString;

use anyhow::{Result, bail};

const COMMANDS: &[(&str, &str)] = &[
    (
        "login",
        "sagy login NAME\nAdd or authorize a subscription profile.",
    ),
    (
        "run",
        "sagy run NAME [agy arguments...]\nOpen a profile and pass arguments to agy.",
    ),
    (
        "use",
        "sagy use NAME|INDEX [agy arguments...]\nOpen a profile selected by label or list index.",
    ),
    (
        "auto",
        "sagy auto [agy arguments...]\nChoose an available profile and start agy.",
    ),
    ("list", "sagy list\nShow local profiles and cached quota."),
    (
        "refresh",
        "sagy refresh [--strict] [NAME]\nRefresh quota for idle profiles.",
    ),
    (
        "push",
        "sagy push [REPO] [options]\nPush encrypted native profiles.",
    ),
    (
        "pull",
        "sagy pull [REPO] [options]\nImport missing native profiles.",
    ),
    (
        "rm",
        "sagy rm NAME\nArchive a profile and remove it from the local account pool.",
    ),
];

/// 打印可从入口、子命令或 `help NAME` 请求的帮助，并在完成后返回。
pub(super) fn help_or_version(args: &[OsString]) -> Option<i32> {
    if args.is_empty() {
        return None;
    }
    let action = args[0].to_str()?;
    if matches!(action, "--version" | "-V") && args.len() == 1 {
        println!("sagy {}", env!("CARGO_PKG_VERSION"));
        return Some(0);
    }
    if matches!(action, "help" | "-h" | "--help") {
        if args.len() == 1 || (args.len() == 2 && matches!(args[1].to_str(), Some("-h" | "--help")))
        {
            print_root_help();
            return Some(0);
        }
        if args.len() == 2 {
            return print_command_help(args[1].to_str()?);
        }
    }
    let rest = &args[1..];
    let help = rest.len() == 1 && matches!(rest[0].to_str(), Some("-h" | "--help"));
    if help {
        return print_command_help(action);
    }
    None
}

pub(super) fn print_root_help() {
    eprintln!(
        "Usage:\n  sagy                         Start auto with Gemini 3.8 Flash High and auto-approved tools\n  sagy -p PROMPT [options]     Print one response with those defaults\n  sagy --print PROMPT [options] Print one response with those defaults\n  sagy-profile <COMMAND>       Manage native subscription profiles\n\nCommands:"
    );
    for (name, usage) in COMMANDS {
        let summary = usage.lines().nth(1).unwrap_or_default();
        eprintln!("  {name:8} {summary}");
    }
    eprintln!("\nRun `sagy help COMMAND` or `sagy COMMAND --help` for details.");
}

fn print_command_help(command: &str) -> Option<i32> {
    if matches!(command, "push" | "pull") {
        return super::repo_sync::help(command == "push", &[OsString::from("--help")]);
    }
    if let Some((_, usage)) = COMMANDS.iter().find(|(name, _)| *name == command) {
        eprintln!("{usage}");
        if command == "rm" {
            eprintln!(
                "NAME is an exact profile label or email address. Numeric labels are literal."
            );
            eprintln!("The profile home and login data are moved into a private local archive.");
        }
        if command == "refresh" {
            eprintln!("--strict exits nonzero if any requested quota probe is incomplete.");
        }
        Some(0)
    } else {
        None
    }
}

/// 判断 `sagy` 快捷入口的选项前缀中是否启用了 print 模式。
pub(super) fn is_print_invocation(args: &[OsString]) -> bool {
    let mut index = 0;
    while let Some(argument) = args.get(index).and_then(|arg| arg.to_str()) {
        if argument == "--" || !argument.starts_with('-') {
            return false;
        }
        if matches!(argument, "-p" | "--print" | "--prompt")
            || argument.starts_with("--print=")
            || argument.starts_with("--prompt=")
        {
            return true;
        }
        let (flag, has_inline_value) = argument
            .split_once('=')
            .map_or((argument, false), |(flag, _)| (flag, true));
        let flag = flag.trim_start_matches('-');
        if has_inline_value {
            index += 1;
            continue;
        }
        if super::quota::takes_value(flag) {
            index += 2;
            if index > args.len() {
                return false;
            }
            continue;
        }
        if takes_no_value(flag) {
            index += 1;
            continue;
        }
        return false;
    }
    false
}

fn takes_no_value(flag: &str) -> bool {
    matches!(
        flag,
        "c" | "continue"
            | "dangerously-skip-permissions"
            | "disable-slash-commands"
            | "new-project"
            | "remote-control"
            | "sandbox"
    )
}

/// 解析严格刷新选项，接受严格标记和单个名称的任意顺序。
pub(super) fn refresh_options(args: &[OsString]) -> Result<(bool, Option<OsString>)> {
    let mut strict = false;
    let mut name = None;
    let mut options_ended = false;
    for argument in args {
        if !options_ended && argument == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && argument == "--strict" {
            if strict {
                bail!("--strict may only be provided once.");
            }
            strict = true;
            continue;
        }
        if !options_ended && argument.to_str().is_some_and(|arg| arg.starts_with('-')) {
            bail!("Unknown refresh option. Run sagy refresh --help.");
        }
        if name.replace(argument.clone()).is_some() {
            bail!("Refresh accepts at most one profile name.");
        }
    }
    Ok((strict, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn help_and_version_are_recognized_before_account_lookup() {
        assert_eq!(help_or_version(&args(&["--version"])), Some(0));
        for command in ["login", "run", "use", "auto", "list", "refresh", "rm"] {
            assert_eq!(
                help_or_version(&args(&["help", command])),
                Some(0),
                "{command}"
            );
            assert_eq!(
                help_or_version(&args(&[command, "--help"])),
                Some(0),
                "{command}"
            );
        }
        assert_eq!(help_or_version(&args(&["help", "push"])), Some(0));
        assert_eq!(help_or_version(&args(&["push", "--help"])), Some(0));
        assert_eq!(help_or_version(&args(&["run"])), None);
        assert_eq!(help_or_version(&args(&["rm"])), None);
        assert_eq!(help_or_version(&args(&["run", "account", "--help"])), None);
        assert_eq!(help_or_version(&args(&["use", "1", "--help"])), None);
    }

    #[test]
    fn print_shortcut_scans_options_without_mistaking_option_values() {
        assert!(is_print_invocation(&args(&[
            "--model", "gemini", "--print", "hello"
        ])));
        assert!(is_print_invocation(&args(&[
            "--dangerously-skip-permissions",
            "--print=hello"
        ])));
        assert!(is_print_invocation(&args(&[
            "--model=gemini",
            "-p",
            "hello"
        ])));
        assert!(!is_print_invocation(&args(&[
            "--model", "--print", "hello"
        ])));
        assert!(!is_print_invocation(&args(&["--", "--print", "hello"])));
        assert!(!is_print_invocation(&args(&["hello", "--print"])));
    }

    #[test]
    fn strict_refresh_flag_accepts_either_order() {
        assert_eq!(
            refresh_options(&args(&["--strict", "alice"])).unwrap(),
            (true, Some("alice".into()))
        );
        assert_eq!(
            refresh_options(&args(&["alice", "--strict"])).unwrap(),
            (true, Some("alice".into()))
        );
        assert_eq!(
            refresh_options(&args(&["--", "--strict"])).unwrap(),
            (false, Some("--strict".into()))
        );
        assert!(refresh_options(&args(&["alice", "bob"])).is_err());
    }
}
