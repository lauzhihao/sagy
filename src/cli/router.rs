use std::ffi::OsString;
use std::path::PathBuf;

use super::help::is_known_subcmd;

/// argv 在进入 clap 或 agy 前的最小路由结果。
///
/// 只有显式支持的 global prefix 会被这里消费；其余 token 必须保持原样，
/// 这样 agy 的 option value 不会因为恰好等于 sagy 命令名而被误路由。
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    Clap(Vec<OsString>),
    Passthrough {
        state_dir: Option<PathBuf>,
        args: Vec<OsString>,
    },
}

const ROOT_HELP_FLAGS: [&str; 2] = ["-h", "--help"];
const ROOT_VERSION_FLAGS: [&str; 2] = ["-V", "--version"];
const LAUNCH_SHORTCUT_FLAGS: [&str; 4] = [
    "--dry-run",
    "--no-resume",
    "--no-launch",
    "--no-import-known",
];

/// 根据固定的 sagy global prefix 决定交给 clap 还是直接交给 agy。
///
/// 路由只看 prefix 后的第一个 token。遇到未知 option、裸 prompt 或 `--`
/// 后，剩余 argv 都是 agy passthrough，绝不继续扫描其中的 token。
pub fn route(raw_args: &[OsString]) -> Route {
    let program = raw_args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("sagy"));
    let mut clap_prefix = vec![program];
    let mut state_dir = None;
    let mut launch_shortcuts = Vec::new();
    let mut index = 1;

    while let Some(arg) = raw_args.get(index) {
        let text = arg.to_string_lossy();

        if text == "--state-dir" {
            clap_prefix.push(arg.clone());
            let Some(value) = raw_args.get(index + 1) else {
                // 让 clap 负责生成标准的 missing value 错误。
                return Route::Clap(raw_args.to_vec());
            };
            clap_prefix.push(value.clone());
            state_dir = Some(PathBuf::from(value));
            index += 2;
            continue;
        }

        if let Some(value) = text.strip_prefix("--state-dir=") {
            clap_prefix.push(arg.clone());
            state_dir = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        if ROOT_HELP_FLAGS.contains(&text.as_ref()) || ROOT_VERSION_FLAGS.contains(&text.as_ref()) {
            // 根级 help/version 是 prefix 语义；后续 token 不应影响其输出。
            clap_prefix.push(arg.clone());
            return Route::Clap(clap_prefix);
        }

        if LAUNCH_SHORTCUT_FLAGS.contains(&text.as_ref()) {
            launch_shortcuts.push(arg.clone());
            index += 1;
            continue;
        }

        break;
    }

    if !launch_shortcuts.is_empty() {
        let mut clap_args = clap_prefix;
        clap_args.push(OsString::from("launch"));
        clap_args.extend(launch_shortcuts);
        let remaining = raw_args.get(index..).unwrap_or_default();
        if !remaining.is_empty() {
            clap_args.push(OsString::from("--"));
            if remaining.first().is_some_and(|arg| arg == "--") {
                clap_args.extend_from_slice(&remaining[1..]);
            } else {
                clap_args.extend_from_slice(remaining);
            }
        }
        return Route::Clap(clap_args);
    }

    let Some(first) = raw_args.get(index) else {
        return Route::Clap(clap_prefix);
    };

    if first == "--" {
        return Route::Passthrough {
            state_dir,
            args: raw_args.get(index + 1..).unwrap_or_default().to_vec(),
        };
    }

    if is_known_subcmd(&first.to_string_lossy()) {
        let mut clap_args = clap_prefix;
        clap_args.extend_from_slice(&raw_args[index..]);
        return Route::Clap(clap_args);
    }

    Route::Passthrough {
        state_dir,
        args: raw_args[index..].to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn routes_known_command_after_state_dir_to_clap() {
        assert!(matches!(
            route(&args(&["sagy", "--state-dir", "/tmp/state", "list"])),
            Route::Clap(_)
        ));
        assert!(matches!(
            route(&args(&["sagy", "--state-dir=/tmp/state", "upgrade"])),
            Route::Clap(_)
        ));
        assert!(matches!(
            route(&args(&["sagy", "help", "launch"])),
            Route::Clap(_)
        ));
    }

    #[test]
    fn routes_unknown_option_and_all_values_as_one_passthrough() {
        let routed = route(&args(&["sagy", "--model", "custom", "list"]));
        assert_eq!(
            routed,
            Route::Passthrough {
                state_dir: None,
                args: args(&["--model", "custom", "list"]),
            }
        );

        let routed = route(&args(&["sagy", "--prompt", "list"]));
        assert_eq!(
            routed,
            Route::Passthrough {
                state_dir: None,
                args: args(&["--prompt", "list"]),
            }
        );
    }

    #[test]
    fn rewrites_reserved_launch_shortcuts_without_inspecting_passthrough() {
        assert_eq!(
            route(&args(&[
                "sagy",
                "--state-dir",
                "/tmp/state",
                "--no-resume",
                "--no-import-known",
                "--prompt",
                "list",
            ])),
            Route::Clap(args(&[
                "sagy",
                "--state-dir",
                "/tmp/state",
                "launch",
                "--no-resume",
                "--no-import-known",
                "--",
                "--prompt",
                "list",
            ]))
        );
        assert_eq!(
            route(&args(&["sagy", "--dry-run"])),
            Route::Clap(args(&["sagy", "launch", "--dry-run"]))
        );
        assert_eq!(
            route(&args(&["sagy", "--no-resume", "--", "--help"])),
            Route::Clap(args(&["sagy", "launch", "--no-resume", "--", "--help",]))
        );
    }

    #[test]
    fn routes_delimiter_without_inspecting_following_tokens() {
        let routed = route(&args(&["sagy", "--", "--help", "list"]));
        assert_eq!(
            routed,
            Route::Passthrough {
                state_dir: None,
                args: args(&["--help", "list"]),
            }
        );
    }

    #[test]
    fn root_help_and_version_only_use_prefix() {
        assert_eq!(
            route(&args(&[
                "sagy",
                "--state-dir",
                "/tmp/state",
                "--help",
                "list"
            ])),
            Route::Clap(args(&["sagy", "--state-dir", "/tmp/state", "--help"]))
        );
        assert_eq!(
            route(&args(&["sagy", "-V", "--prompt", "list"])),
            Route::Clap(args(&["sagy", "-V"]))
        );
    }
}
