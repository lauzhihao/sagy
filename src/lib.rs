pub mod adapters;
pub mod cli;
pub mod core;
#[cfg(target_os = "macos")]
mod profile;

pub fn main_entry() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{}", core::ui::format_top_level_error(&error));
            std::process::exit(1);
        }
    }
}

fn run() -> anyhow::Result<i32> {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    #[cfg(target_os = "macos")]
    if let Some(code) = profile::statusline_helper(&raw_args) {
        return Ok(code);
    }
    if adapters::antigravity::native_session::is_probe_invocation(&raw_args) {
        return Ok(adapters::antigravity::native_session::run_probe_helper());
    }
    // 使用调用名区分入口；旧 CLI 的 Keychain 子进程仍须先分派。
    let name = raw_args
        .first()
        .and_then(|arg| std::path::Path::new(arg).file_name());
    let named_profile = name == Some(std::ffi::OsStr::new("sagy-profile"))
        || (cfg!(windows) && name == Some(std::ffi::OsStr::new("sagy-profile.exe")));
    #[cfg(target_os = "macos")]
    {
        let shortcut = name == Some(std::ffi::OsStr::new("sagy"))
            && std::env::current_exe()?.canonicalize()?.file_name()
                == Some(std::ffi::OsStr::new("sagy-profile"));
        if shortcut || named_profile {
            return profile::run(&raw_args[1..], shortcut);
        }
    }
    #[cfg(not(target_os = "macos"))]
    if named_profile {
        anyhow::bail!("The native subscription profile launcher requires macOS.");
    }
    let cli = cli::Cli::parse_args();
    cli::run(cli)
}
