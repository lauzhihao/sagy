pub mod adapters;
pub mod cli;
pub mod core;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod profile;

pub fn main_entry() {
    finish(run())
}

pub fn legacy_main_entry() {
    finish(run_legacy())
}

fn finish(result: anyhow::Result<i32>) {
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{}", core::ui::format_top_level_error(&error));
            std::process::exit(1);
        }
    }
}

fn run_legacy() -> anyhow::Result<i32> {
    if adapters::antigravity::native_session::is_probe_invocation(
        &std::env::args_os().collect::<Vec<_>>(),
    ) {
        return Ok(adapters::antigravity::native_session::run_probe_helper());
    }
    cli::run(cli::Cli::parse_args())
}

fn run() -> anyhow::Result<i32> {
    let raw_args = std::env::args_os().collect::<Vec<_>>();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(code) = profile::statusline_helper(&raw_args) {
        return Ok(code);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(code) = profile::title_helper(&raw_args) {
        return Ok(code);
    }
    if adapters::antigravity::native_session::is_probe_invocation(&raw_args) {
        return Ok(adapters::antigravity::native_session::run_probe_helper());
    }
    // 使用调用名区分新原生入口与显式保留的可携带账号池入口。
    let name = raw_args
        .first()
        .and_then(|arg| std::path::Path::new(arg).file_name());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let legacy_entry = name == Some(std::ffi::OsStr::new("sagy-legacy"));
    let named_profile = name == Some(std::ffi::OsStr::new("sagy-profile"))
        || (cfg!(windows) && name == Some(std::ffi::OsStr::new("sagy-profile.exe")));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if !legacy_entry {
        let shortcut = !named_profile;
        return profile::run(&raw_args[1..], shortcut);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    if named_profile {
        anyhow::bail!("The native subscription profile launcher requires macOS or Linux.");
    }
    let cli = cli::Cli::parse_args();
    cli::run(cli)
}
