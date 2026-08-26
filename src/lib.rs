pub mod adapters;
pub mod cli;
pub mod core;

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
    if adapters::antigravity::native_session::is_probe_invocation(&raw_args) {
        return Ok(adapters::antigravity::native_session::run_probe_helper());
    }
    let cli = cli::Cli::parse_args();
    cli::run(cli)
}
