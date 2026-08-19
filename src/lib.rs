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
    let cli = cli::Cli::parse_args();
    cli::run(cli)
}
