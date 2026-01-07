use clap::Parser;
use mini_sync_common::{config::Config, paths};

#[derive(Parser)]
#[command(name = "mini-syncd", version, about = "mini-sync daemon (stub)")]
struct Args {}

fn main() {
    let _args = Args::parse();
    let config_path = paths::config_file();
    println!("config_path: {}", config_path.display());
    match Config::load_optional(&config_path) {
        Ok(Some(_config)) => println!("config_status: loaded"),
        Ok(None) => println!("config_status: missing (defaults)"),
        Err(err) => eprintln!("config_error: {}", err),
    }
    println!("mini-syncd stub: daemon not implemented yet");
}
