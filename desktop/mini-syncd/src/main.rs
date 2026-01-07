use clap::Parser;
use mini_sync_common::{config::Config, identity::Identity, paths};

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
    let identity_path = paths::identity_file();
    println!("identity_path: {}", identity_path.display());
    match Identity::load_or_generate(&identity_path) {
        Ok(identity) => {
            println!("device_id: {}", identity.device_id);
            println!("public_key: {}", identity.public_key);
        }
        Err(err) => {
            eprintln!("identity_error: {}", err);
        }
    }
    println!("mini-syncd stub: daemon not implemented yet");
}
