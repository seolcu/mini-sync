use clap::{Parser, Subcommand};
use mini_sync_common::{config::Config, paths};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mini-sync", version, about = "Minimal PC <-> Android sync CLI")]
#[command(subcommand_required = true, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Devices,
    Pair,
    Unpair {
        device: String,
    },
    Send {
        device: String,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    Clipboard {
        #[command(subcommand)]
        command: ClipboardCommand,
    },
    Config,
}

#[derive(Subcommand)]
enum ClipboardCommand {
    Push { device: String },
    Watch { device: String },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Status => print_status(),
        Command::Devices => print_devices(),
        Command::Pair => print_stub("pair"),
        Command::Unpair { device } => {
            println!("unpair {}: not implemented yet", device);
        }
        Command::Send { device, paths } => {
            println!(
                "send to {}: {} item(s) (stub)",
                device,
                paths.len()
            );
        }
        Command::Clipboard { command } => match command {
            ClipboardCommand::Push { device } => {
                println!("clipboard push to {}: not implemented yet", device);
            }
            ClipboardCommand::Watch { device } => {
                println!("clipboard watch for {}: not implemented yet", device);
            }
        },
        Command::Config => print_config(),
    }
}

fn print_stub(action: &str) {
    println!("{}: not implemented yet", action);
}

fn print_status() {
    let config_path = paths::config_file();
    println!("config_path: {}", config_path.display());

    match Config::load_optional(&config_path) {
        Ok(Some(config)) => {
            print_config_summary(&config);
            println!("config_status: loaded");
        }
        Ok(None) => {
            let config = Config::default();
            print_config_summary(&config);
            println!("config_status: missing (defaults)");
        }
        Err(err) => {
            eprintln!("config_error: {}", err);
            println!("config_status: error");
        }
    }

    println!("daemon_status: stub");
}

fn print_devices() {
    let config_path = paths::config_file();
    match Config::load_optional(&config_path) {
        Ok(Some(config)) => {
            if config.paired_devices.is_empty() {
                println!("paired_devices: none");
            } else {
                for device in config.paired_devices {
                    let name = device.device_name.unwrap_or_else(|| "unknown".to_string());
                    println!("{} {}", device.device_id, name);
                }
            }
        }
        Ok(None) => {
            println!("paired_devices: none");
        }
        Err(err) => {
            eprintln!("config_error: {}", err);
        }
    }
}

fn print_config() {
    let config_path = paths::config_file();
    println!("config_path: {}", config_path.display());
    println!("state_dir: {}", paths::state_dir().display());
    println!("log_dir: {}", paths::log_dir().display());

    match Config::load_optional(&config_path) {
        Ok(Some(config)) => {
            print_config_summary(&config);
            println!("config_status: loaded");
        }
        Ok(None) => {
            let config = Config::default();
            print_config_summary(&config);
            println!("config_status: missing (defaults)");
        }
        Err(err) => {
            eprintln!("config_error: {}", err);
            println!("config_status: error");
        }
    }
}

fn print_config_summary(config: &Config) {
    println!("listen_port: {}", config.listen_port);
    println!("download_dir: {}", config.download_dir.display());
    println!("clipboard.watch: {}", config.clipboard.watch);
    println!("paired_devices: {}", config.paired_devices.len());
}
