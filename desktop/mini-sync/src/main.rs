use clap::{Parser, Subcommand};
use mini_sync_common::{
    config::{Config, PairedDevice},
    paths,
};
use std::path::{Path, PathBuf};

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
    Pair {
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        last_seen_ms: Option<u64>,
    },
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
        Command::Pair {
            device_id,
            pubkey,
            name,
            last_seen_ms,
        } => {
            if let Some(device_id) = device_id {
                if let Err(err) = upsert_device(
                    &device_id,
                    pubkey,
                    name,
                    last_seen_ms,
                    &paths::config_file(),
                ) {
                    eprintln!("pair_error: {}", err);
                    std::process::exit(1);
                }
            } else {
                print_stub("pair");
            }
        }
        Command::Unpair { device } => {
            if let Err(err) = remove_device(&device, &paths::config_file()) {
                eprintln!("unpair_error: {}", err);
                std::process::exit(1);
            }
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

fn upsert_device(
    device_id: &str,
    pubkey: Option<String>,
    name: Option<String>,
    last_seen_ms: Option<u64>,
    config_path: &Path,
) -> Result<(), String> {
    let mut config = load_config_or_default(config_path)?;
    let mut updated = false;

    if let Some(existing) = config
        .paired_devices
        .iter_mut()
        .find(|device| device.device_id == device_id)
    {
        if let Some(pubkey) = pubkey {
            existing.pubkey = pubkey;
        }
        if name.is_some() {
            existing.device_name = name;
        }
        if last_seen_ms.is_some() {
            existing.last_seen_ms = last_seen_ms;
        }
        updated = true;
    } else {
        let pubkey = pubkey.ok_or_else(|| "missing --pubkey for new device".to_string())?;
        config.paired_devices.push(PairedDevice {
            device_id: device_id.to_string(),
            device_name: name,
            pubkey,
            last_seen_ms,
        });
    }

    config
        .save(config_path)
        .map_err(|err| format!("config_save_failed: {}", err))?;

    if updated {
        println!("pair: updated {}", device_id);
    } else {
        println!("pair: added {}", device_id);
    }
    Ok(())
}

fn remove_device(device_id: &str, config_path: &Path) -> Result<(), String> {
    let mut config = load_config_or_default(config_path)?;
    let before = config.paired_devices.len();
    config.paired_devices.retain(|device| device.device_id != device_id);
    if config.paired_devices.len() == before {
        return Err(format!("device_not_found: {}", device_id));
    }
    config
        .save(config_path)
        .map_err(|err| format!("config_save_failed: {}", err))?;
    println!("unpair: removed {}", device_id);
    Ok(())
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
                    let last_seen = device
                        .last_seen_ms
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    println!("{}\t{}\t{}", device.device_id, name, last_seen);
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

fn load_config_or_default(config_path: &Path) -> Result<Config, String> {
    match Config::load_optional(config_path) {
        Ok(Some(config)) => Ok(config),
        Ok(None) => Ok(Config::default()),
        Err(err) => Err(format!("config_load_failed: {}", err)),
    }
}
