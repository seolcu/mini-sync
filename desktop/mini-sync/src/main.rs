use clap::{Parser, Subcommand};
use mini_sync_common::{
    config::{Config, PairedDevice},
    identity::Identity,
    paths,
};
use qrcode::QrCode;
use rand::RngCore;
use serde::Serialize;
use std::env;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        device_name: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        no_qr: bool,
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
            addr,
            port,
            device_name,
            json,
            no_qr,
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
            } else if let Err(err) =
                print_pairing_payload(addr, port, device_name, json, no_qr)
            {
                eprintln!("pair_error: {}", err);
                std::process::exit(1);
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

#[derive(Serialize)]
struct PairingPayload {
    version: u8,
    device_id: String,
    device_name: String,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    addr: Option<String>,
    port: u16,
    token: String,
    code: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    capabilities: Vec<String>,
}

fn print_pairing_payload(
    addr: Option<String>,
    port_override: Option<u16>,
    device_name: Option<String>,
    json_only: bool,
    no_qr: bool,
) -> Result<(), String> {
    let identity_path = paths::identity_file();
    let identity = Identity::load_or_generate(&identity_path)
        .map_err(|err| format!("identity_load_failed: {}", err))?;
    let config = load_config_or_default(&paths::config_file())?;
    let port = port_override.unwrap_or(config.listen_port);
    let device_name = device_name
        .or_else(|| config.device_name.clone())
        .unwrap_or_else(default_device_name);

    let created_at_ms = now_ms();
    let expires_at_ms = created_at_ms.saturating_add(PAIR_TOKEN_TTL_MS);
    let payload = PairingPayload {
        version: 1,
        device_id: identity.device_id,
        device_name,
        public_key: identity.public_key,
        addr,
        port,
        token: random_token(),
        code: random_code(),
        created_at_ms,
        expires_at_ms,
        capabilities: vec!["clipboard".to_string(), "file".to_string()],
    };

    let json_compact =
        serde_json::to_string(&payload).map_err(|err| format!("json_error: {}", err))?;
    if json_only {
        println!("{}", json_compact);
        return Ok(());
    }

    let json_pretty =
        serde_json::to_string_pretty(&payload).map_err(|err| format!("json_error: {}", err))?;
    println!("pair_code: {}", payload.code);
    println!("pair_token: {}", payload.token);
    println!("expires_at_ms: {}", payload.expires_at_ms);
    println!("payload_json:\n{}", json_pretty);

    if !no_qr {
        println!("qr:");
        print_qr(&json_compact)?;
    }

    Ok(())
}

fn print_qr(data: &str) -> Result<(), String> {
    let code = QrCode::new(data.as_bytes())
        .map_err(|err| format!("qr_encode_failed: {}", err))?;
    let rendered = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .dark_color('#')
        .light_color(' ')
        .build();
    println!("{}", rendered);
    Ok(())
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn random_code() -> String {
    let mut bytes = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let value = u32::from_le_bytes(bytes) % 1_000_000;
    format!("{:06}", value)
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
    let identity_path = paths::identity_file();
    println!("identity_path: {}", identity_path.display());
    print_identity(identity_path, true);

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
    println!("identity_path: {}", paths::identity_file().display());

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
    println!(
        "device_name: {}",
        config
            .device_name
            .as_deref()
            .unwrap_or("unset")
    );
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

fn default_device_name() -> String {
    env::var("MINI_SYNC_DEVICE_NAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "mini-sync".to_string())
}

const PAIR_TOKEN_TTL_MS: u64 = 180_000;

fn print_identity(identity_path: PathBuf, create_if_missing: bool) {
    if create_if_missing {
        match Identity::load_or_generate(&identity_path) {
            Ok(identity) => {
                println!("device_id: {}", identity.device_id);
                println!("public_key: {}", identity.public_key);
            }
            Err(err) => {
                eprintln!("identity_error: {}", err);
            }
        }
        return;
    }

    match Identity::load_optional(&identity_path) {
        Ok(Some(identity)) => {
            println!("device_id: {}", identity.device_id);
            println!("public_key: {}", identity.public_key);
        }
        Ok(None) => {
            println!("identity_status: missing");
        }
        Err(err) => {
            eprintln!("identity_error: {}", err);
        }
    }
}
