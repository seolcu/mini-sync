use clap::{Parser, Subcommand};
use mini_sync_common::{
    config::{Config, PairedDevice},
    identity::Identity,
    pairing::PairingSession,
    paths,
};
use qrcode::QrCode;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        #[arg(long)]
        no_store: bool,
    },
    PairRequest {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        code: Option<String>,
        #[arg(long)]
        sender_device_id: Option<String>,
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long)]
        device_name: Option<String>,
        #[arg(long)]
        timeout_secs: Option<u64>,
    },
    Ping {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        timeout_secs: Option<u64>,
    },
    Hello {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        device_name: Option<String>,
        #[arg(long, value_delimiter = ',')]
        capabilities: Option<Vec<String>>,
        #[arg(long)]
        timeout_secs: Option<u64>,
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
            no_store,
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
                print_pairing_payload(addr, port, device_name, json, no_qr, no_store)
            {
                eprintln!("pair_error: {}", err);
                std::process::exit(1);
            }
        }
        Command::PairRequest {
            addr,
            port,
            token,
            code,
            sender_device_id,
            pubkey,
            device_name,
            timeout_secs,
        } => {
            if let Err(err) = send_pair_request(
                addr,
                port,
                token,
                code,
                sender_device_id,
                pubkey,
                device_name,
                timeout_secs,
            ) {
                eprintln!("pair_request_error: {}", err);
                std::process::exit(1);
            }
        }
        Command::Ping {
            addr,
            port,
            device_id,
            timeout_secs,
        } => {
            if let Err(err) = send_ping(addr, port, device_id, timeout_secs) {
                eprintln!("ping_error: {}", err);
                std::process::exit(1);
            }
        }
        Command::Hello {
            addr,
            port,
            device_id,
            device_name,
            capabilities,
            timeout_secs,
        } => {
            if let Err(err) = send_hello(
                addr,
                port,
                device_id,
                device_name,
                capabilities,
                timeout_secs,
            ) {
                eprintln!("hello_error: {}", err);
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

fn print_pairing_payload(
    addr: Option<String>,
    port_override: Option<u16>,
    device_name: Option<String>,
    json_only: bool,
    no_qr: bool,
    no_store: bool,
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
    let payload = PairingSession {
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

    if !no_store {
        let pairing_path = paths::pairing_file();
        payload
            .save(&pairing_path)
            .map_err(|err| format!("pairing_save_failed: {}", err))?;
        println!("pairing_path: {}", pairing_path.display());
    }

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
    let pairing_path = paths::pairing_file();
    println!("pairing_path: {}", pairing_path.display());
    print_pairing_status(&pairing_path);

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
    println!("pairing_path: {}", paths::pairing_file().display());

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

fn print_pairing_status(pairing_path: &Path) {
    match PairingSession::load_optional(pairing_path) {
        Ok(Some(session)) => {
            let now = now_ms();
            if session.is_expired(now) {
                println!("pairing_status: expired");
            } else {
                println!("pairing_status: active");
                println!("pairing_expires_at_ms: {}", session.expires_at_ms);
            }
        }
        Ok(None) => println!("pairing_status: none"),
        Err(err) => eprintln!("pairing_error: {}", err),
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

#[derive(Serialize)]
struct PairRequestMessage {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    token: String,
    code: String,
    pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
}

#[derive(Serialize)]
struct PingMessage {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
}

#[derive(Serialize)]
struct HelloMessage {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    device_name: String,
    capabilities: Vec<String>,
}

#[derive(Deserialize)]
struct ResponseBase {
    msg_type: String,
    reason: Option<String>,
}

fn send_pair_request(
    addr: Option<String>,
    port_override: Option<u16>,
    token: Option<String>,
    code: Option<String>,
    sender_device_id: Option<String>,
    pubkey: Option<String>,
    device_name: Option<String>,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let config = load_config_or_default(&paths::config_file())?;
    let pairing = PairingSession::load_optional(&paths::pairing_file())
        .map_err(|err| format!("pairing_load_failed: {}", err))?;
    let identity = Identity::load_or_generate(&paths::identity_file())
        .map_err(|err| format!("identity_load_failed: {}", err))?;

    let port = port_override
        .or_else(|| pairing.as_ref().map(|session| session.port))
        .unwrap_or(config.listen_port);
    let addr = addr
        .or_else(|| pairing.as_ref().and_then(|session| session.addr.clone()))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let token = token
        .or_else(|| pairing.as_ref().map(|session| session.token.clone()))
        .ok_or_else(|| "missing token (use --token or create pairing session)".to_string())?;
    let code = code
        .or_else(|| pairing.as_ref().map(|session| session.code.clone()))
        .ok_or_else(|| "missing code (use --code or create pairing session)".to_string())?;
    let sender_device_id = sender_device_id.unwrap_or_else(|| identity.device_id.clone());
    let pubkey = pubkey.unwrap_or(identity.public_key);
    let device_name = device_name
        .or_else(|| config.device_name.clone())
        .or_else(|| Some(default_device_name()));

    let message = PairRequestMessage {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id,
        timestamp_ms: now_ms(),
        msg_type: "PAIR_REQUEST".to_string(),
        token,
        code,
        pubkey,
        device_name,
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;

    let target = format!("{}:{}", addr, port);
    let response = send_line_request(
        &target,
        &payload,
        timeout_secs.unwrap_or(REQUEST_TIMEOUT_SECS),
    )?;
    println!("{}", response);
    Ok(())
}

fn send_ping(
    addr: Option<String>,
    port_override: Option<u16>,
    device_id: Option<String>,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let config = load_config_or_default(&paths::config_file())?;
    let identity = Identity::load_or_generate(&paths::identity_file())
        .map_err(|err| format!("identity_load_failed: {}", err))?;
    let sender_device_id = device_id.unwrap_or(identity.device_id);
    let port = port_override.unwrap_or(config.listen_port);
    let addr = addr.unwrap_or_else(|| "127.0.0.1".to_string());

    let message = PingMessage {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id,
        timestamp_ms: now_ms(),
        msg_type: "PING".to_string(),
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;
    let target = format!("{}:{}", addr, port);
    let response = send_line_request(
        &target,
        &payload,
        timeout_secs.unwrap_or(REQUEST_TIMEOUT_SECS),
    )?;
    print_control_response(&response);
    Ok(())
}

fn send_hello(
    addr: Option<String>,
    port_override: Option<u16>,
    device_id: Option<String>,
    device_name: Option<String>,
    capabilities: Option<Vec<String>>,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let config = load_config_or_default(&paths::config_file())?;
    let identity = Identity::load_or_generate(&paths::identity_file())
        .map_err(|err| format!("identity_load_failed: {}", err))?;
    let sender_device_id = device_id.unwrap_or(identity.device_id);
    let port = port_override.unwrap_or(config.listen_port);
    let addr = addr.unwrap_or_else(|| "127.0.0.1".to_string());
    let device_name = device_name
        .or_else(|| config.device_name.clone())
        .unwrap_or_else(default_device_name);
    let capabilities = capabilities.unwrap_or_else(default_capabilities);

    let message = HelloMessage {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id,
        timestamp_ms: now_ms(),
        msg_type: "HELLO".to_string(),
        device_name,
        capabilities,
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;
    let target = format!("{}:{}", addr, port);
    let response = send_line_request(
        &target,
        &payload,
        timeout_secs.unwrap_or(REQUEST_TIMEOUT_SECS),
    )?;
    print_control_response(&response);
    Ok(())
}

fn send_line_request(target: &str, payload: &str, timeout_secs: u64) -> Result<String, String> {
    let mut stream = TcpStream::connect(target).map_err(|err| format!("connect_failed: {}", err))?;
    let timeout = Duration::from_secs(timeout_secs);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("timeout_failed: {}", err))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("timeout_failed: {}", err))?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|err| format!("write_failed: {}", err))?;
    stream
        .write_all(b"\n")
        .map_err(|err| format!("write_failed: {}", err))?;

    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader
        .read_line(&mut response)
        .map_err(|err| format!("read_failed: {}", err))?;
    Ok(response.trim().to_string())
}

fn print_control_response(response: &str) {
    match serde_json::from_str::<ResponseBase>(response) {
        Ok(parsed) if parsed.msg_type == "PONG" => {
            println!("pong: ok");
        }
        Ok(parsed) if parsed.msg_type == "PAIR_REJECT" => {
            if let Some(reason) = parsed.reason {
                println!("reject: {}", reason);
            } else {
                println!("reject");
            }
        }
        _ => println!("{}", response),
    }
}

fn default_capabilities() -> Vec<String> {
    vec!["clipboard".to_string(), "file".to_string()]
}

const REQUEST_TIMEOUT_SECS: u64 = 10;

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
