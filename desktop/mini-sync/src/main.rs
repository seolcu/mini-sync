use clap::{Parser, Subcommand};
use mini_sync_common::{
    config::{Config, PairedDevice},
    discovery::DiscoveryState,
    identity::Identity,
    pairing::PairingSession,
    paths,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use qrcode::QrCode;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use snow::Builder;
use std::collections::HashSet;
use std::env;
use std::io::{Read, Write};
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
    Devices {
        #[arg(long)]
        available: bool,
        #[arg(long)]
        all: bool,
    },
    Pair {
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        pubkey: Option<String>,
        #[arg(long)]
        dh_pubkey: Option<String>,
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
        dh_pubkey: Option<String>,
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
        device: Option<String>,
        #[arg(long)]
        peer_dh_pubkey: Option<String>,
        #[arg(long)]
        secure: bool,
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
        device: Option<String>,
        #[arg(long)]
        peer_dh_pubkey: Option<String>,
        #[arg(long)]
        secure: bool,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        device_name: Option<String>,
        #[arg(long, value_delimiter = ',')]
        capabilities: Option<Vec<String>>,
        #[arg(long)]
        timeout_secs: Option<u64>,
    },
    DaemonStatus {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        device: Option<String>,
        #[arg(long)]
        peer_dh_pubkey: Option<String>,
        #[arg(long)]
        secure: bool,
        #[arg(long)]
        include_discovery: bool,
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
        Command::Devices { available, all } => print_devices(available, all),
        Command::Pair {
            device_id,
            pubkey,
            dh_pubkey,
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
                    dh_pubkey,
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
            dh_pubkey,
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
                dh_pubkey,
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
            device,
            peer_dh_pubkey,
            secure,
            device_id,
            timeout_secs,
        } => {
            if let Err(err) = send_ping(
                addr,
                port,
                device,
                peer_dh_pubkey,
                secure,
                device_id,
                timeout_secs,
            ) {
                eprintln!("ping_error: {}", err);
                std::process::exit(1);
            }
        }
        Command::Hello {
            addr,
            port,
            device,
            peer_dh_pubkey,
            secure,
            device_id,
            device_name,
            capabilities,
            timeout_secs,
        } => {
            if let Err(err) = send_hello(
                addr,
                port,
                device,
                peer_dh_pubkey,
                secure,
                device_id,
                device_name,
                capabilities,
                timeout_secs,
            ) {
                eprintln!("hello_error: {}", err);
                std::process::exit(1);
            }
        }
        Command::DaemonStatus {
            addr,
            port,
            device,
            peer_dh_pubkey,
            secure,
            include_discovery,
            timeout_secs,
        } => {
            if let Err(err) = send_daemon_status(
                addr,
                port,
                device,
                peer_dh_pubkey,
                secure,
                include_discovery,
                timeout_secs,
            ) {
                eprintln!("daemon_status_error: {}", err);
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
        dh_public_key: identity.dh_public_key.clone(),
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
    dh_pubkey: Option<String>,
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
        if dh_pubkey.is_some() {
            existing.dh_pubkey = dh_pubkey;
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
            dh_pubkey,
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
    let discovery_path = paths::discovery_file();
    println!("discovery_path: {}", discovery_path.display());

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

fn print_devices(show_available: bool, show_all: bool) {
    let config_path = paths::config_file();
    let config = match Config::load_optional(&config_path) {
        Ok(Some(config)) => {
            config
        }
        Ok(None) => {
            Config::default()
        }
        Err(err) => {
            eprintln!("config_error: {}", err);
            return;
        }
    };

    if !show_available && !show_all {
        print_paired_devices(&config, false);
        return;
    }

    let paired_ids: HashSet<String> = config
        .paired_devices
        .iter()
        .map(|device| device.device_id.clone())
        .collect();

    let discovery_path = paths::discovery_file();
    let discovery = match DiscoveryState::load_optional(&discovery_path) {
        Ok(Some(mut state)) => {
            let now = now_ms();
            state.prune_expired(now, DISCOVERY_TTL_MS);
            Some(state)
        }
        Ok(None) => None,
        Err(err) => {
            eprintln!("discovery_error: {}", err);
            None
        }
    };

    if show_all {
        print_paired_devices(&config, true);
        print_available_devices(&discovery, &paired_ids);
        return;
    }

    print_available_devices(&discovery, &paired_ids);
}

fn print_config() {
    let config_path = paths::config_file();
    println!("config_path: {}", config_path.display());
    println!("state_dir: {}", paths::state_dir().display());
    println!("log_dir: {}", paths::log_dir().display());
    println!("identity_path: {}", paths::identity_file().display());
    println!("pairing_path: {}", paths::pairing_file().display());
    println!("discovery_path: {}", paths::discovery_file().display());

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

fn print_paired_devices(config: &Config, include_prefix: bool) {
    if config.paired_devices.is_empty() {
        println!("paired_devices: none");
        return;
    }
    for device in &config.paired_devices {
        let name = device.device_name.clone().unwrap_or_else(|| "unknown".to_string());
        let last_seen = device
            .last_seen_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        if include_prefix {
            println!("paired\t{}\t{}\t{}", device.device_id, name, last_seen);
        } else {
            println!("{}\t{}\t{}", device.device_id, name, last_seen);
        }
    }
}

fn print_available_devices(
    discovery: &Option<DiscoveryState>,
    paired_ids: &HashSet<String>,
) {
    let Some(state) = discovery else {
        println!("available_devices: none");
        return;
    };
    let mut printed = false;
    for device in &state.devices {
        if paired_ids.contains(&device.device_id) {
            continue;
        }
        let name = device
            .device_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let last_seen = device.last_seen_ms.to_string();
        let addr = if device.addresses.is_empty() {
            "-".to_string()
        } else {
            device.addresses.join(",")
        };
        let caps = if device.capabilities.is_empty() {
            "-".to_string()
        } else {
            device.capabilities.join(",")
        };
        println!(
            "available\t{}\t{}\t{}\t{}\t{}",
            device.device_id, name, last_seen, addr, caps
        );
        printed = true;
    }
    if !printed {
        println!("available_devices: none");
    }
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
    dh_pubkey: Option<String>,
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

#[derive(Serialize)]
struct StatusRequest {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    include_discovery: bool,
}

#[derive(Deserialize)]
struct StatusResponse {
    msg_type: String,
    paired_devices: Vec<StatusPairedDevice>,
    #[serde(default)]
    available_devices: Option<Vec<StatusAvailableDevice>>,
}

#[derive(Deserialize)]
struct StatusPairedDevice {
    device_id: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    last_seen_ms: Option<u64>,
}

#[derive(Deserialize)]
struct StatusAvailableDevice {
    device_id: String,
    #[serde(default)]
    device_name: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    addresses: Vec<String>,
    port: u16,
    last_seen_ms: u64,
}

#[derive(Deserialize)]
struct ResponseBase {
    msg_type: String,
    reason: Option<String>,
}

#[derive(Serialize)]
struct SecureInit {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    payload: String,
}

#[derive(Deserialize)]
struct SecureAccept {
    msg_type: String,
    payload: String,
}

#[derive(Deserialize)]
struct SecureReject {
    msg_type: String,
    reason: String,
}

#[derive(Serialize, Deserialize)]
struct SecurePacket {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    payload: String,
}

fn send_pair_request(
    addr: Option<String>,
    port_override: Option<u16>,
    token: Option<String>,
    code: Option<String>,
    sender_device_id: Option<String>,
    pubkey: Option<String>,
    dh_pubkey: Option<String>,
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
    let dh_pubkey = dh_pubkey.or_else(|| identity.dh_public_key.clone());
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
        dh_pubkey,
        device_name,
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;

    let target = format!("{}:{}", addr, port);
    let response = send_plain_request(
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
    device: Option<String>,
    peer_dh_pubkey: Option<String>,
    secure: bool,
    device_id: Option<String>,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let config = load_config_or_default(&paths::config_file())?;
    let identity = Identity::load_or_generate(&paths::identity_file())
        .map_err(|err| format!("identity_load_failed: {}", err))?;
    let sender_device_id = device_id.unwrap_or_else(|| identity.device_id.clone());
    let port = port_override.unwrap_or(config.listen_port);
    let addr = addr.unwrap_or_else(|| "127.0.0.1".to_string());

    let message = PingMessage {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id: sender_device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "PING".to_string(),
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;
    let target = format!("{}:{}", addr, port);
    let peer_dh_pubkey = resolve_peer_dh_pubkey(&config, device, peer_dh_pubkey)?;
    let response = send_control_request(
        &target,
        &payload,
        timeout_secs.unwrap_or(REQUEST_TIMEOUT_SECS),
        secure,
        &identity,
        &sender_device_id,
        peer_dh_pubkey,
    )?;
    print_control_response(&response);
    Ok(())
}

fn send_hello(
    addr: Option<String>,
    port_override: Option<u16>,
    device: Option<String>,
    peer_dh_pubkey: Option<String>,
    secure: bool,
    device_id: Option<String>,
    device_name: Option<String>,
    capabilities: Option<Vec<String>>,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let config = load_config_or_default(&paths::config_file())?;
    let identity = Identity::load_or_generate(&paths::identity_file())
        .map_err(|err| format!("identity_load_failed: {}", err))?;
    let sender_device_id = device_id.unwrap_or_else(|| identity.device_id.clone());
    let port = port_override.unwrap_or(config.listen_port);
    let addr = addr.unwrap_or_else(|| "127.0.0.1".to_string());
    let device_name = device_name
        .or_else(|| config.device_name.clone())
        .unwrap_or_else(default_device_name);
    let capabilities = capabilities.unwrap_or_else(default_capabilities);

    let message = HelloMessage {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id: sender_device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "HELLO".to_string(),
        device_name,
        capabilities,
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;
    let target = format!("{}:{}", addr, port);
    let peer_dh_pubkey = resolve_peer_dh_pubkey(&config, device, peer_dh_pubkey)?;
    let response = send_control_request(
        &target,
        &payload,
        timeout_secs.unwrap_or(REQUEST_TIMEOUT_SECS),
        secure,
        &identity,
        &sender_device_id,
        peer_dh_pubkey,
    )?;
    print_control_response(&response);
    Ok(())
}

fn send_daemon_status(
    addr: Option<String>,
    port_override: Option<u16>,
    device: Option<String>,
    peer_dh_pubkey: Option<String>,
    secure: bool,
    include_discovery: bool,
    timeout_secs: Option<u64>,
) -> Result<(), String> {
    let config = load_config_or_default(&paths::config_file())?;
    let identity = Identity::load_or_generate(&paths::identity_file())
        .map_err(|err| format!("identity_load_failed: {}", err))?;
    let sender_device_id = identity.device_id.clone();
    let port = port_override.unwrap_or(config.listen_port);
    let addr = addr.unwrap_or_else(|| "127.0.0.1".to_string());

    let message = StatusRequest {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id: sender_device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "STATUS_REQUEST".to_string(),
        include_discovery,
    };
    let payload =
        serde_json::to_string(&message).map_err(|err| format!("json_error: {}", err))?;
    let target = format!("{}:{}", addr, port);
    let peer_dh_pubkey = resolve_peer_dh_pubkey(&config, device, peer_dh_pubkey)?;
    let response = send_control_request(
        &target,
        &payload,
        timeout_secs.unwrap_or(REQUEST_TIMEOUT_SECS),
        secure,
        &identity,
        &sender_device_id,
        peer_dh_pubkey,
    )?;

    let status: StatusResponse =
        serde_json::from_str(&response).map_err(|err| format!("json_error: {}", err))?;
    if status.msg_type != "STATUS_RESPONSE" {
        println!("{}", response);
        return Ok(());
    }
    for device in status.paired_devices {
        let name = device.device_name.unwrap_or_else(|| "unknown".to_string());
        let last_seen = device
            .last_seen_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!("paired\t{}\t{}\t{}", device.device_id, name, last_seen);
    }
    if let Some(available) = status.available_devices {
        if available.is_empty() {
            println!("available_devices: none");
        } else {
            for device in available {
                let name = device.device_name.unwrap_or_else(|| "unknown".to_string());
                let addr = if device.addresses.is_empty() {
                    "-".to_string()
                } else {
                    device.addresses.join(",")
                };
                let caps = if device.capabilities.is_empty() {
                    "-".to_string()
                } else {
                    device.capabilities.join(",")
                };
                println!(
                    "available\t{}\t{}\t{}\t{}:{}\t{}",
                    device.device_id, name, device.last_seen_ms, addr, device.port, caps
                );
            }
        }
    }
    Ok(())
}

fn send_control_request(
    target: &str,
    payload: &str,
    timeout_secs: u64,
    secure: bool,
    identity: &Identity,
    sender_device_id: &str,
    peer_dh_pubkey: Option<String>,
) -> Result<String, String> {
    if secure {
        let peer_dh_pubkey = peer_dh_pubkey.ok_or_else(|| {
            "missing peer dh pubkey (use --device or --peer-dh-pubkey)".to_string()
        })?;
        send_secure_request(
            target,
            payload,
            timeout_secs,
            identity,
            sender_device_id,
            &peer_dh_pubkey,
        )
    } else {
        send_plain_request(target, payload, timeout_secs)
    }
}

fn resolve_peer_dh_pubkey(
    config: &Config,
    device: Option<String>,
    peer_dh_pubkey: Option<String>,
) -> Result<Option<String>, String> {
    if let Some(value) = peer_dh_pubkey {
        return Ok(Some(value));
    }
    let Some(device_id) = device else {
        return Ok(None);
    };
    let Some(device) = config
        .paired_devices
        .iter()
        .find(|entry| entry.device_id == device_id)
    else {
        return Err(format!("device_not_paired: {}", device_id));
    };
    Ok(device.dh_pubkey.clone())
}

fn send_plain_request(target: &str, payload: &str, timeout_secs: u64) -> Result<String, String> {
    let mut stream = TcpStream::connect(target).map_err(|err| format!("connect_failed: {}", err))?;
    let timeout = Duration::from_secs(timeout_secs);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("timeout_failed: {}", err))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("timeout_failed: {}", err))?;
    write_frame(&mut stream, payload.as_bytes())?;
    let response = read_frame(&mut stream)?;
    let response =
        String::from_utf8(response).map_err(|err| format!("utf8_error: {}", err))?;
    Ok(response.trim().to_string())
}

fn send_secure_request(
    target: &str,
    payload: &str,
    timeout_secs: u64,
    identity: &Identity,
    sender_device_id: &str,
    peer_dh_pubkey: &str,
) -> Result<String, String> {
    let dh_secret = identity
        .dh_secret_key_bytes()
        .map_err(|err| format!("dh_key_error: {}", err))?;
    let peer_dh_pubkey = decode_key(peer_dh_pubkey, "peer dh pubkey")?;

    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|err| format!("noise_params_error: {}", err))?;
    let builder = Builder::new(params)
        .local_private_key(&dh_secret)
        .remote_public_key(&peer_dh_pubkey);
    let mut noise = builder
        .build_initiator()
        .map_err(|err| format!("noise_init_error: {}", err))?;

    let mut stream = TcpStream::connect(target).map_err(|err| format!("connect_failed: {}", err))?;
    let timeout = Duration::from_secs(timeout_secs);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("timeout_failed: {}", err))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("timeout_failed: {}", err))?;

    let mut handshake_out = vec![0u8; MAX_FRAME_SIZE];
    let len = noise
        .write_message(&[], &mut handshake_out)
        .map_err(|err| format!("noise_write_failed: {}", err))?;
    let init = SecureInit {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id: sender_device_id.to_string(),
        timestamp_ms: now_ms(),
        msg_type: "SECURE_INIT".to_string(),
        payload: STANDARD.encode(&handshake_out[..len]),
    };
    let init_json =
        serde_json::to_string(&init).map_err(|err| format!("json_error: {}", err))?;
    write_frame(&mut stream, init_json.as_bytes())?;

    let response_raw = read_frame(&mut stream)?;
    let response_str =
        String::from_utf8(response_raw).map_err(|err| format!("utf8_error: {}", err))?;
    let base: ResponseBase =
        serde_json::from_str(&response_str).map_err(|err| format!("json_error: {}", err))?;
    match base.msg_type.as_str() {
        "SECURE_ACCEPT" => {
            let accept: SecureAccept = serde_json::from_str(&response_str)
                .map_err(|err| format!("json_error: {}", err))?;
            let _ = accept.msg_type.as_str();
            let payload =
                STANDARD.decode(accept.payload).map_err(|err| format!("b64_error: {}", err))?;
            let mut handshake_in = vec![0u8; MAX_FRAME_SIZE];
            noise
                .read_message(&payload, &mut handshake_in)
                .map_err(|err| format!("noise_read_failed: {}", err))?;
        }
        "SECURE_REJECT" => {
            let reject: SecureReject = serde_json::from_str(&response_str)
                .map_err(|err| format!("json_error: {}", err))?;
            let _ = reject.msg_type.as_str();
            return Err(format!("secure_reject: {}", reject.reason));
        }
        _ => return Err("secure_invalid_response".to_string()),
    }

    let mut transport = noise
        .into_transport_mode()
        .map_err(|err| format!("noise_transport_failed: {}", err))?;
    let mut cipher = vec![0u8; payload.len() + 64];
    let len = transport
        .write_message(payload.as_bytes(), &mut cipher)
        .map_err(|err| format!("noise_encrypt_failed: {}", err))?;
    let packet = SecurePacket {
        version: 1,
        msg_id: uuid::Uuid::new_v4().to_string(),
        sender_device_id: sender_device_id.to_string(),
        timestamp_ms: now_ms(),
        msg_type: "SECURE_PACKET".to_string(),
        payload: STANDARD.encode(&cipher[..len]),
    };
    let packet_json =
        serde_json::to_string(&packet).map_err(|err| format!("json_error: {}", err))?;
    write_frame(&mut stream, packet_json.as_bytes())?;

    let response_raw = read_frame(&mut stream)?;
    let response_str =
        String::from_utf8(response_raw).map_err(|err| format!("utf8_error: {}", err))?;
    let packet: SecurePacket =
        serde_json::from_str(&response_str).map_err(|err| format!("json_error: {}", err))?;
    if packet.msg_type != "SECURE_PACKET" {
        return Err("secure_invalid_packet".to_string());
    }
    let payload = STANDARD
        .decode(packet.payload)
        .map_err(|err| format!("b64_error: {}", err))?;
    let mut plain = vec![0u8; payload.len() + 64];
    let len = transport
        .read_message(&payload, &mut plain)
        .map_err(|err| format!("noise_decrypt_failed: {}", err))?;
    let response =
        String::from_utf8(plain[..len].to_vec()).map_err(|err| format!("utf8_error: {}", err))?;
    Ok(response.trim().to_string())
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err("frame_too_large".to_string());
    }
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|err| format!("write_failed: {}", err))?;
    stream
        .write_all(payload)
        .map_err(|err| format!("write_failed: {}", err))?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| format!("read_failed: {}", err))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err("frame_too_large".to_string());
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|err| format!("read_failed: {}", err))?;
    Ok(buf)
}

fn decode_key(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|err| format!("{} decode error: {}", label, err))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{} length invalid", label))?;
    Ok(array)
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
const DISCOVERY_TTL_MS: u64 = 300_000;
const MAX_FRAME_SIZE: usize = 1_048_576;
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn print_identity(identity_path: PathBuf, create_if_missing: bool) {
    if create_if_missing {
        match Identity::load_or_generate(&identity_path) {
            Ok(identity) => {
                println!("device_id: {}", identity.device_id);
                println!("public_key: {}", identity.public_key);
                if let Some(dh_public_key) = identity.dh_public_key {
                    println!("dh_public_key: {}", dh_public_key);
                }
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
            if let Some(dh_public_key) = identity.dh_public_key {
                println!("dh_public_key: {}", dh_public_key);
            }
        }
        Ok(None) => {
            println!("identity_status: missing");
        }
        Err(err) => {
            eprintln!("identity_error: {}", err);
        }
    }
}
