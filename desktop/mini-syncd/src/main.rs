use clap::Parser;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use mini_sync_common::{
    config::{Config, PairedDevice},
    discovery::{DiscoveredDevice, DiscoveryState},
    identity::Identity,
    pairing::PairingSession,
    paths,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "mini-syncd", version, about = "mini-sync daemon")]
struct Args {
    #[arg(long)]
    device_name: Option<String>,
    #[arg(long)]
    no_mdns: bool,
}

#[derive(Deserialize)]
struct BaseMessage {
    msg_type: String,
}

#[derive(Deserialize)]
struct PairRequest {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    token: String,
    code: String,
    pubkey: String,
    device_name: Option<String>,
}

#[derive(Deserialize)]
struct PingRequest {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
}

#[derive(Deserialize)]
struct HelloRequest {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    device_name: String,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct PairAccept {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    code_confirm: String,
    pubkey: String,
}

#[derive(Serialize)]
struct PairReject {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    reason: String,
}

#[derive(Serialize)]
struct Pong {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ControlResponse {
    Accept(PairAccept),
    Reject(PairReject),
    Pong(Pong),
}

fn main() {
    let args = Args::parse();
    let config_path = paths::config_file();
    println!("config_path: {}", config_path.display());
    let config = match Config::load_optional(&config_path) {
        Ok(Some(config)) => {
            println!("config_status: loaded");
            config
        }
        Ok(None) => {
            println!("config_status: missing (defaults)");
            Config::default()
        }
        Err(err) => {
            eprintln!("config_error: {}", err);
            std::process::exit(1);
        }
    };
    let identity_path = paths::identity_file();
    println!("identity_path: {}", identity_path.display());
    let identity = match Identity::load_or_generate(&identity_path) {
        Ok(identity) => identity,
        Err(err) => {
            eprintln!("identity_error: {}", err);
            std::process::exit(1);
        }
    };
    println!("device_id: {}", identity.device_id);
    println!("public_key: {}", identity.public_key);
    print_pairing_status();

    let device_name = args
        .device_name
        .or_else(|| config.device_name.clone())
        .unwrap_or_else(default_device_name);
    println!("device_name: {}", device_name);

    if args.no_mdns {
        println!("mdns_status: disabled");
    } else {
        let identity_clone = identity.clone();
        let device_name_clone = device_name.clone();
        let port = config.listen_port;
        let discovery_path = paths::discovery_file();
        thread::spawn(move || {
            if let Err(err) = run_mdns(&identity_clone, &device_name_clone, port, discovery_path) {
                eprintln!("mdns_error: {}", err);
            }
        });
    }

    let pairing_path = paths::pairing_file();
    if let Err(err) =
        run_pairing_listener(&identity, &config_path, &pairing_path, config.listen_port)
    {
        eprintln!("pairing_listener_error: {}", err);
        std::process::exit(1);
    }
}

fn print_pairing_status() {
    let pairing_path = paths::pairing_file();
    println!("pairing_path: {}", pairing_path.display());
    match PairingSession::load_optional(&pairing_path) {
        Ok(Some(session)) => {
            let now = now_ms();
            if session.is_expired(now) {
                if let Err(err) = fs::remove_file(&pairing_path) {
                    eprintln!("pairing_cleanup_error: {}", err);
                }
                println!("pairing_status: expired");
            } else {
                println!("pairing_status: active");
                println!("pairing_expires_at_ms: {}", session.expires_at_ms);
            }
        }
        Ok(None) => {
            println!("pairing_status: none");
        }
        Err(err) => {
            eprintln!("pairing_error: {}", err);
        }
    }
}

fn run_pairing_listener(
    identity: &Identity,
    config_path: &Path,
    pairing_path: &Path,
    port: u16,
) -> Result<(), String> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .map_err(|err| format!("pairing_bind_failed: {}", err))?;
    let address = listener
        .local_addr()
        .map_err(|err| format!("pairing_addr_failed: {}", err))?;
    println!("pairing_listener: {}", address);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(err) = handle_pairing_stream(stream, identity, config_path, pairing_path)
                {
                    eprintln!("pairing_request_error: {}", err);
                }
            }
            Err(err) => return Err(format!("pairing_accept_failed: {}", err)),
        }
    }

    Ok(())
}

fn handle_pairing_stream(
    mut stream: TcpStream,
    identity: &Identity,
    config_path: &Path,
    pairing_path: &Path,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(PAIRING_READ_TIMEOUT_SECS)))
        .map_err(|err| format!("pairing_timeout_failed: {}", err))?;
    let mut raw = String::new();
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|err| format!("pairing_stream_clone_failed: {}", err))?,
    );
    reader
        .read_line(&mut raw)
        .map_err(|err| format!("pairing_read_failed: {}", err))?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("pairing_empty_request".to_string());
    }

    let response = handle_control_message(raw, identity, config_path, pairing_path);
    let response_json =
        serde_json::to_string(&response).map_err(|err| format!("pairing_json_failed: {}", err))?;
    stream
        .write_all(response_json.as_bytes())
        .map_err(|err| format!("pairing_write_failed: {}", err))?;
    stream
        .write_all(b"\n")
        .map_err(|err| format!("pairing_write_failed: {}", err))?;
    Ok(())
}

fn handle_control_message(
    raw: &str,
    identity: &Identity,
    config_path: &Path,
    pairing_path: &Path,
) -> ControlResponse {
    let base: BaseMessage = match serde_json::from_str(raw) {
        Ok(base) => base,
        Err(_) => return reject(identity, "invalid_json"),
    };
    match base.msg_type.as_str() {
        "PAIR_REQUEST" => {
            let request: PairRequest = match serde_json::from_str(raw) {
                Ok(request) => request,
                Err(_) => return reject(identity, "invalid_request"),
            };
            handle_pair_request(request, identity, config_path, pairing_path)
        }
        "PING" => {
            let request: PingRequest = match serde_json::from_str(raw) {
                Ok(request) => request,
                Err(_) => return reject(identity, "invalid_request"),
            };
            handle_ping_request(request, identity, config_path)
        }
        "HELLO" => {
            let request: HelloRequest = match serde_json::from_str(raw) {
                Ok(request) => request,
                Err(_) => return reject(identity, "invalid_request"),
            };
            handle_hello_request(request, identity, config_path)
        }
        _ => reject(identity, "unsupported_msg_type"),
    }
}

fn handle_pair_request(
    request: PairRequest,
    identity: &Identity,
    config_path: &Path,
    pairing_path: &Path,
) -> ControlResponse {
    let _ = request.msg_id.as_str();
    let _ = request.timestamp_ms;
    if request.msg_type != "PAIR_REQUEST" {
        return reject(identity, "invalid_msg_type");
    }
    if request.version != 1 {
        return reject(identity, "unsupported_version");
    }
    if request.sender_device_id == identity.device_id {
        return reject(identity, "self_pairing_not_allowed");
    }

    let session = match PairingSession::load_optional(pairing_path) {
        Ok(Some(session)) => session,
        Ok(None) => return reject(identity, "no_active_pairing"),
        Err(_) => return reject(identity, "pairing_load_failed"),
    };
    let now = now_ms();
    if session.is_expired(now) {
        let _ = fs::remove_file(pairing_path);
        return reject(identity, "pairing_expired");
    }
    if request.token != session.token {
        return reject(identity, "token_mismatch");
    }
    if request.code != session.code {
        return reject(identity, "code_mismatch");
    }

    if let Err(err) = upsert_paired_device(
        config_path,
        &request.sender_device_id,
        &request.pubkey,
        request.device_name.as_deref(),
        now,
    ) {
        return reject(identity, &format!("config_error: {}", err));
    }
    let _ = fs::remove_file(pairing_path);

    accept(identity, session.code)
}

fn handle_ping_request(
    request: PingRequest,
    identity: &Identity,
    config_path: &Path,
) -> ControlResponse {
    let _ = request.msg_id.as_str();
    let _ = request.timestamp_ms;
    if request.msg_type != "PING" {
        return reject(identity, "invalid_msg_type");
    }
    if request.version != 1 {
        return reject(identity, "unsupported_version");
    }
    if request.sender_device_id == identity.device_id {
        return reject(identity, "self_ping_not_allowed");
    }
    let now = now_ms();
    match update_paired_device(config_path, &request.sender_device_id, None, now) {
        Ok(true) => pong(identity),
        Ok(false) => reject(identity, "unpaired_device"),
        Err(err) => reject(identity, &format!("config_error: {}", err)),
    }
}

fn handle_hello_request(
    request: HelloRequest,
    identity: &Identity,
    config_path: &Path,
) -> ControlResponse {
    let _ = request.msg_id.as_str();
    let _ = request.timestamp_ms;
    let _ = request.capabilities;
    if request.msg_type != "HELLO" {
        return reject(identity, "invalid_msg_type");
    }
    if request.version != 1 {
        return reject(identity, "unsupported_version");
    }
    if request.sender_device_id == identity.device_id {
        return reject(identity, "self_hello_not_allowed");
    }
    let now = now_ms();
    match update_paired_device(
        config_path,
        &request.sender_device_id,
        Some(&request.device_name),
        now,
    ) {
        Ok(true) => pong(identity),
        Ok(false) => reject(identity, "unpaired_device"),
        Err(err) => reject(identity, &format!("config_error: {}", err)),
    }
}

fn accept(identity: &Identity, code_confirm: String) -> ControlResponse {
    ControlResponse::Accept(PairAccept {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "PAIR_ACCEPT".to_string(),
        code_confirm,
        pubkey: identity.public_key.clone(),
    })
}

fn reject(identity: &Identity, reason: &str) -> ControlResponse {
    ControlResponse::Reject(PairReject {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "PAIR_REJECT".to_string(),
        reason: reason.to_string(),
    })
}

fn pong(identity: &Identity) -> ControlResponse {
    ControlResponse::Pong(Pong {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "PONG".to_string(),
    })
}

fn new_msg_id() -> String {
    Uuid::new_v4().to_string()
}

fn run_mdns(
    identity: &Identity,
    device_name: &str,
    port: u16,
    discovery_path: std::path::PathBuf,
) -> Result<(), String> {
    let mdns = ServiceDaemon::new().map_err(|err| format!("mdns_init_failed: {}", err))?;
    let service_type = "_minisync._tcp.local.";
    let short_id = short_device_id(&identity.device_id);
    let instance_name = format!("mini-sync-{}", short_id);
    let host_name = format!("{}.local.", instance_name);

    let mut properties = HashMap::new();
    properties.insert("device_id".to_string(), identity.device_id.clone());
    properties.insert("device_name".to_string(), device_name.to_string());
    properties.insert("capabilities".to_string(), "clipboard,file".to_string());

    let service_info = ServiceInfo::new(service_type, &instance_name, &host_name, (), port, properties)
        .map_err(|err| format!("mdns_service_failed: {}", err))?
        .enable_addr_auto();
    mdns.register(service_info)
        .map_err(|err| format!("mdns_register_failed: {}", err))?;

    let receiver = mdns
        .browse(service_type)
        .map_err(|err| format!("mdns_browse_failed: {}", err))?;
    println!("mdns_status: running");

    let mut fullname_map: HashMap<String, String> = HashMap::new();
    loop {
        match receiver.recv() {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(device) =
                    build_discovered_device(&info, &identity.device_id, now_ms())
                {
                    fullname_map.insert(info.get_fullname().to_string(), device.device_id.clone());
                    print_discovered_device(&device);
                    if let Err(err) =
                        store_discovered_device(&discovery_path, device, DISCOVERY_TTL_MS)
                    {
                        eprintln!("discovery_store_error: {}", err);
                    }
                }
            }
            Ok(ServiceEvent::ServiceRemoved(_ty, fullname)) => {
                println!("mdns_removed: {}", fullname);
                if let Some(device_id) = fullname_map.remove(&fullname) {
                    if let Err(err) = remove_discovered_device(&discovery_path, &device_id) {
                        eprintln!("discovery_remove_error: {}", err);
                    }
                }
            }
            Ok(ServiceEvent::SearchStarted(_)) | Ok(ServiceEvent::SearchStopped(_)) => {}
            Ok(ServiceEvent::ServiceFound(_, _)) => {}
            Ok(_) => {}
            Err(err) => return Err(format!("mdns_receive_failed: {}", err)),
        }
    }
}

fn build_discovered_device(
    info: &ResolvedService,
    local_device_id: &str,
    last_seen_ms: u64,
) -> Option<DiscoveredDevice> {
    let device_id = info
        .txt_properties
        .get_property_val_str("device_id")
        .unwrap_or("unknown");
    if device_id == local_device_id {
        return None;
    }
    let device_name = info
        .txt_properties
        .get_property_val_str("device_name")
        .map(|value| value.to_string());
    let capabilities = info
        .txt_properties
        .get_property_val_str("capabilities")
        .unwrap_or("");
    let addresses: Vec<String> = info
        .get_addresses()
        .iter()
        .map(|addr| addr.to_ip_addr().to_string())
        .collect();
    let capabilities: Vec<String> = capabilities
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .collect();
    Some(DiscoveredDevice {
        device_id: device_id.to_string(),
        device_name,
        capabilities,
        addresses,
        port: info.get_port(),
        last_seen_ms,
    })
}

fn print_discovered_device(device: &DiscoveredDevice) {
    let name = device
        .device_name
        .as_deref()
        .unwrap_or("unknown");
    let caps = if device.capabilities.is_empty() {
        "-".to_string()
    } else {
        device.capabilities.join(",")
    };
    let addresses = if device.addresses.is_empty() {
        "-".to_string()
    } else {
        device.addresses.join(",")
    };
    println!(
        "mdns_device: {} {} {} {}:{}",
        device.device_id, name, caps, addresses, device.port
    );
}

fn store_discovered_device(
    discovery_path: &Path,
    device: DiscoveredDevice,
    ttl_ms: u64,
) -> Result<(), String> {
    let mut state =
        DiscoveryState::load_or_default(discovery_path).map_err(|err| err.to_string())?;
    state.prune_expired(device.last_seen_ms, ttl_ms);
    state.upsert(device);
    state
        .save(discovery_path)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn remove_discovered_device(discovery_path: &Path, device_id: &str) -> Result<(), String> {
    let mut state =
        DiscoveryState::load_or_default(discovery_path).map_err(|err| err.to_string())?;
    if state.remove_device(device_id) {
        state
            .save(discovery_path)
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn upsert_paired_device(
    config_path: &Path,
    device_id: &str,
    pubkey: &str,
    device_name: Option<&str>,
    last_seen_ms: u64,
) -> Result<(), String> {
    let mut config = load_config_or_default(config_path)?;
    if let Some(existing) = config
        .paired_devices
        .iter_mut()
        .find(|device| device.device_id == device_id)
    {
        existing.pubkey = pubkey.to_string();
        if let Some(name) = device_name {
            existing.device_name = Some(name.to_string());
        }
        existing.last_seen_ms = Some(last_seen_ms);
    } else {
        config.paired_devices.push(PairedDevice {
            device_id: device_id.to_string(),
            device_name: device_name.map(|name| name.to_string()),
            pubkey: pubkey.to_string(),
            last_seen_ms: Some(last_seen_ms),
        });
    }
    config
        .save(config_path)
        .map_err(|err| format!("config_save_failed: {}", err))?;
    Ok(())
}

fn update_paired_device(
    config_path: &Path,
    device_id: &str,
    device_name: Option<&str>,
    last_seen_ms: u64,
) -> Result<bool, String> {
    let mut config = load_config_or_default(config_path)?;
    let existing = config
        .paired_devices
        .iter_mut()
        .find(|device| device.device_id == device_id);
    let Some(existing) = existing else {
        return Ok(false);
    };
    if let Some(name) = device_name {
        existing.device_name = Some(name.to_string());
    }
    existing.last_seen_ms = Some(last_seen_ms);
    config
        .save(config_path)
        .map_err(|err| format!("config_save_failed: {}", err))?;
    Ok(true)
}

fn load_config_or_default(config_path: &Path) -> Result<Config, String> {
    match Config::load_optional(config_path) {
        Ok(Some(config)) => Ok(config),
        Ok(None) => Ok(Config::default()),
        Err(err) => Err(format!("config_load_failed: {}", err)),
    }
}

fn short_device_id(device_id: &str) -> String {
    device_id
        .split('-')
        .next()
        .unwrap_or(device_id)
        .to_string()
}

fn default_device_name() -> String {
    env::var("MINI_SYNC_DEVICE_NAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "mini-sync".to_string())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

const PAIRING_READ_TIMEOUT_SECS: u64 = 10;
const DISCOVERY_TTL_MS: u64 = 300_000;
