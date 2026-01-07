use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use mini_sync_common::{
    clipboard::ClipboardState,
    config::{Config, PairedDevice},
    discovery::{DiscoveredDevice, DiscoveryState},
    identity::Identity,
    pairing::PairingSession,
    paths,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::Builder;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
    dh_pubkey: Option<String>,
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

#[derive(Deserialize)]
struct StatusRequest {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    include_discovery: bool,
}

#[derive(Deserialize)]
struct ClipPush {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    content_type: String,
    text: String,
    clip_id: String,
}

#[derive(Deserialize, Clone)]
struct FileItem {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
struct FileOffer {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    offer_id: String,
    items: Vec<FileItem>,
    download_url: Option<String>,
    endpoint: Option<String>,
    token: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    dh_pubkey: Option<String>,
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
struct StatusResponse {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    paired_devices: Vec<StatusPairedDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_devices: Option<Vec<StatusAvailableDevice>>,
}

#[derive(Serialize)]
struct StatusPairedDevice {
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_ms: Option<u64>,
}

#[derive(Serialize)]
struct StatusAvailableDevice {
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    port: u16,
    last_seen_ms: u64,
}

#[derive(Deserialize)]
struct ResponseBase {
    msg_type: String,
}

#[derive(Serialize, Deserialize)]
struct SecureInit {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct SecureAccept {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct SecureReject {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
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

#[derive(Serialize)]
struct ClipAck {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    clip_id: String,
}

#[derive(Serialize)]
struct FileAccept {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    offer_id: String,
}

#[derive(Serialize)]
struct FileReject {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    offer_id: String,
    reason: String,
}

#[derive(Serialize)]
struct FileGet {
    version: u8,
    msg_id: String,
    sender_device_id: String,
    timestamp_ms: u64,
    msg_type: String,
    offer_id: String,
    token: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ControlResponse {
    Accept(PairAccept),
    Reject(PairReject),
    Pong(Pong),
    Status(StatusResponse),
    ClipAck(ClipAck),
    FileAccept(FileAccept),
    FileReject(FileReject),
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
    let raw = read_frame(&mut stream)?;
    let raw = String::from_utf8(raw).map_err(|err| format!("pairing_utf8_failed: {}", err))?;
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("pairing_empty_request".to_string());
    }

    let base: BaseMessage =
        serde_json::from_str(raw).map_err(|_| "pairing_invalid_json".to_string())?;
    if base.msg_type == "SECURE_INIT" {
        let init: SecureInit =
            serde_json::from_str(raw).map_err(|_| "pairing_invalid_request".to_string())?;
        return handle_secure_session(init, &mut stream, identity, config_path, pairing_path);
    }

    let config = load_config_or_default(config_path)?;
    if config.control.require_secure && base.msg_type != "PAIR_REQUEST" {
        let response = reject(identity, "secure_required");
        let response_json = serde_json::to_string(&response)
            .map_err(|err| format!("pairing_json_failed: {}", err))?;
        write_frame(&mut stream, response_json.as_bytes())
            .map_err(|err| format!("pairing_write_failed: {}", err))?;
        return Ok(());
    }

    let response = handle_control_message(raw, identity, config_path, pairing_path);
    let response_json =
        serde_json::to_string(&response).map_err(|err| format!("pairing_json_failed: {}", err))?;
    write_frame(&mut stream, response_json.as_bytes())
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
        "STATUS_REQUEST" => {
            let request: StatusRequest = match serde_json::from_str(raw) {
                Ok(request) => request,
                Err(_) => return reject(identity, "invalid_request"),
            };
            handle_status_request(request, identity, config_path)
        }
        "CLIP_PUSH" => {
            let request: ClipPush = match serde_json::from_str(raw) {
                Ok(request) => request,
                Err(_) => return reject(identity, "invalid_request"),
            };
            handle_clip_push(request, identity, config_path)
        }
        "FILE_OFFER" => {
            let request: FileOffer = match serde_json::from_str(raw) {
                Ok(request) => request,
                Err(_) => return reject(identity, "invalid_request"),
            };
            handle_file_offer(request, identity, config_path)
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
        request.dh_pubkey.as_deref(),
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

fn handle_status_request(
    request: StatusRequest,
    identity: &Identity,
    config_path: &Path,
) -> ControlResponse {
    let _ = request.msg_id.as_str();
    let _ = request.timestamp_ms;
    if request.msg_type != "STATUS_REQUEST" {
        return reject(identity, "invalid_msg_type");
    }
    if request.version != 1 {
        return reject(identity, "unsupported_version");
    }
    let now = now_ms();
    let _ = update_paired_device(
        config_path,
        &request.sender_device_id,
        None,
        now,
    );

    let config = match load_config_or_default(config_path) {
        Ok(config) => config,
        Err(err) => return reject(identity, &format!("config_error: {}", err)),
    };
    let paired_devices = config
        .paired_devices
        .into_iter()
        .map(|device| StatusPairedDevice {
            device_id: device.device_id,
            device_name: device.device_name,
            last_seen_ms: device.last_seen_ms,
        })
        .collect::<Vec<_>>();

    let available_devices = if request.include_discovery {
        match DiscoveryState::load_optional(&paths::discovery_file()) {
            Ok(Some(mut state)) => {
                state.prune_expired(now, DISCOVERY_TTL_MS);
                Some(
                    state
                        .devices
                        .into_iter()
                        .map(|device| StatusAvailableDevice {
                            device_id: device.device_id,
                            device_name: device.device_name,
                            capabilities: device.capabilities,
                            addresses: device.addresses,
                            port: device.port,
                            last_seen_ms: device.last_seen_ms,
                        })
                        .collect(),
                )
            }
            Ok(None) => Some(Vec::new()),
            Err(_) => None,
        }
    } else {
        None
    };

    ControlResponse::Status(StatusResponse {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "STATUS_RESPONSE".to_string(),
        paired_devices,
        available_devices,
    })
}

fn handle_clip_push(
    request: ClipPush,
    identity: &Identity,
    config_path: &Path,
) -> ControlResponse {
    let _ = request.msg_id.as_str();
    let _ = request.timestamp_ms;
    if request.msg_type != "CLIP_PUSH" {
        return reject(identity, "invalid_msg_type");
    }
    if request.version != 1 {
        return reject(identity, "unsupported_version");
    }
    if request.sender_device_id == identity.device_id {
        return reject(identity, "self_clip_push_not_allowed");
    }
    if request.content_type != "text/plain" {
        return reject(identity, "unsupported_content_type");
    }
    if Uuid::parse_str(&request.clip_id).is_err() {
        return reject(identity, "invalid_clip_id");
    }
    let now = now_ms();
    match update_paired_device(config_path, &request.sender_device_id, None, now) {
        Ok(true) => {}
        Ok(false) => return reject(identity, "unpaired_device"),
        Err(err) => return reject(identity, &format!("config_error: {}", err)),
    }
    if let Err(err) = set_clipboard_text(&request.text) {
        return reject(identity, &format!("clipboard_failed: {}", err));
    }
    if let Err(err) = store_clipboard_state(
        &request.clip_id,
        &request.sender_device_id,
        now,
        &request.text,
    ) {
        eprintln!("clipboard_state_error: {}", err);
    }
    ControlResponse::ClipAck(ClipAck {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "CLIP_ACK".to_string(),
        clip_id: request.clip_id,
    })
}

fn handle_file_offer(
    request: FileOffer,
    identity: &Identity,
    config_path: &Path,
) -> ControlResponse {
    let _ = request.msg_id.as_str();
    let _ = request.timestamp_ms;
    if request.msg_type != "FILE_OFFER" {
        return reject(identity, "invalid_msg_type");
    }
    if request.version != 1 {
        return reject(identity, "unsupported_version");
    }
    if request.sender_device_id == identity.device_id {
        return file_reject(identity, &request.offer_id, "self_offer_not_allowed");
    }
    if request.items.is_empty() {
        return file_reject(identity, &request.offer_id, "missing_items");
    }
    let now = now_ms();
    match update_paired_device(config_path, &request.sender_device_id, None, now) {
        Ok(true) => {}
        Ok(false) => return file_reject(identity, &request.offer_id, "unpaired_device"),
        Err(err) => return file_reject(identity, &request.offer_id, &format!("config_error: {}", err)),
    }

    let config = match load_config_or_default(config_path) {
        Ok(config) => config,
        Err(err) => return file_reject(identity, &request.offer_id, &format!("config_error: {}", err)),
    };
    let peer = match config
        .paired_devices
        .iter()
        .find(|device| device.device_id == request.sender_device_id)
    {
        Some(peer) => peer,
        None => return file_reject(identity, &request.offer_id, "unpaired_device"),
    };
    let Some(peer_dh_pubkey) = peer.dh_pubkey.as_deref() else {
        return file_reject(identity, &request.offer_id, "missing_peer_dh_key");
    };
    let endpoint = match request
        .endpoint
        .as_deref()
        .or(request.download_url.as_deref())
    {
        Some(endpoint) => endpoint.to_string(),
        None => return file_reject(identity, &request.offer_id, "missing_endpoint"),
    };
    let token = match request.token.as_deref() {
        Some(token) => token.to_string(),
        None => return file_reject(identity, &request.offer_id, "missing_token"),
    };
    if let Err(err) = parse_endpoint(&endpoint) {
        return file_reject(identity, &request.offer_id, &err);
    }

    let offer_id = request.offer_id.clone();
    let items = request.items.clone();
    let sender_device_id = request.sender_device_id.clone();
    let identity_clone = identity.clone();
    let peer_dh_pubkey = peer_dh_pubkey.to_string();
    let download_dir = config.download_dir.clone();

    thread::spawn(move || {
        if let Err(err) = download_file_offer(
            endpoint,
            token,
            offer_id,
            items,
            sender_device_id,
            identity_clone,
            peer_dh_pubkey,
            download_dir,
        ) {
            eprintln!("file_download_error: {}", err);
        }
    });

    file_accept(identity, &request.offer_id)
}

fn handle_secure_session(
    init: SecureInit,
    stream: &mut TcpStream,
    identity: &Identity,
    config_path: &Path,
    pairing_path: &Path,
) -> Result<(), String> {
    let _ = init.msg_id.as_str();
    let _ = init.timestamp_ms;
    if init.msg_type != "SECURE_INIT" {
        return Err("secure_invalid_msg_type".to_string());
    }
    if init.version != 1 {
        return send_secure_reject(stream, identity, "unsupported_version");
    }
    let config = load_config_or_default(config_path)?;
    let peer = match config
        .paired_devices
        .iter()
        .find(|device| device.device_id == init.sender_device_id)
    {
        Some(peer) => peer,
        None => return send_secure_reject(stream, identity, "unpaired_device"),
    };
    let Some(peer_dh_pubkey) = peer.dh_pubkey.as_deref() else {
        return send_secure_reject(stream, identity, "missing_peer_dh_key");
    };
    let dh_secret = match identity.dh_secret_key_bytes() {
        Ok(value) => value,
        Err(err) => return send_secure_reject(stream, identity, &format!("dh_key_error: {}", err)),
    };
    let peer_dh_pubkey = match decode_key(peer_dh_pubkey, "peer dh pubkey") {
        Ok(value) => value,
        Err(err) => return send_secure_reject(stream, identity, &err),
    };

    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|err| format!("noise_params_error: {}", err))?;
    let builder = Builder::new(params)
        .local_private_key(&dh_secret)
        .remote_public_key(&peer_dh_pubkey);
    let mut noise = builder
        .build_responder()
        .map_err(|err| format!("noise_init_error: {}", err))?;

    let payload =
        STANDARD.decode(init.payload).map_err(|err| format!("b64_error: {}", err))?;
    let mut handshake_in = vec![0u8; MAX_FRAME_SIZE];
    noise
        .read_message(&payload, &mut handshake_in)
        .map_err(|err| format!("noise_read_failed: {}", err))?;

    let mut handshake_out = vec![0u8; MAX_FRAME_SIZE];
    let len = noise
        .write_message(&[], &mut handshake_out)
        .map_err(|err| format!("noise_write_failed: {}", err))?;
    let accept = SecureAccept {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "SECURE_ACCEPT".to_string(),
        payload: STANDARD.encode(&handshake_out[..len]),
    };
    let accept_json =
        serde_json::to_string(&accept).map_err(|err| format!("json_error: {}", err))?;
    write_frame(stream, accept_json.as_bytes())?;

    let mut transport = noise
        .into_transport_mode()
        .map_err(|err| format!("noise_transport_failed: {}", err))?;
    let raw = read_frame(stream)?;
    let raw = String::from_utf8(raw).map_err(|err| format!("utf8_error: {}", err))?;
    let packet: SecurePacket =
        serde_json::from_str(&raw).map_err(|err| format!("json_error: {}", err))?;
    if packet.msg_type != "SECURE_PACKET" {
        return Err("secure_invalid_packet".to_string());
    }
    let payload =
        STANDARD.decode(packet.payload).map_err(|err| format!("b64_error: {}", err))?;
    let mut plain = vec![0u8; payload.len() + 64];
    let len = transport
        .read_message(&payload, &mut plain)
        .map_err(|err| format!("noise_decrypt_failed: {}", err))?;
    let plaintext =
        String::from_utf8(plain[..len].to_vec()).map_err(|err| format!("utf8_error: {}", err))?;

    let response = handle_control_message(&plaintext, identity, config_path, pairing_path);
    let response_json =
        serde_json::to_string(&response).map_err(|err| format!("json_error: {}", err))?;
    let mut cipher = vec![0u8; response_json.len() + 64];
    let len = transport
        .write_message(response_json.as_bytes(), &mut cipher)
        .map_err(|err| format!("noise_encrypt_failed: {}", err))?;
    let response_packet = SecurePacket {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "SECURE_PACKET".to_string(),
        payload: STANDARD.encode(&cipher[..len]),
    };
    let response_packet_json = serde_json::to_string(&response_packet)
        .map_err(|err| format!("json_error: {}", err))?;
    write_frame(stream, response_packet_json.as_bytes())?;
    Ok(())
}

fn send_secure_reject(
    stream: &mut TcpStream,
    identity: &Identity,
    reason: &str,
) -> Result<(), String> {
    let reject = SecureReject {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "SECURE_REJECT".to_string(),
        reason: reason.to_string(),
    };
    let reject_json =
        serde_json::to_string(&reject).map_err(|err| format!("json_error: {}", err))?;
    write_frame(stream, reject_json.as_bytes())?;
    Err(format!("secure_reject: {}", reason))
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
        dh_pubkey: identity.dh_public_key.clone(),
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

fn file_accept(identity: &Identity, offer_id: &str) -> ControlResponse {
    ControlResponse::FileAccept(FileAccept {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "FILE_ACCEPT".to_string(),
        offer_id: offer_id.to_string(),
    })
}

fn file_reject(identity: &Identity, offer_id: &str, reason: &str) -> ControlResponse {
    ControlResponse::FileReject(FileReject {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "FILE_REJECT".to_string(),
        offer_id: offer_id.to_string(),
        reason: reason.to_string(),
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
    dh_pubkey: Option<&str>,
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
        if let Some(dh_pubkey) = dh_pubkey {
            existing.dh_pubkey = Some(dh_pubkey.to_string());
        }
        if let Some(name) = device_name {
            existing.device_name = Some(name.to_string());
        }
        existing.last_seen_ms = Some(last_seen_ms);
    } else {
        config.paired_devices.push(PairedDevice {
            device_id: device_id.to_string(),
            device_name: device_name.map(|name| name.to_string()),
            pubkey: pubkey.to_string(),
            dh_pubkey: dh_pubkey.map(|value| value.to_string()),
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

fn read_frame_optional(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, String> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(err) => return Err(format!("read_failed: {}", err)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err("frame_too_large".to_string());
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|err| format!("read_failed: {}", err))?;
    Ok(Some(buf))
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

fn download_file_offer(
    endpoint: String,
    token: String,
    offer_id: String,
    items: Vec<FileItem>,
    sender_device_id: String,
    identity: Identity,
    peer_dh_pubkey: String,
    download_dir: PathBuf,
) -> Result<(), String> {
    let target = parse_endpoint(&endpoint)?;
    let dh_secret = identity
        .dh_secret_key_bytes()
        .map_err(|err| format!("dh_key_error: {}", err))?;
    let peer_dh_pubkey = decode_key(&peer_dh_pubkey, "peer dh pubkey")?;

    let params: snow::params::NoiseParams = NOISE_PARAMS
        .parse()
        .map_err(|err| format!("noise_params_error: {}", err))?;
    let builder = Builder::new(params)
        .local_private_key(&dh_secret)
        .remote_public_key(&peer_dh_pubkey);
    let mut noise = builder
        .build_initiator()
        .map_err(|err| format!("noise_init_error: {}", err))?;

    let mut stream =
        TcpStream::connect(&target).map_err(|err| format!("connect_failed: {}", err))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(FILE_TRANSFER_TIMEOUT_SECS)))
        .map_err(|err| format!("timeout_failed: {}", err))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(FILE_TRANSFER_TIMEOUT_SECS)))
        .map_err(|err| format!("timeout_failed: {}", err))?;

    let mut handshake_out = vec![0u8; MAX_FRAME_SIZE];
    let len = noise
        .write_message(&[], &mut handshake_out)
        .map_err(|err| format!("noise_write_failed: {}", err))?;
    let init = SecureInit {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
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
            if accept.sender_device_id != sender_device_id {
                return Err("secure_accept_device_mismatch".to_string());
            }
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
            return Err(format!("secure_reject: {}", reject.reason));
        }
        _ => return Err("secure_invalid_response".to_string()),
    }

    let mut transport = noise
        .into_transport_mode()
        .map_err(|err| format!("noise_transport_failed: {}", err))?;

    let get = FileGet {
        version: 1,
        msg_id: new_msg_id(),
        sender_device_id: identity.device_id.clone(),
        timestamp_ms: now_ms(),
        msg_type: "FILE_GET".to_string(),
        offer_id: offer_id.clone(),
        token,
    };
    let get_json =
        serde_json::to_string(&get).map_err(|err| format!("json_error: {}", err))?;
    let mut cipher = vec![0u8; get_json.len() + 64];
    let len = transport
        .write_message(get_json.as_bytes(), &mut cipher)
        .map_err(|err| format!("noise_encrypt_failed: {}", err))?;
    write_frame(&mut stream, &cipher[..len])?;

    fs::create_dir_all(&download_dir)
        .map_err(|err| format!("download_dir_failed: {}", err))?;
    let download_path = resolve_download_path(&download_dir, &items, &offer_id);
    let mut output = File::create(&download_path)
        .map_err(|err| format!("download_create_failed: {}", err))?;
    let expected_size = if items.len() == 1 {
        Some(items[0].size)
    } else {
        None
    };
    let mut received: u64 = 0;

    while let Some(frame) = read_frame_optional(&mut stream)? {
        let mut plain = vec![0u8; frame.len() + 64];
        let len = transport
            .read_message(&frame, &mut plain)
            .map_err(|err| format!("noise_decrypt_failed: {}", err))?;
        output
            .write_all(&plain[..len])
            .map_err(|err| format!("download_write_failed: {}", err))?;
        received = received.saturating_add(len as u64);
        if let Some(expected) = expected_size {
            if received >= expected {
                break;
            }
        }
    }
    output
        .flush()
        .map_err(|err| format!("download_write_failed: {}", err))?;

    if let Some(expected) = expected_size {
        if received != expected {
            return Err(format!(
                "download_size_mismatch: expected {} got {}",
                expected, received
            ));
        }
    }
    if items.len() == 1 {
        let hash = hash_file(&download_path)?;
        if hash != items[0].sha256 {
            return Err("download_hash_mismatch".to_string());
        }
    }

    println!("file_received: {}", download_path.display());
    Ok(())
}

fn parse_endpoint(endpoint: &str) -> Result<String, String> {
    let trimmed = endpoint.trim();
    if let Some(stripped) = trimmed.strip_prefix("tcp://") {
        return Ok(stripped.to_string());
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Err("unsupported_endpoint_scheme".to_string());
    }
    Ok(trimmed.to_string())
}

fn resolve_download_path(download_dir: &Path, items: &[FileItem], offer_id: &str) -> PathBuf {
    let mut name = items
        .first()
        .map(|item| item.name.clone())
        .unwrap_or_else(|| format!("mini-sync-{}", offer_id));
    name = sanitize_filename(&name);
    let mut candidate = download_dir.join(&name);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(&name);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("file");
    let ext = path.extension().and_then(|value| value.to_str());
    for idx in 1..1000 {
        let file_name = if let Some(ext) = ext {
            format!("{}-{}.{}", stem, idx, ext)
        } else {
            format!("{}-{}", stem, idx)
        };
        candidate = download_dir.join(file_name);
        if !candidate.exists() {
            break;
        }
    }
    candidate
}

fn sanitize_filename(name: &str) -> String {
    let mut cleaned = name.replace('/', "_").replace('\\', "_");
    if cleaned.trim().is_empty() {
        cleaned = "file".to_string();
    }
    cleaned
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|err| format!("file_open_failed: {}", err))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf).map_err(|err| format!("file_read_failed: {}", err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn short_device_id(device_id: &str) -> String {
    device_id
        .split('-')
        .next()
        .unwrap_or(device_id)
        .to_string()
}

fn set_clipboard_text(text: &str) -> Result<(), String> {
    let mut child = Command::new("wl-copy")
        .arg("--type")
        .arg("text/plain")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("wl-copy_failed: {}", err))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|err| format!("wl-copy_write_failed: {}", err))?;
    }
    thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn store_clipboard_state(
    clip_id: &str,
    sender_device_id: &str,
    timestamp_ms: u64,
    text: &str,
) -> Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let text_hash = hex::encode(hasher.finalize());
    let state = ClipboardState {
        clip_id: clip_id.to_string(),
        sender_device_id: sender_device_id.to_string(),
        timestamp_ms,
        text_hash,
    };
    let path = paths::clipboard_state_file();
    state
        .save(&path)
        .map_err(|err| format!("clipboard_state_save_failed: {}", err))?;
    Ok(())
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
const FILE_TRANSFER_TIMEOUT_SECS: u64 = 120;
const MAX_FRAME_SIZE: usize = 1_048_576;
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
