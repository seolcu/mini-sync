use clap::Parser;
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use mini_sync_common::{config::Config, identity::Identity, pairing::PairingSession, paths};
use std::collections::HashMap;
use std::env;
use std::fs;

#[derive(Parser)]
#[command(name = "mini-syncd", version, about = "mini-sync daemon")]
struct Args {
    #[arg(long)]
    device_name: Option<String>,
    #[arg(long)]
    no_mdns: bool,
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
        return;
    }

    if let Err(err) = run_mdns(&identity, &device_name, config.listen_port) {
        eprintln!("mdns_error: {}", err);
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

fn run_mdns(identity: &Identity, device_name: &str, port: u16) -> Result<(), String> {
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

    loop {
        match receiver.recv() {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                print_resolved_device(&info, &identity.device_id);
            }
            Ok(ServiceEvent::ServiceRemoved(_ty, fullname)) => {
                println!("mdns_removed: {}", fullname);
            }
            Ok(ServiceEvent::SearchStarted(_)) | Ok(ServiceEvent::SearchStopped(_)) => {}
            Ok(ServiceEvent::ServiceFound(_, _)) => {}
            Ok(_) => {}
            Err(err) => return Err(format!("mdns_receive_failed: {}", err)),
        }
    }
}

fn print_resolved_device(info: &ResolvedService, local_device_id: &str) {
    let device_id = info
        .txt_properties
        .get_property_val_str("device_id")
        .unwrap_or("unknown");
    if device_id == local_device_id {
        return;
    }
    let device_name = info
        .txt_properties
        .get_property_val_str("device_name")
        .unwrap_or("unknown");
    let capabilities = info
        .txt_properties
        .get_property_val_str("capabilities")
        .unwrap_or("-");
    let addresses: Vec<String> = info
        .get_addresses()
        .iter()
        .map(|addr| addr.to_ip_addr().to_string())
        .collect();
    let address_list = if addresses.is_empty() {
        "-".to_string()
    } else {
        addresses.join(",")
    };
    println!(
        "mdns_device: {} {} {} {}:{}",
        device_id,
        device_name,
        capabilities,
        address_list,
        info.get_port()
    );
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
