use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub device_id: String,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
    pub port: u16,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryState {
    #[serde(default)]
    pub devices: Vec<DiscoveredDevice>,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self { devices: Vec::new() }
    }
}

impl DiscoveryState {
    pub fn load(path: &Path) -> Result<Self, DiscoveryError> {
        let contents = fs::read_to_string(path)?;
        let state = toml::from_str(&contents)?;
        Ok(state)
    }

    pub fn load_optional(path: &Path) -> Result<Option<Self>, DiscoveryError> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(toml::from_str(&contents)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(DiscoveryError::Io(err)),
        }
    }

    pub fn load_or_default(path: &Path) -> Result<Self, DiscoveryError> {
        Ok(Self::load_optional(path)?.unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> Result<(), DiscoveryError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }

    pub fn upsert(&mut self, device: DiscoveredDevice) {
        if let Some(existing) = self
            .devices
            .iter_mut()
            .find(|existing| existing.device_id == device.device_id)
        {
            *existing = device;
        } else {
            self.devices.push(device);
        }
    }

    pub fn prune_expired(&mut self, now_ms: u64, ttl_ms: u64) {
        self.devices
            .retain(|device| now_ms.saturating_sub(device.last_seen_ms) <= ttl_ms);
    }
}

#[derive(Debug)]
pub enum DiscoveryError {
    Io(io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::Io(err) => write!(f, "io error: {}", err),
            DiscoveryError::Parse(err) => write!(f, "parse error: {}", err),
            DiscoveryError::Serialize(err) => write!(f, "serialize error: {}", err),
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<io::Error> for DiscoveryError {
    fn from(err: io::Error) -> Self {
        DiscoveryError::Io(err)
    }
}

impl From<toml::de::Error> for DiscoveryError {
    fn from(err: toml::de::Error) -> Self {
        DiscoveryError::Parse(err)
    }
}

impl From<toml::ser::Error> for DiscoveryError {
    fn from(err: toml::ser::Error) -> Self {
        DiscoveryError::Serialize(err)
    }
}
