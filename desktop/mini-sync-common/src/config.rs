use crate::paths;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default = "default_download_dir")]
    pub download_dir: PathBuf,
    #[serde(default)]
    pub clipboard: ClipboardConfig,
    #[serde(default)]
    pub paired_devices: Vec<PairedDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardConfig {
    #[serde(default)]
    pub watch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevice {
    pub device_id: String,
    #[serde(default)]
    pub device_name: Option<String>,
    pub pubkey: String,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self { watch: false }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: default_listen_port(),
            device_name: None,
            download_dir: default_download_dir(),
            clipboard: ClipboardConfig::default(),
            paired_devices: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)?;
        let parsed = toml::from_str(&contents)?;
        Ok(parsed)
    }

    pub fn load_optional(path: &Path) -> Result<Option<Self>, ConfigError> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(toml::from_str(&contents)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "io error: {}", err),
            ConfigError::Parse(err) => write!(f, "parse error: {}", err),
            ConfigError::Serialize(err) => write!(f, "serialize error: {}", err),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self {
        ConfigError::Parse(err)
    }
}

impl From<toml::ser::Error> for ConfigError {
    fn from(err: toml::ser::Error) -> Self {
        ConfigError::Serialize(err)
    }
}

fn default_download_dir() -> PathBuf {
    paths::default_download_dir()
}

fn default_listen_port() -> u16 {
    9150
}
