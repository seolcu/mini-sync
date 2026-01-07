use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingSession {
    pub version: u8,
    pub device_id: String,
    pub device_name: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    pub port: u16,
    pub token: String,
    pub code: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub capabilities: Vec<String>,
}

impl PairingSession {
    pub fn load(path: &Path) -> Result<Self, PairingError> {
        let contents = fs::read_to_string(path)?;
        let session = toml::from_str(&contents)?;
        Ok(session)
    }

    pub fn load_optional(path: &Path) -> Result<Option<Self>, PairingError> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(toml::from_str(&contents)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(PairingError::Io(err)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), PairingError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        set_private_permissions(path)?;
        Ok(())
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

#[derive(Debug)]
pub enum PairingError {
    Io(io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
    Permission(String),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PairingError::Io(err) => write!(f, "io error: {}", err),
            PairingError::Parse(err) => write!(f, "parse error: {}", err),
            PairingError::Serialize(err) => write!(f, "serialize error: {}", err),
            PairingError::Permission(err) => write!(f, "permission error: {}", err),
        }
    }
}

impl std::error::Error for PairingError {}

impl From<io::Error> for PairingError {
    fn from(err: io::Error) -> Self {
        PairingError::Io(err)
    }
}

impl From<toml::de::Error> for PairingError {
    fn from(err: toml::de::Error) -> Self {
        PairingError::Parse(err)
    }
}

impl From<toml::ser::Error> for PairingError {
    fn from(err: toml::ser::Error) -> Self {
        PairingError::Serialize(err)
    }
}

fn set_private_permissions(path: &Path) -> Result<(), PairingError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(PairingError::Io)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|err| PairingError::Permission(err.to_string()))?;
    }
    Ok(())
}
