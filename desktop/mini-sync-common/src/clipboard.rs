use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardState {
    pub clip_id: String,
    pub sender_device_id: String,
    pub timestamp_ms: u64,
    pub text_hash: String,
}

impl ClipboardState {
    pub fn load_optional(path: &Path) -> Result<Option<Self>, ClipboardStateError> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Some(toml::from_str(&contents)?)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(ClipboardStateError::Io(err)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ClipboardStateError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ClipboardStateError {
    Io(io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
}

impl fmt::Display for ClipboardStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClipboardStateError::Io(err) => write!(f, "io error: {}", err),
            ClipboardStateError::Parse(err) => write!(f, "parse error: {}", err),
            ClipboardStateError::Serialize(err) => write!(f, "serialize error: {}", err),
        }
    }
}

impl std::error::Error for ClipboardStateError {}

impl From<io::Error> for ClipboardStateError {
    fn from(err: io::Error) -> Self {
        ClipboardStateError::Io(err)
    }
}

impl From<toml::de::Error> for ClipboardStateError {
    fn from(err: toml::de::Error) -> Self {
        ClipboardStateError::Parse(err)
    }
}

impl From<toml::ser::Error> for ClipboardStateError {
    fn from(err: toml::ser::Error) -> Self {
        ClipboardStateError::Serialize(err)
    }
}
