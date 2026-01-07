use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub device_id: String,
    pub public_key: String,
    pub secret_key: String,
    #[serde(default)]
    pub dh_public_key: Option<String>,
    #[serde(default)]
    pub dh_secret_key: Option<String>,
}

impl Identity {
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let contents = fs::read_to_string(path)?;
        let identity: Identity = toml::from_str(&contents)?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn load_optional(path: &Path) -> Result<Option<Self>, IdentityError> {
        match fs::read_to_string(path) {
            Ok(contents) => {
                let identity: Identity = toml::from_str(&contents)?;
                identity.validate()?;
                Ok(Some(identity))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(IdentityError::Io(err)),
        }
    }

    pub fn load_or_generate(path: &Path) -> Result<Self, IdentityError> {
        match Self::load_optional(path)? {
            Some(mut identity) => {
                let mut changed = false;
                if identity.ensure_dh_keys()? {
                    changed = true;
                }
                if changed {
                    identity.save(path)?;
                }
                Ok(identity)
            }
            None => {
                let identity = Self::generate();
                identity.save(path)?;
                Ok(identity)
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents)?;
        set_private_permissions(path)?;
        Ok(())
    }

    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let secret_key = STANDARD.encode(signing_key.to_bytes());
        let public_key = STANDARD.encode(verifying_key.to_bytes());
        let (dh_public_key, dh_secret_key) = generate_dh_keypair();
        Self {
            device_id: uuid::Uuid::new_v4().to_string(),
            public_key,
            secret_key,
            dh_public_key: Some(dh_public_key),
            dh_secret_key: Some(dh_secret_key),
        }
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32], IdentityError> {
        let bytes = STANDARD
            .decode(&self.public_key)
            .map_err(|err| IdentityError::InvalidKey(err.to_string()))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("public key length".to_string()))?;
        Ok(array)
    }

    pub fn secret_key_bytes(&self) -> Result<[u8; 32], IdentityError> {
        let bytes = STANDARD
            .decode(&self.secret_key)
            .map_err(|err| IdentityError::InvalidKey(err.to_string()))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("secret key length".to_string()))?;
        Ok(array)
    }

    pub fn dh_public_key_bytes(&self) -> Result<[u8; 32], IdentityError> {
        let Some(value) = &self.dh_public_key else {
            return Err(IdentityError::InvalidKey("missing dh public key".to_string()));
        };
        let bytes = STANDARD
            .decode(value)
            .map_err(|err| IdentityError::InvalidKey(err.to_string()))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("dh public key length".to_string()))?;
        Ok(array)
    }

    pub fn dh_secret_key_bytes(&self) -> Result<[u8; 32], IdentityError> {
        let Some(value) = &self.dh_secret_key else {
            return Err(IdentityError::InvalidKey("missing dh secret key".to_string()));
        };
        let bytes = STANDARD
            .decode(value)
            .map_err(|err| IdentityError::InvalidKey(err.to_string()))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKey("dh secret key length".to_string()))?;
        Ok(array)
    }

    fn ensure_dh_keys(&mut self) -> Result<bool, IdentityError> {
        let has_public = self.dh_public_key.is_some();
        let has_secret = self.dh_secret_key.is_some();
        if has_public && has_secret {
            self.validate_dh_keys()?;
            return Ok(false);
        }
        if has_public || has_secret {
            return Err(IdentityError::InvalidKey(
                "incomplete dh keypair".to_string(),
            ));
        }
        let (dh_public_key, dh_secret_key) = generate_dh_keypair();
        self.dh_public_key = Some(dh_public_key);
        self.dh_secret_key = Some(dh_secret_key);
        Ok(true)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        let secret = self.secret_key_bytes()?;
        let public = self.public_key_bytes()?;
        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        if verifying_key.to_bytes() != public {
            return Err(IdentityError::InvalidKey(
                "public key does not match secret key".to_string(),
            ));
        }
        self.validate_dh_keys()?;
        Ok(())
    }

    fn validate_dh_keys(&self) -> Result<(), IdentityError> {
        let has_public = self.dh_public_key.is_some();
        let has_secret = self.dh_secret_key.is_some();
        if !has_public && !has_secret {
            return Ok(());
        }
        if !(has_public && has_secret) {
            return Err(IdentityError::InvalidKey(
                "incomplete dh keypair".to_string(),
            ));
        }
        let secret = self.dh_secret_key_bytes()?;
        let public = self.dh_public_key_bytes()?;
        let secret = StaticSecret::from(secret);
        let derived = X25519PublicKey::from(&secret).to_bytes();
        if derived != public {
            return Err(IdentityError::InvalidKey(
                "dh public key does not match secret key".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IdentityError {
    Io(io::Error),
    Parse(toml::de::Error),
    Serialize(toml::ser::Error),
    InvalidKey(String),
    Permission(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Io(err) => write!(f, "io error: {}", err),
            IdentityError::Parse(err) => write!(f, "parse error: {}", err),
            IdentityError::Serialize(err) => write!(f, "serialize error: {}", err),
            IdentityError::InvalidKey(err) => write!(f, "invalid key: {}", err),
            IdentityError::Permission(err) => write!(f, "permission error: {}", err),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<io::Error> for IdentityError {
    fn from(err: io::Error) -> Self {
        IdentityError::Io(err)
    }
}

impl From<toml::de::Error> for IdentityError {
    fn from(err: toml::de::Error) -> Self {
        IdentityError::Parse(err)
    }
}

impl From<toml::ser::Error> for IdentityError {
    fn from(err: toml::ser::Error) -> Self {
        IdentityError::Serialize(err)
    }
}

fn set_private_permissions(path: &Path) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(IdentityError::Io)?
            .permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|err| IdentityError::Permission(err.to_string()))?;
    }
    Ok(())
}

fn generate_dh_keypair() -> (String, String) {
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = X25519PublicKey::from(&secret);
    let secret_key = STANDARD.encode(secret.to_bytes());
    let public_key = STANDARD.encode(public.to_bytes());
    (public_key, secret_key)
}
