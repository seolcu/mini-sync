use std::env;
use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config").join("mini-sync")
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn state_dir() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", ".local/state").join("mini-sync")
}

pub fn log_dir() -> PathBuf {
    state_dir().join("logs")
}

pub fn default_download_dir() -> PathBuf {
    if let Some(home) = home_dir() {
        home.join("Downloads").join("mini-sync")
    } else {
        PathBuf::from("./downloads/mini-sync")
    }
}

fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    if let Some(value) = env::var_os(var) {
        PathBuf::from(value)
    } else if let Some(home) = home_dir() {
        home.join(fallback)
    } else {
        PathBuf::from(fallback)
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}
