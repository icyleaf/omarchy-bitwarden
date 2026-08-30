use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_SERVER_URL: &str = "https://vault.bitwarden.com";
pub const DEFAULT_BW_PATH: &str = "bw";
pub const DEFAULT_DOWNLOAD_DIR: &str = "~/Downloads";
pub const DEFAULT_AUTO_LOCK_MINUTES: i64 = 15;
pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: i64 = 30;
pub const DEFAULT_MAX_OUTPUT_MB: i64 = 10;
pub const DEFAULT_EMAIL: &str = "";
pub const DEFAULT_REMEMBER_EMAIL: bool = true;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_server_url")]
    pub server_url: String,
    #[serde(default = "default_bw_path")]
    pub bw_path: String,
    #[serde(default = "default_download_dir")]
    pub download_dir: String,
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: i64,
    #[serde(default = "default_clipboard_clear_seconds")]
    pub clipboard_clear_seconds: i64,
    #[serde(default = "default_max_output_mb")]
    pub max_output_mb: i64,
    #[serde(default = "default_email")]
    pub email: String,
    #[serde(default = "default_remember_email")]
    pub remember_email: bool,
}

fn default_server_url() -> String { DEFAULT_SERVER_URL.to_string() }
fn default_bw_path() -> String { DEFAULT_BW_PATH.to_string() }
fn default_download_dir() -> String { DEFAULT_DOWNLOAD_DIR.to_string() }
fn default_auto_lock_minutes() -> i64 { DEFAULT_AUTO_LOCK_MINUTES }
fn default_clipboard_clear_seconds() -> i64 { DEFAULT_CLIPBOARD_CLEAR_SECONDS }
fn default_max_output_mb() -> i64 { DEFAULT_MAX_OUTPUT_MB }
fn default_email() -> String { DEFAULT_EMAIL.to_string() }
fn default_remember_email() -> bool { DEFAULT_REMEMBER_EMAIL }

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            bw_path: default_bw_path(),
            download_dir: default_download_dir(),
            auto_lock_minutes: default_auto_lock_minutes(),
            clipboard_clear_seconds: default_clipboard_clear_seconds(),
            max_output_mb: default_max_output_mb(),
            email: default_email(),
            remember_email: default_remember_email(),
        }
    }
}

pub struct ConfigManager {
    pub config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(custom_path: Option<&Path>) -> Self {
        let config_path = match custom_path {
            Some(p) => p.to_path_buf(),
            None => {
                let xdg_config = env::var("XDG_CONFIG_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
                        PathBuf::from(home).join(".config")
                    });
                xdg_config
                    .join("omarchy")
                    .join("plugins")
                    .join("icyleaf.bitwarden")
                    .join("config.json")
            }
        };
        Self { config_path }
    }

    pub fn load(&self) -> Config {
        if !self.config_path.exists() {
            return Config::default();
        }
        match fs::read_to_string(&self.config_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Config::default(),
        }
    }

    pub fn save(&self, config: &Config) -> std::io::Result<()> {
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(config).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        fs::write(&self.config_path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
        assert_eq!(cfg.bw_path, DEFAULT_BW_PATH);
        assert_eq!(cfg.download_dir, DEFAULT_DOWNLOAD_DIR);
        assert_eq!(cfg.auto_lock_minutes, 15);
        assert_eq!(cfg.clipboard_clear_seconds, 30);
        assert_eq!(cfg.max_output_mb, 10);
        assert_eq!(cfg.email, "");
        assert!(cfg.remember_email);
    }

    #[test]
    fn test_save_and_load_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mgr = ConfigManager::new(Some(&path));

        let mut cfg = Config::default();
        cfg.server_url = "https://custom.vaultwarden.local".to_string();
        cfg.email = "test@example.com".to_string();
        cfg.auto_lock_minutes = 60;
        cfg.remember_email = false;

        mgr.save(&cfg).unwrap();
        assert!(path.exists());

        let loaded = mgr.load();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn test_load_partial_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"email": "partial@test.com", "auto_lock_minutes": 5}"#).unwrap();

        let mgr = ConfigManager::new(Some(&path));
        let loaded = mgr.load();
        assert_eq!(loaded.email, "partial@test.com");
        assert_eq!(loaded.auto_lock_minutes, 5);
        assert_eq!(loaded.server_url, DEFAULT_SERVER_URL);
        assert_eq!(loaded.bw_path, DEFAULT_BW_PATH);
        assert!(loaded.remember_email);
    }

    #[test]
    fn test_load_malformed_json_fallback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "{ invalid json ").unwrap();

        let mgr = ConfigManager::new(Some(&path));
        let loaded = mgr.load();
        assert_eq!(loaded, Config::default());
    }
}
