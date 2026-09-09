use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_SERVER_URL: &str = "https://vault.bitwarden.com";
pub const DEFAULT_DOWNLOAD_DIR: &str = "~/Downloads";
pub const DEFAULT_AUTO_LOCK_MINUTES: i64 = 15;
pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: i64 = 30;
pub const DEFAULT_EMAIL: &str = "";
pub const DEFAULT_REMEMBER_EMAIL: bool = true;
pub const DEFAULT_LOG_LEVEL: &str = "error";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_server_url")]
    pub server_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    #[serde(default = "default_download_dir")]
    pub download_dir: String,
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: i64,
    #[serde(default = "default_clipboard_clear_seconds")]
    pub clipboard_clear_seconds: i64,
    #[serde(default = "default_email")]
    pub email: String,
    #[serde(default = "default_remember_email")]
    pub remember_email: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_server_url() -> String {
    DEFAULT_SERVER_URL.to_string()
}
fn default_download_dir() -> String {
    DEFAULT_DOWNLOAD_DIR.to_string()
}
fn default_auto_lock_minutes() -> i64 {
    DEFAULT_AUTO_LOCK_MINUTES
}
fn default_clipboard_clear_seconds() -> i64 {
    DEFAULT_CLIPBOARD_CLEAR_SECONDS
}
fn default_email() -> String {
    DEFAULT_EMAIL.to_string()
}
fn default_remember_email() -> bool {
    DEFAULT_REMEMBER_EMAIL
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            identity_url: None,
            download_dir: default_download_dir(),
            auto_lock_minutes: default_auto_lock_minutes(),
            clipboard_clear_seconds: default_clipboard_clear_seconds(),
            email: default_email(),
            remember_email: default_remember_email(),
            log_level: default_log_level(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConfigManager {
    pub config_path: PathBuf,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new(None)
    }
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
        let content = serde_json::to_string_pretty(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(&self.config_path, content)
    }

    pub fn update_config(
        &self,
        options: ConfigUpdateOptions,
        storage_mgr: &crate::storage::StorageManager,
        keyring_mgr: &crate::keyring::KeyringManager,
    ) -> std::io::Result<(Config, bool)> {
        let mut cfg = self.load();

        let old_server_norm = cfg.server_url.trim().trim_end_matches('/');
        let server_changed = if let Some(ref new_url) = options.server_url {
            let new_server_norm = new_url.trim().trim_end_matches('/');
            !new_server_norm.is_empty() && old_server_norm != new_server_norm
        } else {
            false
        };

        if let Some(v) = options.server_url {
            cfg.server_url = v.trim().to_string();
        }

        if server_changed {
            // Server address changed: purge identity_url (if not explicitly provided),
            // vault cache (data.json), keyring credentials (api_secret, access_token, refresh_token, session),
            // in-memory daemon state, and temporary preview attachments.
            // Note: Remembered login email (cfg.email) is preserved for user convenience.
            if options.identity_url.is_none() {
                cfg.identity_url = None;
            }

            if storage_mgr.file_path.exists() {
                let _ = fs::remove_file(&storage_mgr.file_path);
            }

            keyring_mgr.clear_all();
            keyring_mgr.clear_session();

            let _ = crate::daemon::send_daemon_request(&serde_json::json!({ "action": "stop" }));
            crate::attachment::clear_preview_attachments(None);

            crate::log_info!(
                "omawarden:config",
                "Bitwarden server URL changed to '{}'. Previous session, API credentials, and vault cache purged.",
                cfg.server_url
            );
        }

        if let Some(v) = options.identity_url {
            let trimmed = v.trim();
            if trimmed.is_empty() {
                cfg.identity_url = None;
            } else {
                cfg.identity_url = Some(trimmed.to_string());
            }
        }
        if let Some(v) = options.download_dir {
            cfg.download_dir = v;
        }
        if let Some(v) = options.auto_lock_minutes {
            cfg.auto_lock_minutes = v;
        }
        if let Some(v) = options.clipboard_clear_seconds {
            cfg.clipboard_clear_seconds = v;
        }
        if let Some(v) = options.email {
            cfg.email = v;
        }
        if let Some(v) = options.remember_email {
            cfg.remember_email = v;
        }
        if let Some(v) = options.log_level {
            cfg.log_level = v.to_lowercase();
        }

        self.save(&cfg)?;
        Ok((cfg, server_changed))
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConfigUpdateOptions {
    pub server_url: Option<String>,
    pub identity_url: Option<String>,
    pub download_dir: Option<String>,
    pub auto_lock_minutes: Option<i64>,
    pub clipboard_clear_seconds: Option<i64>,
    pub email: Option<String>,
    pub remember_email: Option<bool>,
    pub log_level: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
        assert_eq!(cfg.identity_url, None);
        assert_eq!(cfg.download_dir, DEFAULT_DOWNLOAD_DIR);
        assert_eq!(cfg.auto_lock_minutes, 15);
        assert_eq!(cfg.clipboard_clear_seconds, 30);
        assert_eq!(cfg.email, "");
        assert!(cfg.remember_email);
        assert_eq!(cfg.log_level, "error");
    }

    #[test]
    fn test_save_and_load_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mgr = ConfigManager::new(Some(&path));

        let cfg = Config {
            server_url: "https://custom.vaultwarden.local".to_string(),
            email: "test@example.com".to_string(),
            auto_lock_minutes: 60,
            remember_email: false,
            ..Default::default()
        };

        mgr.save(&cfg).unwrap();
        assert!(path.exists());

        let loaded = mgr.load();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn test_load_partial_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            r#"{"email": "partial@test.com", "auto_lock_minutes": 5}"#,
        )
        .unwrap();

        let mgr = ConfigManager::new(Some(&path));
        let loaded = mgr.load();
        assert_eq!(loaded.email, "partial@test.com");
        assert_eq!(loaded.auto_lock_minutes, 5);
        assert_eq!(loaded.server_url, DEFAULT_SERVER_URL);
        assert_eq!(loaded.identity_url, None);
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

    #[test]
    fn test_identity_url_serialization_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mgr = ConfigManager::new(Some(&path));

        let cfg = Config {
            server_url: "https://api.bitwarden.com".to_string(),
            identity_url: Some("https://identity.bitwarden.com".to_string()),
            ..Default::default()
        };

        mgr.save(&cfg).unwrap();
        let json_content = fs::read_to_string(&path).unwrap();
        assert!(json_content.contains("\"identity_url\": \"https://identity.bitwarden.com\""));

        let loaded = mgr.load();
        assert_eq!(loaded.server_url, "https://api.bitwarden.com");
        assert_eq!(
            loaded.identity_url,
            Some("https://identity.bitwarden.com".to_string())
        );

        // Test that skipping identity_url omits it from JSON when None
        let mut cfg_no_id = cfg;
        cfg_no_id.identity_url = None;
        mgr.save(&cfg_no_id).unwrap();
        let json_content_none = fs::read_to_string(&path).unwrap();
        assert!(!json_content_none.contains("\"identity_url\""));

        let loaded_none = mgr.load();
        assert_eq!(loaded_none.identity_url, None);
    }

    fn create_mock_secret_tool(dir: &std::path::Path) -> String {
        let script_path = dir.join("mock_secret_tool.sh");
        let store_dir = dir.join("keyring_store");
        let _ = fs::create_dir_all(&store_dir);

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift

key=""
while [ $# -gt 0 ]; do
    case "$1" in
        --*)
            shift 1
            ;;
        *)
            k="$1"
            v="$2"
            safe_v=$(printf '%s' "$v" | tr '/:' '_')
            key="${{key}}__${{k}}=${{safe_v}}"
            shift 2 2>/dev/null || shift 1
            ;;
    esac
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        fs::write(&script_path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&script_path, perms);
        }
        script_path.to_str().unwrap().to_string()
    }

    #[test]
    fn test_server_url_change_purges_credentials_and_cache() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path.clone());
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        // 1. Initial state on official vault server
        let initial_cfg = Config {
            server_url: "https://vault.bitwarden.com".to_string(),
            email: "user@example.com".to_string(),
            ..Default::default()
        };
        config_mgr.save(&initial_cfg).unwrap();

        let initial_storage = crate::storage::VaultStorage {
            server_url: "https://vault.bitwarden.com".to_string(),
            user_email: "user@example.com".to_string(),
            client_id: Some("user.test-api-key-id".to_string()),
            access_token: Some("old-access-token".to_string()),
            refresh_token: Some("old-refresh-token".to_string()),
            ciphers: vec![serde_json::json!({"id": "cipher-1", "name": "Google"})],
            ..Default::default()
        };
        storage_mgr.save(&initial_storage).unwrap();

        assert!(keyring_mgr.store_token("access_token", "old-access-token"));
        assert!(keyring_mgr.store_api_secret(
            "https://vault.bitwarden.com",
            "user.test-api-key-id",
            "old-api-secret"
        ));

        assert_eq!(config_mgr.load().email, "user@example.com");
        assert!(storage_path.exists());
        assert!(keyring_mgr.get_token("access_token").is_some());
        assert!(keyring_mgr
            .get_api_secret("https://vault.bitwarden.com", "user.test-api-key-id")
            .is_some());

        // 2. Change server_url to a different server
        let (updated_cfg, server_changed) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    server_url: Some("https://vaultwarden.custom.corp".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();

        // 3. Assert server_changed is true and previous session/tokens/data cache are purged,
        // but remembered email in config.json is preserved
        assert!(server_changed, "Server change must be detected");
        assert_eq!(
            updated_cfg.email, "user@example.com",
            "Remembered email in config.json must be preserved when server changes"
        );
        assert!(
            !storage_path.exists(),
            "data.json cache file must be deleted when server changes"
        );
        assert!(
            keyring_mgr.get_token("access_token").is_none(),
            "Session/token in keyring must be cleared when server changes"
        );
        assert!(
            keyring_mgr
                .get_api_secret("https://vault.bitwarden.com", "user.test-api-key-id")
                .is_none(),
            "API secret in keyring must be cleared when server changes"
        );
    }

    #[test]
    fn test_same_server_url_preserves_credentials_and_cache() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path.clone());
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let initial_cfg = Config {
            server_url: "https://vault.bitwarden.com".to_string(),
            email: "user@example.com".to_string(),
            auto_lock_minutes: 15,
            ..Default::default()
        };
        config_mgr.save(&initial_cfg).unwrap();

        let initial_storage = crate::storage::VaultStorage {
            server_url: "https://vault.bitwarden.com".to_string(),
            user_email: "user@example.com".to_string(),
            client_id: Some("user.test-api-key-id".to_string()),
            access_token: Some("valid-token".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&initial_storage).unwrap();
        assert!(keyring_mgr.store_token("access_token", "valid-token"));

        // Update other settings, with same server_url (even with trailing slash)
        let (updated_cfg, server_changed) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    server_url: Some("https://vault.bitwarden.com/".to_string()),
                    auto_lock_minutes: Some(30),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();

        assert!(!server_changed, "Same server URL must not trigger purge");
        assert_eq!(updated_cfg.email, "user@example.com");
        assert_eq!(updated_cfg.auto_lock_minutes, 30);
        assert!(storage_path.exists());
        assert_eq!(
            keyring_mgr.get_token("access_token"),
            Some("valid-token".to_string())
        );
    }
}
