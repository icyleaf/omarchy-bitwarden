use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_FILENAME: &str = "config.json";
pub const DEFAULT_SERVER_URL: &str = "https://vault.bitwarden.com";
pub const DEFAULT_DOWNLOAD_DIR: &str = "~/Downloads";
pub const DEFAULT_AUTO_LOCK_MINUTES: i64 = 15;
pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: i64 = 30;
pub const DEFAULT_EMAIL: &str = "";
pub const DEFAULT_REMEMBER_EMAIL: bool = true;
pub const DEFAULT_CHECK_UPDATES: bool = true;
pub const DEFAULT_LOG_LEVEL: &str = "error";
pub const DEFAULT_SHOW_WEBSITE_ICONS: bool = true;
pub const DEFAULT_REMEMBER_LAST_SEARCH: bool = false;
pub const DEFAULT_MAX_ATTACHMENT_SIZE_MB: u64 = 500;

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
    #[serde(default = "default_check_updates")]
    pub check_updates: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_show_website_icons")]
    pub show_website_icons: bool,
    #[serde(default = "default_remember_last_search")]
    pub remember_last_search: bool,
    #[serde(default = "default_max_attachment_size_mb")]
    pub max_attachment_size_mb: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_cert_server: Option<String>,
    /// Serve the vault's SSH keys on $XDG_RUNTIME_DIR/omawarden-ssh-agent.sock.
    #[serde(default)]
    pub ssh_agent_enabled: bool,
    /// When to confirm signatures: "always", "first-use" (until logout) or "never".
    #[serde(default = "default_ssh_agent_confirm")]
    pub ssh_agent_confirm: String,
    /// ADR-0025: retain the user key across soft locks and require a polkit
    /// check (system password / fingerprint) instead of the master password.
    #[serde(default)]
    pub quick_unlock: bool,
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
fn default_check_updates() -> bool {
    DEFAULT_CHECK_UPDATES
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}
fn default_show_website_icons() -> bool {
    DEFAULT_SHOW_WEBSITE_ICONS
}
fn default_remember_last_search() -> bool {
    DEFAULT_REMEMBER_LAST_SEARCH
}
fn default_ssh_agent_confirm() -> String {
    "first-use".to_string()
}
fn default_max_attachment_size_mb() -> u64 {
    DEFAULT_MAX_ATTACHMENT_SIZE_MB
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
            check_updates: default_check_updates(),
            log_level: default_log_level(),
            show_website_icons: default_show_website_icons(),
            remember_last_search: default_remember_last_search(),
            max_attachment_size_mb: default_max_attachment_size_mb(),
            client_cert_path: None,
            client_key_path: None,
            client_cert_server: None,
            ssh_agent_enabled: false,
            ssh_agent_confirm: default_ssh_agent_confirm(),
            quick_unlock: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConfigManager {
    pub config_path: PathBuf,
}

pub fn resolve_legacy_config_path() -> PathBuf {
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
        .join(DEFAULT_CONFIG_FILENAME)
}

pub fn migrate_legacy_config_file(legacy_path: &Path, target_path: &Path) {
    if legacy_path != target_path && legacy_path.exists() {
        if !target_path.exists() {
            if let Some(parent) = target_path.parent() {
                let _ = crate::fs_util::create_secure_dir_all(parent, 0o700);
            }
            if fs::rename(legacy_path, target_path).is_err()
                && fs::copy(legacy_path, target_path).is_ok()
            {
                let _ = fs::remove_file(legacy_path);
            }
            let _ = fs::set_permissions(target_path, fs::Permissions::from_mode(0o600));
        } else {
            let _ = fs::remove_file(legacy_path);
        }
    }
}

pub fn resolve_default_config_path() -> PathBuf {
    if let Ok(custom_dir) = env::var("OMAWARDEN_CONFIG_DIR") {
        if !custom_dir.trim().is_empty() {
            return PathBuf::from(custom_dir.trim()).join(DEFAULT_CONFIG_FILENAME);
        }
    }

    let xdg_config = env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });
    let target_path = xdg_config.join("omawarden").join(DEFAULT_CONFIG_FILENAME);
    let legacy_path = resolve_legacy_config_path();

    migrate_legacy_config_file(&legacy_path, &target_path);

    target_path
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
            None => resolve_default_config_path(),
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
            crate::fs_util::create_secure_dir_all(parent, 0o700)?;
        }
        let content = serde_json::to_string_pretty(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        crate::fs_util::atomic_write_str(&self.config_path, &content, 0o600)
    }

    pub fn validate_url_scheme_security(url_str: &str, field_name: &str) -> std::io::Result<()> {
        let trimmed = url_str.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let norm = if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            format!("https://{}", trimmed)
        } else {
            trimmed.to_string()
        };

        if let Ok(parsed) = url::Url::parse(&norm) {
            let host = parsed.host_str().unwrap_or("");
            if parsed.scheme() == "http" && !crate::api::is_loopback_host(host) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Insecure {} '{}': Plaintext HTTP is only permitted for local loopback addresses (localhost, 127.0.0.1, [::1]). Remote servers must use HTTPS.",
                        field_name, trimmed
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn update_config(
        &self,
        options: ConfigUpdateOptions,
        storage_mgr: &crate::storage::StorageManager,
        keyring_mgr: &crate::keyring::KeyringManager,
    ) -> std::io::Result<(Config, bool)> {
        let mut cfg = self.load();

        if let Some(ref v) = options.server_url {
            Self::validate_url_scheme_security(v, "server_url")?;
        }
        if let Some(ref v) = options.identity_url {
            Self::validate_url_scheme_security(v, "identity_url")?;
        }
        // Checked before anything is purged for a server change, so a bad
        // value can't leave the settings half applied.
        if let Some(ref v) = options.ssh_agent_confirm {
            if !matches!(v.as_str(), "always" | "first-use" | "never") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("ssh_agent_confirm must be always, first-use or never (got {v:?})"),
                ));
            }
        }

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
            keyring_mgr.clear_session(&cfg.server_url);

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
        if let Some(v) = options.check_updates {
            cfg.check_updates = v;
        }
        if let Some(v) = options.log_level {
            cfg.log_level = v.to_lowercase();
        }
        if let Some(v) = options.show_website_icons {
            cfg.show_website_icons = v;
        }
        if let Some(v) = options.remember_last_search {
            cfg.remember_last_search = v;
        }
        if let Some(v) = options.ssh_agent_enabled {
            cfg.ssh_agent_enabled = v;
        }
        if let Some(v) = options.ssh_agent_confirm {
            cfg.ssh_agent_confirm = v;
        }
        if let Some(v) = options.quick_unlock {
            cfg.quick_unlock = v;
            if !v {
                // Turning the feature off must not leave a retained key behind.
                crate::daemon::send_daemon_request(&serde_json::json!({
                    "action": "wipe_quick_unlock"
                }));
            }
        }
        if let Some(v) = options.max_attachment_size_mb {
            cfg.max_attachment_size_mb = v;
        }

        if let Some(ref cert_path) = options.client_cert_path {
            let trimmed = cert_path.trim();
            if trimmed.is_empty() {
                cfg.client_cert_path = None;
                cfg.client_key_path = None;
                cfg.client_cert_server = None;
            } else {
                cfg.client_cert_path = Some(trimmed.to_string());
                // Automatically bind client_cert_server to the RFC 6454 origin of server_url
                if let Ok(u) = url::Url::parse(&cfg.server_url) {
                    let port_suffix = match u.port() {
                        Some(p) => format!(":{}", p),
                        None => String::new(),
                    };
                    cfg.client_cert_server = Some(format!(
                        "{}://{}{}",
                        u.scheme(),
                        u.host_str().unwrap_or(""),
                        port_suffix
                    ));
                } else {
                    cfg.client_cert_server = Some(cfg.server_url.clone());
                }
            }
        }

        if let Some(ref key_path) = options.client_key_path {
            let trimmed_key = key_path.trim();
            if trimmed_key.is_empty() {
                cfg.client_key_path = None;
            } else {
                cfg.client_key_path = Some(trimmed_key.to_string());
            }
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
    pub check_updates: Option<bool>,
    pub log_level: Option<String>,
    pub show_website_icons: Option<bool>,
    pub remember_last_search: Option<bool>,
    pub max_attachment_size_mb: Option<u64>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub ssh_agent_enabled: Option<bool>,
    pub ssh_agent_confirm: Option<String>,
    pub quick_unlock: Option<bool>,
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
        assert!(!cfg.remember_last_search);
        assert_eq!(cfg.max_attachment_size_mb, 500);
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
        assert_eq!(loaded.max_attachment_size_mb, 500);
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

        crate::write_test_executable(&script_path, script);
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

        assert!(keyring_mgr.store_token(
            "https://vault.bitwarden.com",
            "access_token",
            "old-access-token"
        ));
        assert!(keyring_mgr.store_api_secret(
            "https://vault.bitwarden.com",
            "user.test-api-key-id",
            "old-api-secret"
        ));

        assert_eq!(config_mgr.load().email, "user@example.com");
        assert!(storage_path.exists());
        assert!(keyring_mgr
            .get_token("https://vault.bitwarden.com", "access_token")
            .is_some());
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
            keyring_mgr
                .get_token("https://vault.bitwarden.com", "access_token")
                .is_none(),
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
        assert!(keyring_mgr.store_token(
            "https://vault.bitwarden.com",
            "access_token",
            "valid-token"
        ));

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
            keyring_mgr.get_token("https://vault.bitwarden.com", "access_token"),
            Some("valid-token".to_string())
        );
    }

    #[test]
    fn test_check_updates_default_and_update() {
        assert!(Config::default().check_updates);

        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(dir.path().join("data.json"));
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let (updated_cfg, _server_changed) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    check_updates: Some(false),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert!(!updated_cfg.check_updates);

        // Round-trips through config.json
        assert!(!ConfigManager::new(Some(&config_path)).load().check_updates);

        // Existing configs written before this key existed keep the default
        let legacy_path = dir.path().join("legacy.json");
        fs::write(&legacy_path, r#"{"email": "legacy@test.com"}"#).unwrap();
        assert!(ConfigManager::new(Some(&legacy_path)).load().check_updates);
    }

    #[test]
    fn test_show_website_icons_default_and_update() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        assert!(Config::default().show_website_icons);

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path);
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let (updated_cfg, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    show_website_icons: Some(false),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert!(!updated_cfg.show_website_icons);

        // Persisted to disk
        let reloaded = ConfigManager::new(Some(&config_path)).load();
        assert!(!reloaded.show_website_icons);

        // Upgrade path: config written before the key existed must default to true
        let legacy_path = dir.path().join("legacy.json");
        fs::write(&legacy_path, r#"{"email": "legacy@test.com"}"#).unwrap();
        let legacy = ConfigManager::new(Some(&legacy_path)).load();
        assert!(legacy.show_website_icons);
    }

    #[test]
    fn test_remember_last_search_default_and_update() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        assert!(!Config::default().remember_last_search);

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path);
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let (updated_cfg, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    remember_last_search: Some(true),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert!(updated_cfg.remember_last_search);

        // Persisted to disk
        let reloaded = ConfigManager::new(Some(&config_path)).load();
        assert!(reloaded.remember_last_search);

        // Upgrade path: config written before the key existed must default to false
        let legacy_path = dir.path().join("legacy.json");
        fs::write(&legacy_path, r#"{"email": "legacy@test.com"}"#).unwrap();
        let legacy = ConfigManager::new(Some(&legacy_path)).load();
        assert!(!legacy.remember_last_search);
    }

    #[test]
    fn test_max_attachment_size_mb_default_and_update() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        assert_eq!(Config::default().max_attachment_size_mb, 500);

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path);
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let (updated_cfg, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    max_attachment_size_mb: Some(100),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert_eq!(updated_cfg.max_attachment_size_mb, 100);

        // Persisted to disk
        let reloaded = ConfigManager::new(Some(&config_path)).load();
        assert_eq!(reloaded.max_attachment_size_mb, 100);

        // Upgrade path: config written before the key existed must default to 500
        let legacy_path = dir.path().join("legacy.json");
        fs::write(&legacy_path, r#"{"email": "legacy@test.com"}"#).unwrap();
        let legacy = ConfigManager::new(Some(&legacy_path)).load();
        assert_eq!(legacy.max_attachment_size_mb, 500);
    }

    #[test]
    fn test_validate_url_scheme_security() {
        // Valid secure or loopback URLs
        assert!(ConfigManager::validate_url_scheme_security(
            "https://vault.bitwarden.com",
            "server_url"
        )
        .is_ok());
        assert!(ConfigManager::validate_url_scheme_security(
            "https://vaultwarden.custom.corp",
            "server_url"
        )
        .is_ok());
        assert!(
            ConfigManager::validate_url_scheme_security("http://localhost:8080", "server_url")
                .is_ok()
        );
        assert!(
            ConfigManager::validate_url_scheme_security("http://127.0.0.1:8080", "server_url")
                .is_ok()
        );
        assert!(
            ConfigManager::validate_url_scheme_security("http://[::1]:8080", "server_url").is_ok()
        );
        assert!(ConfigManager::validate_url_scheme_security(
            "vaultwarden.custom.corp",
            "server_url"
        )
        .is_ok());
        assert!(ConfigManager::validate_url_scheme_security("", "server_url").is_ok());

        // Insecure plaintext HTTP remote URLs rejected
        let err = ConfigManager::validate_url_scheme_security(
            "http://vaultwarden.custom.corp",
            "server_url",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err
            .to_string()
            .contains("Plaintext HTTP is only permitted for local loopback"));

        let err = ConfigManager::validate_url_scheme_security(
            "http://192.168.1.100:8080",
            "identity_url",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err
            .to_string()
            .contains("Plaintext HTTP is only permitted for local loopback"));
    }

    #[test]
    fn test_update_config_rejects_insecure_remote_http() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path);
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let res = config_mgr.update_config(
            ConfigUpdateOptions {
                server_url: Some("http://vaultwarden.remote.corp".to_string()),
                ..Default::default()
            },
            &storage_mgr,
            &keyring_mgr,
        );
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("Remote servers must use HTTPS"));
    }

    #[test]
    fn test_update_config_ssh_agent_settings() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path.clone());
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        let (cfg, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    log_level: Some("DEBUG".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert_eq!(cfg.log_level, "debug", "log levels are normalised");

        let defaults = config_mgr.load();
        assert!(!defaults.ssh_agent_enabled);
        assert_eq!(defaults.ssh_agent_confirm, "first-use");

        for confirm in ["always", "first-use", "never"] {
            let (cfg, _) = config_mgr
                .update_config(
                    ConfigUpdateOptions {
                        ssh_agent_enabled: Some(true),
                        ssh_agent_confirm: Some(confirm.to_string()),
                        ..Default::default()
                    },
                    &storage_mgr,
                    &keyring_mgr,
                )
                .unwrap();
            assert!(cfg.ssh_agent_enabled);
            assert_eq!(cfg.ssh_agent_confirm, confirm);
            assert_eq!(config_mgr.load().ssh_agent_confirm, confirm);
        }

        let (cfg, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    ssh_agent_enabled: Some(false),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert!(!cfg.ssh_agent_enabled);
        assert_eq!(cfg.ssh_agent_confirm, "never", "left alone when not given");
    }

    #[test]
    fn test_update_config_rejects_unknown_ssh_agent_confirm_before_any_purge() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path.clone());
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);
        fs::write(&storage_path, "{}").unwrap();

        // Also changes the server, which would purge the vault cache.
        let err = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    server_url: Some("https://vault.example.org".to_string()),
                    ssh_agent_confirm: Some("Always".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("ssh_agent_confirm"));
        assert!(storage_path.exists(), "the vault cache was not purged");
        assert_eq!(config_mgr.load().ssh_agent_confirm, "first-use");
        assert_eq!(config_mgr.load().server_url, default_server_url());
    }

    #[test]
    fn test_default_config_path_not_in_watched_plugin_directory() {
        let config_mgr = ConfigManager::default();
        let path_str = config_mgr.config_path.to_string_lossy();
        assert!(
            !path_str.contains("omarchy/plugins"),
            "Config file path must not reside inside watched omarchy/plugins directory, was: {}",
            path_str
        );
        assert!(
            path_str.ends_with("omawarden/config.json"),
            "Config file path must end with omawarden/config.json, was: {}",
            path_str
        );
    }

    #[test]
    fn test_migrate_legacy_config_file_moves_existing_data() {
        let dir = tempdir().unwrap();
        let legacy_dir = dir.path().join("legacy");
        fs::create_dir_all(&legacy_dir).unwrap();
        let legacy_file = legacy_dir.join("config.json");
        fs::write(
            &legacy_file,
            "{\"server_url\":\"https://vault.example.com\"}",
        )
        .unwrap();

        let target_dir = dir.path().join("target");
        let target_file = target_dir.join("config.json");

        assert!(legacy_file.exists());
        assert!(!target_file.exists());

        migrate_legacy_config_file(&legacy_file, &target_file);

        assert!(
            !legacy_file.exists(),
            "Legacy config file must be removed after migration"
        );
        assert!(
            target_file.exists(),
            "Target config file must exist after migration"
        );

        let content = fs::read_to_string(&target_file).unwrap();
        assert_eq!(content, "{\"server_url\":\"https://vault.example.com\"}");

        let metadata = fs::metadata(&target_file).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Migrated config file must have 0600 permissions"
        );
    }

    #[test]
    fn test_migrate_legacy_config_cleans_up_when_target_already_exists() {
        let dir = tempdir().unwrap();
        let legacy_file = dir.path().join("legacy.json");
        fs::write(&legacy_file, "{\"old\":true}").unwrap();

        let target_file = dir.path().join("target.json");
        fs::write(&target_file, "{\"new\":true}").unwrap();

        migrate_legacy_config_file(&legacy_file, &target_file);

        assert!(
            !legacy_file.exists(),
            "Stale legacy config file must be deleted when target already exists"
        );
        assert!(target_file.exists());
        let content = fs::read_to_string(&target_file).unwrap();
        assert_eq!(content, "{\"new\":true}");
    }

    #[test]
    fn test_mtls_client_cert_configuration_lifecycle() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let storage_path = dir.path().join("data.json");
        let mock_script = create_mock_secret_tool(dir.path());

        let config_mgr = ConfigManager::new(Some(&config_path));
        let storage_mgr = crate::storage::StorageManager::new(storage_path);
        let keyring_mgr = crate::keyring::KeyringManager::new(&mock_script);

        // 1. Set server_url to custom vaultwarden instance
        let (cfg, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    server_url: Some("https://vault.mycorp.internal:8443".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert_eq!(cfg.server_url, "https://vault.mycorp.internal:8443");
        assert_eq!(cfg.client_cert_path, None);
        assert_eq!(cfg.client_key_path, None);
        assert_eq!(cfg.client_cert_server, None);

        // 2. Set client_cert and client_key -> should record and bind client_cert_server origin
        let (cfg_with_cert, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    client_cert_path: Some("/home/user/.certs/client.crt".to_string()),
                    client_key_path: Some("/home/user/.certs/client.key".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert_eq!(
            cfg_with_cert.client_cert_path.as_deref(),
            Some("/home/user/.certs/client.crt")
        );
        assert_eq!(
            cfg_with_cert.client_key_path.as_deref(),
            Some("/home/user/.certs/client.key")
        );
        assert_eq!(
            cfg_with_cert.client_cert_server.as_deref(),
            Some("https://vault.mycorp.internal:8443")
        );

        // 3. Server URL change: per ADR 0023, mTLS cert path and bound origin must be PRESERVED
        let (cfg_switched, server_changed) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    server_url: Some("https://vault.bitwarden.com".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert!(server_changed);
        assert_eq!(cfg_switched.server_url, "https://vault.bitwarden.com");
        assert_eq!(
            cfg_switched.client_cert_path.as_deref(),
            Some("/home/user/.certs/client.crt")
        );
        assert_eq!(
            cfg_switched.client_key_path.as_deref(),
            Some("/home/user/.certs/client.key")
        );
        assert_eq!(
            cfg_switched.client_cert_server.as_deref(),
            Some("https://vault.mycorp.internal:8443")
        );

        // 4. Setting client_cert to empty string clears client_cert_path, client_key_path, and client_cert_server
        let (cfg_cleared, _) = config_mgr
            .update_config(
                ConfigUpdateOptions {
                    client_cert_path: Some("".to_string()),
                    ..Default::default()
                },
                &storage_mgr,
                &keyring_mgr,
            )
            .unwrap();
        assert_eq!(cfg_cleared.client_cert_path, None);
        assert_eq!(cfg_cleared.client_key_path, None);
        assert_eq!(cfg_cleared.client_cert_server, None);
    }
}
