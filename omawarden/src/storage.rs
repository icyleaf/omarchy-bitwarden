use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::crypto::{derive_master_key, EncString, KdfType, SymmetricCryptoKey};

pub const DEFAULT_STORAGE_FILENAME: &str = "data.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultStorage {
    #[serde(default)]
    pub server_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_url: Option<String>,
    #[serde(default)]
    pub user_email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub access_token: Option<String>,
    #[serde(default, skip_serializing)]
    pub refresh_token: Option<String>,
    pub kdf: Option<u32>,
    pub kdf_iterations: Option<u32>,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub enc_user_key: Option<String>,
    pub enc_private_key: Option<String>,
    pub last_sync: Option<String>,
    #[serde(default)]
    pub folders: Vec<Value>,
    #[serde(default)]
    pub organizations: Vec<Value>,
    #[serde(default)]
    pub collections: Vec<Value>,
    #[serde(default)]
    pub ciphers: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct StorageManager {
    pub file_path: PathBuf,
}

pub fn resolve_legacy_storage_path() -> PathBuf {
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
        .join(DEFAULT_STORAGE_FILENAME)
}

pub fn migrate_legacy_storage_file(legacy_path: &Path, target_path: &Path) {
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

pub fn resolve_default_storage_path() -> PathBuf {
    if let Ok(custom_dir) = env::var("OMAWARDEN_DATA_DIR") {
        if !custom_dir.trim().is_empty() {
            return PathBuf::from(custom_dir.trim()).join(DEFAULT_STORAGE_FILENAME);
        }
    }

    let xdg_data = env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".local").join("share")
        });
    let target_path = xdg_data.join("omawarden").join(DEFAULT_STORAGE_FILENAME);
    let legacy_path = resolve_legacy_storage_path();

    migrate_legacy_storage_file(&legacy_path, &target_path);

    target_path
}

impl Default for StorageManager {
    fn default() -> Self {
        Self {
            file_path: resolve_default_storage_path(),
        }
    }
}

impl StorageManager {
    pub fn new(path: PathBuf) -> Self {
        Self { file_path: path }
    }

    pub fn load(&self) -> VaultStorage {
        if !self.file_path.exists() {
            return VaultStorage::default();
        }
        match fs::read_to_string(&self.file_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => VaultStorage::default(),
        }
    }

    pub fn save(&self, data: &VaultStorage) -> std::io::Result<()> {
        if let Some(parent) = self.file_path.parent() {
            crate::fs_util::create_secure_dir_all(parent, 0o700)?;
        }
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        crate::fs_util::atomic_write_str(&self.file_path, &content, 0o600)
    }

    pub fn unlock_user_key(
        &self,
        password: &str,
        storage: &VaultStorage,
    ) -> Result<SymmetricCryptoKey, crate::crypto::CryptoError> {
        let enc_user_key = storage.enc_user_key.as_ref().ok_or_else(|| {
            crate::crypto::CryptoError::InvalidEncString("Missing user key".to_string())
        })?;

        let kdf_type = KdfType::from(storage.kdf.unwrap_or(0));
        let iterations = storage.kdf_iterations.unwrap_or(600_000);

        let master_key = derive_master_key(
            &storage.user_email,
            password,
            kdf_type,
            iterations,
            storage.kdf_memory,
            storage.kdf_parallelism,
        )?;

        let parsed_enc_key = EncString::parse(enc_user_key)?;
        let decrypted_raw_user_key =
            SymmetricCryptoKey::decrypt_with_master_key(&parsed_enc_key, &master_key)?;

        SymmetricCryptoKey::from_raw_bytes(&decrypted_raw_user_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_save_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_storage.json");
        let mgr = StorageManager::new(path);

        let storage = VaultStorage {
            user_email: "tester@domain.com".to_string(),
            server_url: "https://vaultwarden.local".to_string(),
            identity_url: Some("https://identity.vaultwarden.local".to_string()),
            client_id: Some("user.12345678".to_string()),
            ..Default::default()
        };

        mgr.save(&storage).unwrap();
        let loaded = mgr.load();
        assert_eq!(loaded.user_email, "tester@domain.com");
        assert_eq!(loaded.server_url, "https://vaultwarden.local");
        assert_eq!(
            loaded.identity_url,
            Some("https://identity.vaultwarden.local".to_string())
        );
        assert_eq!(loaded.client_id, Some("user.12345678".to_string()));
    }

    #[test]
    fn test_storage_save_file_and_dir_permissions() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempdir().unwrap();
            let sub_dir = dir.path().join("nested_vault");
            let path = sub_dir.join("data.json");
            let mgr = StorageManager::new(path.clone());

            let storage = VaultStorage {
                user_email: "sec@domain.com".to_string(),
                server_url: "https://vault.example.com".to_string(),
                ..Default::default()
            };

            mgr.save(&storage).unwrap();

            // Check file permissions (must be 0600)
            let file_meta = fs::metadata(&path).unwrap();
            assert_eq!(
                file_meta.permissions().mode() & 0o777,
                0o600,
                "data.json must be created with 0600 permissions"
            );

            // Check parent directory permissions (must be 0700)
            let dir_meta = fs::metadata(&sub_dir).unwrap();
            assert_eq!(
                dir_meta.permissions().mode() & 0o777,
                0o700,
                "Parent directory must be restricted to 0700"
            );
        }
    }

    #[test]
    fn test_storage_tokens_never_serialized_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("data.json");
        let mgr = StorageManager::new(path.clone());

        let storage = VaultStorage {
            user_email: "notokens@domain.com".to_string(),
            server_url: "https://vault.example.com".to_string(),
            access_token: Some("secret_access_token_12345".to_string()),
            refresh_token: Some("secret_refresh_token_67890".to_string()),
            ..Default::default()
        };

        mgr.save(&storage).unwrap();

        // Read raw JSON string from disk directly
        let raw = fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("access_token"),
            "access_token must never appear in saved data.json"
        );
        assert!(
            !raw.contains("refresh_token"),
            "refresh_token must never appear in saved data.json"
        );
        assert!(
            !raw.contains("secret_access_token_12345"),
            "Bearer token value must never be written to disk"
        );
        assert!(
            !raw.contains("secret_refresh_token_67890"),
            "Refresh token value must never be written to disk"
        );
    }

    #[test]
    fn test_default_storage_path_not_in_watched_plugin_directory() {
        let storage_mgr = StorageManager::default();
        let path_str = storage_mgr.file_path.to_string_lossy();
        assert!(
            !path_str.contains("omarchy/plugins"),
            "Storage file path must not reside inside watched omarchy/plugins directory, was: {}",
            path_str
        );
        assert!(
            path_str.ends_with("omawarden/data.json"),
            "Storage file path must end with omawarden/data.json, was: {}",
            path_str
        );
    }

    #[test]
    fn test_migrate_legacy_storage_file_moves_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_dir = dir.path().join("legacy");
        fs::create_dir_all(&legacy_dir).unwrap();
        let legacy_file = legacy_dir.join("data.json");
        fs::write(
            &legacy_file,
            "{\"server_url\":\"https://vault.example.com\"}",
        )
        .unwrap();

        let target_dir = dir.path().join("target");
        let target_file = target_dir.join("data.json");

        assert!(legacy_file.exists());
        assert!(!target_file.exists());

        migrate_legacy_storage_file(&legacy_file, &target_file);

        assert!(
            !legacy_file.exists(),
            "Legacy file must be removed after migration"
        );
        assert!(
            target_file.exists(),
            "Target file must exist after migration"
        );

        let content = fs::read_to_string(&target_file).unwrap();
        assert_eq!(content, "{\"server_url\":\"https://vault.example.com\"}");

        let metadata = fs::metadata(&target_file).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Migrated file must have 0600 permissions");
    }

    #[test]
    fn test_migrate_legacy_storage_cleans_up_when_target_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_file = dir.path().join("legacy.json");
        fs::write(&legacy_file, "{\"old\":true}").unwrap();

        let target_file = dir.path().join("target.json");
        fs::write(&target_file, "{\"new\":true}").unwrap();

        migrate_legacy_storage_file(&legacy_file, &target_file);

        assert!(!legacy_file.exists(), "Legacy file must be cleaned up");
        assert!(target_file.exists(), "Target file must be preserved");
        let content = fs::read_to_string(&target_file).unwrap();
        assert_eq!(content, "{\"new\":true}");
    }
}
