use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;

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

impl Default for StorageManager {
    fn default() -> Self {
        let xdg_config = env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
                PathBuf::from(home).join(".config")
            });
        let file_path = xdg_config
            .join("omarchy")
            .join("plugins")
            .join("icyleaf.bitwarden")
            .join(DEFAULT_STORAGE_FILENAME);
        Self { file_path }
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
}
