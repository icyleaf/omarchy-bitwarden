use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::crypto::{derive_master_key, EncString, KdfType, SymmetricCryptoKey};

pub const DEFAULT_STORAGE_FILENAME: &str = "data.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultStorage {
    pub server_url: String,
    pub user_email: String,
    pub user_id: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub kdf: Option<u32>,
    pub kdf_iterations: Option<u32>,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
    pub enc_user_key: Option<String>,
    pub enc_private_key: Option<String>,
    pub last_sync: Option<String>,
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
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        fs::write(&self.file_path, content)
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
            ..Default::default()
        };

        mgr.save(&storage).unwrap();
        let loaded = mgr.load();
        assert_eq!(loaded.user_email, "tester@domain.com");
        assert_eq!(loaded.server_url, "https://vaultwarden.local");
    }
}
