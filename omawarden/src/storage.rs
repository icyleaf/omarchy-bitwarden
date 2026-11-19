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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
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

impl VaultStorage {
    pub(crate) fn scoped_credential_id(&self) -> Option<&str> {
        self.credential_id
            .as_deref()
            .filter(|id| crate::credential_slots::valid_id(id))
    }

    pub(crate) fn has_login_metadata(&self) -> bool {
        !self.user_email.is_empty()
            || self.client_id.is_some()
            || self.enc_user_key.is_some()
            || self.access_token.is_some()
            || self.refresh_token.is_some()
    }

    /// Require a scoped credential reference before unlocking cached ciphertext.
    ///
    /// Offline unlock uses the encrypted cache and the master password. Remote
    /// requests resolve tokens separately, so a locked keyring does not block it.
    ///
    /// # Errors
    /// A missing or malformed reference requires a fresh sign-in.
    pub fn check_unlock_credentials(&self) -> Result<(), &'static str> {
        self.scoped_credential_id()
            .map(|_| ())
            .ok_or("Sign in again to use account-scoped credentials.")
    }

    pub(crate) fn same_account(&self, other: &Self) -> bool {
        self.server_url == other.server_url
            && self.user_email == other.user_email
            && self.user_id == other.user_id
            && self.enc_user_key == other.enc_user_key
    }

    pub(crate) fn same_active_slot(&self, other: &Self) -> bool {
        self.same_account(other)
            && self.identity_url == other.identity_url
            && self.credential_id == other.credential_id
    }

    pub(crate) fn credential_identity_url<'a>(
        &'a self,
        configured: Option<&'a str>,
    ) -> Option<&'a str> {
        // The identity endpoint is bound to the credential slot at login.
        if self.scoped_credential_id().is_some() {
            self.identity_url.as_deref()
        } else {
            configured.or(self.identity_url.as_deref())
        }
    }
}

#[derive(Debug, Clone)]
pub struct StorageManager {
    pub file_path: PathBuf,
    #[cfg(test)]
    pub(crate) fail_credential_cleanup_sync: bool,
}

/// Pins the original inode until commit, preventing inode reuse from passing
/// a stale comparison. All production cache writers replace the file atomically.
pub(crate) struct CacheSnapshot {
    pub(crate) storage: VaultStorage,
    source: Option<(fs::File, fs::Metadata)>,
    write_revision: Option<[u8; 16]>,
}

impl CacheSnapshot {
    /// Call under account_guard when using this as a commit precondition.
    pub(crate) fn is_current(&self, manager: &StorageManager) -> std::io::Result<bool> {
        if let Some(expected) = self.write_revision {
            let barrier = match manager.cipher_barrier() {
                Ok(barrier) => barrier,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) => return Err(error),
            };
            if StorageManager::current_write_revision(&barrier)? != expected {
                return Ok(false);
            }
        }
        use std::os::unix::fs::MetadataExt;
        match (&self.source, manager.file_path.metadata()) {
            (Some((_file, original)), Ok(current)) => Ok((
                original.dev(),
                original.ino(),
                original.len(),
                original.mtime(),
                original.mtime_nsec(),
                original.ctime(),
                original.ctime_nsec(),
            ) == (
                current.dev(),
                current.ino(),
                current.len(),
                current.mtime(),
                current.mtime_nsec(),
                current.ctime(),
                current.ctime_nsec(),
            )),
            (None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
            (_, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            (_, Err(e)) => Err(e),
            (None, Ok(_)) => Ok(false),
        }
    }
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
        Self::new(resolve_default_storage_path())
    }
}

impl StorageManager {
    pub fn new(path: PathBuf) -> Self {
        Self {
            file_path: path,
            #[cfg(test)]
            fail_credential_cleanup_sync: false,
        }
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

    /// Capture before remote work. Missing storage is valid for first login;
    /// unreadable or malformed storage must never become an empty snapshot.
    pub(crate) fn snapshot(&self) -> std::io::Result<CacheSnapshot> {
        let barrier = self.cipher_barrier()?;
        let revision = Self::current_write_revision(&barrier)?;
        let mut snapshot = self.cache_snapshot()?;
        snapshot.write_revision = Some(revision);
        Ok(snapshot)
    }

    // Local decryption and receipt edits pin the cached ciphertext, not a
    // remote response. They need a cache-version check, but must not wait for
    // HTTP writes: locking and re-unlocking cancels an old receipt separately.
    pub(crate) fn cache_snapshot(&self) -> std::io::Result<CacheSnapshot> {
        match fs::File::open(&self.file_path) {
            Ok(source) => {
                let metadata = source.metadata()?;
                let storage = serde_json::from_reader(std::io::BufReader::new(&source))?;
                Ok(CacheSnapshot {
                    storage,
                    source: Some((source, metadata)),
                    write_revision: None,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CacheSnapshot {
                storage: VaultStorage::default(),
                source: None,
                write_revision: None,
            }),
            Err(e) => Err(e),
        }
    }

    fn open_cipher_barrier(&self) -> std::io::Result<fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(parent) = self.file_path.parent() {
            crate::fs_util::create_secure_dir_all(parent, 0o700)?;
        }
        fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.file_path.with_extension("writes.lock"))
    }

    fn current_write_revision(file: &fs::File) -> std::io::Result<[u8; 16]> {
        use std::os::unix::fs::FileExt;
        let mut revision = [0; 16];
        match file.metadata()?.len() {
            0 => {}
            16 => file.read_exact_at(&mut revision, 0)?,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid cipher write revision",
                ))
            }
        }
        Ok(revision)
    }

    fn cipher_barrier(&self) -> std::io::Result<fs::File> {
        let barrier = self.open_cipher_barrier()?;
        barrier.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Cipher write in progress. Please retry synchronization.",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        Ok(barrier)
    }

    /// Shared operation marker, held through the HTTP request and receipt.
    /// It contains no secrets and never blocks lock(), which does not use it.
    /// Sync/login readers fail promptly while any request is outstanding.
    pub(crate) fn begin_cipher_write(&self) -> std::io::Result<fs::File> {
        use std::os::unix::fs::FileExt;
        let _account = self.account_guard()?;
        let barrier = self.open_cipher_barrier()?;
        barrier.try_lock_shared().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Vault snapshot in progress. Please retry the write.",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        Self::current_write_revision(&barrier)?;
        barrier.write_all_at(&rand::random::<[u8; 16]>(), 0)?;
        Ok(barrier)
    }

    /// Serialize outside the session critical section; persist only after
    /// validating the snapshot under account_guard. NamedTempFile uses 0600.
    pub(crate) fn stage(&self, data: &VaultStorage) -> std::io::Result<tempfile::NamedTempFile> {
        use std::io::{BufWriter, Write};
        let parent = self
            .file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent)?;
        {
            let mut writer = BufWriter::new(staged.as_file_mut());
            serde_json::to_writer_pretty(&mut writer, data)?;
            writer.flush()?;
        }
        Ok(staged)
    }

    pub(crate) fn sync_parent(&self) -> std::io::Result<()> {
        let parent = self
            .file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::File::open(parent)?.sync_all()
    }

    pub(crate) fn stage_durable(
        &self,
        data: &VaultStorage,
    ) -> std::io::Result<tempfile::NamedTempFile> {
        let staged = self.stage(data)?;
        staged.as_file().sync_all()?;
        Ok(staged)
    }

    /// Serialize credential replacement and revocation across CLI and daemon processes.
    /// Keep the lock file separate from data.json, whose inode changes on each save.
    pub(crate) fn account_guard(&self) -> std::io::Result<fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let parent = self
            .file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !parent.exists() {
            crate::fs_util::create_secure_dir_all(parent, 0o700)?;
        }
        let guard = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.file_path.with_extension("account.lock"))?;
        guard.lock()?;
        Ok(guard)
    }

    /// A writer must distinguish a missing or corrupt cache from an empty vault.
    pub(crate) fn load_existing(&self) -> std::io::Result<VaultStorage> {
        Ok(serde_json::from_reader(std::io::BufReader::new(
            fs::File::open(&self.file_path)?,
        ))?)
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
        let _lock = crate::env_lock();
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
