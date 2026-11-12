use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::RwLock;

use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::{
    parse_rsa_private_key_der, parse_symmetric_key_from_decrypted_bytes, EncString,
    SymmetricCryptoKey,
};
use crate::keyring::KeyringManager;
use crate::storage::{StorageManager, VaultStorage};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SshMetadata {
    pub is_ssh_key: bool,
    pub key_type: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: i64,
    pub type_name: String,
    pub sub_title: String,
    pub notes: Option<String>,
    pub favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<SshMetadata>,
    #[serde(default)]
    pub fields: Vec<Value>,
    #[serde(default)]
    pub attachments: Vec<Value>,
    pub search_text: String,
}

#[derive(Debug, Clone)]
pub enum CipherTargetResolution {
    Exact(Box<VaultItem>),
    Ambiguous(Vec<VaultItem>),
    NotFound(String),
}

pub fn is_fuzzy_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let p_lower = pattern.to_lowercase();
    let t_lower = text.to_lowercase();
    if t_lower.contains(&p_lower) {
        return true;
    }

    let p_chars: Vec<char> = p_lower.chars().collect();
    let mut p_idx = 0;
    for c in t_lower.chars() {
        if c == p_chars[p_idx] {
            p_idx += 1;
            if p_idx == p_chars.len() {
                return true;
            }
        }
    }
    false
}

pub fn detect_ssh_key_metadata(raw: &Value) -> Option<SshMetadata> {
    let notes = raw.get("notes").and_then(|v| v.as_str()).unwrap_or("");
    let fields = raw.get("fields").and_then(|v| v.as_array());

    let mut private_key: Option<String> = None;
    let mut public_key: Option<String> = None;
    let mut passphrase: Option<String> = None;
    let mut key_type = "SSH".to_string();

    let priv_re = Regex::new(
        r"(-----BEGIN (?:[A-Z0-9_ -]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_ -]+ )?PRIVATE KEY-----)",
    )
    .unwrap();
    if let Some(caps) = priv_re.captures(notes) {
        let matched = caps.get(1).unwrap().as_str().trim().to_string();
        if matched.contains("BEGIN OPENSSH PRIVATE KEY") {
            key_type = if matched.contains("ssh-ed25519") {
                "ED25519".to_string()
            } else {
                "OPENSSH".to_string()
            };
        } else if matched.contains("BEGIN RSA PRIVATE KEY") {
            key_type = "RSA".to_string();
        } else if matched.contains("BEGIN EC PRIVATE KEY") {
            key_type = "ECDSA".to_string();
        } else if matched.contains("BEGIN DSA PRIVATE KEY") {
            key_type = "DSA".to_string();
        } else {
            key_type = "PKCS8".to_string();
        }
        private_key = Some(matched);
    }

    let pub_re = Regex::new(
        r"((?:ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-[a-z0-9]+)\s+[A-Za-z0-9+/=.]+(?:\s+.*)?)",
    )
    .unwrap();
    if let Some(caps) = pub_re.captures(notes) {
        let matched = caps.get(1).unwrap().as_str().trim().to_string();
        if matched.contains("ssh-ed25519") {
            key_type = "ED25519".to_string();
        } else if matched.contains("ssh-rsa") {
            key_type = "RSA".to_string();
        } else if matched.contains("ecdsa-sha2") {
            key_type = "ECDSA".to_string();
        } else if matched.contains("ssh-dss") {
            key_type = "DSA".to_string();
        }
        public_key = Some(matched);
    }

    if let Some(field_arr) = fields {
        for f in field_arr {
            let fname = f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let fval = f
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if fval.is_empty() {
                continue;
            }

            if matches!(
                fname.as_str(),
                "private_key"
                    | "privatekey"
                    | "ssh_private_key"
                    | "id_rsa"
                    | "id_ed25519"
                    | "id_ecdsa"
            ) || fval.contains("PRIVATE KEY-----")
            {
                if private_key.is_none() || fval.contains("BEGIN") {
                    if fval.contains("RSA") {
                        key_type = "RSA".to_string();
                    } else if fval.contains("OPENSSH") {
                        key_type = if fval.contains("ed25519") {
                            "ED25519".to_string()
                        } else {
                            "OPENSSH".to_string()
                        };
                    } else if fval.contains("EC") {
                        key_type = "ECDSA".to_string();
                    } else if fval.contains("DSA") {
                        key_type = "DSA".to_string();
                    } else if fval.contains("PRIVATE KEY") {
                        key_type = "PKCS8".to_string();
                    }
                    private_key = Some(fval);
                } else if private_key.is_none() {
                    private_key = Some(fval);
                }
            } else if matches!(
                fname.as_str(),
                "public_key" | "publickey" | "ssh_public_key" | "ssh_key"
            ) || fval.starts_with("ssh-rsa ")
                || fval.starts_with("ssh-ed25519 ")
                || fval.starts_with("ecdsa-sha2-")
            {
                if fval.contains("ssh-ed25519") {
                    key_type = "ED25519".to_string();
                } else if fval.contains("ssh-rsa") {
                    key_type = "RSA".to_string();
                } else if fval.contains("ecdsa") {
                    key_type = "ECDSA".to_string();
                }
                public_key = Some(fval);
            } else if matches!(
                fname.as_str(),
                "passphrase" | "pass_phrase" | "key_passphrase" | "ssh_passphrase"
            ) {
                passphrase = Some(fval);
            }
        }
    }

    if private_key.is_some() || public_key.is_some() {
        Some(SshMetadata {
            is_ssh_key: true,
            key_type,
            private_key,
            public_key,
            fingerprint: None,
            passphrase,
        })
    } else {
        None
    }
}

pub fn parse_ssh_key_fields(
    private_key: Option<String>,
    public_key: Option<String>,
    fingerprint: Option<String>,
) -> SshMetadata {
    let mut key_type = "SSH".to_string();
    if let Some(ref pk) = public_key {
        if pk.contains("ssh-ed25519") {
            key_type = "ED25519".to_string();
        } else if pk.contains("ssh-rsa") {
            key_type = "RSA".to_string();
        } else if pk.contains("ecdsa") {
            key_type = "ECDSA".to_string();
        } else if pk.contains("ssh-dss") {
            key_type = "DSA".to_string();
        }
    } else if let Some(ref prk) = private_key {
        if prk.contains("OPENSSH") {
            key_type = if prk.contains("ed25519") {
                "ED25519".to_string()
            } else {
                "OPENSSH".to_string()
            };
        } else if prk.contains("RSA") {
            key_type = "RSA".to_string();
        } else if prk.contains("EC") {
            key_type = "ECDSA".to_string();
        } else if prk.contains("DSA") {
            key_type = "DSA".to_string();
        }
    }

    SshMetadata {
        is_ssh_key: true,
        key_type,
        private_key,
        public_key,
        fingerprint,
        passphrase: None,
    }
}

pub struct VaultManager {
    pub server_url: String,
    pub identity_url: Option<String>,
    pub storage_mgr: StorageManager,
    pub keyring_mgr: KeyringManager,
    pub storage: RwLock<VaultStorage>,
    pub decrypted_items: RwLock<Vec<VaultItem>>,
    pub user_key: RwLock<Option<SymmetricCryptoKey>>,
    pub is_unlocked: RwLock<bool>,
    /// ADR-0025: user key retained across soft locks so a polkit check can
    /// re-unlock without the master password. Never leaves mlocked memory.
    pub quick_unlock_key: RwLock<Option<SymmetricCryptoKey>>,
    /// Bumped on every quick-unlock wipe. quick_unlock_restore samples it
    /// before decrypting and aborts if a wipe landed mid-restore, so a hard
    /// lock racing a restore can never be overridden.
    pub quick_unlock_epoch: std::sync::atomic::AtomicU64,
    /// Bumped on account activation and when an unlocked vault locks.
    lock_generation: std::sync::atomic::AtomicU64,
    /// `enc_user_key` as it was when the key was retained. That wrapping is
    /// unique per account *and* per master password, so comparing it on
    /// restore proves the retained key still belongs to this vault even when
    /// there is nothing to decrypt-test (an empty vault with no wrapped
    /// private key). Ciphertext, not a secret; cleared with the slot.
    pub quick_unlock_user_key_wrap: RwLock<Option<String>>,
    /// The epoch check alone leaves a window: a wipe could land between the
    /// final re-check and the four unlocked-state writes, and the restore
    /// would overwrite it (vault left unlocked, ceiling disarmed). Held by
    /// `wipe_quick_unlock` for its whole body and by the restore's final
    /// commit section (which re-checks the epoch under the guard), making
    /// wipe-vs-restore mutually exclusive at the commit point.
    pub restore_guard: std::sync::Mutex<()>,
    /// Tests that assert epoch transitions run concurrently with tests that
    /// lock other vaults. Pin their epoch file to a private directory instead
    /// of sharing the process-wide runtime directory.
    #[cfg(test)]
    pub(crate) lock_epoch_dir: Option<std::path::PathBuf>,
    #[cfg(test)]
    pub(crate) before_unlock_publication: crate::test_support::PausePoint,
    #[cfg(test)]
    pub(crate) cache_validated: crate::test_support::PausePoint,
    #[cfg(test)]
    pub(crate) before_activation_persist: std::sync::OnceLock<fn(&tempfile::NamedTempFile)>,
}

/// Outcome of a lock transition. `lock_epoch` is `Some` only when the shared
/// epoch was durably advanced, so a caller can fall back instead of claiming
/// that queued offline outputs were invalidated.
pub(crate) struct VaultLockOutcome {
    pub(crate) outputs_cleared: bool,
    pub(crate) lock_epoch: Option<u64>,
}

impl VaultManager {
    pub fn new(
        server_url: &str,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
    ) -> Self {
        Self::with_identity_url(server_url, None, storage_mgr, keyring_mgr)
    }

    pub fn with_identity_url(
        server_url: &str,
        identity_url: Option<&str>,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
    ) -> Self {
        let sm = storage_mgr.unwrap_or_default();
        let storage = sm.load();
        let effective_url = if server_url.is_empty() {
            storage.server_url.clone()
        } else {
            server_url.to_string()
        };
        let effective_identity_url = if let Some(id) = identity_url {
            let id_trim = id.trim();
            if !id_trim.is_empty() {
                Some(id_trim.to_string())
            } else {
                None
            }
        } else if server_url.is_empty() || server_url == storage.server_url {
            storage.identity_url.clone()
        } else {
            None
        };

        Self {
            server_url: effective_url,
            identity_url: effective_identity_url,
            storage_mgr: sm,
            keyring_mgr: keyring_mgr.unwrap_or_default(),
            storage: RwLock::new(storage),
            decrypted_items: RwLock::new(Vec::new()),
            user_key: RwLock::new(None),
            is_unlocked: RwLock::new(false),
            quick_unlock_key: RwLock::new(None),
            quick_unlock_epoch: std::sync::atomic::AtomicU64::new(0),
            // Clients compare generations across daemon restarts as well as soft locks.
            lock_generation: std::sync::atomic::AtomicU64::new(rand::random::<u64>() >> 1),
            quick_unlock_user_key_wrap: RwLock::new(None),
            restore_guard: std::sync::Mutex::new(()),
            #[cfg(test)]
            lock_epoch_dir: None,
            #[cfg(test)]
            before_unlock_publication: Default::default(),
            #[cfg(test)]
            cache_validated: Default::default(),
            #[cfg(test)]
            before_activation_persist: Default::default(),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked.read().map(|g| *g).unwrap_or(false)
    }

    /// Which account and lock cycle the vault is in.
    pub fn lock_generation(&self) -> u64 {
        self.lock_generation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn output_session(&self) -> Option<crate::daemon::OutputSession> {
        let unlocked = self.is_unlocked.read().ok()?;
        if !*unlocked {
            return None;
        }
        let storage = self.storage.read().ok()?;
        Some(crate::daemon::OutputSession {
            lock_generation: self.lock_generation(),
            credential_id: storage.scoped_credential_id()?.to_owned(),
        })
    }

    fn purge_decrypted_state(&self) -> VaultLockOutcome {
        let mut unlocked = self.is_unlocked.write().unwrap_or_else(|e| e.into_inner());
        if *unlocked {
            self.lock_generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        *unlocked = false;
        if let Ok(mut items) = self.decrypted_items.write() {
            items.clear();
        }
        if let Ok(mut key) = self.user_key.write() {
            *key = None;
        }
        drop(unlocked);
        let _outputs = match crate::daemon::lock_session_outputs() {
            Ok(outputs) => outputs,
            Err(error) => {
                crate::log_warn!(
                    "omawarden:vault",
                    "Vault locked. Cannot secure output revocation. {error}"
                );
                return VaultLockOutcome {
                    outputs_cleared: false,
                    lock_epoch: None,
                };
            }
        };
        // Advance before cleanup: a pending offline copy must be rejected even
        // when clipboard or preview revocation fails.
        #[cfg(test)]
        let epoch_store = match self.lock_epoch_dir.as_deref() {
            Some(dir) => crate::lock_epoch::LockEpochStore::new(dir),
            None => crate::lock_epoch::store(),
        };
        #[cfg(not(test))]
        let epoch_store = crate::lock_epoch::store();
        let lock_epoch = match epoch_store.advance() {
            Ok(epoch) => Some(epoch.value()),
            Err(error) => {
                crate::log_warn!(
                    "omawarden:vault",
                    "Vault locked, but the shared output epoch could not be advanced. {error}"
                );
                None
            }
        };
        let outputs_cleared = match crate::clipboard::clear_session_outputs() {
            Ok(()) => true,
            Err(error) => {
                crate::log_warn!(
                    "omawarden:vault",
                    "Vault locked. Session output cleanup is pending. {error}"
                );
                false
            }
        };
        VaultLockOutcome {
            outputs_cleared,
            lock_epoch,
        }
    }

    /// Full lock: purges decrypted state AND the quick-unlock slot. This is
    /// the fail-safe default — retention happens only through soft_lock().
    pub fn lock(&self) {
        let _restore = self.restore_guard.lock().unwrap_or_else(|e| e.into_inner());
        self.hard_lock_inner();
    }

    /// Revoke the current plaintext and retained key under restore_guard.
    pub(crate) fn hard_lock_inner(&self) -> VaultLockOutcome {
        self.wipe_quick_unlock_inner();
        self.purge_decrypted_state()
    }

    pub(crate) fn activate_account(
        &self,
        base: &crate::storage::CacheSnapshot,
        replacement: VaultStorage,
        expected_context: &str,
        reset_session: impl FnOnce(),
    ) -> Result<Option<String>, String> {
        use crate::account_activation::SESSION_CHANGED;
        let id = replacement
            .scoped_credential_id()
            .ok_or("Invalid login credential ID")?
            .to_owned();
        let staged = self
            .storage_mgr
            .stage_durable(&replacement)
            .map_err(|_| "Cannot stage the account cache")?;
        let account = self
            .storage_mgr
            .account_guard()
            .map_err(|_| "Cannot secure the account cache")?;
        if !base.is_current(&self.storage_mgr).unwrap_or(false) {
            return Err("Vault cache changed during login. Sign in again.".into());
        }
        let retire_legacy =
            base.storage.scoped_credential_id().is_none() && base.storage.has_login_metadata();
        self.storage_mgr
            .remember_credentials(&base.storage, retire_legacy)
            .map_err(|_| "Cannot track the previous credentials")?;

        let context = {
            let _restore = self
                .restore_guard
                .lock()
                .map_err(|_| "Vault state unavailable")?;
            if self.unlock_context() != expected_context {
                return Err(SESSION_CHANGED.into());
            }
            let _outputs = crate::daemon::lock_session_outputs()
                .map_err(|_| "Cannot secure output from the previous vault session")?;
            if self.is_unlocked()
                && !self
                    .storage
                    .read()
                    .is_ok_and(|storage| storage.same_active_slot(&base.storage))
            {
                return Err(SESSION_CHANGED.into());
            }
            // Revoke outputs before rename, including when the daemon dies
            // before sending its receipt. A failed rename can clear outputs
            // while leaving the previous account active.
            crate::clipboard::clear_session_outputs().map_err(|error| {
                format!("Could not clear the previous vault outputs. Retry sign-in after clearing them. {error}")
            })?;
            {
                let mut unlocked = self
                    .is_unlocked
                    .write()
                    .map_err(|_| "Vault state unavailable")?;
                let mut storage = self
                    .storage
                    .write()
                    .map_err(|_| "Vault state unavailable")?;
                let mut items = self
                    .decrypted_items
                    .write()
                    .map_err(|_| "Vault state unavailable")?;
                let mut key = self
                    .user_key
                    .write()
                    .map_err(|_| "Vault state unavailable")?;
                let mut retained = self
                    .quick_unlock_key
                    .write()
                    .map_err(|_| "Vault state unavailable")?;
                let mut binding = self
                    .quick_unlock_user_key_wrap
                    .write()
                    .map_err(|_| "Vault state unavailable")?;
                #[cfg(test)]
                if let Some(hook) = self.before_activation_persist.get() {
                    hook(&staged);
                }
                staged
                    .persist(&self.storage_mgr.file_path)
                    .map_err(|_| "Cannot save the account cache")?;
                // Once rename succeeds, readers must see B locked even if the directory fsync fails.
                *unlocked = false;
                self.lock_generation
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.quick_unlock_epoch
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                items.clear();
                *key = None;
                *retained = None;
                *binding = None;
                *storage = replacement;
            }
            reset_session();
            self.unlock_context()
        };
        let retired = self.storage_mgr.retired_credentials(Some(&id));
        drop(account);
        match retired {
            Ok(slots) => {
                if let Err(error) = crate::credential_slots::erase_retired(slots, &self.keyring_mgr)
                {
                    crate::log_warn!(
                        "omawarden:auth",
                        "Account published. Previous credential cleanup pending. {error}"
                    );
                }
                Ok(Some(context))
            }
            Err(error) => {
                crate::log_warn!(
                    "omawarden:auth",
                    "Account published. Previous credential cleanup pending. {error}"
                );
                Ok(None)
            }
        }
    }

    /// Soft lock (ADR-0025): purge everything a hard lock purges, except the
    /// user key, which moves to the quick-unlock slot so a later polkit check
    /// can restore the session. Reports whether a key was retained.
    pub fn soft_lock(&self) -> bool {
        // restore_guard makes retention mutually exclusive with the quick
        // unlock restore commit in both directions: without it, the key move
        // and purge below could interleave with the restore's writes and
        // leave the vault flagged unlocked with no items and no user key
        // (recoverable only by locking again). Same lock as
        // wipe_quick_unlock; see quick_unlock_restore for the commit side.
        let _restore = match self.restore_guard.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Read the binding before taking the key lock, so the lock order is
        // always user_key -> slot -> wrap (see wipe_quick_unlock).
        let account_wrap = self
            .storage
            .read()
            .ok()
            .and_then(|s| s.enc_user_key.clone());
        let retained = match self.user_key.write() {
            Ok(mut src) => {
                let taken = src.take();
                let had = taken.is_some();
                if let Ok(mut slot) = self.quick_unlock_key.write() {
                    // Keep a previously retained key if this call had nothing
                    // to move (called on an already-locked vault): dropping
                    // retention would be a surprising side effect.
                    if had || slot.is_none() {
                        *slot = taken;
                        let has_key = slot.is_some();
                        if let Ok(mut wrap) = self.quick_unlock_user_key_wrap.write() {
                            *wrap = if has_key { account_wrap } else { None };
                        }
                    }
                }
                had
            }
            Err(_) => false,
        };
        self.purge_decrypted_state();
        if retained {
            crate::log_info!(
                "omawarden:vault",
                "Soft-locked vault; user key retained for quick unlock."
            );
        }
        retained
    }

    /// Hard lock: everything lock() does (explicit alias for readability at
    /// ADR-0025 call sites: suspend, max session lifetime, explicit lock,
    /// three failed polkit checks, server/account change).
    pub fn hard_lock(&self) {
        self.lock();
    }

    pub fn quick_unlock_available(&self) -> bool {
        self.quick_unlock_key
            .read()
            .map(|slot| slot.is_some())
            .unwrap_or(false)
    }

    pub fn wipe_quick_unlock(&self) {
        // restore_guard makes this wipe mutually exclusive with the
        // restore's final commit section (see quick_unlock_restore).
        let _restore = match self.restore_guard.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.wipe_quick_unlock_inner();
    }

    pub(crate) fn wipe_quick_unlock_inner(&self) {
        self.quick_unlock_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Ok(mut slot) = self.quick_unlock_key.write() {
            // Dropping the LockedMemory-backed key zeroizes its page.
            *slot = None;
            if let Ok(mut wrap) = self.quick_unlock_user_key_wrap.write() {
                *wrap = None;
            }
        }
    }

    fn discard_retained_key(&self, expected: &str) {
        let _restore = self.restore_guard.lock().unwrap_or_else(|e| e.into_inner());
        if self.unlock_context() == expected {
            self.wipe_quick_unlock_inner();
        }
    }

    /// Re-unlock from the retained key (ADR-0025): same decryption path as
    /// unlock(), minus the master-password KDF. The slot keeps its key
    /// untouched; a wipe landing mid-restore aborts via the epoch guard and
    /// the restore_guard mutex (the final commit re-checks the epoch under
    /// the same guard wipe_quick_unlock holds) instead of being silently
    /// overridden.
    pub fn quick_unlock_restore(&self) -> Result<usize, String> {
        self.quick_unlock_restore_in_context(&self.unlock_context())
    }

    pub(crate) fn quick_unlock_restore_in_context(&self, expected: &str) -> Result<usize, String> {
        if self.unlock_context() != expected {
            return Err("Vault session changed during quick unlock.".into());
        }
        let key = {
            let slot = self
                .quick_unlock_key
                .read()
                .map_err(|_| "Quick unlock slot unavailable".to_string())?;
            slot.clone()
        }
        .ok_or_else(|| "No key retained for quick unlock".to_string())?;

        let base = self
            .storage_mgr
            .cache_snapshot()
            .map_err(|e| format!("Cannot read the vault cache: {e}"))?;
        let fresh_storage = &base.storage;
        if let Err(error) = fresh_storage.check_unlock_credentials() {
            self.discard_retained_key(expected);
            return Err(error.into());
        }
        if !self
            .storage
            .read()
            .is_ok_and(|s| s.scoped_credential_id() == fresh_storage.scoped_credential_id())
        {
            self.discard_retained_key(expected);
            return Err(
                "The retained key no longer matches this vault; unlock with the master password."
                    .into(),
            );
        }
        if fresh_storage.enc_user_key.is_none() {
            return Err("Account not logged in or missing encryption keys.".to_string());
        }

        let items = decrypt_sync_ciphers_with_context(
            &fresh_storage.ciphers,
            &fresh_storage.folders,
            &fresh_storage.organizations,
            &key,
            fresh_storage.enc_private_key.as_deref(),
        );
        let count = items.len();

        // Fail closed on a stale key (server-side rotation, password change
        // elsewhere, account switch while soft-locked): decryption failures
        // fall back to "Untitled" names, so the vault would otherwise look
        // unlocked with garbage content. Validation, strongest first:
        // 1. enc_private_key is wrapped under the user key (type 0..=2) and
        //    must decrypt;
        // 2. otherwise (absent, unparseable or asymmetric), at least one
        //    personal cipher must expose a field that decrypts under the
        //    user key: its own item key or its name (both EncStrings under
        //    the user key; the item key decrypts to raw bytes, not UTF-8).
        //    Personal ciphers that all carry item keys still validate; only
        //    org wrappers are skipped.
        let mut validated_by_private_key = false;
        if let Some(enc_priv) = fresh_storage.enc_private_key.as_deref() {
            if let Ok(parsed) = crate::crypto::EncString::parse(enc_priv) {
                if parsed.enc_type <= 2 {
                    validated_by_private_key = true;
                    if parsed.decrypt(&key).is_err() {
                        crate::log_warn!(
                            "omawarden:vault",
                            "Retained key fails to decrypt the private key; wiping quick unlock"
                        );
                        self.discard_retained_key(expected);
                        return Err("The retained key no longer matches this vault; unlock with the master password.".to_string());
                    }
                }
            }
        }
        if !validated_by_private_key {
            let mut candidates = 0usize;
            let mut decrypted_any = false;
            for c in &fresh_storage.ciphers {
                let deleted = c
                    .get("deletedDate")
                    .or_else(|| c.get("DeletedDate"))
                    .map(|v| !v.is_null())
                    .unwrap_or(false);
                if deleted
                    || c.get("organizationId")
                        .map(|v| !v.is_null())
                        .unwrap_or(false)
                {
                    continue;
                }
                // Probe every EncString the cipher exposes under the user
                // key: its own item key first, then its name. A real item
                // key decrypts to a raw 64-byte key blob, so the probe uses
                // decrypt() (raw bytes) rather than decrypt_string(); a name
                // is UTF-8 text but decrypt() accepts it identically. Trying
                // both fields keeps one corrupt value (an unparseable or
                // foreign item key) from vetoing an otherwise valid name. A
                // cipher exposing neither field proves nothing either way and
                // is skipped rather than counted as a failure.
                let key_field = c.get("key").and_then(|v| v.as_str());
                let name_field = c.get("name").and_then(|v| v.as_str());
                if key_field.is_none() && name_field.is_none() {
                    continue;
                }
                candidates += 1;
                for field in [key_field, name_field].into_iter().flatten() {
                    if let Ok(parsed_field) = crate::crypto::EncString::parse(field) {
                        if parsed_field.decrypt(&key).is_ok() {
                            decrypted_any = true;
                            break;
                        }
                    }
                }
                if decrypted_any {
                    break;
                }
            }
            if candidates > 0 && !decrypted_any {
                crate::log_warn!(
                    "omawarden:vault",
                    "Retained key fails to decrypt any personal cipher; wiping quick unlock"
                );
                self.discard_retained_key(expected);
                return Err("The retained key no longer matches this vault; unlock with the master password.".to_string());
            }
            if candidates == 0 {
                // Nothing to decrypt-test: no personal cipher and no usable
                // wrapped private key. An empty vault cannot prove the key on
                // its own, so fall back to the account binding recorded at
                // retention time. An identical wrapping means the same
                // account, the same master password and therefore the same
                // user key; a different one means the key is stale, and
                // committing would let the user write items under a key the
                // next master-password unlock cannot read.
                let recorded = self
                    .quick_unlock_user_key_wrap
                    .read()
                    .ok()
                    .and_then(|wrap| wrap.clone());
                let matches = match (recorded.as_deref(), fresh_storage.enc_user_key.as_deref()) {
                    (Some(recorded), Some(current)) => recorded == current,
                    // Either side missing: nothing proves the key, fail closed.
                    _ => false,
                };
                if !matches {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Retained key cannot be verified against this vault; wiping quick unlock"
                    );
                    self.discard_retained_key(expected);
                    return Err("The retained key no longer matches this vault; unlock with the master password.".to_string());
                }
            }
        }

        // A hard lock (suspend drift, 12h ceiling, explicit lock/logout)
        // landing during the decryption above must win: abort instead of
        // writing unlocked state over a fresh wipe. The cheap epoch check
        // first, then the commit runs under restore_guard with the epoch
        // re-checked inside — wipe_quick_unlock holds the same guard, so a
        // wipe can no longer interleave between this check and the writes.
        if self.unlock_context() != expected {
            crate::log_warn!(
                "omawarden:vault",
                "Vault was locked during quick unlock; aborting restore"
            );
            return Err("The vault was locked during unlock. Try again.".to_string());
        }

        #[cfg(test)]
        self.before_unlock_publication.reach();

        {
            let _account = self
                .storage_mgr
                .account_guard()
                .map_err(|e| format!("Cannot secure the vault cache: {e}"))?;
            let _restore = match self.restore_guard.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if self.unlock_context() != expected {
                crate::log_warn!(
                    "omawarden:vault",
                    "Vault was locked during quick unlock; aborting restore"
                );
                return Err("The vault was locked during unlock. Try again.".to_string());
            }
            if !base
                .is_current(&self.storage_mgr)
                .map_err(|e| format!("Cannot verify the vault cache: {e}"))?
            {
                return Err("Vault cache changed during unlock. Please retry.".into());
            }

            let mut unlocked = self
                .is_unlocked
                .write()
                .map_err(|_| "Vault state unavailable")?;
            let mut storage = self
                .storage
                .write()
                .map_err(|_| "Vault state unavailable")?;
            let mut index = self
                .decrypted_items
                .write()
                .map_err(|_| "Vault state unavailable")?;
            let mut user_key = self
                .user_key
                .write()
                .map_err(|_| "Vault state unavailable")?;
            *index = items;
            *user_key = Some(key);
            *storage = base.storage;
            *unlocked = true;
            // The retained slot is intentionally left untouched: it still
            // holds the same key, and rewriting it would resurrect a key a
            // concurrent wipe just destroyed.
        }

        crate::log_info!(
            "omawarden:vault",
            "Quick-unlocked vault; {} items restored.",
            count
        );
        Ok(count)
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        self.unlock_in_context(password, &self.unlock_context(), None)
    }

    pub(crate) fn unlock_context(&self) -> String {
        format!(
            "{}:{}",
            self.lock_generation(),
            self.quick_unlock_epoch
                .load(std::sync::atomic::Ordering::SeqCst)
        )
    }

    pub(crate) fn unlock_in_context(
        &self,
        password: &str,
        expected: &str,
        credential_id: Option<&str>,
    ) -> Result<usize, String> {
        if self.unlock_context() != expected {
            return Err(
                "Vault session changed during login. Unlock explicitly to continue.".into(),
            );
        }
        let base = self
            .storage_mgr
            .cache_snapshot()
            .map_err(|e| format!("Cannot read the vault cache: {e}"))?;
        let fresh_storage = &base.storage;
        if fresh_storage.enc_user_key.is_none() {
            crate::log_error!(
                "omawarden:vault",
                "Account not logged in or missing encryption keys."
            );
            return Err("Account not logged in or missing encryption keys.".to_string());
        }
        fresh_storage.check_unlock_credentials()?;
        if credential_id.is_some() && fresh_storage.scoped_credential_id() != credential_id {
            return Err("Vault account changed during unlock.".into());
        }

        let user_key = self
            .storage_mgr
            .unlock_user_key(password, fresh_storage)
            .map_err(|e| {
                crate::log_warn!("omawarden:vault", "Unlock user key failed: {:?}", e);
                e.to_string()
            })?;

        let items = decrypt_sync_ciphers_with_context(
            &fresh_storage.ciphers,
            &fresh_storage.folders,
            &fresh_storage.organizations,
            &user_key,
            fresh_storage.enc_private_key.as_deref(),
        );
        let count = items.len();
        #[cfg(test)]
        self.before_unlock_publication.reach();
        let _account = self
            .storage_mgr
            .account_guard()
            .map_err(|e| format!("Cannot secure the vault cache: {e}"))?;
        let _restore = self
            .restore_guard
            .lock()
            .map_err(|_| "Vault state unavailable")?;
        if self.unlock_context() != expected {
            return Err(
                "Vault session changed during login. Unlock explicitly to continue.".into(),
            );
        }
        if !base
            .is_current(&self.storage_mgr)
            .map_err(|e| format!("Cannot verify the vault cache: {e}"))?
        {
            return Err("Vault cache changed during unlock. Please retry.".into());
        }

        let mut unlocked = self
            .is_unlocked
            .write()
            .map_err(|_| "Vault state unavailable")?;
        let mut storage = self
            .storage
            .write()
            .map_err(|_| "Vault state unavailable")?;
        let mut index = self
            .decrypted_items
            .write()
            .map_err(|_| "Vault state unavailable")?;
        let mut key = self
            .user_key
            .write()
            .map_err(|_| "Vault state unavailable")?;
        let mut retained = self
            .quick_unlock_key
            .write()
            .map_err(|_| "Vault state unavailable")?;
        let mut binding = self
            .quick_unlock_user_key_wrap
            .write()
            .map_err(|_| "Vault state unavailable")?;
        // If a soft lock retained a key earlier, keep that copy current with
        // the key now in use (e.g. after a server-side key rotation) and
        // rebind it to the wrapping that came with this unlock.
        if retained.is_some() {
            *retained = Some(user_key.clone());
            *binding = fresh_storage.enc_user_key.clone();
        }
        *index = items;
        *key = Some(user_key);
        *storage = base.storage;
        *unlocked = true;

        crate::log_info!(
            "omawarden:vault",
            "Decrypted and cached {} items in memory.",
            count
        );
        Ok(count)
    }

    pub fn renew_session(&self) -> Result<String, String> {
        self.renew_session_with_client(None)
    }

    pub fn renew_session_with_client(
        &self,
        client_context: Option<&ClientContext>,
    ) -> Result<String, String> {
        let storage = self.storage_mgr.load();
        self.renew_for_account(&storage, client_context, self.lock_generation())
    }

    pub(crate) fn renew_for_account(
        &self,
        storage: &VaultStorage,
        client_context: Option<&ClientContext>,
        generation: u64,
    ) -> Result<String, String> {
        if storage.credential_id.is_none() {
            return Err("Please log in again to use account-scoped credentials.".into());
        }
        let s_url = if !storage.server_url.is_empty() {
            &storage.server_url
        } else {
            &self.server_url
        };
        let id_url = storage.credential_identity_url(self.identity_url.as_deref());
        let client = BitwardenApiClient::with_options(s_url, id_url, client_context);
        let keyring = self.keyring_mgr.for_storage(storage);

        let mut had_credentials = false;
        let mut auth_failed = false;
        let mut last_error = None;

        // 1. Try refresh_token grant
        let refresh_token = keyring.refresh_token();

        if let Some(ref ref_tok) = refresh_token {
            had_credentials = true;
            crate::log_info!(
                "omawarden:vault",
                "Attempting session renewal via refresh token..."
            );
            match client.refresh_token_grant(ref_tok) {
                Ok(tok_resp) => {
                    crate::log_info!("omawarden:vault", "Token refresh grant successful.");
                    self.persist_renewed_tokens(storage, generation, &tok_resp)?;
                    return Ok(tok_resp.access_token);
                }
                Err(ApiError::AuthFailed(msg)) => {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Refresh token grant rejected (auth failed: {}). Falling back to API credentials...",
                        msg
                    );
                    auth_failed = true;
                    last_error = Some(format!("Authentication failed: {}", msg));
                }
                Err(ApiError::Network(msg))
                | Err(ApiError::Http(msg))
                | Err(ApiError::HttpStatus(_, msg)) => {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Refresh token grant encountered network or server error: {}. Falling back...",
                        msg
                    );
                    last_error = Some(format!("Network error during token refresh: {}", msg));
                }
                Err(e) => {
                    crate::log_warn!(
                        "omawarden:vault",
                        "Refresh token grant failed: {:?}. Falling back...",
                        e
                    );
                    last_error = Some(format!("Token refresh failed: {:?}", e));
                }
            }
        }

        // 2. Try client_credentials grant via client_id + client_secret in Keyring
        if let Some(ref cid) = storage.client_id {
            if let Some(sec) = keyring.api_secret() {
                had_credentials = true;
                crate::log_info!(
                    "omawarden:vault",
                    "Attempting silent re-authentication via API key secret..."
                );
                match client.login_apikey(cid, &sec) {
                    Ok(tok_resp) => {
                        crate::log_info!(
                            "omawarden:vault",
                            "Silent re-authentication via API key successful."
                        );
                        self.persist_renewed_tokens(storage, generation, &tok_resp)?;
                        return Ok(tok_resp.access_token);
                    }
                    Err(ApiError::AuthFailed(msg)) => {
                        crate::log_error!(
                            "omawarden:vault",
                            "API key silent re-auth rejected (auth failed: {})",
                            msg
                        );
                        auth_failed = true;
                        last_error = Some(format!("Authentication failed: {}", msg));
                    }
                    Err(ApiError::Network(msg))
                    | Err(ApiError::Http(msg))
                    | Err(ApiError::HttpStatus(_, msg)) => {
                        crate::log_error!(
                            "omawarden:vault",
                            "API key silent re-auth encountered network or server error: {}",
                            msg
                        );
                        last_error = Some(format!(
                            "Network error during API key authentication: {}",
                            msg
                        ));
                    }
                    Err(e) => {
                        crate::log_error!(
                            "omawarden:vault",
                            "API key silent re-auth failed: {:?}",
                            e
                        );
                        last_error = Some(format!("API key login failed: {:?}", e));
                    }
                }
            }
        }

        if !had_credentials {
            self.purge_credentials_and_lock(storage, generation);
            return Err("Session token missing. Please log in.".to_string());
        }

        if auth_failed {
            self.purge_credentials_and_lock(storage, generation);
            return Err(
                "Session expired or credentials rejected. Please log in again.".to_string(),
            );
        }

        Err(last_error.unwrap_or_else(|| {
            "Session renewal failed due to network error. Please check your connection.".to_string()
        }))
    }

    fn persist_renewed_tokens(
        &self,
        storage: &VaultStorage,
        generation: u64,
        tok_resp: &crate::api::TokenResponse,
    ) -> Result<(), String> {
        let _account_guard = self.storage_mgr.account_guard().map_err(|_| {
            self.lock();
            "Cannot secure renewed session state"
        })?;
        let mut updated_storage = self.storage_mgr.load_existing().map_err(|_| {
            self.revoke_account(storage, generation);
            "Vault cache unavailable"
        })?;
        if generation != self.lock_generation() || !storage.same_active_slot(&updated_storage) {
            return Err("Session changed during token renewal".into());
        }
        if self.keyring_mgr.is_available() {
            let keyring = self.keyring_mgr.for_storage(&updated_storage);
            let s1 = keyring.store_token(crate::keyring::KIND_ACCESS_TOKEN, &tok_resp.access_token);
            let s2 = if let Some(ref new_ref) = tok_resp.refresh_token {
                keyring.store_token(crate::keyring::KIND_REFRESH_TOKEN, new_ref)
            } else {
                keyring.clear_token(crate::keyring::KIND_REFRESH_TOKEN);
                true
            };
            if s1 && s2 {
                if updated_storage.access_token.is_some() || updated_storage.refresh_token.is_some()
                {
                    updated_storage.access_token = None;
                    updated_storage.refresh_token = None;
                    self.storage_mgr.save(&updated_storage).map_err(|_| {
                        self.revoke_account(storage, generation);
                        "Failed to save renewed session state"
                    })?;
                }
                return Ok(());
            }
        }

        crate::log_error!(
            "omawarden:vault",
            "Keyring not available or failed to store renewed tokens. Locking session."
        );
        self.revoke_account(storage, generation);
        Err("Failed to store renewed credentials in the keyring".into())
    }

    fn purge_credentials_and_lock(&self, expected: &VaultStorage, generation: u64) {
        match self.storage_mgr.account_guard() {
            Ok(_guard) => self.revoke_account(expected, generation),
            Err(_) => self.lock(),
        }
    }

    fn revoke_account(&self, expected: &VaultStorage, generation: u64) {
        let disk = self.storage_mgr.load_existing();
        if self.lock_generation() != generation
            || disk.as_ref().is_ok_and(|s| !s.same_active_slot(expected))
        {
            return;
        }
        self.lock();
        let keyring = self.keyring_mgr.for_storage(expected);
        keyring.clear_token(crate::keyring::KIND_ACCESS_TOKEN);
        keyring.clear_token(crate::keyring::KIND_REFRESH_TOKEN);
        if let Ok(mut updated) = disk {
            updated.access_token = None;
            updated.refresh_token = None;
            let _ = self.storage_mgr.save(&updated);
        }
    }

    pub fn get_items(&self) -> Vec<VaultItem> {
        let Ok(unlocked) = self.is_unlocked.read() else {
            return Vec::new();
        };
        if !*unlocked {
            return Vec::new();
        }
        self.decrypted_items
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Name and SSH data of the unlocked vault's SSH key items, without
    /// copying the rest of the vault. Empty while locked, and never asks the
    /// daemon: the SSH agent runs inside it.
    pub fn ssh_key_items(&self) -> Vec<(String, SshMetadata)> {
        let Ok(unlocked) = self.is_unlocked.read() else {
            return Vec::new();
        };
        if !*unlocked {
            return Vec::new();
        }
        self.decrypted_items
            .read()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| Some((i.name.clone(), i.ssh_key.clone()?)))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn search_items(&self, query: &str, category: Option<&str>) -> Vec<VaultItem> {
        self.search(&self.get_items(), query, category)
    }

    pub fn resolve_attachment_key(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Option<SymmetricCryptoKey> {
        let unlocked = self.is_unlocked.read().ok()?;
        if !*unlocked {
            return None;
        }
        let user_key_guard = self.user_key.read().ok()?;
        let user_key = user_key_guard.as_ref()?;
        let storage_guard = self.storage.read().ok()?;

        let rsa_priv_key = if let Some(ref enc_priv) = storage_guard.enc_private_key {
            if let Ok(enc_priv_str) = EncString::parse(enc_priv) {
                if let Ok(der_bytes) = enc_priv_str.decrypt(user_key) {
                    parse_rsa_private_key_der(&der_bytes).ok()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let cipher = storage_guard
            .ciphers
            .iter()
            .find(|c| c.get("id").and_then(|v| v.as_str()) == Some(item_id))?;

        let org_id_opt = cipher.get("organizationId").and_then(|v| v.as_str());
        let mut base_key = user_key.clone();
        if let Some(oid) = org_id_opt {
            if let Some(org) = storage_guard
                .organizations
                .iter()
                .find(|o| o.get("id").and_then(|v| v.as_str()) == Some(oid))
            {
                if let Some(org_key_enc) = org.get("key").and_then(|v| v.as_str()) {
                    if let Ok(enc_str) = EncString::parse(org_key_enc) {
                        let raw_key = match enc_str.enc_type {
                            3..=6 => {
                                if let Some(ref rsa) = rsa_priv_key {
                                    enc_str.decrypt_rsa(rsa).ok()
                                } else {
                                    None
                                }
                            }
                            0..=2 => enc_str.decrypt(user_key).ok(),
                            _ => None,
                        };
                        if let Some(key_bytes) = raw_key {
                            if let Some(sym_key) =
                                parse_symmetric_key_from_decrypted_bytes(&key_bytes)
                            {
                                base_key = sym_key;
                            }
                        }
                    }
                }
            }
        }

        let mut cipher_key = base_key.clone();
        if let Some(enc_key_str) = cipher.get("key").and_then(|v| v.as_str()) {
            if let Ok(parsed_k) = EncString::parse(enc_key_str) {
                let raw_k = parsed_k
                    .decrypt(&base_key)
                    .or_else(|_| parsed_k.decrypt(user_key));
                if let Ok(raw_k_bytes) = raw_k {
                    if let Some(k) = parse_symmetric_key_from_decrypted_bytes(&raw_k_bytes) {
                        cipher_key = k;
                    }
                }
            }
        }

        if let Some(attachments) = cipher.get("attachments").and_then(|v| v.as_array()) {
            if let Some(att) = attachments
                .iter()
                .find(|a| a.get("id").and_then(|v| v.as_str()) == Some(attachment_id))
            {
                if let Some(att_key_enc) = att.get("key").and_then(|v| v.as_str()) {
                    if let Ok(parsed_k) = EncString::parse(att_key_enc) {
                        let raw_k = parsed_k
                            .decrypt(&cipher_key)
                            .or_else(|_| parsed_k.decrypt(user_key));
                        if let Ok(raw_k_bytes) = raw_k {
                            if let Some(k) = parse_symmetric_key_from_decrypted_bytes(&raw_k_bytes)
                            {
                                return Some(k);
                            }
                        }
                    }
                }
            }
        }

        Some(cipher_key)
    }

    pub fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        let unlocked = self.is_unlocked.read().ok()?;
        if !*unlocked {
            return None;
        }
        self.user_key.read().ok().and_then(|k| k.clone())
    }

    pub fn find_item(&self, query: &str, category: Option<&str>) -> Option<VaultItem> {
        let items = self.get_items();
        let target = query.trim();
        if target.is_empty() {
            return None;
        }

        let cat_filter = category.map(|c| c.to_lowercase());

        // 1. Exact ID match
        if let Some(item) = items.iter().find(|i| {
            if let Some(ref c) = cat_filter {
                if &i.type_name != c {
                    return false;
                }
            }
            i.id == target
        }) {
            return Some(item.clone());
        }

        // 2. Exact Name match (case-insensitive)
        if let Some(item) = items.iter().find(|i| {
            if let Some(ref c) = cat_filter {
                if &i.type_name != c {
                    return false;
                }
            }
            i.name.eq_ignore_ascii_case(target)
        }) {
            return Some(item.clone());
        }

        // 3. Name contains query (case-insensitive)
        let lower = target.to_lowercase();
        if let Some(item) = items.iter().find(|i| {
            if let Some(ref c) = cat_filter {
                if &i.type_name != c {
                    return false;
                }
            }
            i.name.to_lowercase().contains(&lower)
        }) {
            return Some(item.clone());
        }

        None
    }

    pub fn resolve_cipher_target_candidates(
        &self,
        target: &str,
    ) -> Result<CipherTargetResolution, String> {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            return Err("Target cipher cannot be empty.".to_string());
        }

        let items = self.get_items();

        // 1. Exact ID or 32-character hex ID match
        let is_id_match = |item_id: &str, target_val: &str| -> bool {
            if item_id.eq_ignore_ascii_case(target_val) {
                return true;
            }
            if target_val.len() == 32 && item_id.len() == 36 && !target_val.contains('-') {
                let stripped: String = item_id.chars().filter(|&c| c != '-').collect();
                return stripped.eq_ignore_ascii_case(target_val);
            }
            if target_val.len() == 36 && item_id.len() == 32 && target_val.contains('-') {
                let stripped: String = target_val.chars().filter(|&c| c != '-').collect();
                return item_id.eq_ignore_ascii_case(&stripped);
            }
            false
        };

        let id_matches: Vec<_> = items
            .iter()
            .filter(|i| is_id_match(&i.id, trimmed))
            .cloned()
            .collect();
        if id_matches.len() == 1 {
            return Ok(CipherTargetResolution::Exact(Box::new(
                id_matches[0].clone(),
            )));
        }
        if id_matches.len() > 1 {
            return Ok(CipherTargetResolution::Ambiguous(id_matches));
        }

        // 2. Exact Name match (case-insensitive)
        let exact_name_matches: Vec<_> = items
            .iter()
            .filter(|i| i.name.eq_ignore_ascii_case(trimmed))
            .cloned()
            .collect();
        if exact_name_matches.len() == 1 {
            return Ok(CipherTargetResolution::Exact(Box::new(
                exact_name_matches[0].clone(),
            )));
        }
        if exact_name_matches.len() > 1 {
            return Ok(CipherTargetResolution::Ambiguous(exact_name_matches));
        }

        // 3. ID prefix match (unique prefix, at least 4 characters)
        let is_id_prefix_match = |item_id: &str, target_val: &str| -> bool {
            if target_val.len() < 4 {
                return false;
            }
            if item_id
                .to_lowercase()
                .starts_with(&target_val.to_lowercase())
            {
                return true;
            }
            let stripped_target: String = target_val.chars().filter(|&c| c != '-').collect();
            let stripped_id: String = item_id.chars().filter(|&c| c != '-').collect();
            if stripped_target.len() >= 4
                && stripped_id
                    .to_lowercase()
                    .starts_with(&stripped_target.to_lowercase())
            {
                return true;
            }
            false
        };

        let id_prefix_matches: Vec<_> = items
            .iter()
            .filter(|i| is_id_prefix_match(&i.id, trimmed))
            .cloned()
            .collect();
        if id_prefix_matches.len() == 1 {
            return Ok(CipherTargetResolution::Exact(Box::new(
                id_prefix_matches[0].clone(),
            )));
        }
        if id_prefix_matches.len() > 1 {
            return Ok(CipherTargetResolution::Ambiguous(id_prefix_matches));
        }

        // 4. Substring (fuzzy) match (case-insensitive)
        let lower = trimmed.to_lowercase();
        let sub_matches: Vec<_> = items
            .iter()
            .filter(|i| i.name.to_lowercase().contains(&lower))
            .cloned()
            .collect();
        if sub_matches.len() == 1 {
            return Ok(CipherTargetResolution::Exact(Box::new(
                sub_matches[0].clone(),
            )));
        }
        if sub_matches.len() > 1 {
            return Ok(CipherTargetResolution::Ambiguous(sub_matches));
        }

        Ok(CipherTargetResolution::NotFound(format!(
            "Cipher '{}' not found in vault.",
            target
        )))
    }

    pub fn resolve_cipher_target(&self, target: &str) -> Result<VaultItem, String> {
        match self.resolve_cipher_target_candidates(target)? {
            CipherTargetResolution::Exact(item) => Ok(*item),
            CipherTargetResolution::Ambiguous(candidates) => {
                let ids: Vec<&str> = candidates.iter().map(|c| c.id.as_str()).collect();
                Err(format!(
                    "Multiple ciphers matched '{}': [{}]. Specify by ID or narrower name.",
                    target,
                    ids.join(", ")
                ))
            }
            CipherTargetResolution::NotFound(err) => Err(err),
        }
    }

    pub fn find_ssh_key(&self, id_or_name: &str) -> Option<VaultItem> {
        self.find_item(id_or_name, Some("ssh_key"))
    }

    pub fn get_status(&self) -> Value {
        let fresh_storage = self.storage_mgr.load();
        let keyring = self.keyring_mgr.for_storage(&fresh_storage);
        let active_token = keyring.access_token();
        let has_refresh = keyring.refresh_token().is_some();
        let has_api_secret = keyring.api_secret().is_some();

        let has_valid_token = if let Some(ref tok) = active_token {
            !crate::auth::is_jwt_expired(tok) || has_refresh || has_api_secret
        } else {
            has_refresh || has_api_secret
        };

        // A lock increments the generation under this same write lock.
        let (is_unlocked, generation, count) = self
            .is_unlocked
            .read()
            .map(|unlocked| {
                let current = *unlocked
                    && fresh_storage.scoped_credential_id().is_some()
                    && self
                        .storage
                        .read()
                        .is_ok_and(|s| s.same_active_slot(&fresh_storage));
                let count = if current {
                    self.decrypted_items.read().map(|i| i.len()).unwrap_or(0)
                } else {
                    0
                };
                (current, self.lock_generation(), count)
            })
            .unwrap_or_default();
        let status = if is_unlocked {
            "unlocked"
        } else if fresh_storage.scoped_credential_id().is_some()
            && (has_valid_token || fresh_storage.enc_user_key.is_some())
        {
            "locked"
        } else {
            "unauthenticated"
        };

        json!({
            "ok": true,
            "status": status,
            "server_url": fresh_storage.server_url,
            "user_email": fresh_storage.user_email,
            "user_id": fresh_storage.user_id,
            "credential_id": fresh_storage.credential_id,
            "last_sync": fresh_storage.last_sync,
            "is_unlocked": is_unlocked,
            "lock_generation": generation.to_string(),
            "has_session": has_valid_token,
            "items_count": count,
        })
    }

    pub fn parse_raw_items(&self, raw_items: &[Value]) -> Vec<VaultItem> {
        let mut parsed: Vec<VaultItem> = Vec::new();

        for raw in raw_items {
            let item_type = raw.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
            let name = raw
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Untitled")
                .to_string();
            let notes = raw
                .get("notes")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let favorite = raw
                .get("favorite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let fields = raw
                .get("fields")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let attachments = raw
                .get("attachments")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let id = raw
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let folder_id = raw
                .get("folderId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let organization_id = raw
                .get("organizationId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let collection_ids = raw
                .get("collectionIds")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                });
            let created_at = raw
                .get("created_at")
                .or_else(|| raw.get("creationDate"))
                .or_else(|| raw.get("creation_date"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let updated_at = raw
                .get("updated_at")
                .or_else(|| raw.get("revisionDate"))
                .or_else(|| raw.get("revision_date"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let type_name = match item_type {
                1 => "login",
                2 => "note",
                3 => "card",
                4 => "identity",
                5 => "ssh_key",
                _ => "login",
            }
            .to_string();

            let (sub_title, mut search_tokens) = self.extract_metadata(
                item_type,
                raw,
                &name,
                notes.as_deref().unwrap_or(""),
                &fields,
            );

            for att in &attachments {
                if let Some(fname) = att.get("fileName").and_then(|v| v.as_str()) {
                    search_tokens.push(fname.to_lowercase());
                }
            }
            let search_text = search_tokens
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            let ssh_key = if item_type == 5 {
                if let Some(ssh_data) = raw.get("sshKey").or_else(|| raw.get("ssh_key")) {
                    let priv_k = ssh_data
                        .get("privateKey")
                        .or_else(|| ssh_data.get("private_key"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let pub_k = ssh_data
                        .get("publicKey")
                        .or_else(|| ssh_data.get("public_key"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let fp = ssh_data
                        .get("keyFingerprint")
                        .or_else(|| ssh_data.get("fingerprint"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    Some(parse_ssh_key_fields(priv_k, pub_k, fp))
                } else {
                    None
                }
            } else {
                None
            };

            parsed.push(VaultItem {
                id,
                name,
                item_type,
                type_name,
                sub_title,
                notes,
                favorite,
                created_at,
                updated_at,
                folder_id,
                folder_name: None,
                organization_id,
                organization_name: None,
                collection_ids,
                login: if item_type == 1 {
                    raw.get("login").cloned()
                } else {
                    None
                },
                card: if item_type == 3 {
                    raw.get("card").cloned()
                } else {
                    None
                },
                identity: if item_type == 4 {
                    raw.get("identity").cloned()
                } else {
                    None
                },
                ssh_key,
                fields,
                attachments,
                search_text,
            });
        }

        parsed
    }

    fn extract_metadata(
        &self,
        item_type: i64,
        raw: &Value,
        name: &str,
        notes: &str,
        fields: &[Value],
    ) -> (String, Vec<String>) {
        let mut search_tokens = vec![name.to_lowercase(), notes.to_lowercase()];
        let mut sub_title = String::new();

        match item_type {
            1 => {
                if let Some(login_data) = raw.get("login") {
                    let username = login_data
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    sub_title = username.to_string();
                    search_tokens.push(username.to_lowercase());
                    if let Some(uris) = login_data.get("uris").and_then(|v| v.as_array()) {
                        for u in uris {
                            if let Some(uri_val) = u.get("uri").and_then(|v| v.as_str()) {
                                search_tokens.push(uri_val.to_lowercase());
                            }
                        }
                    }
                }
            }
            3 => {
                if let Some(card_data) = raw.get("card") {
                    let num = card_data
                        .get("number")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let brand = card_data
                        .get("brand")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Card");
                    let last4 = if num.len() >= 4 {
                        &num[num.len() - 4..]
                    } else {
                        num
                    };
                    sub_title = if !last4.is_empty() {
                        format!("{} •••• {}", brand, last4)
                    } else {
                        brand.to_string()
                    };
                    search_tokens.push(brand.to_lowercase());
                    search_tokens.push(num.to_string());
                }
            }
            4 => {
                if let Some(id_data) = raw.get("identity") {
                    let email = id_data.get("email").and_then(|v| v.as_str()).unwrap_or("");
                    let fname = id_data
                        .get("firstName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let lname = id_data
                        .get("lastName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let full_name = format!("{} {}", fname, lname).trim().to_string();
                    sub_title = if !email.is_empty() {
                        email.to_string()
                    } else if !full_name.is_empty() {
                        full_name.clone()
                    } else {
                        "Identity".to_string()
                    };
                    search_tokens.push(email.to_lowercase());
                    search_tokens.push(fname.to_lowercase());
                    search_tokens.push(lname.to_lowercase());
                    search_tokens.push(full_name.to_lowercase());
                }
            }
            5 => {
                if let Some(ssh_data) = raw.get("sshKey").or_else(|| raw.get("ssh_key")) {
                    let pubk = ssh_data
                        .get("publicKey")
                        .or_else(|| ssh_data.get("public_key"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let privk = ssh_data
                        .get("privateKey")
                        .or_else(|| ssh_data.get("private_key"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let fp = ssh_data
                        .get("keyFingerprint")
                        .or_else(|| ssh_data.get("fingerprint"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let mut key_type = "SSH".to_string();
                    if pubk.contains("ssh-ed25519") || privk.contains("ed25519") {
                        key_type = "ED25519".to_string();
                    } else if pubk.contains("ssh-rsa") || privk.contains("RSA") {
                        key_type = "RSA".to_string();
                    } else if pubk.contains("ecdsa") || privk.contains("EC") {
                        key_type = "ECDSA".to_string();
                    } else if pubk.contains("ssh-dss") || privk.contains("DSA") {
                        key_type = "DSA".to_string();
                    }
                    sub_title = format!("SSH Key ({})", key_type);
                    search_tokens.push("ssh".to_string());
                    search_tokens.push("ssh key".to_string());
                    search_tokens.push(key_type.to_lowercase());
                    if !pubk.is_empty() {
                        search_tokens.push(pubk.to_lowercase());
                    }
                    if !fp.is_empty() {
                        search_tokens.push(fp.to_lowercase());
                    }
                } else {
                    sub_title = "SSH Key".to_string();
                    search_tokens.push("ssh".to_string());
                    search_tokens.push("ssh key".to_string());
                }
            }
            2 => {
                sub_title = "Secure Note".to_string();
            }
            _ => {}
        }

        for f in fields {
            let fname = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let fval = f
                .get("value")
                .map(|v| match v {
                    Value::String(s) => s.as_str(),
                    _ => "",
                })
                .unwrap_or("");
            search_tokens.push(fname.to_lowercase());
            search_tokens.push(fval.to_lowercase());
        }

        (sub_title, search_tokens)
    }

    pub fn search(
        &self,
        items: &[VaultItem],
        query: &str,
        category: Option<&str>,
    ) -> Vec<VaultItem> {
        let q = query.trim().to_lowercase();
        let cat = category.unwrap_or("").trim().to_lowercase();
        let cat_filter = if cat.is_empty() || cat == "all" {
            None
        } else {
            Some(cat)
        };

        let mut scored_items: Vec<(&VaultItem, i64)> = Vec::new();

        for item in items {
            if let Some(ref c) = cat_filter {
                if &item.type_name != c {
                    continue;
                }
            }

            if q.is_empty() {
                scored_items.push((item, if item.favorite { 100 } else { 0 }));
                continue;
            }

            let query_words: Vec<&str> = q.split_whitespace().collect();
            let mut total_score: i64 = if item.favorite { 100 } else { 0 };
            let name_lower = item.name.to_lowercase();
            let sub_lower = item.sub_title.to_lowercase();
            let search_lower = item.search_text.to_lowercase();
            let notes_lower = item.notes.as_deref().unwrap_or("").to_lowercase();

            let mut all_words_matched = true;
            for w in query_words {
                let mut word_matched = false;
                if name_lower == w {
                    total_score += 2000;
                    word_matched = true;
                } else if name_lower.starts_with(w) {
                    total_score += 1000;
                    word_matched = true;
                } else if name_lower.contains(w) {
                    total_score += 500;
                    word_matched = true;
                } else if sub_lower.starts_with(w) {
                    total_score += 400;
                    word_matched = true;
                } else if sub_lower.contains(w) {
                    total_score += 300;
                    word_matched = true;
                } else if search_lower.contains(w) || notes_lower.contains(w) {
                    total_score += 100;
                    word_matched = true;
                } else if is_fuzzy_match(w, &name_lower) {
                    total_score += 80;
                    word_matched = true;
                }

                if !word_matched {
                    all_words_matched = false;
                    break;
                }
            }

            if all_words_matched {
                scored_items.push((item, total_score));
            }
        }

        scored_items.sort_by_key(|a| std::cmp::Reverse(a.1));
        scored_items
            .into_iter()
            .map(|(item, _)| item.clone())
            .collect()
    }
}

#[cfg(test)]
// pub(crate): daemon tests reuse the seeded vault fixture for the IPC
// quick-unlock flow.
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a VaultManager whose data.json carries a real login: a type-2
    /// EncString wrapping the raw 64-byte user key under the master key, so
    /// unlock(password) exercises the production key-unwrapping path.
    pub(crate) fn seeded_vault(dir: &std::path::Path, password: &str) -> VaultManager {
        use crate::crypto::{derive_master_key, KdfType, SymmetricCryptoKey, BASE64};
        use base64::Engine as _;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use hmac::Mac;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;

        let email = "quick@unlock.test";
        let master_key =
            derive_master_key(email, password, KdfType::Pbkdf2Sha256, 600_000, None, None)
                .expect("master key");
        let master_sym = SymmetricCryptoKey::from_master_key(master_key.as_slice());
        let raw = [42u8; 64];

        let iv = [9u8; 16];
        let enc = Aes256CbcEnc::new_from_slices(&master_sym.enc_key, &iv).expect("cipher");
        let mut buf = vec![0u8; raw.len() + 16];
        let ct = enc
            .encrypt_padded_b2b_mut::<cbc::cipher::block_padding::Pkcs7>(&raw, &mut buf)
            .expect("encrypt");
        let mut mac = HmacSha256::new_from_slice(master_sym.mac_key.as_ref().expect("mac key"))
            .expect("hmac");
        mac.update(&iv);
        mac.update(ct);
        let mac = mac.finalize().into_bytes();
        let enc_user_key = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );

        let storage = VaultStorage {
            server_url: "https://vault.example.com".to_string(),
            user_email: email.to_string(),
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
            kdf: Some(0),
            kdf_iterations: Some(600_000),
            enc_user_key: Some(enc_user_key),
            ..Default::default()
        };
        let storage_mgr = StorageManager::new(dir.join("data.json"));
        storage_mgr.save(&storage).expect("save storage");
        VaultManager::new("", Some(storage_mgr), None)
    }

    #[test]
    fn test_soft_lock_retains_key_and_quick_unlock_restores() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        assert!(!vault.quick_unlock_available());

        assert_eq!(vault.unlock("master-pw").unwrap(), 0);
        assert!(vault.is_unlocked());

        assert!(vault.soft_lock(), "an unlocked vault must retain its key");
        assert!(!vault.is_unlocked());
        assert!(vault.decrypted_items.read().unwrap().is_empty());
        assert!(vault.user_key.read().unwrap().is_none());
        assert!(vault.quick_unlock_available());

        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert!(vault.is_unlocked());
        assert!(vault.user_key.read().unwrap().is_some());
        assert!(vault.quick_unlock_available(), "slot stays primed");

        // A second soft lock keeps retention working.
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_restore().is_ok());

        // Hard lock wipes the slot; restore now fails.
        vault.hard_lock();
        assert!(!vault.quick_unlock_available());
        assert!(vault.quick_unlock_restore().is_err());
    }

    #[test]
    fn test_plain_lock_wipes_quick_unlock_slot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // lock() is the fail-safe path: any caller that has not opted into
        // retention must not leave the slot behind.
        vault.unlock("master-pw").unwrap();
        vault.lock();
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_soft_lock_without_unlock_retains_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        assert!(!vault.soft_lock());
        assert!(!vault.quick_unlock_available());
        assert!(vault.quick_unlock_restore().is_err());
    }

    #[test]
    fn test_unlock_refreshes_stale_retained_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        // A fresh password unlock replaces the retained copy with the key now
        // in use, so a later restore cannot resurrect an old key.
        vault.unlock("master-pw").unwrap();
        vault.lock();
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn quick_unlock_wipes_the_key_when_the_cache_has_no_scoped_slot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        let mut storage = vault.storage_mgr.load();
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        storage.credential_id = None;
        vault.storage_mgr.save(&storage).unwrap();
        let result = vault.quick_unlock_restore();
        assert!(result.unwrap_err().contains("Sign in again"));
        assert!(!vault.quick_unlock_available());
        assert!(!vault.is_unlocked());
        assert!(vault.user_key.read().unwrap().is_none());
        assert!(vault.get_items().is_empty());
    }

    #[test]
    fn test_quick_unlock_restore_fails_closed_on_stale_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // Simulate a vault whose ciphers were re-encrypted under a different
        // key (rotation / account switch): the retained key decrypts none of
        // them, which previously surfaced as an "unlocked" empty vault.
        let mut stale = vault.storage_mgr.load();
        stale.ciphers = vec![serde_json::json!({
            "id": "cipher-1",
            "type": 1,
            "name": "2.not-a-valid-encstring",
            "login": null,
        })];
        vault.storage_mgr.save(&stale).unwrap();

        let err = vault.quick_unlock_restore().unwrap_err();
        assert!(err.contains("no longer matches"), "got: {err}");
        assert!(
            !vault.is_unlocked(),
            "restore must not leave the vault unlocked"
        );
        assert!(
            !vault.quick_unlock_available(),
            "a stale retained key must be wiped, not re-primed"
        );
    }

    #[test]
    fn test_hard_lock_takes_the_restore_guard_before_purging() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();

        // Regression for the purge-before-wipe ordering: the restore commit
        // section holds restore_guard, so a hard lock that purged first could
        // be overwritten by a commit landing in the gap and leave the vault
        // unlocked after a suspend, the 12h ceiling or an explicit lock. Hold
        // the guard (as the commit section does) and prove the hard lock has
        // not purged anything, nor bumped the epoch, before it gets the guard.
        let epoch_before = vault.quick_unlock_epoch.load(Ordering::SeqCst);
        let guard = vault.restore_guard.lock().unwrap();
        std::thread::scope(|s| {
            let locker = s.spawn(|| vault.lock());
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                vault.is_unlocked(),
                "a hard lock must wait for the restore commit guard before purging"
            );
            assert!(
                vault.user_key.read().unwrap().is_some(),
                "the user key must survive until the wipe has the guard"
            );
            assert_eq!(
                vault.quick_unlock_epoch.load(Ordering::SeqCst),
                epoch_before,
                "the epoch bump that aborts an in-flight restore must come before the purge"
            );
            drop(guard);
            locker.join().unwrap();
        });
        assert!(
            !vault.is_unlocked(),
            "the hard lock must land once the guard is free"
        );
        assert!(!vault.quick_unlock_available());
        assert_ne!(
            vault.quick_unlock_epoch.load(Ordering::SeqCst),
            epoch_before
        );
    }

    #[test]
    fn test_wipe_is_serialized_with_restore_commit() {
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // Regression for the restore TOCTOU: the wipe must share the mutex
        // the restore's commit section holds, so a hard lock landing while a
        // restore is committing cannot be overwritten. Hold the guard (as the
        // commit section does) and prove wipe_quick_unlock waits on it.
        let epoch_before = vault.quick_unlock_epoch.load(Ordering::SeqCst);
        let guard = vault.restore_guard.lock().unwrap();
        std::thread::scope(|s| {
            let wiper = s.spawn(|| vault.wipe_quick_unlock());
            std::thread::sleep(Duration::from_millis(100));
            assert_eq!(
                vault.quick_unlock_epoch.load(Ordering::SeqCst),
                epoch_before,
                "a wipe must not bypass the restore commit guard"
            );
            assert!(
                vault.quick_unlock_available(),
                "the slot must survive while the commit section holds the guard"
            );
            drop(guard);
            wiper.join().unwrap();
        });
        assert_ne!(
            vault.quick_unlock_epoch.load(Ordering::SeqCst),
            epoch_before
        );
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_lock_generation_changes_only_when_an_unlocked_vault_locks() {
        let vault_mgr = VaultManager::new("https://vault.example.com", None, None);
        let start = vault_mgr.lock_generation();

        // Locking an already locked vault is not a new lock cycle.
        vault_mgr.hard_lock();
        vault_mgr.soft_lock();
        assert_eq!(vault_mgr.lock_generation(), start);

        *vault_mgr.is_unlocked.write().unwrap() = true;
        assert_eq!(vault_mgr.lock_generation(), start, "unlocking keeps it");
        vault_mgr.soft_lock();
        assert_eq!(vault_mgr.lock_generation(), start + 1);

        *vault_mgr.is_unlocked.write().unwrap() = true;
        vault_mgr.hard_lock();
        assert_eq!(vault_mgr.lock_generation(), start + 2);
    }

    #[test]
    fn test_shared_lock_epoch_advances_on_lock_and_survives_quick_unlock() {
        let _environment = crate::env_lock();
        let runtime = tempfile::tempdir().unwrap();
        let epoch_dir = tempfile::tempdir().unwrap();
        let mut env = crate::test_support::EnvGuard::new();
        env.set("XDG_RUNTIME_DIR", runtime.path());
        env.remove("WAYLAND_DISPLAY");
        env.remove("WAYLAND_SOCKET");

        let dir = tempfile::tempdir().unwrap();
        let mut vault = seeded_vault(dir.path(), "master-pw");
        vault.lock_epoch_dir = Some(epoch_dir.path().to_path_buf());
        std::fs::write(epoch_dir.path().join("omawarden.lock-epoch"), "70").unwrap();
        let current = || {
            std::fs::read_to_string(epoch_dir.path().join("omawarden.lock-epoch"))
                .unwrap()
                .parse::<u64>()
                .unwrap()
        };

        vault.unlock("master-pw").unwrap();
        assert_eq!(current(), 70, "unlock preserves the epoch");
        assert!(vault.soft_lock());
        assert_eq!(current(), 71, "soft lock advances the epoch");
        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert_eq!(current(), 71, "quick unlock preserves the epoch");
        vault.lock();
        assert_eq!(current(), 72, "hard lock advances the epoch");
    }

    #[test]
    fn test_soft_lock_on_locked_vault_keeps_existing_slot() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        // Calling soft_lock again (nothing to move) must not drop retention.
        assert!(!vault.soft_lock());
        assert!(vault.quick_unlock_available());
    }

    #[test]
    fn test_soft_lock_is_serialized_with_restore_commit() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();

        // Soft lock must share the restore commit guard: while the commit
        // section holds it, the key move and purge cannot run, so the vault
        // stays fully unlocked instead of ending up flagged locked with the
        // key half-moved.
        let guard = vault.restore_guard.lock().unwrap();
        std::thread::scope(|s| {
            let locker = s.spawn(|| vault.soft_lock());
            std::thread::sleep(Duration::from_millis(100));
            assert!(
                vault.is_unlocked(),
                "soft lock must not bypass the restore commit guard"
            );
            assert!(
                vault.user_key.read().unwrap().is_some(),
                "the user key must stay in the session while the guard is held"
            );
            drop(guard);
            assert!(locker.join().unwrap());
        });
        assert!(!vault.is_unlocked());
        assert!(vault.quick_unlock_available());
    }

    #[test]
    fn test_quick_unlock_restore_fails_closed_on_empty_vault_with_changed_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // An empty vault (no ciphers, no wrapped private key) has nothing to
        // decrypt-test, so the only honest check is the account binding
        // recorded at retention. Here the user key is now wrapped under a
        // different master password: the retained key is stale and would
        // otherwise "unlock" an empty vault, letting the user create items
        // under a key the next real unlock cannot read.
        let mut rotated = vault.storage_mgr.load();
        rotated.ciphers = Vec::new();
        rotated.enc_private_key = None;
        rotated.enc_user_key = Some("2.rotated-by-a-password-change".to_string());
        vault.storage_mgr.save(&rotated).unwrap();

        let err = vault.quick_unlock_restore().unwrap_err();
        assert!(err.contains("no longer matches"), "got: {err}");
        assert!(!vault.is_unlocked());
        assert!(
            !vault.quick_unlock_available(),
            "an unverifiable retained key must be wiped, not left in the slot"
        );
        assert!(
            vault.quick_unlock_user_key_wrap.read().unwrap().is_none(),
            "the account binding must be wiped with the key"
        );
    }

    #[test]
    fn test_quick_unlock_restore_allows_an_unchanged_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        // Same account, same wrapping: the binding still matches, so an empty
        // vault must not be forced back to the master password.
        let mut same_account = vault.storage_mgr.load();
        same_account.ciphers = Vec::new();
        same_account.enc_private_key = None;
        vault.storage_mgr.save(&same_account).unwrap();

        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_unlock_rebinds_the_retained_key_so_an_empty_vault_stays_restorable() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());

        // A real unlock while a key is retained replaces the slot copy (and
        // its binding) with the key now in use. If the binding were dropped,
        // the empty-vault fallback below would fail closed for no reason.
        vault.unlock("master-pw").unwrap();
        let storage_wrap = vault
            .storage_mgr
            .load()
            .enc_user_key
            .expect("storage keeps the user key wrapping");
        assert_eq!(
            vault.quick_unlock_user_key_wrap.read().unwrap().as_deref(),
            Some(storage_wrap.as_str())
        );

        assert!(vault.soft_lock());
        assert_eq!(vault.quick_unlock_restore().unwrap(), 0);
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_quick_unlock_restore_wipes_on_stale_keyed_ciphers() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        assert!(vault.soft_lock());
        assert!(vault.quick_unlock_available());

        // Every personal cipher carries its own item key that does not
        // decrypt under the retained key. This vault shape used to leave
        // candidates == 0 (keyed ciphers were skipped) and fail open with
        // "Untitled" items; the key itself must now feed the probe.
        let mut stale = vault.storage_mgr.load();
        stale.ciphers = vec![serde_json::json!({
            "id": "cipher-keyed",
            "type": 1,
            "key": "2.not-a-valid-encstring",
            "name": "2.another-invalid-encstring",
            "login": null,
        })];
        vault.storage_mgr.save(&stale).unwrap();

        let err = vault.quick_unlock_restore().unwrap_err();
        assert!(err.contains("no longer matches"), "got: {err}");
        assert!(!vault.is_unlocked());
        assert!(!vault.quick_unlock_available());
    }

    #[test]
    fn test_quick_unlock_restore_accepts_keyed_ciphers_with_valid_keys() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        // Capture the key before soft_lock moves it to the retained slot.
        let user_key = vault.user_key.read().unwrap().clone().unwrap();
        // A REAL item key: a 64-byte symmetric key blob, not UTF-8 text. The
        // probe must accept it via raw decrypt(); a decrypt_string() probe
        // would reject the valid blob and wipe a perfectly good key.
        let item_key_blob = [42u8; 64];
        let item_key_enc = user_key.encrypt(&item_key_blob).unwrap();
        assert!(vault.soft_lock());

        // A keyed cipher whose item key decrypts under the retained key
        // validates the restore: carrying an item key must not count as a
        // failure (the probe prefers the key over the name).
        let mut fresh = vault.storage_mgr.load();
        fresh.ciphers = vec![serde_json::json!({
            "id": "cipher-keyed-ok",
            "type": 1,
            "key": item_key_enc,
            "name": "2.undecryptable-name-is-irrelevant",
            "login": null,
        })];
        vault.storage_mgr.save(&fresh).unwrap();

        vault.quick_unlock_restore().unwrap();
        assert!(vault.is_unlocked());
    }

    #[test]
    fn test_quick_unlock_restore_falls_back_to_name_when_key_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let vault = seeded_vault(dir.path(), "master-pw");
        vault.unlock("master-pw").unwrap();
        let user_key = vault.user_key.read().unwrap().clone().unwrap();
        let valid_name_enc = user_key.encrypt_string("GitHub").unwrap();
        assert!(vault.soft_lock());

        // An unparseable item key (corrupt sync, server quirk) must not veto
        // the cipher's valid encrypted name: the probe tries both fields.
        let mut fresh = vault.storage_mgr.load();
        fresh.ciphers = vec![serde_json::json!({
            "id": "cipher-corrupt-key",
            "type": 1,
            "key": "2.corrupt-item-key",
            "name": valid_name_enc,
            "login": null,
        })];
        vault.storage_mgr.save(&fresh).unwrap();

        vault.quick_unlock_restore().unwrap();
        assert!(vault.is_unlocked());
        assert!(vault.quick_unlock_available(), "no spurious wipe");
    }

    #[test]
    fn test_fuzzy_match() {
        assert!(is_fuzzy_match("", "anything"));
        assert!(is_fuzzy_match("git", "github"));
        assert!(is_fuzzy_match("gh", "github"));
        assert!(is_fuzzy_match("gthb", "github"));
        assert!(!is_fuzzy_match("xyz", "github"));
    }

    #[test]
    fn test_ssh_heuristics_rsa_in_notes() {
        let raw = json!({
            "name": "Server Key",
            "notes": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\nssh-rsa AAAAB3NzaC1yc2E... user@host"
        });
        let meta = detect_ssh_key_metadata(&raw).unwrap();
        assert!(meta.is_ssh_key);
        assert_eq!(meta.key_type, "RSA");
        assert!(meta.private_key.unwrap().contains("BEGIN RSA PRIVATE KEY"));
        assert!(meta.public_key.unwrap().starts_with("ssh-rsa"));
    }

    #[test]
    fn test_ssh_heuristics_ed25519_openssh() {
        let raw = json!({
            "name": "Dev Ed25519 Key",
            "notes": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...ssh-ed25519\n-----END OPENSSH PRIVATE KEY-----\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host"
        });
        let meta = detect_ssh_key_metadata(&raw).unwrap();
        assert!(meta.is_ssh_key);
        assert_eq!(meta.key_type, "ED25519");
        assert!(meta.private_key.is_some());
        assert_eq!(
            meta.public_key.unwrap(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host"
        );
    }

    #[test]
    fn test_ssh_heuristics_custom_fields() {
        let raw = json!({
            "name": "Custom SSH Item",
            "notes": "Some regular notes",
            "fields": [
                { "name": "private_key", "value": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----" },
                { "name": "public_key", "value": "ecdsa-sha2-nistp256 AAAAE2VjZHNh... user@host" },
                { "name": "passphrase", "value": "secret_passphrase_123" }
            ]
        });
        let meta = detect_ssh_key_metadata(&raw).unwrap();
        assert!(meta.is_ssh_key);
        assert_eq!(meta.key_type, "ECDSA");
        assert!(meta.private_key.unwrap().contains("BEGIN EC PRIVATE KEY"));
        assert!(meta.public_key.unwrap().starts_with("ecdsa-sha2-nistp256"));
        assert_eq!(meta.passphrase.unwrap(), "secret_passphrase_123");
    }

    #[test]
    fn test_parse_and_search_categories() {
        let raw_items = vec![
            json!({
                "id": "1",
                "name": "GitHub",
                "type": 1,
                "login": {
                    "username": "octocat",
                    "uris": [{ "uri": "https://github.com" }]
                },
                "favorite": true
            }),
            json!({
                "id": "2",
                "name": "Bank Card",
                "type": 3,
                "card": {
                    "brand": "Visa",
                    "number": "4111222233334444"
                }
            }),
            json!({
                "id": "3",
                "name": "Server Access",
                "type": 5,
                "sshKey": {
                    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
                    "keyFingerprint": "SHA256:abcd1234efgh"
                }
            }),
            json!({
                "id": "4",
                "name": "Server Backup Notes",
                "type": 2,
                "notes": "Here is a note with ssh-rsa AAAAB3... that should stay as a note"
            }),
        ];

        let vault_mgr = VaultManager::new("https://vault.example.com", None, None);
        let items = vault_mgr.parse_raw_items(&raw_items);
        assert_eq!(items.len(), 4);

        assert_eq!(items[0].type_name, "login");
        assert_eq!(items[0].sub_title, "octocat");

        assert_eq!(items[1].type_name, "card");
        assert_eq!(items[1].sub_title, "Visa •••• 4444");

        assert_eq!(items[2].type_name, "ssh_key");
        assert_eq!(items[2].sub_title, "SSH Key (ED25519)");
        assert!(items[2].ssh_key.is_some());
        assert_eq!(
            items[2].ssh_key.as_ref().unwrap().fingerprint.as_deref(),
            Some("SHA256:abcd1234efgh")
        );

        assert_eq!(items[3].type_name, "note");
        assert_eq!(items[3].sub_title, "Secure Note");
        assert!(items[3].ssh_key.is_none());

        let search_gh = vault_mgr.search(&items, "github", None);
        assert_eq!(search_gh.len(), 1);
        assert_eq!(search_gh[0].id, "1");

        let search_card = vault_mgr.search(&items, "", Some("card"));
        assert_eq!(search_card.len(), 1);
        assert_eq!(search_card[0].id, "2");

        let search_ssh = vault_mgr.search(&items, "", Some("ssh_key"));
        assert_eq!(search_ssh.len(), 1);
        assert_eq!(search_ssh[0].id, "3");

        let search_note = vault_mgr.search(&items, "", Some("note"));
        assert_eq!(search_note.len(), 1);
        assert_eq!(search_note[0].id, "4");
    }

    #[test]
    fn test_vault_manager_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault_test.json");
        let storage_mgr = StorageManager::new(path);

        let dummy_keyring = KeyringManager::new("/nonexistent-keyring");
        let vault_mgr = VaultManager::new(
            "https://vault.example.com",
            Some(storage_mgr),
            Some(dummy_keyring),
        );
        assert!(!vault_mgr.is_unlocked());
        assert_eq!(vault_mgr.decrypted_items.read().unwrap().len(), 0);

        let st = vault_mgr.get_status();
        assert_eq!(
            st.get("status").unwrap().as_str().unwrap(),
            "unauthenticated"
        );

        let cycle = st["lock_generation"].as_str().unwrap();
        assert_eq!(vault_mgr.get_status()["lock_generation"], cycle);
        *vault_mgr.is_unlocked.write().unwrap() = true;
        vault_mgr.lock();
        assert_ne!(vault_mgr.get_status()["lock_generation"], cycle);
        assert!(!vault_mgr.is_unlocked());
        let sync_err = vault_mgr.sync();
        assert!(sync_err.is_err());
        assert_eq!(
            sync_err.unwrap_err(),
            "Please log in again to use account-scoped credentials."
        );
    }

    #[test]
    fn test_sync_allowed_when_locked_with_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault_sync_locked.json");
        let storage_mgr = StorageManager::new(path.clone());
        let fixture = serde_json::json!({
            "server_url": "http://127.0.0.1:9",
            "user_email": "fixture@example.invalid",
            "credential_id": crate::test_support::CREDENTIAL_ID,
        });
        std::fs::write(&path, fixture.to_string()).unwrap();
        let script = dir.path().join("secret-tool");
        crate::write_test_executable(&script, "#!/bin/sh\necho fake_test_token\n");
        let dummy_keyring = KeyringManager::new(script.to_str().unwrap());
        let vault_mgr =
            VaultManager::new("http://127.0.0.1:9", Some(storage_mgr), Some(dummy_keyring));
        assert!(!vault_mgr.is_unlocked());

        let sync_res = vault_mgr.sync();
        assert!(sync_res.is_err());
        let err_msg = sync_res.unwrap_err();
        assert!(!err_msg.contains("Vault is locked"));
        assert!(!err_msg.contains("Session token missing"));
        assert!(err_msg.contains("Sync failed"));
    }

    #[test]
    fn test_find_ssh_key() {
        let raw_items = vec![
            json!({
                "id": "item-uuid-1",
                "name": "Production Deploy Key",
                "type": 5,
                "sshKey": {
                    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@host",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
                    "keyFingerprint": "SHA256:abc123xyz"
                }
            }),
            json!({
                "id": "item-uuid-2",
                "name": "GitHub CI Key",
                "type": 5,
                "sshKey": {
                    "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAA test@github",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-rsa\n-----END OPENSSH PRIVATE KEY-----",
                    "keyFingerprint": "SHA256:rsa456"
                }
            }),
        ];

        let vault_mgr = VaultManager::new("https://vault.example.com", None, None);
        let items = vault_mgr.parse_raw_items(&raw_items);
        *vault_mgr.decrypted_items.write().unwrap() = items;
        *vault_mgr.is_unlocked.write().unwrap() = true;

        // Exact ID lookup
        let found_id = vault_mgr.find_ssh_key("item-uuid-1");
        assert!(found_id.is_some());
        assert_eq!(found_id.unwrap().name, "Production Deploy Key");

        // Exact name lookup (case insensitive)
        let found_name = vault_mgr.find_ssh_key("github ci key");
        assert!(found_name.is_some());
        assert_eq!(found_name.unwrap().id, "item-uuid-2");

        // Substring name lookup
        let found_sub = vault_mgr.find_ssh_key("deploy");
        assert!(found_sub.is_some());
        assert_eq!(found_sub.unwrap().id, "item-uuid-1");

        // Not found
        let not_found = vault_mgr.find_ssh_key("nonexistent-key");
        assert!(not_found.is_none());

        // Generic find_item test
        let found_gen = vault_mgr.find_item("Deploy Key", None);
        assert!(found_gen.is_some());
        assert_eq!(found_gen.unwrap().id, "item-uuid-1");

        let found_cat = vault_mgr.find_item("Deploy Key", Some("ssh_key"));
        assert!(found_cat.is_some());

        let not_found_cat = vault_mgr.find_item("Deploy Key", Some("login"));
        assert!(not_found_cat.is_none());
    }

    #[test]
    fn test_resolve_cipher_target() {
        let raw_items = vec![
            json!({
                "id": "c7694fca-443b-417f-94ad-7be20b694406",
                "name": "GitHub Account",
                "type": 1,
            }),
            json!({
                "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "name": "GitLab Personal",
                "type": 1,
            }),
            json!({
                "id": "cccc1111-cccc-cccc-cccc-cccccccccccc",
                "name": "Duplicate Name",
                "type": 1,
            }),
            json!({
                "id": "cccc2222-dddd-dddd-dddd-dddddddddddd",
                "name": "Duplicate Name",
                "type": 1,
            }),
        ];
        let vault_mgr = VaultManager::new("http://127.0.0.1:9", None, None);
        let items = vault_mgr.parse_raw_items(&raw_items);
        *vault_mgr.decrypted_items.write().unwrap() = items;
        *vault_mgr.is_unlocked.write().unwrap() = true;

        // 1. Exact 36-char UUID match
        let found = vault_mgr
            .resolve_cipher_target("c7694fca-443b-417f-94ad-7be20b694406")
            .unwrap();
        assert_eq!(found.id, "c7694fca-443b-417f-94ad-7be20b694406");

        // 2. 32-char hex match (without hyphens)
        let found_hex = vault_mgr
            .resolve_cipher_target("c7694fca443b417f94ad7be20b694406")
            .unwrap();
        assert_eq!(found_hex.id, "c7694fca-443b-417f-94ad-7be20b694406");

        // 3. Exact name match (case-insensitive)
        let found_name = vault_mgr.resolve_cipher_target("github account").unwrap();
        assert_eq!(found_name.id, "c7694fca-443b-417f-94ad-7be20b694406");

        // 4. Unique ID prefix match (with and without hyphens)
        let found_prefix = vault_mgr.resolve_cipher_target("c7694fca").unwrap();
        assert_eq!(found_prefix.id, "c7694fca-443b-417f-94ad-7be20b694406");

        let found_prefix_uuid = vault_mgr.resolve_cipher_target("c7694fca-443b").unwrap();
        assert_eq!(found_prefix_uuid.id, "c7694fca-443b-417f-94ad-7be20b694406");

        // 5. Substring (fuzzy) match
        let found_sub = vault_mgr.resolve_cipher_target("gitlab").unwrap();
        assert_eq!(found_sub.id, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

        // 6. Ambiguous exact name match fails closed
        let err_ambig_exact = vault_mgr
            .resolve_cipher_target("Duplicate Name")
            .unwrap_err();
        assert!(err_ambig_exact.contains("Multiple ciphers matched 'Duplicate Name'"));

        // 7. Ambiguous ID prefix match fails closed
        let err_ambig_prefix = vault_mgr.resolve_cipher_target("cccc").unwrap_err();
        assert!(err_ambig_prefix.contains("Multiple ciphers matched 'cccc'"));

        // 8. Ambiguous substring match fails closed ("git" matches GitHub Account and GitLab Personal)
        let err_ambig_sub = vault_mgr.resolve_cipher_target("git").unwrap_err();
        assert!(err_ambig_sub.contains("Multiple ciphers matched 'git'"));

        // 9. Not found fails closed
        let err_not_found = vault_mgr.resolve_cipher_target("nonexistent").unwrap_err();
        assert_eq!(err_not_found, "Cipher 'nonexistent' not found in vault.");

        // 10. Empty target fails closed
        let err_empty = vault_mgr.resolve_cipher_target("   ").unwrap_err();
        assert_eq!(err_empty, "Target cipher cannot be empty.");

        // 11. Direct verify CipherTargetResolution variants
        match vault_mgr
            .resolve_cipher_target_candidates("GitHub Account")
            .unwrap()
        {
            CipherTargetResolution::Exact(item) => {
                assert_eq!(item.id, "c7694fca-443b-417f-94ad-7be20b694406");
            }
            _ => panic!("Expected Exact"),
        }

        match vault_mgr
            .resolve_cipher_target_candidates("Duplicate Name")
            .unwrap()
        {
            CipherTargetResolution::Ambiguous(candidates) => {
                assert_eq!(candidates.len(), 2);
            }
            _ => panic!("Expected Ambiguous"),
        }

        match vault_mgr
            .resolve_cipher_target_candidates("does-not-exist")
            .unwrap()
        {
            CipherTargetResolution::NotFound(msg) => {
                assert!(msg.contains("not found in vault"));
            }
            _ => panic!("Expected NotFound"),
        }
    }

    #[test]
    fn test_vault_sync_silent_reauth_with_api_secret_on_expired_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        // Spawn mock server responding to /identity/connect/token and /api/sync
        let server_handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("/identity/connect/token") {
                    let body = serde_json::json!({
                        "access_token": "renewed_access_token_abc123",
                        "expires_in": 7200,
                        "token_type": "Bearer"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("/api/sync") {
                    assert!(req.contains("Bearer renewed_access_token_abc123"));
                    let body = serde_json::json!({
                        "ciphers": [],
                        "folders": [],
                        "collections": [],
                        "profile": {
                            "id": "uuid-sync-user",
                            "email": "sync@example.com"
                        }
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_reauth.json");
        let storage_mgr = StorageManager::new(storage_path);

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
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

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let client_id = "user.reauth-test-id";
        let client_secret = "reauth-secret-val";

        // Store an EXPIRED access token in Keyring
        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 300 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);
        let storage = VaultStorage {
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
            server_url: server_url.clone(),
            user_email: "reauth@example.com".to_string(),
            client_id: Some(client_id.to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();
        let keys = mock_keyring.for_storage(&storage);
        assert!(keys.store_token(crate::keyring::KIND_API_SECRET, client_secret));
        assert!(keys.store_token(crate::keyring::KIND_ACCESS_TOKEN, &expired_token));

        let vault_mgr = VaultManager::new(
            &server_url,
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // sync() should detect expired token, silently re-auth via API secret, and successfully sync
        let sync_res = vault_mgr.sync();
        assert!(
            sync_res.is_ok(),
            "Sync should succeed after silent re-auth: {:?}",
            sync_res
        );

        let _ = server_handle.join();

        // Verify the new token is stored in Keyring
        assert_eq!(
            keys.access_token(),
            Some("renewed_access_token_abc123".to_string())
        );
        // Verify disk storage remains zero-plaintext
        let fresh_storage = storage_mgr.load();
        assert!(fresh_storage.access_token.is_none());
    }

    #[test]
    fn test_vault_sync_reauth_failure_purges_tokens_and_locks() {
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_url = format!("http://{}", listener.local_addr().unwrap());

        let server_handle = thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.contains("/connect/token") {
                    let body = serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "Refresh token revoked"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_reauth_fail.json");
        let storage_mgr = StorageManager::new(storage_path);

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
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

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let client_id = "user.fail-test";
        let client_secret = "secret-val-to-retain";

        let storage = VaultStorage {
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
            client_id: Some(client_id.into()),
            server_url: server_url.clone(),
            user_email: "fail@example.com".to_string(),
            refresh_token: Some("revoked_ref_token".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();
        let keys = mock_keyring.for_storage(&storage);
        assert!(keys.store_token(crate::keyring::KIND_API_SECRET, client_secret));
        assert!(keys.store_token(crate::keyring::KIND_REFRESH_TOKEN, "revoked_ref_token"));

        let vault_mgr = VaultManager::new(
            &server_url,
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // renew_session should fail with auth rejection, purge tokens, and lock vault
        let res = vault_mgr.renew_session();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Session expired or credentials rejected. Please log in again."
        );

        let _ = server_handle.join();

        // Keyring tokens purged
        assert_eq!(keys.access_token(), None);
        assert_eq!(keys.refresh_token(), None);

        // API secret is preserved
        assert_eq!(keys.api_secret(), Some(client_secret.to_string()));

        // Storage tokens purged
        let fresh_storage = storage_mgr.load();
        assert!(fresh_storage.access_token.is_none());
        assert!(fresh_storage.refresh_token.is_none());
    }

    #[test]
    fn test_vault_sync_network_error_preserves_tokens() {
        use std::fs;

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_reauth_net_fail.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
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

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let legacy_json = serde_json::json!({
            "credential_id": crate::test_support::CREDENTIAL_ID,
            "server_url": "http://127.0.0.1:9",
            "user_email": "offline@example.com",
            "refresh_token": "valid_ref_token"
        });
        fs::write(&storage_path, legacy_json.to_string()).unwrap();
        let stored = storage_mgr.load();
        let keys = mock_keyring.for_storage(&stored);
        assert!(keys.store_token(crate::keyring::KIND_REFRESH_TOKEN, "valid_ref_token"));

        let vault_mgr = VaultManager::new(
            "http://127.0.0.1:9",
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // renew_session should fail due to network error without wiping tokens
        let res = vault_mgr.renew_session();
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Network error"));

        // Keyring refresh token NOT purged
        assert_eq!(keys.refresh_token(), Some("valid_ref_token".to_string()));

        // Storage tokens NOT purged
        let fresh_storage = storage_mgr.load();
        assert_eq!(
            fresh_storage.refresh_token,
            Some("valid_ref_token".to_string())
        );
    }

    #[test]
    fn test_vault_sync_server_502_error_preserves_tokens() {
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            let mut count = 0;
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let resp =
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes());
                count += 1;
                if count >= 2 {
                    break;
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().join("vault_502_preserves.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
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

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let legacy_json = serde_json::json!({
            "credential_id": crate::test_support::CREDENTIAL_ID,
            "server_url": server_url.clone(),
            "user_email": "gateway502@example.com",
            "client_id": "test_client_id",
            "refresh_token": "valid_ref_token"
        });
        fs::write(&storage_path, legacy_json.to_string()).unwrap();
        let stored = storage_mgr.load();
        let keys = mock_keyring.for_storage(&stored);
        assert!(keys.store_token(crate::keyring::KIND_REFRESH_TOKEN, "valid_ref_token"));
        assert!(keys.store_token(crate::keyring::KIND_API_SECRET, "test_secret"));

        let vault_mgr = VaultManager::new(
            &server_url,
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // renew_session should fail due to 502 without wiping tokens
        let res = vault_mgr.renew_session();
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Network error"));

        // Keyring refresh token and api secret NOT purged
        assert_eq!(keys.refresh_token(), Some("valid_ref_token".to_string()));
        assert_eq!(keys.api_secret(), Some("test_secret".to_string()));

        // Storage tokens NOT purged
        let fresh_storage = storage_mgr.load();
        assert_eq!(
            fresh_storage.refresh_token,
            Some("valid_ref_token".to_string())
        );

        let _ = handle.join();
    }
}
