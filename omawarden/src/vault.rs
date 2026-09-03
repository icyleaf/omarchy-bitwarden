use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::RwLock;

use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient};
use crate::crypto::{
    parse_rsa_private_key_der, parse_symmetric_key_from_decrypted_bytes, EncString,
    SymmetricCryptoKey,
};
use crate::keyring::KeyringManager;
use crate::storage::{StorageManager, VaultStorage};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshMetadata {
    pub is_ssh_key: bool,
    pub key_type: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub storage_mgr: StorageManager,
    pub keyring_mgr: KeyringManager,
    pub storage: RwLock<VaultStorage>,
    pub decrypted_items: RwLock<Vec<VaultItem>>,
    pub user_key: RwLock<Option<SymmetricCryptoKey>>,
    pub is_unlocked: RwLock<bool>,
}

impl VaultManager {
    pub fn new(
        server_url: &str,
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

        Self {
            server_url: effective_url,
            storage_mgr: sm,
            keyring_mgr: keyring_mgr.unwrap_or_default(),
            storage: RwLock::new(storage),
            decrypted_items: RwLock::new(Vec::new()),
            user_key: RwLock::new(None),
            is_unlocked: RwLock::new(false),
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked.read().map(|g| *g).unwrap_or(false)
    }

    pub fn lock(&self) {
        if let Ok(mut unl) = self.is_unlocked.write() {
            *unl = false;
        }
        if let Ok(mut items) = self.decrypted_items.write() {
            items.clear();
        }
        if let Ok(mut key) = self.user_key.write() {
            *key = None;
        }
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let fresh_storage = self.storage_mgr.load();
        if fresh_storage.enc_user_key.is_none() {
            crate::log_error!(
                "omawarden:vault",
                "Account not logged in or missing encryption keys."
            );
            return Err("Account not logged in or missing encryption keys.".to_string());
        }

        let user_key = self
            .storage_mgr
            .unlock_user_key(password, &fresh_storage)
            .map_err(|e| {
                crate::log_warn!("omawarden:vault", "Unlock user key failed: {:?}", e);
                format!("Unlock failed: {:?}", e)
            })?;

        let items = decrypt_sync_ciphers_with_context(
            &fresh_storage.ciphers,
            &fresh_storage.folders,
            &fresh_storage.organizations,
            &user_key,
            fresh_storage.enc_private_key.as_deref(),
        );
        let count = items.len();

        if let Ok(mut dec_items) = self.decrypted_items.write() {
            *dec_items = items;
        }
        if let Ok(mut key) = self.user_key.write() {
            *key = Some(user_key);
        }
        if let Ok(mut unl) = self.is_unlocked.write() {
            *unl = true;
        }
        if let Ok(mut st) = self.storage.write() {
            *st = fresh_storage;
        }

        crate::log_info!(
            "omawarden:vault",
            "Decrypted and cached {} items in memory.",
            count
        );
        Ok(count)
    }

    pub fn sync(&self) -> Result<usize, String> {
        crate::log_info!(
            "omawarden:vault",
            "Starting vault synchronization with server..."
        );
        let storage = self.storage_mgr.load();
        let token = storage.access_token.as_ref().ok_or_else(|| {
            crate::log_error!("omawarden:vault", "Session token missing. Please log in.");
            "Session token missing. Please log in.".to_string()
        })?;

        let client = BitwardenApiClient::new(if self.server_url.is_empty() {
            &storage.server_url
        } else {
            &self.server_url
        });
        let sync_resp_res = client.sync_vault(token);

        let sync_resp = match sync_resp_res {
            Ok(resp) => resp,
            Err(ApiError::Http(ref msg)) if msg.contains("401") || msg.contains("403") => {
                crate::log_warn!(
                    "omawarden:vault",
                    "HTTP 401/403 on sync. Attempting token refresh..."
                );
                if let Some(ref ref_tok) = storage.refresh_token {
                    if let Ok(tok_resp) = client.refresh_token_grant(ref_tok) {
                        crate::log_info!(
                            "omawarden:vault",
                            "Token refresh successful. Resuming sync."
                        );
                        let mut updated_tok = storage.clone();
                        updated_tok.access_token = Some(tok_resp.access_token.clone());
                        if let Some(new_ref) = tok_resp.refresh_token {
                            updated_tok.refresh_token = Some(new_ref);
                        }
                        let _ = self.storage_mgr.save(&updated_tok);
                        client.sync_vault(&tok_resp.access_token).map_err(|e| {
                            crate::log_error!(
                                "omawarden:vault",
                                "Sync failed after token refresh: {:?}",
                                e
                            );
                            format!("Sync failed: {:?}", e)
                        })?
                    } else {
                        crate::log_error!(
                            "omawarden:vault",
                            "Session expired. Please log in again."
                        );
                        return Err("Session expired. Please log in again.".to_string());
                    }
                } else {
                    crate::log_error!(
                        "omawarden:vault",
                        "Session expired and no refresh token available."
                    );
                    return Err("Session expired. Please log in again.".to_string());
                }
            }
            Err(e) => {
                crate::log_error!("omawarden:vault", "Sync failed: {:?}", e);
                return Err(format!("Sync failed: {:?}", e));
            }
        };

        let count = sync_resp.ciphers.len();
        let mut updated = storage.clone();
        updated.ciphers = sync_resp.ciphers;
        updated.folders = sync_resp.folders;
        updated.collections = sync_resp.collections;
        if let Some(ref prof) = sync_resp.profile {
            if let Some(orgs) = prof.get("organizations").and_then(|v| v.as_array()) {
                updated.organizations = orgs.clone();
            }
        }
        updated.last_sync = Some(chrono::Utc::now().to_rfc3339());

        self.storage_mgr
            .save(&updated)
            .map_err(|e| format!("Failed to save storage: {:?}", e))?;

        if let Ok(key_guard) = self.user_key.read() {
            if let Some(user_key) = key_guard.as_ref() {
                let items = decrypt_sync_ciphers_with_context(
                    &updated.ciphers,
                    &updated.folders,
                    &updated.organizations,
                    user_key,
                    updated.enc_private_key.as_deref(),
                );
                if let Ok(mut dec_items) = self.decrypted_items.write() {
                    *dec_items = items;
                }
            }
        }

        if let Ok(mut st) = self.storage.write() {
            *st = updated;
        }

        crate::log_info!(
            "omawarden:vault",
            "Vault sync complete. {} ciphers, {} folders saved.",
            count,
            self.storage.read().map(|s| s.folders.len()).unwrap_or(0)
        );

        Ok(count)
    }

    pub fn get_items(&self) -> Vec<VaultItem> {
        let is_unlocked = self.is_unlocked();
        if !is_unlocked {
            if let Some(daemon_resp) =
                crate::daemon::send_daemon_request(&serde_json::json!({ "action": "list" }))
            {
                if let Ok(items) = serde_json::from_value::<Vec<VaultItem>>(daemon_resp) {
                    return items;
                }
            }
            return Vec::new();
        }
        self.decrypted_items
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn search_items(&self, query: &str, category: Option<&str>) -> Vec<VaultItem> {
        let is_unlocked = self.is_unlocked();
        if !is_unlocked {
            if let Some(daemon_resp) = crate::daemon::send_daemon_request(&serde_json::json!({
                "action": "search",
                "query": query,
                "category": category
            })) {
                if let Ok(items) = serde_json::from_value::<Vec<VaultItem>>(daemon_resp) {
                    return items;
                }
            }
            return Vec::new();
        }
        let items = self.decrypted_items.read().unwrap().clone();
        self.search(&items, query, category)
    }

    pub fn resolve_attachment_key(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Option<SymmetricCryptoKey> {
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
        self.user_key.read().ok().and_then(|k| k.clone())
    }

    pub fn create_ssh_key(
        &self,
        name: &str,
        ssh_key_data: &crate::ssh::GeneratedSshKey,
        notes: Option<&str>,
        folder_id: Option<&str>,
        user_key: &SymmetricCryptoKey,
    ) -> Result<VaultItem, String> {
        let storage = self.storage_mgr.load();
        let token = storage
            .access_token
            .as_deref()
            .ok_or_else(|| "Not logged in or missing access token".to_string())?;

        let enc_name = user_key
            .encrypt_string(name)
            .map_err(|e| format!("Failed to encrypt item name: {:?}", e))?;

        let enc_notes = if let Some(n) = notes.filter(|s| !s.is_empty()) {
            Some(
                user_key
                    .encrypt_string(n)
                    .map_err(|e| format!("Failed to encrypt notes: {:?}", e))?,
            )
        } else {
            None
        };

        let enc_private_key = user_key
            .encrypt_string(&ssh_key_data.private_key)
            .map_err(|e| format!("Failed to encrypt private key: {:?}", e))?;

        let enc_public_key = user_key
            .encrypt_string(&ssh_key_data.public_key)
            .map_err(|e| format!("Failed to encrypt public key: {:?}", e))?;

        let enc_fingerprint = user_key
            .encrypt_string(&ssh_key_data.fingerprint)
            .map_err(|e| format!("Failed to encrypt fingerprint: {:?}", e))?;

        let payload = json!({
            "type": 5,
            "folderId": folder_id,
            "organizationId": null,
            "name": enc_name,
            "notes": enc_notes,
            "favorite": false,
            "reprompt": 0,
            "sshKey": {
                "privateKey": enc_private_key,
                "publicKey": enc_public_key,
                "keyFingerprint": enc_fingerprint,
            }
        });

        let client = BitwardenApiClient::new(if !storage.server_url.is_empty() {
            &storage.server_url
        } else {
            &self.server_url
        });

        let created_cipher = client
            .create_cipher(token, &payload)
            .map_err(|e| format!("Failed to create SSH key on server: {:?}", e))?;

        // Update local storage data.json
        let mut updated_storage = storage.clone();
        updated_storage.ciphers.push(created_cipher.clone());
        let _ = self.storage_mgr.save(&updated_storage);

        // Decrypt the created item into a VaultItem
        let decrypted_items = decrypt_sync_ciphers_with_context(
            &[created_cipher],
            &updated_storage.folders,
            &updated_storage.organizations,
            user_key,
            updated_storage.enc_private_key.as_deref(),
        );

        let decrypted_item = decrypted_items
            .into_iter()
            .next()
            .ok_or_else(|| "Failed to decrypt newly created cipher item".to_string())?;

        // Update in-memory items if unlocked
        if let Ok(mut items) = self.decrypted_items.write() {
            items.push(decrypted_item.clone());
        }

        crate::log_info!(
            "omawarden:vault",
            "Successfully created and stored SSH key '{}' ({})",
            decrypted_item.name,
            decrypted_item.id
        );

        Ok(decrypted_item)
    }

    pub fn find_ssh_key(&self, id_or_name: &str) -> Option<VaultItem> {
        let items = self.get_items();
        let target = id_or_name.trim();

        // 1. Exact ID match
        if let Some(item) = items
            .iter()
            .find(|i| i.type_name == "ssh_key" && i.id == target)
        {
            return Some(item.clone());
        }

        // 2. Exact Name match (case-insensitive)
        if let Some(item) = items
            .iter()
            .find(|i| i.type_name == "ssh_key" && i.name.eq_ignore_ascii_case(target))
        {
            return Some(item.clone());
        }

        // 3. Name contains query (case-insensitive)
        let lower = target.to_lowercase();
        if let Some(item) = items
            .iter()
            .find(|i| i.type_name == "ssh_key" && i.name.to_lowercase().contains(&lower))
        {
            return Some(item.clone());
        }

        None
    }

    pub fn get_status(&self) -> Value {
        let is_unlocked = self.is_unlocked();
        let fresh_storage = self.storage_mgr.load();
        json!({
            "ok": true,
            "status": if is_unlocked { "unlocked" } else if fresh_storage.enc_user_key.is_some() { "locked" } else { "unauthenticated" },
            "server_url": fresh_storage.server_url,
            "user_email": fresh_storage.user_email,
            "user_id": fresh_storage.user_id,
            "last_sync": fresh_storage.last_sync,
            "is_unlocked": is_unlocked,
            "items_count": self.decrypted_items.read().map(|i| i.len()).unwrap_or(0),
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
mod tests {
    use super::*;
    use serde_json::json;

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

        let vault_mgr = VaultManager::new("https://vault.example.com", Some(storage_mgr), None);
        assert!(!vault_mgr.is_unlocked());
        assert_eq!(vault_mgr.decrypted_items.read().unwrap().len(), 0);

        let st = vault_mgr.get_status();
        assert_eq!(
            st.get("status").unwrap().as_str().unwrap(),
            "unauthenticated"
        );

        vault_mgr.lock();
        assert!(!vault_mgr.is_unlocked());
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
    }
}
