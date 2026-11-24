//! Daemon-owned folder mutations and decrypted folder directory access.
//! Folder names are encrypted with `user_key` before crossing the HTTP boundary,
//! and local cache + in-memory cipher projections are reconciled atomically.
use crate::api::{ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::EncString;
use crate::ssh_write::WriteError;
use crate::storage::VaultStorage;
use crate::vault::VaultManager;
use crate::vault_cache::{CacheSession, IndexUpdate};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedFolder {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) count: usize,
}

impl VaultManager {
    /// Returns all decrypted folders from local storage with active (non-trashed)
    /// cipher counts, sorted alphabetically by name (case-insensitive, tie-broken by id).
    pub(crate) fn list_folders(&self) -> Result<Vec<Value>, String> {
        let unlocked = self
            .is_unlocked
            .read()
            .map_err(|_| "Vault state unavailable".to_string())?;
        if !*unlocked {
            return Err("Vault is locked.".to_string());
        }
        let user_key_guard = self
            .user_key
            .read()
            .map_err(|_| "Vault key unavailable".to_string())?;
        let user_key = user_key_guard
            .as_ref()
            .ok_or_else(|| "Vault is locked.".to_string())?;
        let storage = self
            .storage
            .read()
            .map_err(|_| "Vault state unavailable".to_string())?;
        let items = self
            .decrypted_items
            .read()
            .map_err(|_| "Vault index unavailable".to_string())?;

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for item in items.iter() {
            if item.deleted_at.is_none() {
                if let Some(fid) = item.folder_id.as_deref().filter(|s| !s.is_empty()) {
                    *counts.entry(fid).or_insert(0) += 1;
                }
            }
        }

        let mut entries: Vec<ResolvedFolder> = Vec::with_capacity(storage.folders.len());
        for f in &storage.folders {
            let Some(id) = f
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            let name = f
                .get("name")
                .and_then(Value::as_str)
                .and_then(|enc| EncString::parse(enc).ok())
                .and_then(|enc| enc.decrypt_string(user_key).ok())
                .unwrap_or_default();
            let count = counts.get(id).copied().unwrap_or(0);
            entries.push(ResolvedFolder {
                id: id.to_string(),
                name,
                count,
            });
        }

        entries.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.id.cmp(&b.id))
        });

        Ok(entries
            .into_iter()
            .map(|e| json!({ "id": e.id, "name": e.name, "count": e.count }))
            .collect())
    }

    pub(crate) fn resolve_folder_target(&self, target: &str) -> Result<ResolvedFolder, String> {
        let needle = target.trim();
        if needle.is_empty() {
            return Err("Missing folder target.".to_string());
        }
        let folders = self.list_folders()?;
        let parsed: Vec<ResolvedFolder> = folders
            .into_iter()
            .filter_map(|v| {
                Some(ResolvedFolder {
                    id: v.get("id")?.as_str()?.to_string(),
                    name: v.get("name")?.as_str()?.to_string(),
                    count: v.get("count")?.as_u64()? as usize,
                })
            })
            .collect();

        // 1. Exact UUID / ID match
        if let Some(found) = parsed.iter().find(|f| f.id == needle) {
            return Ok(found.clone());
        }

        // 2. Exact name match
        let exact_matches: Vec<&ResolvedFolder> =
            parsed.iter().filter(|f| f.name == needle).collect();
        if exact_matches.len() == 1 {
            return Ok(exact_matches[0].clone());
        }
        if exact_matches.len() > 1 {
            let list = exact_matches
                .iter()
                .map(|f| format!("{} ({})", f.name, f.id))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "Multiple folders matched '{needle}': [{list}]. Specify the folder by its UUID."
            ));
        }

        // 3. Case-insensitive name match
        let ci_matches: Vec<&ResolvedFolder> = parsed
            .iter()
            .filter(|f| f.name.eq_ignore_ascii_case(needle))
            .collect();
        if ci_matches.len() == 1 {
            return Ok(ci_matches[0].clone());
        }
        if ci_matches.len() > 1 {
            let list = ci_matches
                .iter()
                .map(|f| format!("{} ({})", f.name, f.id))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "Multiple folders matched '{needle}': [{list}]. Specify the folder by its UUID."
            ));
        }

        Err(format!("Folder '{needle}' not found."))
    }

    pub(crate) fn create_folder(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;
        let req_payload = request.get("mutation").unwrap_or(&request);
        let raw_name = req_payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if raw_name.is_empty() {
            return Err(WriteError::Rejected("Folder name cannot be empty.".into()));
        }

        let payload = {
            let unlocked = self
                .is_unlocked
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            let active = self
                .storage
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            if !*unlocked
                || generation != self.lock_generation()
                || !active.same_active_slot(&storage)
            {
                return Err(WriteError::Rejected("Vault session changed.".into()));
            }
            drop(active);
            let key = self
                .user_key
                .read()
                .map_err(|_| "Vault key unavailable".to_string())?;
            let user_key = key.as_ref().ok_or_else(|| "Vault is locked.".to_string())?;
            let enc_name = user_key
                .encrypt_string(&raw_name)
                .map_err(|_| "Could not encrypt folder name.".to_string())?;
            json!({ "name": enc_name })
        };

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_cipher_write(server, context).map_err(|_| {
            WriteError::Rejected("Could not initialize the folder HTTP client.".into())
        })?;
        let token = self.keyring_mgr.for_storage(&storage).access_token();
        let renew = || self.renew_for_account(&storage, context, generation);
        let mut token = match token.filter(|t| !crate::auth::is_jwt_expired(t)) {
            Some(t) => t,
            None => renew()?,
        };
        let mut renewed_after_rejection = false;
        let _pending = self
            .storage_mgr
            .begin_cipher_write()
            .map_err(|e| e.to_string())?;

        let folder = loop {
            let same_account = self
                .storage_mgr
                .load_existing()
                .is_ok_and(|s| s.same_active_slot(&storage));
            let current = self
                .is_unlocked
                .read()
                .is_ok_and(|unlocked| *unlocked && self.lock_generation() == generation);
            if !same_account || !current {
                return Err(WriteError::Rejected(
                    "Session changed before creating the folder.".into(),
                ));
            }
            match client.create_folder(&token, &payload) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => break result?,
            }
        };

        let id = folder["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or(WriteError::Unknown)?;
        let cached = self
            .cache_upserted_folder(&storage, generation, &folder, id, None)
            .is_some();
        Ok(json!({
            "ok": true,
            "outcome": if cached { "saved" } else { "saved_needs_sync" },
            "folder": {
                "id": id,
                "name": raw_name,
                "count": 0,
                "revisionDate": folder["revisionDate"].as_str(),
            }
        }))
    }

    pub(crate) fn update_folder(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;
        let req_payload = request.get("mutation").unwrap_or(&request);
        let target = req_payload
            .get("id")
            .or_else(|| req_payload.get("target"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let new_name = req_payload
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if new_name.is_empty() {
            return Err(WriteError::Rejected("Folder name cannot be empty.".into()));
        }

        let (resolved, payload) = {
            let unlocked = self
                .is_unlocked
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            let active = self
                .storage
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            if !*unlocked
                || generation != self.lock_generation()
                || !active.same_active_slot(&storage)
            {
                return Err(WriteError::Rejected("Vault session changed.".into()));
            }
            drop(active);
            drop(unlocked);

            let resolved = self
                .resolve_folder_target(target)
                .map_err(WriteError::Rejected)?;
            let key = self
                .user_key
                .read()
                .map_err(|_| "Vault key unavailable".to_string())?;
            let user_key = key.as_ref().ok_or_else(|| "Vault is locked.".to_string())?;
            let enc_name = user_key
                .encrypt_string(&new_name)
                .map_err(|_| "Could not encrypt folder name.".to_string())?;
            (resolved, json!({ "name": enc_name }))
        };

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_cipher_write(server, context).map_err(|_| {
            WriteError::Rejected("Could not initialize the folder HTTP client.".into())
        })?;
        let token = self.keyring_mgr.for_storage(&storage).access_token();
        let renew = || self.renew_for_account(&storage, context, generation);
        let mut token = match token.filter(|t| !crate::auth::is_jwt_expired(t)) {
            Some(t) => t,
            None => renew()?,
        };
        let mut renewed_after_rejection = false;
        let _pending = self
            .storage_mgr
            .begin_cipher_write()
            .map_err(|e| e.to_string())?;

        let folder = loop {
            let same_account = self
                .storage_mgr
                .load_existing()
                .is_ok_and(|s| s.same_active_slot(&storage));
            let current = self
                .is_unlocked
                .read()
                .is_ok_and(|unlocked| *unlocked && self.lock_generation() == generation);
            if !same_account || !current {
                return Err(WriteError::Rejected(
                    "Session changed before updating the folder.".into(),
                ));
            }
            match client.update_folder(&token, &resolved.id, &payload) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => break result?,
            }
        };

        let id = folder["id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(&resolved.id);
        let cached = self
            .cache_upserted_folder(&storage, generation, &folder, id, Some(&new_name))
            .is_some();
        Ok(json!({
            "ok": true,
            "outcome": if cached { "saved" } else { "saved_needs_sync" },
            "folder": {
                "id": id,
                "name": new_name,
                "count": resolved.count,
                "revisionDate": folder["revisionDate"].as_str(),
            }
        }))
    }

    pub(crate) fn delete_folder(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;
        let req_payload = request.get("mutation").unwrap_or(&request);
        let target = req_payload
            .get("id")
            .or_else(|| req_payload.get("target"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let resolved = {
            let unlocked = self
                .is_unlocked
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            let active = self
                .storage
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            if !*unlocked
                || generation != self.lock_generation()
                || !active.same_active_slot(&storage)
            {
                return Err(WriteError::Rejected("Vault session changed.".into()));
            }
            drop(active);
            drop(unlocked);
            self.resolve_folder_target(target)
                .map_err(WriteError::Rejected)?
        };

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_cipher_write(server, context).map_err(|_| {
            WriteError::Rejected("Could not initialize the folder HTTP client.".into())
        })?;
        let token = self.keyring_mgr.for_storage(&storage).access_token();
        let renew = || self.renew_for_account(&storage, context, generation);
        let mut token = match token.filter(|t| !crate::auth::is_jwt_expired(t)) {
            Some(t) => t,
            None => renew()?,
        };
        let mut renewed_after_rejection = false;
        let _pending = self
            .storage_mgr
            .begin_cipher_write()
            .map_err(|e| e.to_string())?;

        loop {
            let same_account = self
                .storage_mgr
                .load_existing()
                .is_ok_and(|s| s.same_active_slot(&storage));
            let current = self
                .is_unlocked
                .read()
                .is_ok_and(|unlocked| *unlocked && self.lock_generation() == generation);
            if !same_account || !current {
                return Err(WriteError::Rejected(
                    "Session changed before deleting the folder.".into(),
                ));
            }
            match client.delete_folder(&token, &resolved.id) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => {
                    result.map_err(|e| match e {
                        ApiError::HttpStatus(status, msg) => WriteError::Rejected(format!(
                            "Server rejected folder deletion (HTTP {status}): {msg}"
                        )),
                        other => {
                            WriteError::Rejected(format!("Server communication failed: {other}"))
                        }
                    })?;
                    break;
                }
            }
        }

        let cached = self
            .cache_deleted_folder(&storage, generation, &resolved.id)
            .is_some();
        Ok(json!({
            "ok": true,
            "outcome": if cached { "deleted" } else { "deleted_needs_sync" },
            "folder": {
                "id": resolved.id,
                "name": resolved.name,
                "unassigned_count": resolved.count,
            }
        }))
    }

    fn cache_upserted_folder(
        &self,
        account: &VaultStorage,
        generation: u64,
        folder: &Value,
        id: &str,
        renamed_to: Option<&str>,
    ) -> Option<()> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_active_slot(account) {
            return None;
        }
        let mut updated = base.storage.clone();
        updated.folders.retain(|f| f["id"] != id);
        updated.folders.push(folder.clone());

        let index_update = if let Some(new_name) = renamed_to {
            let mut items = self.decrypted_items.read().ok()?.clone();
            for item in &mut items {
                if item.folder_id.as_deref() == Some(id) {
                    item.folder_name = Some(new_name.to_string());
                }
            }
            IndexUpdate::Replace(items)
        } else {
            IndexUpdate::CiphertextOnly
        };

        self.commit_cache(
            &base,
            updated,
            index_update,
            CacheSession {
                generation,
                unlocked: true,
            },
        )
        .ok()?;
        Some(())
    }

    fn cache_deleted_folder(
        &self,
        account: &VaultStorage,
        generation: u64,
        id: &str,
    ) -> Option<()> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_active_slot(account) {
            return None;
        }
        let mut updated = base.storage.clone();
        updated.folders.retain(|f| f["id"] != id);
        for cipher in &mut updated.ciphers {
            if cipher.get("folderId").and_then(Value::as_str) == Some(id) {
                cipher["folderId"] = Value::Null;
            }
        }
        let mut items = self.decrypted_items.read().ok()?.clone();
        for item in &mut items {
            if item.folder_id.as_deref() == Some(id) {
                item.folder_id = None;
                item.folder_name = None;
            }
        }
        self.commit_cache(
            &base,
            updated,
            IndexUpdate::Replace(items),
            CacheSession {
                generation,
                unlocked: true,
            },
        )
        .ok()?;
        Some(())
    }
}
