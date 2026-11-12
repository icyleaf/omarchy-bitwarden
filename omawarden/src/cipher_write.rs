//! Daemon-owned cipher mutations. Only encrypted payloads cross the HTTP
//! boundary, and only receipts cross the return IPC boundary.
use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::{parse_symmetric_key_from_decrypted_bytes, EncString, SymmetricCryptoKey};
use crate::ssh_write::WriteError;
use crate::storage::VaultStorage;
use crate::vault::VaultManager;
use crate::vault_cache::{CacheSession, IndexUpdate};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::ZeroizeOnDrop;

#[derive(Deserialize, ZeroizeOnDrop, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum LoginUriDraft {
    Plain(String),
    Object { uri: String },
}

impl LoginUriDraft {
    pub(crate) fn uri(&self) -> &str {
        match self {
            Self::Plain(s) => s.as_str(),
            Self::Object { uri } => uri.as_str(),
        }
    }
}

/// Wire representation of a Bitwarden custom field. `type` maps to `0`
/// (Text), `1` (Hidden), `2` (Boolean) or `3` (Linked); both `name` and
/// `value` are encrypted with the cipher key before they leave the daemon.
#[derive(Deserialize, ZeroizeOnDrop, Clone, Debug)]
pub(crate) struct CipherFieldDraft {
    pub(crate) name: String,
    pub(crate) value: String,
    #[serde(default, rename = "type")]
    pub(crate) field_type: u32,
}

#[derive(Deserialize, ZeroizeOnDrop, Default)]
pub(crate) struct LoginDraft {
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) uris: Option<Vec<LoginUriDraft>>,
    pub(crate) totp: Option<String>,
}

#[derive(Deserialize, ZeroizeOnDrop, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum CipherTypeField {
    Numeric(u32),
    Named(String),
}

#[derive(Deserialize, ZeroizeOnDrop)]
pub(crate) struct CipherCreateDraft {
    #[serde(default, rename = "type")]
    pub(crate) raw_type: Option<CipherTypeField>,
    #[serde(default)]
    pub(crate) cipher_type: Option<String>,
    pub(crate) name: String,
    pub(crate) notes: Option<String>,
    pub(crate) folder_id: Option<String>,
    #[serde(rename = "folderId")]
    pub(crate) folder_id_camel: Option<String>,
    pub(crate) organization_id: Option<String>,
    #[serde(rename = "organizationId")]
    pub(crate) organization_id_camel: Option<String>,
    pub(crate) collection_id: Option<String>,
    #[serde(rename = "collectionId")]
    pub(crate) collection_id_camel: Option<String>,
    pub(crate) collection_ids: Option<Vec<String>>,
    #[serde(rename = "collectionIds")]
    pub(crate) collection_ids_camel: Option<Vec<String>>,
    pub(crate) favorite: Option<bool>,
    pub(crate) login: Option<LoginDraft>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) uris: Option<Vec<LoginUriDraft>>,
    pub(crate) fields: Option<Vec<CipherFieldDraft>>,
}

#[derive(Deserialize, ZeroizeOnDrop, Default)]
pub(crate) struct CipherUpdateDraft {
    pub(crate) id: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) notes: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) uris: Option<Vec<LoginUriDraft>>,
    pub(crate) add_uris: Option<Vec<LoginUriDraft>>,
    pub(crate) clear_uris: Option<bool>,
    pub(crate) fields: Option<Vec<CipherFieldDraft>>,
    pub(crate) remove_fields: Option<Vec<String>>,
    pub(crate) folder_id: Option<String>,
    pub(crate) favorite: Option<bool>,
}

impl VaultManager {
    pub(crate) fn create_cipher(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;
        let mut payload = {
            let draft: CipherCreateDraft = serde_json::from_value(request)
                .map_err(|_| WriteError::Rejected("Invalid cipher fields.".into()))?;
            let has_org = draft
                .organization_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .is_some()
                || draft
                    .organization_id_camel
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .is_some();
            let has_col_single = draft
                .collection_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .is_some()
                || draft
                    .collection_id_camel
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .is_some();
            let has_cols = draft
                .collection_ids
                .as_ref()
                .filter(|c| !c.is_empty())
                .is_some()
                || draft
                    .collection_ids_camel
                    .as_ref()
                    .filter(|c| !c.is_empty())
                    .is_some();
            if has_org || has_col_single || has_cols {
                return Err(WriteError::Rejected(
                    "Organization ciphers are read-only.".into(),
                ));
            }
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
            encrypt_cipher(
                key.as_ref().ok_or_else(|| "Vault is locked".to_string())?,
                &draft,
            )?
        };

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_cipher_write(server, context).map_err(|_| {
            WriteError::Rejected("Could not initialize the cipher HTTP client.".into())
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
        let cipher = loop {
            let claims = crate::auth::jwt_claims(&token);
            let subject = claims
                .as_ref()
                .and_then(|c| c["sub"].as_str())
                .filter(|s| !s.is_empty());
            let stored = storage.user_id.as_deref().filter(|s| !s.is_empty());
            if stored.zip(subject).is_some_and(|(a, b)| a != b) {
                return Err(WriteError::Rejected(
                    "Credential belongs to a different account.".into(),
                ));
            }
            let id = stored
                .or(subject)
                .ok_or_else(|| WriteError::Rejected("Missing account ID. Sign in again.".into()))?;
            payload["encryptedFor"] = json!(id);

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
                    "Session changed before sending the cipher.".into(),
                ));
            }
            match client.create_cipher(&token, &payload) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => break result?,
            }
        };
        let id = cipher["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or(WriteError::Unknown)?;
        let receipt = json!({"id": id, "revisionDate": cipher["revisionDate"].as_str()});
        let cached = self
            .cache_created_cipher(&storage, generation, &cipher, id)
            .is_some();
        Ok(
            json!({"ok": true, "outcome": if cached { "saved" } else { "saved_needs_sync" }, "item": receipt}),
        )
    }

    fn cache_created_cipher(
        &self,
        account: &VaultStorage,
        generation: u64,
        cipher: &Value,
        id: &str,
    ) -> Option<()> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_active_slot(account) {
            return None;
        }
        let mut updated = base.storage.clone();
        updated.ciphers.retain(|c| c["id"] != id);
        updated.ciphers.push(cipher.clone());
        let item = {
            let key = self.user_key.read().ok()?;
            decrypt_sync_ciphers_with_context(
                std::slice::from_ref(cipher),
                &updated.folders,
                &[],
                key.as_ref()?,
                None,
            )
            .pop()?
        };
        self.commit_cache(
            &base,
            updated,
            IndexUpdate::Upsert(Box::new(item)),
            CacheSession {
                generation,
                unlocked: true,
            },
        )
        .ok()?;
        Some(())
    }

    pub(crate) fn update_cipher(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;

        let draft: CipherUpdateDraft = serde_json::from_value(request)
            .map_err(|_| WriteError::Rejected("Invalid cipher update fields.".into()))?;

        let (target_id, target_name, base_cipher) = {
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

            let resolved_item = if let Some(id) = draft.id.as_deref().filter(|s| !s.is_empty()) {
                self.resolve_cipher_target(id)
                    .map_err(WriteError::Rejected)?
            } else if let Some(target) = draft.target.as_deref().filter(|s| !s.is_empty()) {
                self.resolve_cipher_target(target)
                    .map_err(WriteError::Rejected)?
            } else {
                return Err(WriteError::Rejected("Missing cipher target.".into()));
            };

            if resolved_item
                .organization_id
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            {
                return Err(WriteError::Rejected(
                    "Organization ciphers are read-only.".into(),
                ));
            }

            let cipher_in_storage = storage
                .ciphers
                .iter()
                .find(|c| c["id"] == resolved_item.id)
                .cloned()
                .ok_or_else(|| WriteError::Rejected("Cipher not found in local cache.".into()))?;

            if cipher_in_storage["organizationId"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            {
                return Err(WriteError::Rejected(
                    "Organization ciphers are read-only.".into(),
                ));
            }

            let cipher_type = cipher_in_storage
                .get("type")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            let is_login = cipher_type == 1;
            if (draft.username.is_some()
                || draft.password.is_some()
                || draft.uri.is_some()
                || draft.uris.is_some()
                || draft.add_uris.is_some()
                || draft.clear_uris.is_some())
                && !is_login
            {
                return Err(WriteError::Rejected(
                    "Username, password, and URI can only be updated on login ciphers.".into(),
                ));
            }

            (resolved_item.id, resolved_item.name, cipher_in_storage)
        };

        // Prepare updated payload
        let mut payload = base_cipher;
        let user_key_guard = self
            .user_key
            .read()
            .map_err(|_| "Vault key unavailable".to_string())?;
        let user_key = user_key_guard
            .as_ref()
            .ok_or_else(|| "Vault is locked".to_string())?;

        // Resolve cipher encryption key:
        // Individual Bitwarden vault ciphers carry their own 64-byte symmetric key
        // in `cipher.key` (encrypted by user_key). Sensitive fields must be encrypted
        // with this item key if present, falling back to user_key.
        let mut cipher_key = user_key.clone();
        if let Some(enc_k) = payload.get("key").and_then(Value::as_str) {
            if let Ok(parsed_k) = EncString::parse(enc_k) {
                if let Ok(raw_k_bytes) = parsed_k.decrypt(user_key) {
                    if let Some(k) = parse_symmetric_key_from_decrypted_bytes(&raw_k_bytes) {
                        cipher_key = k;
                    }
                }
            }
        }

        let mut field_changed = false;

        if let Some(ref name) = draft.name {
            payload["name"] = json!(cipher_key
                .encrypt_string(name)
                .map_err(|_| "Could not encrypt cipher name.".to_string())?);
            field_changed = true;
        }

        if let Some(ref notes) = draft.notes {
            payload["notes"] = json!(cipher_key
                .encrypt_string(notes)
                .map_err(|_| "Could not encrypt cipher notes.".to_string())?);
            field_changed = true;
        }

        if let Some(fav) = draft.favorite {
            payload["favorite"] = json!(fav);
            field_changed = true;
        }

        if let Some(ref fid) = draft.folder_id {
            if fid.is_empty() {
                payload["folderId"] = Value::Null;
            } else {
                payload["folderId"] = json!(fid);
            }
            field_changed = true;
        }

        let has_login_updates = draft.username.is_some()
            || draft.password.is_some()
            || draft.uri.is_some()
            || draft.uris.is_some()
            || draft.add_uris.is_some()
            || draft.clear_uris == Some(true);

        if has_login_updates {
            if !payload["login"].is_object() {
                payload["login"] = json!({});
            }

            if let Some(ref user) = draft.username {
                payload["login"]["username"] = json!(cipher_key
                    .encrypt_string(user)
                    .map_err(|_| "Could not encrypt username.".to_string())?);
                field_changed = true;
            }

            if let Some(ref pass) = draft.password {
                payload["login"]["password"] = json!(cipher_key
                    .encrypt_string(pass)
                    .map_err(|_| "Could not encrypt password.".to_string())?);
                payload["login"]["passwordRevisionDate"] = json!(chrono::Utc::now().to_rfc3339());
                field_changed = true;
            }

            if draft.clear_uris == Some(true) {
                payload["login"]["uris"] = json!([]);
                field_changed = true;
            } else if let Some(ref replace_uris) = draft.uris {
                let mut enc_uris = Vec::new();
                for u in replace_uris {
                    let u_str = u.uri();
                    if !u_str.is_empty() {
                        let enc_uri = cipher_key
                            .encrypt_string(u_str)
                            .map_err(|_| "Could not encrypt URI.".to_string())?;
                        enc_uris.push(json!({"uri": enc_uri, "match": Value::Null}));
                    }
                }
                payload["login"]["uris"] = json!(enc_uris);
                field_changed = true;
            } else if let Some(ref add_uris) = draft.add_uris {
                if !payload["login"]["uris"].is_array() {
                    payload["login"]["uris"] = json!([]);
                }
                let uris_arr = payload["login"]["uris"].as_array_mut().unwrap();
                for u in add_uris {
                    let u_str = u.uri();
                    if !u_str.is_empty() {
                        let enc_uri = cipher_key
                            .encrypt_string(u_str)
                            .map_err(|_| "Could not encrypt URI.".to_string())?;
                        uris_arr.push(json!({"uri": enc_uri, "match": Value::Null}));
                        field_changed = true;
                    }
                }
            } else if let Some(ref uri) = draft.uri {
                if uri.is_empty() {
                    payload["login"]["uris"] = json!([]);
                } else {
                    let enc_uri = cipher_key
                        .encrypt_string(uri)
                        .map_err(|_| "Could not encrypt URI.".to_string())?;
                    if let Some(uris) = payload["login"]["uris"].as_array_mut() {
                        if !uris.is_empty() {
                            uris[0]["uri"] = json!(enc_uri);
                        } else {
                            uris.push(json!({"uri": enc_uri, "match": Value::Null}));
                        }
                    } else {
                        payload["login"]["uris"] = json!([{"uri": enc_uri, "match": Value::Null}]);
                    }
                }
                field_changed = true;
            }
        }

        if draft.fields.is_some() || draft.remove_fields.is_some() {
            let mut fields: Vec<Value> = payload
                .get("fields")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            if let Some(removals) = draft.remove_fields.as_deref() {
                let mut unmatched: Vec<&str> = Vec::new();
                for name in removals {
                    let before = fields.len();
                    fields.retain(|field| {
                        decrypt_field_name(field, &cipher_key).is_none_or(|existing| {
                            existing != *name && !existing.eq_ignore_ascii_case(name)
                        })
                    });
                    if fields.len() == before {
                        unmatched.push(name);
                    }
                }
                if !unmatched.is_empty() {
                    let available: Vec<String> = fields
                        .iter()
                        .filter_map(|f| decrypt_field_name(f, &cipher_key))
                        .collect();
                    let hint = if available.is_empty() {
                        "this cipher has no custom fields".to_string()
                    } else {
                        format!("available fields: {}", available.join(", "))
                    };
                    let missing = unmatched
                        .iter()
                        .map(|n| format!("'{n}'"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(WriteError::Rejected(format!(
                        "No custom field named {missing} on this cipher ({hint})."
                    )));
                }
                field_changed = true;
            }

            if let Some(upserts) = draft.fields.as_deref() {
                for field in upserts {
                    let encrypted = encrypt_cipher_field(
                        &cipher_key,
                        &field.name,
                        &field.value,
                        field.field_type,
                    )?;
                    let existing = fields
                        .iter()
                        .position(|f| {
                            decrypt_field_name(f, &cipher_key).as_deref()
                                == Some(field.name.as_str())
                        })
                        .or_else(|| {
                            fields.iter().position(|f| {
                                decrypt_field_name(f, &cipher_key)
                                    .is_some_and(|n| n.eq_ignore_ascii_case(&field.name))
                            })
                        });
                    match existing {
                        Some(idx) => fields[idx] = encrypted,
                        None => fields.push(encrypted),
                    }
                    field_changed = true;
                }
            }

            payload["fields"] = json!(fields);
        }

        if !field_changed {
            return Err(WriteError::Rejected(
                "No fields specified to edit. Provide at least one field to update (e.g. --password).".into(),
            ));
        }

        // Concurrency check: include lastKnownRevisionDate and revisionDate
        let cached_rev = payload
            .get("revisionDate")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        payload["lastKnownRevisionDate"] = json!(cached_rev);
        payload["revisionDate"] = json!(cached_rev);

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_cipher_write(server, context).map_err(|_| {
            WriteError::Rejected("Could not initialize the cipher HTTP client.".into())
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

        let cipher = loop {
            let claims = crate::auth::jwt_claims(&token);
            let subject = claims
                .as_ref()
                .and_then(|c| c["sub"].as_str())
                .filter(|s| !s.is_empty());
            let stored = storage.user_id.as_deref().filter(|s| !s.is_empty());
            if stored.zip(subject).is_some_and(|(a, b)| a != b) {
                return Err(WriteError::Rejected(
                    "Credential belongs to a different account.".into(),
                ));
            }

            // Vaultwarden 1.37+ requires `encryptedFor` on `PUT /api/ciphers/{id}`,
            // exactly as on create. Without it the server answers 422, so every
            // edit — including a favorite toggle — is rejected outright.
            let encrypted_for = stored
                .or(subject)
                .ok_or_else(|| WriteError::Rejected("Missing account ID. Sign in again.".into()))?;
            payload["encryptedFor"] = json!(encrypted_for);

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
                    "Session changed before updating the cipher.".into(),
                ));
            }

            match client.update_cipher(&token, &target_id, &payload) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                Err(ApiError::HttpStatus(reqwest::StatusCode::CONFLICT, _)) => {
                    return Err(WriteError::Rejected(
                        "Cipher has been modified remotely. Please sync the vault before editing."
                            .into(),
                    ));
                }
                Err(ApiError::HttpStatus(reqwest::StatusCode::BAD_REQUEST, ref msg))
                    if msg.to_lowercase().contains("revision") =>
                {
                    return Err(WriteError::Rejected(
                        "Cipher has been modified remotely. Please sync the vault before editing."
                            .into(),
                    ));
                }
                result => break result?,
            }
        };

        let id = cipher["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or(WriteError::Unknown)?;
        let effective_name = draft.name.as_deref().unwrap_or(&target_name);
        let receipt = json!({
            "id": id,
            "name": effective_name,
            "revisionDate": cipher["revisionDate"].as_str(),
        });
        let cached = self
            .cache_created_cipher(&storage, generation, &cipher, id)
            .is_some();
        Ok(
            json!({"ok": true, "outcome": if cached { "saved" } else { "saved_needs_sync" }, "item": receipt}),
        )
    }

    pub(crate) fn delete_cipher(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;

        let permanent = request
            .get("permanent")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let (target_id, target_name) = {
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

            let resolved_item = if let Some(id) = request
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                self.resolve_cipher_target(id)
                    .map_err(WriteError::Rejected)?
            } else if let Some(target) = request
                .get("target")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                self.resolve_cipher_target(target)
                    .map_err(WriteError::Rejected)?
            } else {
                return Err(WriteError::Rejected("Missing cipher target.".into()));
            };

            if resolved_item
                .organization_id
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            {
                return Err(WriteError::Rejected(
                    "Organization ciphers are read-only.".into(),
                ));
            }

            (resolved_item.id, resolved_item.name)
        };

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_cipher_write(server, context).map_err(|_| {
            WriteError::Rejected("Could not initialize the cipher HTTP client.".into())
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
            let claims = crate::auth::jwt_claims(&token);
            let subject = claims
                .as_ref()
                .and_then(|c| c["sub"].as_str())
                .filter(|s| !s.is_empty());
            let stored = storage.user_id.as_deref().filter(|s| !s.is_empty());
            if stored.zip(subject).is_some_and(|(a, b)| a != b) {
                return Err(WriteError::Rejected(
                    "Credential belongs to a different account.".into(),
                ));
            }

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
                    "Session changed before deleting the cipher.".into(),
                ));
            }

            match client.delete_cipher(&token, &target_id, permanent) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => {
                    result.map_err(|e| match e {
                        ApiError::HttpStatus(status, msg) => WriteError::Rejected(format!(
                            "Server rejected deletion (HTTP {status}): {msg}"
                        )),
                        other => {
                            WriteError::Rejected(format!("Server communication failed: {other}"))
                        }
                    })?;
                    break;
                }
            }
        }

        let receipt = json!({
            "id": target_id,
            "name": target_name,
            "permanent": permanent,
        });
        let cached = self
            .cache_deleted_cipher(&storage, generation, &target_id)
            .is_some();
        Ok(
            json!({"ok": true, "outcome": if cached { "deleted" } else { "deleted_needs_sync" }, "item": receipt}),
        )
    }

    fn cache_deleted_cipher(
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
        updated.ciphers.retain(|c| c["id"] != id);
        self.commit_cache(
            &base,
            updated,
            IndexUpdate::Remove(id.to_string()),
            CacheSession {
                generation,
                unlocked: true,
            },
        )
        .ok()?;
        Some(())
    }
}

fn encrypt_cipher(key: &SymmetricCryptoKey, draft: &CipherCreateDraft) -> Result<Value, String> {
    let encrypt = |text: &str| {
        key.encrypt_string(text)
            .map_err(|_| "Could not encrypt cipher field.".to_string())
    };

    let name = encrypt(&draft.name)?;
    let notes = draft
        .notes
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(encrypt)
        .transpose()?;
    let folder_id = draft
        .folder_id
        .clone()
        .or_else(|| draft.folder_id_camel.clone());
    let favorite = draft.favorite.unwrap_or(false);

    let encrypted_fields = match draft.fields.as_deref() {
        Some(fields) => Some(encrypt_cipher_fields(key, fields)?),
        None => None,
    };

    enum ResolvedType {
        Login,
        Note,
    }

    let resolved_type = match (&draft.raw_type, &draft.cipher_type) {
        (Some(CipherTypeField::Numeric(1)), _) => ResolvedType::Login,
        (Some(CipherTypeField::Numeric(2)), _) => ResolvedType::Note,
        (Some(CipherTypeField::Numeric(other)), _) => {
            return Err(format!(
                "Unsupported cipher type {other}. Only login (type 1) and secure note (type 2) ciphers are supported."
            ));
        }
        (Some(CipherTypeField::Named(name)), _) | (None, Some(name)) => {
            match name.to_lowercase().as_str() {
                "login" => ResolvedType::Login,
                "note" | "secure_note" | "securenote" => ResolvedType::Note,
                other => {
                    return Err(format!(
                        "Unsupported cipher type '{other}'. Only login (type 1) and secure note (type 2) ciphers are supported."
                    ));
                }
            }
        }
        (None, None) => {
            if draft.login.is_some() || draft.username.is_some() || draft.password.is_some() {
                ResolvedType::Login
            } else if draft.notes.is_some() {
                ResolvedType::Note
            } else {
                ResolvedType::Login
            }
        }
    };

    if matches!(resolved_type, ResolvedType::Note) {
        let mut payload = json!({
            "type": 2,
            "folderId": folder_id,
            "organizationId": null,
            "favorite": favorite,
            "reprompt": 0,
            "name": name,
            "notes": notes,
            "secureNote": { "type": 0 }
        });
        if let Some(ref fields) = encrypted_fields {
            payload["fields"] = json!(fields);
        }
        return Ok(payload);
    }

    let username = draft
        .login
        .as_ref()
        .and_then(|l| l.username.as_deref())
        .or(draft.username.as_deref())
        .filter(|s| !s.is_empty())
        .map(encrypt)
        .transpose()?;
    let password = draft
        .login
        .as_ref()
        .and_then(|l| l.password.as_deref())
        .or(draft.password.as_deref())
        .filter(|s| !s.is_empty())
        .map(encrypt)
        .transpose()?;
    let totp = draft
        .login
        .as_ref()
        .and_then(|l| l.totp.as_deref())
        .filter(|s| !s.is_empty())
        .map(encrypt)
        .transpose()?;

    let mut uris_list = Vec::new();
    let all_uris = draft
        .login
        .as_ref()
        .and_then(|l| l.uris.as_deref())
        .or(draft.uris.as_deref());

    if let Some(uris) = all_uris {
        for u in uris {
            let uri_str = u.uri();
            if !uri_str.is_empty() {
                uris_list.push(json!({
                    "uri": encrypt(uri_str)?,
                    "match": null
                }));
            }
        }
    } else if let Some(uri) = draft
        .login
        .as_ref()
        .and_then(|l| l.uri.as_deref())
        .or(draft.uri.as_deref())
    {
        if !uri.is_empty() {
            uris_list.push(json!({
                "uri": encrypt(uri)?,
                "match": null
            }));
        }
    }

    let mut payload = json!({
        "type": 1,
        "folderId": folder_id,
        "organizationId": null,
        "favorite": favorite,
        "reprompt": 0,
        "name": name,
        "notes": notes,
        "login": {
            "username": username,
            "password": password,
            "totp": totp,
            "uris": uris_list,
            "autofillOnPageLoad": null
        }
    });
    if let Some(ref fields) = encrypted_fields {
        payload["fields"] = json!(fields);
    }
    Ok(payload)
}

/// Encrypt the `name` and `value` of every custom field with the cipher's
/// symmetric key. Plaintext field data must never cross the HTTP boundary.
fn encrypt_cipher_fields(
    key: &SymmetricCryptoKey,
    fields: &[CipherFieldDraft],
) -> Result<Vec<Value>, String> {
    fields
        .iter()
        .map(|field| encrypt_cipher_field(key, &field.name, &field.value, field.field_type))
        .collect()
}

/// Encrypt a single custom field into its Bitwarden wire shape.
fn encrypt_cipher_field(
    key: &SymmetricCryptoKey,
    name: &str,
    value: &str,
    field_type: u32,
) -> Result<Value, String> {
    Ok(json!({
        "name": key
            .encrypt_string(name)
            .map_err(|_| "Could not encrypt custom field name.".to_string())?,
        "value": key
            .encrypt_string(value)
            .map_err(|_| "Could not encrypt custom field value.".to_string())?,
        "type": field_type,
    }))
}

/// Decrypt a custom field's `name` from the cached cipher so name-based
/// upserts and removals can match existing entries.
fn decrypt_field_name(field: &Value, key: &SymmetricCryptoKey) -> Option<String> {
    field
        .get("name")
        .and_then(Value::as_str)
        .and_then(|enc| EncString::parse(enc).ok())
        .and_then(|enc| enc.decrypt_string(key).ok())
}
