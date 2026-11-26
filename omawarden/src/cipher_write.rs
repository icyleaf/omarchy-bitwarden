//! Daemon-owned cipher mutations. Only encrypted payloads cross the HTTP
//! boundary, and only receipts cross the return IPC boundary.
use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::{
    parse_rsa_private_key_der, parse_symmetric_key_from_decrypted_bytes, EncString,
    SymmetricCryptoKey,
};
use crate::ssh_write::WriteError;
use crate::storage::VaultStorage;
use crate::vault::VaultManager;
use crate::vault_cache::{CacheSession, IndexUpdate};
use rand_core::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Strictly resolves an Organization's 64-byte symmetric key (`org_key`).
/// Fails closed if `enc_private_key` or the Organization's key is missing or
/// undecryptable; NEVER falls back to `user_key`.
pub(crate) fn resolve_org_key(
    storage: &VaultStorage,
    user_key: &SymmetricCryptoKey,
    org_id: &str,
) -> Result<SymmetricCryptoKey, WriteError> {
    let org = storage
        .organizations
        .iter()
        .find(|o| o.get("id").and_then(Value::as_str) == Some(org_id))
        .ok_or_else(|| {
            WriteError::Rejected(format!(
                "Organization '{org_id}' not found in local vault cache. Sync the vault and try again."
            ))
        })?;

    let org_key_enc = org
        .get("key")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            WriteError::Rejected(format!(
                "Missing encryption key for Organization '{org_id}'. Cannot write Organization cipher."
            ))
        })?;

    let enc_str = EncString::parse(org_key_enc).map_err(|_| {
        WriteError::Rejected(format!(
            "Malformed encryption key for Organization '{org_id}'."
        ))
    })?;

    let raw_key = Zeroizing::new(match enc_str.enc_type {
        3..=6 => {
            let enc_priv = storage
                .enc_private_key
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    WriteError::Rejected(
                        "Missing encrypted user private key. Cannot unwrap Organization encryption key."
                            .into(),
                    )
                })?;
            let enc_priv_str = EncString::parse(enc_priv).map_err(|_| {
                WriteError::Rejected("Malformed encrypted user private key.".into())
            })?;
            let der_bytes =
                Zeroizing::new(enc_priv_str.decrypt(user_key).map_err(|_| {
                    WriteError::Rejected("Could not decrypt user private key.".into())
                })?);
            let rsa_priv = parse_rsa_private_key_der(&der_bytes).map_err(|_| {
                WriteError::Rejected("Could not parse user RSA private key.".into())
            })?;
            enc_str.decrypt_rsa(&rsa_priv).map_err(|_| {
                WriteError::Rejected(format!(
                    "Could not decrypt RSA-wrapped key for Organization '{org_id}'."
                ))
            })?
        }
        0..=2 => enc_str.decrypt(user_key).map_err(|_| {
            WriteError::Rejected(format!(
                "Could not decrypt symmetric key for Organization '{org_id}'."
            ))
        })?,
        other => {
            return Err(WriteError::Rejected(format!(
                "Unsupported Organization key encryption type ({other}) for '{org_id}'."
            )));
        }
    });

    parse_symmetric_key_from_decrypted_bytes(&raw_key).ok_or_else(|| {
        WriteError::Rejected(format!(
            "Invalid decrypted symmetric key length for Organization '{org_id}'."
        ))
    })
}

/// Validates that `collection_ids` is non-empty and that every collection exists
/// in `storage.collections`, belongs to `org_id`, and is writable (`!read_only || manage`).
/// Absent permission flags default fail-closed (`readOnly: true`, `manage: false`).
pub(crate) fn validate_writable_collections(
    storage: &VaultStorage,
    org_id: &str,
    collection_ids: &[String],
) -> Result<(), WriteError> {
    if collection_ids.is_empty() {
        return Err(WriteError::Rejected(
            "You must select at least one collection for an Organization cipher.".into(),
        ));
    }

    for col_id in collection_ids {
        let col = storage
            .collections
            .iter()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(col_id.as_str()))
            .ok_or_else(|| {
                WriteError::Rejected(format!(
                    "Collection '{col_id}' not found in local vault cache. Sync the vault and try again."
                ))
            })?;

        let col_org_id = col
            .get("organizationId")
            .or_else(|| col.get("organization_id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if col_org_id != org_id {
            return Err(WriteError::Rejected(format!(
                "Collection '{col_id}' does not belong to Organization '{org_id}'."
            )));
        }

        let read_only = col
            .get("readOnly")
            .or_else(|| col.get("read_only"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let manage = col.get("manage").and_then(Value::as_bool).unwrap_or(false);
        if read_only && !manage {
            return Err(WriteError::Rejected(format!(
                "You do not have write permission for collection '{col_id}'."
            )));
        }
    }

    Ok(())
}

fn generate_random_cipher_key() -> Result<(SymmetricCryptoKey, Zeroizing<[u8; 64]>), WriteError> {
    let mut raw = Zeroizing::new([0u8; 64]);
    rand_core::OsRng.fill_bytes(raw.as_mut());
    let key = SymmetricCryptoKey::from_raw_bytes(raw.as_slice()).map_err(|_| {
        WriteError::Rejected("Could not generate per-cipher encryption key.".into())
    })?;
    Ok((key, raw))
}

#[derive(Deserialize, ZeroizeOnDrop, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum LoginUriDraft {
    Plain(String),
    Object {
        uri: String,
        #[serde(default, rename = "match")]
        #[zeroize(skip)]
        match_type: Option<u32>,
    },
}

impl LoginUriDraft {
    pub(crate) fn uri(&self) -> &str {
        match self {
            Self::Plain(s) => s.as_str(),
            Self::Object { uri, .. } => uri.as_str(),
        }
    }

    fn resolve_match(
        &self,
        existing_uris: Option<&std::collections::HashMap<String, Value>>,
    ) -> Result<Value, String> {
        match self {
            Self::Plain(u_str) => Ok(existing_uris
                .and_then(|map| map.get(u_str))
                .cloned()
                .unwrap_or(Value::Null)),
            Self::Object { match_type, .. } => validate_uri_match_rule(*match_type),
        }
    }
}

fn validate_uri_match_rule(match_type: Option<u32>) -> Result<Value, String> {
    match match_type {
        None => Ok(Value::Null),
        Some(m) if m <= 5 => Ok(json!(m)),
        Some(m) => Err(format!(
            "Invalid URI match rule '{m}'. Expected 0 (Base Domain) through 5 (Never), or null for Default."
        )),
    }
}

fn decrypt_existing_uri_matches(
    uris: Option<&Value>,
    cipher_key: &SymmetricCryptoKey,
) -> std::collections::HashMap<String, Value> {
    uris.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|u| {
                    let enc_uri = u["uri"].as_str()?;
                    let plain_uri = EncString::parse(enc_uri)
                        .ok()
                        .and_then(|enc| enc.decrypt_string(cipher_key).ok())?;
                    let match_val = u.get("match").cloned().unwrap_or(Value::Null);
                    Some((plain_uri, match_val))
                })
                .collect::<std::collections::HashMap<_, _>>()
        })
        .unwrap_or_default()
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

#[derive(Deserialize, ZeroizeOnDrop, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct CardDraft {
    #[serde(rename = "cardholderName", alias = "cardholder_name")]
    pub(crate) cardholder_name: Option<String>,
    pub(crate) brand: Option<String>,
    pub(crate) number: Option<String>,
    #[serde(rename = "expMonth", alias = "exp_month")]
    pub(crate) exp_month: Option<String>,
    #[serde(rename = "expYear", alias = "exp_year")]
    pub(crate) exp_year: Option<String>,
    pub(crate) code: Option<String>,
}

#[derive(Deserialize, ZeroizeOnDrop, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityDraft {
    pub(crate) title: Option<String>,
    #[serde(rename = "firstName", alias = "first_name")]
    pub(crate) first_name: Option<String>,
    #[serde(rename = "middleName", alias = "middle_name")]
    pub(crate) middle_name: Option<String>,
    #[serde(rename = "lastName", alias = "last_name")]
    pub(crate) last_name: Option<String>,
    pub(crate) address1: Option<String>,
    pub(crate) address2: Option<String>,
    pub(crate) address3: Option<String>,
    pub(crate) city: Option<String>,
    pub(crate) state: Option<String>,
    #[serde(rename = "postalCode", alias = "postal_code")]
    pub(crate) postal_code: Option<String>,
    pub(crate) country: Option<String>,
    pub(crate) company: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) phone: Option<String>,
    pub(crate) ssn: Option<String>,
    pub(crate) username: Option<String>,
    #[serde(rename = "passportNumber", alias = "passport_number")]
    pub(crate) passport_number: Option<String>,
    #[serde(rename = "licenseNumber", alias = "license_number")]
    pub(crate) license_number: Option<String>,
}

#[derive(Deserialize, ZeroizeOnDrop, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum CipherTypeField {
    Numeric(u32),
    Named(String),
}

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct CipherCreateDraft {
    #[serde(default)]
    #[zeroize(skip)]
    pub(crate) action: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    pub(crate) client: Option<Value>,
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
    pub(crate) card: Option<CardDraft>,
    pub(crate) identity: Option<IdentityDraft>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) totp: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) uris: Option<Vec<LoginUriDraft>>,
    pub(crate) fields: Option<Vec<CipherFieldDraft>>,
}

#[derive(Deserialize, ZeroizeOnDrop, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct CipherUpdateDraft {
    #[serde(default)]
    #[zeroize(skip)]
    pub(crate) action: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    pub(crate) client: Option<Value>,
    pub(crate) id: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) totp: Option<String>,
    pub(crate) notes: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) uris: Option<Vec<LoginUriDraft>>,
    pub(crate) add_uris: Option<Vec<LoginUriDraft>>,
    pub(crate) clear_uris: Option<bool>,
    pub(crate) card: Option<CardDraft>,
    pub(crate) identity: Option<IdentityDraft>,
    pub(crate) fields: Option<Vec<CipherFieldDraft>>,
    pub(crate) remove_fields: Option<Vec<String>>,
    pub(crate) folder_id: Option<String>,
    pub(crate) favorite: Option<bool>,
}

impl CipherUpdateDraft {
    fn is_partial_only(&self) -> bool {
        (self.folder_id.is_some() || self.favorite.is_some())
            && self.name.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.totp.is_none()
            && self.notes.is_none()
            && self.uri.is_none()
            && self.uris.is_none()
            && self.add_uris.is_none()
            && self.clear_uris.is_none()
            && self.card.is_none()
            && self.identity.is_none()
            && self.fields.is_none()
            && self.remove_fields.is_none()
    }
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
        let req_payload = if let Some(inner) = request.get("mutation").cloned() {
            inner
        } else {
            request
        };
        let (mut payload, org_collection_ids) = {
            let draft: CipherCreateDraft = serde_json::from_value(req_payload)
                .map_err(|_| WriteError::Rejected("Invalid cipher fields.".into()))?;
            let org_id = draft
                .organization_id
                .as_deref()
                .or(draft.organization_id_camel.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);

            let mut collection_ids: Vec<String> = Vec::new();
            for list in [&draft.collection_ids, &draft.collection_ids_camel]
                .into_iter()
                .flatten()
            {
                for cid in list {
                    let trimmed = cid.trim();
                    if !trimmed.is_empty() && !collection_ids.iter().any(|c| c == trimmed) {
                        collection_ids.push(trimmed.to_string());
                    }
                }
            }
            for single in [&draft.collection_id, &draft.collection_id_camel]
                .into_iter()
                .flatten()
            {
                let trimmed = single.trim();
                if !trimmed.is_empty() && !collection_ids.iter().any(|c| c == trimmed) {
                    collection_ids.push(trimmed.to_string());
                }
            }

            if org_id.is_none() && !collection_ids.is_empty() {
                return Err(WriteError::Rejected(
                    "Collection IDs require an Organization ID.".into(),
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
            let user_key = key.as_ref().ok_or_else(|| "Vault is locked".to_string())?;

            if let Some(ref oid) = org_id {
                validate_writable_collections(&storage, oid, &collection_ids)?;
                let org_key = resolve_org_key(&storage, user_key, oid)?;
                let (cipher_key, raw_cipher_key) = generate_random_cipher_key()?;
                let wrapped_cipher_key =
                    org_key.encrypt(raw_cipher_key.as_slice()).map_err(|_| {
                        WriteError::Rejected("Could not wrap Organization cipher key.".into())
                    })?;
                let mut encrypted = encrypt_cipher(&cipher_key, &draft)?;
                encrypted["organizationId"] = json!(oid);
                encrypted["key"] = json!(wrapped_cipher_key);
                (encrypted, Some(collection_ids))
            } else {
                (encrypt_cipher(user_key, &draft)?, None)
            }
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
            let create_res = if let Some(ref cols) = org_collection_ids {
                client.create_org_cipher(&token, &payload, cols)
            } else {
                client.create_cipher(&token, &payload)
            };
            match create_res {
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
                &updated.organizations,
                key.as_ref()?,
                updated.enc_private_key.as_deref(),
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

        let req_payload = if let Some(inner) = request.get("mutation").cloned() {
            inner
        } else {
            request
        };
        let draft: CipherUpdateDraft = serde_json::from_value(req_payload)
            .map_err(|_| WriteError::Rejected("Invalid cipher update fields.".into()))?;

        let is_partial_only = draft.is_partial_only();

        let (target_id, target_name, base_cipher, org_id_opt, is_org_partial) = {
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

            let cipher_in_storage = storage
                .ciphers
                .iter()
                .find(|c| c["id"] == resolved_item.id)
                .cloned()
                .ok_or_else(|| WriteError::Rejected("Cipher not found in local cache.".into()))?;

            let org_id_opt = resolved_item
                .organization_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    cipher_in_storage["organizationId"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                })
                .map(str::to_string);
            let is_org = org_id_opt.is_some();

            if is_org && !is_partial_only {
                if !resolved_item.edit {
                    return Err(WriteError::Rejected(
                        "You do not have permission to edit this Organization cipher.".into(),
                    ));
                }
                if !resolved_item.view_password {
                    return Err(WriteError::Rejected(
                        "Cannot edit Organization cipher while passwords are hidden (viewPassword is false)."
                            .into(),
                    ));
                }
            }

            if !(is_org && is_partial_only) {
                let cipher_type = cipher_in_storage
                    .get("type")
                    .and_then(Value::as_i64)
                    .unwrap_or(1);
                let is_login = cipher_type == 1;
                if (draft.username.is_some()
                    || draft.password.is_some()
                    || draft.totp.is_some()
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
                if draft.card.is_some() && cipher_type != 3 {
                    return Err(WriteError::Rejected(
                        "Card fields can only be updated on card ciphers.".into(),
                    ));
                }
                if draft.identity.is_some() && cipher_type != 4 {
                    return Err(WriteError::Rejected(
                        "Identity fields can only be updated on identity ciphers.".into(),
                    ));
                }
            }

            (
                resolved_item.id,
                resolved_item.name,
                cipher_in_storage,
                org_id_opt,
                is_org && is_partial_only,
            )
        };

        // Per-user Favorite & Folder updates on Organization Ciphers route through
        // `PUT /ciphers/{id}/partial` (allowed on any readable Organization Cipher).
        if is_org_partial {
            let effective_folder_id: Option<String> = match draft.folder_id.as_deref() {
                Some(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }
                None => base_cipher["folderId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            };
            let effective_favorite = draft
                .favorite
                .unwrap_or_else(|| base_cipher["favorite"].as_bool().unwrap_or(false));

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

                match client.update_cipher_partial(
                    &token,
                    &target_id,
                    effective_folder_id.as_deref(),
                    effective_favorite,
                ) {
                    Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                        if !renewed_after_rejection =>
                    {
                        renewed_after_rejection = true;
                        token = renew()?;
                    }
                    result => break result?,
                }
            };

            let updated_cipher = if cipher.get("id").and_then(Value::as_str).is_some()
                && cipher.get("name").is_some()
            {
                cipher
            } else {
                let mut merged = base_cipher;
                merged["folderId"] = match effective_folder_id {
                    Some(ref fid) => json!(fid),
                    None => Value::Null,
                };
                merged["favorite"] = json!(effective_favorite);
                merged
            };

            let id = updated_cipher["id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .unwrap_or(&target_id);
            let receipt = json!({
                "id": id,
                "name": target_name,
                "revisionDate": updated_cipher["revisionDate"].as_str(),
            });
            let cached = self
                .cache_created_cipher(&storage, generation, &updated_cipher, id)
                .is_some();
            return Ok(
                json!({"ok": true, "outcome": if cached { "saved" } else { "saved_needs_sync" }, "item": receipt}),
            );
        }

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
        // - For Organization ciphers: resolve `org_key` strictly (fail-closed, never
        //   fall back to `user_key`) and unwrap `cipher.key` strictly with `org_key`.
        // - For personal ciphers: unwrap `cipher.key` with `user_key`, falling back to
        //   `user_key` when `cipher.key` is absent (legacy personal cipher).
        let cipher_key = if let Some(ref oid) = org_id_opt {
            let org_key = resolve_org_key(&storage, user_key, oid)?;
            payload["organizationId"] = json!(oid);
            if let Some(enc_k) = payload
                .get("key")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                let parsed_k = EncString::parse(enc_k).map_err(|_| {
                    WriteError::Rejected("Malformed Organization cipher key.".into())
                })?;
                let raw_k_bytes = Zeroizing::new(parsed_k.decrypt(&org_key).map_err(|_| {
                    WriteError::Rejected(
                        "Could not decrypt Organization cipher key under Organization key.".into(),
                    )
                })?);
                parse_symmetric_key_from_decrypted_bytes(&raw_k_bytes).ok_or_else(|| {
                    WriteError::Rejected("Invalid decrypted Organization cipher key length.".into())
                })?
            } else {
                org_key
            }
        } else {
            let mut key = user_key.clone();
            if let Some(enc_k) = payload.get("key").and_then(Value::as_str) {
                if let Ok(parsed_k) = EncString::parse(enc_k) {
                    if let Ok(raw_k_bytes) = parsed_k.decrypt(user_key) {
                        if let Some(k) = parse_symmetric_key_from_decrypted_bytes(&raw_k_bytes) {
                            key = k;
                        }
                    }
                }
            }
            key
        };

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
            || draft.totp.is_some()
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

            if let Some(ref totp_raw) = draft.totp {
                if totp_raw.is_empty() {
                    payload["login"]["totp"] = Value::Null;
                } else {
                    crate::totp::validate_totp_seed(totp_raw).map_err(WriteError::Rejected)?;
                    payload["login"]["totp"] = json!(cipher_key
                        .encrypt_string(totp_raw)
                        .map_err(|_| "Could not encrypt TOTP seed.".to_string())?);
                }
                field_changed = true;
            }

            if draft.clear_uris == Some(true) {
                payload["login"]["uris"] = json!([]);
                field_changed = true;
            } else if let Some(ref replace_uris) = draft.uris {
                let mut enc_uris = Vec::new();
                // Decrypt existing URIs so plain-string replacements preserve their match rule
                let existing_uris =
                    decrypt_existing_uri_matches(payload["login"].get("uris"), &cipher_key);
                for u in replace_uris {
                    let u_str = u.uri();
                    if !u_str.is_empty() {
                        let match_val = u
                            .resolve_match(Some(&existing_uris))
                            .map_err(WriteError::Rejected)?;
                        let enc_uri = cipher_key
                            .encrypt_string(u_str)
                            .map_err(|_| "Could not encrypt URI.".to_string())?;
                        enc_uris.push(json!({"uri": enc_uri, "match": match_val}));
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
                        let match_val = u.resolve_match(None).map_err(WriteError::Rejected)?;
                        let enc_uri = cipher_key
                            .encrypt_string(u_str)
                            .map_err(|_| "Could not encrypt URI.".to_string())?;
                        uris_arr.push(json!({"uri": enc_uri, "match": match_val}));
                        field_changed = true;
                    }
                }
            } else if let Some(ref uri) = draft.uri {
                let existing_uris =
                    decrypt_existing_uri_matches(payload["login"].get("uris"), &cipher_key);
                let u_str = uri;
                if u_str.is_empty() {
                    payload["login"]["uris"] = json!([]);
                } else {
                    let enc_uri = cipher_key
                        .encrypt_string(u_str)
                        .map_err(|_| "Could not encrypt URI.".to_string())?;
                    let match_val = existing_uris.get(u_str).cloned().unwrap_or(Value::Null);
                    if let Some(uris) = payload["login"]["uris"].as_array_mut() {
                        if !uris.is_empty() {
                            uris[0]["uri"] = json!(enc_uri);
                            uris[0]["match"] = match_val;
                        } else {
                            uris.push(json!({"uri": enc_uri, "match": match_val}));
                        }
                    } else {
                        payload["login"]["uris"] = json!([{"uri": enc_uri, "match": match_val}]);
                    }
                }
                field_changed = true;
            }
        }

        if let Some(ref card_draft) = draft.card {
            if !payload["card"].is_object() {
                payload["card"] = json!({});
            }
            if apply_card_updates(&mut payload["card"], card_draft, &cipher_key)? {
                field_changed = true;
            }
        }

        if let Some(ref identity_draft) = draft.identity {
            if !payload["identity"].is_object() {
                payload["identity"] = json!({});
            }
            if apply_identity_updates(&mut payload["identity"], identity_draft, &cipher_key)? {
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
                && !resolved_item.can_delete
            {
                return Err(WriteError::Rejected(
                    "You do not have permission to delete this Organization cipher.".into(),
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
        let server_deleted_at = loop {
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
                    break result.map_err(|e| match e {
                        ApiError::HttpStatus(status, msg) => WriteError::Rejected(format!(
                            "Server rejected deletion (HTTP {status}): {msg}"
                        )),
                        other => {
                            WriteError::Rejected(format!("Server communication failed: {other}"))
                        }
                    })?;
                }
            }
        };

        // For soft deletes, stamp the receipt with the same timestamp used to
        // cache the item so callers see `deleted_at` without a manual sync.
        let deleted_at = if permanent {
            None
        } else {
            Some(server_deleted_at.unwrap_or_else(|| {
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            }))
        };
        let mut receipt = json!({
            "id": target_id,
            "name": target_name,
            "permanent": permanent,
        });
        if let Some(ref deleted_at) = deleted_at {
            receipt["deleted_at"] = json!(deleted_at);
        }
        let cached = if permanent {
            self.cache_deleted_cipher(&storage, generation, &target_id)
                .is_some()
        } else {
            // Soft delete keeps the cipher in the cache so `--trash` sees it
            // immediately, stamped with the server timestamp when returned.
            self.cache_soft_deleted_cipher(
                &storage,
                generation,
                &target_id,
                deleted_at.as_deref().unwrap_or_default(),
            )
            .is_some()
        };
        Ok(
            json!({"ok": true, "outcome": if cached { "deleted" } else { "deleted_needs_sync" }, "item": receipt}),
        )
    }

    pub(crate) fn restore_cipher(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;

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
                self.resolve_cipher_target_by_state(id, true)
                    .map_err(WriteError::Rejected)?
            } else if let Some(target) = request
                .get("target")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                self.resolve_cipher_target_by_state(target, true)
                    .map_err(WriteError::Rejected)?
            } else {
                return Err(WriteError::Rejected("Missing cipher target.".into()));
            };

            if resolved_item
                .organization_id
                .as_deref()
                .is_some_and(|s| !s.is_empty())
                && !resolved_item.can_restore
            {
                return Err(WriteError::Rejected(
                    "You do not have permission to restore this Organization cipher.".into(),
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
                    "Session changed before restoring the cipher.".into(),
                ));
            }

            match client.restore_cipher(&token, &target_id) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => {
                    break result.map_err(|e| match e {
                        ApiError::HttpStatus(status, msg) => WriteError::Rejected(format!(
                            "Server rejected restore (HTTP {status}): {msg}"
                        )),
                        other => {
                            WriteError::Rejected(format!("Server communication failed: {other}"))
                        }
                    })?;
                }
            }
        }

        let receipt = json!({
            "id": target_id,
            "name": target_name,
        });
        self.cache_restored_cipher(&storage, generation, &target_id);
        Ok(json!({"ok": true, "outcome": "restored", "item": receipt}))
    }

    pub(crate) fn delete_cipher_trash(
        &self,
        request: Value,
        context: Option<&ClientContext>,
    ) -> Result<Value, WriteError> {
        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| WriteError::Rejected("Cannot read the vault cache.".into()))?;

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
                self.resolve_cipher_target_by_state(id, true)
                    .map_err(WriteError::Rejected)?
            } else if let Some(target) = request
                .get("target")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                self.resolve_cipher_target_by_state(target, true)
                    .map_err(WriteError::Rejected)?
            } else {
                return Err(WriteError::Rejected("Missing cipher target.".into()));
            };

            if resolved_item
                .organization_id
                .as_deref()
                .is_some_and(|s| !s.is_empty())
                && !resolved_item.can_delete
            {
                return Err(WriteError::Rejected(
                    "You do not have permission to delete this Organization cipher.".into(),
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
                    "Session changed before permanently deleting the cipher.".into(),
                ));
            }

            match client.delete_cipher(&token, &target_id, true) {
                Err(ApiError::HttpStatus(reqwest::StatusCode::UNAUTHORIZED, _))
                    if !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    token = renew()?;
                }
                result => {
                    break result.map(|_| ()).map_err(|e| match e {
                        ApiError::HttpStatus(status, msg) => WriteError::Rejected(format!(
                            "Server rejected permanent delete (HTTP {status}): {msg}"
                        )),
                        other => {
                            WriteError::Rejected(format!("Server communication failed: {other}"))
                        }
                    })?;
                }
            }
        }

        let receipt = json!({
            "id": target_id,
            "name": target_name,
            "permanent": true,
        });
        self.cache_purged_cipher(&storage, generation, &target_id);
        Ok(json!({"ok": true, "outcome": "deleted", "item": receipt, "permanent": true}))
    }

    fn cache_purged_cipher(&self, account: &VaultStorage, generation: u64, id: &str) -> Option<()> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_active_slot(account) {
            return None;
        }
        let mut updated = base.storage.clone();
        updated
            .ciphers
            .retain(|c| c.get("id").and_then(Value::as_str) != Some(id));
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

    fn cache_restored_cipher(
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
        let cipher = updated
            .ciphers
            .iter_mut()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(id))?;
        if let Some(object) = cipher.as_object_mut() {
            object.remove("deletedDate");
            object.remove("DeletedDate");
        }

        // Reuse the already-decrypted Trash item so the restored cipher is
        // active immediately, without waiting for a manual sync.
        let mut item = {
            let items = self.decrypted_items.read().ok()?;
            items.iter().find(|item| item.id == id)?.clone()
        };
        item.deleted_at = None;
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

    fn cache_soft_deleted_cipher(
        &self,
        account: &VaultStorage,
        generation: u64,
        id: &str,
        deleted_at: &str,
    ) -> Option<()> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_active_slot(account) {
            return None;
        }
        let mut updated = base.storage.clone();
        let cipher = updated
            .ciphers
            .iter_mut()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(id))?;
        let deleted_key = if cipher.get("DeletedDate").is_some() {
            "DeletedDate"
        } else {
            "deletedDate"
        };
        cipher[deleted_key] = Value::String(deleted_at.to_string());

        // Reuse the already-decrypted active item so the Trash entry is
        // visible immediately, without waiting for a manual sync.
        let mut item = {
            let items = self.decrypted_items.read().ok()?;
            items.iter().find(|item| item.id == id)?.clone()
        };
        item.deleted_at = Some(deleted_at.to_string());
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
        Card,
        Identity,
    }

    let resolved_type = match (&draft.raw_type, &draft.cipher_type) {
        (Some(CipherTypeField::Numeric(1)), _) => ResolvedType::Login,
        (Some(CipherTypeField::Numeric(2)), _) => ResolvedType::Note,
        (Some(CipherTypeField::Numeric(3)), _) => ResolvedType::Card,
        (Some(CipherTypeField::Numeric(4)), _) => ResolvedType::Identity,
        (Some(CipherTypeField::Numeric(other)), _) => {
            return Err(format!(
                "Unsupported cipher type {other}. Supported types are login (1), secure note (2), card (3), and identity (4)."
            ));
        }
        (Some(CipherTypeField::Named(name)), _) | (None, Some(name)) => {
            match name.to_lowercase().as_str() {
                "login" => ResolvedType::Login,
                "note" | "secure_note" | "securenote" => ResolvedType::Note,
                "card" => ResolvedType::Card,
                "identity" => ResolvedType::Identity,
                other => {
                    return Err(format!(
                        "Unsupported cipher type '{other}'. Supported types are login (1), secure note (2), card (3), and identity (4)."
                    ));
                }
            }
        }
        (None, None) => {
            if draft.card.is_some() {
                ResolvedType::Card
            } else if draft.identity.is_some() {
                ResolvedType::Identity
            } else if draft.login.is_some()
                || draft.username.is_some()
                || draft.password.is_some()
                || draft.totp.is_some()
            {
                ResolvedType::Login
            } else if draft.notes.is_some() {
                ResolvedType::Note
            } else {
                ResolvedType::Login
            }
        }
    };

    let has_login_payload = draft.login.is_some()
        || draft.username.is_some()
        || draft.password.is_some()
        || draft.totp.is_some()
        || draft.uri.is_some()
        || draft.uris.is_some();
    if !matches!(resolved_type, ResolvedType::Login) && has_login_payload {
        return Err("Login fields can only be set on login ciphers.".to_string());
    }
    if !matches!(resolved_type, ResolvedType::Card) && draft.card.is_some() {
        return Err("Card fields can only be set on card ciphers.".to_string());
    }
    if !matches!(resolved_type, ResolvedType::Identity) && draft.identity.is_some() {
        return Err("Identity fields can only be set on identity ciphers.".to_string());
    }

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

    if matches!(resolved_type, ResolvedType::Card) {
        let card_obj = encrypt_card_object(key, draft.card.as_ref())?;
        let mut payload = json!({
            "type": 3,
            "folderId": folder_id,
            "organizationId": null,
            "favorite": favorite,
            "reprompt": 0,
            "name": name,
            "notes": notes,
            "card": card_obj
        });
        if let Some(ref fields) = encrypted_fields {
            payload["fields"] = json!(fields);
        }
        return Ok(payload);
    }

    if matches!(resolved_type, ResolvedType::Identity) {
        let identity_obj = encrypt_identity_object(key, draft.identity.as_ref())?;
        let mut payload = json!({
            "type": 4,
            "folderId": folder_id,
            "organizationId": null,
            "favorite": favorite,
            "reprompt": 0,
            "name": name,
            "notes": notes,
            "identity": identity_obj
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
    let totp = match draft
        .login
        .as_ref()
        .and_then(|l| l.totp.as_deref())
        .or(draft.totp.as_deref())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            crate::totp::validate_totp_seed(raw)?;
            Some(encrypt(raw)?)
        }
        None => None,
    };

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
                let match_val = u.resolve_match(None)?;
                uris_list.push(json!({
                    "uri": encrypt(uri_str)?,
                    "match": match_val
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

fn encrypt_optional_field(
    key: &SymmetricCryptoKey,
    value: Option<&str>,
) -> Result<Option<String>, String> {
    value
        .filter(|s| !s.is_empty())
        .map(|s| {
            key.encrypt_string(s)
                .map_err(|_| "Could not encrypt cipher field.".to_string())
        })
        .transpose()
}

fn apply_optional_encrypted_field(
    target: &mut Value,
    wire_key: &str,
    value: Option<&str>,
    key: &SymmetricCryptoKey,
) -> Result<bool, String> {
    let Some(val) = value else {
        return Ok(false);
    };
    if val.is_empty() {
        target[wire_key] = Value::Null;
    } else {
        let enc = key
            .encrypt_string(val)
            .map_err(|_| format!("Could not encrypt {wire_key}."))?;
        target[wire_key] = json!(enc);
    }
    Ok(true)
}

fn validate_card_expiration(exp_month: Option<&str>, exp_year: Option<&str>) -> Result<(), String> {
    if let Some(month) = exp_month.map(str::trim).filter(|s| !s.is_empty()) {
        let valid_month = month.chars().all(|c| c.is_ascii_digit())
            && month.parse::<u32>().is_ok_and(|m| (1..=12).contains(&m));
        if !valid_month {
            return Err("Expiration month must be between 01 and 12 (e.g. 08 or 12).".to_string());
        }
    }
    if let Some(year) = exp_year.map(str::trim).filter(|s| !s.is_empty()) {
        let valid_year = year.len() == 4 && year.chars().all(|c| c.is_ascii_digit());
        if !valid_year {
            return Err("Expiration year must be a 4-digit number (e.g. 2029).".to_string());
        }
    }
    Ok(())
}

fn encrypt_card_object(
    key: &SymmetricCryptoKey,
    card: Option<&CardDraft>,
) -> Result<Value, String> {
    if let Some(c) = card {
        validate_card_expiration(c.exp_month.as_deref(), c.exp_year.as_deref())?;
    }
    Ok(json!({
        "cardholderName": encrypt_optional_field(key, card.and_then(|c| c.cardholder_name.as_deref()))?,
        "brand": encrypt_optional_field(key, card.and_then(|c| c.brand.as_deref()))?,
        "number": encrypt_optional_field(key, card.and_then(|c| c.number.as_deref()))?,
        "expMonth": encrypt_optional_field(key, card.and_then(|c| c.exp_month.as_deref()))?,
        "expYear": encrypt_optional_field(key, card.and_then(|c| c.exp_year.as_deref()))?,
        "code": encrypt_optional_field(key, card.and_then(|c| c.code.as_deref()))?,
    }))
}

fn apply_card_updates(
    target: &mut Value,
    card: &CardDraft,
    key: &SymmetricCryptoKey,
) -> Result<bool, String> {
    validate_card_expiration(card.exp_month.as_deref(), card.exp_year.as_deref())?;
    let mut changed = false;
    changed |= apply_optional_encrypted_field(
        target,
        "cardholderName",
        card.cardholder_name.as_deref(),
        key,
    )?;
    changed |= apply_optional_encrypted_field(target, "brand", card.brand.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "number", card.number.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "expMonth", card.exp_month.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "expYear", card.exp_year.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "code", card.code.as_deref(), key)?;
    Ok(changed)
}

fn encrypt_identity_object(
    key: &SymmetricCryptoKey,
    identity: Option<&IdentityDraft>,
) -> Result<Value, String> {
    Ok(json!({
        "title": encrypt_optional_field(key, identity.and_then(|i| i.title.as_deref()))?,
        "firstName": encrypt_optional_field(key, identity.and_then(|i| i.first_name.as_deref()))?,
        "middleName": encrypt_optional_field(key, identity.and_then(|i| i.middle_name.as_deref()))?,
        "lastName": encrypt_optional_field(key, identity.and_then(|i| i.last_name.as_deref()))?,
        "address1": encrypt_optional_field(key, identity.and_then(|i| i.address1.as_deref()))?,
        "address2": encrypt_optional_field(key, identity.and_then(|i| i.address2.as_deref()))?,
        "address3": encrypt_optional_field(key, identity.and_then(|i| i.address3.as_deref()))?,
        "city": encrypt_optional_field(key, identity.and_then(|i| i.city.as_deref()))?,
        "state": encrypt_optional_field(key, identity.and_then(|i| i.state.as_deref()))?,
        "postalCode": encrypt_optional_field(key, identity.and_then(|i| i.postal_code.as_deref()))?,
        "country": encrypt_optional_field(key, identity.and_then(|i| i.country.as_deref()))?,
        "company": encrypt_optional_field(key, identity.and_then(|i| i.company.as_deref()))?,
        "email": encrypt_optional_field(key, identity.and_then(|i| i.email.as_deref()))?,
        "phone": encrypt_optional_field(key, identity.and_then(|i| i.phone.as_deref()))?,
        "ssn": encrypt_optional_field(key, identity.and_then(|i| i.ssn.as_deref()))?,
        "username": encrypt_optional_field(key, identity.and_then(|i| i.username.as_deref()))?,
        "passportNumber": encrypt_optional_field(key, identity.and_then(|i| i.passport_number.as_deref()))?,
        "licenseNumber": encrypt_optional_field(key, identity.and_then(|i| i.license_number.as_deref()))?,
    }))
}

fn apply_identity_updates(
    target: &mut Value,
    identity: &IdentityDraft,
    key: &SymmetricCryptoKey,
) -> Result<bool, String> {
    let mut changed = false;
    changed |= apply_optional_encrypted_field(target, "title", identity.title.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "firstName", identity.first_name.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "middleName", identity.middle_name.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "lastName", identity.last_name.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "address1", identity.address1.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "address2", identity.address2.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "address3", identity.address3.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "city", identity.city.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "state", identity.state.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "postalCode", identity.postal_code.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "country", identity.country.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "company", identity.company.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "email", identity.email.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "phone", identity.phone.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(target, "ssn", identity.ssn.as_deref(), key)?;
    changed |=
        apply_optional_encrypted_field(target, "username", identity.username.as_deref(), key)?;
    changed |= apply_optional_encrypted_field(
        target,
        "passportNumber",
        identity.passport_number.as_deref(),
        key,
    )?;
    changed |= apply_optional_encrypted_field(
        target,
        "licenseNumber",
        identity.license_number.as_deref(),
        key,
    )?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SymmetricCryptoKey {
        let mut raw = [0x11u8; 64];
        raw[32..].fill(0x22);
        parse_symmetric_key_from_decrypted_bytes(&raw).expect("valid 64-byte symmetric key")
    }

    fn decrypt_str(val: &Value, key: &SymmetricCryptoKey) -> String {
        EncString::parse(val.as_str().expect("encrypted string"))
            .expect("valid enc string")
            .decrypt_string(key)
            .expect("decrypt")
    }

    #[test]
    fn schema_version_is_v3_for_card_mutations() {
        assert_eq!(crate::daemon::CURRENT_SCHEMA_VERSION, 3);
    }

    #[test]
    fn encrypt_card_cipher_round_trip() {
        let key = test_key();
        let draft: CipherCreateDraft = serde_json::from_value(json!({
            "cipher_type": "card",
            "name": "Corporate Visa",
            "notes": "Travel card",
            "card": {
                "cardholderName": "Jane Doe",
                "brand": "Visa",
                "number": "4111111111111111",
                "expMonth": "08",
                "expYear": "2029",
                "code": "123"
            }
        }))
        .unwrap();

        let payload = encrypt_cipher(&key, &draft).unwrap();
        assert_eq!(payload["type"], 3);
        assert_eq!(decrypt_str(&payload["name"], &key), "Corporate Visa");
        assert_eq!(decrypt_str(&payload["notes"], &key), "Travel card");
        assert_eq!(
            decrypt_str(&payload["card"]["cardholderName"], &key),
            "Jane Doe"
        );
        assert_eq!(decrypt_str(&payload["card"]["brand"], &key), "Visa");
        assert_eq!(
            decrypt_str(&payload["card"]["number"], &key),
            "4111111111111111"
        );
        assert_eq!(decrypt_str(&payload["card"]["expMonth"], &key), "08");
        assert_eq!(decrypt_str(&payload["card"]["expYear"], &key), "2029");
        assert_eq!(decrypt_str(&payload["card"]["code"], &key), "123");
    }

    #[test]
    fn encrypt_cipher_rejects_card_fields_on_non_card_and_login_fields_on_card() {
        let key = test_key();
        let card_on_login: CipherCreateDraft = serde_json::from_value(json!({
            "cipher_type": "login",
            "name": "Bad",
            "card": { "brand": "Visa" }
        }))
        .unwrap();
        assert!(encrypt_cipher(&key, &card_on_login)
            .unwrap_err()
            .contains("Card fields"));

        let login_on_card: CipherCreateDraft = serde_json::from_value(json!({
            "cipher_type": "card",
            "name": "Bad",
            "username": "octocat"
        }))
        .unwrap();
        assert!(encrypt_cipher(&key, &login_on_card)
            .unwrap_err()
            .contains("Login fields"));
    }

    #[test]
    fn partial_merge_card_preserves_untouched_and_clears_empty() {
        let key = test_key();
        let mut card = json!({
            "brand": key.encrypt_string("Visa").unwrap(),
            "number": key.encrypt_string("4111111111111111").unwrap(),
            "code": key.encrypt_string("123").unwrap(),
        });
        let patch: CardDraft = serde_json::from_value(json!({
            "expMonth": "12",
            "code": ""
        }))
        .unwrap();
        assert!(apply_card_updates(&mut card, &patch, &key).unwrap());
        assert_eq!(decrypt_str(&card["brand"], &key), "Visa");
        assert_eq!(decrypt_str(&card["number"], &key), "4111111111111111");
        assert_eq!(decrypt_str(&card["expMonth"], &key), "12");
        assert!(card["code"].is_null());
    }

    #[test]
    fn card_expiration_validation_rejects_out_of_range_and_allows_clear() {
        let key = test_key();
        let bad_month: CipherCreateDraft = serde_json::from_value(json!({
            "cipher_type": "card",
            "name": "Bad Month",
            "card": { "expMonth": "13" }
        }))
        .unwrap();
        assert!(encrypt_cipher(&key, &bad_month)
            .unwrap_err()
            .contains("01 and 12"));

        let bad_year: CipherCreateDraft = serde_json::from_value(json!({
            "cipher_type": "card",
            "name": "Bad Year",
            "card": { "expYear": "29" }
        }))
        .unwrap();
        assert!(encrypt_cipher(&key, &bad_year)
            .unwrap_err()
            .contains("4-digit"));

        let mut card = json!({
            "expMonth": key.encrypt_string("08").unwrap(),
            "expYear": key.encrypt_string("2029").unwrap(),
        });
        let clear_patch: CardDraft = serde_json::from_value(json!({
            "expMonth": "",
            "expYear": ""
        }))
        .unwrap();
        assert!(apply_card_updates(&mut card, &clear_patch, &key).unwrap());
        assert!(card["expMonth"].is_null());
        assert!(card["expYear"].is_null());
    }

    #[test]
    fn encrypt_identity_cipher_includes_all_18_fields() {
        let key = test_key();
        let draft: CipherCreateDraft = serde_json::from_value(json!({
            "type": 4,
            "name": "Work Identity",
            "notes": "ID notes",
            "identity": {
                "title": "Dr",
                "firstName": "Ada",
                "middleName": "Augusta",
                "lastName": "Lovelace",
                "username": "ada",
                "company": "Analytical Engines",
                "ssn": "123-45-6789",
                "passportNumber": "P998877",
                "licenseNumber": "DL-42",
                "email": "ada@example.com",
                "phone": "+44 20 7946 0958",
                "address1": "12 St James Sq",
                "address2": "Floor 2",
                "address3": "Suite B",
                "city": "London",
                "state": "Greater London",
                "postalCode": "SW1Y 4LB",
                "country": "UK"
            }
        }))
        .unwrap();

        let payload = encrypt_cipher(&key, &draft).unwrap();
        assert_eq!(payload["type"], 4);
        assert_eq!(decrypt_str(&payload["name"], &key), "Work Identity");
        assert_eq!(decrypt_str(&payload["notes"], &key), "ID notes");
        for (wire_key, expected) in [
            ("title", "Dr"),
            ("firstName", "Ada"),
            ("middleName", "Augusta"),
            ("lastName", "Lovelace"),
            ("username", "ada"),
            ("company", "Analytical Engines"),
            ("ssn", "123-45-6789"),
            ("passportNumber", "P998877"),
            ("licenseNumber", "DL-42"),
            ("email", "ada@example.com"),
            ("phone", "+44 20 7946 0958"),
            ("address1", "12 St James Sq"),
            ("address2", "Floor 2"),
            ("address3", "Suite B"),
            ("city", "London"),
            ("state", "Greater London"),
            ("postalCode", "SW1Y 4LB"),
            ("country", "UK"),
        ] {
            assert_eq!(
                decrypt_str(&payload["identity"][wire_key], &key),
                expected,
                "identity.{wire_key} round-trip mismatch"
            );
        }
    }

    #[test]
    fn partial_merge_identity_preserves_untouched_and_clears_empty() {
        let key = test_key();
        let mut identity = json!({
            "firstName": key.encrypt_string("Ada").unwrap(),
            "address3": key.encrypt_string("Suite B").unwrap(),
        });
        let patch: IdentityDraft = serde_json::from_value(json!({
            "city": "London",
            "address3": ""
        }))
        .unwrap();
        assert!(apply_identity_updates(&mut identity, &patch, &key).unwrap());
        assert_eq!(decrypt_str(&identity["firstName"], &key), "Ada");
        assert_eq!(decrypt_str(&identity["city"], &key), "London");
        assert!(identity["address3"].is_null());
    }

    #[test]
    fn encrypt_cipher_rejects_identity_fields_on_non_identity() {
        let key = test_key();
        let id_on_card: CipherCreateDraft = serde_json::from_value(json!({
            "cipher_type": "card",
            "name": "Bad",
            "identity": { "firstName": "Ada" }
        }))
        .unwrap();
        assert!(encrypt_cipher(&key, &id_on_card)
            .unwrap_err()
            .contains("Identity fields"));
    }

    #[test]
    fn resolve_org_key_fails_closed_without_user_key_fallback() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        use rsa::pkcs8::EncodePrivateKey;

        let user_key = test_key();
        let wrong_user_key = SymmetricCryptoKey::from_raw_bytes(&[99u8; 64]).unwrap();
        let raw_org = [88u8; 64];
        let enc_org = user_key.encrypt(&raw_org).unwrap();
        let wrong_enc_org = wrong_user_key.encrypt(&raw_org).unwrap();

        // Generate RSA keypair for type-4 RSA-OAEP SHA-1 org key unwrap
        let mut rng = rand_core::OsRng;
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let priv_der = priv_key.to_pkcs8_der().unwrap();
        let enc_private_key = user_key
            .encrypt_string(&BASE64.encode(priv_der.as_bytes()))
            .unwrap();
        let enc_org_rsa = pub_key
            .encrypt(&mut rng, rsa::Oaep::new::<sha1::Sha1>(), &raw_org)
            .unwrap();
        let rsa_org_key_str = format!("4.{}", BASE64.encode(&enc_org_rsa));

        let storage_no_priv = VaultStorage {
            organizations: vec![
                json!({ "id": "org-sym", "name": "Sym Org", "key": enc_org }),
                json!({ "id": "org-wrong", "name": "Wrong Key Org", "key": wrong_enc_org }),
                json!({ "id": "org-rsa", "name": "RSA Org", "key": rsa_org_key_str }),
                json!({ "id": "org-no-key", "name": "No Key Org" }),
            ],
            ..Default::default()
        };

        // Valid symmetric org key unwraps cleanly
        let resolved = resolve_org_key(&storage_no_priv, &user_key, "org-sym")
            .ok()
            .expect("valid org key must resolve");
        assert_eq!(resolved.enc_key.as_slice(), &raw_org[..32]);

        // Missing org_id, wrong-key ciphertext, missing enc_private_key, and missing key all fail closed
        assert!(resolve_org_key(&storage_no_priv, &user_key, "org-unknown").is_err());
        assert!(resolve_org_key(&storage_no_priv, &user_key, "org-wrong").is_err());
        assert!(resolve_org_key(&storage_no_priv, &user_key, "org-rsa").is_err());
        assert!(resolve_org_key(&storage_no_priv, &user_key, "org-no-key").is_err());

        // Undecryptable enc_private_key fails closed
        let mut storage_bad_priv = storage_no_priv.clone();
        storage_bad_priv.enc_private_key = Some(wrong_user_key.encrypt_string("bad-der").unwrap());
        assert!(resolve_org_key(&storage_bad_priv, &user_key, "org-rsa").is_err());

        // Valid RSA-wrapped org key unwraps cleanly
        let mut storage_with_priv = storage_no_priv;
        storage_with_priv.enc_private_key = Some(enc_private_key);
        let resolved_rsa = resolve_org_key(&storage_with_priv, &user_key, "org-rsa")
            .ok()
            .expect("valid RSA-wrapped org key must resolve");
        assert_eq!(resolved_rsa.enc_key.as_slice(), &raw_org[..32]);
    }

    #[test]
    fn validate_writable_collections_enforces_fail_closed_defaults() {
        let storage = VaultStorage {
            collections: vec![
                json!({ "id": "col-w", "organizationId": "org-1", "readOnly": false, "manage": false }),
                json!({ "id": "col-m", "organizationId": "org-1", "readOnly": true, "manage": true }),
                json!({ "id": "col-ro", "organizationId": "org-1", "readOnly": true, "manage": false }),
                json!({ "id": "col-legacy", "organizationId": "org-1" }),
                json!({ "id": "col-other", "organizationId": "org-2", "readOnly": false, "manage": true }),
            ],
            ..Default::default()
        };

        assert!(validate_writable_collections(&storage, "org-1", &[]).is_err());
        assert!(validate_writable_collections(
            &storage,
            "org-1",
            &["col-w".into(), "col-m".into()]
        )
        .is_ok());
        assert!(validate_writable_collections(&storage, "org-1", &["col-ro".into()]).is_err());
        assert!(validate_writable_collections(&storage, "org-1", &["col-legacy".into()]).is_err());
        assert!(validate_writable_collections(&storage, "org-1", &["col-other".into()]).is_err());
        assert!(validate_writable_collections(&storage, "org-1", &["col-missing".into()]).is_err());
    }
}
