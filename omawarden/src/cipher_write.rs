//! Daemon-owned cipher mutations. Only encrypted payloads cross the HTTP
//! boundary, and only receipts cross the return IPC boundary.
use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::SymmetricCryptoKey;
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
        return Ok(json!({
            "type": 2,
            "folderId": folder_id,
            "organizationId": null,
            "favorite": favorite,
            "reprompt": 0,
            "name": name,
            "notes": notes,
            "secureNote": { "type": 0 }
        }));
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
    if let Some(uri) = draft
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
    if let Some(extra_uris) = draft.login.as_ref().and_then(|l| l.uris.as_deref()) {
        for u in extra_uris {
            let uri_str = u.uri();
            if !uri_str.is_empty() {
                uris_list.push(json!({
                    "uri": encrypt(uri_str)?,
                    "match": null
                }));
            }
        }
    }

    Ok(json!({
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
    }))
}
