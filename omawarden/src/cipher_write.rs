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

#[derive(Deserialize, ZeroizeOnDrop, Default)]
pub(crate) struct LoginDraft {
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) uris: Option<Vec<String>>,
    pub(crate) totp: Option<String>,
}

#[derive(Deserialize, ZeroizeOnDrop)]
pub(crate) struct CipherCreateDraft {
    #[serde(default)]
    pub(crate) cipher_type: Option<String>,
    #[serde(rename = "type")]
    pub(crate) numeric_type: Option<u32>,
    pub(crate) name: String,
    pub(crate) notes: Option<String>,
    pub(crate) folder_id: Option<String>,
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
    let folder_id = draft.folder_id.clone();
    let favorite = draft.favorite.unwrap_or(false);

    let is_note = draft.numeric_type == Some(2) || draft.cipher_type.as_deref() == Some("note");
    if is_note {
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
            if !u.is_empty() {
                uris_list.push(json!({
                    "uri": encrypt(u)?,
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
