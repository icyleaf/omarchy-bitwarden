//! Daemon-owned SSH cipher writes. Only an encrypted payload crosses the HTTP
//! boundary, and only a receipt crosses the return IPC boundary.
use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::crypto::SymmetricCryptoKey;
use crate::storage::VaultStorage;
use crate::vault::VaultManager;
use crate::vault_cache::{CacheSession, IndexUpdate};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::ZeroizeOnDrop;

pub(crate) enum WriteError {
    Rejected(String),
    Unknown,
}

impl WriteError {
    pub(crate) fn response(self) -> Value {
        match self {
            Self::Rejected(reason) => json!({"ok": false, "outcome": "rejected", "error": reason}),
            Self::Unknown => {
                json!({"ok": false, "outcome": "unknown", "error": "Could not confirm the write. Sync the vault before trying again."})
            }
        }
    }
}

impl From<String> for WriteError {
    fn from(reason: String) -> Self {
        Self::Rejected(reason)
    }
}

impl From<ApiError> for WriteError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::HttpStatus(status, _)
                if status.is_client_error() && status.as_u16() != 408 =>
            {
                Self::Rejected(format!("Server rejected the cipher (HTTP {status})."))
            }
            _ => Self::Unknown,
        }
    }
}

#[derive(Deserialize, ZeroizeOnDrop)]
struct SshDraft {
    name: String,
    private_key: String,
    public_key: String,
    fingerprint: String,
    notes: Option<String>,
    folder_id: Option<String>,
}

impl VaultManager {
    pub(crate) fn write_ssh_key(
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
            let draft: SshDraft = serde_json::from_value(request)
                .map_err(|_| WriteError::Rejected("Invalid SSH cipher fields.".into()))?;
            let unlocked = self
                .is_unlocked
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            let active = self
                .storage
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            if !*unlocked || generation != self.lock_generation() || !active.same_account(&storage)
            {
                return Err(WriteError::Rejected("Vault session changed.".into()));
            }
            drop(active);
            let key = self
                .user_key
                .read()
                .map_err(|_| "Vault key unavailable".to_string())?;
            encrypt_ssh(
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
        let token = self
            .keyring_mgr
            .for_storage(&storage, server)
            .access_token();
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
            // Older caches can lack the profile ID. The server checks encryptedFor
            // against the very same bearer; the decoded subject is not authorization.
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
                .is_ok_and(|s| s.same_account(&storage));
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
        let cached = cipher["type"] == 5
            && cipher["name"] == payload["name"]
            && cipher["organizationId"].is_null()
            && ["privateKey", "publicKey", "keyFingerprint"]
                .iter()
                .all(|field| cipher["sshKey"][*field] == payload["sshKey"][*field])
            && self
                .cache_created_ssh(&storage, generation, &cipher, id)
                .is_some();
        Ok(
            json!({"ok": true, "outcome": if cached { "saved" } else { "saved_needs_sync" }, "item": receipt}),
        )
    }

    fn cache_created_ssh(
        &self,
        account: &VaultStorage,
        generation: u64,
        cipher: &Value,
        id: &str,
    ) -> Option<()> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_account(account) {
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

fn encrypt_ssh(key: &SymmetricCryptoKey, draft: &SshDraft) -> Result<Value, String> {
    let encrypt = |text: &str| {
        key.encrypt_string(text)
            .map_err(|_| "Could not encrypt SSH cipher.".to_string())
    };
    Ok(json!({
        "type": 5, "folderId": draft.folder_id, "organizationId": null, "favorite": false, "reprompt": 0,
        "name": encrypt(&draft.name)?, "notes": draft.notes.as_deref().filter(|s| !s.is_empty()).map(encrypt).transpose()?,
        "sshKey": {"privateKey": encrypt(&draft.private_key)?, "publicKey": encrypt(&draft.public_key)?, "keyFingerprint": encrypt(&draft.fingerprint)?}
    }))
}
