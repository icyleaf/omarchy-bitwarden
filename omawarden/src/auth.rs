use regex::Regex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api::BitwardenApiClient;
use crate::keyring::{KeyringManager, KIND_ACCESS_TOKEN, KIND_REFRESH_TOKEN};
use crate::storage::{StorageManager, VaultStorage};

pub fn sanitize_auth_error(err_str: Option<&str>) -> String {
    let raw = match err_str {
        Some(s) if !s.trim().is_empty() => s,
        _ => return "Authentication operation failed.".to_string(),
    };

    let lower = raw.to_lowercase();
    if lower.contains("mac mismatch:") {
        return raw.to_string();
    }
    if lower.contains("invalid")
        && (lower.contains("password") || lower.contains("username") || lower.contains("email"))
    {
        return "Invalid username, email, or master password.".to_string();
    }
    if lower.contains("decryption") || lower.contains("not the expected type") {
        return "Decryption failed. Incorrect master password.".to_string();
    }
    if lower.contains("two-step") || lower.contains("two-factor") || lower.contains("code") {
        return "Two-factor authentication required or invalid code.".to_string();
    }
    if lower.contains("already logged in") {
        return "Already logged in.".to_string();
    }
    if lower.contains("network")
        || lower.contains("failed to fetch")
        || lower.contains("econnrefused")
        || lower.contains("timeout")
    {
        return "Network error: unable to reach Bitwarden server.".to_string();
    }
    if lower.contains("vault is locked") {
        return "Vault is locked.".to_string();
    }

    let first_line = raw.lines().next().unwrap_or("").trim();
    let re = Regex::new(r"[A-Za-z0-9+/=_-]{20,}").unwrap();
    let redacted = re.replace_all(first_line, "[REDACTED]");
    let truncated: String = redacted.chars().take(120).collect();
    truncated.trim().to_string()
}

pub fn is_jwt_expired(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    let payload = parts[1];
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .or_else(|_| STANDARD.decode(payload));

    if let Ok(bytes) = decoded {
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(exp) = val.get("exp").and_then(|v| v.as_i64()) {
                let now = chrono::Utc::now().timestamp();
                return now >= exp;
            }
        }
    }
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthStatus {
    pub status: String,
    pub server_url: Option<String>,
    pub last_sync: Option<String>,
    pub user_email: Option<String>,
    pub user_id: Option<String>,
    pub has_session: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResult {
    pub ok: bool,
    pub status: Option<String>,
    pub session: Option<String>,
    pub error: Option<String>,
}

pub struct AuthManager {
    pub server_url: String,
    pub storage_mgr: StorageManager,
    pub keyring_mgr: KeyringManager,
}

impl AuthManager {
    pub fn new(
        server_url: &str,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
    ) -> Self {
        Self {
            server_url: server_url.to_string(),
            storage_mgr: storage_mgr.unwrap_or_default(),
            keyring_mgr: keyring_mgr.unwrap_or_default(),
        }
    }

    pub fn get_status(&self, _verify: bool) -> AuthStatus {
        let mut storage = self.storage_mgr.load();

        // 1. Resolve active access token from Keyring or Storage fallback
        let active_token = self
            .keyring_mgr
            .get_token(KIND_ACCESS_TOKEN)
            .or_else(|| self.keyring_mgr.get_session())
            .or_else(|| storage.access_token.clone());

        // 2. Migration: If keyring is available and plaintext tokens are in storage, migrate them to Keyring safely
        if self.keyring_mgr.is_available()
            && (storage.access_token.is_some() || storage.refresh_token.is_some())
        {
            let mut access_saved = true;
            if let Some(ref tok) = storage.access_token {
                access_saved = self.keyring_mgr.store_token(KIND_ACCESS_TOKEN, tok);
            }
            let mut refresh_saved = true;
            if let Some(ref ref_tok) = storage.refresh_token {
                refresh_saved = self.keyring_mgr.store_token(KIND_REFRESH_TOKEN, ref_tok);
            }

            // Only scrub from disk if store was confirmed successful
            if access_saved {
                storage.access_token = None;
            }
            if refresh_saved {
                storage.refresh_token = None;
            }
            if access_saved || refresh_saved {
                let _ = self.storage_mgr.save(&storage);
            }
        }

        // Detect renewal capabilities using correct server URL precedence
        let has_refresh = self.keyring_mgr.get_token(KIND_REFRESH_TOKEN).is_some()
            || storage.refresh_token.is_some();
        let s_url = if !storage.server_url.is_empty() {
            &storage.server_url
        } else {
            &self.server_url
        };
        let has_api_secret = storage
            .client_id
            .as_ref()
            .and_then(|cid| self.keyring_mgr.get_api_secret(s_url, cid))
            .is_some();

        if (storage.enc_user_key.is_none() && active_token.is_none() && !has_api_secret)
            || (storage.user_email.is_empty() && storage.client_id.is_none())
        {
            return AuthStatus {
                status: "unauthenticated".to_string(),
                server_url: if storage.server_url.is_empty() {
                    Some(self.server_url.clone())
                } else {
                    Some(storage.server_url)
                },
                last_sync: storage.last_sync,
                user_email: None,
                user_id: storage.user_id,
                has_session: false,
            };
        }

        let mut token_expired = false;
        if let Some(ref tok) = active_token {
            if is_jwt_expired(tok) {
                if !has_refresh && !has_api_secret {
                    crate::log_warn!(
                        "omawarden:auth",
                        "Stored session token has expired and cannot be renewed. Invalidation required."
                    );
                    self.keyring_mgr.clear_token(KIND_ACCESS_TOKEN);
                    self.keyring_mgr.clear_session();
                    storage.access_token = None;
                    let _ = self.storage_mgr.save(&storage);
                    let _ = crate::daemon::send_daemon_request(
                        &serde_json::json!({ "action": "lock" }),
                    );

                    return AuthStatus {
                        status: "unauthenticated".to_string(),
                        server_url: if storage.server_url.is_empty() {
                            Some(self.server_url.clone())
                        } else {
                            Some(storage.server_url)
                        },
                        last_sync: storage.last_sync,
                        user_email: Some(storage.user_email),
                        user_id: storage.user_id,
                        has_session: false,
                    };
                } else {
                    token_expired = true;
                }
            }
        }

        if let Some(daemon_resp) =
            crate::daemon::send_daemon_request(&serde_json::json!({ "action": "status" }))
        {
            let is_unlocked = daemon_resp
                .get("is_unlocked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let daemon_email = daemon_resp
                .get("user_email")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let is_unlocked_same_user =
                is_unlocked && !daemon_email.is_empty() && daemon_email == storage.user_email;
            let status_str = if is_unlocked_same_user {
                "unlocked".to_string()
            } else {
                "locked".to_string()
            };

            return AuthStatus {
                status: status_str,
                server_url: if storage.server_url.is_empty() {
                    Some(self.server_url.clone())
                } else {
                    Some(storage.server_url)
                },
                last_sync: storage.last_sync,
                user_email: Some(storage.user_email),
                user_id: storage.user_id,
                has_session: is_unlocked_same_user
                    || (!token_expired && active_token.is_some())
                    || has_refresh
                    || has_api_secret,
            };
        }

        AuthStatus {
            status: "locked".to_string(),
            server_url: if storage.server_url.is_empty() {
                Some(self.server_url.clone())
            } else {
                Some(storage.server_url)
            },
            last_sync: storage.last_sync,
            user_email: Some(storage.user_email),
            user_id: storage.user_id,
            has_session: (!token_expired && active_token.is_some())
                || has_refresh
                || has_api_secret,
        }
    }

    pub fn login_password(&self, email: &str, password: &str, code: Option<&str>) -> AuthResult {
        crate::log_info!(
            "omawarden:auth",
            "Starting login with password for {}",
            email
        );
        let client = BitwardenApiClient::new(&self.server_url);
        let password_zeroizing = Zeroizing::new(password.to_string());

        let (token_resp, _user_key) = match client.login_password(email, &password_zeroizing, code)
        {
            Ok(r) => r,
            Err(e) => {
                let err_msg = sanitize_auth_error(Some(&e.to_string()));
                crate::log_warn!("omawarden:auth", "Login failed for {}: {}", email, err_msg);
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(err_msg),
                };
            }
        };

        let mut storage = self.storage_mgr.load();
        storage.server_url = self.server_url.clone();
        storage.user_email = email.trim().to_lowercase();
        storage.enc_user_key = token_resp.key;
        storage.enc_private_key = token_resp.private_key;
        storage.kdf = token_resp.kdf;
        storage.kdf_iterations = token_resp.kdf_iterations;
        storage.kdf_memory = token_resp.kdf_memory;
        storage.kdf_parallelism = token_resp.kdf_parallelism;

        let mut access_stored = false;
        let mut refresh_stored = false;
        if self.keyring_mgr.is_available() {
            access_stored = self
                .keyring_mgr
                .store_token(KIND_ACCESS_TOKEN, &token_resp.access_token);
            if let Some(ref ref_tok) = token_resp.refresh_token {
                refresh_stored = self.keyring_mgr.store_token(KIND_REFRESH_TOKEN, ref_tok);
            }
        }

        if access_stored {
            storage.access_token = None;
        } else {
            crate::log_warn!(
                "omawarden:auth",
                "System keyring not available or store failed. Storing session token in local storage."
            );
            storage.access_token = Some(token_resp.access_token.clone());
        }

        if refresh_stored {
            storage.refresh_token = None;
        } else {
            storage.refresh_token = token_resp.refresh_token;
        }

        // Pull initial sync
        if let Ok(sync_data) = client.sync_vault(&token_resp.access_token) {
            storage.ciphers = sync_data.ciphers;
            storage.folders = sync_data.folders;
            storage.collections = sync_data.collections;
            if let Some(ref prof) = sync_data.profile {
                if let Some(id) = prof.get("id").and_then(|v| v.as_str()) {
                    storage.user_id = Some(id.to_string());
                }
                if storage.enc_user_key.is_none() {
                    if let Some(key) = prof.get("key").and_then(|v| v.as_str()) {
                        storage.enc_user_key = Some(key.to_string());
                    }
                }
                if storage.enc_private_key.is_none() {
                    if let Some(pk) = prof.get("privateKey").and_then(|v| v.as_str()) {
                        storage.enc_private_key = Some(pk.to_string());
                    }
                }
                if let Some(orgs) = prof.get("organizations").and_then(|v| v.as_array()) {
                    storage.organizations = orgs.clone();
                }
            }
            storage.last_sync = Some(chrono::Utc::now().to_rfc3339());
        }

        let _ = self.storage_mgr.save(&storage);

        // Auto-unlock daemon with decrypted items in memory
        crate::daemon::ensure_daemon_running();
        let _ = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "unlock",
            "password": password
        }));

        crate::log_info!(
            "omawarden:auth",
            "Login successful for {}. Initial sync retrieved {} ciphers.",
            email,
            storage.ciphers.len()
        );

        AuthResult {
            ok: true,
            status: Some("unlocked".to_string()),
            session: Some(token_resp.access_token),
            error: None,
        }
    }

    pub fn login_apikey(&self, client_id: &str, client_secret: &str) -> AuthResult {
        crate::log_info!(
            "omawarden:auth",
            "Starting login with API Key client_id: {}",
            client_id
        );
        let client = BitwardenApiClient::new(&self.server_url);
        let token_resp = match client.login_apikey(client_id, client_secret) {
            Ok(r) => r,
            Err(e) => {
                let err_msg = sanitize_auth_error(Some(&e.to_string()));
                crate::log_warn!("omawarden:auth", "API key login failed: {}", err_msg);
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(err_msg),
                };
            }
        };

        let mut storage = self.storage_mgr.load();
        storage.server_url = self.server_url.clone();
        storage.client_id = Some(client_id.trim().to_string());
        storage.enc_user_key = token_resp.key;
        storage.enc_private_key = token_resp.private_key;
        storage.kdf = token_resp.kdf;
        storage.kdf_iterations = token_resp.kdf_iterations;
        storage.kdf_memory = token_resp.kdf_memory;
        storage.kdf_parallelism = token_resp.kdf_parallelism;

        let mut access_stored = false;
        let mut refresh_stored = false;
        if self.keyring_mgr.is_available() {
            access_stored = self
                .keyring_mgr
                .store_token(KIND_ACCESS_TOKEN, &token_resp.access_token);
            if let Some(ref ref_tok) = token_resp.refresh_token {
                refresh_stored = self.keyring_mgr.store_token(KIND_REFRESH_TOKEN, ref_tok);
            }
            let s_url = if !storage.server_url.is_empty() {
                &storage.server_url
            } else {
                &self.server_url
            };
            let _ =
                self.keyring_mgr
                    .store_api_secret(s_url, client_id.trim(), client_secret.trim());
        }

        if access_stored {
            storage.access_token = None;
        } else {
            crate::log_warn!(
                "omawarden:auth",
                "System keyring not available or store failed. Storing session token in local storage."
            );
            storage.access_token = Some(token_resp.access_token.clone());
        }

        if refresh_stored {
            storage.refresh_token = None;
        } else {
            storage.refresh_token = token_resp.refresh_token;
        }

        // Pull initial sync
        if let Ok(sync_data) = client.sync_vault(&token_resp.access_token) {
            storage.ciphers = sync_data.ciphers;
            storage.folders = sync_data.folders;
            storage.collections = sync_data.collections;
            if let Some(ref prof) = sync_data.profile {
                if let Some(email) = prof.get("email").and_then(|v| v.as_str()) {
                    storage.user_email = email.trim().to_lowercase();
                }
                if let Some(id) = prof.get("id").and_then(|v| v.as_str()) {
                    storage.user_id = Some(id.to_string());
                }
                if storage.enc_user_key.is_none() {
                    if let Some(key) = prof.get("key").and_then(|v| v.as_str()) {
                        storage.enc_user_key = Some(key.to_string());
                    }
                }
                if storage.enc_private_key.is_none() {
                    if let Some(pk) = prof.get("privateKey").and_then(|v| v.as_str()) {
                        storage.enc_private_key = Some(pk.to_string());
                    }
                }
                if storage.kdf.is_none() {
                    if let Some(kdf) = prof.get("kdf").and_then(|v| v.as_u64()) {
                        storage.kdf = Some(kdf as u32);
                    }
                }
                if storage.kdf_iterations.is_none() {
                    if let Some(iter) = prof.get("kdfIterations").and_then(|v| v.as_u64()) {
                        storage.kdf_iterations = Some(iter as u32);
                    }
                }
                if storage.kdf_memory.is_none() {
                    if let Some(mem) = prof.get("kdfMemory").and_then(|v| v.as_u64()) {
                        storage.kdf_memory = Some(mem as u32);
                    }
                }
                if storage.kdf_parallelism.is_none() {
                    if let Some(par) = prof.get("kdfParallelism").and_then(|v| v.as_u64()) {
                        storage.kdf_parallelism = Some(par as u32);
                    }
                }
                if let Some(orgs) = prof.get("organizations").and_then(|v| v.as_array()) {
                    storage.organizations = orgs.clone();
                }
            }
            storage.last_sync = Some(chrono::Utc::now().to_rfc3339());
        }

        if storage.user_email.is_empty() {
            storage.user_email = client_id.trim().to_string();
        }

        let _ = self.storage_mgr.save(&storage);

        crate::log_info!("omawarden:auth", "API key authentication successful.");

        AuthResult {
            ok: true,
            status: Some("locked".to_string()),
            session: Some(token_resp.access_token),
            error: None,
        }
    }

    pub fn unlock(&self, password: &str) -> AuthResult {
        crate::log_info!("omawarden:auth", "Unlocking vault with master password...");
        let storage = self.storage_mgr.load();
        if storage.enc_user_key.is_none() {
            crate::log_warn!("omawarden:auth", "Account is not logged in.");
            return AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some("Account is not logged in.".to_string()),
            };
        }

        let password_zeroizing = Zeroizing::new(password.to_string());
        match self
            .storage_mgr
            .unlock_user_key(&password_zeroizing, &storage)
        {
            Ok(_user_key) => {
                let token_opt = self
                    .keyring_mgr
                    .get_token(KIND_ACCESS_TOKEN)
                    .or_else(|| self.keyring_mgr.get_session())
                    .or_else(|| storage.access_token.clone());

                let session_val = if let Some(ref token) = token_opt {
                    if token != "session_unlocked" && !token.is_empty() {
                        self.keyring_mgr.store_token(KIND_ACCESS_TOKEN, token);
                    }
                    Some(token.clone())
                } else {
                    None
                };

                // Auto-unlock daemon with decrypted items in memory
                crate::daemon::ensure_daemon_running();
                let _ = crate::daemon::send_daemon_request(&serde_json::json!({
                    "action": "unlock",
                    "password": password
                }));

                crate::log_info!("omawarden:auth", "Vault unlocked successfully.");

                AuthResult {
                    ok: true,
                    status: Some("unlocked".to_string()),
                    session: session_val,
                    error: None,
                }
            }
            Err(e) => {
                let err_msg = sanitize_auth_error(Some(&e.to_string()));
                crate::log_warn!("omawarden:auth", "Unlock failed: {}", err_msg);
                AuthResult {
                    ok: false,
                    status: Some("locked".to_string()),
                    session: None,
                    error: Some(err_msg),
                }
            }
        }
    }

    pub fn lock(&self) -> AuthResult {
        self.keyring_mgr.clear_session();
        let _ = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "lock"
        }));
        crate::attachment::clear_preview_attachments(None);
        crate::log_info!("omawarden:auth", "Vault locked.");
        AuthResult {
            ok: true,
            status: Some("locked".to_string()),
            session: None,
            error: None,
        }
    }

    pub fn logout(&self) -> AuthResult {
        self.keyring_mgr.clear_all();
        self.keyring_mgr.clear_session();
        let _ = self.storage_mgr.save(&VaultStorage::default());
        let _ = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "lock"
        }));
        crate::attachment::clear_preview_attachments(None);
        crate::log_info!(
            "omawarden:auth",
            "Account logged out and all keyring credentials cleared."
        );
        AuthResult {
            ok: true,
            status: Some("unauthenticated".to_string()),
            session: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sanitize_auth_error_patterns() {
        assert_eq!(
            sanitize_auth_error(Some("Invalid password")),
            "Invalid username, email, or master password."
        );
        assert_eq!(
            sanitize_auth_error(Some("Decryption failed on item cipher")),
            "Decryption failed. Incorrect master password."
        );
        assert_eq!(
            sanitize_auth_error(Some("Two-factor code required")),
            "Two-factor authentication required or invalid code."
        );
        assert_eq!(
            sanitize_auth_error(Some("Already logged in")),
            "Already logged in."
        );
        assert_eq!(
            sanitize_auth_error(Some("network error ECONNREFUSED")),
            "Network error: unable to reach Bitwarden server."
        );
        assert_eq!(
            sanitize_auth_error(Some("Vault is locked")),
            "Vault is locked."
        );
        assert_eq!(
            sanitize_auth_error(Some(
                "Random error with token a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
            )),
            "Random error with token [REDACTED]"
        );
    }

    #[test]
    fn test_auth_manager_status_and_lock() {
        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_auth_data.json");
        let storage_mgr = StorageManager::new(storage_path);

        let mock_keyring = KeyringManager::new("non_existent_secret_tool_for_test");
        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring),
        );

        // Initially unauthenticated
        let st = auth_mgr.get_status(false);
        assert_eq!(st.status, "unauthenticated");

        // Simulate stored account
        let storage = VaultStorage {
            user_email: "test@example.com".to_string(),
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let st_locked = auth_mgr.get_status(false);
        assert_eq!(st_locked.status, "locked");
        assert_eq!(st_locked.user_email.as_deref(), Some("test@example.com"));

        // Lock
        let lock_res = auth_mgr.lock();
        assert!(lock_res.ok);
        assert_eq!(lock_res.status.as_deref(), Some("locked"));

        // Logout
        let logout_res = auth_mgr.logout();
        assert!(logout_res.ok);
        assert_eq!(logout_res.status.as_deref(), Some("unauthenticated"));
    }

    #[test]
    fn test_login_apikey_network_failure() {
        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_apikey_data.json");
        let storage_mgr = StorageManager::new(storage_path);

        let mock_keyring = KeyringManager::new("non_existent_secret_tool_for_test");
        let auth_mgr = AuthManager::new(
            "http://127.0.0.1:9", // Invalid dead port to verify network error handling
            Some(storage_mgr),
            Some(mock_keyring),
        );

        let res = auth_mgr.login_apikey("user.client-id-123", "secret-xyz");
        assert!(!res.ok);
        assert_eq!(res.status.as_deref(), Some("unauthenticated"));
        assert!(res.error.is_some());
    }

    #[test]
    fn test_auth_status_with_apikey_session() {
        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_apikey_status.json");
        let storage_mgr = StorageManager::new(storage_path);

        let mock_keyring = KeyringManager::new("non_existent_secret_tool_for_test");
        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring),
        );

        // Simulate storage after API key authentication
        let storage = VaultStorage {
            user_email: "apikey-user@example.com".to_string(),
            user_id: Some("user-uuid-123".to_string()),
            access_token: Some("fake_access_token_abc".to_string()),
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let st = auth_mgr.get_status(false);
        assert_eq!(st.status, "locked");
        assert_eq!(st.user_email.as_deref(), Some("apikey-user@example.com"));
        assert_eq!(st.user_id.as_deref(), Some("user-uuid-123"));
        assert!(st.has_session);
    }

    #[test]
    fn test_jwt_expiration_detection() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 3600 });
        let future_payload = serde_json::json!({ "exp": now + 3600 });

        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let future_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&future_payload).unwrap());

        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);
        let valid_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", future_b64);

        assert!(is_jwt_expired(&expired_token));
        assert!(!is_jwt_expired(&valid_token));
        assert!(!is_jwt_expired("invalid_token_not_three_parts"));
    }

    #[test]
    fn test_auth_status_with_expired_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_expired_status.json");
        let storage_mgr = StorageManager::new(storage_path);

        let mock_keyring = KeyringManager::new("non_existent_secret_tool_for_test");
        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring),
        );

        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 100 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);

        let storage = VaultStorage {
            user_email: "expired-user@example.com".to_string(),
            user_id: Some("user-uuid-999".to_string()),
            access_token: Some(expired_token),
            refresh_token: None,
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let st = auth_mgr.get_status(false);
        assert_eq!(st.status, "unauthenticated");
        assert!(!st.has_session);
        assert_eq!(st.user_email.as_deref(), Some("expired-user@example.com"));

        // Verify storage had access_token cleared
        let fresh_storage = storage_mgr.load();
        assert!(fresh_storage.access_token.is_none());
    }

    #[test]
    fn test_auth_status_with_expired_token_but_renewable_via_api_secret() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_expired_renewable.json");
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

        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 100 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);

        // Store API secret in Keyring
        assert!(mock_keyring.store_api_secret(
            "https://vault.example.com",
            "user.test-client-id",
            "secret_xyz_123"
        ));
        assert!(mock_keyring.store_token(KIND_ACCESS_TOKEN, &expired_token));

        let storage = VaultStorage {
            server_url: "https://vault.example.com".to_string(),
            user_email: "apikey-user@example.com".to_string(),
            user_id: Some("user-uuid-999".to_string()),
            client_id: Some("user.test-client-id".to_string()),
            access_token: None, // Stored in keyring!
            refresh_token: None,
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let st = auth_mgr.get_status(false);
        // Because client_secret exists in keyring, has_session remains true
        assert!(st.has_session);
        assert_eq!(st.status, "locked");
    }

    #[test]
    fn test_auth_status_token_auto_migration() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_migration.json");
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

        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        // Pre-migration storage contains plaintext tokens
        let storage = VaultStorage {
            user_email: "migrate@example.com".to_string(),
            server_url: "https://vault.example.com".to_string(),
            access_token: Some("plaintext_access_123".to_string()),
            refresh_token: Some("plaintext_refresh_456".to_string()),
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        // Check status triggers migration
        let st = auth_mgr.get_status(false);
        assert!(st.has_session);
        assert_eq!(st.status, "locked");

        // Verify tokens migrated to Keyring
        assert_eq!(
            mock_keyring.get_token(KIND_ACCESS_TOKEN),
            Some("plaintext_access_123".to_string())
        );
        assert_eq!(
            mock_keyring.get_token(KIND_REFRESH_TOKEN),
            Some("plaintext_refresh_456".to_string())
        );

        // Verify plaintext tokens scrubbed from disk
        let fresh_storage = storage_mgr.load();
        assert!(fresh_storage.access_token.is_none());
        assert!(fresh_storage.refresh_token.is_none());
    }

    #[test]
    fn test_auth_status_token_migration_failure_preserves_disk_tokens() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_migration_failure.json");
        let storage_mgr = StorageManager::new(storage_path);

        let script_path = dir.path().join("mock-secret-tool-fail");
        // Script is an executable that always exits with code 1
        let script = "#!/bin/sh\nexit 1\n";
        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        // keyring is_available() will return true because the binary exists, but store will fail
        assert!(mock_keyring.is_available());

        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring),
        );

        let storage = VaultStorage {
            user_email: "safeguard@example.com".to_string(),
            server_url: "https://vault.example.com".to_string(),
            access_token: Some("critical_access_tok".to_string()),
            refresh_token: Some("critical_refresh_tok".to_string()),
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        let st = auth_mgr.get_status(false);
        assert!(st.has_session);

        // Tokens MUST remain on disk because keyring store failed!
        let fresh_storage = storage_mgr.load();
        assert_eq!(
            fresh_storage.access_token.as_deref(),
            Some("critical_access_tok")
        );
        assert_eq!(
            fresh_storage.refresh_token.as_deref(),
            Some("critical_refresh_tok")
        );
    }

    #[test]
    fn test_auth_status_custom_server_url_precedence() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_custom_url.json");
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
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        // Default CLI server_url is bitwarden.com
        let auth_mgr = AuthManager::new(
            "https://vault.bitwarden.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        let custom_url = "https://vaultwarden.custom.local";
        let client_id = "user.custom-client-123";

        // Store API secret keyed to custom_url
        assert!(mock_keyring.store_api_secret(custom_url, client_id, "top_secret"));

        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 50 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);
        assert!(mock_keyring.store_token(KIND_ACCESS_TOKEN, &expired_token));

        let storage = VaultStorage {
            server_url: custom_url.to_string(),
            user_email: "custom@local.org".to_string(),
            client_id: Some(client_id.to_string()),
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();

        // get_status should prioritize storage.server_url over default self.server_url and find the secret
        let st = auth_mgr.get_status(false);
        assert!(st.has_session);
        assert_eq!(st.status, "locked");
    }
}
