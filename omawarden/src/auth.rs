use regex::Regex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::api::BitwardenApiClient;
use crate::keyring::KeyringManager;
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
        let storage = self.storage_mgr.load();

        if storage.enc_user_key.is_none() || storage.user_email.is_empty() {
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
                has_session: is_unlocked_same_user,
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
            has_session: false,
        }
    }

    pub fn login_password(&self, email: &str, password: &str, code: Option<&str>) -> AuthResult {
        let client = BitwardenApiClient::new(&self.server_url);
        let password_zeroizing = Zeroizing::new(password.to_string());

        let (token_resp, _user_key) = match client.login_password(email, &password_zeroizing, code)
        {
            Ok(r) => r,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                };
            }
        };

        let mut storage = self.storage_mgr.load();
        storage.server_url = self.server_url.clone();
        storage.user_email = email.trim().to_lowercase();
        storage.access_token = Some(token_resp.access_token.clone());
        storage.refresh_token = token_resp.refresh_token;
        storage.enc_user_key = token_resp.key;
        storage.enc_private_key = token_resp.private_key;
        storage.kdf = token_resp.kdf;
        storage.kdf_iterations = token_resp.kdf_iterations;
        storage.kdf_memory = token_resp.kdf_memory;
        storage.kdf_parallelism = token_resp.kdf_parallelism;

        // Pull initial sync
        if let Ok(sync_data) = client.sync_vault(&token_resp.access_token) {
            storage.ciphers = sync_data.ciphers;
            storage.last_sync = Some(chrono::Utc::now().to_rfc3339());
        }

        let _ = self.storage_mgr.save(&storage);
        self.keyring_mgr.store_session(&token_resp.access_token);

        // Auto-unlock daemon with decrypted items in memory
        crate::daemon::ensure_daemon_running();
        let _ = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "unlock",
            "password": password
        }));

        AuthResult {
            ok: true,
            status: Some("unlocked".to_string()),
            session: Some(token_resp.access_token),
            error: None,
        }
    }

    pub fn login_apikey(&self, _client_id: &str, _client_secret: &str) -> AuthResult {
        // Direct API Key flow
        AuthResult {
            ok: false,
            status: Some("unauthenticated".to_string()),
            session: None,
            error: Some("API Key login will be integrated in next patch.".to_string()),
        }
    }

    pub fn unlock(&self, password: &str) -> AuthResult {
        let storage = self.storage_mgr.load();
        if storage.enc_user_key.is_none() {
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
                let token = storage
                    .access_token
                    .clone()
                    .unwrap_or_else(|| "session_unlocked".to_string());
                self.keyring_mgr.store_session(&token);

                // Auto-unlock daemon with decrypted items in memory
                crate::daemon::ensure_daemon_running();
                let _ = crate::daemon::send_daemon_request(&serde_json::json!({
                    "action": "unlock",
                    "password": password
                }));

                AuthResult {
                    ok: true,
                    status: Some("unlocked".to_string()),
                    session: Some(token),
                    error: None,
                }
            }
            Err(e) => AuthResult {
                ok: false,
                status: Some("locked".to_string()),
                session: None,
                error: Some(sanitize_auth_error(Some(&e.to_string()))),
            },
        }
    }

    pub fn lock(&self) -> AuthResult {
        self.keyring_mgr.clear_session();
        AuthResult {
            ok: true,
            status: Some("locked".to_string()),
            session: None,
            error: None,
        }
    }

    pub fn logout(&self) -> AuthResult {
        self.keyring_mgr.clear_session();
        let _ = self.storage_mgr.save(&VaultStorage::default());
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

        // Logout
        let logout_res = auth_mgr.logout();
        assert!(logout_res.ok);
        assert_eq!(logout_res.status.as_deref(), Some("unauthenticated"));
    }
}
