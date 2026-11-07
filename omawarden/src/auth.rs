use regex::Regex;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::account_activation::{ActivationError, LoginConnection};
use crate::api::BitwardenApiClient;
use crate::config::ConfigManager;
use crate::credential_slots::erase_retired;
use crate::keyring::{KeyringManager, KIND_ACCESS_TOKEN, KIND_API_SECRET, KIND_REFRESH_TOKEN};
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
    if (lower.contains("invalid") || lower.contains("incorrect") || lower.contains("not found"))
        && (lower.contains("password")
            || lower.contains("username")
            || lower.contains("email")
            || lower.contains("user"))
    {
        return "Invalid username, email, or master password.".to_string();
    }
    if lower.contains("decryption") || lower.contains("not the expected type") {
        return "Decryption failed. Incorrect master password.".to_string();
    }
    if lower.contains("new device verification") {
        return "New device verification required. Please check your email for the verification code.".to_string();
    }
    if lower.contains("two-step")
        || lower.contains("two-factor")
        || lower.contains("two factor")
        || lower.contains("twofactor")
        || lower.contains("2fa")
        || lower.contains("verification code")
        || lower.contains("authenticator code")
        || lower.contains("security code")
    {
        return "Two-factor authentication required or invalid code.".to_string();
    }
    if lower.contains("already logged in") {
        return "Already logged in.".to_string();
    }
    if lower.contains("404") || lower.contains("endpoint not found") {
        return "Bitwarden server endpoint not found (HTTP 404). Please verify your server URL."
            .to_string();
    }
    if lower.contains("http error 500")
        || lower.contains("http 500")
        || lower.contains("status 500")
        || lower.contains("internal server error")
    {
        return "Bitwarden server encountered an internal error (HTTP 500).".to_string();
    }
    if lower.contains("http error 502")
        || lower.contains("http 502")
        || lower.contains("status 502")
        || lower.contains("bad gateway")
    {
        return "Bitwarden server is unavailable (HTTP 502 Bad Gateway).".to_string();
    }
    if lower.contains("http error 503")
        || lower.contains("http 503")
        || lower.contains("status 503")
        || lower.contains("service unavailable")
    {
        return "Bitwarden server is temporarily unavailable (HTTP 503).".to_string();
    }
    if lower.contains("network")
        || lower.contains("failed to fetch")
        || lower.contains("econnrefused")
        || lower.contains("connection refused")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("unable to reach")
        || lower.contains("dns")
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

pub(crate) fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    let mut parts = token.split('.');
    parts.next()?;
    let payload = parts.next()?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .or_else(|_| STANDARD.decode(payload))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn is_jwt_expired(token: &str) -> bool {
    jwt_claims(token)
        .and_then(|claims| claims["exp"].as_i64())
        .is_some_and(|exp| chrono::Utc::now().timestamp() >= exp)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthStatus {
    pub status: String,
    /// Opaque lock cycle for the unlocked account. Older daemons omit it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_generation: Option<String>,
    pub server_url: Option<String>,
    pub last_sync: Option<String>,
    pub user_email: Option<String>,
    pub user_id: Option<String>,
    pub has_session: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResult {
    pub ok: bool,
    pub status: Option<String>,
    pub session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_providers: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_provider: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub two_factor_providers2: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_device_verification_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fido2_status: Option<String>,
}

pub struct AuthManager {
    pub server_url: String,
    pub identity_url: Option<String>,
    pub storage_mgr: StorageManager,
    pub keyring_mgr: KeyringManager,
    pub config_mgr: Option<ConfigManager>,
}

impl AuthManager {
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
        Self::with_config(server_url, identity_url, storage_mgr, keyring_mgr, None)
    }

    pub fn with_config(
        server_url: &str,
        identity_url: Option<&str>,
        storage_mgr: Option<StorageManager>,
        keyring_mgr: Option<KeyringManager>,
        config_mgr: Option<ConfigManager>,
    ) -> Self {
        let sm = storage_mgr.unwrap_or_default();
        let storage = sm.load();
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
            server_url: server_url.to_string(),
            identity_url: effective_identity_url,
            storage_mgr: sm,
            keyring_mgr: keyring_mgr.unwrap_or_default(),
            config_mgr,
        }
    }

    fn daemon_unlock_context() -> Result<Option<String>, &'static str> {
        use crate::daemon::{dispatch_daemon_request, DispatchError};

        match dispatch_daemon_request(&serde_json::json!({"action":"ping"})) {
            Ok(reply) if reply["account_activation_v1"] == true => reply["unlock_context"]
                .as_str()
                .map(|context| Some(context.to_owned()))
                .ok_or("Cannot verify the daemon session before login."),
            Ok(_) => Err("Lock the vault to update the running daemon, then sign in again."),
            Err(DispatchError::NotSent) => Ok(None),
            Err(DispatchError::Unconfirmed) => {
                Err("Cannot verify the daemon session before login.")
            }
            Err(DispatchError::IncompatibleProtocol { .. }) => {
                Err("Incompatible daemon protocol version. Restart the daemon to sign in.")
            }
            Err(DispatchError::LaunchFailed(_)) => Err("Cannot start the daemon before login."),
        }
    }

    fn publish_login(
        &self,
        connection: LoginConnection,
        storage: &mut VaultStorage,
        access_token: &str,
        refresh_token: Option<&str>,
        api_secret: Option<&str>,
    ) -> Result<Option<String>, String> {
        let credential_id = connection.attempt_id.clone();
        storage.credential_id = Some(credential_id.clone());
        let lease = self
            .storage_mgr
            .lease_candidate(&credential_id)
            .map_err(|_| "Cannot track the candidate credentials")?;
        let candidate = self.keyring_mgr.for_storage(storage).with_lease(&lease);
        let prepared = (|| {
            if !candidate.store_token(KIND_ACCESS_TOKEN, access_token) {
                return Err("Failed to store access token in system keyring.");
            }
            if refresh_token.is_some_and(|token| !candidate.store_token(KIND_REFRESH_TOKEN, token))
            {
                return Err("Failed to store refresh token in system keyring.");
            }
            if api_secret.is_some_and(|secret| !candidate.store_token(KIND_API_SECRET, secret)) {
                return Err("Failed to store API secret in system keyring.");
            }

            lease
                .write_candidate(storage)
                .map_err(|_| "Cannot stage the login snapshot")
        })();
        let publication = match prepared {
            Ok(()) => connection.activate(&self.storage_mgr),
            Err(error) => Err(ActivationError::Rejected(error.into())),
        };
        drop(lease);
        match publication {
            Err(ActivationError::Rejected(error)) => {
                let cleanup = self.storage_mgr.rejected_candidate(&credential_id)
                    .and_then(|slot| erase_retired(slot, &self.keyring_mgr));
                if let Err(cleanup_error) = cleanup {
                    crate::log_warn!(
                        "omawarden:auth",
                        "Candidate credential cleanup pending. {}",
                        cleanup_error
                    );
                }
                Err(error)
            }
            Err(ActivationError::Unknown) => Err(format!(
                "Could not confirm sign-in. Check the vault before trying again. Attempt {credential_id}."
            )),
            Ok(context) => Ok(context),
        }
    }

    fn invalidate_expired_session(&self, expected: &VaultStorage, token: &str) -> bool {
        let Ok(_account) = self.storage_mgr.account_guard() else {
            return false;
        };
        let Ok(mut storage) = self.storage_mgr.load_existing() else {
            return false;
        };
        if !storage.same_active_slot(expected) {
            return false;
        }
        let keyring = self.keyring_mgr.for_storage(&storage);
        let current = keyring.access_token();
        if current.as_deref() != Some(token)
            || keyring.refresh_token().is_some()
            || keyring.api_secret().is_some()
        {
            return false;
        }
        keyring.clear_token(KIND_ACCESS_TOKEN);
        if storage.access_token.take().is_some() {
            let _ = self.storage_mgr.save(&storage);
        }
        true
    }

    pub fn get_status(&self, _verify: bool) -> AuthStatus {
        let storage = self.storage_mgr.load();
        let keyring = self.keyring_mgr.for_storage(&storage);
        let active_token = keyring.access_token();
        let has_refresh = keyring.refresh_token().is_some();
        let has_api_secret = keyring.api_secret().is_some();

        if storage.scoped_credential_id().is_none()
            || (storage.enc_user_key.is_none() && active_token.is_none() && !has_api_secret)
            || (storage.user_email.is_empty() && storage.client_id.is_none())
        {
            return AuthStatus {
                lock_generation: None,
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
                    if self.invalidate_expired_session(&storage, tok) {
                        let _ = crate::daemon::send_daemon_request(
                            &serde_json::json!({ "action": "lock" }),
                        );
                        return AuthStatus {
                            lock_generation: None,
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
                    }
                    token_expired = true;
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
            let is_unlocked_same_user = is_unlocked
                && daemon_resp["credential_id"].as_str() == storage.scoped_credential_id();
            let status_str = if is_unlocked_same_user {
                "unlocked".to_string()
            } else {
                "locked".to_string()
            };

            return AuthStatus {
                lock_generation: if is_unlocked_same_user {
                    daemon_resp["lock_generation"].as_str().map(str::to_owned)
                } else {
                    None
                },
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
            lock_generation: None,
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

    pub fn login_password(
        &self,
        email: &str,
        password: &str,
        code: Option<&str>,
        two_factor_provider: Option<i32>,
        new_device_otp: Option<&str>,
    ) -> AuthResult {
        crate::log_info!(
            "omawarden:auth",
            "Starting login with password for {}",
            email
        );
        if !self.keyring_mgr.is_available() {
            let err_msg = "System keyring is not available. Keyring is required to securely store authentication tokens.";
            crate::log_error!("omawarden:auth", "{}", err_msg);
            return AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some(err_msg.to_string()),
                two_factor_required: None,
                two_factor_providers: None,
                two_factor_provider: None,
                new_device_verification_required: None,
                ..Default::default()
            };
        }
        // Start once at the login entry point. The later context check must
        // observe a stopped/locked daemon, never restart it and sample anew.
        if let Err(e @ crate::daemon::DispatchError::IncompatibleProtocol { .. }) =
            crate::daemon::ensure_daemon_running()
        {
            return AuthResult {
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
        let login_context = match Self::daemon_unlock_context() {
            Ok(context) => context,
            Err(error) => {
                return AuthResult {
                    error: Some(error.into()),
                    ..Default::default()
                }
            }
        };
        let client =
            BitwardenApiClient::with_identity_url(&self.server_url, self.identity_url.as_deref());
        let password_zeroizing = Zeroizing::new(password.to_string());

        let (token_resp, _user_key) = match client.login_password(
            email,
            &password_zeroizing,
            code,
            two_factor_provider,
            new_device_otp,
        ) {
            Ok(r) => r,
            Err(crate::api::ApiError::TwoFactorRequired {
                providers,
                providers2,
            }) => {
                crate::log_info!(
                    "omawarden:auth",
                    "Two-factor authentication required for {}",
                    email
                );

                // If WebAuthn (provider 7) is requested (or is the sole provider) and token was not provided,
                // automatically attempt FIDO2 assertion with a connected security key.
                let is_webauthn_target = two_factor_provider == Some(7)
                    || (two_factor_provider.is_none() && providers == vec![7]);
                if is_webauthn_target && code.is_none() {
                    if let Some(ref p2) = providers2 {
                        if let Some(ch) =
                            crate::webauthn::parse_webauthn_challenge(p2, &self.server_url)
                        {
                            crate::log_info!(
                                "omawarden:auth",
                                "Attempting FIDO2 WebAuthn assertion with security key..."
                            );
                            match crate::webauthn::create_webauthn_two_factor_token(&ch) {
                                Ok(token) => {
                                    return self.login_password(
                                        email,
                                        password,
                                        Some(&token),
                                        Some(7),
                                        new_device_otp,
                                    );
                                }
                                Err(e) => {
                                    crate::log_warn!(
                                        "omawarden:auth",
                                        "WebAuthn assertion failed: {}",
                                        e
                                    );
                                    let current_fido2 = crate::webauthn::check_fido2_status();
                                    return AuthResult {
                                        ok: false,
                                        status: Some("unauthenticated".to_string()),
                                        error: Some(format!("Security key error: {}", e)),
                                        two_factor_required: Some(true),
                                        two_factor_providers: Some(providers),
                                        two_factor_provider: Some(7),
                                        two_factor_providers2: providers2,
                                        fido2_status: Some(current_fido2.as_str().to_string()),
                                        ..Default::default()
                                    };
                                }
                            }
                        }
                    }
                }

                let fido2_status = if providers.contains(&7) {
                    Some(crate::webauthn::check_fido2_status())
                } else {
                    None
                };

                let default_provider = if providers.contains(&7)
                    && fido2_status == Some(crate::webauthn::Fido2Status::Available)
                {
                    7
                } else if providers.contains(&0) {
                    0
                } else if providers.contains(&1) {
                    1
                } else if providers.contains(&7) {
                    7
                } else {
                    *providers.first().unwrap_or(&0)
                };
                let err_text = if default_provider == 7 {
                    if fido2_status == Some(crate::webauthn::Fido2Status::ToolNotFound) {
                        "WebAuthn security key authentication required, but libfido2 tools were not found. Please install 'libfido2' package or choose another method."
                    } else if fido2_status == Some(crate::webauthn::Fido2Status::NoDevice) {
                        "WebAuthn security key authentication required. Please insert your security key, or choose another method."
                    } else {
                        "WebAuthn security key authentication required. Please insert and touch your security key."
                    }
                } else if default_provider == 1 {
                    "Email two-factor authentication required. Please check your email for the verification code."
                } else {
                    "Two-factor authentication required or invalid code."
                };
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(err_text.to_string()),
                    two_factor_required: Some(true),
                    two_factor_providers: Some(providers),
                    two_factor_provider: Some(default_provider),
                    two_factor_providers2: providers2,
                    fido2_status: fido2_status.map(|s| s.as_str().to_string()),
                    ..Default::default()
                };
            }
            Err(crate::api::ApiError::NewDeviceVerificationRequired) => {
                crate::log_info!(
                    "omawarden:auth",
                    "New device verification required for {}",
                    email
                );
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(
                        "New device verification required. Please check your email for the verification code."
                            .to_string(),
                    ),
                    two_factor_required: Some(true),
                    new_device_verification_required: Some(true),
                    ..Default::default()
                };
            }
            Err(e) => {
                let err_msg = sanitize_auth_error(Some(&e.to_string()));
                let is_new_device = err_msg.to_lowercase().contains("new device verification");
                let is_2fa = is_new_device
                    || err_msg.to_lowercase().contains("two-factor")
                    || err_msg.to_lowercase().contains("two factor")
                    || err_msg.to_lowercase().contains("2fa");
                crate::log_warn!("omawarden:auth", "Login failed for {}: {}", email, err_msg);
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(err_msg),
                    two_factor_required: if is_2fa { Some(true) } else { None },
                    new_device_verification_required: if is_new_device { Some(true) } else { None },
                    two_factor_providers: None,
                    ..Default::default()
                };
            }
        };

        if !self.keyring_mgr.is_available() {
            let err_msg = "System keyring is not available. Keyring is required to securely store authentication tokens.";
            crate::log_error!("omawarden:auth", "{}", err_msg);
            return AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some(err_msg.to_string()),
                two_factor_required: None,
                two_factor_providers: None,
                ..Default::default()
            };
        }
        let connection = match LoginConnection::begin(login_context.as_deref()) {
            Ok(connection) => connection,
            Err(error) => {
                return AuthResult {
                    error: Some(error),
                    ..Default::default()
                }
            }
        };
        let initial_sync = match client.sync_vault(&token_resp.access_token) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return AuthResult {
                    ok: false,
                    error: Some("Initial vault synchronization failed. Check the connection and sign in again.".into()),
                    ..Default::default()
                };
            }
        };
        let mut storage = VaultStorage {
            server_url: self.server_url.clone(),
            identity_url: self.identity_url.clone(),
            user_email: email.trim().to_lowercase(),
            enc_user_key: token_resp.key,
            enc_private_key: token_resp.private_key,
            kdf: token_resp.kdf,
            kdf_iterations: token_resp.kdf_iterations,
            kdf_memory: token_resp.kdf_memory,
            kdf_parallelism: token_resp.kdf_parallelism,
            ..Default::default()
        };

        // Install only a complete snapshot belonging to these credentials.
        let sync_data = initial_sync;
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

        let context = match self.publish_login(
            connection,
            &mut storage,
            &token_resp.access_token,
            token_resp.refresh_token.as_deref(),
            None,
        ) {
            Ok(context) => context,
            Err(error) => {
                return AuthResult {
                    error: Some(error),
                    ..Default::default()
                }
            }
        };

        if let Some(ref cm) = self.config_mgr {
            let mut cfg = cm.load();
            if cfg.remember_email {
                cfg.email = email.trim().to_lowercase();
                let _ = cm.save(&cfg);
            }
        }

        // A lock after activation takes priority over this optional auto-unlock.
        let unlocked = context.is_some_and(|context| {
            crate::daemon::send_daemon_request(&serde_json::json!({
                "action":"unlock", "password":password, "expected_unlock_context":context,
                "expected_credential_id":storage.credential_id
            }))
            .is_some_and(|reply| reply["ok"] == true)
        });

        crate::log_info!(
            "omawarden:auth",
            "Login successful for {}. Initial sync retrieved {} ciphers.",
            email,
            storage.ciphers.len()
        );

        AuthResult {
            ok: true,
            status: Some(if unlocked { "unlocked" } else { "locked" }.to_string()),
            ..Default::default()
        }
    }

    pub fn send_two_factor_email(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(), crate::api::ApiError> {
        let client =
            BitwardenApiClient::with_identity_url(&self.server_url, self.identity_url.as_deref());
        client.send_two_factor_email(email, password)
    }

    pub fn login_apikey(&self, client_id: &str, client_secret: &str) -> AuthResult {
        crate::log_info!(
            "omawarden:auth",
            "Starting login with API Key client_id: {}",
            client_id
        );
        if !self.keyring_mgr.is_available() {
            let err_msg = "System keyring is not available. Keyring is required to securely store authentication tokens.";
            crate::log_error!("omawarden:auth", "{}", err_msg);
            return AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some(err_msg.to_string()),
                ..Default::default()
            };
        }
        if let Err(e @ crate::daemon::DispatchError::IncompatibleProtocol { .. }) =
            crate::daemon::ensure_daemon_running()
        {
            return AuthResult {
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
        let login_context = match Self::daemon_unlock_context() {
            Ok(context) => context,
            Err(error) => {
                return AuthResult {
                    error: Some(error.into()),
                    ..Default::default()
                }
            }
        };
        let client =
            BitwardenApiClient::with_identity_url(&self.server_url, self.identity_url.as_deref());
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
                    ..Default::default()
                };
            }
        };

        if !self.keyring_mgr.is_available() {
            let err_msg = "System keyring is not available. Keyring is required to securely store authentication tokens.";
            crate::log_error!("omawarden:auth", "{}", err_msg);
            return AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some(err_msg.to_string()),
                ..Default::default()
            };
        }
        let connection = match LoginConnection::begin(login_context.as_deref()) {
            Ok(connection) => connection,
            Err(error) => {
                return AuthResult {
                    error: Some(error),
                    ..Default::default()
                }
            }
        };
        let initial_sync = match client.sync_vault(&token_resp.access_token) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return AuthResult {
                    ok: false,
                    error: Some("Initial vault synchronization failed. Check the connection and sign in again.".into()),
                    ..Default::default()
                };
            }
        };
        let mut storage = VaultStorage {
            server_url: self.server_url.clone(),
            identity_url: self.identity_url.clone(),
            client_id: Some(client_id.trim().to_string()),
            enc_user_key: token_resp.key,
            enc_private_key: token_resp.private_key,
            kdf: token_resp.kdf,
            kdf_iterations: token_resp.kdf_iterations,
            kdf_memory: token_resp.kdf_memory,
            kdf_parallelism: token_resp.kdf_parallelism,
            ..Default::default()
        };

        // Install only a complete snapshot belonging to these credentials.
        let sync_data = initial_sync;
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

        if storage.user_email.is_empty() {
            storage.user_email = client_id.trim().to_string();
        }

        if let Err(error) = self.publish_login(
            connection,
            &mut storage,
            &token_resp.access_token,
            token_resp.refresh_token.as_deref(),
            Some(client_secret.trim()),
        ) {
            return AuthResult {
                ok: false,
                error: Some(error),
                ..Default::default()
            };
        }

        if let Some(ref cm) = self.config_mgr {
            let mut cfg = cm.load();
            if cfg.remember_email && cfg.email.is_empty() && !storage.user_email.is_empty() {
                cfg.email = storage.user_email.clone();
                let _ = cm.save(&cfg);
            }
        }

        crate::log_info!("omawarden:auth", "API key authentication successful.");

        AuthResult {
            ok: true,
            status: Some("locked".to_string()),
            session: Some(token_resp.access_token),
            ..Default::default()
        }
    }

    pub fn unlock(&self, password: &str) -> AuthResult {
        crate::log_info!("omawarden:auth", "Unlocking vault with master password...");
        if let Err(e @ crate::daemon::DispatchError::IncompatibleProtocol { .. }) =
            crate::daemon::ensure_daemon_running()
        {
            return AuthResult {
                error: Some(e.to_string()),
                ..Default::default()
            };
        }
        let storage = self.storage_mgr.load();
        let unlock_credentials = if storage.enc_user_key.is_some() {
            storage.check_unlock_credentials()
        } else {
            Err("Account is not logged in.")
        };
        if let Err(error) = unlock_credentials {
            return AuthResult {
                status: Some("unauthenticated".into()),
                error: Some(error.into()),
                ..Default::default()
            };
        }

        let reply = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "unlock", "password": password
        }));
        if reply.as_ref().is_some_and(|reply| reply["ok"] == true) {
            return AuthResult {
                ok: true,
                status: Some("unlocked".into()),
                ..Default::default()
            };
        }
        let error = reply
            .as_ref()
            .and_then(|reply| reply["error"].as_str())
            .map(|error| sanitize_auth_error(Some(error)))
            .unwrap_or_else(|| "Could not confirm unlock with the vault daemon.".into());
        crate::log_warn!("omawarden:auth", "Unlock failed: {}", error);
        AuthResult {
            status: Some("locked".into()),
            error: Some(error),
            ..Default::default()
        }
    }

    pub fn lock(&self) -> AuthResult {
        let storage = self.storage_mgr.load();
        let reply = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "lock"
        }));
        self.keyring_mgr
            .for_storage(&storage)
            .clear_token(KIND_ACCESS_TOKEN);
        if !reply.is_some_and(|reply| reply["outputs_cleared"] == true) {
            if let Err(error) = crate::clipboard::revoke_session_outputs() {
                crate::log_warn!(
                    "omawarden:auth",
                    "Session output cleanup is pending. {error}"
                );
            }
        }
        crate::log_info!("omawarden:auth", "Vault locked.");
        AuthResult {
            ok: true,
            status: Some("locked".to_string()),
            session: None,
            ..Default::default()
        }
    }

    pub fn logout(&self) -> AuthResult {
        let cleared = (|| {
            let _account = self.storage_mgr.account_guard()?;
            // Unlock and offline output publication need this same account
            // guard. Revoke A before they can see the signed-out cache.
            let locked =
                crate::daemon::send_daemon_request(&serde_json::json!({ "action": "lock" }));
            // The explicit wipe also covers a daemon with a separate quick-unlock handler.
            let _ = crate::daemon::send_daemon_request(
                &serde_json::json!({ "action": "wipe_quick_unlock" }),
            );
            let current = self.storage_mgr.cache_snapshot()?;
            self.storage_mgr
                .remember_credentials(&current.storage, true)?;
            self.storage_mgr
                .stage_durable(&VaultStorage::default())?
                .persist(&self.storage_mgr.file_path)
                .map_err(|error| error.error)?;
            let outputs = if locked.is_some_and(|reply| reply["outputs_cleared"] == true) {
                Ok(())
            } else {
                crate::clipboard::revoke_session_outputs()
            };
            Ok::<_, std::io::Error>((outputs, self.storage_mgr.retired_credentials(None)))
        })();
        let (outputs, retired) = match cleared {
            Ok(retired) => retired,
            Err(error) => {
                return AuthResult {
                    error: Some(format!("Could not complete logout. {error}")),
                    ..Default::default()
                }
            }
        };
        let credentials = retired.and_then(|slots| erase_retired(slots, &self.keyring_mgr));
        let pending = match (outputs, credentials) {
            (Err(output), Err(keyring)) => Some(format!(
                "Output cleanup failed. {output} Keyring cleanup failed. {keyring}"
            )),
            (Err(error), Ok(())) => Some(format!("Output cleanup is pending. {error}")),
            (Ok(()), Err(error)) => Some(format!("Keyring cleanup is pending. {error}")),
            (Ok(()), Ok(())) => None,
        };
        if let Some(pending) = pending {
            let message = format!("Signed out locally. {pending} Retry logout.");
            crate::log_warn!("omawarden:auth", "{}", message);
            return AuthResult {
                status: Some("unauthenticated".into()),
                error: Some(message),
                ..Default::default()
            };
        }
        crate::log_info!("omawarden:auth", "Account logged out.");
        AuthResult {
            ok: true,
            status: Some("unauthenticated".to_string()),
            session: None,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    fn create_test_mock_keyring(dir: &std::path::Path) -> KeyringManager {
        let script_path = dir.join("mock-secret-tool");
        crate::write_test_executable(
            &script_path,
            "#!/bin/sh\nif [ \"$1\" = store ]; then /bin/cat >/dev/null; fi\n",
        );
        KeyringManager::new(script_path.to_str().unwrap())
    }

    fn fixture_access_keyring(dir: &std::path::Path, token: &str) -> KeyringManager {
        let saved = dir.join("access");
        fs::write(&saved, token).unwrap();
        let script = dir.join("secret-tool");
        crate::write_test_executable(
            &script,
            format!(
                "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) /bin/cat '{}' 2>/dev/null;;\nclear*'kind access_token'*) /bin/rm '{}' ;;\n*) exit 1;;\nesac\n",
                saved.display(),
                saved.display(),
            ),
        );
        KeyringManager::new(script.to_str().unwrap())
    }

    #[test]
    fn legacy_credentials_require_sign_in_without_reading_or_migrating_tokens() {
        let dir = tempdir().unwrap();
        let storage = StorageManager::new(dir.path().join("data.json"));
        let trace = dir.path().join("keyring-called");
        let script = dir.path().join("secret-tool");
        crate::write_test_executable(
            &script,
            format!(
                "#!/bin/sh\n: > '{}'\necho another-account-token\n",
                trace.display()
            ),
        );
        let auth = AuthManager::new(
            "https://fixture.invalid",
            Some(storage.clone()),
            Some(KeyringManager::new(script.to_str().unwrap())),
        );
        for (inline, credential_id) in [
            (None, None),
            (Some("another-account-token"), None),
            (None, Some("malformed")),
        ] {
            let before = serde_json::json!({
                "server_url":"https://fixture.invalid", "user_email":"fixture@example.invalid",
                "access_token":inline, "refresh_token":inline,
                "credential_id":credential_id,
                "enc_user_key":"2.dummy_iv|dummy_ct|dummy_mac",
                "ciphers":[{"id":"existing"}]
            })
            .to_string();
            fs::write(&storage.file_path, &before).unwrap();
            let status = auth.get_status(false);
            assert_eq!(status.status, "unauthenticated");
            assert!(!status.has_session);
            assert!(!trace.exists());
            assert_eq!(fs::read_to_string(&storage.file_path).unwrap(), before);
        }
    }

    #[test]
    fn logout_retains_cleanup_records_through_sync_and_keyring_failures() {
        let _environment = crate::env_lock();
        let dir = tempdir().unwrap();
        let storage_mgr = StorageManager::new(dir.path().join("data.json"));
        let server = "https://fixture.invalid";
        storage_mgr
            .save(&VaultStorage {
                server_url: server.into(),
                user_email: "fixture@example.invalid".into(),
                credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
                ..Default::default()
            })
            .unwrap();
        let scoped = dir.path().join("scoped");
        let legacy = dir.path().join("legacy");
        let trace = dir.path().join("keyring-called");
        let locked = dir.path().join("keyring-locked");
        for path in [&scoped, &legacy, &locked] {
            fs::write(path, []).unwrap();
        }
        let script = dir.path().join("secret-tool");
        crate::write_test_executable(
            &script,
            format!(
                r#"#!/bin/sh
command=$1
shift
if [ "$1" = --all ]; then shift; fi
: > '{}'
case "$2" in
    omarchy-bitwarden-v2) record='{}';;
    omarchy-bitwarden) record='{}';;
    *) exit 1;;
esac
case "$command" in
    clear)
        if [ -e '{}' ]; then exit 1; fi
        /bin/rm "$record"
        ;;
    search)
        if [ -e "$record" ]; then echo present; fi
        ;;
    *) exit 1;;
esac
"#,
                trace.display(),
                scoped.display(),
                legacy.display(),
                locked.display(),
            ),
        );
        let keyring = KeyringManager::new(script.to_str().unwrap());
        let mut failed_sync = storage_mgr.clone();
        failed_sync.fail_credential_cleanup_sync = true;
        let auth = AuthManager::new(server, Some(failed_sync), Some(keyring.clone()));
        let result = auth.logout();
        assert!(!result.ok);
        assert_eq!(result.status.as_deref(), Some("unauthenticated"));
        assert!(result.error.unwrap().contains("directory sync failure"));
        assert!(storage_mgr.load().credential_id.is_none());
        assert!(!trace.exists());
        assert!(scoped.exists() && legacy.exists());

        let auth = AuthManager::new(server, Some(storage_mgr), Some(keyring));
        let result = auth.logout();
        assert!(!result.ok);
        assert!(result.error.unwrap().contains("Keyring cleanup is pending"));
        assert!(trace.exists());
        assert!(scoped.exists() && legacy.exists());

        fs::remove_file(locked).unwrap();
        assert!(auth.logout().ok);
        assert!(!scoped.exists() && !legacy.exists());
    }

    #[test]
    fn expired_session_cleanup_preserves_the_latest_cipher_snapshot() {
        let dir = tempdir().unwrap();
        let manager = StorageManager::new(dir.path().join("data.json"));
        let initial = serde_json::json!({
            "server_url":"https://fixture.invalid", "user_email":"fixture@example.invalid",
            "access_token":"legacy", "ciphers":[], "credential_id":crate::test_support::CREDENTIAL_ID
        });
        fs::write(&manager.file_path, initial.to_string()).unwrap();
        let expected = manager.load();
        let mut latest = initial;
        latest["ciphers"] = serde_json::json!([{"id":"created"}]);
        fs::write(&manager.file_path, latest.to_string()).unwrap();
        let auth = AuthManager::new(
            "https://fixture.invalid",
            Some(manager.clone()),
            Some(fixture_access_keyring(dir.path(), "legacy")),
        );
        assert!(auth.invalidate_expired_session(&expected, "legacy"));
        assert_eq!(manager.load().ciphers[0]["id"], "created");
        assert!(manager.load().access_token.is_none());
    }

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
            sanitize_auth_error(Some("Network error: dns lookup failed")),
            "Network error: unable to reach Bitwarden server."
        );
        assert_eq!(
            sanitize_auth_error(Some("HTTP error 404: Not Found")),
            "Bitwarden server endpoint not found (HTTP 404). Please verify your server URL."
        );
        assert_eq!(
            sanitize_auth_error(Some("Prelogin returned HTTP 404 Not Found")),
            "Bitwarden server endpoint not found (HTTP 404). Please verify your server URL."
        );
        assert_eq!(
            sanitize_auth_error(Some("HTTP error 500: Internal Server Error")),
            "Bitwarden server encountered an internal error (HTTP 500)."
        );
        assert_eq!(
            sanitize_auth_error(Some("HTTP error 502: Bad Gateway")),
            "Bitwarden server is unavailable (HTTP 502 Bad Gateway)."
        );
        assert_eq!(
            sanitize_auth_error(Some("HTTP error 503: Service Unavailable")),
            "Bitwarden server is temporarily unavailable (HTTP 503)."
        );
        assert_eq!(
            sanitize_auth_error(Some("Connection timed out")),
            "Network error: unable to reach Bitwarden server."
        );
        assert_eq!(
            sanitize_auth_error(Some("operation timed out")),
            "Network error: unable to reach Bitwarden server."
        );
        assert_eq!(
            sanitize_auth_error(Some("Invalid username or password (kdf 500000 iterations)")),
            "Invalid username, email, or master password."
        );
        assert_eq!(
            sanitize_auth_error(Some("Username not found")),
            "Invalid username, email, or master password."
        );
        assert_eq!(
            sanitize_auth_error(Some("Two factor required.")),
            "Two-factor authentication required or invalid code."
        );
        assert_eq!(
            sanitize_auth_error(Some("2FA code invalid")),
            "Two-factor authentication required or invalid code."
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

        let mock_keyring = create_test_mock_keyring(dir.path());
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
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
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
        let _environment = crate::env_lock();
        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_apikey_data.json");
        let storage_mgr = StorageManager::new(storage_path);

        let script_path = dir.path().join("mock-secret-tool");
        crate::write_test_executable(&script_path, "#!/bin/sh\nexit 0\n");
        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());

        let auth_mgr = AuthManager::new(
            "http://127.0.0.1:9", // Invalid dead port to verify network error handling
            Some(storage_mgr),
            Some(mock_keyring),
        );

        let res = auth_mgr.login_apikey("user.client-id-123", "secret-xyz");
        assert!(!res.ok);
        assert_eq!(res.status.as_deref(), Some("unauthenticated"));
        assert_eq!(
            res.error.as_deref(),
            Some("Network error: unable to reach Bitwarden server.")
        );
    }

    #[test]
    fn test_login_password_endpoint_404_error() {
        let _environment = crate::env_lock();
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
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes());
                count += 1;
                if count >= 2 {
                    break;
                }
            }
        });

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_404_data.json");
        let storage_mgr = StorageManager::new(storage_path);
        let mock_keyring = create_test_mock_keyring(dir.path());
        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr), Some(mock_keyring));
        let res = auth_mgr.login_password("test@example.com", "password123", None, None, None);
        assert!(!res.ok);
        assert_eq!(
            res.error.as_deref(),
            Some("Bitwarden server endpoint not found (HTTP 404). Please verify your server URL.")
        );
        let _ = handle.join();
    }

    #[test]
    fn test_login_password_two_factor_required() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":600000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = r#"{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0"]}"#;
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_2fa_data.json");
        let storage_mgr = StorageManager::new(storage_path);
        let mock_keyring = create_test_mock_keyring(dir.path());

        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr), Some(mock_keyring));
        let res = auth_mgr.login_password("user@example.com", "password123", None, None, None);
        assert!(!res.ok);
        assert_eq!(res.status.as_deref(), Some("unauthenticated"));
        assert_eq!(res.two_factor_required, Some(true));
        assert_eq!(res.two_factor_providers, Some(vec![0]));
        assert_eq!(res.two_factor_provider, Some(0));
        assert_eq!(
            res.error.as_deref(),
            Some("Two-factor authentication required or invalid code.")
        );
        let _ = handle.join();
    }

    #[test]
    fn test_login_password_webauthn_smart_default_provider_selection() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":600000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = r#"{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["1","7"],"TwoFactorProviders2":{"1":null,"7":{"challenge":"abc","rpId":"example.com","allowCredentials":[]}}}"#;
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_smart_2fa.json");
        let storage_mgr = StorageManager::new(storage_path);
        let mock_keyring = create_test_mock_keyring(dir.path());

        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr), Some(mock_keyring));
        let res = auth_mgr.login_password("user@example.com", "password123", None, None, None);
        assert!(!res.ok);
        assert_eq!(res.status.as_deref(), Some("unauthenticated"));
        assert_eq!(res.two_factor_required, Some(true));
        assert_eq!(res.two_factor_providers, Some(vec![1, 7]));
        assert!(res.fido2_status.is_some());
        // If FIDO2 device is available, default is 7; if no device or tool missing, smart default falls back to 1
        if res.fido2_status.as_deref() == Some("available") {
            assert_eq!(res.two_factor_provider, Some(7));
        } else {
            assert_eq!(res.two_factor_provider, Some(1));
        }
        let _ = handle.join();
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
        let storage_mgr = StorageManager::new(storage_path.clone());

        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 100 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);

        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(fixture_access_keyring(dir.path(), &expired_token)),
        );
        let legacy_json = serde_json::json!({
            "server_url":"https://vault.example.com",
            "credential_id":crate::test_support::CREDENTIAL_ID,
            "user_email": "expired-user@example.com",
            "user_id": "user-uuid-999",
            "access_token": expired_token,
            "refresh_token": null,
            "enc_user_key": "2.dummy_iv|dummy_ct|dummy_mac"
        });
        std::fs::write(
            &storage_path,
            serde_json::to_string_pretty(&legacy_json).unwrap(),
        )
        .unwrap();

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

        crate::write_test_executable(&script_path, script);

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

        let storage = VaultStorage {
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
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
        let keys = mock_keyring.for_storage(&storage);
        assert!(keys.store_token(KIND_API_SECRET, "secret_xyz_123"));
        assert!(keys.store_token(KIND_ACCESS_TOKEN, &expired_token));

        let st = auth_mgr.get_status(false);
        // Because client_secret exists in keyring, has_session remains true
        assert!(st.has_session);
        assert_eq!(st.status, "locked");
    }

    #[test]
    fn test_auth_status_custom_server_url_precedence() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use std::fs;

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

        crate::write_test_executable(&script_path, script);

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        // Default CLI server_url is bitwarden.com
        let auth_mgr = AuthManager::new(
            "https://vault.bitwarden.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring.clone()),
        );

        let custom_url = "https://vaultwarden.custom.local";
        let client_id = "user.custom-client-123";

        let now = chrono::Utc::now().timestamp();
        let past_payload = serde_json::json!({ "exp": now - 50 });
        let past_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&past_payload).unwrap());
        let expired_token = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", past_b64);

        let storage = VaultStorage {
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
            server_url: custom_url.to_string(),
            user_email: "custom@local.org".to_string(),
            client_id: Some(client_id.to_string()),
            enc_user_key: Some("2.dummy_iv|dummy_ct|dummy_mac".to_string()),
            ..Default::default()
        };
        storage_mgr.save(&storage).unwrap();
        let keys = mock_keyring.for_storage(&storage);
        assert!(keys.store_token(KIND_API_SECRET, "top_secret"));
        assert!(keys.store_token(KIND_ACCESS_TOKEN, &expired_token));

        // get_status should prioritize storage.server_url over default self.server_url and find the secret
        let st = auth_mgr.get_status(false);
        assert!(st.has_session);
        assert_eq!(st.status, "locked");
    }

    #[test]
    fn test_auth_manager_identity_url_isolation_and_clearing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("storage_isolation.json");
        let storage_mgr = StorageManager::new(path);

        // Pre-save storage for custom server with an identity URL
        let initial_storage = VaultStorage {
            server_url: "https://vaultwarden.custom.local".to_string(),
            identity_url: Some("https://id.custom.local".to_string()),
            user_email: "user@custom.local".to_string(),
            ..Default::default()
        };
        storage_mgr.save(&initial_storage).unwrap();

        // 1. When switching to a new server, old storage identity_url must NOT be inherited
        let auth_mgr_cloud = AuthManager::with_identity_url(
            "https://vault.bitwarden.com",
            None,
            Some(storage_mgr.clone()),
            None,
        );
        assert_eq!(auth_mgr_cloud.identity_url, None);

        // 2. When same server URL is used, storage identity_url is inherited
        let auth_mgr_same = AuthManager::with_identity_url(
            "https://vaultwarden.custom.local",
            None,
            Some(storage_mgr.clone()),
            None,
        );
        assert_eq!(
            auth_mgr_same.identity_url,
            Some("https://id.custom.local".to_string())
        );

        // 3. When empty string is explicitly provided, identity_url is cleared (None)
        let auth_mgr_cleared = AuthManager::with_identity_url(
            "https://vaultwarden.custom.local",
            Some(""),
            Some(storage_mgr.clone()),
            None,
        );
        assert_eq!(auth_mgr_cleared.identity_url, None);

        // 4. When explicit non-empty identity URL is provided, it is used
        let auth_mgr_override = AuthManager::with_identity_url(
            "https://vaultwarden.custom.local",
            Some("https://new-id.custom.local"),
            Some(storage_mgr.clone()),
            None,
        );
        assert_eq!(
            auth_mgr_override.identity_url,
            Some("https://new-id.custom.local".to_string())
        );
    }

    #[test]
    fn test_login_password_persists_email_to_config_based_on_remember_email() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        use aes::Aes256;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::BlockEncryptMut;
        use cbc::cipher::KeyIvInit;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        use crate::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};

        let email = "user@example.com";
        let password = "password123";
        let master_key =
            derive_master_key(email, password, KdfType::Pbkdf2Sha256, 5000, None, None).unwrap();
        let sym_key = SymmetricCryptoKey::from_master_key(&master_key);

        let iv = [1u8; 16];
        let plaintext = [2u8; 64];
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&sym_key.enc_key, &iv).unwrap();
        let mut buf = vec![0u8; 128];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let mut hmac = Hmac::<Sha256>::new_from_slice(sym_key.mac_key.as_ref().unwrap()).unwrap();
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        let enc_user_key = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let key_clone = enc_user_key.clone();
        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":5000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = format!(
                        r#"{{"access_token":"mock_token_abc","token_type":"Bearer","Key":"{}"}}"#,
                        key_clone
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /api/sync") {
                    let body = r#"{"profile":{"id":"user-1","email":"user@example.com"},"ciphers":[],"folders":[],"collections":[]}"#;
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

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_data.json");
        let storage_mgr = StorageManager::new(storage_path);
        let config_path = dir.path().join("config.json");
        let config_mgr = ConfigManager::new(Some(&config_path));

        // Initial state: remember_email is true, but email is empty in config.json
        let mut cfg = config_mgr.load();
        cfg.remember_email = true;
        cfg.email = String::new();
        config_mgr.save(&cfg).unwrap();

        let mock_keyring = create_test_mock_keyring(dir.path());
        let auth_mgr = AuthManager::with_config(
            &server_url,
            None,
            Some(storage_mgr),
            Some(mock_keyring.clone()),
            Some(config_mgr.clone()),
        );

        let daemon = crate::test_support::TestDaemon::for_auth(&auth_mgr);
        let res = auth_mgr.login_password("User@Example.COM", password, None, None, None);
        assert!(res.ok, "Login should succeed: {:?}", res.error);
        drop(daemon);

        // Verify config.json email was populated with normalized email
        let updated_cfg = config_mgr.load();
        assert_eq!(
            updated_cfg.email, "user@example.com",
            "Config email must be saved on successful login when remember_email is true"
        );
        assert!(updated_cfg.remember_email);

        let _ = handle.join();

        // 2. When remember_email is false, email is not saved into config.json
        let mut cfg_no_remember = config_mgr.load();
        cfg_no_remember.remember_email = false;
        cfg_no_remember.email = String::new();
        config_mgr.save(&cfg_no_remember).unwrap();

        let email2 = "other@example.com";
        let master_key2 =
            derive_master_key(email2, password, KdfType::Pbkdf2Sha256, 5000, None, None).unwrap();
        let sym_key2 = SymmetricCryptoKey::from_master_key(&master_key2);
        let enc2 = Aes256CbcEnc::new_from_slices(&sym_key2.enc_key, &iv).unwrap();
        let mut buf2 = vec![0u8; 128];
        let ct_len2 = enc2
            .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf2)
            .unwrap()
            .len();
        let ct2 = &buf2[..ct_len2];

        let mut hmac2 = Hmac::<Sha256>::new_from_slice(sym_key2.mac_key.as_ref().unwrap()).unwrap();
        hmac2.update(&iv);
        hmac2.update(ct2);
        let mac2 = hmac2.finalize().into_bytes();

        let key_clone2 = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct2),
            BASE64.encode(mac2)
        );

        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let port2 = listener2.local_addr().unwrap().port();
        let server_url2 = format!("http://127.0.0.1:{}", port2);

        let handle2 = thread::spawn(move || {
            for mut stream in listener2.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":5000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = format!(
                        r#"{{"access_token":"mock_token_abc","token_type":"Bearer","Key":"{}"}}"#,
                        key_clone2
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /api/sync") {
                    let body = r#"{"profile":{"id":"user-1","email":"user@example.com"},"ciphers":[],"folders":[],"collections":[]}"#;
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

        let storage_path2 = dir.path().join("test_data2.json");
        let storage_mgr2 = StorageManager::new(storage_path2);
        let auth_mgr2 = AuthManager::with_config(
            &server_url2,
            None,
            Some(storage_mgr2),
            Some(mock_keyring),
            Some(config_mgr.clone()),
        );

        let _daemon = crate::test_support::TestDaemon::for_auth(&auth_mgr2);
        let res2 = auth_mgr2.login_password("other@example.com", password, None, None, None);
        assert!(res2.ok, "Login should succeed: {:?}", res2.error);

        let updated_cfg2 = config_mgr.load();
        assert_eq!(
            updated_cfg2.email, "",
            "Config email must remain empty when remember_email is false"
        );
        assert!(!updated_cfg2.remember_email);

        let _ = handle2.join();
    }

    #[test]
    fn test_login_keyring_unavailable_fails_closed() {
        let _environment = crate::env_lock();
        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("data_unavailable.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        // Keyring pointing to non-existent tool
        let mock_keyring = KeyringManager::new("/non/existent/secret-tool-binary");
        assert!(!mock_keyring.is_available());

        let auth_mgr = AuthManager::new(
            "https://vault.example.com",
            Some(storage_mgr.clone()),
            Some(mock_keyring),
        );

        // Password login must fail closed
        let res_pwd = auth_mgr.login_password("test@example.com", "password", None, None, None);
        assert!(!res_pwd.ok);
        assert!(
            res_pwd
                .error
                .as_deref()
                .unwrap()
                .contains("Keyring is required"),
            "Error should mention keyring requirement: {:?}",
            res_pwd.error
        );
        assert!(storage_mgr.load().access_token.is_none());

        // API login must fail closed
        let res_api = auth_mgr.login_apikey("client.id", "client_secret");
        assert!(!res_api.ok);
        assert!(
            res_api
                .error
                .as_deref()
                .unwrap()
                .contains("Keyring is required"),
            "Error should mention keyring requirement: {:?}",
            res_api.error
        );
        assert!(storage_mgr.load().access_token.is_none());
    }

    #[test]
    fn test_login_password_keyring_store_failure_fails_closed() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("data_fail_pwd.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        // Executable script that always fails
        let script_path = dir.path().join("mock-secret-tool-fail");
        crate::write_test_executable(&script_path, "#!/bin/sh\nexit 1\n");

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        assert!(mock_keyring.is_available());

        use crate::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use base64::Engine;
        use cbc::Encryptor;
        use hmac::Mac;
        use sha2::Sha256;
        type Aes256CbcEnc = Encryptor<aes::Aes256>;

        let email = "test@example.com";
        let password = "password";
        let master_key =
            derive_master_key(email, password, KdfType::Pbkdf2Sha256, 5000, None, None).unwrap();
        let sym_key = SymmetricCryptoKey::from_master_key(&master_key);
        let iv = [1u8; 16];
        let enc = Aes256CbcEnc::new_from_slices(&sym_key.enc_key, &iv).unwrap();
        let mut buf = vec![0u8; 128];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                &mut buf,
            )
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let mut hmac =
            hmac::Hmac::<Sha256>::new_from_slice(sym_key.mac_key.as_ref().unwrap()).unwrap();
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        let valid_key = format!(
            "2.{}|{}|{}",
            crate::crypto::BASE64.encode(iv),
            crate::crypto::BASE64.encode(ct),
            crate::crypto::BASE64.encode(mac)
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":5000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = format!(
                        r#"{{"access_token":"synthetic_bearer_token_123","refresh_token":"synthetic_refresh_token_456","token_type":"Bearer","Key":"{}"}}"#,
                        valid_key
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /api/sync") {
                    let body = r#"{"ciphers":[],"folders":[],"collections":[]}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr.clone()), Some(mock_keyring));

        let _daemon = crate::test_support::TestDaemon::for_auth(&auth_mgr);
        let res = auth_mgr.login_password("test@example.com", "password", None, None, None);
        assert!(!res.ok, "Login must fail when keyring store fails");
        assert!(
            res.error
                .as_deref()
                .unwrap()
                .contains("Failed to store access token in system keyring"),
            "Expected keyring error, got: {:?}",
            res.error
        );

        // Ensure tokens never entered storage
        let storage = storage_mgr.load();
        assert!(storage.access_token.is_none());
        assert!(storage.refresh_token.is_none());

        // Ensure raw JSON on disk does not contain synthetic tokens
        if storage_path.exists() {
            let raw = fs::read_to_string(&storage_path).unwrap();
            assert!(!raw.contains("synthetic_bearer_token_123"));
            assert!(!raw.contains("synthetic_refresh_token_456"));
        }

        let _ = handle.join();
    }

    #[test]
    fn test_login_apikey_keyring_store_failure_fails_closed() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;

        use std::thread;

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("data_fail_api.json");
        let storage_mgr = StorageManager::new(storage_path.clone());

        // Executable script that always fails
        let script_path = dir.path().join("mock-secret-tool-fail");
        crate::write_test_executable(&script_path, "#!/bin/sh\nexit 1\n");

        let mock_keyring = KeyringManager::new(script_path.to_str().unwrap());
        assert!(mock_keyring.is_available());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/connect/token") {
                    let body = r#"{"access_token":"synthetic_api_token_789","token_type":"Bearer","Key":"2.dummy_iv|dummy_ct|dummy_mac"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /api/sync") {
                    let body = r#"{"ciphers":[],"folders":[],"collections":[]}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr.clone()), Some(mock_keyring));

        let _daemon = crate::test_support::TestDaemon::for_auth(&auth_mgr);
        let res = auth_mgr.login_apikey("client.id", "client_secret");
        assert!(!res.ok, "API login must fail when keyring store fails");
        assert!(
            res.error
                .as_deref()
                .unwrap()
                .contains("Failed to store access token in system keyring"),
            "Expected keyring error, got: {:?}",
            res.error
        );

        // Ensure tokens never entered storage
        let storage = storage_mgr.load();
        assert!(storage.access_token.is_none());
        assert!(storage.refresh_token.is_none());

        if storage_path.exists() {
            let raw = fs::read_to_string(&storage_path).unwrap();
            assert!(!raw.contains("synthetic_api_token_789"));
        }

        let _ = handle.join();
    }

    #[test]
    fn test_login_password_auto_unlocks_daemon() {
        let _lock = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        use aes::Aes256;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::BlockEncryptMut;
        use cbc::cipher::KeyIvInit;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        use crate::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};

        let email = "daemon_test@example.com";
        let password = "password123";
        let master_key =
            derive_master_key(email, password, KdfType::Pbkdf2Sha256, 5000, None, None).unwrap();
        let sym_key = SymmetricCryptoKey::from_master_key(&master_key);

        let iv = [3u8; 16];
        let plaintext = [4u8; 64];
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&sym_key.enc_key, &iv).unwrap();
        let mut buf = vec![0u8; 128];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(&plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let mut hmac = Hmac::<Sha256>::new_from_slice(sym_key.mac_key.as_ref().unwrap()).unwrap();
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        let enc_user_key = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );

        let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", http_port);

        let key_clone = enc_user_key.clone();
        let http_handle = thread::spawn(move || {
            for mut stream in http_listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":5000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = format!(
                        r#"{{"access_token":"remote_jwt_access_token_123","token_type":"Bearer","Key":"{}"}}"#,
                        key_clone
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("GET /api/sync") {
                    let body = r#"{"profile":{"id":"user-99","email":"daemon_test@example.com"},"ciphers":[],"folders":[],"collections":[]}"#;
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

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("daemon_test_data.json");
        let storage_mgr = StorageManager::new(storage_path);
        let config_path = dir.path().join("config.json");
        let config_mgr = ConfigManager::new(Some(&config_path));
        let mock_keyring = create_test_mock_keyring(dir.path());

        let auth_mgr = AuthManager::with_config(
            &server_url,
            None,
            Some(storage_mgr),
            Some(mock_keyring),
            Some(config_mgr),
        );

        let daemon = crate::test_support::TestDaemon::for_auth(&auth_mgr);
        let res = auth_mgr.login_password(email, password, None, None, None);
        assert!(res.ok, "Login should succeed: {:?}", res.error);
        assert_eq!(res.status.as_deref(), Some("unlocked"));
        assert!(daemon.state.vault_mgr.is_unlocked());
        assert!(daemon.state.vault_mgr.get_user_key().is_some());
        http_handle.join().unwrap();
    }

    #[test]
    fn test_login_password_new_device_verification_flow() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":5000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = r#"{"error":"device_error","error_description":"New device verification required"}"#;
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_ndv_data.json");
        let storage_mgr = StorageManager::new(storage_path);
        let mock_keyring = create_test_mock_keyring(dir.path());

        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr), Some(mock_keyring));
        let res = auth_mgr.login_password("user@example.com", "password123", None, None, None);
        assert!(!res.ok);
        assert_eq!(res.status.as_deref(), Some("unauthenticated"));
        assert_eq!(res.two_factor_required, Some(true));
        assert_eq!(res.new_device_verification_required, Some(true));
        assert!(
            res.error
                .as_deref()
                .unwrap()
                .contains("New device verification required"),
            "Error should mention new device verification: {:?}",
            res.error
        );

        let _ = handle.join();
    }

    #[test]
    fn test_login_password_email_two_factor_flow() {
        let _environment = crate::env_lock();
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{}", port);

        let handle = thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /identity/accounts/prelogin")
                    || req.contains("POST /api/accounts/prelogin")
                {
                    let body = r#"{"kdf":0,"kdfIterations":5000}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                } else if req.contains("POST /identity/connect/token") {
                    let body = r#"{"error":"invalid_grant","TwoFactorProviders":[1],"TwoFactorProviders2":{"1":null}}"#;
                    let resp = format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    break;
                }
            }
        });

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("test_email_2fa_data.json");
        let storage_mgr = StorageManager::new(storage_path);
        let mock_keyring = create_test_mock_keyring(dir.path());

        let auth_mgr = AuthManager::new(&server_url, Some(storage_mgr), Some(mock_keyring));
        let res = auth_mgr.login_password("user@example.com", "password123", None, None, None);
        assert!(!res.ok);
        assert_eq!(res.status.as_deref(), Some("unauthenticated"));
        assert_eq!(res.two_factor_required, Some(true));
        assert_eq!(res.two_factor_providers, Some(vec![1]));
        assert_eq!(res.two_factor_provider, Some(1));
        assert_eq!(
            res.error.as_deref(),
            Some("Email two-factor authentication required. Please check your email for the verification code.")
        );

        let _ = handle.join();
    }
}
