pub mod macos;
pub mod mock;
pub mod provider;
pub mod secret_tool;

pub use macos::MacOsKeychainProvider;
pub use mock::MockKeyringProvider;
pub use provider::{resolve_provider, KeyringProvider, UnavailableKeyringProvider};
pub use secret_tool::SecretToolKeyringProvider;

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::credential_slots::CredentialSlot;
use crate::storage::VaultStorage;

pub const SERVICE_NAME: &str = "omarchy-bitwarden";
pub(crate) const SCOPED_SERVICE_NAME: &str = "omarchy-bitwarden-v2";
pub const ACCOUNT_NAME: &str = "session";
pub const LABEL: &str = "Omarchy Bitwarden Session";
pub const KIND_ACCESS_TOKEN: &str = "access_token";
pub const KIND_REFRESH_TOKEN: &str = "refresh_token";
pub const KIND_API_SECRET: &str = "api_secret";

pub fn normalize_server_url(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

#[derive(Clone)]
pub struct KeyringManager {
    provider: Arc<dyn KeyringProvider>,
}

impl Default for KeyringManager {
    fn default() -> Self {
        Self::with_provider(resolve_provider(None, None))
    }
}

impl std::fmt::Debug for KeyringManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyringManager")
            .field("provider", &self.provider.name())
            .field("is_available", &self.provider.is_available())
            .finish()
    }
}

impl KeyringManager {
    /// Constructs a `KeyringManager` using a legacy `secret-tool` path string or provider name.
    pub fn new(path_or_provider: &str) -> Self {
        let path = Path::new(path_or_provider);
        if path.is_absolute()
            || path_or_provider.contains('/')
            || path_or_provider.contains("secret-tool")
        {
            Self::with_provider(Arc::new(SecretToolKeyringProvider::new(path_or_provider)))
        } else {
            Self::with_provider(resolve_provider(Some(path_or_provider), None))
        }
    }

    /// Constructs a `KeyringManager` with an explicit `KeyringProvider` implementation.
    pub fn with_provider(provider: Arc<dyn KeyringProvider>) -> Self {
        Self { provider }
    }

    /// Accesses the underlying active provider.
    pub fn provider(&self) -> &Arc<dyn KeyringProvider> {
        &self.provider
    }

    pub fn is_available(&self) -> bool {
        self.provider.is_available()
    }

    pub fn unavailable_reason(&self) -> Option<String> {
        self.provider.unavailable_reason()
    }

    fn store(
        &self,
        label: &str,
        attributes: &[&str],
        secret: &str,
        lease: Option<&CredentialSlot>,
    ) -> bool {
        if secret.is_empty() {
            return false;
        }
        self.provider.store(label, attributes, secret, lease)
    }

    fn lookup(&self, attributes: &[&str]) -> Option<String> {
        self.provider.lookup(attributes)
    }

    fn clear(&self, attributes: &[&str]) -> bool {
        self.provider.clear(attributes)
    }

    pub(crate) fn erase_credential_slot(
        &self,
        credential_id: Option<&str>,
        deadline: Instant,
    ) -> io::Result<()> {
        self.provider.erase_credential_slot(credential_id, deadline)
    }

    pub fn store_token(&self, server_url: &str, kind: &str, token: &str) -> bool {
        legacy_token_attributes(server_url, kind)
            .is_some_and(|attrs| self.store(credential_label(kind), &attrs, token, None))
    }

    pub fn get_token(&self, server_url: &str, kind: &str) -> Option<String> {
        self.lookup(&legacy_token_attributes(server_url, kind)?)
    }

    pub fn clear_token(&self, server_url: &str, kind: &str) -> bool {
        legacy_token_attributes(server_url, kind).is_some_and(|attrs| self.clear(&attrs))
    }

    pub fn store_api_secret(&self, server_url: &str, client_id: &str, secret: &str) -> bool {
        legacy_api_attributes(server_url, client_id).is_some_and(|attrs| {
            self.store(credential_label(KIND_API_SECRET), &attrs, secret, None)
        })
    }

    pub fn get_api_secret(&self, server_url: &str, client_id: &str) -> Option<String> {
        self.lookup(&legacy_api_attributes(server_url, client_id)?)
    }

    pub fn clear_api_secret(&self, server_url: &str, client_id: &str) -> bool {
        legacy_api_attributes(server_url, client_id).is_some_and(|attrs| self.clear(&attrs))
    }

    pub fn clear_all(&self) -> bool {
        self.clear(&["service", SERVICE_NAME])
    }

    pub fn store_session(&self, server_url: &str, session_token: &str) -> bool {
        let Some(attrs) = legacy_session_attributes(server_url) else {
            return false;
        };
        let _ = self.store_token(server_url, KIND_ACCESS_TOKEN, session_token);
        self.store(LABEL, &attrs, session_token, None)
    }

    pub fn get_session(&self, server_url: &str) -> Option<String> {
        self.get_token(server_url, KIND_ACCESS_TOKEN)
            .or_else(|| self.lookup(&legacy_session_attributes(server_url)?))
    }

    pub fn clear_session(&self, server_url: &str) -> bool {
        let Some(attrs) = legacy_session_attributes(server_url) else {
            return false;
        };
        let _ = self.clear_token(server_url, KIND_ACCESS_TOKEN);
        self.clear(&attrs)
    }

    pub(crate) fn for_storage<'a>(&'a self, storage: &'a VaultStorage) -> AccountKeyring<'a> {
        AccountKeyring {
            keyring: self,
            storage,
            lease: None,
        }
    }
}

fn credential_label(kind: &str) -> &'static str {
    match kind {
        KIND_REFRESH_TOKEN => "Omarchy Bitwarden Refresh Token",
        KIND_API_SECRET => "Omarchy Bitwarden API Secret",
        _ => "Omarchy Bitwarden Access Token",
    }
}

fn legacy_token_attributes<'a>(server: &'a str, kind: &'a str) -> Option<[&'a str; 6]> {
    let server = normalize_server_url(server);
    (!server.is_empty() && !kind.is_empty()).then_some([
        "service",
        SERVICE_NAME,
        "kind",
        kind,
        "server_url",
        server,
    ])
}

fn legacy_api_attributes<'a>(server: &'a str, client_id: &'a str) -> Option<[&'a str; 8]> {
    let server = normalize_server_url(server);
    let client_id = client_id.trim();
    (!server.is_empty() && !client_id.is_empty()).then_some([
        "service",
        SERVICE_NAME,
        "kind",
        KIND_API_SECRET,
        "server_url",
        server,
        "client_id",
        client_id,
    ])
}

fn legacy_session_attributes(server: &str) -> Option<[&str; 6]> {
    let server = normalize_server_url(server);
    (!server.is_empty()).then_some([
        "service",
        SERVICE_NAME,
        "account",
        ACCOUNT_NAME,
        "server_url",
        server,
    ])
}

pub(crate) struct AccountKeyring<'a> {
    keyring: &'a KeyringManager,
    storage: &'a VaultStorage,
    lease: Option<&'a CredentialSlot>,
}

impl<'a> AccountKeyring<'a> {
    pub(crate) fn with_lease(mut self, lease: &'a CredentialSlot) -> Self {
        self.lease = Some(lease);
        self
    }

    fn slot(&self) -> Option<[&str; 10]> {
        let id = self.storage.scoped_credential_id()?;
        let server = normalize_server_url(&self.storage.server_url);
        let account = self
            .storage
            .user_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(&self.storage.user_email);
        if server.is_empty() || account.is_empty() {
            return None;
        }
        Some([
            "service",
            SCOPED_SERVICE_NAME,
            "server_url",
            server,
            "account",
            account,
            "credential_id",
            id,
            "identity_url",
            self.storage.identity_url.as_deref().unwrap_or(""),
        ])
    }

    fn attributes<'b>(&'b self, kind: &'b str) -> Option<Vec<&'b str>> {
        let mut attributes = self.slot()?.to_vec();
        attributes.extend(["kind", kind]);
        if kind == KIND_API_SECRET {
            let client_id = self.storage.client_id.as_deref()?.trim();
            if client_id.is_empty() {
                return None;
            }
            attributes.extend(["client_id", client_id]);
        }
        Some(attributes)
    }

    pub(crate) fn access_token(&self) -> Option<String> {
        self.keyring.lookup(&self.attributes(KIND_ACCESS_TOKEN)?)
    }

    pub(crate) fn refresh_token(&self) -> Option<String> {
        self.keyring.lookup(&self.attributes(KIND_REFRESH_TOKEN)?)
    }

    pub(crate) fn api_secret(&self) -> Option<String> {
        self.keyring.lookup(&self.attributes(KIND_API_SECRET)?)
    }

    pub(crate) fn store_token(&self, kind: &str, token: &str) -> bool {
        self.attributes(kind).is_some_and(|attrs| {
            self.keyring
                .store(credential_label(kind), &attrs, token, self.lease)
        })
    }

    pub(crate) fn clear_token(&self, kind: &str) {
        if let Some(attrs) = self.attributes(kind) {
            self.keyring.clear(&attrs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    use tempfile::tempdir;

    #[test]
    fn test_mock_provider_unit_lifecycle() {
        let mock = Arc::new(MockKeyringProvider::new());
        let mgr = KeyringManager::with_provider(mock.clone());

        assert!(mgr.is_available());
        assert_eq!(mgr.provider().name(), "mock");
        assert!(mgr.unavailable_reason().is_none());

        let server_a = "https://server-a.example";
        let server_b = "https://server-b.example";

        assert!(mgr.store_token(server_a, KIND_ACCESS_TOKEN, "tok_a"));
        assert!(mgr.store_token(server_b, KIND_ACCESS_TOKEN, "tok_b"));
        assert_eq!(
            mgr.get_token(server_a, KIND_ACCESS_TOKEN),
            Some("tok_a".to_string())
        );
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("tok_b".to_string())
        );

        assert!(mgr.clear_token(server_a, KIND_ACCESS_TOKEN));
        assert_eq!(mgr.get_token(server_a, KIND_ACCESS_TOKEN), None);
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("tok_b".to_string())
        );

        assert!(mgr.clear_all());
        assert_eq!(mgr.get_token(server_b, KIND_ACCESS_TOKEN), None);
        assert!(mock.is_empty());
    }

    #[test]
    fn test_mock_provider_scoped_slot_and_erase() {
        let mock = Arc::new(MockKeyringProvider::new());
        let mgr = KeyringManager::with_provider(mock.clone());

        let storage_a = VaultStorage {
            server_url: "https://vault.example.com".into(),
            user_email: "alice@example.com".into(),
            user_id: Some("uid-alice".into()),
            credential_id: Some("11111111111111111111111111111111".into()),
            client_id: Some("user.alice".into()),
            ..Default::default()
        };
        let storage_b = VaultStorage {
            server_url: "https://vault.example.com".into(),
            user_email: "bob@example.com".into(),
            user_id: Some("uid-bob".into()),
            credential_id: Some("22222222222222222222222222222222".into()),
            ..Default::default()
        };

        let slot_a = mgr.for_storage(&storage_a);
        let slot_b = mgr.for_storage(&storage_b);

        assert!(slot_a.store_token(KIND_ACCESS_TOKEN, "access_a"));
        assert!(slot_a.store_token(KIND_REFRESH_TOKEN, "refresh_a"));
        assert!(slot_a.store_token(KIND_API_SECRET, "secret_a"));
        assert!(slot_b.store_token(KIND_ACCESS_TOKEN, "access_b"));

        assert_eq!(slot_a.access_token().as_deref(), Some("access_a"));
        assert_eq!(slot_a.refresh_token().as_deref(), Some("refresh_a"));
        assert_eq!(slot_a.api_secret().as_deref(), Some("secret_a"));
        assert_eq!(slot_b.access_token().as_deref(), Some("access_b"));

        // Erasing slot A must leave slot B intact.
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.erase_credential_slot(Some("11111111111111111111111111111111"), deadline)
            .unwrap();
        assert_eq!(slot_a.access_token(), None);
        assert_eq!(slot_a.refresh_token(), None);
        assert_eq!(slot_a.api_secret(), None);
        assert_eq!(slot_b.access_token().as_deref(), Some("access_b"));
    }

    #[test]
    fn test_mock_provider_unavailable_fails_closed() {
        let mock = Arc::new(MockKeyringProvider::new());
        mock.set_available(false);
        let mgr = KeyringManager::with_provider(mock);

        assert!(!mgr.is_available());
        assert!(mgr.unavailable_reason().is_some());
        assert!(!mgr.store_token("https://bw.local", KIND_ACCESS_TOKEN, "secret"));
        assert_eq!(mgr.get_token("https://bw.local", KIND_ACCESS_TOKEN), None);
        assert!(!mgr.clear_token("https://bw.local", KIND_ACCESS_TOKEN));
        assert!(mgr
            .erase_credential_slot(None, Instant::now() + Duration::from_secs(1))
            .is_err());
    }

    #[test]
    fn test_provider_resolution_precedence() {
        let mut env = crate::test_support::TestEnv::isolated();

        env.set_var("OMA_KEYRING_PROVIDER", "mock");
        let env_resolved = resolve_provider(None, None);
        assert_eq!(env_resolved.name(), "mock");
        assert!(env_resolved.is_available());

        // Explicit argument overrides environment variable.
        let explicit = resolve_provider(Some("secret-tool"), None);
        assert_eq!(explicit.name(), "secret-tool");

        env.remove_var("OMA_KEYRING_PROVIDER");

        // OMA_SECRET_TOOL_PATH selects SecretToolKeyringProvider when no provider name is set.
        env.set_var("OMA_SECRET_TOOL_PATH", "/custom/bin/secret-tool");
        let path_env_resolved = resolve_provider(None, None);
        assert_eq!(path_env_resolved.name(), "secret-tool");
        assert!(!path_env_resolved.is_available());
        env.remove_var("OMA_SECRET_TOOL_PATH");

        let unknown = resolve_provider(Some("nonexistent_keyring_provider"), None);
        assert_eq!(unknown.name(), "unavailable");
        assert!(!unknown.is_available());
        assert!(unknown.unavailable_reason().is_some());

        let macos = resolve_provider(Some("macos"), None);
        assert_eq!(macos.name(), "macos");
        let keychain_alias = resolve_provider(Some("keychain"), None);
        assert_eq!(keychain_alias.name(), "macos");

        // KeyringManager::new with provider name resolves through resolve_provider.
        let mgr_mock = KeyringManager::new("mock");
        assert_eq!(mgr_mock.provider().name(), "mock");
        assert!(mgr_mock.is_available());

        // KeyringManager::new with path constructs SecretToolKeyringProvider.
        let mgr_path = KeyringManager::new("/nonexistent/secret-tool");
        assert_eq!(mgr_path.provider().name(), "secret-tool");
        assert!(!mgr_path.is_available());
    }

    #[test]
    fn test_empty_token_store() {
        let mgr = KeyringManager::new("mock");
        assert!(!mgr.store_session("https://vault.bitwarden.com", ""));
        assert!(!mgr.store_session("", "some_token"));
    }

    #[test]
    fn cleanup_reaps_stalled_keyring_commands() {
        for action in ["clear", "search"] {
            let dir = tempdir().unwrap();
            let started = dir.path().join("started");
            let secret_tool = dir.path().join("secret-tool");
            crate::write_test_executable(
                &secret_tool,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = '{action}' ]; then echo $$ > '{}'; exec /bin/sleep 15; fi\n",
                    started.display()
                ),
            );
            let keyring = KeyringManager::new(secret_tool.to_str().unwrap());
            let deadline = Instant::now() + Duration::from_millis(750);
            let error = keyring
                .erase_credential_slot(Some(crate::test_support::CREDENTIAL_ID), deadline)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{action}");
            let pid = fs::read_to_string(&started).unwrap();
            assert!(
                !std::path::Path::new("/proc").join(pid.trim()).exists(),
                "{action} was not reaped"
            );
        }
    }

    #[test]
    fn test_mock_keyring_lifecycle() {
        let dir = tempdir().unwrap();
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

        let mgr = KeyringManager::new(script_path.to_str().unwrap());
        assert!(mgr.is_available());

        let server_url = "https://bw.local";

        // Initial lookup should be None
        assert_eq!(mgr.get_session(server_url), None);
        assert_eq!(mgr.get_token(server_url, "access_token"), None);
        assert_eq!(mgr.get_token(server_url, "refresh_token"), None);
        assert_eq!(mgr.get_api_secret(server_url, "user.123"), None);

        // Store tokens
        assert!(mgr.store_token(server_url, "access_token", "jwt_access_123"));
        assert_eq!(
            mgr.get_token(server_url, "access_token"),
            Some("jwt_access_123".to_string())
        );
        assert_eq!(
            mgr.get_session(server_url),
            Some("jwt_access_123".to_string())
        );

        assert!(mgr.store_token(server_url, "refresh_token", "jwt_refresh_456"));
        assert_eq!(
            mgr.get_token(server_url, "refresh_token"),
            Some("jwt_refresh_456".to_string())
        );

        // Store API secret
        assert!(mgr.store_api_secret(server_url, "user.123", "secret_abc_xyz"));
        assert_eq!(
            mgr.get_api_secret(server_url, "user.123"),
            Some("secret_abc_xyz".to_string())
        );
        assert_eq!(mgr.get_api_secret(server_url, "other.456"), None);

        // Clear specific token
        assert!(mgr.clear_token(server_url, "access_token"));
        assert_eq!(mgr.get_token(server_url, "access_token"), None);
        assert_eq!(
            mgr.get_token(server_url, "refresh_token"),
            Some("jwt_refresh_456".to_string())
        );
        assert_eq!(
            mgr.get_api_secret(server_url, "user.123"),
            Some("secret_abc_xyz".to_string())
        );

        // Clear API secret
        assert!(mgr.clear_api_secret(server_url, "user.123"));
        assert_eq!(mgr.get_api_secret(server_url, "user.123"), None);

        // Store again and test clear_all
        assert!(mgr.store_token(server_url, KIND_ACCESS_TOKEN, "jwt_access_999"));
        assert!(mgr.store_api_secret(server_url, "user.123", "secret_999"));
        assert!(mgr.clear_all());
        assert_eq!(mgr.get_token(server_url, KIND_ACCESS_TOKEN), None);
        assert_eq!(mgr.get_token(server_url, KIND_REFRESH_TOKEN), None);
        assert_eq!(mgr.get_api_secret(server_url, "user.123"), None);
        assert_eq!(mgr.get_session(server_url), None);
    }

    #[test]
    fn test_legacy_session_and_priority() {
        let dir = tempdir().unwrap();
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

        let mgr = KeyringManager::new(script_path.to_str().unwrap());
        let server_url = "https://vault.bitwarden.com";

        // 1. Store via legacy store_session
        assert!(mgr.store_session(server_url, "token_initial"));
        assert_eq!(
            mgr.get_session(server_url),
            Some("token_initial".to_string())
        );
        assert_eq!(
            mgr.get_token(server_url, KIND_ACCESS_TOKEN),
            Some("token_initial".to_string())
        );

        // 2. Overwrite via modern store_token
        assert!(mgr.store_token(server_url, KIND_ACCESS_TOKEN, "token_refreshed"));
        // get_session MUST return the refreshed token (priority inversion fixed)
        assert_eq!(
            mgr.get_session(server_url),
            Some("token_refreshed".to_string())
        );

        // 3. Clear session
        assert!(mgr.clear_session(server_url));
        assert_eq!(mgr.get_session(server_url), None);
        assert_eq!(mgr.get_token(server_url, KIND_ACCESS_TOKEN), None);
    }

    #[test]
    fn test_server_url_isolation_in_keyring() {
        let dir = tempdir().unwrap();
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

        let mgr = KeyringManager::new(script_path.to_str().unwrap());
        let server_a = "https://server-a.com";
        let server_b = "https://server-b.com";

        // Store tokens on server A
        assert!(mgr.store_token(server_a, KIND_ACCESS_TOKEN, "token_a_access"));
        assert!(mgr.store_token(server_a, KIND_REFRESH_TOKEN, "token_a_refresh"));

        // Store tokens on server B
        assert!(mgr.store_token(server_b, KIND_ACCESS_TOKEN, "token_b_access"));
        assert!(mgr.store_token(server_b, KIND_REFRESH_TOKEN, "token_b_refresh"));

        // Ensure Server A returns only its own tokens
        assert_eq!(
            mgr.get_token(server_a, KIND_ACCESS_TOKEN),
            Some("token_a_access".to_string())
        );
        assert_eq!(
            mgr.get_token(server_a, KIND_REFRESH_TOKEN),
            Some("token_a_refresh".to_string())
        );

        // Ensure Server B returns only its own tokens
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("token_b_access".to_string())
        );
        assert_eq!(
            mgr.get_token(server_b, KIND_REFRESH_TOKEN),
            Some("token_b_refresh".to_string())
        );

        // Clear token on server A and verify server B is intact
        assert!(mgr.clear_token(server_a, KIND_ACCESS_TOKEN));
        assert_eq!(mgr.get_token(server_a, KIND_ACCESS_TOKEN), None);
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("token_b_access".to_string())
        );
    }

    #[test]
    fn test_validation_rejects_empty_inputs() {
        let mgr = KeyringManager::new("mock");
        assert!(!mgr.store_token("", "access_token", "token"));
        assert!(!mgr.store_token("https://bw.local", "", "token"));
        assert!(!mgr.store_token("https://bw.local", "kind", ""));
        assert_eq!(mgr.get_token("", "kind"), None);
        assert_eq!(mgr.get_token("https://bw.local", ""), None);
        assert!(!mgr.clear_token("", "kind"));
        assert!(!mgr.clear_token("https://bw.local", ""));

        assert!(!mgr.store_api_secret("", "client_id", "secret"));
        assert!(!mgr.store_api_secret("https://bw.local", "", "secret"));
        assert!(!mgr.store_api_secret("https://bw.local", "client_id", ""));
        assert_eq!(mgr.get_api_secret("", "client_id"), None);
        assert_eq!(mgr.get_api_secret("https://bw.local", ""), None);
        assert!(!mgr.clear_api_secret("", "client_id"));
        assert!(!mgr.clear_api_secret("https://bw.local", ""));
    }

    #[test]
    fn test_keyring_trailing_slash_normalization() {
        let dir = tempdir().unwrap();
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

        let mgr = KeyringManager::new(script_path.to_str().unwrap());

        // Store with trailing slash
        assert!(mgr.store_api_secret("https://vault.example.com/", "user.123 ", "secret_val"));

        // Lookup without trailing slash
        assert_eq!(
            mgr.get_api_secret("https://vault.example.com", "user.123"),
            Some("secret_val".to_string())
        );

        // Clear with trailing slash
        assert!(mgr.clear_api_secret("https://vault.example.com/", "user.123"));
        assert_eq!(
            mgr.get_api_secret("https://vault.example.com", "user.123"),
            None
        );
    }
}
