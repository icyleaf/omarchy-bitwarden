use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::credential_slots::CredentialSlot;

use super::macos::MacOsKeychainProvider;
use super::mock::MockKeyringProvider;
use super::secret_tool::SecretToolKeyringProvider;

/// Platform-specific keyring backend adapter responsible for low-level
/// credential storage, attribute-scoped lookup, slot erasure, and availability checks.
pub trait KeyringProvider: Send + Sync {
    /// Canonical identifier for the provider (e.g. "secret-tool", "macos", "mock", "unavailable").
    fn name(&self) -> &'static str;

    /// Checks if the underlying system keyring utility or platform API is available.
    fn is_available(&self) -> bool;

    /// Returns a human-readable diagnostic message when unavailable.
    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            None
        } else {
            Some(format!(
                "Keyring provider '{}' is not available on this system.",
                self.name()
            ))
        }
    }

    /// Persists a secret indexed by key-value attribute pairs (`[k1, v1, k2, v2, ...]`).
    ///
    /// Providers that spawn external writer subprocesses MUST inherit `lease` so
    /// retired slot cleanup waits until the writer exits.
    fn store(
        &self,
        label: &str,
        attributes: &[&str],
        secret: &str,
        lease: Option<&CredentialSlot>,
    ) -> bool;

    /// Looks up a secret matching the given key-value attribute pairs.
    fn lookup(&self, attributes: &[&str]) -> Option<String>;

    /// Clears credentials matching the given key-value attribute pairs.
    fn clear(&self, attributes: &[&str]) -> bool;

    /// Erases all credentials belonging to a scoped credential slot (`Some(id)`)
    /// or the legacy service namespace (`None`) and confirms absence before `deadline`.
    fn erase_credential_slot(
        &self,
        credential_id: Option<&str>,
        deadline: Instant,
    ) -> io::Result<()>;
}

/// Fail-closed fallback provider used when no supported Keyring Provider is available.
#[derive(Debug, Clone, Default)]
pub struct UnavailableKeyringProvider {
    reason: String,
}

impl UnavailableKeyringProvider {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl KeyringProvider for UnavailableKeyringProvider {
    fn name(&self) -> &'static str {
        "unavailable"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn unavailable_reason(&self) -> Option<String> {
        Some(self.reason.clone())
    }

    fn store(
        &self,
        _label: &str,
        _attributes: &[&str],
        _secret: &str,
        _lease: Option<&CredentialSlot>,
    ) -> bool {
        false
    }

    fn lookup(&self, _attributes: &[&str]) -> Option<String> {
        None
    }

    fn clear(&self, _attributes: &[&str]) -> bool {
        false
    }

    fn erase_credential_slot(
        &self,
        _credential_id: Option<&str>,
        _deadline: Instant,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            self.unavailable_reason()
                .unwrap_or_else(|| "No supported keyring provider is available.".to_string()),
        ))
    }
}

/// Resolves the appropriate keyring provider based on explicit overrides,
/// environment variables, and compile-time target OS dispatch.
pub fn resolve_provider(
    explicit_name: Option<&str>,
    explicit_path: Option<&Path>,
) -> Arc<dyn KeyringProvider> {
    let env_provider = std::env::var("OMA_KEYRING_PROVIDER").ok();
    let name = explicit_name
        .or(env_provider.as_deref())
        .map(|s| s.trim().to_ascii_lowercase());

    if let Some(ref provider_name) = name {
        match provider_name.as_str() {
            "secret-tool" | "secret_tool" | "linux" | "freedesktop" => {
                return Arc::new(SecretToolKeyringProvider::new_with_path(explicit_path));
            }
            "macos" | "keychain" => {
                return Arc::new(MacOsKeychainProvider::new());
            }
            "mock" => {
                return Arc::new(MockKeyringProvider::new());
            }
            unknown => {
                return Arc::new(UnavailableKeyringProvider::new(format!(
                    "Unknown keyring provider '{unknown}' requested."
                )));
            }
        }
    }

    if explicit_path.is_some() || std::env::var_os("OMA_SECRET_TOOL_PATH").is_some() {
        return Arc::new(SecretToolKeyringProvider::new_with_path(explicit_path));
    }

    #[cfg(target_os = "macos")]
    {
        Arc::new(MacOsKeychainProvider::new())
    }

    #[cfg(target_os = "linux")]
    {
        Arc::new(SecretToolKeyringProvider::new_with_path(None))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Arc::new(UnavailableKeyringProvider::new(
            "No supported system keyring provider is available on this platform.",
        ))
    }
}
