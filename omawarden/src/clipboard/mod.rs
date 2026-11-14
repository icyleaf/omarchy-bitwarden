pub mod macos;
pub mod mock;
pub mod provider;
pub mod wayland;
pub mod x11;

pub use macos::MacOsClipboardProvider;
pub use mock::MockClipboardProvider;
pub use provider::{resolve_provider, ClipboardProvider, UnavailableClipboardProvider};
pub use wayland::WlClipboardProvider;
pub use x11::X11ClipboardProvider;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

#[doc(hidden)]
pub const CLIPBOARD_SETUP_TIMEOUT: Duration = Duration::from_secs(2);

/// The authorization that supplied a vault clipboard value.
#[doc(hidden)]
pub enum ClipboardScope {
    Session(u64),
    Cache {
        path: PathBuf,
        credential_id: String,
        /// Lock transition that authorized this cache read. A later hard or
        /// soft lock advances the shared epoch and invalidates the scope.
        lock_epoch: u64,
    },
}

/// Read the shared epoch that every lock transition advances.
///
/// Offline copy authorization captures this value before reading the
/// encrypted cache; the detached holder compares it again before publishing.
/// Sampling uses the default runtime socket and releases its owner leases
/// after this read. The holder reacquires them through publication acknowledgement.
#[doc(hidden)]
pub fn current_lock_epoch(cache: &Path) -> io::Result<u64> {
    let _daemon = crate::daemon::guard_cache_daemon(cache)?;
    crate::lock_epoch::store()
        .current()
        .map(|epoch| epoch.value())
}

#[doc(hidden)]
pub struct ClipboardOutput {
    _output: File,
    _account: Option<File>,
    _daemon: Option<crate::daemon::DaemonOwnerGuard>,
}

impl ClipboardScope {
    /// Revalidate the source in the detached holder, before it writes to the clipboard.
    #[doc(hidden)]
    pub fn begin_output(&self) -> io::Result<ClipboardOutput> {
        self.begin_output_with_provider(&*resolve_provider(None, None))
    }

    /// Revalidate the source in the detached holder with an explicit provider.
    #[doc(hidden)]
    pub fn begin_output_with_provider(
        &self,
        provider: &dyn ClipboardProvider,
    ) -> io::Result<ClipboardOutput> {
        if !provider.is_configured()? {
            return Err(io::Error::other(
                provider
                    .unavailable_reason()
                    .unwrap_or_else(|| "No clipboard provider is configured".to_string()),
            ));
        }
        let (output, account, daemon) = match self {
            Self::Session(generation) => (
                crate::daemon::guard_session_output(*generation)?,
                None,
                None,
            ),
            Self::Cache {
                path,
                credential_id,
                lock_epoch,
            } => {
                let storage = crate::storage::StorageManager::new(path.clone());
                let account = storage.account_guard()?;
                let output = crate::daemon::lock_session_outputs()?;
                let daemon = crate::daemon::guard_cache_daemon(path)?;
                if storage.load_existing()?.scoped_credential_id() != Some(credential_id) {
                    return Err(io::Error::other("Vault account changed. Retry the copy."));
                }
                if crate::lock_epoch::store().current()?.value() != *lock_epoch {
                    return Err(io::Error::other(
                        "Vault was locked during the copy. Retry the copy.",
                    ));
                }
                (output, Some(account), daemon)
            }
        };
        // Record possible exposure before contacting the provider, even if the
        // holder or daemon dies before the copy can be acknowledged.
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(clipboard_marker())?;
        Ok(ClipboardOutput {
            _output: output,
            _account: account,
            _daemon: daemon,
        })
    }
}

pub(crate) fn clipboard_marker() -> PathBuf {
    crate::daemon::get_socket_path().with_extension("clipboard.pending")
}

pub(crate) fn wayland_configured() -> io::Result<bool> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("WAYLAND_SOCKET").is_some()
    {
        return Ok(true);
    }
    match crate::daemon::get_runtime_dir()
        .join("wayland-0")
        .metadata()
    {
        Ok(metadata) => Ok(metadata.file_type().is_socket()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

// Call with the runtime output gate. Attempt both cleanups so a failure on
// one surface never prevents revoking the other.
pub(crate) fn clear_session_outputs() -> io::Result<()> {
    let previews = crate::attachment::clear_preview_attachments().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Attachment preview cleanup failed. {error}"),
        )
    });
    let guard = ClipboardGuard::default();
    let prefix = if guard.provider().name() == "wayland" {
        "Wayland clipboard cleanup failed."
    } else {
        "Clipboard cleanup failed."
    };
    let clipboard = guard
        .clear_session_selection()
        .map_err(|error| io::Error::new(error.kind(), format!("{prefix} {error}")));
    previews.and(clipboard)
}

pub(crate) fn revoke_session_outputs() -> io::Result<()> {
    let _output = crate::daemon::lock_session_outputs()?;
    clear_session_outputs()
}

/// The ephemeral clipboard subsystem that enforces automatic time-to-live
/// clearing and secure revocation of copied secrets across supported
/// display and OS clipboard providers.
#[derive(Clone)]
pub struct ClipboardGuard {
    provider: Arc<dyn ClipboardProvider>,
}

/// Backward compatibility alias for `ClipboardGuard`.
pub type ClipboardManager = ClipboardGuard;

impl Default for ClipboardGuard {
    fn default() -> Self {
        Self::with_provider(resolve_provider(None, None))
    }
}

impl std::fmt::Debug for ClipboardGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardGuard")
            .field("provider", &self.provider.name())
            .field("is_available", &self.provider.is_available())
            .finish()
    }
}

impl ClipboardGuard {
    /// Constructs a `ClipboardGuard` using a legacy `wl-copy` path string or provider name.
    pub fn new(path_or_provider: &str) -> Self {
        let path = Path::new(path_or_provider);
        if path.is_absolute()
            || path_or_provider.contains('/')
            || path_or_provider.contains("wl-copy")
        {
            Self::with_provider(Arc::new(WlClipboardProvider::new(path_or_provider)))
        } else {
            Self::with_provider(resolve_provider(Some(path_or_provider), None))
        }
    }

    /// Constructs a `ClipboardGuard` with an explicit `ClipboardProvider` implementation.
    pub fn with_provider(provider: Arc<dyn ClipboardProvider>) -> Self {
        Self { provider }
    }

    /// Accesses the underlying active provider.
    pub fn provider(&self) -> &Arc<dyn ClipboardProvider> {
        &self.provider
    }

    /// Checks if the underlying active provider is available.
    pub fn is_available(&self) -> bool {
        self.provider.is_available()
    }

    /// Diagnostic error/warning message if unavailable.
    pub fn unavailable_reason(&self) -> Option<String> {
        self.provider.unavailable_reason()
    }

    pub fn copy(&self, text: &str, sensitive: bool, timeout_seconds: i64) -> bool {
        self.copy_inner(text, sensitive, timeout_seconds, None)
    }

    /// Copy only while the vault session that supplied the text is current.
    #[doc(hidden)]
    pub fn copy_in_session(
        &self,
        text: &str,
        sensitive: bool,
        timeout_seconds: i64,
        generation: u64,
    ) -> bool {
        self.copy_vault_output(
            text,
            sensitive,
            timeout_seconds,
            &ClipboardScope::Session(generation),
        )
    }

    #[doc(hidden)]
    pub fn copy_vault_output(
        &self,
        text: &str,
        sensitive: bool,
        timeout_seconds: i64,
        scope: &ClipboardScope,
    ) -> bool {
        self.copy_inner(text, sensitive, timeout_seconds, Some(scope))
    }

    fn copy_inner(
        &self,
        text: &str,
        sensitive: bool,
        timeout_seconds: i64,
        scope: Option<&ClipboardScope>,
    ) -> bool {
        let seconds = if sensitive { timeout_seconds.max(0) } else { 0 };
        let result = if scope.is_some() || seconds > 0 {
            self.copy_with_holder(text, sensitive, seconds, scope)
        } else {
            self.copy_without_expiry(text, sensitive)
        };
        match result {
            Ok(true) => {
                crate::log_info!(
                    "omawarden:clipboard",
                    "Copied content to clipboard via '{}' (sensitive: {}, ttl: {}s)",
                    self.provider.name(),
                    sensitive,
                    timeout_seconds.max(0)
                );
                true
            }
            Ok(false) => false,
            Err(err) => {
                crate::log_error!(
                    "omawarden:clipboard",
                    "Clipboard copy failed via '{}': {err}",
                    self.provider.name()
                );
                false
            }
        }
    }

    fn copy_with_holder(
        &self,
        text: &str,
        sensitive: bool,
        seconds: i64,
        scope: Option<&ClipboardScope>,
    ) -> io::Result<bool> {
        let (input, mut sender) = io::pipe()?;
        let (mut ready, ack) = io::pipe()?;
        let mut worker = Command::new(std::env::current_exe()?);
        worker
            .arg("clipboard-holder")
            .arg(seconds.to_string())
            .arg("--provider")
            .arg(self.provider.name())
            .stdin(input)
            .stdout(ack)
            .stderr(Stdio::null());

        if let Some(binary_path) = self.provider.binary_path() {
            worker.arg("--binary-path").arg(binary_path);
        }

        if !sensitive {
            worker.arg("--public");
        }
        match scope {
            Some(ClipboardScope::Session(generation)) => {
                worker.args(["--expected-lock-generation", &generation.to_string()]);
            }
            Some(ClipboardScope::Cache {
                path,
                credential_id,
                lock_epoch,
            }) => {
                worker
                    .arg("--cache-path")
                    .arg(path)
                    .args(["--expected-credential-id", credential_id])
                    .args(["--expected-lock-epoch", &lock_epoch.to_string()]);
            }
            None => {}
        }

        // Register the waiter before spawning: the CLI may exit immediately
        // after the ack, while a long-running daemon needs to reap every holder.
        std::thread::Builder::new()
            .name("clipboard-reaper".into())
            .spawn(move || worker.status())?;
        sender.write_all(text.as_bytes())?;
        drop(sender);
        let mut response = [0];
        ready.read_exact(&mut response)?;
        Ok(response == [1])
    }

    fn copy_without_expiry(&self, text: &str, sensitive: bool) -> io::Result<bool> {
        self.provider.copy(text, sensitive).map(|()| true)
    }

    pub fn clear(&self) -> bool {
        match crate::daemon::lock_session_outputs().and_then(|_gate| self.clear_confirmed()) {
            Ok(()) => {
                crate::log_info!("omawarden:clipboard", "Clipboard cleared.");
                true
            }
            Err(err) => {
                crate::log_error!("omawarden:clipboard", "Failed to clear clipboard: {err}");
                false
            }
        }
    }

    /// Clear under the output gate when a desktop or a previous export is known.
    pub(crate) fn clear_session_selection(&self) -> io::Result<()> {
        if clipboard_marker().try_exists()? || self.provider.is_configured()? {
            self.clear_confirmed()?;
        }
        Ok(())
    }

    fn clear_confirmed(&self) -> io::Result<()> {
        if let Err(err) = self.provider.clear() {
            return Err(io::Error::other(format!("Provider clear failed: {err}")));
        }
        match fs::remove_file(clipboard_marker()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_provider_unit() {
        let mock = Arc::new(MockClipboardProvider::new());
        let guard = ClipboardGuard::with_provider(mock.clone());

        assert!(guard.is_available());
        assert_eq!(guard.provider().name(), "mock");

        assert!(guard.copy("unit-test-secret", true, 0));
        assert_eq!(mock.last_copied().as_deref(), Some("unit-test-secret"));
        assert!(mock.is_sensitive());
        assert!(!mock.was_cleared());

        assert!(guard.clear());
        assert!(mock.was_cleared());
        assert_eq!(mock.last_copied(), None);
    }

    #[test]
    fn test_mock_clipboard_unavailable() {
        let mock = Arc::new(MockClipboardProvider::new());
        mock.set_available(false);
        let guard = ClipboardGuard::with_provider(mock.clone());

        assert!(!guard.is_available());
        assert!(!guard.copy("secret", false, 0));
        assert!(!guard.clear());
    }

    #[test]
    fn test_provider_resolution() {
        let _guard = crate::env_lock();
        std::env::set_var("OMA_CLIPBOARD_PROVIDER", "mock");
        let provider = resolve_provider(None, None);
        assert_eq!(provider.name(), "mock");
        std::env::remove_var("OMA_CLIPBOARD_PROVIDER");

        let p_x11 = resolve_provider(Some("x11"), None);
        assert_eq!(p_x11.name(), "x11");

        let p_mac = resolve_provider(Some("macos"), None);
        assert_eq!(p_mac.name(), "macos");

        let p_unknown = resolve_provider(Some("nonexistent_provider"), None);
        assert_eq!(p_unknown.name(), "unavailable");
        assert!(!p_unknown.is_available());
        assert!(p_unknown.unavailable_reason().is_some());
    }

    #[test]
    fn test_mock_provider_metrics() {
        let mock = Arc::new(MockClipboardProvider::new());
        assert_eq!(mock.copy_count(), 0);
        assert_eq!(mock.clear_count(), 0);

        mock.copy("test", false).unwrap();
        assert_eq!(mock.copy_count(), 1);

        mock.clear().unwrap();
        assert_eq!(mock.clear_count(), 1);
    }

    #[test]
    fn test_non_existent_wl_copy() {
        let mgr = ClipboardManager::new("non_existent_wl_copy_bin_12345");
        assert!(!mgr.is_available());
        assert!(mgr.unavailable_reason().is_some());
    }

    #[test]
    fn test_mock_clipboard_copy_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let mock_wl = dir.path().join("mock-wl-copy");

        let script = r#"#!/bin/sh
if [ "$1" = "--clear" ]; then
    exit 0
fi
exit 0
"#;
        crate::write_test_executable(&mock_wl, script);

        let mgr = ClipboardManager::new(mock_wl.to_str().unwrap());
        assert!(mgr.is_available());

        let res = mgr.copy("my_secret_token", false, 0);
        assert!(res, "ClipboardManager copy should succeed with mock script");

        let res_clear = mgr.clear();
        assert!(res_clear, "ClipboardManager clear should succeed");
    }
}
