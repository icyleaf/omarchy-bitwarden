use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::macos::MacOsClipboardProvider;
use super::mock::MockClipboardProvider;
use super::wayland::WlClipboardProvider;
use super::x11::X11ClipboardProvider;

/// Platform-specific clipboard backend adapter responsible for low-level
/// clipboard copy, clear, and availability checks.
pub trait ClipboardProvider: Send + Sync {
    /// Canonical identifier for the provider (e.g. "wayland", "x11", "macos", "mock").
    fn name(&self) -> &'static str;

    /// Checks if the underlying binary or platform API is available on the system.
    fn is_available(&self) -> bool;

    /// Checks if this provider is active and configured in the current desktop session.
    fn is_configured(&self) -> io::Result<bool> {
        Ok(self.is_available())
    }

    /// Returns a human-readable diagnostic message when unavailable.
    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            None
        } else {
            Some(format!(
                "Clipboard provider '{}' is not available on this system.",
                self.name()
            ))
        }
    }

    /// Whether this provider manages selection via a persistent background process
    /// that exits upon selection takeover, allowing the holder to reap and release early.
    fn monitors_selection(&self) -> bool {
        false
    }

    /// Copies text to the system clipboard without holding or expiring.
    fn copy(&self, text: &str, sensitive: bool) -> io::Result<()>;

    /// Copies content directly from standard input to avoid secret exposure in process argv.
    fn copy_from_stdin(&self, sensitive: bool) -> io::Result<()> {
        let mut buf = zeroize::Zeroizing::new(String::new());
        io::Read::read_to_string(&mut io::stdin(), &mut buf)?;
        self.copy(&buf, sensitive)
    }

    /// Clears the system clipboard selection.
    fn clear(&self) -> io::Result<()>;

    /// Path to the underlying binary, if file-based.
    fn binary_path(&self) -> Option<PathBuf> {
        None
    }
}

/// Fallback provider used when no supported clipboard system is detected.
#[derive(Debug, Clone, Default)]
pub struct UnavailableClipboardProvider {
    reason: String,
}

impl UnavailableClipboardProvider {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl ClipboardProvider for UnavailableClipboardProvider {
    fn name(&self) -> &'static str {
        "unavailable"
    }

    fn is_available(&self) -> bool {
        false
    }

    fn unavailable_reason(&self) -> Option<String> {
        Some(self.reason.clone())
    }

    fn copy(&self, _text: &str, _sensitive: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            self.unavailable_reason().unwrap_or_default(),
        ))
    }

    fn copy_from_stdin(&self, _sensitive: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            self.unavailable_reason().unwrap_or_default(),
        ))
    }

    fn clear(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            self.unavailable_reason().unwrap_or_default(),
        ))
    }
}

/// Resolves the appropriate clipboard provider based on explicit overrides,
/// environment variables, compile-time target OS, and runtime display detection.
pub fn resolve_provider(
    explicit_name: Option<&str>,
    explicit_path: Option<&Path>,
) -> Arc<dyn ClipboardProvider> {
    let env_provider = std::env::var("OMA_CLIPBOARD_PROVIDER").ok();
    let name = explicit_name
        .or(env_provider.as_deref())
        .map(|s| s.trim().to_ascii_lowercase());

    if let Some(ref provider_name) = name {
        match provider_name.as_str() {
            "wayland" | "wl-clipboard" | "wl-copy" => {
                return Arc::new(WlClipboardProvider::new_with_path(explicit_path));
            }
            "x11" | "xclip" => {
                return Arc::new(X11ClipboardProvider::new_with_path(explicit_path));
            }
            "macos" | "pbcopy" => {
                return Arc::new(MacOsClipboardProvider::new_with_path(explicit_path));
            }
            "mock" => {
                return Arc::new(MockClipboardProvider::new());
            }
            unknown => {
                return Arc::new(UnavailableClipboardProvider::new(format!(
                    "Unknown clipboard provider '{unknown}' requested."
                )));
            }
        }
    }

    // Auto-detect based on platform environment:
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacOsClipboardProvider::new_with_path(explicit_path))
    }

    #[cfg(not(target_os = "macos"))]
    {
        if super::wayland_configured().unwrap_or(false) {
            Arc::new(WlClipboardProvider::new_with_path(explicit_path))
        } else if std::env::var_os("DISPLAY").is_some() {
            let x11 = X11ClipboardProvider::new_with_path(explicit_path);
            if x11.is_available() {
                Arc::new(x11)
            } else {
                let wl = WlClipboardProvider::new_with_path(explicit_path);
                if wl.is_available() {
                    Arc::new(wl)
                } else {
                    Arc::new(UnavailableClipboardProvider::new(
                        "No supported clipboard provider (Wayland or X11) is available.",
                    ))
                }
            }
        } else {
            let wl = WlClipboardProvider::new_with_path(explicit_path);
            if wl.is_available() {
                Arc::new(wl)
            } else {
                Arc::new(UnavailableClipboardProvider::new(
                    "No supported display session or clipboard utility found.",
                ))
            }
        }
    }
}
