use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
#[doc(hidden)]
pub fn current_lock_epoch() -> io::Result<u64> {
    crate::lock_epoch::store()
        .current()
        .map(|epoch| epoch.value())
}

#[doc(hidden)]
pub struct ClipboardOutput {
    _output: File,
    _account: Option<File>,
}

impl ClipboardScope {
    /// Revalidate the source in the detached holder, before it starts wl-copy.
    #[doc(hidden)]
    pub fn begin_output(&self) -> io::Result<ClipboardOutput> {
        if !wayland_configured()? {
            return Err(io::Error::other("No Wayland clipboard is configured"));
        }
        let (output, account) = match self {
            Self::Session(generation) => (crate::daemon::guard_session_output(*generation)?, None),
            Self::Cache {
                path,
                credential_id,
                lock_epoch,
            } => {
                let storage = crate::storage::StorageManager::new(path.clone());
                let account = storage.account_guard()?;
                let output = crate::daemon::lock_session_outputs()?;
                if storage.load_existing()?.scoped_credential_id() != Some(credential_id) {
                    return Err(io::Error::other("Vault account changed. Retry the copy."));
                }
                if crate::lock_epoch::store().current()?.value() != *lock_epoch {
                    return Err(io::Error::other(
                        "Vault was locked during the copy. Retry the copy.",
                    ));
                }
                (output, Some(account))
            }
        };
        // Record possible exposure before contacting Wayland, even if the
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
        })
    }
}

fn clipboard_marker() -> PathBuf {
    crate::daemon::get_socket_path().with_extension("clipboard.pending")
}

fn wayland_configured() -> io::Result<bool> {
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
    let clipboard = ClipboardManager::default()
        .clear_session_selection()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Wayland clipboard cleanup failed. {error}"),
            )
        });
    previews.and(clipboard)
}

pub(crate) fn revoke_session_outputs() -> io::Result<()> {
    let _output = crate::daemon::lock_session_outputs()?;
    clear_session_outputs()
}

#[derive(Debug, Clone)]
pub struct ClipboardManager {
    pub wl_copy_path: String,
}

impl Default for ClipboardManager {
    fn default() -> Self {
        Self::new("wl-copy")
    }
}

impl ClipboardManager {
    pub fn new(wl_copy_path: &str) -> Self {
        let path = which::which(wl_copy_path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| wl_copy_path.to_owned());
        Self { wl_copy_path: path }
    }

    pub fn is_available(&self) -> bool {
        which::which(&self.wl_copy_path).is_ok()
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
                    "Copied content to clipboard (sensitive: {}, ttl: {}s)",
                    sensitive,
                    timeout_seconds.max(0)
                );
                true
            }
            Ok(false) => false,
            Err(err) => {
                crate::log_error!("omawarden:clipboard", "Clipboard copy failed: {err}");
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
            .arg(&self.wl_copy_path)
            .stdin(input)
            .stdout(ack)
            .stderr(Stdio::null());
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
        let mut cmd = Command::new(&self.wl_copy_path);
        if sensitive {
            cmd.arg("--sensitive");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let written = child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(text.as_bytes());
        let status = child.wait()?;
        written?;
        Ok(status.success())
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
        if clipboard_marker().try_exists()? || wayland_configured()? {
            self.clear_confirmed()?;
        }
        Ok(())
    }

    fn clear_confirmed(&self) -> io::Result<()> {
        if !self.clear_selection()? {
            return Err(io::Error::other("wl-copy --clear failed"));
        }
        match fs::remove_file(clipboard_marker()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }

    fn clear_selection(&self) -> io::Result<bool> {
        let mut child = Command::new(&self.wl_copy_path)
            .arg("--clear")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + CLIPBOARD_SETUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status.success()),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(result.err().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::TimedOut, "wl-copy --clear timed out")
                    }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_mock_clipboard_copy_and_clear() {
        let dir = tempdir().unwrap();
        let clip_file = dir.path().join("clipboard.txt");
        let args_file = dir.path().join("args.txt");
        let mock_wl = dir.path().join("mock-wl-copy");

        let script = format!(
            r#"#!/bin/sh
CF="{}"
AF="{}"
echo "$*" > "$AF"
if [ "$1" = "--clear" ]; then
    rm -f "$CF"
    exit 0
else
    cat > "$CF"
    exit 0
fi
"#,
            clip_file.display(),
            args_file.display()
        );

        crate::write_test_executable(&mock_wl, script);

        let mgr = ClipboardManager::new(mock_wl.to_str().unwrap());

        // Copy sensitive text -> should pass --sensitive
        assert!(mgr.copy("super_secret_password", true, 0));
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "super_secret_password"
        );
        let args = fs::read_to_string(&args_file).unwrap();
        assert!(args.contains("--sensitive"));

        // Copy non-sensitive text -> should NOT pass --sensitive
        assert!(mgr.copy("public_username", false, 0));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), "public_username");
        let args_non_sensitive = fs::read_to_string(&args_file).unwrap();
        assert!(!args_non_sensitive.contains("--sensitive"));

        // Copy multi-line report
        let multiline_report = "### Title\n\n- item 1\n- item 2\n```\nlog 1\n```\n";
        assert!(mgr.copy(multiline_report, false, 0));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), multiline_report);

        // Clear clipboard
        assert!(mgr.clear());
        assert!(!clip_file.exists());
        let clear_args = fs::read_to_string(&args_file).unwrap();
        assert!(clear_args.contains("--clear"));
    }

    #[test]
    fn test_non_existent_wl_copy() {
        let mgr = ClipboardManager::new("non_existent_wl_copy_bin_12345");
        assert!(!mgr.copy("text", false, 0));
        assert!(!mgr.clear());
    }
}
