use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use super::provider::ClipboardProvider;

#[cfg(target_os = "macos")]
mod pasteboard_ffi {
    use std::ffi::{c_char, c_void};

    #[link(name = "AppKit", kind = "framework")]
    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend();
    }

    pub fn get_pasteboard_change_count() -> Option<i64> {
        unsafe {
            let class_name = b"NSPasteboard\0";
            let cls = objc_getClass(class_name.as_ptr() as *const c_char);
            if cls.is_null() {
                return None;
            }

            let sel_general = sel_registerName(b"generalPasteboard\0".as_ptr() as *const c_char);
            if sel_general.is_null() {
                return None;
            }

            let msg_send_id: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let pasteboard = msg_send_id(cls, sel_general);
            if pasteboard.is_null() {
                return None;
            }

            let sel_change_count = sel_registerName(b"changeCount\0".as_ptr() as *const c_char);
            if sel_change_count.is_null() {
                return None;
            }

            let msg_send_isize: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let count = msg_send_isize(pasteboard, sel_change_count);
            Some(count as i64)
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod pasteboard_ffi {
    pub fn get_pasteboard_change_count() -> Option<i64> {
        None
    }
}

/// macOS clipboard provider backed by `pbcopy` and `NSPasteboard.changeCount`.
///
/// Handles standard text clipboard copies and clears by piping content to/from
/// the system `pbcopy` utility. Ephemeral secrecy for sensitive tokens is enforced
/// via Omawarden's core `ClipboardGuard` and `clipboard-holder` TTL expiration timers
/// and vault session lock revocation.
///
/// To prevent clobbering external clipboard replacements upon TTL expiration (Scheme A),
/// `MacOsClipboardProvider` tracks the system `NSPasteboard.changeCount`. If the pasteboard's
/// `changeCount` has incremented between the initial copy and TTL expiry, Omawarden skips
/// clearing to preserve newer clipboard content.
#[derive(Clone)]
pub struct MacOsClipboardProvider {
    pub path: PathBuf,
    recorded_change_count: Arc<AtomicI64>,
    change_count_reader: Option<Arc<dyn Fn() -> Option<i64> + Send + Sync>>,
}

impl std::fmt::Debug for MacOsClipboardProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsClipboardProvider")
            .field("path", &self.path)
            .field(
                "recorded_change_count",
                &self.recorded_change_count.load(Ordering::SeqCst),
            )
            .field("has_custom_reader", &self.change_count_reader.is_some())
            .finish()
    }
}

impl Default for MacOsClipboardProvider {
    fn default() -> Self {
        Self::new_with_path(None)
    }
}

impl MacOsClipboardProvider {
    pub fn new(path: &str) -> Self {
        Self::new_with_path(Some(Path::new(path)))
    }

    pub fn new_with_path(explicit_path: Option<&Path>) -> Self {
        let path = if let Some(p) = explicit_path {
            p.to_path_buf()
        } else {
            PathBuf::from("pbcopy")
        };
        Self {
            path,
            recorded_change_count: Arc::new(AtomicI64::new(-1)),
            change_count_reader: None,
        }
    }

    /// Internal or test constructor allowing injection of a custom changeCount reader.
    pub fn with_change_count_reader<F>(mut self, reader: F) -> Self
    where
        F: Fn() -> Option<i64> + Send + Sync + 'static,
    {
        self.change_count_reader = Some(Arc::new(reader));
        self
    }

    /// Queries the current system pasteboard change count.
    pub fn current_change_count(&self) -> Option<i64> {
        if let Some(ref reader) = self.change_count_reader {
            reader()
        } else {
            pasteboard_ffi::get_pasteboard_change_count()
        }
    }

    /// Returns the change count recorded during the most recent copy, if any.
    pub fn recorded_change_count(&self) -> Option<i64> {
        let val = self.recorded_change_count.load(Ordering::SeqCst);
        if val >= 0 {
            Some(val)
        } else {
            None
        }
    }
}

impl ClipboardProvider for MacOsClipboardProvider {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn is_available(&self) -> bool {
        which::which(&self.path).is_ok()
    }

    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            None
        } else {
            Some("macOS clipboard utility 'pbcopy' not found.".to_string())
        }
    }

    fn monitors_selection(&self) -> bool {
        false
    }

    fn binary_path(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn copy(&self, text: &str, _sensitive: bool) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
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
        if status.success() {
            if let Some(count) = self.current_change_count() {
                self.recorded_change_count.store(count, Ordering::SeqCst);
            }
            Ok(())
        } else {
            Err(io::Error::other("pbcopy failed"))
        }
    }

    fn copy_from_stdin(&self, _sensitive: bool) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            if let Some(count) = self.current_change_count() {
                self.recorded_change_count.store(count, Ordering::SeqCst);
            }
            Ok(())
        } else {
            Err(io::Error::other("pbcopy from stdin failed"))
        }
    }

    fn clear(&self) -> io::Result<()> {
        let recorded = self.recorded_change_count.load(Ordering::SeqCst);
        if recorded >= 0 {
            if let Some(current) = self.current_change_count() {
                if current != recorded {
                    // Pasteboard selection was replaced by another application or copy since our copy.
                    // Preserve the replacement selection and skip wiping the pasteboard.
                    return Ok(());
                }
            }
        }

        let mut cmd = Command::new(&self.path);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let written = child.stdin.take().expect("stdin was piped").write_all(b"");
        let status = child.wait()?;
        written?;
        if status.success() {
            if let Some(after) = self.current_change_count() {
                self.recorded_change_count.store(after, Ordering::SeqCst);
            }
            Ok(())
        } else {
            Err(io::Error::other("pbcopy clear failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_macos_provider_copy_and_clear_when_changecount_unchanged() {
        let dir = tempdir().unwrap();
        let mock_pbcopy = dir.path().join("pbcopy");
        let pbcopy_log = dir.path().join("pbcopy.log");

        let pbcopy_script = format!(
            r#"#!/bin/sh
cat > "{}"
exit 0
"#,
            pbcopy_log.display()
        );

        crate::write_test_executable(&mock_pbcopy, pbcopy_script);

        let change_counter = Arc::new(AtomicI64::new(42));
        let counter_reader = change_counter.clone();

        let provider = MacOsClipboardProvider::new_with_path(Some(&mock_pbcopy))
            .with_change_count_reader(move || Some(counter_reader.load(Ordering::SeqCst)));

        assert!(provider.is_available());
        assert_eq!(provider.name(), "macos");

        // 1. Copy content -> records changeCount 42
        provider.copy("macos_test_token", true).unwrap();
        assert_eq!(provider.recorded_change_count(), Some(42));
        let pbcopy_content = fs::read_to_string(&pbcopy_log).unwrap();
        assert_eq!(pbcopy_content, "macos_test_token");

        // 2. Clear clipboard while changeCount is still 42 -> clear proceeds
        provider.clear().unwrap();
        let pbcopy_clear = fs::read_to_string(&pbcopy_log).unwrap();
        assert!(pbcopy_clear.is_empty());
    }

    #[test]
    fn test_macos_provider_skips_clear_when_changecount_changed() {
        let dir = tempdir().unwrap();
        let mock_pbcopy = dir.path().join("pbcopy");
        let pbcopy_log = dir.path().join("pbcopy.log");

        let pbcopy_script = format!(
            r#"#!/bin/sh
cat > "{}"
exit 0
"#,
            pbcopy_log.display()
        );

        crate::write_test_executable(&mock_pbcopy, pbcopy_script);

        let change_counter = Arc::new(AtomicI64::new(100));
        let counter_reader = change_counter.clone();

        let provider = MacOsClipboardProvider::new_with_path(Some(&mock_pbcopy))
            .with_change_count_reader(move || Some(counter_reader.load(Ordering::SeqCst)));

        // 1. Copy secret token -> records changeCount 100
        provider.copy("secret_token_to_expire", true).unwrap();
        assert_eq!(provider.recorded_change_count(), Some(100));
        assert_eq!(
            fs::read_to_string(&pbcopy_log).unwrap(),
            "secret_token_to_expire"
        );

        // 2. Simulate external user copy by incrementing changeCount to 101
        change_counter.store(101, Ordering::SeqCst);

        // 3. Clear triggered upon TTL expiry
        provider.clear().unwrap();

        // 4. pbcopy clear MUST NOT have been executed; file content remains untouched
        assert_eq!(
            fs::read_to_string(&pbcopy_log).unwrap(),
            "secret_token_to_expire"
        );
    }

    #[test]
    fn test_macos_provider_explicit_clear_without_prior_copy() {
        let dir = tempdir().unwrap();
        let mock_pbcopy = dir.path().join("pbcopy");
        let pbcopy_log = dir.path().join("pbcopy.log");

        let pbcopy_script = format!(
            r#"#!/bin/sh
cat > "{}"
exit 0
"#,
            pbcopy_log.display()
        );

        crate::write_test_executable(&mock_pbcopy, pbcopy_script);

        // Provider without prior copy has recorded_change_count = -1
        let provider = MacOsClipboardProvider::new_with_path(Some(&mock_pbcopy));
        assert_eq!(provider.recorded_change_count(), None);

        // Writing initial content manually
        fs::write(&pbcopy_log, "pre-existing content").unwrap();

        // Calling clear() directly clears the pasteboard
        provider.clear().unwrap();
        assert!(fs::read_to_string(&pbcopy_log).unwrap().is_empty());
    }

    #[test]
    fn test_macos_provider_unavailable() {
        let provider = MacOsClipboardProvider::new("nonexistent_pbcopy_tool_123");
        assert!(!provider.is_available());
        assert!(provider.unavailable_reason().is_some());
    }
}
