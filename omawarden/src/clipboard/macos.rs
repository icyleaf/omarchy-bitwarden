use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::provider::ClipboardProvider;

/// macOS clipboard provider backed by `pbcopy`.
///
/// Handles standard text clipboard copies and clears by piping content to/from
/// the system `pbcopy` utility. Ephemeral secrecy for sensitive tokens is enforced
/// via Omawarden's core `ClipboardGuard` and `clipboard-holder` TTL expiration timers
/// and vault session lock revocation.
#[derive(Debug, Clone)]
pub struct MacOsClipboardProvider {
    pub path: PathBuf,
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
        Self { path }
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
            Ok(())
        } else {
            Err(io::Error::other("pbcopy from stdin failed"))
        }
    }

    fn clear(&self) -> io::Result<()> {
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
    fn test_macos_provider_copy_and_clear() {
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

        let provider = MacOsClipboardProvider::new_with_path(Some(&mock_pbcopy));
        assert!(provider.is_available());
        assert_eq!(provider.name(), "macos");

        // 1. Copy content
        provider.copy("macos_test_token", true).unwrap();
        let pbcopy_content = fs::read_to_string(&pbcopy_log).unwrap();
        assert_eq!(pbcopy_content, "macos_test_token");

        // 2. Clear clipboard -> writes empty string
        provider.clear().unwrap();
        let pbcopy_clear = fs::read_to_string(&pbcopy_log).unwrap();
        assert!(pbcopy_clear.is_empty());
    }

    #[test]
    fn test_macos_provider_unavailable() {
        let provider = MacOsClipboardProvider::new("nonexistent_pbcopy_tool_123");
        assert!(!provider.is_available());
        assert!(provider.unavailable_reason().is_some());
    }
}
