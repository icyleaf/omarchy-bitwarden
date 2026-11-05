use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[doc(hidden)]
pub const CLIPBOARD_SETUP_TIMEOUT: Duration = Duration::from_secs(2);

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
        self.copy_inner(text, sensitive, timeout_seconds, Some(generation))
    }

    fn copy_inner(
        &self,
        text: &str,
        sensitive: bool,
        timeout_seconds: i64,
        generation: Option<u64>,
    ) -> bool {
        let seconds = if sensitive { timeout_seconds.max(0) } else { 0 };
        let result = if generation.is_some() || seconds > 0 {
            self.copy_with_holder(text, sensitive, seconds, generation)
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
        generation: Option<u64>,
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
        if let Some(generation) = generation {
            worker.args(["--expected-lock-generation", &generation.to_string()]);
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
        match self.clear_selection() {
            Ok(true) => {
                crate::log_info!("omawarden:clipboard", "Clipboard cleared.");
                true
            }
            Ok(false) => false,
            Err(err) => {
                crate::log_error!("omawarden:clipboard", "Failed to clear clipboard: {err}");
                false
            }
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
