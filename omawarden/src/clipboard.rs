use std::io::{self, Read, Write};
use std::process::{Command, Stdio};

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
        let result = if sensitive && timeout_seconds > 0 {
            self.copy_with_expiry(text, timeout_seconds)
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

    fn copy_with_expiry(&self, text: &str, seconds: i64) -> io::Result<bool> {
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
        match Command::new(&self.wl_copy_path).arg("--clear").output() {
            Ok(output) => {
                let success = output.status.success();
                if success {
                    crate::log_info!("omawarden:clipboard", "Clipboard cleared.");
                }
                success
            }
            Err(err) => {
                crate::log_error!("omawarden:clipboard", "Failed to clear clipboard: {err}");
                false
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
