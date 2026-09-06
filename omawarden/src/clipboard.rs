use std::io::Write;
use std::os::unix::process::CommandExt;
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
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| wl_copy_path.to_string());
        Self { wl_copy_path: path }
    }

    pub fn is_available(&self) -> bool {
        which::which(&self.wl_copy_path).is_ok()
    }

    pub fn copy(&self, text: &str, sensitive: bool, timeout_seconds: i64) -> bool {
        if !self.is_available() {
            crate::log_warn!(
                "omawarden:clipboard",
                "Wayland clipboard utility '{}' not found in PATH. Please install 'wl-clipboard'.",
                self.wl_copy_path
            );
            return false;
        }

        let mut cmd = Command::new(&self.wl_copy_path);
        if sensitive {
            cmd.arg("--sensitive");
        }

        let mut child = match cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                crate::log_error!(
                    "omawarden:clipboard",
                    "Failed to spawn {}: {:?}",
                    self.wl_copy_path,
                    e
                );
                return false;
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }

        let success = match child.wait() {
            Ok(status) => status.success(),
            Err(e) => {
                crate::log_error!("omawarden:clipboard", "wl-copy process error: {:?}", e);
                false
            }
        };

        if success {
            crate::log_info!(
                "omawarden:clipboard",
                "Copied content to clipboard (sensitive: {}, ttl: {}s)",
                sensitive,
                timeout_seconds
            );
            if sensitive && timeout_seconds > 0 {
                self.schedule_auto_clear(timeout_seconds);
            }
        }

        success
    }

    fn schedule_auto_clear(&self, timeout_seconds: i64) {
        let shell_cmd = format!(
            "sleep {} && '{}' --clear >/dev/null 2>&1",
            timeout_seconds, self.wl_copy_path
        );
        let _ = unsafe {
            Command::new("sh")
                .args(["-c", &shell_cmd])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .pre_exec(|| {
                    libc::setsid();
                    Ok(())
                })
                .spawn()
        };
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
            Err(e) => {
                crate::log_error!("omawarden:clipboard", "Failed to clear clipboard: {:?}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
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

        fs::write(&mock_wl, script).unwrap();
        let mut perms = fs::metadata(&mock_wl).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&mock_wl, perms).unwrap();

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
