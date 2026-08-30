use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

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

    pub fn copy(&self, text: &str, sensitive: bool, timeout_seconds: i64) -> bool {
        let mut child = match Command::new(&self.wl_copy_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
        }

        let success = match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        };

        if success && sensitive && timeout_seconds > 0 {
            self.schedule_auto_clear(timeout_seconds);
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
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
}
