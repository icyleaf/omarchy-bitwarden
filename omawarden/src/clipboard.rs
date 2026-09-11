use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ClipboardManager {
    pub wl_copy_path: String,
    pub detach_worker: bool,
    gen_path: Option<PathBuf>,
    generation: Arc<AtomicU64>,
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
        Self {
            wl_copy_path: path,
            detach_worker: true,
            gen_path: None,
            generation: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn without_detached_worker(mut self) -> Self {
        self.detach_worker = false;
        self
    }

    pub fn with_generation_path(mut self, path: PathBuf) -> Self {
        self.gen_path = Some(path);
        self
    }

    pub fn is_available(&self) -> bool {
        which::which(&self.wl_copy_path).is_ok()
    }

    pub fn get_generation_file_path(&self) -> PathBuf {
        self.gen_path
            .clone()
            .unwrap_or_else(|| crate::daemon::get_runtime_dir().join("clipboard_gen"))
    }

    pub fn current_generation(&self) -> u64 {
        let path = self.get_generation_file_path();
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(val) = content.trim().parse::<u64>() {
                return val;
            }
        }
        self.generation.load(Ordering::SeqCst)
    }

    pub fn next_generation(&self) -> u64 {
        let gen = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let path = self.get_generation_file_path();
        let _ = crate::fs_util::atomic_write_file(&path, gen.to_string().as_bytes(), 0o600);
        gen
    }

    pub fn copy(&self, text: &str, sensitive: bool, timeout_seconds: i64) -> bool {
        self.copy_with_duration(
            text,
            sensitive,
            Duration::from_secs(timeout_seconds.max(0) as u64),
        )
    }

    pub fn copy_with_duration(&self, text: &str, sensitive: bool, timeout: Duration) -> bool {
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
                "Copied content to clipboard (sensitive: {}, ttl: {:?})",
                sensitive,
                timeout
            );
            if sensitive && !timeout.is_zero() {
                self.schedule_auto_clear(timeout);
            }
        }

        success
    }

    fn schedule_auto_clear(&self, timeout: Duration) {
        let expected_gen = self.next_generation();
        let copy_path = self.wl_copy_path.clone();
        let gen_path = self.get_generation_file_path();
        let local_gen = Arc::clone(&self.generation);

        // 1. In-process timer thread: handles daemon, long-lived hosts, and test suites
        let _ = std::thread::Builder::new()
            .name("clipboard-autoclear".into())
            .spawn(move || {
                std::thread::sleep(timeout);
                let cur = if let Ok(content) = fs::read_to_string(&gen_path) {
                    content
                        .trim()
                        .parse::<u64>()
                        .unwrap_or_else(|_| local_gen.load(Ordering::SeqCst))
                } else {
                    local_gen.load(Ordering::SeqCst)
                };

                if cur == expected_gen {
                    let _ = Command::new(&copy_path).arg("--clear").output();
                }
            });

        // 2. Detached worker process: ensures timeout survives CLI parent exit without /bin/sh
        if self.detach_worker && !cfg!(test) {
            if let Ok(current_exe) = std::env::current_exe() {
                let is_omawarden = current_exe
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name == "omawarden" || name.starts_with("omawarden-"));
                if is_omawarden {
                    let mut cmd = Command::new(&current_exe);
                    cmd.args([
                        "copy",
                        "--clear-after",
                        &timeout.as_secs().to_string(),
                        "--expected-gen",
                        &expected_gen.to_string(),
                    ]);
                    if self.wl_copy_path != "wl-copy" {
                        cmd.arg("--wl-copy-path").arg(&self.wl_copy_path);
                    }
                    if let Some(ref custom_gen) = self.gen_path {
                        cmd.arg("--gen-path").arg(custom_gen);
                    }
                    cmd.stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());

                    unsafe {
                        cmd.pre_exec(|| {
                            libc::setsid();
                            Ok(())
                        });
                    }

                    let _ = cmd.spawn();
                }
            }
        }
    }

    pub fn clear(&self) -> bool {
        self.next_generation();
        if !self.is_available() {
            return false;
        }

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

    #[test]
    fn test_auto_clear_timeout() {
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

        let mgr = ClipboardManager::new(mock_wl.to_str().unwrap())
            .with_generation_path(dir.path().join("clipboard_gen"))
            .without_detached_worker();

        assert!(mgr.copy_with_duration("transient_secret", true, Duration::from_millis(150)));
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), "transient_secret");

        // Sleep to let timer expire and clear
        std::thread::sleep(Duration::from_millis(250));
        assert!(!clip_file.exists());
    }

    #[test]
    fn test_auto_clear_reset_by_subsequent_copy() {
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

        let mgr = ClipboardManager::new(mock_wl.to_str().unwrap())
            .with_generation_path(dir.path().join("clipboard_gen"))
            .without_detached_worker();

        assert!(mgr.copy_with_duration("secret_1", true, Duration::from_millis(250)));
        std::thread::sleep(Duration::from_millis(100));
        assert!(mgr.copy_with_duration("secret_2", true, Duration::from_millis(250)));

        // Wait past secret_1's 250ms deadline (now at 300ms from secret_1 start, 200ms from secret_2 start)
        std::thread::sleep(Duration::from_millis(200));
        // secret_2 should STILL be present because secret_1's timer generation mismatched!
        assert_eq!(fs::read_to_string(&clip_file).unwrap(), "secret_2");

        // Now wait for secret_2's timer to expire (another 100ms)
        std::thread::sleep(Duration::from_millis(150));
        assert!(!clip_file.exists());
    }

    #[test]
    fn test_clear_cancels_pending_auto_clear() {
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

        let mgr = ClipboardManager::new(mock_wl.to_str().unwrap())
            .with_generation_path(dir.path().join("clipboard_gen"))
            .without_detached_worker();

        assert!(mgr.copy_with_duration("secret_to_cancel", true, Duration::from_millis(200)));
        std::thread::sleep(Duration::from_millis(50));
        assert!(mgr.clear());
        assert!(!clip_file.exists());

        // Write arbitrary content manually to simulate user copying something unrelated
        fs::write(&clip_file, "unrelated_user_text").unwrap();

        // Wait past original auto-clear timer (200ms)
        std::thread::sleep(Duration::from_millis(250));

        // The unrelated content must NOT have been cleared because clear() invalidated the timer generation
        assert!(clip_file.exists());
        assert_eq!(
            fs::read_to_string(&clip_file).unwrap(),
            "unrelated_user_text"
        );
    }

    #[test]
    fn test_generation_isolation_and_security() {
        let dir = tempdir().unwrap();
        let gen_file = dir.path().join("clipboard_gen");
        let mgr = ClipboardManager::new("wl-copy").with_generation_path(gen_file.clone());

        let g1 = mgr.current_generation();
        let g2 = mgr.next_generation();
        assert!(g2 > g1);
        assert_eq!(mgr.current_generation(), g2);

        // Verify file permissions 0600
        let meta = fs::metadata(&gen_file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
