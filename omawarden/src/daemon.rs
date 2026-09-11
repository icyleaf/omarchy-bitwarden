use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::{Engine, BASE64};
use crate::storage::StorageManager;
use crate::vault::VaultManager;

use std::os::unix::process::CommandExt;

/// Resolves the secure runtime directory for daemon sockets and IPC.
///
/// Precedence:
/// 1. `XDG_RUNTIME_DIR`: Verified to exist, owned by current UID, and not a symlink.
/// 2. Fallback: Creates an isolated `/tmp/omawarden-runtime-{uid}/` directory with mode `0700`.
pub fn get_runtime_dir() -> PathBuf {
    let current_uid = unsafe { libc::getuid() };

    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir);
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if !meta.file_type().is_symlink() && meta.uid() == current_uid {
                return p;
            }
        }
    }

    let fallback = env::temp_dir().join(format!("omawarden-runtime-{}", current_uid));
    let _ = crate::fs_util::create_secure_dir_all(&fallback, 0o700);
    fallback
}

pub fn get_socket_path() -> PathBuf {
    get_runtime_dir().join("omawarden.sock")
}

/// Validates that a socket file (and its parent directory) is owned by the current UID
/// and is not a symlink to prevent cross-user socket hijacking or TOCTOU attacks.
pub fn validate_socket_path(path: &Path) -> std::io::Result<()> {
    let current_uid = unsafe { libc::getuid() };

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Socket path '{}' is a symlink (potential hijacking attempt)",
                    path.display()
                ),
            ));
        }

        if meta.uid() != current_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Socket path '{}' is owned by foreign UID {} (expected current UID {})",
                    path.display(),
                    meta.uid(),
                    current_uid
                ),
            ));
        }
    }

    if let Some(parent) = path.parent() {
        if let Ok(parent_meta) = fs::symlink_metadata(parent) {
            if parent_meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Socket parent directory '{}' is a symlink (potential hijacking attempt)",
                        parent.display()
                    ),
                ));
            }

            if parent_meta.uid() != current_uid
                && parent != Path::new("/tmp")
                && parent != Path::new("/var/tmp")
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Socket parent directory '{}' is owned by foreign UID {} (expected current UID {})",
                        parent.display(),
                        parent_meta.uid(),
                        current_uid
                    ),
                ));
            }
        }
    }

    Ok(())
}

pub fn ensure_daemon_running() {
    if let Some(resp) = send_daemon_request(&json!({ "action": "ping" })) {
        let running_commit = resp.get("commit").and_then(|v| v.as_str()).unwrap_or("");
        if running_commit == env!("GIT_HASH") {
            return;
        }
        // Outdated daemon running: gracefully stop it so we can spawn the latest binary version
        let _ = send_daemon_request(&json!({ "action": "stop" }));
        std::thread::sleep(Duration::from_millis(50));
    }

    if let Ok(exe_path) = env::current_exe() {
        let cfg = crate::config::ConfigManager::default().load();
        let auto_lock_mins = if cfg.auto_lock_minutes >= 0 {
            cfg.auto_lock_minutes as u64
        } else {
            15
        };

        let mut cmd = Command::new(exe_path);
        cmd.arg("daemon")
            .arg("--auto-lock")
            .arg(auto_lock_mins.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        let _ = cmd.spawn();

        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(20));
            if send_daemon_request(&json!({ "action": "ping" })).is_some() {
                break;
            }
        }
    }
}

pub fn send_daemon_request(req: &Value) -> Option<Value> {
    let socket_path = get_socket_path();
    if !socket_path.exists() {
        return None;
    }

    if let Err(e) = validate_socket_path(&socket_path) {
        crate::log_error!(
            "omawarden:daemon",
            "Refusing to connect to socket {}: {}",
            socket_path.display(),
            e
        );
        return None;
    }

    let mut stream = UnixStream::connect(&socket_path).ok()?;

    // Mutual SO_PEERCRED verification: client verifies that server process UID matches current UID
    if let Err(e) = verify_peer_credentials(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Refusing to send request: server peer UID verification failed: {}",
            e
        );
        return None;
    }

    let payload = format!("{}\n", req);
    stream.write_all(payload.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).ok()?;

    serde_json::from_str(&response_line).ok()
}

pub struct DaemonState {
    pub vault_mgr: Arc<VaultManager>,
    pub last_activity: Mutex<Instant>,
    pub auto_lock_duration: Mutex<Duration>,
    pub unlocked_at: Mutex<Option<Instant>>,
    pub max_session_lifetime: Mutex<Duration>,
}

impl DaemonState {
    pub fn new(storage_mgr: StorageManager, auto_lock_minutes: u64) -> Self {
        let vault_mgr = Arc::new(VaultManager::new("", Some(storage_mgr), None));
        Self {
            vault_mgr,
            last_activity: Mutex::new(Instant::now()),
            auto_lock_duration: Mutex::new(Duration::from_secs(auto_lock_minutes * 60)),
            unlocked_at: Mutex::new(None),
            max_session_lifetime: Mutex::new(Duration::from_secs(12 * 3600)),
        }
    }

    pub fn set_auto_lock_duration(&self, duration: Duration) {
        if let Ok(mut dur) = self.auto_lock_duration.lock() {
            *dur = duration;
        }
    }

    pub fn set_auto_lock_minutes(&self, minutes: u64) {
        self.set_auto_lock_duration(Duration::from_secs(minutes * 60));
    }

    pub fn check_auto_lock(&self) -> bool {
        if self.vault_mgr.is_unlocked() {
            // 1. Check absolute maximum session lifetime (e.g. 12 hours)
            let max_lifetime_expired = {
                if let Ok(ua_guard) = self.unlocked_at.lock() {
                    if let Some(unlocked_time) = *ua_guard {
                        if let Ok(max_dur) = self.max_session_lifetime.lock() {
                            !max_dur.is_zero() && unlocked_time.elapsed() > *max_dur
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if max_lifetime_expired {
                crate::log_info!(
                    "omawarden:daemon",
                    "Maximum session lifetime reached; locking vault"
                );
                self.lock();
                crate::attachment::clear_preview_attachments(None);
                return true;
            }

            // 2. Check idle inactivity timeout
            let idle_expired = {
                if let Ok(dur) = self.auto_lock_duration.lock() {
                    if !dur.is_zero() {
                        if let Ok(last) = self.last_activity.lock() {
                            last.elapsed() > *dur
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if idle_expired {
                crate::log_info!("omawarden:daemon", "Idle timeout elapsed; locking vault");
                self.lock();
                crate::attachment::clear_preview_attachments(None);
                return true;
            }
        }
        false
    }

    pub fn check_screen_lock(&self) -> bool {
        self.check_screen_lock_with(is_system_or_screen_locked)
    }

    pub fn check_screen_lock_with<F>(&self, detector: F) -> bool
    where
        F: FnOnce() -> bool,
    {
        if self.vault_mgr.is_unlocked() && detector() {
            self.lock();
            crate::attachment::clear_preview_attachments(None);
            return true;
        }
        false
    }

    pub fn touch_activity(&self) {
        if let Ok(mut act) = self.last_activity.lock() {
            *act = Instant::now();
        }
    }

    pub fn lock(&self) {
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        self.vault_mgr.lock();
        let _ = crate::clipboard::ClipboardManager::default()
            .without_detached_worker()
            .clear();
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let count = self.vault_mgr.unlock(password)?;
        if let Ok(mut ua_guard) = self.unlocked_at.lock() {
            *ua_guard = Some(Instant::now());
        }
        self.touch_activity();
        Ok(count)
    }

    pub fn sync(&self) -> Result<usize, String> {
        let res = self.vault_mgr.sync();
        if res.is_ok() {
            self.touch_activity();
        }
        res
    }
}

pub fn should_touch_activity(action: &str, req: &Value) -> bool {
    if let Some(touch) = req.get("touch").and_then(|v| v.as_bool()) {
        return touch;
    }
    matches!(
        action,
        "sync"
            | "list"
            | "search"
            | "ssh_key_create"
            | "get_item"
            | "get_ssh_key"
            | "get_attachment_key"
            | "copy"
    )
}

pub fn run_daemon_server(state: Arc<DaemonState>) -> std::io::Result<()> {
    let socket_path = get_socket_path();
    if socket_path.exists() {
        validate_socket_path(&socket_path)?;
        let _ = fs::remove_file(&socket_path);
    }

    if let Some(parent) = socket_path.parent() {
        crate::fs_util::create_secure_dir_all(parent, 0o700)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    let mut perms = fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&socket_path, perms)?;

    let state_clone = state.clone();
    std::thread::spawn(move || loop {
        let is_unlocked = state_clone.vault_mgr.is_unlocked();
        let sleep_duration = if is_unlocked {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(5)
        };
        std::thread::sleep(sleep_duration);
        state_clone.check_auto_lock();
        state_clone.check_screen_lock();
    });

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let st = state.clone();
                std::thread::spawn(move || {
                    let _ = handle_client(stream, st);
                });
            }
            Err(e) => {
                eprintln!("Socket accept error: {}", e);
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn verify_peer_credentials(stream: &UnixStream) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut ucred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut ucred_len,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let current_uid = unsafe { libc::getuid() };
    if ucred.uid != current_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Peer UID mismatch: expected {}, got {}",
                current_uid, ucred.uid
            ),
        ));
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_peer_credentials(_stream: &UnixStream) -> std::io::Result<()> {
    Ok(())
}

pub const SCREEN_LOCKER_PROCESS_NAMES: &[&str] = &["hyprlock", "swaylock", "waylock", "gtklock"];

pub fn get_omarchy_shell_cmd() -> Option<PathBuf> {
    if which::which("omarchy-shell").is_ok() {
        return Some(PathBuf::from("omarchy-shell"));
    }
    if let Ok(home) = env::var("HOME") {
        let candidate = PathBuf::from(home).join(".local/share/omarchy/bin/omarchy-shell");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn is_omarchy_locked() -> bool {
    let cmd_name = match get_omarchy_shell_cmd() {
        Some(cmd) => cmd,
        None => return false,
    };

    if let Ok(output) = Command::new(cmd_name).args(["lock", "isLocked"]).output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "true" {
                return true;
            }
        }
    }
    false
}

pub fn is_screen_locker_running() -> bool {
    let locker_regex = SCREEN_LOCKER_PROCESS_NAMES.join("|");
    if let Ok(output) = Command::new("pgrep").args(["-x", &locker_regex]).output() {
        if output.status.success() && !output.stdout.is_empty() {
            return true;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                if let Some(name_str) = file_name.to_str() {
                    if name_str.chars().all(|c| c.is_ascii_digit()) {
                        let comm_path = entry.path().join("comm");
                        if let Ok(comm) = fs::read_to_string(comm_path) {
                            let comm = comm.trim();
                            if SCREEN_LOCKER_PROCESS_NAMES.contains(&comm) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

pub fn is_logind_locked_or_sleeping() -> bool {
    // 1. Check session LockedHint
    if let Ok(output) = Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1/session/auto",
            "org.freedesktop.login1.Session",
            "LockedHint",
        ])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "b true" {
                return true;
            }
        }
    }

    // 2. Check Manager PreparingForSleep
    if let Ok(output) = Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "PreparingForSleep",
        ])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "b true" {
                return true;
            }
        }
    }

    false
}

pub fn is_system_or_screen_locked() -> bool {
    is_omarchy_locked() || is_screen_locker_running() || is_logind_locked_or_sleeping()
}

fn handle_client(mut stream: UnixStream, state: Arc<DaemonState>) -> std::io::Result<()> {
    if let Err(e) = verify_peer_credentials(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Client connection rejected: peer credential check failed: {}",
            e
        );
        let err = json!({ "ok": false, "error": "Access denied: client UID mismatch" });
        let _ = writeln!(stream, "{}", err);
        return Ok(());
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if line.trim().is_empty() {
        return Ok(());
    }

    let req: Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(_) => {
            let err = json!({ "ok": false, "error": "Malformed JSON request" });
            let _ = writeln!(stream, "{}", err);
            return Ok(());
        }
    };

    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let is_unlocked = state.vault_mgr.is_unlocked();

    let is_privileged = matches!(
        action,
        "list"
            | "search"
            | "get_item"
            | "get_ssh_key"
            | "get_attachment_key"
            | "ssh_key_create"
            | "sync"
    ) || (action == "totp"
        && (req.get("query").is_some() || req.get("id").is_some()))
        || ((action == "stop" || action == "set_auto_lock") && is_unlocked);

    if is_privileged && !is_unlocked {
        let _ = writeln!(
            stream,
            "{}",
            json!({ "ok": false, "error": "Vault is locked. Please unlock the vault first." })
        );
        return Ok(());
    }

    if should_touch_activity(action, &req) {
        state.touch_activity();
    }

    let response = match action {
        "ping" => json!({
            "ok": true,
            "pong": true,
            "version": env!("CARGO_PKG_VERSION"),
            "commit": env!("GIT_HASH"),
        }),
        "stop" => {
            state.lock();
            crate::attachment::clear_preview_attachments(None);
            let _ = writeln!(stream, "{}", json!({ "ok": true }));
            let _ = stream.flush();
            std::process::exit(0);
        }
        "status" => state.vault_mgr.get_status(),
        "unlock" => {
            let pwd = req.get("password").and_then(|v| v.as_str()).unwrap_or("");
            match state.unlock(pwd) {
                Ok(count) => json!({
                    "ok": true,
                    "status": "unlocked",
                    "items_count": count,
                }),
                Err(e) => json!({ "ok": false, "status": "locked", "error": e }),
            }
        }
        "lock" => {
            state.lock();
            crate::attachment::clear_preview_attachments(None);
            json!({ "ok": true, "status": "locked" })
        }
        "sync" => match state.sync() {
            Ok(count) => json!({ "ok": true, "ciphers_count": count }),
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "list" => json!(state.vault_mgr.get_items()),
        "search" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let category = req.get("category").and_then(|v| v.as_str());
            json!(state.vault_mgr.search_items(query, category))
        }
        "ssh_key_create" => {
            if let Some(user_key) = state.vault_mgr.get_user_key() {
                let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let priv_k = req
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let pub_k = req.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
                let fp = req
                    .get("fingerprint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let notes = req.get("notes").and_then(|v| v.as_str());
                let folder_id = req.get("folder_id").and_then(|v| v.as_str());

                let ssh_data = crate::ssh::GeneratedSshKey {
                    algorithm_name: String::new(),
                    private_key: priv_k.to_string(),
                    public_key: pub_k.to_string(),
                    fingerprint: fp.to_string(),
                };

                match state
                    .vault_mgr
                    .create_ssh_key(name, &ssh_data, notes, folder_id, &user_key)
                {
                    Ok(item) => json!({ "ok": true, "item": item }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            } else {
                json!({ "ok": false, "error": "Vault is locked. Please unlock the vault first." })
            }
        }
        "get_item" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let category = req.get("category").and_then(|v| v.as_str());
            if let Some(item) = state.vault_mgr.find_item(query, category) {
                json!({ "ok": true, "item": item })
            } else {
                json!({ "ok": false, "error": format!("Item '{}' not found in vault", query) })
            }
        }
        "get_ssh_key" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(item) = state.vault_mgr.find_ssh_key(query) {
                json!({ "ok": true, "item": item })
            } else {
                json!({ "ok": false, "error": format!("SSH key item '{}' not found", query) })
            }
        }
        "get_attachment_key" => {
            let item_id = req.get("item_id").and_then(|v| v.as_str()).unwrap_or("");
            let attachment_id = req
                .get("attachment_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(key) = state
                .vault_mgr
                .resolve_attachment_key(item_id, attachment_id)
            {
                let mut raw = Vec::new();
                raw.extend_from_slice(&key.enc_key);
                if let Some(mac_k) = key.mac_key {
                    raw.extend_from_slice(&mac_k);
                }
                json!({
                    "ok": true,
                    "key_b64": BASE64.encode(&raw)
                })
            } else {
                json!({ "ok": false, "error": "Unable to resolve attachment key (vault locked or missing item)" })
            }
        }
        "totp" => {
            let secret = req.get("secret").and_then(|v| v.as_str());
            let query = req
                .get("query")
                .or_else(|| req.get("id"))
                .and_then(|v| v.as_str());

            if let Some(q) = query {
                if let Some(item) = state.vault_mgr.find_item(q, None) {
                    let totp_seed = item
                        .login
                        .as_ref()
                        .and_then(|l| l.get("totp"))
                        .and_then(|v| v.as_str());
                    if let Some(seed) = totp_seed {
                        if let Some(res) = crate::totp::generate_totp(seed, None, 6, 30) {
                            json!({
                                "ok": true,
                                "code": res.code,
                                "ttl": res.ttl,
                                "period": res.period,
                                "id": item.id,
                                "name": item.name
                            })
                        } else {
                            json!({ "ok": false, "error": "Item has invalid TOTP configuration" })
                        }
                    } else {
                        json!({ "ok": false, "error": format!("Item '{}' has no TOTP configured", item.name) })
                    }
                } else {
                    json!({ "ok": false, "error": format!("Item '{}' not found in vault", q) })
                }
            } else if let Some(sec) = secret {
                if let Some(res) = crate::totp::generate_totp(sec, None, 6, 30) {
                    json!({ "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period })
                } else {
                    json!({ "ok": false, "error": "Invalid TOTP secret" })
                }
            } else {
                json!({ "ok": false, "error": "Missing TOTP secret or item query" })
            }
        }
        "copy" => {
            let text = req.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let sensitive = req
                .get("sensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let timeout = req.get("timeout").and_then(|v| v.as_i64()).unwrap_or(30);
            let clip_mgr = crate::clipboard::ClipboardManager::default().without_detached_worker();
            if clip_mgr.copy(text, sensitive, timeout) {
                json!({ "ok": true })
            } else {
                json!({ "ok": false, "error": "Failed to copy to clipboard" })
            }
        }
        "set_auto_lock" => {
            if let Some(secs) = req.get("auto_lock_seconds").and_then(|v| v.as_u64()) {
                state.set_auto_lock_duration(Duration::from_secs(secs));
                json!({ "ok": true, "auto_lock_seconds": secs })
            } else {
                let mins = req
                    .get("auto_lock")
                    .or_else(|| req.get("auto_lock_minutes"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(15);
                state.set_auto_lock_minutes(mins);
                json!({ "ok": true, "auto_lock_minutes": mins })
            }
        }
        other => json!({ "ok": false, "error": format!("Unknown action: {}", other) }),
    };

    let _ = writeln!(stream, "{}", response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_daemon_state_lifecycle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);

        let state = DaemonState::new(storage_mgr, 15);
        assert!(!state.vault_mgr.is_unlocked());

        // Lock
        state.lock();
        assert!(!state.vault_mgr.is_unlocked());
        assert_eq!(state.vault_mgr.decrypted_items.read().unwrap().len(), 0);
    }

    #[test]
    fn test_daemon_totp_action() {
        let res = crate::totp::generate_totp("JBSWY3DPEHPK3PXP", None, 6, 30);
        assert!(res.is_some());
        let totp_res = res.unwrap();
        assert_eq!(totp_res.code.len(), 6);
    }

    #[test]
    fn test_daemon_totp_action_with_item_query() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);

        let state = DaemonState::new(storage_mgr, 15);
        let test_item = crate::vault::VaultItem {
            id: "item-totp-123".to_string(),
            name: "Github 2FA".to_string(),
            item_type: 1,
            type_name: "login".to_string(),
            sub_title: "user@github.com".to_string(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(serde_json::json!({
                "username": "user",
                "totp": "JBSWY3DPEHPK3PXP"
            })),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: "github 2fa user".to_string(),
        };

        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state
            .vault_mgr
            .decrypted_items
            .write()
            .unwrap()
            .push(test_item);

        // Find by ID
        let found = state.vault_mgr.find_item("item-totp-123", None);
        assert!(found.is_some());
        let seed = found
            .unwrap()
            .login
            .unwrap()
            .get("totp")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let res = crate::totp::generate_totp(&seed, None, 6, 30);
        assert!(res.is_some());
        assert_eq!(res.unwrap().code.len(), 6);

        // Find by Name
        let found_name = state.vault_mgr.find_item("Github", None);
        assert!(found_name.is_some());
    }

    #[test]
    fn test_should_touch_activity_classification() {
        // Passive actions must not touch activity
        for action in &[
            "ping",
            "status",
            "stop",
            "lock",
            "totp",
            "set_auto_lock",
            "unknown_action",
            "",
        ] {
            assert!(
                !should_touch_activity(action, &json!({ "action": action })),
                "Action '{}' should not touch activity",
                action
            );
        }

        // Active user actions must touch activity
        for action in &[
            "sync",
            "list",
            "search",
            "ssh_key_create",
            "get_item",
            "get_ssh_key",
            "get_attachment_key",
            "copy",
        ] {
            assert!(
                should_touch_activity(action, &json!({ "action": action })),
                "Action '{}' should touch activity",
                action
            );
        }

        // Explicit touch: false must override active actions
        let req_touch_false = json!({ "action": "list", "touch": false });
        assert!(!should_touch_activity("list", &req_touch_false));

        // Explicit touch: true must override passive actions
        let req_touch_true = json!({ "action": "ping", "touch": true });
        assert!(should_touch_activity("ping", &req_touch_true));
    }

    #[test]
    fn test_handle_client_selective_activity_touch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        // Set initial activity to a known point in the past
        let past = Instant::now() - Duration::from_secs(10);
        *state.last_activity.lock().unwrap() = past;

        // Helper to send a request via UnixStream pair and receive response
        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. "ping" without touch should not touch activity
        let res = send_req(json!({ "action": "ping" }));
        assert_eq!(res.get("pong").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 2. "status" without touch should not touch activity
        let _ = send_req(json!({ "action": "status" }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 3. "totp" with raw secret should not touch activity
        let _ = send_req(json!({ "action": "totp", "secret": "JBSWY3DPEHPK3PXP" }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 4. "get_item" with explicit touch: false should not touch activity
        let _ = send_req(json!({ "action": "get_item", "query": "none", "touch": false }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 5. "ping" with explicit touch: true DOES touch activity
        let ping_touch_res = send_req(json!({ "action": "ping", "touch": true }));
        assert_eq!(
            ping_touch_res.get("pong").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(*state.last_activity.lock().unwrap() > past);

        // Reset past activity for subsequent test
        *state.last_activity.lock().unwrap() = past;

        // 6. Active action (e.g. "search") should touch activity
        let search_res = send_req(json!({ "action": "search", "query": "test" }));
        assert!(search_res.is_array());
        assert!(*state.last_activity.lock().unwrap() > past);
    }

    #[test]
    fn test_background_pings_do_not_prevent_idle_auto_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        // Configure a short timeout (100ms) for testing
        state.set_auto_lock_duration(Duration::from_millis(100));

        // Unlock the vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.vault_mgr.is_unlocked());

        // Send repeated pings over 150ms (crossing the 100ms threshold)
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(150) {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", json!({ "action": "ping" }));
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();
            handle.join().unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }

        // Auto-lock check must lock the vault despite the continuous background pings
        assert!(state.check_auto_lock());
        assert!(!state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_set_auto_lock_action() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // Update with minutes
        let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_minutes": 5 }));
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            *state.auto_lock_duration.lock().unwrap(),
            Duration::from_secs(300)
        );

        // Update with seconds
        let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_seconds": 45 }));
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            *state.auto_lock_duration.lock().unwrap(),
            Duration::from_secs(45)
        );
    }

    #[test]
    fn test_verify_peer_credentials() {
        let (client, server) = UnixStream::pair().unwrap();
        assert!(verify_peer_credentials(&client).is_ok());
        assert!(verify_peer_credentials(&server).is_ok());
    }

    #[test]
    fn test_check_screen_lock_custom_detector() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = DaemonState::new(storage_mgr, 15);

        // Vault is initially locked: detector should not be invoked or return false
        let mut called = false;
        assert!(!state.check_screen_lock_with(|| {
            called = true;
            true
        }));
        assert!(!called);
        assert!(!state.vault_mgr.is_unlocked());

        // Unlock the vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.vault_mgr.is_unlocked());

        // Detector returns false -> vault remains unlocked
        assert!(!state.check_screen_lock_with(|| false));
        assert!(state.vault_mgr.is_unlocked());

        // Detector returns true -> vault locks immediately
        assert!(state.check_screen_lock_with(|| true));
        assert!(!state.vault_mgr.is_unlocked());

        // Subsequent call returns false because already locked
        assert!(!state.check_screen_lock_with(|| true));
    }

    #[test]
    fn test_screen_lock_detection_functions_safe() {
        // Ensure detection functions execute safely without panicking
        let _ = is_omarchy_locked();
        let _ = is_screen_locker_running();
        let _ = is_logind_locked_or_sleeping();
        let _ = is_system_or_screen_locked();
    }

    #[test]
    fn test_validate_socket_path_valid_and_symlink_rejection() {
        let dir = tempdir().unwrap();
        let real_socket = dir.path().join("real.sock");
        fs::write(&real_socket, b"").unwrap();

        // Valid socket file owned by current user
        assert!(validate_socket_path(&real_socket).is_ok());

        // Symlink pointing to the real socket must be rejected
        let symlink_socket = dir.path().join("symlink.sock");
        std::os::unix::fs::symlink(&real_socket, &symlink_socket).unwrap();
        let err = validate_socket_path(&symlink_socket);
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_validate_socket_path_parent_symlink_rejection() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_runtime");
        fs::create_dir_all(&real_dir).unwrap();

        let symlink_dir = dir.path().join("symlink_runtime");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let socket_in_symlink_parent = symlink_dir.join("omawarden.sock");
        let err = validate_socket_path(&socket_in_symlink_parent);
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_get_runtime_dir_permissions_and_ownership() {
        let runtime_dir = get_runtime_dir();
        assert!(runtime_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&runtime_dir).unwrap();
            assert_eq!(meta.uid(), unsafe { libc::getuid() });
        }
    }

    #[test]
    fn test_privileged_actions_require_unlocked_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let privileged_actions = vec![
            json!({ "action": "list" }),
            json!({ "action": "search", "query": "test" }),
            json!({ "action": "get_item", "query": "test" }),
            json!({ "action": "get_ssh_key", "query": "test" }),
            json!({ "action": "get_attachment_key", "item_id": "i", "attachment_id": "a" }),
            json!({ "action": "sync" }),
            json!({ "action": "totp", "query": "test" }),
        ];

        // 1. While locked, all privileged actions fail with locked error
        for req in &privileged_actions {
            let res = send_req(req.clone());
            assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
            assert!(
                res.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .contains("locked"),
                "Action '{}' should fail when vault is locked",
                req.get("action").unwrap()
            );
        }

        // 2. Unlock vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        // 3. When unlocked, privileged actions proceed without needing any session token
        let list_res = send_req(json!({ "action": "list" }));
        assert!(list_res.is_array(), "List should succeed when unlocked");

        let search_res = send_req(json!({ "action": "search", "query": "test" }));
        assert!(search_res.is_array(), "Search should succeed when unlocked");
    }

    #[test]
    fn test_max_session_lifetime_auto_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = DaemonState::new(storage_mgr, 15);

        // Vault unlocked 2 hours ago with max lifetime of 1 hour
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        *state.unlocked_at.lock().unwrap() = Some(Instant::now() - Duration::from_secs(7200));
        *state.max_session_lifetime.lock().unwrap() = Duration::from_secs(3600);

        // Keep last_activity brand new (just now) so idle timeout would NOT trigger
        *state.last_activity.lock().unwrap() = Instant::now();

        // check_auto_lock must trigger because max_session_lifetime has elapsed!
        assert!(state.check_auto_lock());
        assert!(!state.vault_mgr.is_unlocked());
        assert!(state.unlocked_at.lock().unwrap().is_none());
    }
}
