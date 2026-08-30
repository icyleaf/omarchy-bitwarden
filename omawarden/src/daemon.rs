use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::api::{decrypt_sync_ciphers, BitwardenApiClient};
use crate::storage::{StorageManager, VaultStorage};
use crate::vault::{VaultItem, VaultManager};

use std::os::unix::process::CommandExt;

pub fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("omawarden.sock")
    } else {
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/omawarden-{}.sock", uid))
    }
}

pub fn ensure_daemon_running() {
    if send_daemon_request(&json!({ "action": "ping" })).is_some() {
        return;
    }

    if let Ok(exe_path) = env::current_exe() {
        let mut cmd = Command::new(exe_path);
        cmd.arg("daemon")
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

    let mut stream = UnixStream::connect(socket_path).ok()?;
    let payload = format!("{}\n", req);
    stream.write_all(payload.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).ok()?;

    serde_json::from_str(&response_line).ok()
}

pub struct DaemonState {
    pub storage_mgr: StorageManager,
    pub storage: RwLock<VaultStorage>,
    pub decrypted_items: RwLock<Vec<VaultItem>>,
    pub is_unlocked: RwLock<bool>,
    pub last_activity: Mutex<Instant>,
    pub auto_lock_duration: Duration,
}

impl DaemonState {
    pub fn new(storage_mgr: StorageManager, auto_lock_minutes: u64) -> Self {
        let storage = storage_mgr.load();
        Self {
            storage_mgr,
            storage: RwLock::new(storage),
            decrypted_items: RwLock::new(Vec::new()),
            is_unlocked: RwLock::new(false),
            last_activity: Mutex::new(Instant::now()),
            auto_lock_duration: Duration::from_secs(auto_lock_minutes * 60),
        }
    }

    pub fn touch_activity(&self) {
        if let Ok(mut act) = self.last_activity.lock() {
            *act = Instant::now();
        }
    }

    pub fn lock(&self) {
        if let Ok(mut unl) = self.is_unlocked.write() {
            *unl = false;
        }
        if let Ok(mut items) = self.decrypted_items.write() {
            items.clear();
        }
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let fresh_storage = self.storage_mgr.load();
        if fresh_storage.enc_user_key.is_none() {
            return Err("Account not logged in or missing encryption keys.".to_string());
        }

        let user_key = self
            .storage_mgr
            .unlock_user_key(password, &fresh_storage)
            .map_err(|e| format!("Unlock failed: {:?}", e))?;

        let items = decrypt_sync_ciphers(&fresh_storage.ciphers, &user_key);
        let count = items.len();

        if let Ok(mut dec_items) = self.decrypted_items.write() {
            *dec_items = items;
        }
        if let Ok(mut unl) = self.is_unlocked.write() {
            *unl = true;
        }
        if let Ok(mut st) = self.storage.write() {
            *st = fresh_storage;
        }
        self.touch_activity();

        Ok(count)
    }

    pub fn sync(&self) -> Result<usize, String> {
        let storage = self.storage_mgr.load();
        let token = storage
            .access_token
            .as_ref()
            .ok_or_else(|| "Session token missing. Please log in.".to_string())?;

        let client = BitwardenApiClient::new(&storage.server_url);
        let sync_resp = client
            .sync_vault(token)
            .map_err(|e| format!("Sync failed: {}", e))?;

        let count = sync_resp.ciphers.len();
        let mut updated = storage.clone();
        updated.ciphers = sync_resp.ciphers;
        updated.last_sync = Some(chrono::Utc::now().to_rfc3339());

        self.storage_mgr
            .save(&updated)
            .map_err(|e| format!("Failed to save storage: {}", e))?;

        if let Ok(mut st) = self.storage.write() {
            *st = updated;
        }

        Ok(count)
    }
}

pub fn run_daemon_server(state: Arc<DaemonState>) -> std::io::Result<()> {
    let socket_path = get_socket_path();
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path)?;
    let mut perms = fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&socket_path, perms)?;

    let state_clone = state.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let is_unlocked = state_clone.is_unlocked.read().map(|g| *g).unwrap_or(false);
        if is_unlocked {
            if let Ok(last) = state_clone.last_activity.lock() {
                if last.elapsed() > state_clone.auto_lock_duration {
                    state_clone.lock();
                }
            }
        }
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

fn handle_client(mut stream: UnixStream, state: Arc<DaemonState>) -> std::io::Result<()> {
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

    state.touch_activity();
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");

    let response = match action {
        "ping" => json!({ "ok": true, "pong": true }),
        "status" => {
            let is_unlocked = state.is_unlocked.read().map(|g| *g).unwrap_or(false);
            let fresh_storage = state.storage_mgr.load();
            json!({
                "ok": true,
                "status": if is_unlocked { "unlocked" } else if fresh_storage.enc_user_key.is_some() { "locked" } else { "unauthenticated" },
                "server_url": fresh_storage.server_url,
                "user_email": fresh_storage.user_email,
                "user_id": fresh_storage.user_id,
                "last_sync": fresh_storage.last_sync,
                "is_unlocked": is_unlocked,
                "items_count": state.decrypted_items.read().map(|i| i.len()).unwrap_or(0),
            })
        }
        "unlock" => {
            let pwd = req.get("password").and_then(|v| v.as_str()).unwrap_or("");
            match state.unlock(pwd) {
                Ok(count) => json!({ "ok": true, "status": "unlocked", "items_count": count }),
                Err(e) => json!({ "ok": false, "status": "locked", "error": e }),
            }
        }
        "lock" => {
            state.lock();
            json!({ "ok": true, "status": "locked" })
        }
        "sync" => match state.sync() {
            Ok(count) => json!({ "ok": true, "ciphers_count": count }),
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "list" => {
            let is_unlocked = state.is_unlocked.read().map(|g| *g).unwrap_or(false);
            if !is_unlocked {
                json!([])
            } else {
                let items = state.decrypted_items.read().unwrap().clone();
                json!(items)
            }
        }
        "search" => {
            let is_unlocked = state.is_unlocked.read().map(|g| *g).unwrap_or(false);
            if !is_unlocked {
                json!([])
            } else {
                let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
                let category = req.get("category").and_then(|v| v.as_str());
                let items = state.decrypted_items.read().unwrap().clone();
                let vault_mgr = VaultManager::new("", None, None);
                let results = vault_mgr.search(&items, query, category);
                json!(results)
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
        assert!(!*state.is_unlocked.read().unwrap());

        // Lock
        state.lock();
        assert!(!*state.is_unlocked.read().unwrap());
        assert_eq!(state.decrypted_items.read().unwrap().len(), 0);
    }
}
