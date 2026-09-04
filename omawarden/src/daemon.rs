use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::{Engine, BASE64};
use crate::storage::StorageManager;
use crate::vault::VaultManager;

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
    pub vault_mgr: Arc<VaultManager>,
    pub last_activity: Mutex<Instant>,
    pub auto_lock_duration: Duration,
}

impl DaemonState {
    pub fn new(storage_mgr: StorageManager, auto_lock_minutes: u64) -> Self {
        let vault_mgr = Arc::new(VaultManager::new("", Some(storage_mgr), None));
        Self {
            vault_mgr,
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
        self.vault_mgr.lock();
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let res = self.vault_mgr.unlock(password);
        if res.is_ok() {
            self.touch_activity();
        }
        res
    }

    pub fn sync(&self) -> Result<usize, String> {
        self.vault_mgr.sync()
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
        let is_unlocked = state_clone.vault_mgr.is_unlocked();
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
        "ping" => json!({
            "ok": true,
            "pong": true,
            "version": env!("CARGO_PKG_VERSION"),
            "commit": env!("GIT_HASH"),
        }),
        "stop" => {
            let _ = writeln!(stream, "{}", json!({ "ok": true }));
            let _ = stream.flush();
            std::process::exit(0);
        }
        "status" => state.vault_mgr.get_status(),
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
            let clip_mgr = crate::clipboard::ClipboardManager::default();
            if clip_mgr.copy(text, sensitive, timeout) {
                json!({ "ok": true })
            } else {
                json!({ "ok": false, "error": "Failed to copy to clipboard" })
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
}
