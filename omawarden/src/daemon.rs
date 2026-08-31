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

use crate::api::BitwardenApiClient;
use crate::crypto::{Engine, BASE64};
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
    pub storage_mgr: StorageManager,
    pub storage: RwLock<VaultStorage>,
    pub decrypted_items: RwLock<Vec<VaultItem>>,
    pub user_key: RwLock<Option<crate::crypto::SymmetricCryptoKey>>,
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
            user_key: RwLock::new(None),
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
        if let Ok(mut key) = self.user_key.write() {
            *key = None;
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

        let items = crate::api::decrypt_sync_ciphers_with_context(
            &fresh_storage.ciphers,
            &fresh_storage.folders,
            &fresh_storage.organizations,
            &user_key,
            fresh_storage.enc_private_key.as_deref(),
        );
        let count = items.len();

        if let Ok(mut dec_items) = self.decrypted_items.write() {
            *dec_items = items;
        }
        if let Ok(mut key) = self.user_key.write() {
            *key = Some(user_key);
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
        let sync_resp_res = client.sync_vault(token);

        let sync_resp = match sync_resp_res {
            Ok(resp) => resp,
            Err(crate::api::ApiError::Http(ref msg)) if msg.contains("401") => {
                if let Some(ref ref_tok) = storage.refresh_token {
                    if let Ok(tok_resp) = client.refresh_token_grant(ref_tok) {
                        let mut updated_tok = storage.clone();
                        updated_tok.access_token = Some(tok_resp.access_token.clone());
                        if let Some(new_ref) = tok_resp.refresh_token {
                            updated_tok.refresh_token = Some(new_ref);
                        }
                        let _ = self.storage_mgr.save(&updated_tok);
                        client
                            .sync_vault(&tok_resp.access_token)
                            .map_err(|e| format!("Sync failed: {}", e))?
                    } else {
                        return Err("Session expired. Please log in again.".to_string());
                    }
                } else {
                    return Err("Session expired. Please log in again.".to_string());
                }
            }
            Err(e) => return Err(format!("Sync failed: {}", e)),
        };

        let count = sync_resp.ciphers.len();
        let mut updated = storage.clone();
        updated.ciphers = sync_resp.ciphers;
        updated.folders = sync_resp.folders;
        updated.collections = sync_resp.collections;
        if let Some(ref prof) = sync_resp.profile {
            if let Some(orgs) = prof.get("organizations").and_then(|v| v.as_array()) {
                updated.organizations = orgs.clone();
            }
        }
        updated.last_sync = Some(chrono::Utc::now().to_rfc3339());

        self.storage_mgr
            .save(&updated)
            .map_err(|e| format!("Failed to save storage: {}", e))?;

        // Re-decrypt all items in memory if unlocked
        if let Ok(key_guard) = self.user_key.read() {
            if let Some(user_key) = key_guard.as_ref() {
                let items = crate::api::decrypt_sync_ciphers_with_context(
                    &updated.ciphers,
                    &updated.folders,
                    &updated.organizations,
                    user_key,
                    updated.enc_private_key.as_deref(),
                );
                if let Ok(mut dec_items) = self.decrypted_items.write() {
                    *dec_items = items;
                }
            }
        }

        if let Ok(mut st) = self.storage.write() {
            *st = updated;
        }

        Ok(count)
    }

    pub fn resolve_attachment_key(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Option<crate::crypto::SymmetricCryptoKey> {
        let user_key_guard = self.user_key.read().ok()?;
        let user_key = user_key_guard.as_ref()?;
        let storage_guard = self.storage.read().ok()?;

        // 1. Resolve user RSA private key if available
        let rsa_priv_key = if let Some(ref enc_priv) = storage_guard.enc_private_key {
            if let Ok(enc_priv_str) = crate::crypto::EncString::parse(enc_priv) {
                if let Ok(der_bytes) = enc_priv_str.decrypt(user_key) {
                    crate::crypto::parse_rsa_private_key_der(&der_bytes).ok()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // 2. Find cipher in storage
        let cipher = storage_guard
            .ciphers
            .iter()
            .find(|c| c.get("id").and_then(|v| v.as_str()) == Some(item_id))?;

        // 3. Resolve base key (Org key or user_key)
        let org_id_opt = cipher.get("organizationId").and_then(|v| v.as_str());
        let mut base_key = user_key.clone();
        if let Some(oid) = org_id_opt {
            if let Some(org) = storage_guard
                .organizations
                .iter()
                .find(|o| o.get("id").and_then(|v| v.as_str()) == Some(oid))
            {
                if let Some(org_key_enc) = org.get("key").and_then(|v| v.as_str()) {
                    if let Ok(enc_str) = crate::crypto::EncString::parse(org_key_enc) {
                        let raw_key = match enc_str.enc_type {
                            3..=6 => {
                                if let Some(ref rsa) = rsa_priv_key {
                                    enc_str.decrypt_rsa(rsa).ok()
                                } else {
                                    None
                                }
                            }
                            0..=2 => enc_str.decrypt(user_key).ok(),
                            _ => None,
                        };
                        if let Some(key_bytes) = raw_key {
                            if let Some(sym_key) =
                                crate::crypto::parse_symmetric_key_from_decrypted_bytes(&key_bytes)
                            {
                                base_key = sym_key;
                            }
                        }
                    }
                }
            }
        }

        // 4. Resolve cipher_key
        let mut cipher_key = base_key.clone();
        if let Some(enc_key_str) = cipher.get("key").and_then(|v| v.as_str()) {
            if let Ok(parsed_k) = crate::crypto::EncString::parse(enc_key_str) {
                let raw_k = parsed_k
                    .decrypt(&base_key)
                    .or_else(|_| parsed_k.decrypt(user_key));
                if let Ok(raw_k_bytes) = raw_k {
                    if let Some(k) =
                        crate::crypto::parse_symmetric_key_from_decrypted_bytes(&raw_k_bytes)
                    {
                        cipher_key = k;
                    }
                }
            }
        }

        // 5. Resolve attachment_key
        if let Some(attachments) = cipher.get("attachments").and_then(|v| v.as_array()) {
            if let Some(att) = attachments
                .iter()
                .find(|a| a.get("id").and_then(|v| v.as_str()) == Some(attachment_id))
            {
                if let Some(att_key_enc) = att.get("key").and_then(|v| v.as_str()) {
                    if let Ok(parsed_k) = crate::crypto::EncString::parse(att_key_enc) {
                        let raw_k = parsed_k
                            .decrypt(&cipher_key)
                            .or_else(|_| parsed_k.decrypt(user_key));
                        if let Ok(raw_k_bytes) = raw_k {
                            if let Some(k) = crate::crypto::parse_symmetric_key_from_decrypted_bytes(
                                &raw_k_bytes,
                            ) {
                                return Some(k);
                            }
                        }
                    }
                }
            }
        }

        Some(cipher_key)
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
        "get_attachment_key" => {
            let item_id = req.get("item_id").and_then(|v| v.as_str()).unwrap_or("");
            let attachment_id = req
                .get("attachment_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(key) = state.resolve_attachment_key(item_id, attachment_id) {
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
            let secret = req.get("secret").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(res) = crate::totp::generate_totp(secret, None, 6, 30) {
                json!({ "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period })
            } else {
                json!({ "ok": false, "error": "Invalid TOTP secret" })
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
        assert!(!*state.is_unlocked.read().unwrap());

        // Lock
        state.lock();
        assert!(!*state.is_unlocked.read().unwrap());
        assert_eq!(state.decrypted_items.read().unwrap().len(), 0);
    }

    #[test]
    fn test_daemon_totp_action() {
        let res = crate::totp::generate_totp("JBSWY3DPEHPK3PXP", None, 6, 30);
        assert!(res.is_some());
        let totp_res = res.unwrap();
        assert_eq!(totp_res.code.len(), 6);
    }
}
