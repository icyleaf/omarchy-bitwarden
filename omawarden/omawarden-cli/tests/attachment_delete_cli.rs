use omawarden_engine::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ipc(socket: &Path, request: Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e)
                if e.kind() == ErrorKind::ConnectionRefused || e.kind() == ErrorKind::NotFound =>
            {
                assert!(
                    Instant::now() < deadline,
                    "daemon socket not ready after 5s"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("{e}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

fn read_http_request(stream: &mut TcpStream) -> HttpRequest {
    let _ = stream.set_nonblocking(false);
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let parts: Vec<&str> = line.split_whitespace().collect();
    let method = parts[0].to_owned();
    let path = parts[1].to_owned();
    let mut headers = HashMap::new();
    let mut size = 0usize;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                size = val.parse().unwrap();
            }
            headers.insert(key, val);
        }
    }
    let mut body = vec![0u8; size];
    reader.read_exact(&mut body).unwrap();
    HttpRequest {
        method,
        path,
        headers,
    }
}

const CREDENTIAL_ID: &str = "11111111111111111111111111111111";

struct TestEnv {
    temp: tempfile::TempDir,
    api: TcpListener,
    keyed_cipher_json: Value,
}

impl TestEnv {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        api.set_nonblocking(true).unwrap();
        let server_url = format!("http://{}", api.local_addr().unwrap());

        let keyring = dir.join("secret-tool");
        fs::write(
            &keyring,
            "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\n*) exit 1;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();

        let email = "user@fixture.invalid";
        let master =
            derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None)
                .unwrap();
        let raw_user_key = [42u8; 64];
        let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();
        let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
            .encrypt(&raw_user_key)
            .unwrap();

        let raw_cipher_key = [61u8; 64];
        let cipher_key = SymmetricCryptoKey::from_raw_bytes(&raw_cipher_key).unwrap();
        let enc_cipher_key = user_key.encrypt(&raw_cipher_key).unwrap();

        let raw_att1_key = [71u8; 64];
        let raw_att2_key = [72u8; 64];

        let keyed_cipher_json = json!({
            "id": "cipher-keyed-1",
            "type": 1,
            "name": cipher_key.encrypt_string("Personal Keyed").unwrap(),
            "key": enc_cipher_key,
            "organizationId": null,
            "folderId": null,
            "favorite": false,
            "deletedDate": null,
            "revisionDate": "2026-11-26T00:00:00.000Z",
            "notes": cipher_key.encrypt_string("keep these notes").unwrap(),
            "login": {
                "username": cipher_key.encrypt_string("alice").unwrap(),
                "password": cipher_key.encrypt_string("s3cret").unwrap()
            },
            "attachments": [
                {
                    "id": "att-1",
                    "fileName": cipher_key.encrypt_string("recovery-codes.txt").unwrap(),
                    "key": cipher_key.encrypt(&raw_att1_key).unwrap(),
                    "size": "128",
                    "sizeName": "128 B"
                },
                {
                    "id": "att-2",
                    "fileName": cipher_key.encrypt_string("keep-cert.pem").unwrap(),
                    "key": cipher_key.encrypt(&raw_att2_key).unwrap(),
                    "size": "256",
                    "sizeName": "256 B"
                }
            ]
        });

        let trashed_cipher_json = json!({
            "id": "cipher-trashed-1",
            "type": 2,
            "name": user_key.encrypt_string("Trashed Note").unwrap(),
            "key": null,
            "organizationId": null,
            "deletedDate": "2026-11-25T00:00:00.000Z",
            "attachments": [
                {
                    "id": "att-trash-1",
                    "fileName": user_key.encrypt_string("old.txt").unwrap(),
                    "size": "10",
                    "sizeName": "10 B"
                }
            ]
        });

        let org_cipher_json = json!({
            "id": "cipher-org-1",
            "type": 1,
            "name": user_key.encrypt_string("Org Cipher").unwrap(),
            "organizationId": "org-1",
            "collectionIds": ["col-1"],
            "edit": true,
            "viewPassword": true,
            "deletedDate": null,
            "attachments": [
                {
                    "id": "att-org-1",
                    "fileName": user_key.encrypt_string("shared.pdf").unwrap(),
                    "size": "512",
                    "sizeName": "512 B"
                }
            ]
        });

        let data_dir = dir.join("data");
        let cfg_dir = dir.join("config").join("omawarden");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&cfg_dir).unwrap();

        fs::write(
            cfg_dir.join("config.json"),
            json!({ "server_url": server_url }).to_string(),
        )
        .unwrap();

        let data = json!({
            "user_email": email,
            "user_id": "user-uuid-1",
            "credential_id": CREDENTIAL_ID,
            "server_url": server_url,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "enc_user_key": wrap,
            "ciphers": [
                keyed_cipher_json,
                trashed_cipher_json,
                org_cipher_json
            ],
            "folders": [],
            "organizations": [],
            "collections": []
        });
        fs::write(data_dir.join("data.json"), data.to_string()).unwrap();
        fs::set_permissions(
            data_dir.join("data.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        Self {
            temp,
            api,
            keyed_cipher_json,
        }
    }

    fn dir(&self) -> &Path {
        self.temp.path()
    }

    fn socket(&self) -> std::path::PathBuf {
        self.dir().join("omawarden.sock")
    }

    fn cmd(&self) -> Command {
        let dir = self.dir();
        let path = format!("{}:/usr/bin:/bin", dir.display());
        let mut c = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        c.env_clear()
            .env("HOME", dir)
            .env("PATH", path)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("OMAWARDEN_DATA_DIR", dir.join("data"))
            .env("OMA_DAEMON_BIN", env!("CARGO_BIN_EXE_omawarden"))
            .env("OMA_KEYRING_PROVIDER", "secret-tool");
        c
    }

    fn start_unlocked_daemon(&self) -> Daemon {
        let child = self
            .cmd()
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = Daemon(child);
        let ping = ipc(&self.socket(), json!({ "action": "ping" }));
        assert_eq!(ping["ok"], true);
        let unlock = ipc(
            &self.socket(),
            json!({ "action": "unlock", "password": "fixture" }),
        );
        assert_eq!(unlock["ok"], true, "unlock failed: {unlock}");
        daemon
    }
}

#[test]
fn test_attachment_delete_bitwarden_mini_response_updates_cache_and_purges_preview() {
    let env = TestEnv::new();
    let _daemon = env.start_unlocked_daemon();

    // Seed cached preview directories for both att-1 (to be deleted) and att-2 (to remain).
    let preview_base = env
        .dir()
        .join("omarchy-bitwarden/scoped-attachments")
        .join(CREDENTIAL_ID)
        .join("cipher-keyed-1");
    let att1_preview = preview_base.join("att-1");
    let att2_preview = preview_base.join("att-2");
    fs::create_dir_all(&att1_preview).unwrap();
    fs::create_dir_all(&att2_preview).unwrap();
    fs::write(att1_preview.join("recovery-codes.txt"), b"1234-5678").unwrap();
    fs::write(att2_preview.join("keep-cert.pem"), b"CERT").unwrap();

    let api = env.api.try_clone().unwrap();
    let seen_req = Arc::new(Mutex::new(None::<(String, String, Option<String>)>));
    let seen_req_bg = seen_req.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();

    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream);
                    *seen_req_bg.lock().unwrap() = Some((
                        req.method.clone(),
                        req.path.clone(),
                        req.headers.get("authorization").cloned(),
                    ));
                    // Bitwarden official CipherMiniResponseModel (omits login/notes/name/key)
                    let body = json!({
                        "id": "cipher-keyed-1",
                        "object": "cipherMini",
                        "revisionDate": "2026-11-27T18:30:00.000Z",
                        "attachments": [
                            { "id": "att-2" }
                        ]
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let out = env
        .cmd()
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();

    assert!(
        out.status.success(),
        "delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let json_out: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_out["ok"], true);
    assert_eq!(json_out["item_id"], "cipher-keyed-1");
    assert_eq!(json_out["attachment_id"], "att-1");
    assert_eq!(json_out["file_name"], "recovery-codes.txt");
    assert_eq!(json_out["item"]["name"], "Personal Keyed");
    assert_eq!(json_out["item"]["notes"], "keep these notes");
    assert_eq!(json_out["item"]["login"]["username"], "alice");
    let atts = json_out["item"]["attachments"].as_array().unwrap();
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0]["id"], "att-2");
    assert_eq!(atts[0]["fileName"], "keep-cert.pem");

    // Verify HTTP DELETE request and Bearer auth
    let req_info = seen_req
        .lock()
        .unwrap()
        .clone()
        .expect("expected HTTP call");
    assert_eq!(req_info.0, "DELETE");
    assert_eq!(req_info.1, "/api/ciphers/cipher-keyed-1/attachment/att-1");
    assert_eq!(req_info.2.as_deref(), Some("Bearer fixture-token"));

    // Verify local cache file permissions (0600) and updated revisionDate
    let data_path = env.dir().join("data").join("data.json");
    let mode = fs::metadata(&data_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "data.json must retain 0600 permissions");
    let cached: Value = serde_json::from_str(&fs::read_to_string(&data_path).unwrap()).unwrap();
    let cached_cipher = cached["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "cipher-keyed-1")
        .unwrap();
    assert_eq!(cached_cipher["revisionDate"], "2026-11-27T18:30:00.000Z");
    assert_eq!(cached_cipher["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(cached_cipher["attachments"][0]["id"], "att-2");

    // Verify in-memory daemon index reflects deletion immediately without sync
    let item_resp = ipc(
        &env.socket(),
        json!({ "action": "get_item", "query": "cipher-keyed-1" }),
    );
    assert_eq!(item_resp["ok"], true);
    assert_eq!(
        item_resp["item"]["attachments"].as_array().unwrap().len(),
        1
    );

    // Verify deleted preview directory was purged immediately while sibling preview remains
    assert!(
        !att1_preview.exists(),
        "Deleted attachment preview directory must be purged immediately"
    );
    assert!(
        att2_preview.join("keep-cert.pem").exists(),
        "Sibling attachment preview must remain intact"
    );
}

#[test]
fn test_attachment_delete_vaultwarden_full_response_and_aliases() {
    let env = TestEnv::new();
    let _daemon = env.start_unlocked_daemon();

    let mut full_after_first = env.keyed_cipher_json.clone();
    full_after_first["revisionDate"] = json!("2026-11-27T19:00:00.000Z");
    full_after_first["attachments"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["id"] != "att-1");

    let mut full_after_second = full_after_first.clone();
    full_after_second["revisionDate"] = json!("2026-11-27T19:05:00.000Z");
    full_after_second["attachments"] = json!([]);

    let api = env.api.try_clone().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let count_bg = count.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();

    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    let idx = count_bg.fetch_add(1, Ordering::SeqCst);
                    let body = if idx == 0 {
                        full_after_first.to_string()
                    } else {
                        full_after_second.to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    // Alias `rm` in human-readable mode
    let out_rm = env
        .cmd()
        .args([
            "attachment",
            "rm",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(out_rm.status.success());
    let stdout_rm = String::from_utf8_lossy(&out_rm.stdout);
    assert!(
        stdout_rm.contains("recovery-codes.txt") && stdout_rm.contains("Personal Keyed"),
        "Expected human-readable confirmation with filename and cipher name: {stdout_rm}"
    );

    // Alias `remove` in JSON mode
    let out_remove = env
        .cmd()
        .args([
            "attachment",
            "remove",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-2",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();

    assert!(out_remove.status.success());
    let json_out: Value = serde_json::from_slice(&out_remove.stdout).unwrap();
    assert_eq!(json_out["ok"], true);
    assert_eq!(json_out["file_name"], "keep-cert.pem");
    assert_eq!(json_out["item"]["attachments"].as_array().unwrap().len(), 0);
}

#[test]
fn test_attachment_delete_confirmation_guards_and_interactive_prompt() {
    let env = TestEnv::new();
    let _daemon = env.start_unlocked_daemon();

    let api = env.api.try_clone().unwrap();
    let http_calls = Arc::new(AtomicUsize::new(0));
    let http_calls_bg = http_calls.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();

    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    http_calls_bg.fetch_add(1, Ordering::SeqCst);
                    let body = json!({
                        "id": "cipher-keyed-1",
                        "revisionDate": "2026-11-27T19:10:00.000Z"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    // 1. Non-interactive without --yes fails closed with zero HTTP calls
    let out_ni = env
        .cmd()
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out_ni.status.success());
    assert!(String::from_utf8_lossy(&out_ni.stderr).contains("--yes"));
    assert_eq!(http_calls.load(Ordering::SeqCst), 0);

    // 2. --json mode without --yes fails closed even if OMA_FORCE_PROMPT is set
    let out_json = env
        .cmd()
        .env("OMA_FORCE_PROMPT", "1")
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out_json.status.success());
    let json_err: Value = serde_json::from_slice(&out_json.stdout).unwrap();
    assert_eq!(json_err["ok"], false);
    assert!(json_err["error"].as_str().unwrap_or("").contains("--yes"));
    assert_eq!(http_calls.load(Ordering::SeqCst), 0);

    // 3. Interactive prompt (OMA_FORCE_PROMPT=1) shows both filename and cipher name; 'n' aborts
    let mut child_no = env
        .cmd()
        .env("OMA_FORCE_PROMPT", "1")
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_no.stdin.as_mut().unwrap().write_all(b"n\n").unwrap();
    let out_no = child_no.wait_with_output().unwrap();
    assert!(!out_no.status.success());
    let stderr_no = String::from_utf8_lossy(&out_no.stderr);
    assert!(
        stderr_no.contains("recovery-codes.txt") && stderr_no.contains("Personal Keyed"),
        "Prompt must display both filename and cipher name: {stderr_no}"
    );
    assert_eq!(http_calls.load(Ordering::SeqCst), 0);

    // 4. Interactive prompt with 'y' proceeds with DELETE
    let mut child_yes = env
        .cmd()
        .env("OMA_FORCE_PROMPT", "1")
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child_yes.stdin.as_mut().unwrap().write_all(b"y\n").unwrap();
    let out_yes = child_yes.wait_with_output().unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();

    assert!(
        out_yes.status.success(),
        "Interactive 'y' should succeed: stderr={}",
        String::from_utf8_lossy(&out_yes.stderr)
    );
    assert_eq!(http_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn test_attachment_delete_rejects_trashed_and_org_ciphers_before_http() {
    let env = TestEnv::new();
    let _daemon = env.start_unlocked_daemon();

    let api = env.api.try_clone().unwrap();
    let http_calls = Arc::new(AtomicUsize::new(0));
    let http_calls_bg = http_calls.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();

    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    http_calls_bg.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let out_trash = env
        .cmd()
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-trashed-1",
            "--attachment-id",
            "att-trash-1",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!out_trash.status.success());
    let trash_json: Value = serde_json::from_slice(&out_trash.stdout).unwrap();
    assert_eq!(trash_json["ok"], false);
    assert!(trash_json["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("trashed"));

    let out_org = env
        .cmd()
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-org-1",
            "--attachment-id",
            "att-org-1",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();

    assert!(!out_org.status.success());
    let org_json: Value = serde_json::from_slice(&out_org.stdout).unwrap();
    assert_eq!(org_json["ok"], false);
    assert!(org_json["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("organization"));
    assert_eq!(
        http_calls.load(Ordering::SeqCst),
        0,
        "Zero HTTP calls may be made for trashed or org ciphers"
    );
}

#[test]
fn test_attachment_delete_capability_gating_restarts_stale_standalone_daemon() {
    let env = TestEnv::new();
    let sock = env.socket();
    let _ = fs::remove_file(&sock);

    // Spawn a mock stale standalone daemon that omits "attachment_delete" from ping.capabilities
    // and exits cleanly on admin stop so the CLI auto-restarts the real omawarden binary.
    let listener = UnixListener::bind(&sock).unwrap();
    let sock_for_thread = sock.clone();
    let stale_stopped = Arc::new(AtomicBool::new(false));
    let stale_stopped_bg = stale_stopped.clone();

    let mock_stale = thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            let mut out = stream;
            match req["action"].as_str() {
                Some("ping") => {
                    let _ = writeln!(
                        out,
                        "{}",
                        json!({
                            "ok": true,
                            "pong": true,
                            "protocol_version": 1,
                            "schema_version": 3,
                            "capabilities": ["cipher_mutation_v3", "attachment_upload"],
                            "unlocked": true
                        })
                    );
                }
                Some("stop") if req["admin"] == true => {
                    let _ = writeln!(out, "{}", json!({ "ok": true, "protocol_version": 1 }));
                    let _ = fs::remove_file(&sock_for_thread);
                    stale_stopped_bg.store(true, Ordering::SeqCst);
                    break;
                }
                _ => {
                    let _ = writeln!(
                        out,
                        "{}",
                        json!({ "ok": false, "error": "unexpected action", "protocol_version": 1 })
                    );
                }
            }
        }
    });

    // Run CLI delete (without unlocking the restarted daemon -> proves stale daemon was stopped
    // and real daemon was restarted and queried with capability "attachment_delete").
    let out = env
        .cmd()
        .env("OMA_DAEMON_BIN", env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
            "--yes",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = mock_stale.join();

    // Clean up restarted daemon if running
    let _ = env.cmd().args(["daemon", "stop"]).output();

    assert!(
        stale_stopped.load(Ordering::SeqCst),
        "CLI must auto-restart stale standalone daemon lacking 'attachment_delete'"
    );
    let resp: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(resp["ok"], false);
    assert!(
        resp["error"]
            .as_str()
            .unwrap_or("")
            .contains("Unlock the vault"),
        "After auto-restart, fresh daemon should advertise attachment_delete and fail closed on locked vault: {resp}"
    );
}

#[test]
fn test_attachment_delete_org_cipher_succeeds_and_refreshes_cache() {
    let env = TestEnv::new();

    let raw_user_key = [42u8; 64];
    let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();
    let raw_org_key = [77u8; 64];
    let org_key = SymmetricCryptoKey::from_raw_bytes(&raw_org_key).unwrap();
    let raw_org_cipher_key = [88u8; 64];
    let org_cipher_key = SymmetricCryptoKey::from_raw_bytes(&raw_org_cipher_key).unwrap();

    let org_cipher_json = json!({
        "id": "cipher-org-writable",
        "type": 1,
        "name": org_cipher_key.encrypt_string("Org Writable Login").unwrap(),
        "key": org_key.encrypt(&raw_org_cipher_key).unwrap(),
        "organizationId": "org-writable",
        "collectionIds": ["col-w"],
        "edit": true,
        "viewPassword": true,
        "deletedDate": null,
        "revisionDate": "2026-11-26T00:00:00.000Z",
        "login": {
            "username": org_cipher_key.encrypt_string("ops@corp.invalid").unwrap(),
            "password": org_cipher_key.encrypt_string("org-secret-pw").unwrap(),
            "uris": []
        },
        "attachments": [
            {
                "id": "att-org-del",
                "fileName": org_cipher_key.encrypt_string("obsolete.pem").unwrap(),
                "size": "128",
                "sizeName": "128 B"
            },
            {
                "id": "att-org-keep",
                "fileName": org_cipher_key.encrypt_string("keep.pem").unwrap(),
                "size": "256",
                "sizeName": "256 B"
            }
        ]
    });

    let data_path = env.dir().join("data/data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&data_path).unwrap()).unwrap();
    data["organizations"].as_array_mut().unwrap().push(json!({
        "id": "org-writable",
        "name": "Acme Org",
        "key": user_key.encrypt(&raw_org_key).unwrap(),
    }));
    data["ciphers"]
        .as_array_mut()
        .unwrap()
        .push(org_cipher_json);
    fs::write(&data_path, data.to_string()).unwrap();

    let _daemon = env.start_unlocked_daemon();

    let api = env.api.try_clone().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();
    let delete_hits = Arc::new(AtomicUsize::new(0));
    let delete_hits_bg = delete_hits.clone();

    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream);
                    if req.method == "DELETE"
                        && req.path == "/api/ciphers/cipher-org-writable/attachment/att-org-del"
                    {
                        delete_hits_bg.fetch_add(1, Ordering::SeqCst);
                        // Return Bitwarden CipherMiniResponseModel omitting encrypted fields
                        let resp_body = json!({
                            "id": "cipher-org-writable",
                            "object": "cipherMini",
                            "revisionDate": "2026-11-27T12:00:00.000Z"
                        })
                        .to_string();
                        let http = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        );
                        stream.write_all(http.as_bytes()).unwrap();
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let out = env
        .cmd()
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-org-writable",
            "--attachment-id",
            "att-org-del",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();

    assert!(
        out.status.success(),
        "Org attachment delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(delete_hits.load(Ordering::SeqCst), 1);

    let resp: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["file_name"], "obsolete.pem");
    assert_eq!(
        resp["item"]["name"], "Org Writable Login",
        "Re-decrypted Organization Cipher must not degrade to Untitled: {resp}"
    );
    let atts = resp["item"]["attachments"].as_array().unwrap();
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0]["id"], "att-org-keep");
    assert_eq!(atts[0]["fileName"], "keep.pem");

    // Verify local cache file keeps 0600 permissions and immediately reflects deletion
    let mode = fs::metadata(&data_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let get_resp = ipc(
        &env.socket(),
        json!({ "action": "get_item", "query": "cipher-org-writable" }),
    );
    assert_eq!(get_resp["ok"], true);
    assert_eq!(get_resp["item"]["name"], "Org Writable Login");
    assert_eq!(get_resp["item"]["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(get_resp["item"]["attachments"][0]["fileName"], "keep.pem");
}

#[test]
fn test_attachment_delete_org_cipher_permission_and_key_guards_fail_closed_before_http() {
    let env = TestEnv::new();

    let raw_user_key = [42u8; 64];
    let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();
    let raw_org_key = [77u8; 64];
    let org_key = SymmetricCryptoKey::from_raw_bytes(&raw_org_key).unwrap();

    let data_path = env.dir().join("data/data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&data_path).unwrap()).unwrap();
    data["organizations"].as_array_mut().unwrap().push(json!({
        "id": "org-known",
        "name": "Acme Org",
        "key": user_key.encrypt(&raw_org_key).unwrap(),
    }));
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": "cipher-org-ro",
        "type": 1,
        "name": org_key.encrypt_string("Org RO").unwrap(),
        "organizationId": "org-known",
        "edit": false,
        "viewPassword": true,
        "deletedDate": null,
        "attachments": [{
            "id": "att-ro",
            "fileName": org_key.encrypt_string("ro.txt").unwrap(),
            "size": "10",
            "sizeName": "10 B"
        }]
    }));
    ciphers.push(json!({
        "id": "cipher-org-hidden-pw",
        "type": 1,
        "name": org_key.encrypt_string("Org Hidden PW").unwrap(),
        "organizationId": "org-known",
        "edit": true,
        "viewPassword": false,
        "deletedDate": null,
        "attachments": [{
            "id": "att-hp",
            "fileName": org_key.encrypt_string("hp.txt").unwrap(),
            "size": "10",
            "sizeName": "10 B"
        }]
    }));
    fs::write(&data_path, data.to_string()).unwrap();

    let _daemon = env.start_unlocked_daemon();

    let api = env.api.try_clone().unwrap();
    let http_calls = Arc::new(AtomicUsize::new(0));
    let http_calls_bg = http_calls.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();
    let server = thread::spawn(move || {
        while !stop_bg.load(Ordering::SeqCst) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    http_calls_bg.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    for (cipher_id, att_id, expected_substr) in [
        ("cipher-org-ro", "att-ro", "permission"),
        ("cipher-org-hidden-pw", "att-hp", "passwords are hidden"),
        (
            "cipher-org-1",
            "att-org-1",
            "Organization 'org-1' not found",
        ),
    ] {
        let out = env
            .cmd()
            .args([
                "attachment",
                "delete",
                "--item-id",
                cipher_id,
                "--attachment-id",
                att_id,
                "--yes",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(!out.status.success(), "Expected {cipher_id} to fail closed");
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v["ok"], false);
        let err = v["error"].as_str().unwrap_or("");
        assert!(
            err.to_lowercase().contains(&expected_substr.to_lowercase()),
            "Expected '{expected_substr}' for {cipher_id}, got: {err}"
        );
    }

    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert_eq!(
        http_calls.load(Ordering::SeqCst),
        0,
        "Zero HTTP calls may occur for unauthorized or missing-key Organization Ciphers"
    );
}

#[test]
fn test_attachment_delete_stale_daemon_missing_org_write_auto_restarts() {
    let env = TestEnv::new();
    let sock = env.socket();
    let _ = fs::remove_file(&sock);

    let listener = UnixListener::bind(&sock).unwrap();
    let sock_for_thread = sock.clone();
    let stale_stopped = Arc::new(AtomicBool::new(false));
    let stale_stopped_bg = stale_stopped.clone();

    let mock_stale = thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            let mut out = stream;
            match req["action"].as_str() {
                Some("ping") => {
                    let _ = writeln!(
                        out,
                        "{}",
                        json!({
                            "ok": true,
                            "pong": true,
                            "protocol_version": 1,
                            "schema_version": 3,
                            // Advertises attachment_delete but omits org_write
                            "capabilities": ["cipher_mutation_v3", "attachment_delete"],
                            "unlocked": true
                        })
                    );
                }
                Some("stop") if req["admin"] == true => {
                    let _ = writeln!(out, "{}", json!({ "ok": true, "protocol_version": 1 }));
                    let _ = fs::remove_file(&sock_for_thread);
                    stale_stopped_bg.store(true, Ordering::SeqCst);
                    break;
                }
                _ => {
                    let _ = writeln!(
                        out,
                        "{}",
                        json!({ "ok": false, "error": "unexpected action", "protocol_version": 1 })
                    );
                }
            }
        }
    });

    let out = env
        .cmd()
        .env("OMA_DAEMON_BIN", env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "attachment",
            "delete",
            "--item-id",
            "cipher-keyed-1",
            "--attachment-id",
            "att-1",
            "--yes",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = mock_stale.join();
    let _ = env.cmd().args(["daemon", "stop"]).output();

    assert!(
        stale_stopped.load(Ordering::SeqCst),
        "CLI must auto-restart stale standalone daemon lacking 'org_write'"
    );
    let resp: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(resp["ok"], false);
    assert!(
        resp["error"]
            .as_str()
            .unwrap_or("")
            .contains("Unlock the vault"),
        "After auto-restart, fresh daemon should advertise org_write and fail closed on locked vault: {resp}"
    );
}
