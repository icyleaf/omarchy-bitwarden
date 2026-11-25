use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{fs::PermissionsExt, net::UnixListener, net::UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

fn read_http_request(stream: &mut TcpStream) -> (String, String, Vec<u8>) {
    let _ = stream.set_nonblocking(false);
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let parts: Vec<&str> = line.split_whitespace().collect();
    let method = parts[0].to_owned();
    let path = parts[1].to_owned();
    let mut size = 0;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
            size = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body).unwrap();
    (method, path, body)
}

struct TestEnv {
    temp: tempfile::TempDir,
    api: TcpListener,
    user_key: SymmetricCryptoKey,
    org_key: SymmetricCryptoKey,
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

        let raw_org_key = [77u8; 64];
        let org_key = SymmetricCryptoKey::from_raw_bytes(&raw_org_key).unwrap();
        let enc_org_key = user_key.encrypt(&raw_org_key).unwrap();

        let folder_id = "folder-1";
        let folder_name_enc = user_key.encrypt_string("Pinned Work").unwrap();
        let col_writable_name_enc = org_key.encrypt_string("Engineering").unwrap();
        let col_legacy_name_enc = org_key.encrypt_string("Legacy Archive").unwrap();

        let org_cipher_name = org_key.encrypt_string("Shared Prod DB").unwrap();
        let org_cipher_user = org_key.encrypt_string("readonly_user").unwrap();
        let org_cipher_pass = org_key.encrypt_string("s3cr3t").unwrap();

        let cache = dir.join("data.json");
        let data = json!({
            "user_id": "user-id-123",
            "user_email": email,
            "server_url": server_url,
            "credential_id": "11111111111111111111111111111111",
            "enc_user_key": wrap,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "folders": [
                { "id": folder_id, "name": folder_name_enc }
            ],
            "organizations": [
                {
                    "id": "org-1",
                    "name": "Acme Corp",
                    "key": enc_org_key,
                    "type": 2,
                    "enabled": true
                }
            ],
            "collections": [
                {
                    "id": "col-writable",
                    "organizationId": "org-1",
                    "name": col_writable_name_enc,
                    "readOnly": false,
                    "hidePasswords": false,
                    "manage": true
                },
                {
                    "id": "col-legacy",
                    "organizationId": "org-1",
                    "name": col_legacy_name_enc
                }
            ],
            "ciphers": [
                {
                    "id": "org-cipher-1",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 1,
                    "name": org_cipher_name,
                    "notes": null,
                    "favorite": false,
                    "edit": false,
                    "viewPassword": false,
                    "permissions": {
                        "delete": false,
                        "restore": false
                    },
                    "collectionIds": ["col-legacy"],
                    "login": {
                        "username": org_cipher_user,
                        "password": org_cipher_pass,
                        "uris": []
                    },
                    "fields": [],
                    "revisionDate": "2026-01-01T00:00:00Z"
                }
            ]
        });
        fs::write(&cache, data.to_string()).unwrap();

        Self {
            temp,
            api,
            user_key,
            org_key,
        }
    }

    fn path_env(&self) -> String {
        format!(
            "{}:{}",
            self.temp.path().display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }

    fn spawn_and_unlock_daemon(&self) -> Daemon {
        let dir = self.temp.path();
        let child = Command::new(env!("CARGO_BIN_EXE_omawarden"))
            .arg("daemon")
            .env("XDG_DATA_HOME", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .env("PATH", self.path_env())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = Daemon(child);

        let socket = dir.join("omawarden.sock");
        let unlock = ipc(
            &socket,
            json!({ "action": "unlock", "password": "fixture" }),
        );
        assert_eq!(unlock["ok"], true, "unlock failed: {unlock}");
        daemon
    }

    fn run_cli(&self, args: &[&str], stdin_data: Option<&str>) -> std::process::Output {
        let dir = self.temp.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.args(args)
            .env("XDG_DATA_HOME", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .env("PATH", self.path_env());
        if let Some(input) = stdin_data {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn().unwrap();
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        } else {
            cmd.output().unwrap()
        }
    }
}

#[test]
fn org_list_returns_decrypted_collections_with_fail_closed_defaults() {
    let env = TestEnv::new();
    let _daemon = env.spawn_and_unlock_daemon();

    let out = env.run_cli(&["org", "list", "--json"], None);
    assert!(
        out.status.success(),
        "org list --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["ok"], true);
    let orgs = body["organizations"].as_array().unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["id"], "org-1");
    assert_eq!(orgs[0]["name"], "Acme Corp");

    let cols = body["collections"].as_array().unwrap();
    assert_eq!(cols.len(), 2);

    let eng = cols.iter().find(|c| c["id"] == "col-writable").unwrap();
    assert_eq!(eng["name"], "Engineering");
    assert_eq!(eng["read_only"], false);
    assert_eq!(eng["hide_passwords"], false);
    assert_eq!(eng["manage"], true);
    assert_eq!(eng["writable"], true);

    let legacy = cols.iter().find(|c| c["id"] == "col-legacy").unwrap();
    assert_eq!(legacy["name"], "Legacy Archive");
    assert_eq!(legacy["read_only"], true);
    assert_eq!(legacy["hide_passwords"], true);
    assert_eq!(legacy["manage"], false);
    assert_eq!(legacy["writable"], false);

    // Human-readable output
    let text_out = env.run_cli(&["org", "list"], None);
    assert!(text_out.status.success());
    let stdout = String::from_utf8_lossy(&text_out.stdout);
    assert!(stdout.contains("Acme Corp"));
    assert!(stdout.contains("Engineering"));
    assert!(stdout.contains("Legacy Archive"));
}

#[test]
fn org_list_fails_closed_when_in_process_daemon_lacks_org_write_capability() {
    let env = TestEnv::new();
    let socket_path = env.temp.path().join("omawarden.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let _ = BufReader::new(&stream).read_line(&mut line);
                    let req: Value = serde_json::from_str(&line).unwrap_or_default();
                    let resp = match req["action"].as_str() {
                        Some("ping") => json!({
                            "ok": true,
                            "pong": true,
                            "protocol_version": 1,
                            "schema_version": 3,
                            "capabilities": ["cipher_mutation_v3", "folder_crud", "vault_get"],
                            "unlocked": true,
                        }),
                        Some("stop") => json!({
                            "ok": false,
                            "error": "Access denied: cannot terminate in-process daemon hosted by an external application",
                            "protocol_version": 1,
                        }),
                        other => panic!("unexpected action sent to legacy daemon: {other:?}"),
                    };
                    let _ = writeln!(stream, "{resp}");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let out = env.run_cli(&["org", "list", "--json"], None);
    stop_flag.store(true, Ordering::SeqCst);
    let _ = server.join();

    assert!(!out.status.success());
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["ok"], false);
    assert!(
        body["error"].as_str().unwrap_or("").contains("org_write"),
        "expected error naming org_write, got: {body}"
    );
}

#[test]
fn org_list_auto_restarts_legacy_standalone_daemon_missing_org_write() {
    let env = TestEnv::new();
    let socket_path = env.temp.path().join("omawarden.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();

    let stop_received = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_received.clone();
    let sock_clone = socket_path.clone();

    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let _ = BufReader::new(&stream).read_line(&mut line);
                    let req: Value = serde_json::from_str(&line).unwrap_or_default();
                    match req["action"].as_str() {
                        Some("ping") => {
                            let _ = writeln!(
                                stream,
                                "{}",
                                json!({
                                    "ok": true,
                                    "pong": true,
                                    "protocol_version": 1,
                                    "schema_version": 3,
                                    "capabilities": ["cipher_mutation_v3", "folder_crud", "vault_get"],
                                    "unlocked": false,
                                })
                            );
                        }
                        Some("stop") if req["admin"] == true => {
                            let _ = writeln!(
                                stream,
                                "{}",
                                json!({ "ok": true, "protocol_version": 1 })
                            );
                            let _ = fs::remove_file(&sock_clone);
                            stop_clone.store(true, Ordering::SeqCst);
                            break;
                        }
                        other => panic!("unexpected action sent to legacy daemon: {other:?}"),
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // Running `org list --json` against the legacy standalone daemon should stop it,
    // restart the new binary (which advertises "org_write"), and then fail closed only
    // because the freshly restarted daemon is locked (proving capability negotiation succeeded).
    let out = env.run_cli(&["org", "list", "--json"], None);
    let _ = server.join();

    // Clean up restarted daemon
    let _ = ipc(&socket_path, json!({ "action": "stop", "admin": true }));

    assert!(
        stop_received.load(Ordering::SeqCst),
        "expected stop(admin: true) to be sent"
    );
    let body: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(body["ok"], false);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("unlock"),
        "expected locked error after successful capability restart, got: {body}"
    );
}

#[test]
fn org_cipher_partial_favorite_and_folder_updates_work_on_read_only_org_cipher() {
    let env = TestEnv::new();
    let _daemon = env.spawn_and_unlock_daemon();

    let org_cipher_name = env.org_key.encrypt_string("Shared Prod DB").unwrap();
    let org_cipher_user = env.org_key.encrypt_string("readonly_user").unwrap();
    let org_cipher_pass = env.org_key.encrypt_string("s3cr3t").unwrap();
    let _ = &env.user_key;

    let api = env.api.try_clone().unwrap();
    let received_requests = Arc::new(std::sync::Mutex::new(Vec::<(String, String, Value)>::new()));
    let reqs_clone = received_requests.clone();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, body) = read_http_request(&mut stream);
                    let parsed: Value = serde_json::from_slice(&body).unwrap_or_default();
                    reqs_clone
                        .lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), parsed.clone()));
                    let resp_body = json!({
                        "id": "org-cipher-1",
                        "organizationId": "org-1",
                        "folderId": parsed["folderId"],
                        "type": 1,
                        "name": org_cipher_name,
                        "notes": null,
                        "favorite": parsed["favorite"],
                        "edit": false,
                        "viewPassword": false,
                        "permissions": {
                            "delete": false,
                            "restore": false
                        },
                        "collectionIds": ["col-legacy"],
                        "login": {
                            "username": org_cipher_user,
                            "password": org_cipher_pass,
                            "uris": []
                        },
                        "fields": [],
                        "revisionDate": "2026-01-02T00:00:00Z"
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // 1. Favorite toggle via CLI flag on read-only org cipher -> PUT /api/ciphers/org-cipher-1/partial
    let out1 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-cipher-1",
            "--favorite",
            "true",
            "--json",
        ],
        None,
    );
    assert!(
        out1.status.success(),
        "favorite toggle failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let body1: Value = serde_json::from_slice(&out1.stdout).unwrap();
    assert_eq!(body1["ok"], true);
    assert_eq!(body1["outcome"], "saved");

    // Verify immediate local cache re-decryption preserved real org cipher name (not "Untitled")
    let get1 = env.run_cli(&["vault", "get", "org-cipher-1", "--json"], None);
    assert!(get1.status.success());
    let item1: Value = serde_json::from_slice(&get1.stdout).unwrap();
    assert_eq!(item1["item"]["name"], "Shared Prod DB");
    assert_eq!(item1["item"]["favorite"], true);
    assert_eq!(item1["item"]["edit"], false);

    // 2. Folder assignment via --folder CLI flag -> PUT /api/ciphers/org-cipher-1/partial
    let out2 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-cipher-1",
            "--folder",
            "folder-1",
            "--json",
        ],
        None,
    );
    assert!(
        out2.status.success(),
        "folder flag update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );

    // Verify folder updated while favorite remained true
    let get2 = env.run_cli(&["vault", "get", "org-cipher-1", "--json"], None);
    let item2: Value = serde_json::from_slice(&get2.stdout).unwrap();
    assert_eq!(item2["item"]["folder_id"], "folder-1");
    assert_eq!(item2["item"]["favorite"], true);

    // 2b. Clear folder + unfavorite via --stdin --json -> PUT /api/ciphers/org-cipher-1/partial
    let out2b = env.run_cli(
        &["vault", "edit", "org-cipher-1", "--stdin", "--json"],
        Some(r#"{"folder_id": "", "favorite": false}"#),
    );
    assert!(
        out2b.status.success(),
        "stdin partial update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2b.stdout),
        String::from_utf8_lossy(&out2b.stderr)
    );
    let get2b = env.run_cli(&["vault", "get", "org-cipher-1", "--json"], None);
    let item2b: Value = serde_json::from_slice(&get2b.stdout).unwrap();
    assert!(item2b["item"]["folder_id"].is_null());
    assert_eq!(item2b["item"]["favorite"], false);

    // 3. Content edit (--name) on read-only org cipher must still fail closed with zero HTTP calls
    let count_before = received_requests.lock().unwrap().len();
    let out3 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-cipher-1",
            "--name",
            "Hacked",
            "--json",
        ],
        None,
    );
    assert!(!out3.status.success());
    let body3: Value = serde_json::from_slice(&out3.stdout).unwrap();
    assert_eq!(body3["ok"], false);
    assert_eq!(received_requests.lock().unwrap().len(), count_before);

    stop_flag.store(true, Ordering::SeqCst);
    let _ = server.join();

    let reqs = received_requests.lock().unwrap();
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[0].0, "PUT");
    assert_eq!(reqs[0].1, "/api/ciphers/org-cipher-1/partial");
    assert_eq!(reqs[0].2["favorite"], true);
    assert!(reqs[0].2["folderId"].is_null());

    assert_eq!(reqs[1].0, "PUT");
    assert_eq!(reqs[1].1, "/api/ciphers/org-cipher-1/partial");
    assert_eq!(reqs[1].2["folderId"], "folder-1");
    assert_eq!(reqs[1].2["favorite"], true);

    assert_eq!(reqs[2].0, "PUT");
    assert_eq!(reqs[2].1, "/api/ciphers/org-cipher-1/partial");
    assert!(reqs[2].2["folderId"].is_null());
    assert_eq!(reqs[2].2["favorite"], false);
}
