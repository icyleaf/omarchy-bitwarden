use omawarden_engine::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    org_key: SymmetricCryptoKey,
    org_cipher_key: SymmetricCryptoKey,
    enc_org_cipher_key: String,
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

        let org_cipher_raw_key = [66u8; 64];
        let org_cipher_key = SymmetricCryptoKey::from_raw_bytes(&org_cipher_raw_key).unwrap();
        let enc_org_cipher_key = org_key.encrypt(&org_cipher_raw_key).unwrap();

        let other_org_key = SymmetricCryptoKey::from_raw_bytes(&[88u8; 64]).unwrap();

        let organizations = vec![
            json!({
                "id": "org-1",
                "name": "Acme Corp",
                "type": 2,
                "enabled": true,
                "key": enc_org_key
            }),
            json!({
                "id": "org-2",
                "name": "Other Corp",
                "type": 2,
                "enabled": true,
                "key": user_key.encrypt(&[88u8; 64]).unwrap()
            }),
        ];

        let collections = vec![
            json!({
                "id": "col-w1",
                "organizationId": "org-1",
                "name": org_key.encrypt_string("Engineering").unwrap(),
                "readOnly": false,
                "hidePasswords": false,
                "manage": false
            }),
            json!({
                "id": "col-w2",
                "organizationId": "org-1",
                "name": org_key.encrypt_string("Platform").unwrap(),
                "readOnly": false,
                "hidePasswords": false,
                "manage": false
            }),
            json!({
                "id": "col-manage",
                "organizationId": "org-1",
                "name": org_key.encrypt_string("Ops Managed").unwrap(),
                "readOnly": true,
                "hidePasswords": false,
                "manage": true
            }),
            json!({
                "id": "col-ro",
                "organizationId": "org-1",
                "name": org_key.encrypt_string("Audit ReadOnly").unwrap(),
                "readOnly": true,
                "hidePasswords": false,
                "manage": false
            }),
            json!({
                "id": "col-other-org",
                "organizationId": "org-2",
                "name": other_org_key.encrypt_string("Other Team").unwrap(),
                "readOnly": false,
                "hidePasswords": false,
                "manage": false
            }),
        ];

        let ciphers = vec![
            // 1. Writable Org cipher assigned to [col-ro, col-w1]
            json!({
                "id": "org-cipher-writable",
                "type": 1,
                "organizationId": "org-1",
                "collectionIds": ["col-ro", "col-w1"],
                "folderId": null,
                "favorite": false,
                "edit": true,
                "viewPassword": true,
                "key": enc_org_cipher_key,
                "name": org_cipher_key.encrypt_string("Org Prod DB").unwrap(),
                "login": {
                    "username": org_cipher_key.encrypt_string("dbadmin").unwrap(),
                    "password": org_cipher_key.encrypt_string("prod-pass").unwrap(),
                    "uris": []
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 2. Writable Org cipher assigned only to [col-w1] (used for unavailable: true & empty-set tests)
            json!({
                "id": "org-cipher-single",
                "type": 1,
                "organizationId": "org-1",
                "collectionIds": ["col-w1"],
                "folderId": null,
                "favorite": false,
                "edit": true,
                "viewPassword": true,
                "key": enc_org_cipher_key,
                "name": org_cipher_key.encrypt_string("Org Ephemeral").unwrap(),
                "login": {
                    "username": org_cipher_key.encrypt_string("svc").unwrap(),
                    "password": org_cipher_key.encrypt_string("ephem-pass").unwrap(),
                    "uris": []
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 3. Read-only Org cipher (edit: false)
            json!({
                "id": "org-cipher-readonly",
                "type": 1,
                "organizationId": "org-1",
                "collectionIds": ["col-w1"],
                "folderId": null,
                "favorite": false,
                "edit": false,
                "viewPassword": true,
                "key": enc_org_cipher_key,
                "name": org_cipher_key.encrypt_string("Org ReadOnly").unwrap(),
                "login": {
                    "username": org_cipher_key.encrypt_string("ro").unwrap(),
                    "password": org_cipher_key.encrypt_string("ro-pass").unwrap(),
                    "uris": []
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 4. Hidden-password Org cipher (edit: true, viewPassword: false)
            json!({
                "id": "org-cipher-hidden-pw",
                "type": 1,
                "organizationId": "org-1",
                "collectionIds": ["col-w1"],
                "folderId": null,
                "favorite": false,
                "edit": true,
                "viewPassword": false,
                "key": enc_org_cipher_key,
                "name": org_cipher_key.encrypt_string("Org Hidden PW").unwrap(),
                "login": {
                    "username": org_cipher_key.encrypt_string("hid").unwrap(),
                    "password": org_cipher_key.encrypt_string("hid-pass").unwrap(),
                    "uris": []
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 5. Personal cipher
            json!({
                "id": "personal-cipher",
                "type": 1,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "name": user_key.encrypt_string("Personal Login").unwrap(),
                "login": {
                    "username": user_key.encrypt_string("me").unwrap(),
                    "password": user_key.encrypt_string("my-pass").unwrap(),
                    "uris": []
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 6. Trashed Org cipher
            json!({
                "id": "org-cipher-trashed",
                "type": 1,
                "organizationId": "org-1",
                "collectionIds": ["col-w1"],
                "folderId": null,
                "favorite": false,
                "edit": true,
                "viewPassword": true,
                "deletedDate": "2026-01-02T00:00:00Z",
                "key": enc_org_cipher_key,
                "name": org_cipher_key.encrypt_string("Org Trashed").unwrap(),
                "login": {
                    "username": org_cipher_key.encrypt_string("old").unwrap(),
                    "password": org_cipher_key.encrypt_string("old-pass").unwrap(),
                    "uris": []
                },
                "revisionDate": "2026-01-02T00:00:00Z"
            }),
        ];

        let data_dir = dir.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let data_path = data_dir.join("data.json");
        fs::write(
            &data_path,
            serde_json::to_string(&json!({
                "server_url": server_url,
                "user_email": email,
                "user_id": "user-uuid-1",
                "credential_id": "11111111111111111111111111111111",
                "kdf": 0,
                "kdf_iterations": 100_000,
                "enc_user_key": wrap,
                "ciphers": ciphers,
                "folders": [],
                "organizations": organizations,
                "collections": collections
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&data_path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::write(
            dir.join("config.json"),
            serde_json::to_string(&json!({
                "server_url": server_url,
                "auto_lock_minutes": 15
            }))
            .unwrap(),
        )
        .unwrap();

        Self {
            temp,
            api,
            org_key,
            org_cipher_key,
            enc_org_cipher_key,
        }
    }

    fn cmd(&self) -> Command {
        let dir = self.temp.path();
        let mut c = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        c.env("HOME", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_DATA_HOME", dir)
            .env("XDG_CONFIG_HOME", dir)
            .env("OMAWARDEN_DATA_DIR", dir.join("data"))
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            );
        c
    }

    fn start_daemon(&self) -> Daemon {
        let dir = self.temp.path();
        let child = self
            .cmd()
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = Daemon(child);
        let unlock = ipc(
            &dir.join("omawarden.sock"),
            json!({ "action": "unlock", "password": "fixture" }),
        );
        assert_eq!(unlock["ok"], true, "unlock failed: {unlock}");
        daemon
    }

    fn run_cli(&self, args: &[&str]) -> std::process::Output {
        self.cmd().args(args).output().unwrap()
    }
}

#[test]
fn vault_collections_replace_and_delta_modes_preserve_untouched_readonly_collections() {
    let env = TestEnv::new();
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();
    let enc_key = env.enc_org_cipher_key.clone();
    let enc_name = env.org_cipher_key.encrypt_string("Org Prod DB").unwrap();
    let enc_user = env.org_cipher_key.encrypt_string("dbadmin").unwrap();
    let enc_pass = env.org_cipher_key.encrypt_string("prod-pass").unwrap();
    let _ = &env.org_key;

    let server = thread::spawn(move || {
        let mut received: Vec<(String, String, Value)> = Vec::new();
        while !stop_srv.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, body) = read_http_request(&mut stream);
                    let req_json: Value = serde_json::from_slice(&body).unwrap();
                    let col_ids = req_json["collectionIds"].clone();
                    received.push((method, path, req_json));

                    let resp_body = json!({
                        "unavailable": false,
                        "cipher": {
                            "id": "org-cipher-writable",
                            "type": 1,
                            "organizationId": "org-1",
                            "collectionIds": col_ids,
                            "folderId": null,
                            "favorite": false,
                            "edit": true,
                            "viewPassword": true,
                            "key": enc_key,
                            "name": enc_name,
                            "login": {
                                "username": enc_user,
                                "password": enc_pass,
                                "uris": []
                            },
                            "revisionDate": "2026-02-01T00:00:00Z"
                        }
                    })
                    .to_string();
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(http.as_bytes());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        received
    });

    // 1. Replace mode: keep untouched col-ro, swap col-w1 -> col-w2
    let out1 = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-writable",
        "--collection-id",
        "col-ro",
        "--collection-id",
        "col-w2",
        "--json",
    ]);
    assert!(
        out1.status.success(),
        "replace mode failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let resp1: Value = serde_json::from_slice(&out1.stdout).unwrap();
    assert_eq!(resp1["ok"], true);
    assert_eq!(resp1["unavailable"], false);
    assert_eq!(resp1["outcome"], "updated");
    assert_eq!(resp1["item"]["collection_ids"], json!(["col-ro", "col-w2"]));

    // 2. Delta mode: add col-manage (readOnly: true, manage: true) and remove col-w2
    let out2 = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-writable",
        "--add",
        "col-manage",
        "--remove",
        "col-w2",
        "--json",
    ]);
    assert!(
        out2.status.success(),
        "delta mode failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
    let resp2: Value = serde_json::from_slice(&out2.stdout).unwrap();
    assert_eq!(resp2["ok"], true);
    assert_eq!(resp2["unavailable"], false);
    assert_eq!(resp2["outcome"], "updated");
    assert_eq!(
        resp2["item"]["collection_ids"],
        json!(["col-ro", "col-manage"])
    );

    // Verify local cache reflects updated collections immediately
    let get_out = env.run_cli(&["vault", "get", "org-cipher-writable", "--json"]);
    assert!(get_out.status.success());
    let get_json: Value = serde_json::from_slice(&get_out.stdout).unwrap();
    assert_eq!(
        get_json["item"]["collection_ids"],
        json!(["col-ro", "col-manage"])
    );

    stop.store(true, Ordering::SeqCst);
    let received = server.join().unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0].0, "PUT");
    assert_eq!(
        received[0].1,
        "/api/ciphers/org-cipher-writable/collections_v2"
    );
    assert_eq!(
        received[0].2,
        json!({ "collectionIds": ["col-ro", "col-w2"] })
    );
    assert_eq!(received[1].0, "PUT");
    assert_eq!(
        received[1].1,
        "/api/ciphers/org-cipher-writable/collections_v2"
    );
    assert_eq!(
        received[1].2,
        json!({ "collectionIds": ["col-ro", "col-manage"] })
    );
}

#[test]
fn vault_collections_unavailable_true_evicts_cipher_atomically_with_0600_and_notices_user() {
    let env = TestEnv::new();
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();

    let server = thread::spawn(move || {
        let mut hits = 0usize;
        while !stop_srv.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, _body) = read_http_request(&mut stream);
                    assert_eq!(method, "PUT");
                    assert!(path.ends_with("/collections_v2"));
                    hits += 1;

                    let resp_body = json!({
                        "unavailable": true,
                        "cipher": null
                    })
                    .to_string();
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(http.as_bytes());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        hits
    });

    // Human mode prints explicit local-cache-removal notice
    let out = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-single",
        "--collection-id",
        "col-w2",
    ]);
    assert!(
        out.status.success(),
        "unavailable convergence failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("removed from the local vault cache"),
        "expected local-cache-removal notice, got: {stdout}"
    );

    // Verify 0600 file permissions on data.json and atomic eviction from storage.ciphers
    let data_path = env.temp.path().join("data").join("data.json");
    let mode = fs::metadata(&data_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "data.json must remain 0600 after eviction");
    let stored: Value = serde_json::from_str(&fs::read_to_string(&data_path).unwrap()).unwrap();
    let still_in_disk = stored["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["id"] == "org-cipher-single");
    assert!(
        !still_in_disk,
        "evicted cipher must not remain in disk storage.ciphers"
    );

    // Verify evicted from in-memory index
    let get_after = env.run_cli(&["vault", "get", "org-cipher-single", "--json"]);
    assert!(!get_after.status.success());

    // Also verify JSON envelope shape for unavailable: true on another writable cipher
    let out_json = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-writable",
        "--collection-id",
        "col-ro",
        "--collection-id",
        "col-w2",
        "--json",
    ]);
    assert!(out_json.status.success());
    let resp_json: Value = serde_json::from_slice(&out_json.stdout).unwrap();
    assert_eq!(resp_json["ok"], true);
    assert_eq!(resp_json["unavailable"], true);
    assert_eq!(resp_json["id"], "org-cipher-writable");
    assert_eq!(resp_json["outcome"], "evicted");

    stop.store(true, Ordering::SeqCst);
    assert_eq!(server.join().unwrap(), 2);
}

#[test]
fn vault_collections_fails_closed_before_http_on_invalid_permissions_and_scopes() {
    let env = TestEnv::new();
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let http_hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = Arc::clone(&http_hits);
    let listener = env.api.try_clone().unwrap();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = read_http_request(&mut stream);
                    hits_srv.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    // 1. Combining replace and delta flags rejected by clap
    let out_conflict = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-writable",
        "--collection-id",
        "col-w1",
        "--add",
        "col-w2",
        "--json",
    ]);
    assert!(!out_conflict.status.success());

    // 2. Removing the last remaining collection (empty target set)
    let out_empty = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-single",
        "--remove",
        "col-w1",
        "--json",
    ]);
    assert!(!out_empty.status.success());
    let err_empty: Value = serde_json::from_slice(&out_empty.stdout).unwrap();
    assert_eq!(err_empty["ok"], false);
    assert!(err_empty["error"]
        .as_str()
        .unwrap()
        .contains("at least one collection"));

    // 3. Personal cipher rejected
    let out_personal = env.run_cli(&[
        "vault",
        "collections",
        "personal-cipher",
        "--collection-id",
        "col-w1",
        "--json",
    ]);
    assert!(!out_personal.status.success());
    let err_personal: Value = serde_json::from_slice(&out_personal.stdout).unwrap();
    assert_eq!(err_personal["ok"], false);
    assert!(err_personal["error"]
        .as_str()
        .unwrap()
        .contains("Organization"));

    // 4. Org cipher with edit == false rejected
    let out_ro_cipher = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-readonly",
        "--add",
        "col-w2",
        "--json",
    ]);
    assert!(!out_ro_cipher.status.success());
    let err_ro_cipher: Value = serde_json::from_slice(&out_ro_cipher.stdout).unwrap();
    assert_eq!(err_ro_cipher["ok"], false);

    // 5. Org cipher with edit == true && viewPassword == false rejected
    let out_hidden = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-hidden-pw",
        "--add",
        "col-w2",
        "--json",
    ]);
    assert!(!out_hidden.status.success());
    let err_hidden: Value = serde_json::from_slice(&out_hidden.stdout).unwrap();
    assert_eq!(err_hidden["ok"], false);
    assert!(err_hidden["error"]
        .as_str()
        .unwrap()
        .contains("passwords are hidden"));

    // 6. Removing a non-writable collection (col-ro) rejected
    let out_rm_ro = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-writable",
        "--remove",
        "col-ro",
        "--json",
    ]);
    assert!(!out_rm_ro.status.success());
    let err_rm_ro: Value = serde_json::from_slice(&out_rm_ro.stdout).unwrap();
    assert_eq!(err_rm_ro["ok"], false);
    assert!(err_rm_ro["error"]
        .as_str()
        .unwrap()
        .contains("write permission"));

    // 7. Adding a non-writable collection (col-ro) rejected
    let out_add_ro = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-single",
        "--add",
        "col-ro",
        "--json",
    ]);
    assert!(!out_add_ro.status.success());

    // 8. Adding a cross-Organization collection (col-other-org) rejected
    let out_cross_org = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-single",
        "--add",
        "col-other-org",
        "--json",
    ]);
    assert!(!out_cross_org.status.success());
    let err_cross: Value = serde_json::from_slice(&out_cross_org.stdout).unwrap();
    assert_eq!(err_cross["ok"], false);
    assert!(err_cross["error"]
        .as_str()
        .unwrap()
        .contains("does not belong to Organization"));

    // 9. Trashed Org cipher rejected
    let out_trashed = env.run_cli(&[
        "vault",
        "collections",
        "org-cipher-trashed",
        "--add",
        "col-w2",
        "--json",
    ]);
    assert!(!out_trashed.status.success());

    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    assert_eq!(
        http_hits.load(Ordering::SeqCst),
        0,
        "fail-closed guards must reject before any HTTP request is issued"
    );
}
