use omawarden_engine::crypto::{
    decrypt_attachment_blob, derive_master_key, EncString, KdfType, SymmetricCryptoKey,
};
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
    body: Vec<u8>,
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
        body,
    }
}

fn extract_multipart_data_part(content_type: &str, body: &[u8]) -> (String, Vec<u8>) {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("missing boundary in Content-Type")
        .trim();
    let start_marker = format!("--{boundary}\r\n");
    let end_marker = format!("\r\n--{boundary}--");
    let start_pos = body
        .windows(start_marker.len())
        .position(|w| w == start_marker.as_bytes())
        .expect("missing start boundary");
    let after_start = &body[start_pos + start_marker.len()..];
    let header_end = after_start
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("missing multipart header separator");
    let headers_str = String::from_utf8_lossy(&after_start[..header_end]).to_string();
    let payload_start = &after_start[header_end + 4..];
    let end_pos = payload_start
        .windows(end_marker.len())
        .position(|w| w == end_marker.as_bytes())
        .expect("missing end boundary");
    (headers_str, payload_start[..end_pos].to_vec())
}

struct TestEnv {
    temp: tempfile::TempDir,
    api: TcpListener,
    user_key: SymmetricCryptoKey,
    cipher_key: SymmetricCryptoKey,
    keyed_cipher_json: Value,
    legacy_cipher_json: Value,
}

impl TestEnv {
    fn new(max_attachment_size_mb: u64) -> Self {
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
            "login": {
                "username": cipher_key.encrypt_string("alice").unwrap(),
                "password": cipher_key.encrypt_string("s3cret").unwrap()
            },
            "attachments": []
        });

        let legacy_cipher_json = json!({
            "id": "cipher-legacy-1",
            "type": 2,
            "name": user_key.encrypt_string("Personal Legacy Note").unwrap(),
            "key": null,
            "organizationId": null,
            "folderId": null,
            "favorite": false,
            "deletedDate": null,
            "revisionDate": "2026-11-26T00:00:00.000Z",
            "notes": user_key.encrypt_string("legacy unkeyed note").unwrap(),
            "attachments": []
        });

        let trashed_cipher_json = json!({
            "id": "cipher-trashed-1",
            "type": 2,
            "name": user_key.encrypt_string("Trashed Note").unwrap(),
            "key": null,
            "organizationId": null,
            "deletedDate": "2026-11-25T00:00:00.000Z",
            "attachments": []
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
            "attachments": []
        });

        let data_dir = dir.join("data");
        let cfg_dir = dir.join("config").join("omawarden");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&cfg_dir).unwrap();

        fs::write(
            cfg_dir.join("config.json"),
            json!({
                "server_url": server_url,
                "max_attachment_size_mb": max_attachment_size_mb,
            })
            .to_string(),
        )
        .unwrap();

        let data = json!({
            "user_email": email,
            "user_id": "user-uuid-1",
            "credential_id": "11111111111111111111111111111111",
            "server_url": server_url,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "enc_user_key": wrap,
            "ciphers": [
                keyed_cipher_json,
                legacy_cipher_json,
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
            user_key,
            cipher_key,
            keyed_cipher_json,
            legacy_cipher_json,
        }
    }

    fn cmd(&self) -> Command {
        let dir = self.temp.path();
        let path = format!("{}:/usr/bin:/bin", dir.display());
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.env_clear()
            .env("HOME", dir)
            .env("PATH", path)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("OMAWARDEN_DATA_DIR", dir.join("data"))
            .env("OMA_DAEMON_BIN", env!("CARGO_BIN_EXE_omawarden"))
            .env("OMA_KEYRING_PROVIDER", "secret-tool");
        cmd
    }

    fn start_daemon(&self) -> Daemon {
        let child = self
            .cmd()
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = Daemon(child);
        let socket = self.temp.path().join("omawarden.sock");
        let ping = ipc(&socket, json!({"action": "ping"}));
        assert_eq!(ping["ok"], true);
        let unlock = ipc(&socket, json!({"action": "unlock", "password": "fixture"}));
        assert_eq!(unlock["ok"], true, "unlock failed: {unlock}");
        daemon
    }
}

#[test]
fn attachment_upload_direct_end_to_end_text_and_json_with_cipher_key_and_legacy_unkeyed() {
    let env = TestEnv::new(500);
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = stop.clone();
    let api = env.api.try_clone().unwrap();
    let keyed_cipher = env.keyed_cipher_json.clone();
    let legacy_cipher = env.legacy_cipher_json.clone();
    let cipher_key = env.cipher_key.clone();
    let user_key = env.user_key.clone();

    type UploadedRecord = (String, String, Vec<u8>);
    let uploaded_records: Arc<Mutex<Vec<UploadedRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let records_srv = uploaded_records.clone();

    let server = thread::spawn(move || {
        let mut next_att_num = 0usize;
        let mut pending: HashMap<String, (String, String, String, u64)> = HashMap::new();
        let mut keyed_attachments: Vec<Value> = Vec::new();
        let mut legacy_attachments: Vec<Value> = Vec::new();

        while !stop_srv.load(Ordering::Relaxed) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream);
                    assert_eq!(
                        req.headers.get("authorization").map(String::as_str),
                        Some("Bearer fixture-token"),
                        "Expected Bearer auth on {} {}",
                        req.method,
                        req.path
                    );

                    if req.method == "POST" && req.path.ends_with("/attachment/v2") {
                        let cid = req
                            .path
                            .strip_prefix("/api/ciphers/")
                            .and_then(|s| s.strip_suffix("/attachment/v2"))
                            .unwrap()
                            .to_string();
                        let body: Value = serde_json::from_slice(&req.body).unwrap();
                        let wrapped_key = body["key"].as_str().unwrap().to_string();
                        let enc_name = body["fileName"].as_str().unwrap().to_string();
                        let file_size = body["fileSize"].as_u64().unwrap();
                        assert_eq!(body["adminRequest"], false);

                        next_att_num += 1;
                        let aid = format!("att-{next_att_num}");
                        pending.insert(
                            aid.clone(),
                            (
                                cid.clone(),
                                wrapped_key.clone(),
                                enc_name.clone(),
                                file_size,
                            ),
                        );

                        let att_obj = json!({
                            "id": aid,
                            "fileName": enc_name,
                            "key": wrapped_key,
                            "size": file_size.to_string(),
                            "sizeName": format!("{file_size} B")
                        });

                        let mut cipher_resp = if cid == "cipher-keyed-1" {
                            keyed_attachments.push(att_obj);
                            let mut c = keyed_cipher.clone();
                            c["attachments"] = json!(keyed_attachments);
                            c
                        } else {
                            legacy_attachments.push(att_obj);
                            let mut c = legacy_cipher.clone();
                            c["attachments"] = json!(legacy_attachments);
                            c
                        };
                        cipher_resp["revisionDate"] = json!("2026-11-27T01:00:00.000Z");

                        // Intentionally return a hostile cross-origin URL to prove Direct (0) ignores it!
                        let resp_body = json!({
                            "object": "attachment-fileUpload",
                            "attachmentId": aid,
                            "url": "https://evil.attacker.invalid/steal-bearer",
                            "fileUploadType": 0,
                            "cipherResponse": cipher_resp
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        );
                        stream.write_all(resp.as_bytes()).unwrap();
                    } else if req.method == "POST" && req.path.contains("/attachment/") {
                        let tail = req.path.strip_prefix("/api/ciphers/").unwrap();
                        let (cid, aid) = tail.split_once("/attachment/").unwrap();
                        let (exp_cid, wrapped_key, enc_name, exp_size) =
                            pending.remove(aid).expect("unexpected attachmentId");
                        assert_eq!(cid, exp_cid);

                        let ct = req.headers.get("content-type").unwrap();
                        let (part_headers, raw_blob) = extract_multipart_data_part(ct, &req.body);
                        assert!(part_headers.contains("name=\"data\""));
                        assert_eq!(raw_blob.len() as u64, exp_size);

                        let unwrap_with = if cid == "cipher-keyed-1" {
                            &cipher_key
                        } else {
                            &user_key
                        };
                        let decrypted_name = EncString::parse(&enc_name)
                            .unwrap()
                            .decrypt_string(unwrap_with)
                            .unwrap();
                        let raw_att_key = EncString::parse(&wrapped_key)
                            .unwrap()
                            .decrypt(unwrap_with)
                            .unwrap();
                        assert_eq!(raw_att_key.len(), 64);
                        let att_key = SymmetricCryptoKey::from_raw_bytes(&raw_att_key).unwrap();
                        let plaintext = decrypt_attachment_blob(&raw_blob, &att_key).unwrap();

                        records_srv.lock().unwrap().push((
                            cid.to_string(),
                            decrypted_name,
                            plaintext,
                        ));

                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .unwrap();
                    } else {
                        panic!("Unexpected HTTP request: {} {}", req.method, req.path);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    // 1. Keyed personal cipher upload with --name override and --json
    let payload_file = env.temp.path().join("original.bin");
    let secret_bytes = b"TLS-CERT-DATA-\x00\x01\xfe\xff-END";
    fs::write(&payload_file, secret_bytes).unwrap();

    let out = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            payload_file.to_str().unwrap(),
            "--name",
            "prod-cert.pem",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "upload failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let json_out: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_out["ok"], true);
    assert_eq!(json_out["item_id"], "cipher-keyed-1");
    assert_eq!(json_out["attachment"]["id"], "att-1");
    assert_eq!(json_out["attachment"]["fileName"], "prod-cert.pem");
    assert_eq!(json_out["item"]["id"], "cipher-keyed-1");
    assert_eq!(json_out["item"]["attachments"].as_array().unwrap().len(), 1);
    assert_eq!(json_out["protocol_version"], 1);

    // Verify data.json cache mode is 0600 and immediately reflects the uploaded attachment
    let data_path = env.temp.path().join("data/data.json");
    let mode = fs::metadata(&data_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "data.json must remain 0600 after cache upsert");

    let get_out = env
        .cmd()
        .args(["vault", "get", "cipher-keyed-1", "--json"])
        .output()
        .unwrap();
    assert!(get_out.status.success());
    let get_json: Value = serde_json::from_slice(&get_out.stdout).unwrap();
    assert_eq!(
        get_json["item"]["attachments"][0]["fileName"],
        "prod-cert.pem"
    );

    // 2. Legacy unkeyed personal cipher upload: 0-byte regular file in default text mode (basename derived)
    let empty_file = env.temp.path().join("empty-marker.txt");
    fs::write(&empty_file, b"").unwrap();
    let out_empty = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-legacy-1",
            "--file",
            empty_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out_empty.status.success(),
        "0-byte upload failed: stderr={}",
        String::from_utf8_lossy(&out_empty.stderr)
    );
    let stdout_text = String::from_utf8_lossy(&out_empty.stdout);
    assert!(stdout_text.contains("empty-marker.txt"), "{stdout_text}");
    assert!(stdout_text.contains("att-2"), "{stdout_text}");

    // 3. Duplicate filename on the same Cipher is allowed
    let out_dup = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-legacy-1",
            "--file",
            empty_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(out_dup.status.success());
    let dup_json: Value = serde_json::from_slice(&out_dup.stdout).unwrap();
    assert_eq!(dup_json["attachment"]["id"], "att-3");
    assert_eq!(dup_json["item"]["attachments"].as_array().unwrap().len(), 2);

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    let records = uploaded_records.lock().unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].0, "cipher-keyed-1");
    assert_eq!(records[0].1, "prod-cert.pem");
    assert_eq!(records[0].2, secret_bytes);
    assert_eq!(records[1].0, "cipher-legacy-1");
    assert_eq!(records[1].1, "empty-marker.txt");
    assert!(records[1].2.is_empty());
    assert_eq!(records[2].0, "cipher-legacy-1");
    assert_eq!(records[2].1, "empty-marker.txt");
    assert!(records[2].2.is_empty());
}

#[test]
fn attachment_upload_step2_failure_triggers_rollback_and_preserves_cache() {
    let env = TestEnv::new(500);
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = stop.clone();
    let api = env.api.try_clone().unwrap();
    let keyed_cipher = env.keyed_cipher_json.clone();
    let rollback_called = Arc::new(AtomicBool::new(false));
    let rollback_srv = rollback_called.clone();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream);
                    if req.method == "POST"
                        && req.path == "/api/ciphers/cipher-keyed-1/attachment/v2"
                    {
                        let mut cipher_resp = keyed_cipher.clone();
                        cipher_resp["attachments"] = json!([{
                            "id": "att-rollback-1",
                            "fileName": "2.a|b|c",
                            "size": "65",
                            "sizeName": "65 B"
                        }]);
                        let body = json!({
                            "attachmentId": "att-rollback-1",
                            "url": "/ciphers/cipher-keyed-1/attachment/att-rollback-1",
                            "fileUploadType": 0,
                            "cipherResponse": cipher_resp
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream.write_all(resp.as_bytes()).unwrap();
                    } else if req.method == "POST"
                        && req.path == "/api/ciphers/cipher-keyed-1/attachment/att-rollback-1"
                    {
                        let body = "storage disk full";
                        let resp = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream.write_all(resp.as_bytes()).unwrap();
                    } else if req.method == "DELETE"
                        && req.path == "/api/ciphers/cipher-keyed-1/attachment/att-rollback-1"
                    {
                        assert_eq!(
                            req.headers.get("authorization").map(String::as_str),
                            Some("Bearer fixture-token")
                        );
                        rollback_srv.store(true, Ordering::Relaxed);
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .unwrap();
                    } else {
                        panic!("Unexpected request: {} {}", req.method, req.path);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let file_path = env.temp.path().join("doc.txt");
    fs::write(&file_path, b"hello rollback").unwrap();

    let out = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            file_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(!out.status.success());
    let json_out: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_out["ok"], false);
    assert!(
        json_out["error"]
            .as_str()
            .unwrap()
            .contains("step 2 failed"),
        "Unexpected error: {json_out}"
    );
    assert!(
        rollback_called.load(Ordering::Relaxed),
        "Step 2 failure MUST invoke DELETE rollback"
    );

    // Local cache and in-memory index must remain untouched
    let get_out = env
        .cmd()
        .args(["vault", "get", "cipher-keyed-1", "--json"])
        .output()
        .unwrap();
    assert!(get_out.status.success());
    let get_json: Value = serde_json::from_slice(&get_out.stdout).unwrap();
    assert!(
        get_json["item"]["attachments"]
            .as_array()
            .unwrap()
            .is_empty(),
        "Local cache must remain untouched after Step 2 failure"
    );
}

#[test]
fn attachment_upload_dual_failure_surfaces_primary_error_and_unvalidated_slot_warning() {
    let env = TestEnv::new(500);
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = stop.clone();
    let api = env.api.try_clone().unwrap();
    let keyed_cipher = env.keyed_cipher_json.clone();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let req = read_http_request(&mut stream);
                    if req.method == "POST"
                        && req.path == "/api/ciphers/cipher-keyed-1/attachment/v2"
                    {
                        let body = json!({
                            "attachmentId": "att-dual-fail",
                            "url": "/ciphers/cipher-keyed-1/attachment/att-dual-fail",
                            "fileUploadType": 0,
                            "cipherResponse": keyed_cipher
                        })
                        .to_string();
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        stream.write_all(resp.as_bytes()).unwrap();
                    } else if req.method == "POST"
                        && req.path == "/api/ciphers/cipher-keyed-1/attachment/att-dual-fail"
                    {
                        stream
                            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nboom")
                            .unwrap();
                    } else if req.method == "DELETE"
                        && req.path == "/api/ciphers/cipher-keyed-1/attachment/att-dual-fail"
                    {
                        stream
                            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndown")
                            .unwrap();
                    } else {
                        panic!("Unexpected request: {} {}", req.method, req.path);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let file_path = env.temp.path().join("dual.txt");
    fs::write(&file_path, b"dual failure test").unwrap();

    let out = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            file_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert!(!out.status.success());
    let json_out: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_out["ok"], false);
    let err = json_out["error"].as_str().unwrap();
    assert!(
        err.contains("step 2 failed"),
        "Missing primary error: {err}"
    );
    assert!(
        err.contains("unvalidated attachment slot may remain on the server"),
        "Missing dual-failure warning: {err}"
    );
}

#[test]
fn attachment_upload_fails_closed_before_http_on_trash_org_oversized_and_invalid_inputs() {
    let env = TestEnv::new(1); // 1 MiB limit
    let _daemon = env.start_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = stop.clone();
    let api = env.api.try_clone().unwrap();
    let http_hits = Arc::new(AtomicUsize::new(0));
    let hits_srv = http_hits.clone();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match api.accept() {
                Ok((_stream, _)) => {
                    hits_srv.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let good_file = env.temp.path().join("small.txt");
    fs::write(&good_file, b"ok").unwrap();

    // 1. Trashed cipher fails closed
    let res_trash = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-trashed-1",
            "--file",
            good_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!res_trash.status.success());
    let v: Value = serde_json::from_slice(&res_trash.stdout).unwrap();
    assert!(v["error"].as_str().unwrap().contains("trashed"), "{v}");

    // 2. Organization cipher fails closed
    let res_org = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-org-1",
            "--file",
            good_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!res_org.status.success());
    let v: Value = serde_json::from_slice(&res_org.stdout).unwrap();
    assert!(v["error"].as_str().unwrap().contains("Organization"), "{v}");

    // 3. Invalid --name fails closed
    let res_bad_name = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            good_file.to_str().unwrap(),
            "--name",
            "../escape.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!res_bad_name.status.success());
    let v: Value = serde_json::from_slice(&res_bad_name.stdout).unwrap();
    assert!(
        v["error"].as_str().unwrap().contains("single basename"),
        "{v}"
    );

    // 4. Directory as --file fails closed
    let res_dir = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            env.temp.path().to_str().unwrap(),
            "--name",
            "dir.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!res_dir.status.success());
    let v: Value = serde_json::from_slice(&res_dir.stdout).unwrap();
    assert!(
        v["error"].as_str().unwrap().contains("not a regular file"),
        "{v}"
    );

    // 5. Oversized file (> 1 MiB) fails closed with explicit allowed-range error
    let big_file = env.temp.path().join("oversized.bin");
    fs::write(&big_file, vec![0u8; 1024 * 1024 + 1]).unwrap();
    let res_big = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            big_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!res_big.status.success());
    let v: Value = serde_json::from_slice(&res_big.stdout).unwrap();
    let err = v["error"].as_str().unwrap();
    assert!(err.contains("exceeds the maximum allowed size"), "{err}");
    assert!(err.contains("allowed range: 0 to 1 MiB"), "{err}");

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    assert_eq!(
        http_hits.load(Ordering::Relaxed),
        0,
        "Zero HTTP requests may be made when local guardrails reject the upload"
    );
}

#[test]
fn attachment_upload_capability_gating_auto_restarts_stale_standalone_daemon() {
    let env = TestEnv::new(500);
    let socket = env.temp.path().join("omawarden.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    let stop_seen = Arc::new(AtomicBool::new(false));
    let stop_seen_srv = stop_seen.clone();
    let socket_srv = socket.clone();

    // Fake stale standalone daemon missing "attachment_upload" in ping.capabilities
    let stale_daemon = thread::spawn(move || {
        for _ in 0..4 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let mut line = String::new();
            let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
            let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
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
                            "capabilities": ["cipher_mutation_v3", "folder_crud"],
                            "unlocked": true
                        })
                    );
                }
                Some("stop") if req["admin"] == true => {
                    stop_seen_srv.store(true, Ordering::Relaxed);
                    let _ = writeln!(stream, "{}", json!({ "ok": true, "protocol_version": 1 }));
                    drop(listener);
                    let _ = fs::remove_file(&socket_srv);
                    break;
                }
                _ => {
                    let _ = writeln!(stream, "{}", json!({ "ok": false, "error": "unsupported" }));
                }
            }
        }
    });

    let file_path = env.temp.path().join("cap.txt");
    fs::write(&file_path, b"hello").unwrap();

    // Run CLI: it will detect missing "attachment_upload", stop the stale daemon,
    // restart the real standalone daemon, and then fail closed on locked vault
    // (proving restart succeeded and ping now advertises "attachment_upload").
    let out = env
        .cmd()
        .args([
            "attachment",
            "upload",
            "--item-id",
            "cipher-keyed-1",
            "--file",
            file_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    stale_daemon.join().unwrap();

    // Clean up the auto-restarted daemon
    let _ = ipc(&socket, json!({ "action": "stop", "admin": true }));

    assert!(
        stop_seen.load(Ordering::Relaxed),
        "Client must stop stale standalone daemon when 'attachment_upload' capability is absent"
    );
    let json_out: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json_out["ok"], false);
    assert!(
        json_out["error"]
            .as_str()
            .unwrap()
            .contains("Unlock the vault before uploading an attachment."),
        "After auto-restart, real daemon should be running with 'attachment_upload' capability and prompt unlock: {json_out}"
    );
}
