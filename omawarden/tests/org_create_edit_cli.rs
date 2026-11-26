use omawarden::crypto::{derive_master_key, EncString, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
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
    fn new(include_org_key: bool) -> Self {
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

        // Cipher key wrapped under org_key for writable org login
        let raw_cipher_key = [99u8; 64];
        let cipher_key = SymmetricCryptoKey::from_raw_bytes(&raw_cipher_key).unwrap();
        let enc_cipher_key = org_key.encrypt(&raw_cipher_key).unwrap();

        let mut org_obj = json!({
            "id": "org-1",
            "name": "Acme Corp",
            "type": 2,
            "enabled": true
        });
        if include_org_key {
            org_obj["key"] = json!(enc_org_key);
        }

        let cache = dir.join("data.json");
        let data = json!({
            "user_id": "user-id-123",
            "user_email": email,
            "server_url": server_url,
            "credential_id": "11111111111111111111111111111111",
            "enc_user_key": wrap,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "folders": [],
            "organizations": [
                org_obj,
                {
                    "id": "org-2",
                    "name": "Other Org",
                    "key": user_key.encrypt(&[88u8; 64]).unwrap(),
                    "type": 2,
                    "enabled": true
                }
            ],
            "collections": [
                {
                    "id": "col-writable",
                    "organizationId": "org-1",
                    "name": org_key.encrypt_string("Engineering").unwrap(),
                    "readOnly": false,
                    "hidePasswords": false,
                    "manage": false
                },
                {
                    "id": "col-manage",
                    "organizationId": "org-1",
                    "name": org_key.encrypt_string("Admins").unwrap(),
                    "readOnly": true,
                    "hidePasswords": false,
                    "manage": true
                },
                {
                    "id": "col-readonly",
                    "organizationId": "org-1",
                    "name": org_key.encrypt_string("ReadOnly").unwrap(),
                    "readOnly": true,
                    "hidePasswords": true,
                    "manage": false
                },
                {
                    "id": "col-other-org",
                    "organizationId": "org-2",
                    "name": "Other Col",
                    "readOnly": false,
                    "hidePasswords": false,
                    "manage": true
                }
            ],
            "ciphers": [
                {
                    "id": "org-writable-login",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 1,
                    "key": enc_cipher_key,
                    "name": cipher_key.encrypt_string("Shared Staging").unwrap(),
                    "notes": null,
                    "favorite": false,
                    "edit": true,
                    "viewPassword": true,
                    "permissions": { "delete": true, "restore": true },
                    "collectionIds": ["col-writable"],
                    "login": {
                        "username": cipher_key.encrypt_string("stage_user").unwrap(),
                        "password": cipher_key.encrypt_string("stage_pass").unwrap(),
                        "uris": []
                    },
                    "fields": [],
                    "revisionDate": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "org-hidden-login",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 1,
                    "name": org_key.encrypt_string("Hidden Secret").unwrap(),
                    "notes": null,
                    "favorite": false,
                    "edit": true,
                    "viewPassword": false,
                    "permissions": { "delete": false, "restore": false },
                    "collectionIds": ["col-writable"],
                    "login": {
                        "username": org_key.encrypt_string("hidden_user").unwrap(),
                        "password": org_key.encrypt_string("top_secret").unwrap(),
                        "uris": []
                    },
                    "fields": [],
                    "revisionDate": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "org-readonly-login",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 1,
                    "name": org_key.encrypt_string("ReadOnly Login").unwrap(),
                    "notes": null,
                    "favorite": false,
                    "edit": false,
                    "viewPassword": true,
                    "permissions": { "delete": false, "restore": false },
                    "collectionIds": ["col-readonly"],
                    "login": {
                        "username": org_key.encrypt_string("ro_user").unwrap(),
                        "password": org_key.encrypt_string("ro_pass").unwrap(),
                        "uris": []
                    },
                    "fields": [],
                    "revisionDate": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "org-ssh-1",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 5,
                    "name": org_key.encrypt_string("Org Deploy Key").unwrap(),
                    "notes": org_key.encrypt_string("old notes").unwrap(),
                    "favorite": false,
                    "edit": true,
                    "viewPassword": true,
                    "permissions": { "delete": true, "restore": true },
                    "collectionIds": ["col-writable"],
                    "sshKey": {
                        "privateKey": org_key.encrypt_string("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----").unwrap(),
                        "publicKey": org_key.encrypt_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@org").unwrap(),
                        "keyFingerprint": org_key.encrypt_string("SHA256:orgfp").unwrap()
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
fn org_create_login_and_stdin_encrypts_with_org_key_and_decrypts_immediately() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_and_unlock_daemon();

    let api = env.api.try_clone().unwrap();
    let captured = Arc::new(std::sync::Mutex::new(Vec::<(String, String, Value)>::new()));
    let cap_clone = captured.clone();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut counter = 0u32;
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, body) = read_http_request(&mut stream);
                    let parsed: Value = serde_json::from_slice(&body).unwrap_or_default();
                    cap_clone
                        .lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), parsed.clone()));
                    counter += 1;
                    let mut cipher_resp = parsed["cipher"].clone();
                    cipher_resp["id"] = json!(format!("created-org-{counter}"));
                    cipher_resp["collectionIds"] = parsed["collectionIds"].clone();
                    cipher_resp["edit"] = json!(true);
                    cipher_resp["viewPassword"] = json!(true);
                    cipher_resp["permissions"] = json!({ "delete": true, "restore": true });
                    cipher_resp["revisionDate"] = json!("2026-01-03T00:00:00Z");
                    let resp_body = cipher_resp.to_string();
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

    // 1. CLI flags create with repeatable --collection-id
    let out1 = env.run_cli(
        &[
            "vault",
            "create",
            "login",
            "--name",
            "Team DB",
            "--username",
            "dbadmin",
            "--password-stdin",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-writable",
            "--collection-id",
            "col-manage",
            "--json",
        ],
        Some("super-secret-pass\n"),
    );
    assert!(
        out1.status.success(),
        "org create login failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let body1: Value = serde_json::from_slice(&out1.stdout).unwrap();
    assert_eq!(body1["ok"], true);
    assert_eq!(body1["outcome"], "saved");

    // Verify immediate local cache decryption (not "Untitled")
    let get1 = env.run_cli(&["vault", "get", "created-org-1", "--json"], None);
    assert!(get1.status.success());
    let item1: Value = serde_json::from_slice(&get1.stdout).unwrap();
    assert_eq!(item1["item"]["name"], "Team DB");
    assert_eq!(item1["item"]["organization_id"], "org-1");
    assert_eq!(item1["item"]["login"]["username"], "dbadmin");
    assert_eq!(item1["item"]["login"]["password"], "super-secret-pass");

    // 2. --stdin JSON create for Secure Note in Organization
    let out2 = env.run_cli(
        &["vault", "create", "--stdin", "--json"],
        Some(
            r#"{"type": 2, "name": "Runbook", "notes": "Restart service", "organization_id": "org-1", "collection_ids": ["col-writable"]}"#,
        ),
    );
    assert!(
        out2.status.success(),
        "org create --stdin failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
    let get2 = env.run_cli(&["vault", "get", "created-org-2", "--json"], None);
    let item2: Value = serde_json::from_slice(&get2.stdout).unwrap();
    assert_eq!(item2["item"]["name"], "Runbook");
    assert_eq!(item2["item"]["notes"], "Restart service");

    stop_flag.store(true, Ordering::SeqCst);
    let _ = server.join();

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].0, "POST");
    assert_eq!(reqs[0].1, "/api/ciphers/create");
    assert_eq!(reqs[0].2["cipher"]["organizationId"], "org-1");
    assert_eq!(reqs[0].2["cipher"]["encryptedFor"], "user-id-123");
    assert_eq!(
        reqs[0].2["collectionIds"],
        json!(["col-writable", "col-manage"])
    );

    // Verify cipher.key is wrapped strictly under org_key (NOT user_key!)
    let enc_key_str = reqs[0].2["cipher"]["key"].as_str().unwrap();
    let enc_key = EncString::parse(enc_key_str).unwrap();
    assert!(
        enc_key.decrypt(&env.user_key).is_err(),
        "cipher.key must NOT be decryptable with user_key"
    );
    let raw_ck = enc_key
        .decrypt(&env.org_key)
        .expect("cipher.key must decrypt with org_key");
    let ck = SymmetricCryptoKey::from_raw_bytes(&raw_ck).unwrap();
    let dec_name = EncString::parse(reqs[0].2["cipher"]["name"].as_str().unwrap())
        .unwrap()
        .decrypt_string(&ck)
        .unwrap();
    assert_eq!(dec_name, "Team DB");
}

#[test]
fn org_create_rejects_empty_non_writable_or_cross_org_collections_fail_closed() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_and_unlock_daemon();

    // Missing collection-id
    let out1 = env.run_cli(
        &[
            "vault",
            "create",
            "note",
            "--name",
            "No Col",
            "--notes",
            "hello",
            "--organization-id",
            "org-1",
            "--json",
        ],
        None,
    );
    assert!(!out1.status.success());

    // Read-only collection
    let out2 = env.run_cli(
        &[
            "vault",
            "create",
            "note",
            "--name",
            "RO Col",
            "--notes",
            "hello",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-readonly",
            "--json",
        ],
        None,
    );
    assert!(!out2.status.success());

    // Cross-organization collection
    let out3 = env.run_cli(
        &[
            "vault",
            "create",
            "note",
            "--name",
            "Cross Org",
            "--notes",
            "hello",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-other-org",
            "--json",
        ],
        None,
    );
    assert!(!out3.status.success());

    // Zero HTTP requests must have been sent
    assert!(env.api.accept().is_err());
}

#[test]
fn org_edit_succeeds_when_writable_and_fails_closed_when_hidden_or_readonly() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_and_unlock_daemon();

    let api = env.api.try_clone().unwrap();
    let captured = Arc::new(std::sync::Mutex::new(Vec::<(String, String, Value)>::new()));
    let cap_clone = captured.clone();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, body) = read_http_request(&mut stream);
                    let parsed: Value = serde_json::from_slice(&body).unwrap_or_default();
                    cap_clone
                        .lock()
                        .unwrap()
                        .push((method.clone(), path.clone(), parsed.clone()));
                    let mut resp_json = if path.ends_with("/partial") {
                        json!({
                            "id": "org-hidden-login",
                            "favorite": parsed["favorite"],
                            "folderId": parsed["folderId"]
                        })
                    } else {
                        let mut c = parsed.clone();
                        c["edit"] = json!(true);
                        c["viewPassword"] = json!(true);
                        c["permissions"] = json!({ "delete": true, "restore": true });
                        c["revisionDate"] = json!("2026-01-04T00:00:00Z");
                        c
                    };
                    if path.contains("org-writable-login") {
                        resp_json["id"] = json!("org-writable-login");
                    } else if path.contains("org-ssh-1") {
                        resp_json["id"] = json!("org-ssh-1");
                    }
                    let resp_body = resp_json.to_string();
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

    // 1. Writable Org Login (edit: true, viewPassword: true) -> succeeds via PUT /api/ciphers/{id}
    let out1 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-writable-login",
            "--name",
            "Updated Staging",
            "--json",
        ],
        None,
    );
    assert!(
        out1.status.success(),
        "writable org edit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let get1 = env.run_cli(&["vault", "get", "org-writable-login", "--json"], None);
    let item1: Value = serde_json::from_slice(&get1.stdout).unwrap();
    assert_eq!(item1["item"]["name"], "Updated Staging");

    // 2. Writable Org SSH Key metadata-only edit -> succeeds
    let out2 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-ssh-1",
            "--name",
            "Org Prod Key",
            "--notes",
            "updated notes",
            "--json",
        ],
        None,
    );
    assert!(
        out2.status.success(),
        "writable org ssh edit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
    let get2 = env.run_cli(&["vault", "get", "org-ssh-1", "--json"], None);
    let item2: Value = serde_json::from_slice(&get2.stdout).unwrap();
    assert_eq!(item2["item"]["name"], "Org Prod Key");
    assert_eq!(item2["item"]["notes"], "updated notes");

    // 3. edit: true && viewPassword: false -> full content edit MUST fail closed
    let out3 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-hidden-login",
            "--name",
            "Should Fail",
            "--json",
        ],
        None,
    );
    assert!(!out3.status.success());

    // 4. edit: true && viewPassword: false -> /partial favorite STILL succeeds
    let out4 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-hidden-login",
            "--favorite",
            "true",
            "--json",
        ],
        None,
    );
    assert!(
        out4.status.success(),
        "partial favorite on hidden-password org cipher failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out4.stdout),
        String::from_utf8_lossy(&out4.stderr)
    );

    // 5. edit: false -> full content edit MUST fail closed
    let out5 = env.run_cli(
        &[
            "vault",
            "edit",
            "org-readonly-login",
            "--name",
            "Should Fail",
            "--json",
        ],
        None,
    );
    assert!(!out5.status.success());

    stop_flag.store(true, Ordering::SeqCst);
    let _ = server.join();

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[0].0, "PUT");
    assert_eq!(reqs[0].1, "/api/ciphers/org-writable-login");
    assert_eq!(reqs[0].2["organizationId"], "org-1");
    assert_eq!(reqs[0].2["encryptedFor"], "user-id-123");
    assert_eq!(reqs[1].0, "PUT");
    assert_eq!(reqs[1].1, "/api/ciphers/org-ssh-1");
    assert_eq!(reqs[2].0, "PUT");
    assert_eq!(reqs[2].1, "/api/ciphers/org-hidden-login/partial");
}

#[test]
fn org_edit_fails_closed_when_org_key_is_missing() {
    let env = TestEnv::new(false);
    let _daemon = env.spawn_and_unlock_daemon();

    let out = env.run_cli(
        &[
            "vault",
            "edit",
            "org-writable-login",
            "--name",
            "Must Not Corrupt",
            "--json",
        ],
        None,
    );
    assert!(!out.status.success());
    // Must not fall back to user_key or send any HTTP request
    assert!(env.api.accept().is_err());
}
