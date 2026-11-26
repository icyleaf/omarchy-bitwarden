use omawarden::crypto::{
    derive_master_key, parse_symmetric_key_from_decrypted_bytes, EncString, KdfType,
    SymmetricCryptoKey,
};
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
    modern_cipher_raw_key: [u8; 64],
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

        let modern_cipher_raw_key = [99u8; 64];
        let modern_cipher_key = SymmetricCryptoKey::from_raw_bytes(&modern_cipher_raw_key).unwrap();
        let enc_modern_cipher_key = user_key.encrypt(&modern_cipher_raw_key).unwrap();

        let raw_att_key = [55u8; 64];
        let enc_att_key = modern_cipher_key.encrypt(&raw_att_key).unwrap();

        let mut org_obj = json!({
            "id": "org-1",
            "name": "Acme Corp",
            "type": 2,
            "enabled": true
        });
        if include_org_key {
            org_obj["key"] = json!(enc_org_key);
        }
        let org_other = json!({
            "id": "org-2",
            "name": "Other Corp",
            "type": 2,
            "enabled": true,
            "key": user_key.encrypt(&[88u8; 64]).unwrap()
        });

        let enc_col_write = org_key.encrypt_string("Engineering").unwrap();
        let enc_col_ro = org_key.encrypt_string("ReadOnly").unwrap();
        let enc_col_other = SymmetricCryptoKey::from_raw_bytes(&[88u8; 64])
            .unwrap()
            .encrypt_string("Other Team")
            .unwrap();

        let org_cipher_raw_key = [66u8; 64];
        let org_cipher_key = SymmetricCryptoKey::from_raw_bytes(&org_cipher_raw_key).unwrap();
        let enc_org_cipher_key = org_key.encrypt(&org_cipher_raw_key).unwrap();

        let ciphers = vec![
            // 1. Modern personal Login with a modern keyed attachment
            json!({
                "id": "personal-login-modern",
                "type": 1,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": enc_modern_cipher_key,
                "name": modern_cipher_key.encrypt_string("Modern Login").unwrap(),
                "notes": modern_cipher_key.encrypt_string("Login notes").unwrap(),
                "login": {
                    "username": modern_cipher_key.encrypt_string("alice").unwrap(),
                    "password": modern_cipher_key.encrypt_string("s3cr3t!").unwrap(),
                    "uris": [{ "uri": modern_cipher_key.encrypt_string("https://example.com").unwrap(), "match": null }]
                },
                "attachments": [{
                    "id": "att-modern-1",
                    "fileName": modern_cipher_key.encrypt_string("cert.pem").unwrap(),
                    "key": enc_att_key,
                    "size": "128",
                    "sizeName": "128 Bytes"
                }],
                "encryptedByKeyId": "user-key-legacy-marker",
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 2. Modern personal SSH Key (Type 5)
            json!({
                "id": "personal-ssh-modern",
                "type": 5,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": enc_modern_cipher_key,
                "name": modern_cipher_key.encrypt_string("Deploy SSH Key").unwrap(),
                "sshKey": {
                    "privateKey": modern_cipher_key.encrypt_string("-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(),
                    "publicKey": modern_cipher_key.encrypt_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5").unwrap(),
                    "keyFingerprint": modern_cipher_key.encrypt_string("SHA256:testfp").unwrap()
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 3. Legacy personal Login (cipher.key == null, zero attachments)
            json!({
                "id": "personal-login-legacy",
                "type": 1,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": null,
                "name": user_key.encrypt_string("Legacy Login").unwrap(),
                "notes": user_key.encrypt_string("Legacy notes").unwrap(),
                "login": {
                    "username": user_key.encrypt_string("legacy-user").unwrap(),
                    "password": user_key.encrypt_string("legacy-pass").unwrap(),
                    "totp": user_key.encrypt_string("JBSWY3DPEHPK3PXP").unwrap(),
                    "uris": [{ "uri": user_key.encrypt_string("https://legacy.example.com").unwrap(), "match": null }]
                },
                "fields": [{
                    "name": user_key.encrypt_string("env").unwrap(),
                    "value": user_key.encrypt_string("prod").unwrap(),
                    "type": 0
                }],
                "passwordHistory": [{
                    "password": user_key.encrypt_string("old-pass").unwrap(),
                    "lastUsedDate": "2025-01-01T00:00:00Z"
                }],
                "attachments": [],
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 4. Modern personal Cipher with legacy UNKEYED attachment (attachment.key == null)
            json!({
                "id": "personal-unkeyed-att",
                "type": 2,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": enc_modern_cipher_key,
                "name": modern_cipher_key.encrypt_string("Unkeyed Att Note").unwrap(),
                "secureNote": { "type": 0 },
                "attachments": [{
                    "id": "att-legacy-1",
                    "fileName": modern_cipher_key.encrypt_string("old.txt").unwrap(),
                    "key": null,
                    "size": "64"
                }],
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 5. Legacy no-cipher.key Cipher WITH an attachment
            json!({
                "id": "personal-legacy-with-att",
                "type": 2,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": null,
                "name": user_key.encrypt_string("Legacy Att Note").unwrap(),
                "secureNote": { "type": 0 },
                "attachments": [{
                    "id": "att-any-1",
                    "fileName": user_key.encrypt_string("doc.txt").unwrap(),
                    "key": user_key.encrypt(&raw_att_key).unwrap(),
                    "size": "64"
                }],
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 6. Already Organization-owned Cipher
            json!({
                "id": "already-org-cipher",
                "type": 1,
                "organizationId": "org-1",
                "collectionIds": ["col-write"],
                "folderId": null,
                "favorite": false,
                "edit": true,
                "viewPassword": true,
                "key": enc_org_cipher_key,
                "name": org_cipher_key.encrypt_string("Already Shared").unwrap(),
                "login": {
                    "username": org_cipher_key.encrypt_string("svc").unwrap(),
                    "password": org_cipher_key.encrypt_string("pw").unwrap()
                },
                "revisionDate": "2026-01-01T00:00:00Z"
            }),
            // 7. Trashed personal Cipher
            json!({
                "id": "personal-trashed",
                "type": 2,
                "organizationId": null,
                "folderId": null,
                "favorite": false,
                "key": enc_modern_cipher_key,
                "name": modern_cipher_key.encrypt_string("Trashed Note").unwrap(),
                "secureNote": { "type": 0 },
                "deletedDate": "2026-02-01T00:00:00Z",
                "revisionDate": "2026-02-01T00:00:00Z"
            }),
        ];

        let data_dir = dir.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let vault_path = data_dir.join("data.json");
        fs::write(
            &vault_path,
            serde_json::to_vec(&json!({
                "user_email": email,
                "user_id": "user-1",
                "server_url": server_url,
                "credential_id": "11111111111111111111111111111111",
                "kdf": 0,
                "kdf_iterations": 100_000,
                "enc_user_key": wrap,
                "folders": [],
                "organizations": [org_obj, org_other],
                "collections": [
                    {
                        "id": "col-write",
                        "organizationId": "org-1",
                        "name": enc_col_write,
                        "readOnly": false,
                        "hidePasswords": false,
                        "manage": false
                    },
                    {
                        "id": "col-ro",
                        "organizationId": "org-1",
                        "name": enc_col_ro,
                        "readOnly": true,
                        "hidePasswords": false,
                        "manage": false
                    },
                    {
                        "id": "col-other-org",
                        "organizationId": "org-2",
                        "name": enc_col_other,
                        "readOnly": false,
                        "hidePasswords": false,
                        "manage": true
                    }
                ],
                "ciphers": ciphers
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&vault_path, fs::Permissions::from_mode(0o600)).unwrap();

        Self {
            temp,
            api,
            user_key,
            org_key,
            modern_cipher_raw_key,
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

    fn spawn_unlocked_daemon(&self) -> Daemon {
        let child = self
            .cmd()
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let socket = self.temp.path().join("omawarden.sock");
        let unlock = ipc(
            &socket,
            json!({ "action": "unlock", "password": "fixture" }),
        );
        assert_eq!(unlock["ok"], true, "unlock failed: {unlock}");
        Daemon(child)
    }
}

#[test]
fn share_modern_login_and_ssh_key_rewraps_cipher_key_preserves_keyed_attachments_and_caches() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_unlocked_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();
    let captured = Arc::new(std::sync::Mutex::new(Vec::<(String, String, Value)>::new()));
    let captured_srv = Arc::clone(&captured);

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, body) = read_http_request(&mut stream);
                    let req_json: Value = serde_json::from_slice(&body).unwrap();
                    captured_srv.lock().unwrap().push((
                        method.clone(),
                        path.clone(),
                        req_json.clone(),
                    ));

                    let mut resp_cipher = req_json["cipher"].clone();
                    resp_cipher["collectionIds"] = req_json["collectionIds"].clone();
                    resp_cipher["edit"] = json!(true);
                    resp_cipher["viewPassword"] = json!(true);
                    resp_cipher["revisionDate"] = json!("2026-03-01T00:00:00Z");
                    let resp_body = serde_json::to_vec(&resp_cipher).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp_body.len()
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                    stream.write_all(&resp_body).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    // 1. Share modern Login with modern keyed attachment
    let out = env
        .cmd()
        .args([
            "vault",
            "share",
            "personal-login-modern",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-write",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "share login failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let resp: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["outcome"], "shared");
    assert_eq!(resp["item"]["organization_id"], "org-1");

    // 2. Share modern personal SSH Key
    let out_ssh = env
        .cmd()
        .args([
            "vault",
            "share",
            "personal-ssh-modern",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-write",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out_ssh.status.success(),
        "share ssh key failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_ssh.stdout),
        String::from_utf8_lossy(&out_ssh.stderr)
    );

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].0, "PUT");
    assert_eq!(reqs[0].1, "/api/ciphers/personal-login-modern/share");
    assert_eq!(reqs[0].2["collectionIds"], json!(["col-write"]));
    let sent_cipher = &reqs[0].2["cipher"];
    assert_eq!(sent_cipher["organizationId"], "org-1");
    assert_eq!(sent_cipher["encryptedFor"], "user-1");
    assert!(
        sent_cipher.get("encryptedByKeyId").is_none(),
        "encryptedByKeyId must be omitted for Organization ciphers"
    );

    // Verify cipher.key was re-wrapped under org_key (NOT user_key) and preserves the exact 64-byte key
    let rewrapped_k = sent_cipher["key"].as_str().unwrap();
    let enc_k = EncString::parse(rewrapped_k).unwrap();
    assert!(
        enc_k.decrypt(&env.user_key).is_err(),
        "re-wrapped cipher.key must not decrypt under user_key"
    );
    let unwrapped_bytes = enc_k.decrypt(&env.org_key).unwrap();
    assert_eq!(unwrapped_bytes.as_slice(), &env.modern_cipher_raw_key);

    // Verify modern keyed attachment was preserved
    assert_eq!(
        sent_cipher["attachments"][0]["id"].as_str(),
        Some("att-modern-1")
    );
    assert!(sent_cipher["attachments"][0]["key"].as_str().is_some());

    // Verify immediate local cache decryption (not "Untitled")
    let get_out = env
        .cmd()
        .args([
            "vault",
            "get",
            "personal-login-modern",
            "--json",
            "--reveal",
        ])
        .output()
        .unwrap();
    assert!(get_out.status.success());
    let get_json: Value = serde_json::from_slice(&get_out.stdout).unwrap();
    assert_eq!(get_json["item"]["name"], "Modern Login");
    assert_eq!(get_json["item"]["organization_id"], "org-1");
    assert_eq!(get_json["item"]["login"]["password"], "s3cr3t!");

    let get_ssh = env
        .cmd()
        .args(["vault", "get", "personal-ssh-modern", "--json", "--reveal"])
        .output()
        .unwrap();
    assert!(get_ssh.status.success());
    let get_ssh_json: Value = serde_json::from_slice(&get_ssh.stdout).unwrap();
    assert_eq!(get_ssh_json["item"]["name"], "Deploy SSH Key");
    assert_eq!(get_ssh_json["item"]["organization_id"], "org-1");
}

#[test]
fn share_legacy_no_cipher_key_reencrypts_all_fields_under_fresh_org_wrapped_key() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_unlocked_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();
    let captured = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let captured_srv = Arc::clone(&captured);

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let (_method, _path, body) = read_http_request(&mut stream);
                    let req_json: Value = serde_json::from_slice(&body).unwrap();
                    captured_srv.lock().unwrap().push(req_json.clone());

                    let mut resp_cipher = req_json["cipher"].clone();
                    resp_cipher["collectionIds"] = req_json["collectionIds"].clone();
                    resp_cipher["edit"] = json!(true);
                    resp_cipher["viewPassword"] = json!(true);
                    resp_cipher["revisionDate"] = json!("2026-03-01T00:00:00Z");
                    let resp_body = serde_json::to_vec(&resp_cipher).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp_body.len()
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                    stream.write_all(&resp_body).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let out = env
        .cmd()
        .args([
            "vault",
            "share",
            "personal-login-legacy",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-write",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "share legacy failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    let sent = &reqs[0]["cipher"];
    assert_eq!(sent["organizationId"], "org-1");
    assert_eq!(sent["encryptedFor"], "user-1");

    // Unwrap fresh 64-byte cipher_key under org_key and decrypt every field
    let wrapped_k = sent["key"].as_str().expect("fresh cipher.key must be set");
    let raw_ck = EncString::parse(wrapped_k)
        .unwrap()
        .decrypt(&env.org_key)
        .unwrap();
    let fresh_ck = parse_symmetric_key_from_decrypted_bytes(&raw_ck).unwrap();

    assert_eq!(
        EncString::parse(sent["name"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "Legacy Login"
    );
    assert_eq!(
        EncString::parse(sent["notes"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "Legacy notes"
    );
    assert_eq!(
        EncString::parse(sent["login"]["username"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "legacy-user"
    );
    assert_eq!(
        EncString::parse(sent["login"]["password"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "legacy-pass"
    );
    assert_eq!(
        EncString::parse(sent["login"]["totp"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "JBSWY3DPEHPK3PXP"
    );
    assert_eq!(
        EncString::parse(sent["login"]["uris"][0]["uri"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "https://legacy.example.com"
    );
    assert_eq!(
        EncString::parse(sent["fields"][0]["name"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "env"
    );
    assert_eq!(
        EncString::parse(sent["passwordHistory"][0]["password"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&fresh_ck)
            .unwrap(),
        "old-pass"
    );

    // Local cache decrypts immediately
    let get_out = env
        .cmd()
        .args([
            "vault",
            "get",
            "personal-login-legacy",
            "--json",
            "--reveal",
        ])
        .output()
        .unwrap();
    assert!(get_out.status.success());
    let get_json: Value = serde_json::from_slice(&get_out.stdout).unwrap();
    assert_eq!(get_json["item"]["name"], "Legacy Login");
    assert_eq!(get_json["item"]["organization_id"], "org-1");
}

#[test]
fn share_fails_closed_before_http_on_invalid_attachments_ownership_trash_collections_and_json_confirmation(
) {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_unlocked_daemon();

    let http_called = Arc::new(AtomicBool::new(false));
    let http_called_srv = Arc::clone(&http_called);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok(_) => {
                    http_called_srv.store(true, Ordering::Relaxed);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let cases: Vec<(&str, Vec<&str>, &str)> = vec![
        (
            "missing --yes in --json mode",
            vec![
                "vault",
                "share",
                "personal-login-modern",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-write",
                "--json",
            ],
            "--yes",
        ),
        (
            "legacy unkeyed attachment",
            vec![
                "vault",
                "share",
                "personal-unkeyed-att",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-write",
                "--yes",
                "--json",
            ],
            "unkeyed attachment",
        ),
        (
            "legacy no-cipher.key with attachment",
            vec![
                "vault",
                "share",
                "personal-legacy-with-att",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-write",
                "--yes",
                "--json",
            ],
            "legacy cipher",
        ),
        (
            "already org-owned cipher",
            vec![
                "vault",
                "share",
                "already-org-cipher",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-write",
                "--yes",
                "--json",
            ],
            "already belongs to an Organization",
        ),
        (
            "trashed cipher",
            vec![
                "vault",
                "share",
                "personal-trashed",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-write",
                "--yes",
                "--json",
            ],
            "trash",
        ),
        (
            "non-writable collection",
            vec![
                "vault",
                "share",
                "personal-login-modern",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-ro",
                "--yes",
                "--json",
            ],
            "write permission",
        ),
        (
            "cross-organization collection",
            vec![
                "vault",
                "share",
                "personal-login-modern",
                "--organization-id",
                "org-1",
                "--collection-id",
                "col-other-org",
                "--yes",
                "--json",
            ],
            "does not belong to Organization",
        ),
    ];

    for (label, args, expected_substr) in cases {
        let out = env.cmd().args(&args).output().unwrap();
        assert!(
            !out.status.success(),
            "case '{label}' unexpectedly succeeded: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let parsed: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            panic!(
                "case '{label}' did not emit JSON: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        assert_eq!(parsed["ok"], false, "case '{label}'");
        let err = parsed["error"].as_str().unwrap_or("").to_lowercase();
        assert!(
            err.contains(&expected_substr.to_lowercase()),
            "case '{label}': expected '{expected_substr}' in error '{err}'"
        );
    }

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    assert!(
        !http_called.load(Ordering::Relaxed),
        "No HTTP call may be sent when fail-closed guards reject share"
    );
}

#[test]
fn share_interactive_confirmation_warns_irreversible_and_aborts_on_no() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_unlocked_daemon();

    let http_called = Arc::new(AtomicBool::new(false));
    let http_called_srv = Arc::clone(&http_called);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok(_) => {
                    http_called_srv.store(true, Ordering::Relaxed);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let mut child = env
        .cmd()
        .env("OMA_FORCE_PROMPT", "1")
        .args([
            "vault",
            "share",
            "personal-login-modern",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-write",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"n\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("irreversible"),
        "Expected irreversible warning in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("[y/N]"),
        "Expected [y/N] prompt in stderr, got: {stderr}"
    );

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    assert!(!http_called.load(Ordering::Relaxed));
}

#[test]
fn share_missing_org_key_fails_closed_before_http() {
    let env = TestEnv::new(false);
    let _daemon = env.spawn_unlocked_daemon();

    let http_called = Arc::new(AtomicBool::new(false));
    let http_called_srv = Arc::clone(&http_called);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok(_) => {
                    http_called_srv.store(true, Ordering::Relaxed);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let out = env
        .cmd()
        .args([
            "vault",
            "share",
            "personal-login-modern",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-write",
            "--yes",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], false);
    assert!(
        parsed["error"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("missing encryption key"),
        "Expected missing org key error, got: {parsed}"
    );

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
    assert!(!http_called.load(Ordering::Relaxed));
}

#[test]
fn share_interactive_confirmation_succeeds_on_yes() {
    let env = TestEnv::new(true);
    let _daemon = env.spawn_unlocked_daemon();

    let stop = Arc::new(AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop);
    let listener = env.api.try_clone().unwrap();

    let server = thread::spawn(move || {
        while !stop_srv.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let (_method, _path, body) = read_http_request(&mut stream);
                    let req_json: Value = serde_json::from_slice(&body).unwrap();
                    let mut resp_cipher = req_json["cipher"].clone();
                    resp_cipher["collectionIds"] = req_json["collectionIds"].clone();
                    resp_cipher["edit"] = json!(true);
                    resp_cipher["viewPassword"] = json!(true);
                    resp_cipher["revisionDate"] = json!("2026-03-01T00:00:00Z");
                    let resp_body = serde_json::to_vec(&resp_cipher).unwrap();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp_body.len()
                    );
                    stream.write_all(resp.as_bytes()).unwrap();
                    stream.write_all(&resp_body).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });

    let mut child = env
        .cmd()
        .env("OMA_FORCE_PROMPT", "1")
        .args([
            "vault",
            "share",
            "personal-login-modern",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-write",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(b"y\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "interactive y share failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("irreversible"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Shared cipher"));

    stop.store(true, Ordering::Relaxed);
    server.join().unwrap();
}
