use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
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
                {
                    "id": "org-1",
                    "name": "Acme Corp",
                    "key": enc_org_key,
                    "type": 2,
                    "enabled": true
                }
            ],
            "collections": [],
            "ciphers": [
                {
                    "id": "org-deletable-login",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 1,
                    "name": org_key.encrypt_string("Org Deletable").unwrap(),
                    "notes": null,
                    "favorite": false,
                    "edit": true,
                    "viewPassword": true,
                    "permissions": { "delete": true, "restore": true },
                    "login": {
                        "username": org_key.encrypt_string("svc").unwrap(),
                        "password": org_key.encrypt_string("pass").unwrap(),
                        "uris": []
                    },
                    "fields": [],
                    "revisionDate": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "org-limit-deletion",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 1,
                    "name": org_key.encrypt_string("Org LimitDeletion").unwrap(),
                    "notes": null,
                    "favorite": false,
                    "edit": true,
                    "viewPassword": true,
                    "permissions": { "delete": false, "restore": false },
                    "login": {
                        "username": org_key.encrypt_string("svc").unwrap(),
                        "password": org_key.encrypt_string("pass").unwrap(),
                        "uris": []
                    },
                    "fields": [],
                    "revisionDate": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "org-trashed-ssh-deletable",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 5,
                    "name": org_key.encrypt_string("Trashed Org SSH").unwrap(),
                    "notes": null,
                    "favorite": false,
                    "edit": true,
                    "viewPassword": true,
                    "permissions": { "delete": true, "restore": false },
                    "sshKey": {
                        "privateKey": org_key.encrypt_string("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----").unwrap(),
                        "publicKey": org_key.encrypt_string("ssh-ed25519 AAAA test@org").unwrap(),
                        "keyFingerprint": org_key.encrypt_string("SHA256:fp").unwrap()
                    },
                    "fields": [],
                    "deletedDate": "2026-01-02T00:00:00Z",
                    "revisionDate": "2026-01-01T00:00:00Z"
                },
                {
                    "id": "org-trashed-locked",
                    "organizationId": "org-1",
                    "folderId": null,
                    "type": 2,
                    "name": org_key.encrypt_string("Trashed No Perms").unwrap(),
                    "notes": org_key.encrypt_string("note").unwrap(),
                    "favorite": false,
                    "edit": true,
                    "viewPassword": true,
                    "permissions": { "delete": false, "restore": false },
                    "fields": [],
                    "deletedDate": "2026-01-02T00:00:00Z",
                    "revisionDate": "2026-01-01T00:00:00Z"
                }
            ]
        });
        fs::write(&cache, data.to_string()).unwrap();

        Self { temp, api }
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

    fn run_cli(&self, args: &[&str]) -> std::process::Output {
        let dir = self.temp.path();
        Command::new(env!("CARGO_BIN_EXE_omawarden"))
            .args(args)
            .env("XDG_DATA_HOME", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .env("PATH", self.path_env())
            .output()
            .unwrap()
    }
}

#[test]
fn org_soft_delete_restore_and_permanent_delete_succeed_when_permitted() {
    let env = TestEnv::new();
    let _daemon = env.spawn_and_unlock_daemon();

    let api = env.api.try_clone().unwrap();
    let captured = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let cap_clone = captured.clone();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();

    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop_clone.load(Ordering::SeqCst) && Instant::now() < deadline {
            match api.accept() {
                Ok((mut stream, _)) => {
                    let (method, path, _body) = read_http_request(&mut stream);
                    cap_clone.lock().unwrap().push((method, path));
                    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                    stream.write_all(resp.as_bytes()).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // 1. Soft delete org-deletable-login
    let out1 = env.run_cli(&["vault", "delete", "org-deletable-login", "--yes", "--json"]);
    assert!(
        out1.status.success(),
        "soft delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out1.stdout),
        String::from_utf8_lossy(&out1.stderr)
    );
    let get_trash = env.run_cli(&["vault", "get", "org-deletable-login", "--trash", "--json"]);
    assert!(get_trash.status.success());

    // 2. Restore org-deletable-login
    let out2 = env.run_cli(&["vault", "restore", "org-deletable-login", "--json"]);
    assert!(
        out2.status.success(),
        "restore failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
    let get_active = env.run_cli(&["vault", "get", "org-deletable-login", "--json"]);
    assert!(get_active.status.success());

    // 3. Permanent delete org-deletable-login
    let out3 = env.run_cli(&[
        "vault",
        "delete",
        "org-deletable-login",
        "--permanent",
        "--yes",
        "--json",
    ]);
    assert!(
        out3.status.success(),
        "permanent delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out3.stdout),
        String::from_utf8_lossy(&out3.stderr)
    );
    let get_after_perm = env.run_cli(&["vault", "get", "org-deletable-login", "--json"]);
    assert!(!get_after_perm.status.success());

    // 4. Permanent delete trashed org SSH key with can_delete: true
    let out4 = env.run_cli(&[
        "vault",
        "delete",
        "org-trashed-ssh-deletable",
        "--trash",
        "--yes",
        "--json",
    ]);
    assert!(
        out4.status.success(),
        "trash delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out4.stdout),
        String::from_utf8_lossy(&out4.stderr)
    );
    let get_after_trash_del = env.run_cli(&[
        "vault",
        "get",
        "org-trashed-ssh-deletable",
        "--trash",
        "--json",
    ]);
    assert!(!get_after_trash_del.status.success());

    stop_flag.store(true, Ordering::SeqCst);
    let _ = server.join();

    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 4);
    assert_eq!(
        reqs[0],
        (
            "PUT".into(),
            "/api/ciphers/org-deletable-login/delete".into()
        )
    );
    assert_eq!(
        reqs[1],
        (
            "PUT".into(),
            "/api/ciphers/org-deletable-login/restore".into()
        )
    );
    assert_eq!(
        reqs[2],
        ("DELETE".into(), "/api/ciphers/org-deletable-login".into())
    );
    assert_eq!(
        reqs[3],
        (
            "DELETE".into(),
            "/api/ciphers/org-trashed-ssh-deletable".into()
        )
    );
}

#[test]
fn org_delete_and_restore_fail_closed_when_unauthorized_including_limit_item_deletion() {
    let env = TestEnv::new();
    let _daemon = env.spawn_and_unlock_daemon();

    // LimitItemDeletion: edit == true, viewPassword == true, but permissions.delete == false
    let out1 = env.run_cli(&["vault", "delete", "org-limit-deletion", "--yes", "--json"]);
    assert!(!out1.status.success());
    let body1: Value = serde_json::from_slice(&out1.stdout).unwrap();
    assert_eq!(body1["ok"], false);
    assert!(body1["error"].as_str().unwrap_or("").contains("permission"));

    let out2 = env.run_cli(&[
        "vault",
        "delete",
        "org-limit-deletion",
        "--permanent",
        "--yes",
        "--json",
    ]);
    assert!(!out2.status.success());

    // Trashed org cipher with can_restore: false -> restore fails closed
    let out3 = env.run_cli(&["vault", "restore", "org-trashed-locked", "--json"]);
    assert!(!out3.status.success());
    let body3: Value = serde_json::from_slice(&out3.stdout).unwrap();
    assert_eq!(body3["ok"], false);
    assert!(body3["error"].as_str().unwrap_or("").contains("permission"));

    // Trashed org cipher with can_delete: false -> permanent trash delete fails closed
    let out4 = env.run_cli(&[
        "vault",
        "delete",
        "org-trashed-locked",
        "--trash",
        "--yes",
        "--json",
    ]);
    assert!(!out4.status.success());

    // Zero HTTP requests must have been sent
    assert!(env.api.accept().is_err());
}
