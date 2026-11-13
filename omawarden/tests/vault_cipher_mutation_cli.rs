use omawarden::crypto::{derive_master_key, EncString, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ipc(socket: &Path, request: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let path = line.split_whitespace().nth(1).unwrap().to_owned();
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
    (path, body)
}

fn read_request_with_method(stream: &mut TcpStream) -> (String, String, Vec<u8>) {
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

fn setup_test_environment() -> (tempfile::TempDir, TcpListener, String, SymmetricCryptoKey) {
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
        derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None).unwrap();
    let raw_user_key = [42u8; 64];
    let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&raw_user_key)
        .unwrap();

    let cache = dir.join("data.json");
    let data = json!({
        "user_id": "user-id-123",
        "user_email": email,
        "server_url": server_url,
        "credential_id": "11111111111111111111111111111111",
        "enc_user_key": wrap,
        "kdf": 0,
        "kdf_iterations": 100_000,
        "ciphers": []
    });
    fs::write(&cache, data.to_string()).unwrap();

    (temp, api, server_url, user_key)
}

fn make_command(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
    cmd.env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir);
    cmd
}

#[test]
fn test_create_login_cipher_end_to_end() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "My Site",
            "--username",
            "octocat",
            "--password",
            "supersecret",
            "--notes",
            "Special note",
            "--uri",
            "https://example.com/login",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["type"], 1);

        // Verify wire encryption: all strings must be valid EncString that decrypt with user_key
        let decrypt = |v: &Value| -> String {
            let enc_str = v.as_str().expect("must be string");
            EncString::parse(enc_str)
                .unwrap()
                .decrypt_string(&user_key)
                .unwrap()
        };

        assert_eq!(decrypt(&payload["name"]), "My Site");
        assert_eq!(decrypt(&payload["notes"]), "Special note");
        assert_eq!(decrypt(&payload["login"]["username"]), "octocat");
        assert_eq!(decrypt(&payload["login"]["password"]), "supersecret");
        assert_eq!(
            decrypt(&payload["login"]["uris"][0]["uri"]),
            "https://example.com/login"
        );

        // Return Bitwarden server response
        let resp_body = json!({
            "id": "created-cipher-uuid-1234",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI exit status failed");
    assert!(posted, "Bitwarden API POST was not received");
    let cli_stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        cli_stdout.contains("Created login cipher \"My Site\" (created-cipher-uuid-1234)."),
        "Unexpected CLI confirmation output: {cli_stdout}"
    );

    // Verify newly created item is immediately discoverable via positional search without manual sync
    let search_output = make_command(dir)
        .args(["vault", "search", "My Site"])
        .output()
        .unwrap();
    assert!(search_output.status.success());
    let stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(
        stdout.contains("My Site"),
        "search did not find the newly created item: {stdout}"
    );
    assert!(
        stdout.contains("octocat"),
        "search output missing username: {stdout}"
    );

    // Verify newly created item is also immediately discoverable via vault list
    let list_output = make_command(dir).args(["vault", "list"]).output().unwrap();
    assert!(list_output.status.success());
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        list_stdout.contains("My Site"),
        "list did not contain newly created item: {list_stdout}"
    );
}

#[test]
fn test_create_login_cipher_server_failure_leaves_vault_untouched() {
    let (temp, api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Failed Site",
            "--username",
            "failed_user",
            "--password",
            "failed_pass",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (_path, _body) = read_request(&mut stream);
        let resp_body = json!({
            "error": "Internal Server Error",
            "message": "Something went wrong on Bitwarden server"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let status = cli.wait().unwrap();
    assert!(!status.success(), "CLI should have failed on server error");

    // Verify local vault did NOT save or index the failed cipher
    let search_output = make_command(dir)
        .args(["vault", "search", "--query", "Failed Site"])
        .output()
        .unwrap();
    assert!(search_output.status.success());
    let stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(
        !stdout.contains("Failed Site"),
        "Failed item should not be present in vault search: {stdout}"
    );
}

#[test]
fn test_create_login_cipher_locked_vault_rejected() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    // Notice: Vault is intentionally NOT unlocked
    let output = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Locked Site",
            "--username",
            "user",
            "--password",
            "pass",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!output.status.success(), "Should fail when vault is locked");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unlock the vault before creating a cipher"),
        "Unexpected error output: {stderr}"
    );
}

#[test]
fn test_create_login_cipher_json_mode_and_password_stdin() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "--json",
            "login",
            "--name",
            "Json Site",
            "--username",
            "stdinuser",
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli.stdin.take().unwrap();
        stdin.write_all(b"pipedpassword\n").unwrap();
    }

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_pwd = payload["login"]["password"].as_str().unwrap();
        let decrypted_pwd = EncString::parse(enc_pwd)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_pwd, "pipedpassword");

        let resp_body = json!({
            "id": "json-cipher-uuid-9999",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI exit status failed");
    assert!(posted, "Bitwarden API POST was not received");

    let stdout_json: Value = serde_json::from_slice(&out.stdout).expect("output must be JSON");
    assert_eq!(stdout_json["ok"], true);
    assert_eq!(stdout_json["outcome"], "saved");
    assert_eq!(stdout_json["item"]["id"], "json-cipher-uuid-9999");
}

#[test]
fn test_create_note_cipher_end_to_end() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "note",
            "--name",
            "Wifi Password",
            "--notes",
            "SuperSecret",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["type"], 2);

        let decrypt = |v: &Value| -> String {
            let enc_str = v.as_str().expect("must be string");
            EncString::parse(enc_str)
                .unwrap()
                .decrypt_string(&user_key)
                .unwrap()
        };

        assert_eq!(decrypt(&payload["name"]), "Wifi Password");
        assert_eq!(decrypt(&payload["notes"]), "SuperSecret");

        let resp_body = json!({
            "id": "note-cipher-uuid-5678",
            "organizationId": null,
            "folderId": null,
            "type": 2,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "secureNote": { "type": 0 },
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI exit status failed");
    assert!(posted, "Bitwarden API POST was not received");
    let cli_stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        cli_stdout.contains("Created note cipher \"Wifi Password\" (note-cipher-uuid-5678)."),
        "Unexpected CLI confirmation output: {cli_stdout}"
    );

    // Verify discoverability via positional search
    let search_output = make_command(dir)
        .args(["vault", "search", "Wifi Password"])
        .output()
        .unwrap();
    assert!(search_output.status.success());
    let stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(stdout.contains("Wifi Password"));

    // Verify discoverability via vault list
    let list_output = make_command(dir).args(["vault", "list"]).output().unwrap();
    assert!(list_output.status.success());
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains("Wifi Password"));
}

#[test]
fn test_create_cipher_from_stdin_and_from_json() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // 1. Test via stdin
    let raw_payload = json!({
        "type": 2,
        "name": "Note From Stdin",
        "notes": "Stdin Secret Content"
    });

    let mut cli_stdin = make_command(dir)
        .args(["vault", "create", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli_stdin.stdin.take().unwrap();
        stdin.write_all(raw_payload.to_string().as_bytes()).unwrap();
    }

    let mut posted_stdin = false;
    while cli_stdin.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted_stdin = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["type"], 2);

        let decrypt = |v: &Value| -> String {
            let enc_str = v.as_str().expect("must be string");
            EncString::parse(enc_str)
                .unwrap()
                .decrypt_string(&user_key)
                .unwrap()
        };

        assert_eq!(decrypt(&payload["name"]), "Note From Stdin");
        assert_eq!(decrypt(&payload["notes"]), "Stdin Secret Content");

        let resp_body = json!({
            "id": "stdin-note-uuid",
            "organizationId": null,
            "folderId": null,
            "type": 2,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "secureNote": { "type": 0 },
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out_stdin = cli_stdin.wait_with_output().unwrap();
    assert!(out_stdin.status.success());
    assert!(posted_stdin);

    // 2. Test via --from-json
    let json_file = dir.join("item.json");
    let file_payload = json!({
        "type": 2,
        "name": "Note From File",
        "notes": "File Secret Content"
    });
    std::fs::write(&json_file, file_payload.to_string()).unwrap();

    let mut cli_file = make_command(dir)
        .args([
            "vault",
            "create",
            "--from-json",
            json_file.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted_file = false;
    while cli_file.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted_file = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["type"], 2);

        let resp_body = json!({
            "id": "file-note-uuid",
            "organizationId": null,
            "folderId": null,
            "type": 2,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "secureNote": { "type": 0 },
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out_file = cli_file.wait_with_output().unwrap();
    assert!(out_file.status.success());
    assert!(posted_file);
}

#[test]
fn test_create_cipher_organization_scope_rejected() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Reject organizationId
    let mut cli_org = make_command(dir)
        .args(["vault", "create", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli_org.stdin.take().unwrap();
        stdin
            .write_all(
                json!({
                    "type": 2,
                    "name": "Org Note",
                    "organizationId": "some-org-id"
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
    }

    let out_org = cli_org.wait_with_output().unwrap();
    assert!(!out_org.status.success());
    let stderr_org = String::from_utf8_lossy(&out_org.stderr);
    assert!(
        stderr_org.contains("Organization ciphers are read-only"),
        "Unexpected error: {stderr_org}"
    );

    // Reject collectionIds
    let mut cli_col = make_command(dir)
        .args(["vault", "create", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli_col.stdin.take().unwrap();
        stdin
            .write_all(
                json!({
                    "type": 2,
                    "name": "Col Note",
                    "collectionIds": ["some-col-id"]
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
    }

    let out_col = cli_col.wait_with_output().unwrap();
    assert!(!out_col.status.success());
    let stderr_col = String::from_utf8_lossy(&out_col.stderr);
    assert!(
        stderr_col.contains("Organization ciphers are read-only"),
        "Unexpected error: {stderr_col}"
    );

    // Reject collectionId as singular string
    let mut cli_col_single = make_command(dir)
        .args(["vault", "create", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli_col_single.stdin.take().unwrap();
        stdin
            .write_all(
                json!({
                    "type": 2,
                    "name": "Col Note Single",
                    "collectionId": "single-col-id"
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
    }

    let out_col_single = cli_col_single.wait_with_output().unwrap();
    assert!(!out_col_single.status.success());
    let stderr_col_single = String::from_utf8_lossy(&out_col_single.stderr);
    assert!(
        stderr_col_single.contains("Organization ciphers are read-only"),
        "Unexpected error: {stderr_col_single}"
    );

    // Reject CLI flags --organization-id and --collection-id
    let out_cli_flags = make_command(dir)
        .args([
            "vault",
            "create",
            "note",
            "--name",
            "CLI Org Note",
            "--notes",
            "Secret",
            "--organization-id",
            "cli-org-id",
        ])
        .output()
        .unwrap();
    assert!(!out_cli_flags.status.success());
    let stderr_cli = String::from_utf8_lossy(&out_cli_flags.stderr);
    assert!(
        stderr_cli.contains("Organization ciphers are read-only"),
        "Unexpected error: {stderr_cli}"
    );
}

#[test]
fn test_create_cipher_unsupported_type_rejected() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Passing type 3 (Card) must be explicitly rejected, not coerced into login
    let mut cli_card = make_command(dir)
        .args(["vault", "create", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli_card.stdin.take().unwrap();
        stdin
            .write_all(
                json!({
                    "type": 3,
                    "name": "Card Item",
                    "notes": "Card Secret"
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
    }

    let out_card = cli_card.wait_with_output().unwrap();
    assert!(!out_card.status.success());
    let stderr_card = String::from_utf8_lossy(&out_card.stderr);
    assert!(
        stderr_card.contains("Unsupported cipher type"),
        "Unexpected error: {stderr_card}"
    );
}

#[test]
fn test_create_cipher_string_type_and_bitwarden_uris_format() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Test standard Bitwarden export with object uris array and string type
    let mut cli = make_command(dir)
        .args(["vault", "create", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let mut stdin = cli.stdin.take().unwrap();
        stdin
            .write_all(
                json!({
                    "type": "login",
                    "name": "Exported Item",
                    "login": {
                        "username": "exportuser",
                        "password": "exportpass",
                        "uris": [
                            {"uri": "https://service.com", "match": null}
                        ]
                    }
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap();
    }

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["type"], 1);

        let enc_uri = payload["login"]["uris"][0]["uri"].as_str().unwrap();
        let decrypted_uri = EncString::parse(enc_uri)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_uri, "https://service.com");

        let resp_body = json!({
            "id": "export-item-uuid",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI exit status failed");
    assert!(posted, "Bitwarden API POST was not received");
}

fn add_cipher_with_login_to_cache(
    dir: &Path,
    user_key: &SymmetricCryptoKey,
    id: &str,
    name: &str,
    login: Value,
) {
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": id,
        "organizationId": null,
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": login,
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();
}

fn add_cipher_to_cache(
    dir: &Path,
    user_key: &SymmetricCryptoKey,
    id: &str,
    name: &str,
    username: &str,
) {
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": id,
        "organizationId": null,
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": {
            "username": user_key.encrypt_string(username).unwrap(),
            "password": user_key.encrypt_string("secretpass").unwrap(),
            "uris": []
        },
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();
}

/// Adds a cipher with an explicit type and optional `deletedDate`, so tests can
/// seed the Trash without going through a server round-trip.
fn add_cipher_with_state(
    dir: &Path,
    user_key: &SymmetricCryptoKey,
    id: &str,
    name: &str,
    cipher_type: i64,
    deleted_at: Option<&str>,
) {
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    let mut cipher = json!({
        "id": id,
        "organizationId": null,
        "folderId": null,
        "type": cipher_type,
        "name": user_key.encrypt_string(name).unwrap(),
        "notes": null,
        "favorite": false,
        "revisionDate": "2026-11-09T00:00:00.000Z"
    });
    if cipher_type == 1 {
        cipher["login"] = json!({
            "username": user_key.encrypt_string("user").unwrap(),
            "password": user_key.encrypt_string("secretpass").unwrap(),
            "uris": []
        });
    }
    if let Some(ts) = deleted_at {
        cipher["deletedDate"] = json!(ts);
    }
    ciphers.push(cipher);
    fs::write(&cache_path, data.to_string()).unwrap();
}

#[test]
fn test_delete_cipher_soft_delete_end_to_end() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "11111111-2222-3333-4444-555555555555";
    let cipher_name = "Site to Soft Delete";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user1");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "delete", cipher_name, "-y"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}/delete"));
        received = true;

        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI exit status failed");
    assert!(received, "Bitwarden API soft delete was not received");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("Deleted cipher \"{cipher_name}\" ({cipher_id}).")),
        "Unexpected CLI output: {stdout}"
    );

    // Verify hidden from the active search index
    let search_out = make_command(dir)
        .args(["vault", "search", cipher_name])
        .output()
        .unwrap();
    assert!(search_out.status.success());
    let search_str = String::from_utf8_lossy(&search_out.stdout);
    assert!(
        !search_str.contains(cipher_name),
        "Item should be hidden from active search: {search_str}"
    );

    // Verify hidden from the default list
    let list_out = make_command(dir).args(["vault", "list"]).output().unwrap();
    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        !list_str.contains(cipher_name),
        "Item should be hidden from the default list: {list_str}"
    );
    let active_items: Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert!(
        active_items
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i.get("deleted_at").is_none()),
        "Active list must omit deleted_at: {list_str}"
    );

    // Verify retained in data.json cache with a non-null deletedDate
    let cache_data: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("data.json")).unwrap()).unwrap();
    let cached = cache_data["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == cipher_id)
        .expect("soft-deleted cipher must stay in data.json");
    assert!(
        cached.get("deletedDate").and_then(Value::as_str).is_some(),
        "soft-deleted cipher must carry deletedDate: {cached}"
    );

    // Verify immediately visible in the Trash with a deleted_at timestamp
    let trash_out = make_command(dir)
        .args(["vault", "list", "--trash"])
        .output()
        .unwrap();
    assert!(trash_out.status.success());
    let trash_items: Value = serde_json::from_slice(&trash_out.stdout).unwrap();
    let trashed = trash_items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == cipher_id)
        .expect("soft-deleted cipher must appear in vault list --trash");
    assert!(
        trashed.get("deleted_at").and_then(Value::as_str).is_some(),
        "Trash item must expose deleted_at: {trashed}"
    );

    // Verify searchable within the Trash
    let trash_search = make_command(dir)
        .args(["vault", "search", cipher_name, "--trash"])
        .output()
        .unwrap();
    assert!(trash_search.status.success());
    let trash_search_str = String::from_utf8_lossy(&trash_search.stdout);
    assert!(
        trash_search_str.contains(cipher_name),
        "Trash search did not find the soft-deleted item: {trash_search_str}"
    );
}

#[test]
fn test_delete_cipher_by_32char_hex_id() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "11111111-2222-3333-4444-555555555555";
    let hex_target = "11111111222233334444555555555555";
    let cipher_name = "Target By Hex";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user2");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "delete", hex_target, "-y"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}/delete"));
        received = true;

        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
}

#[test]
fn test_delete_cipher_permanent_hard_delete() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "22222222-3333-4444-5555-666666666666";
    let cipher_name = "Site to Purge";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user3");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "delete", cipher_name, "--permanent", "--yes"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "DELETE");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI exit status failed");
    assert!(received, "Bitwarden API DELETE was not received");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!(
            "Permanently deleted cipher \"{cipher_name}\" ({cipher_id})."
        )),
        "Unexpected CLI output: {stdout}"
    );
}

#[test]
fn test_list_and_search_trash_with_category_filter() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    add_cipher_with_state(
        dir,
        &user_key,
        "aaaaaaaa-1111-2222-3333-444444444444",
        "Trashed Login",
        1,
        Some("2026-11-10T00:00:00.000Z"),
    );
    add_cipher_with_state(
        dir,
        &user_key,
        "bbbbbbbb-1111-2222-3333-444444444444",
        "Trashed Note",
        2,
        Some("2026-11-10T00:00:00.000Z"),
    );
    add_cipher_with_state(
        dir,
        &user_key,
        "cccccccc-1111-2222-3333-444444444444",
        "Active Login",
        1,
        None,
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Default list: only active items, and no deleted_at field.
    let list_out = make_command(dir).args(["vault", "list"]).output().unwrap();
    assert!(list_out.status.success());
    let active: Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let active = active.as_array().unwrap();
    assert_eq!(
        active.len(),
        1,
        "only the active cipher is listed: {active:?}"
    );
    assert_eq!(active[0]["name"], "Active Login");
    assert!(
        active[0].get("deleted_at").is_none(),
        "active JSON must omit deleted_at"
    );

    // Trash list: only soft-deleted items, each with deleted_at.
    let trash_out = make_command(dir)
        .args(["vault", "list", "--trash"])
        .output()
        .unwrap();
    assert!(trash_out.status.success());
    let trash: Value = serde_json::from_slice(&trash_out.stdout).unwrap();
    let trash = trash.as_array().unwrap();
    assert_eq!(trash.len(), 2, "both trashed ciphers are listed: {trash:?}");
    assert!(trash
        .iter()
        .all(|item| item.get("deleted_at").and_then(Value::as_str).is_some()));

    // --filter narrows the Trash list to a single category.
    let note_out = make_command(dir)
        .args(["vault", "list", "--trash", "--filter", "note"])
        .output()
        .unwrap();
    assert!(note_out.status.success());
    let notes: Value = serde_json::from_slice(&note_out.stdout).unwrap();
    let notes = notes.as_array().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0]["name"], "Trashed Note");

    // Trash search is scoped to Trash and supports --filter.
    let search_out = make_command(dir)
        .args(["vault", "search", "Trashed", "--trash", "--filter", "login"])
        .output()
        .unwrap();
    assert!(search_out.status.success());
    let found: Value = serde_json::from_slice(&search_out.stdout).unwrap();
    let found = found.as_array().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["name"], "Trashed Login");

    // Active search never sees the Trash.
    let active_search = make_command(dir)
        .args(["vault", "search", "Trashed"])
        .output()
        .unwrap();
    assert!(active_search.status.success());
    assert!(
        !String::from_utf8_lossy(&active_search.stdout).contains("Trashed"),
        "active search must not surface trashed items"
    );
}

#[test]
fn test_unlock_and_status_items_count_exclude_trash() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    add_cipher_with_state(dir, &user_key, "active-item-1", "Active One", 1, None);
    add_cipher_with_state(
        dir,
        &user_key,
        "trashed-item-1",
        "Trashed One",
        1,
        Some("2026-11-10T00:00:00.000Z"),
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    let unlock = ipc(&socket, json!({"action": "unlock", "password": "fixture"}));
    assert_eq!(unlock["ok"], true);
    assert_eq!(
        unlock["items_count"], 1,
        "unlock must count active items only"
    );

    let status = ipc(&socket, json!({"action": "status"}));
    assert_eq!(status["items_count"], 1, "status must exclude Trash");
}

#[test]
fn test_trashed_cipher_is_not_served_to_active_consumers() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "dead0000-0000-0000-0000-000000000001";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Trashed Copy Target",
        &[],
        &[("PIN", "1234", 0)],
    );
    // Mark the cipher as trashed in the cache.
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    data["ciphers"][0]["deletedDate"] = json!("2026-11-10T00:00:00.000Z");
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = start_unlocked_daemon(dir);

    // copy must not resolve the trashed cipher.
    let copy_out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "PIN"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(!copy_out.status.success(), "copy must fail closed");
    assert!(
        String::from_utf8_lossy(&copy_out.stdout).contains("not found in vault"),
        "copy should report the trashed item as missing: {}",
        String::from_utf8_lossy(&copy_out.stdout)
    );
    assert!(
        !dir.join("wl-copy-content").exists(),
        "nothing may be copied from a trashed cipher"
    );

    // get_item (used by totp/attachment) must not resolve it either.
    let get_item = ipc(
        &dir.join("omawarden.sock"),
        json!({"action": "get_item", "query": cipher_id}),
    );
    assert_eq!(get_item["ok"], false, "trashed item must not be served");
}

#[test]
fn test_delete_cipher_interactive_prompt_abort() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "33333333-4444-5555-6666-777777777777";
    let cipher_name = "Site to Abort";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user4");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Run CLI with OMA_FORCE_PROMPT=1 and answer 'n'
    let mut cli = make_command(dir)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "delete", cipher_name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = cli.stdin.take().unwrap();
    stdin.write_all(b"n\n").unwrap();
    drop(stdin);

    let out = cli.wait_with_output().unwrap();
    assert!(!out.status.success(), "CLI should abort with non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("Delete item '{cipher_name}'? [y/N] ")),
        "Expected confirmation prompt in stderr: {stderr}"
    );
    assert!(
        stderr.contains("Deletion aborted."),
        "Expected abort message in stderr: {stderr}"
    );

    // Verify cipher is STILL in vault
    let search_out = make_command(dir)
        .args(["vault", "search", cipher_name])
        .output()
        .unwrap();
    assert!(search_out.status.success());
    let search_str = String::from_utf8_lossy(&search_out.stdout);
    assert!(
        search_str.contains(cipher_name),
        "Item must still exist after abort: {search_str}"
    );
}

#[test]
fn test_delete_cipher_interactive_prompt_confirm() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "44444444-5555-6666-7777-888888888888";
    let cipher_name = "Site to Confirm";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user5");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Run CLI with OMA_FORCE_PROMPT=1 and answer 'y'
    let mut cli = make_command(dir)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "delete", cipher_name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = cli.stdin.take().unwrap();
    stdin.write_all(b"y\n").unwrap();
    drop(stdin);

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}/delete"));
        received = true;

        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success(), "CLI should succeed on confirmation");
    assert!(received);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&format!("Delete item '{cipher_name}'? [y/N] ")));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("Deleted cipher \"{cipher_name}\" ({cipher_id}).")));
}

#[test]
fn test_delete_cipher_json_mode() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "55555555-6666-7777-8888-999999999999";
    let cipher_name = "JSON Mode Delete";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user6");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "delete", cipher_name, "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}/delete"));
        received = true;

        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);

    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["outcome"], "deleted");
    assert_eq!(parsed["item"]["id"], cipher_id);
    assert_eq!(parsed["item"]["name"], cipher_name);
    assert_eq!(parsed["item"]["permanent"], false);
}

#[test]
fn test_delete_cipher_not_found_fails_closed() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "delete", "Nonexistent Item", "-y"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cipher 'Nonexistent Item' not found in vault."),
        "Unexpected error: {stderr}"
    );
}

#[test]
fn test_delete_cipher_ambiguous_fails_closed() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    add_cipher_to_cache(
        dir,
        &user_key,
        "66666666-7777-8888-9999-000000000001",
        "AWS Prod",
        "admin",
    );
    add_cipher_to_cache(
        dir,
        &user_key,
        "66666666-7777-8888-9999-000000000002",
        "AWS Staging",
        "dev",
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "delete", "AWS", "-y"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Multiple ciphers matched 'AWS':"),
        "Unexpected error: {stderr}"
    );
}

#[test]
fn test_delete_cipher_locked_vault_rejected() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    // Vault is NOT unlocked
    let out = make_command(dir)
        .args(["vault", "delete", "Any Target", "-y"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Unlock the vault before deleting a cipher."),
        "Unexpected error: {stderr}"
    );
}

#[test]
fn test_delete_cipher_organization_read_only_rejected() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "77777777-8888-9999-aaaa-bbbbbbbbbbbb";
    let cipher_name = "Org Shared Vault Item";

    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": cipher_id,
        "organizationId": "org-uuid-1234",
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(cipher_name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": {
            "username": user_key.encrypt_string("orguser").unwrap(),
            "password": user_key.encrypt_string("secretpass").unwrap(),
            "uris": []
        },
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "delete", cipher_name, "-y"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Organization ciphers are read-only."),
        "Unexpected error output: {stderr}"
    );
}

#[test]
fn test_edit_login_cipher_password_end_to_end() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "11111111-2222-3333-4444-555555555555";
    let cipher_name = "github";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "octocat");

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_name, "--password", "new-secret"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        // Concurrency check: lastKnownRevisionDate must match local cached revision
        assert_eq!(payload["lastKnownRevisionDate"], "2026-11-09T00:00:00.000Z");

        // Password must be re-encrypted
        let enc_pwd = payload["login"]["password"].as_str().unwrap();
        let dec_pwd = EncString::parse(enc_pwd)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(dec_pwd, "new-secret");

        // Username must remain intact
        let enc_user = payload["login"]["username"].as_str().unwrap();
        let dec_user = EncString::parse(enc_user)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(dec_user, "octocat");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T12:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("Updated cipher \"{cipher_name}\" ({cipher_id}).")),
        "Unexpected output: {stdout}"
    );

    // Verify cache updated
    let cache_path = dir.join("data.json");
    let data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let updated_entry = data["ciphers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == cipher_id)
        .unwrap();
    assert_eq!(updated_entry["revisionDate"], "2026-11-09T12:00:00.000Z");
}

#[test]
fn test_edit_cipher_partial_field_update() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "22222222-3333-4444-5555-666666666666";
    let cipher_name = "My Partial Site";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "existing_user");

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_name, "--notes", "Brand New Note"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_notes = payload["notes"].as_str().unwrap();
        let dec_notes = EncString::parse(enc_notes)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(dec_notes, "Brand New Note");

        // Existing login username and password must stay intact
        let enc_user = payload["login"]["username"].as_str().unwrap();
        let dec_user = EncString::parse(enc_user)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(dec_user, "existing_user");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T13:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
}

/// Vaultwarden 1.37+ requires `encryptedFor` on `PUT /api/ciphers/{id}`, the same
/// as on create. Without it every edit — including a favorite toggle — comes
/// back 422, so the update path must send it.
#[test]
fn test_edit_cipher_sends_encrypted_for() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "22222222-3333-4444-5555-666666666666";
    let cipher_name = "Favorite Site";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user1");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_name, "--favorite", "true"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["encryptedFor"].as_str(),
            Some("user-id-123"),
            "update payload must carry encryptedFor"
        );
        assert_eq!(payload["favorite"], true);

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": true,
            "login": payload["login"],
            "revisionDate": "2026-11-09T14:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
}

#[test]
fn test_edit_cipher_optimistic_concurrency_conflict_rejected() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "33333333-4444-5555-6666-777777777777";
    let cipher_name = "Stale Item";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user");

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_name,
            "--password",
            "conflict-secret",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        // Simulate Bitwarden returning 409 Conflict
        let resp_body = json!({
            "error": "Conflict",
            "message": "Cipher revisionDate does not match server"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(!out.status.success(), "Should fail on 409 conflict");
    assert!(received);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cipher has been modified remotely. Please sync the vault before editing."),
        "Unexpected error output: {stderr}"
    );
}

#[test]
fn test_edit_cipher_no_fields_specified_rejected() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "44444444-5555-6666-7777-888888888888";
    let cipher_name = "Item No Fields";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user");

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "edit", cipher_name])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "No fields specified to edit. Provide at least one field to update (e.g. --password) or run in an interactive terminal to use $EDITOR."
        ),
        "Unexpected error output: {stderr}"
    );
}

#[test]
fn test_edit_cipher_organization_read_only_rejected() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "55555555-6666-7777-8888-999999999999";
    let cipher_name = "Org Item Edit";

    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": cipher_id,
        "organizationId": "org-uuid-1",
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(cipher_name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": {
            "username": user_key.encrypt_string("orguser").unwrap(),
            "password": user_key.encrypt_string("secretpass").unwrap(),
            "uris": []
        },
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "edit", cipher_name, "--password", "new-pass"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Organization ciphers are read-only."),
        "Unexpected error output: {stderr}"
    );
}

#[test]
fn test_edit_cipher_json_mode() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "66666666-7777-8888-9999-aaaaaaaaaaaa";
    let cipher_name = "JSON Edit Site";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "jsonuser");

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_name,
            "--password",
            "json-pass",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T14:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);

    let stdout_json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout_json["ok"], true);
    assert_eq!(stdout_json["item"]["id"], cipher_id);
    assert_eq!(stdout_json["item"]["name"], cipher_name);
}

#[test]
fn test_edit_cipher_not_found_fails_closed() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "edit", "Nonexistent Item", "--password", "val"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Cipher 'Nonexistent Item' not found in vault."),
        "Unexpected error: {stderr}"
    );
}

#[test]
fn test_edit_cipher_locked_vault_rejected() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    // Vault is NOT unlocked
    let out = make_command(dir)
        .args(["vault", "edit", "Any Target", "--password", "val"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Unlock the vault before editing a cipher."),
        "Unexpected error: {stderr}"
    );
}

#[test]
fn test_edit_cipher_rename_receipt_and_output() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "77777777-8888-9999-aaaa-bbbbbbbbbbbb";
    let old_name = "Old Service Name";
    let new_name = "New Service Name";
    add_cipher_to_cache(dir, &user_key, cipher_id, old_name, "myuser");

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", old_name, "--name", new_name, "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_name = payload["name"].as_str().unwrap();
        let decrypted_name = EncString::parse(enc_name)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_name, new_name);

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": enc_name,
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T15:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);

    let stdout_json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(stdout_json["ok"], true);
    assert_eq!(stdout_json["item"]["id"], cipher_id);
    assert_eq!(stdout_json["item"]["name"], new_name);
}

#[test]
fn test_edit_cipher_with_item_key_end_to_end() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "88888888-9999-aaaa-bbbb-cccccccccccc";
    let cipher_name = "Item With Dedicated Key";

    // Dedicated 64-byte symmetric key for the cipher (distinct from user_key [42u8; 64])
    let raw_cipher_key = [99u8; 64];
    let cipher_sym_key = SymmetricCryptoKey::from_raw_bytes(&raw_cipher_key).unwrap();
    let enc_cipher_key = user_key.encrypt(&raw_cipher_key).unwrap();

    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": cipher_id,
        "organizationId": null,
        "folderId": null,
        "type": 1,
        "name": cipher_sym_key.encrypt_string(cipher_name).unwrap(),
        "notes": null,
        "favorite": false,
        "key": enc_cipher_key,
        "login": {
            "username": cipher_sym_key.encrypt_string("sym_user").unwrap(),
            "password": cipher_sym_key.encrypt_string("old_pass").unwrap(),
            "uris": []
        },
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_name, "--password", "new_sym_pass"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_pass = payload["login"]["password"].as_str().unwrap();

        // The password must be decryptable with cipher_sym_key, NOT user_key!
        let dec_pass = EncString::parse(enc_pass)
            .unwrap()
            .decrypt_string(&cipher_sym_key)
            .unwrap();
        assert_eq!(dec_pass, "new_sym_pass");

        // user_key must fail to decrypt it
        assert!(EncString::parse(enc_pass)
            .unwrap()
            .decrypt_string(&user_key)
            .is_err());

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "key": enc_cipher_key,
            "login": payload["login"],
            "revisionDate": "2026-11-09T16:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
}

#[test]
fn test_edit_cipher_rejects_login_fields_on_note() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "99999999-aaaa-bbbb-cccc-dddddddddddd";
    let cipher_name = "My Secure Note";

    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": cipher_id,
        "organizationId": null,
        "folderId": null,
        "type": 2, // Note type
        "name": user_key.encrypt_string(cipher_name).unwrap(),
        "notes": user_key.encrypt_string("Original note content").unwrap(),
        "favorite": false,
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "edit", cipher_name, "--password", "secret"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Username, password, and URI can only be updated on login ciphers."),
        "Unexpected error: {stderr}"
    );
}

#[test]
fn test_edit_cipher_clears_uri_with_empty_string() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let cipher_name = "Site With Existing URI";

    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    ciphers.push(json!({
        "id": cipher_id,
        "organizationId": null,
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(cipher_name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": {
            "username": user_key.encrypt_string("user").unwrap(),
            "password": user_key.encrypt_string("pass").unwrap(),
            "uris": [{"uri": user_key.encrypt_string("https://old.example.com").unwrap(), "match": null}]
        },
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = Daemon(
        make_command(dir)
            .args(["daemon"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_name, "--uri", ""])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let uris = payload["login"]["uris"].as_array().unwrap();
        assert!(uris.is_empty(), "URI list should be empty after clearing");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T17:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
}

#[test]
fn test_edit_cipher_conflicting_flags_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    // --password and --password-stdin conflict
    let out1 = make_command(dir)
        .args([
            "vault",
            "edit",
            "target",
            "--password",
            "p",
            "--password-stdin",
        ])
        .output()
        .unwrap();
    assert!(!out1.status.success());

    // --notes and --notes-stdin conflict
    let out2 = make_command(dir)
        .args(["vault", "edit", "target", "--notes", "n", "--notes-stdin"])
        .output()
        .unwrap();
    assert!(!out2.status.success());
}

#[test]
fn test_create_login_cipher_generate_password_flag() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Gen Pass Site",
            "--username",
            "octocat",
            "--generate-password",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_pwd = payload["login"]["password"].as_str().unwrap();
        let decrypted_pwd = EncString::parse(enc_pwd)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_pwd.len(), 16);
        assert!(decrypted_pwd.chars().any(|c| c.is_ascii_uppercase()));
        assert!(decrypted_pwd.chars().any(|c| c.is_ascii_lowercase()));
        assert!(decrypted_pwd.chars().any(|c| c.is_ascii_digit()));

        let resp_body = json!({
            "id": "gen-pwd-uuid",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(posted);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Created login cipher \"Gen Pass Site\" (gen-pwd-uuid)."));
}

#[test]
fn test_create_login_cipher_generate_passphrase_flag() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Gen Phrase Site",
            "--username",
            "octocat",
            "--generate-passphrase",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_pwd = payload["login"]["password"].as_str().unwrap();
        let decrypted_pwd = EncString::parse(enc_pwd)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        let words: Vec<&str> = decrypted_pwd.split('-').collect();
        assert_eq!(words.len(), 4, "Expected 4 words, got {decrypted_pwd}");

        let resp_body = json!({
            "id": "gen-phrase-uuid",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(posted);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Created login cipher \"Gen Phrase Site\" (gen-phrase-uuid)."));
}

#[test]
fn test_create_login_cipher_interactive_enter_generates_password() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .env("OMA_FORCE_PROMPT", "1")
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Prompt Site",
            "--username",
            "octocat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // User presses enter (empty input) to trigger generator
    {
        let mut stdin = cli.stdin.take().unwrap();
        stdin.write_all(b"\n").unwrap();
    }

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_pwd = payload["login"]["password"].as_str().unwrap();
        let decrypted_pwd = EncString::parse(enc_pwd)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_pwd.len(), 16);

        let resp_body = json!({
            "id": "prompt-uuid",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(posted);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Enter password (or press Enter to generate): "));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Created login cipher \"Prompt Site\" (prompt-uuid)."));
}

#[test]
fn test_create_login_cipher_non_interactive_without_password_fails_closed() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Fail Site",
            "--username",
            "octocat",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Password is required. Provide --password, --password-stdin, --generate-password, or run interactively in a terminal."));
}

#[test]
fn test_edit_cipher_generate_password_flag() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "55555555-5555-5555-5555-555555555555";
    let cipher_name = "Site To Gen Pwd";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "olduser");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_name, "--generate-password"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_pwd = payload["login"]["password"].as_str().unwrap();
        let decrypted_pwd = EncString::parse(enc_pwd)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_pwd.len(), 16);

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T01:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("Updated cipher \"{cipher_name}\" ({cipher_id}).")));
}

#[test]
fn test_edit_cipher_in_editor() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "66666666-6666-6666-6666-666666666666";
    let cipher_name = "Editor Test Site";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "editor_old");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Create a mock editor script that changes Username: editor_old to Username: editor_new
    let editor_script = dir.join("mock_editor.sh");
    fs::write(
        &editor_script,
        "#!/bin/sh\nif [ -x /usr/bin/sed ]; then /usr/bin/sed -i 's/Username: editor_old/Username: editor_new/' \"$1\"; else /bin/sed -i 's/Username: editor_old/Username: editor_new/' \"$1\"; fi\n",
    )
    .unwrap();
    fs::set_permissions(&editor_script, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cli = make_command(dir)
        .env("EDITOR", &editor_script)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "edit", cipher_name])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_user = payload["login"]["username"].as_str().unwrap();
        let decrypted_user = EncString::parse(enc_user)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(decrypted_user, "editor_new");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": null,
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-09T01:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("Updated cipher \"{cipher_name}\" ({cipher_id}).")));
}

#[test]
fn test_edit_cipher_in_editor_no_changes() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "77777777-7777-7777-7777-777777777777";
    let cipher_name = "Editor No Change Site";
    add_cipher_to_cache(dir, &user_key, cipher_id, cipher_name, "user_unchanged");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Mock editor that exits without making changes
    let editor_script = dir.join("mock_editor_noop.sh");
    fs::write(&editor_script, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&editor_script, fs::Permissions::from_mode(0o700)).unwrap();

    let out = make_command(dir)
        .env("EDITOR", &editor_script)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "edit", cipher_name])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No changes made."));
}

#[test]
fn test_disambiguation_interactive_selection() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher1_id = "88888888-1111-1111-1111-111111111111";
    let cipher2_id = "88888888-2222-2222-2222-222222222222";
    let cipher_name = "Ambiguous Duplicate";
    add_cipher_to_cache(dir, &user_key, cipher1_id, cipher_name, "candidate_one");
    add_cipher_to_cache(dir, &user_key, cipher2_id, cipher_name, "candidate_two");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "delete", cipher_name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Select candidate 1, then confirm deletion with 'y'
    {
        let mut stdin = cli.stdin.take().unwrap();
        stdin.write_all(b"1\ny\n").unwrap();
    }

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher1_id}/delete"));
        received = true;

        let response =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(received);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Multiple ciphers matched 'Ambiguous Duplicate':"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("Deleted cipher \"{cipher_name}\" ({cipher1_id}).")));
}

#[test]
fn test_disambiguation_non_interactive_fails_closed_with_ids() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher1_id = "99999999-1111-1111-1111-111111111111";
    let cipher2_id = "99999999-2222-2222-2222-222222222222";
    let cipher_name = "Ambiguous Duplicate NonInteractive";
    add_cipher_to_cache(dir, &user_key, cipher1_id, cipher_name, "candidate_one");
    add_cipher_to_cache(dir, &user_key, cipher2_id, cipher_name, "candidate_two");

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args(["vault", "edit", cipher_name, "--password", "newsecret"])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&format!("Multiple ciphers matched '{cipher_name}': [{cipher1_id}, {cipher2_id}]. Specify by ID or narrower name.")));
}

#[test]
fn test_create_login_cipher_multiple_uris() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "MultiURI Cipher",
            "--username",
            "octocat",
            "--password",
            "secretpass",
            "--uri",
            "https://github.com",
            "--uri",
            "https://api.github.com",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let uris_arr = payload["login"]["uris"]
            .as_array()
            .expect("uris must be array");
        assert_eq!(uris_arr.len(), 2);

        let u1 = EncString::parse(uris_arr[0]["uri"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        let u2 = EncString::parse(uris_arr[1]["uri"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(u1, "https://github.com");
        assert_eq!(u2, "https://api.github.com");

        let resp_body = json!({
            "id": "multi-uri-uuid-1111",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-10T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI exit status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(posted, "Bitwarden API POST was not received");

    let stdout_json: Value = serde_json::from_slice(&out.stdout).expect("output must be JSON");
    assert_eq!(stdout_json["ok"], true);
    assert_eq!(stdout_json["outcome"], "saved");
    assert_eq!(stdout_json["item"]["id"], "multi-uri-uuid-1111");
}

#[test]
fn test_edit_login_cipher_add_uri_and_clear_uris() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "11111111-2222-3333-4444-555555555555";
    let cipher_name = "Edit MultiURI Target";

    let initial_login = json!({
        "username": user_key.encrypt_string("octo").unwrap(),
        "password": user_key.encrypt_string("pass").unwrap(),
        "uris": [
            { "uri": user_key.encrypt_string("https://primary.com").unwrap(), "match": Value::Null }
        ]
    });
    add_cipher_with_login_to_cache(dir, &user_key, cipher_id, cipher_name, initial_login);

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // 1. Test --add-uri
    let mut cli_add = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_id,
            "--add-uri",
            "https://secondary.com",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut add_received = false;
    while cli_add.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        add_received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let uris_arr = payload["login"]["uris"]
            .as_array()
            .expect("uris must be array");
        assert_eq!(uris_arr.len(), 2);
        let u1 = EncString::parse(uris_arr[0]["uri"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        let u2 = EncString::parse(uris_arr[1]["uri"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(u1, "https://primary.com");
        assert_eq!(u2, "https://secondary.com");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-10T01:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out_add = cli_add.wait_with_output().unwrap();
    assert!(
        out_add.status.success(),
        "CLI add-uri failed: {}",
        String::from_utf8_lossy(&out_add.stderr)
    );
    assert!(add_received);

    // 2. Test --clear-uris
    let mut cli_clear = make_command(dir)
        .args(["vault", "edit", cipher_id, "--clear-uris", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut clear_received = false;
    while cli_clear.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        clear_received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let uris_arr = payload["login"]["uris"]
            .as_array()
            .expect("uris must be array");
        assert_eq!(uris_arr.len(), 0);

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-10T02:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out_clear = cli_clear.wait_with_output().unwrap();
    assert!(
        out_clear.status.success(),
        "CLI clear-uris failed: {}",
        String::from_utf8_lossy(&out_clear.stderr)
    );
    assert!(clear_received);
}

#[test]
fn test_edit_login_cipher_replace_uris() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "22222222-3333-4444-5555-666666666666";
    let cipher_name = "Edit Replace URIs Target";

    let initial_login = json!({
        "username": user_key.encrypt_string("octo").unwrap(),
        "password": user_key.encrypt_string("pass").unwrap(),
        "uris": [
            { "uri": user_key.encrypt_string("https://old-1.com").unwrap(), "match": Value::Null },
            { "uri": user_key.encrypt_string("https://old-2.com").unwrap(), "match": Value::Null }
        ]
    });
    add_cipher_with_login_to_cache(dir, &user_key, cipher_id, cipher_name, initial_login);

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_id,
            "--uri",
            "https://single-replacement.com",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let uris_arr = payload["login"]["uris"]
            .as_array()
            .expect("uris must be array");
        assert_eq!(uris_arr.len(), 1);
        let u1 = EncString::parse(uris_arr[0]["uri"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(u1, "https://single-replacement.com");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "revisionDate": "2026-11-10T03:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI replace uris failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(received);
}

fn decrypt_field_string(value: &Value, key: &SymmetricCryptoKey) -> String {
    let enc = value.as_str().expect("field component must be a string");
    EncString::parse(enc).unwrap().decrypt_string(key).unwrap()
}

#[test]
fn test_create_login_cipher_with_custom_fields() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Fields Cipher",
            "--username",
            "octocat",
            "--password",
            "secretpass",
            "--field",
            "Cluster=Prod",
            "--hidden-field",
            "API_KEY=secret-tok",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let fields = payload["fields"].as_array().expect("fields must be array");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["type"], 0);
        assert_eq!(fields[1]["type"], 1);

        // Both name and value cross the wire as ciphertext only.
        assert_ne!(fields[0]["name"].as_str().unwrap(), "Cluster");
        assert_ne!(fields[0]["value"].as_str().unwrap(), "Prod");
        assert_eq!(
            decrypt_field_string(&fields[0]["name"], &user_key),
            "Cluster"
        );
        assert_eq!(decrypt_field_string(&fields[0]["value"], &user_key), "Prod");

        assert_ne!(fields[1]["name"].as_str().unwrap(), "API_KEY");
        assert_ne!(fields[1]["value"].as_str().unwrap(), "secret-tok");
        assert_eq!(
            decrypt_field_string(&fields[1]["name"], &user_key),
            "API_KEY"
        );
        assert_eq!(
            decrypt_field_string(&fields[1]["value"], &user_key),
            "secret-tok"
        );

        let resp_body = json!({
            "id": "custom-fields-uuid-1111",
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T00:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI exit status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(posted, "Bitwarden API POST was not received");

    // The decrypted cache snapshot must retain both typed custom fields.
    let item = ipc(
        &socket,
        json!({"action": "get_item", "query": "Fields Cipher", "touch": true}),
    );
    assert_eq!(item["ok"], true, "cached item missing: {item}");
    let cached = item["item"]["fields"].as_array().unwrap();
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0]["name"], "Cluster");
    assert_eq!(cached[0]["value"], "Prod");
    assert_eq!(cached[0]["type"], 0);
    assert_eq!(cached[1]["name"], "API_KEY");
    assert_eq!(cached[1]["value"], "secret-tok");
    assert_eq!(cached[1]["type"], 1);
}

#[test]
fn test_create_note_cipher_with_bool_field() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "note",
            "--name",
            "Bool Note",
            "--notes",
            "content",
            "--bool-field",
            "Verified=true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut posted = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (path, body) = read_request(&mut stream);
        assert_eq!(path, "/api/ciphers");
        posted = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["type"], 2);
        let fields = payload["fields"].as_array().expect("fields must be array");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0]["type"], 2);
        assert_eq!(
            decrypt_field_string(&fields[0]["name"], &user_key),
            "Verified"
        );
        assert_eq!(decrypt_field_string(&fields[0]["value"], &user_key), "true");

        let resp_body = json!({
            "id": "bool-note-uuid-2222",
            "organizationId": null,
            "folderId": null,
            "type": 2,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "secureNote": { "type": 0 },
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T01:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI exit status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(posted, "Bitwarden API POST was not received");
}

#[test]
fn test_create_cipher_rejects_malformed_boolean_custom_field() {
    let (temp, _api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();

    let out = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Bad Bool",
            "--username",
            "octocat",
            "--password",
            "secretpass",
            "--bool-field",
            "Active=maybe",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Invalid boolean value 'maybe' for custom field 'Active'"),
        "unexpected error output: {stderr}"
    );
}

fn add_login_cipher_with_fields_to_cache(
    dir: &Path,
    user_key: &SymmetricCryptoKey,
    id: &str,
    name: &str,
    fields: &[(&str, &str, i64)],
) {
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    let encrypted: Vec<Value> = fields
        .iter()
        .map(|(field_name, value, field_type)| {
            json!({
                "name": user_key.encrypt_string(field_name).unwrap(),
                "value": user_key.encrypt_string(value).unwrap(),
                "type": field_type,
            })
        })
        .collect();
    ciphers.push(json!({
        "id": id,
        "organizationId": null,
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": {
            "username": user_key.encrypt_string("octo").unwrap(),
            "password": user_key.encrypt_string("pass").unwrap(),
            "uris": []
        },
        "fields": encrypted,
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();
}

fn decrypt_payload_fields(payload: &Value, key: &SymmetricCryptoKey) -> Vec<(String, String, i64)> {
    payload["fields"]
        .as_array()
        .expect("fields must be array")
        .iter()
        .map(|field| {
            (
                decrypt_field_string(&field["name"], key),
                decrypt_field_string(&field["value"], key),
                field["type"].as_i64().unwrap(),
            )
        })
        .collect()
}

#[test]
fn test_edit_login_cipher_upserts_custom_field() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "afaf1111-2222-3333-4444-555555555555";
    let cipher_name = "Upsert Field Target";
    add_login_cipher_with_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[("PIN", "1234", 0), ("Keep", "untouched", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_id, "--field", "PIN=9999", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let fields = decrypt_payload_fields(&payload, &user_key);
        assert_eq!(
            fields,
            vec![
                ("PIN".to_string(), "9999".to_string(), 0),
                ("Keep".to_string(), "untouched".to_string(), 0),
            ]
        );
        // Unmentioned credentials stay intact.
        let username = decrypt_field_string(&payload["login"]["username"], &user_key);
        assert_eq!(username, "octo");

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T02:00:00.000Z"
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI upsert failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(received);
}

#[test]
fn test_edit_login_cipher_upserts_custom_field_case_insensitive() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "afaf2222-2222-3333-4444-555555555555";
    let cipher_name = "Case Insensitive Field Target";
    add_login_cipher_with_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[("pin", "1234", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_id, "--field", "PIN=9999", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (_, _, body) = read_request_with_method(&mut stream);
        received = true;
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let fields = decrypt_payload_fields(&payload, &user_key);
        assert_eq!(fields, vec![("PIN".to_string(), "9999".to_string(), 0)]);

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T02:10:00.000Z"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI case-insensitive upsert failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(received);
}

#[test]
fn test_edit_login_cipher_appends_hidden_field() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "afaf3333-2222-3333-4444-555555555555";
    let cipher_name = "Append Field Target";
    add_login_cipher_with_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[("Existing", "value", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_id,
            "--hidden-field",
            "NewSecret=val123",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (_, _, body) = read_request_with_method(&mut stream);
        received = true;
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let fields = decrypt_payload_fields(&payload, &user_key);
        assert_eq!(
            fields,
            vec![
                ("Existing".to_string(), "value".to_string(), 0),
                ("NewSecret".to_string(), "val123".to_string(), 1),
            ]
        );

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T02:20:00.000Z"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI append failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(received);
}

#[test]
fn test_edit_login_cipher_removes_custom_field() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "afaf4444-2222-3333-4444-555555555555";
    let cipher_name = "Remove Field Target";
    add_login_cipher_with_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[("Keep", "x", 0), ("ObsoleteKey", "stale", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_id,
            "--remove-field",
            "ObsoleteKey",
            "--json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (_, _, body) = read_request_with_method(&mut stream);
        received = true;
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let fields = decrypt_payload_fields(&payload, &user_key);
        assert_eq!(fields, vec![("Keep".to_string(), "x".to_string(), 0)]);

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T02:30:00.000Z"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "CLI removal failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(received);
}

#[test]
fn test_edit_login_cipher_remove_unknown_field_fails_without_request() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "afaf5555-2222-3333-4444-555555555555";
    let cipher_name = "Unknown Remove Target";
    add_login_cipher_with_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[("Keep", "x", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let out = make_command(dir)
        .args([
            "vault",
            "edit",
            cipher_id,
            "--remove-field",
            "Nope",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No custom field named 'Nope'"),
        "unexpected output: {stdout}"
    );
    assert!(
        stdout.contains("Keep"),
        "should list available fields: {stdout}"
    );
}

#[test]
fn test_edit_login_cipher_optimistic_concurrency_conflict_on_field() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "afaf6666-2222-3333-4444-555555555555";
    let cipher_name = "Field Conflict Target";
    add_login_cipher_with_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[("PIN", "1234", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    let mut cli = make_command(dir)
        .args(["vault", "edit", cipher_id, "--field", "PIN=9999", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (_, _, _) = read_request_with_method(&mut stream);
        received = true;
        let resp_body = json!({
            "error": "Conflict",
            "message": "Cipher revisionDate does not match server"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(received);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("modified remotely"),
        "unexpected output: {stdout}"
    );
}

fn add_login_cipher_with_uris_and_fields_to_cache(
    dir: &Path,
    user_key: &SymmetricCryptoKey,
    id: &str,
    name: &str,
    uris: &[&str],
    fields: &[(&str, &str, i64)],
) {
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();
    let encrypted_uris: Vec<Value> = uris
        .iter()
        .map(|uri| json!({"uri": user_key.encrypt_string(uri).unwrap(), "match": Value::Null}))
        .collect();
    let encrypted_fields: Vec<Value> = fields
        .iter()
        .map(|(field_name, value, field_type)| {
            json!({
                "name": user_key.encrypt_string(field_name).unwrap(),
                "value": user_key.encrypt_string(value).unwrap(),
                "type": field_type,
            })
        })
        .collect();
    ciphers.push(json!({
        "id": id,
        "organizationId": null,
        "folderId": null,
        "type": 1,
        "name": user_key.encrypt_string(name).unwrap(),
        "notes": null,
        "favorite": false,
        "login": {
            "username": user_key.encrypt_string("octo").unwrap(),
            "password": user_key.encrypt_string("pass").unwrap(),
            "uris": encrypted_uris
        },
        "fields": encrypted_fields,
        "revisionDate": "2026-11-09T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();
}

#[test]
fn test_edit_cipher_in_editor_multiple_uris_and_custom_fields() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "ed170000-1111-2222-3333-444444444444";
    let cipher_name = "Editor Fields Site";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &["https://one.example", "https://two.example"],
        &[("PIN", "1234", 0), ("Old", "x", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Editor: drop the second URI, drop the Obsolete field, edit PIN and add a
    // new hidden field.
    let editor_script = dir.join("mock_editor_fields.sh");
    fs::write(
        &editor_script,
        "#!/bin/sh\n\
         SED=/usr/bin/sed\n\
         [ -x \"$SED\" ] || SED=/bin/sed\n\
         \"$SED\" -i '/URI: https:\\/\\/two.example/d' \"$1\"\n\
         \"$SED\" -i '/Field: Old = x/d' \"$1\"\n\
         \"$SED\" -i 's/Field: PIN = 1234/Field: PIN = 9999/' \"$1\"\n\
         \"$SED\" -i '/# Custom Fields:/a Hidden Field: Added = fresh' \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&editor_script, fs::Permissions::from_mode(0o700)).unwrap();

    let mut cli = make_command(dir)
        .env("EDITOR", &editor_script)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "edit", cipher_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received = false;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish in time");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/ciphers/{cipher_id}"));
        received = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();

        let uris: Vec<String> = payload["login"]["uris"]
            .as_array()
            .expect("login.uris must be array")
            .iter()
            .map(|u| decrypt_field_string(&u["uri"], &user_key))
            .collect();
        assert_eq!(uris, vec!["https://one.example"]);

        let fields = decrypt_payload_fields(&payload, &user_key);
        assert_eq!(
            fields,
            vec![
                ("PIN".to_string(), "9999".to_string(), 0),
                ("Added".to_string(), "fresh".to_string(), 1),
            ]
        );

        let resp_body = json!({
            "id": cipher_id,
            "organizationId": null,
            "folderId": null,
            "type": 1,
            "name": payload["name"],
            "notes": payload["notes"],
            "favorite": false,
            "login": payload["login"],
            "fields": payload["fields"],
            "revisionDate": "2026-11-11T03:00:00.000Z"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    let out = cli.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "editor edit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(received, "no cipher update was sent");
}

#[test]
fn test_edit_cipher_in_editor_malformed_field_keeps_draft() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let cipher_id = "ed170000-2222-3333-4444-555555555555";
    let cipher_name = "Editor Bad Field Site";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        cipher_name,
        &[],
        &[("PIN", "1234", 0)],
    );

    let _daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );

    // Editor writes a malformed field line without the '=' separator.
    let editor_script = dir.join("mock_editor_bad_field.sh");
    fs::write(
        &editor_script,
        "#!/bin/sh\n\
         SED=/usr/bin/sed\n\
         [ -x \"$SED\" ] || SED=/bin/sed\n\
         \"$SED\" -i '/# Custom Fields:/a Field: NoSeparator' \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&editor_script, fs::Permissions::from_mode(0o700)).unwrap();

    let out = make_command(dir)
        .env("EDITOR", &editor_script)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["vault", "edit", cipher_id])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("expected 'Field: NAME = VALUE'"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains("Your edits were kept at"),
        "draft must not be discarded: {stderr}"
    );
}

fn install_wl_copy_stub(dir: &Path) {
    let stub = dir.join("wl-copy");
    fs::write(
        &stub,
        "#!/bin/sh\nset -eu\nif [ \"${1:-}\" = --clear ]; then exit 0; fi\n\
         CAT=/bin/cat\n\
         [ -x \"$CAT\" ] || CAT=/usr/bin/cat\n\
         echo \"$*\" >> \"$XDG_RUNTIME_DIR/wl-copy-args.log\"\n\
         \"$CAT\" > \"$XDG_RUNTIME_DIR/wl-copy-content\"\n",
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();
}

fn copy_command(dir: &Path) -> Command {
    let mut cmd = make_command(dir);
    cmd.env("WAYLAND_DISPLAY", "fixture-wayland");
    cmd
}

fn start_unlocked_daemon(dir: &Path) -> Daemon {
    let daemon = Daemon(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        ipc(&socket, json!({"action": "unlock", "password": "fixture"}))["ok"],
        true
    );
    daemon
}

#[test]
fn test_copy_custom_field_text() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "copy0000-0000-0000-0000-000000000001";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Copy Field Target",
        &[],
        &[("PIN", "1234", 0), ("API_KEY", "secret-token", 0)],
    );
    let _daemon = start_unlocked_daemon(dir);

    let out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "PIN"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(
        out.status.success(),
        "copy failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["copied"], "PIN");
    assert_eq!(result["timeout"], 0, "text fields are not sensitive");

    // The clipboard stub actually received the decrypted value, without the
    // sensitive flag.
    assert_eq!(
        fs::read_to_string(dir.join("wl-copy-content")).unwrap(),
        "1234"
    );
    let args = fs::read_to_string(dir.join("wl-copy-args.log")).unwrap();
    assert!(args.contains("--type text/plain"));
    assert!(!args.contains("--sensitive"));
}

#[test]
fn test_copy_custom_field_hidden_is_sensitive() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "copy0000-0000-0000-0000-000000000002";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Copy Hidden Target",
        &[],
        &[("API_KEY", "secret-token", 1)],
    );
    let _daemon = start_unlocked_daemon(dir);

    let out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "API_KEY", "--timeout", "3"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(
        out.status.success(),
        "copy failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["copied"], "API_KEY");
    assert_eq!(result["timeout"], 3, "hidden fields enforce a TTL");

    assert_eq!(
        fs::read_to_string(dir.join("wl-copy-content")).unwrap(),
        "secret-token"
    );
    let args = fs::read_to_string(dir.join("wl-copy-args.log")).unwrap();
    assert!(
        args.contains("--sensitive"),
        "hidden field must be copied as sensitive: {args}"
    );
}

#[test]
fn test_copy_custom_field_case_insensitive_fallback() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "copy0000-0000-0000-0000-000000000003";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Copy Case Insensitive",
        &[],
        &[("PIN", "1234", 0), ("RecoveryCode", "abc123", 0)],
    );
    let _daemon = start_unlocked_daemon(dir);

    let out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "recoverycode"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(out.status.success());
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["copied"], "RecoveryCode");
    assert_eq!(
        fs::read_to_string(dir.join("wl-copy-content")).unwrap(),
        "abc123"
    );
}

#[test]
fn test_copy_custom_field_not_found_lists_available() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "copy0000-0000-0000-0000-000000000004";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Copy Not Found",
        &[],
        &[("PIN", "1234", 0), ("API_KEY", "secret", 1)],
    );
    let _daemon = start_unlocked_daemon(dir);

    let out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "NONEXISTENT"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(!out.status.success());
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"], false);
    let error = result["error"].as_str().unwrap();
    assert!(error.contains("NONEXISTENT"));
    assert!(error.contains("Available fields"));
    assert!(error.contains("PIN"));
    assert!(error.contains("API_KEY"));
    assert!(!dir.join("wl-copy-content").exists(), "nothing was copied");
}

#[test]
fn test_copy_custom_field_item_without_fields() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "copy0000-0000-0000-0000-000000000005";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Copy No Fields",
        &[],
        &[],
    );
    let _daemon = start_unlocked_daemon(dir);

    let out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "ANYTHING"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(!out.status.success());
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert!(result["error"]
        .as_str()
        .unwrap()
        .contains("has no custom fields"));
}

#[test]
fn test_copy_custom_field_conflicts_with_other_flags() {
    let (temp, _api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    install_wl_copy_stub(dir);
    let cipher_id = "copy0000-0000-0000-0000-000000000006";
    add_login_cipher_with_uris_and_fields_to_cache(
        dir,
        &user_key,
        cipher_id,
        "Copy Conflict",
        &[],
        &[("PIN", "1234", 0)],
    );
    let _daemon = start_unlocked_daemon(dir);

    let out = copy_command(dir)
        .args(["copy", cipher_id, "--field", "PIN", "--password"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    assert!(!out.status.success());
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["ok"], false);
    assert!(result["error"]
        .as_str()
        .unwrap()
        .contains("--field cannot be combined with"));
}
