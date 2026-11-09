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

    // Verify evicted from search index
    let search_out = make_command(dir)
        .args(["vault", "search", cipher_name])
        .output()
        .unwrap();
    assert!(search_out.status.success());
    let search_str = String::from_utf8_lossy(&search_out.stdout);
    assert!(
        !search_str.contains(cipher_name),
        "Item should be evicted from search index: {search_str}"
    );

    // Verify evicted from data.json cache
    let cache_data: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("data.json")).unwrap()).unwrap();
    assert!(
        cache_data["ciphers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["id"] != cipher_id),
        "Cipher should be removed from data.json"
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
        stderr.contains("Multiple ciphers matched 'AWS'. Specify by ID or narrower name."),
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
