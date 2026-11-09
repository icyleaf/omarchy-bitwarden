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
