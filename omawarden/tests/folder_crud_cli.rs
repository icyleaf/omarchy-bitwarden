use omawarden::crypto::{derive_master_key, EncString, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
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
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e) if e.kind() == ErrorKind::ConnectionRefused => {
                assert!(
                    Instant::now() < deadline,
                    "daemon socket not ready after 5s"
                );
                std::thread::sleep(Duration::from_millis(5));
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

fn read_request_with_method(stream: &mut TcpStream) -> (String, String, Vec<u8>) {
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
        "ciphers": [],
        "folders": []
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
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_KEYRING_PROVIDER", "secret-tool");
    cmd
}

fn start_daemon(dir: &Path) -> Daemon {
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
    daemon
}

fn unlock_daemon(dir: &Path) {
    let socket = dir.join("omawarden.sock");
    let resp = ipc(&socket, json!({"action": "unlock", "password": "fixture"}));
    assert_eq!(resp["ok"], true, "unlock failed: {resp}");
}

#[test]
fn test_folder_crud_lifecycle_end_to_end() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let _daemon = start_daemon(dir);
    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(20);

    // 1. Locked vault rejects folder list and folder create fail-closed
    let locked_list = make_command(dir)
        .args(["folder", "list", "--json"])
        .output()
        .unwrap();
    assert!(!locked_list.status.success());

    let locked_create = make_command(dir)
        .args(["folder", "create", "Work/Prod", "--json"])
        .output()
        .unwrap();
    assert!(!locked_create.status.success());

    unlock_daemon(dir);

    // 2. Empty folder name fails closed before hitting server
    let empty_create = make_command(dir)
        .args(["folder", "create", "   ", "--json"])
        .output()
        .unwrap();
    assert!(!empty_create.status.success());
    let empty_json: Value = serde_json::from_slice(&empty_create.stdout).unwrap();
    assert_eq!(empty_json["ok"], false);

    // 3. Create folder "Work/Prod" (preserving slash)
    let folder_id = "f01de000-1111-2222-3333-444444444444";
    let mut create_cli = make_command(dir)
        .args(["folder", "create", "Work/Prod", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received_create = false;
    while create_cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "create timed out");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/folders");
        received_create = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_name = payload["name"].as_str().expect("encrypted folder name");
        let dec_name = EncString::parse(enc_name)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(dec_name, "Work/Prod");

        let resp_body = json!({
            "id": folder_id,
            "name": enc_name,
            "revisionDate": "2026-11-24T01:00:00.000Z"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }
    let create_out = create_cli.wait_with_output().unwrap();
    assert!(
        create_out.status.success(),
        "create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create_out.stdout),
        String::from_utf8_lossy(&create_out.stderr)
    );
    assert!(received_create);

    // 4. folder list (and ls alias) returns empty folder with count 0 (JSON and terminal modes)
    let list_out = make_command(dir)
        .args(["folder", "ls", "--json"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_json: Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list_json["ok"], true);
    let folders = list_json["folders"].as_array().unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0]["id"], folder_id);
    assert_eq!(folders[0]["name"], "Work/Prod");
    assert_eq!(folders[0]["count"], 0);

    let list_text = make_command(dir).args(["folder", "list"]).output().unwrap();
    assert!(list_text.status.success());
    let list_stdout = String::from_utf8_lossy(&list_text.stdout);
    assert!(list_stdout.contains("Work/Prod (0)"));
    assert!(list_stdout.contains(folder_id));

    // Empty rename fails closed before hitting server
    let empty_rename = make_command(dir)
        .args(["folder", "edit", folder_id, "--name", "   ", "--json"])
        .output()
        .unwrap();
    assert!(!empty_rename.status.success());

    // 5. Rename folder via `rename` alias
    let mut rename_cli = make_command(dir)
        .args([
            "folder",
            "rename",
            "Work/Prod",
            "--name",
            "Engineering",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received_update = false;
    while rename_cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "rename timed out");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let (method, path, body) = read_request_with_method(&mut stream);
        assert_eq!(method, "PUT");
        assert_eq!(path, format!("/api/folders/{folder_id}"));
        received_update = true;

        let payload: Value = serde_json::from_slice(&body).unwrap();
        let enc_name = payload["name"].as_str().unwrap();
        let dec_name = EncString::parse(enc_name)
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap();
        assert_eq!(dec_name, "Engineering");

        let resp_body = json!({
            "id": folder_id,
            "name": enc_name,
            "revisionDate": "2026-11-24T02:00:00.000Z"
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }
    let rename_out = rename_cli.wait_with_output().unwrap();
    assert!(
        rename_out.status.success(),
        "rename failed: {}",
        String::from_utf8_lossy(&rename_out.stderr)
    );
    assert!(received_update);

    // Verify renamed folder is immediately visible in folder list
    let list_after_rename = make_command(dir)
        .args(["folder", "list", "--json"])
        .output()
        .unwrap();
    let list_after_json: Value = serde_json::from_slice(&list_after_rename.stdout).unwrap();
    assert_eq!(list_after_json["folders"][0]["name"], "Engineering");

    // 6. Non-interactive delete without --yes fails closed
    let delete_no_yes = make_command(dir)
        .args(["folder", "delete", "Engineering", "--json"])
        .output()
        .unwrap();
    assert!(!delete_no_yes.status.success());

    // 7. Seed a cipher assigned to this folder and verify delete reconciles folderId -> null
    let cipher_id = "c1fe0000-1111-2222-3333-444444444444";
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    data["ciphers"].as_array_mut().unwrap().push(json!({
        "id": cipher_id,
        "type": 2,
        "folderId": folder_id,
        "name": user_key.encrypt_string("Folder Note").unwrap(),
        "notes": user_key.encrypt_string("inside engineering").unwrap(),
        "favorite": false,
        "secureNote": { "type": 0 },
        "revisionDate": "2026-11-24T02:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();
    // Re-unlock to reload seeded cipher into in-memory index
    assert_eq!(ipc(&socket, json!({"action": "lock"}))["ok"], true);
    unlock_daemon(dir);

    let list_with_count = make_command(dir)
        .args(["folder", "list", "--json"])
        .output()
        .unwrap();
    let count_json: Value = serde_json::from_slice(&list_with_count.stdout).unwrap();
    assert_eq!(count_json["folders"][0]["count"], 1);

    let mut delete_cli = make_command(dir)
        .args(["folder", "rm", "Engineering", "--yes", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut received_delete = false;
    while delete_cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "delete timed out");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let (method, path, _body) = read_request_with_method(&mut stream);
        assert_eq!(method, "DELETE");
        assert_eq!(path, format!("/api/folders/{folder_id}"));
        received_delete = true;

        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    }
    let delete_out = delete_cli.wait_with_output().unwrap();
    assert!(
        delete_out.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&delete_out.stderr)
    );
    assert!(received_delete);

    // Verify folder is gone AND cipher's folder_id/folder_name are immediately cleared without sync
    let list_after_delete = make_command(dir)
        .args(["folder", "list", "--json"])
        .output()
        .unwrap();
    let after_del_json: Value = serde_json::from_slice(&list_after_delete.stdout).unwrap();
    assert_eq!(after_del_json["folders"].as_array().unwrap().len(), 0);

    let item_resp = ipc(&socket, json!({"action": "get_item", "query": cipher_id}));
    assert_eq!(item_resp["ok"], true);
    assert!(item_resp["item"]["folder_id"].is_null());
    assert!(item_resp["item"]["folder_name"].is_null());

    let cached_after: Value =
        serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    assert_eq!(cached_after["folders"].as_array().unwrap().len(), 0);
    assert!(cached_after["ciphers"][0]["folderId"].is_null());
}

#[test]
fn test_folder_delete_interactive_confirmation_and_duplicate_disambiguation() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let id_a = "aaaaaaaa-1111-2222-3333-444444444444";
    let id_b = "bbbbbbbb-1111-2222-3333-444444444444";

    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    data["folders"] = json!([
        { "id": id_a, "name": user_key.encrypt_string("Shared").unwrap(), "revisionDate": "2026-11-24T00:00:00.000Z" },
        { "id": id_b, "name": user_key.encrypt_string("Shared").unwrap(), "revisionDate": "2026-11-24T00:00:00.000Z" }
    ]);
    data["ciphers"] = json!([
        {
            "id": "11111111-aaaa-bbbb-cccc-dddddddddddd",
            "type": 2,
            "folderId": id_a,
            "name": user_key.encrypt_string("Note 1").unwrap(),
            "notes": user_key.encrypt_string("a").unwrap(),
            "favorite": false,
            "secureNote": { "type": 0 },
            "revisionDate": "2026-11-24T00:00:00.000Z"
        },
        {
            "id": "22222222-aaaa-bbbb-cccc-dddddddddddd",
            "type": 2,
            "folderId": id_a,
            "name": user_key.encrypt_string("Note 2").unwrap(),
            "notes": user_key.encrypt_string("b").unwrap(),
            "favorite": false,
            "secureNote": { "type": 0 },
            "revisionDate": "2026-11-24T00:00:00.000Z"
        }
    ]);
    fs::write(&cache_path, data.to_string()).unwrap();

    let _daemon = start_daemon(dir);
    unlock_daemon(dir);

    // 1. Ambiguous folder name fails closed listing both IDs
    let ambig = make_command(dir)
        .args(["folder", "delete", "Shared", "--yes"])
        .output()
        .unwrap();
    assert!(!ambig.status.success());
    let ambig_err = String::from_utf8_lossy(&ambig.stderr);
    assert!(ambig_err.contains(id_a));
    assert!(ambig_err.contains(id_b));

    // 2. Interactive delete by UUID shows affected cipher count and aborts on "n"
    let mut abort_cli = make_command(dir)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["folder", "delete", id_a])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    abort_cli.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let abort_out = abort_cli.wait_with_output().unwrap();
    assert!(!abort_out.status.success());
    let prompt_err = String::from_utf8_lossy(&abort_out.stderr);
    assert!(
        prompt_err.contains("2 ciphers will be moved to No Folder"),
        "expected affected count in prompt, got: {prompt_err}"
    );

    // 3. Interactive delete by UUID succeeds on "y"
    let mut confirm_cli = make_command(dir)
        .env("OMA_FORCE_PROMPT", "1")
        .args(["folder", "delete", id_a])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    confirm_cli.stdin.take().unwrap().write_all(b"y\n").unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut received = false;
    while confirm_cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "confirm delete timed out");
        let (mut stream, _) = match api.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let (method, path, _) = read_request_with_method(&mut stream);
        assert_eq!(method, "DELETE");
        assert_eq!(path, format!("/api/folders/{id_a}"));
        received = true;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    }
    let confirm_out = confirm_cli.wait_with_output().unwrap();
    assert!(
        confirm_out.status.success(),
        "confirm delete failed: {}",
        String::from_utf8_lossy(&confirm_out.stderr)
    );
    assert!(received);
}
