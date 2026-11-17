//! Tests covering mixed-version CLI and daemon interactions (Issue #382).
//!
//! A newer CLI must never silently allow an older daemon to drop URIs or custom
//! fields. Instead of proliferating versioned action names (`cipher_create_v2`, etc.),
//! canonical actions (`cipher_create` and `cipher_update`) are preserved, and
//! compatibility is maintained through:
//! 1. Monotonic `schema_version` negotiation in `ping` (v1: legacy, v2: custom fields + multi-URI).
//! 2. Strict `deny_unknown_fields` on daemon mutation drafts (fails closed on unknown keys).
//! 3. On-demand auto-restart of stale standalone daemons when advanced features are used.
//! 4. Friendly, explicit guidance when an in-process host daemon cannot be terminated.

use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct ProcessGuard(Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

fn seed_cipher_in_cache(
    dir: &Path,
    user_key: &SymmetricCryptoKey,
    id: &str,
    name: &str,
    username: &str,
    uris: &[&str],
    fields: &[(&str, &str, u32)],
) {
    let cache_path = dir.join("data.json");
    let mut data: Value = serde_json::from_str(&fs::read_to_string(&cache_path).unwrap()).unwrap();
    let ciphers = data["ciphers"].as_array_mut().unwrap();

    let encrypted_uris: Vec<Value> = uris
        .iter()
        .map(|u| {
            json!({
                "uri": user_key.encrypt_string(u).unwrap(),
                "match": Value::Null,
            })
        })
        .collect();

    let encrypted_fields: Vec<Value> = fields
        .iter()
        .map(|(n, v, t)| {
            json!({
                "name": user_key.encrypt_string(n).unwrap(),
                "value": user_key.encrypt_string(v).unwrap(),
                "type": t,
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
            "username": user_key.encrypt_string(username).unwrap(),
            "password": user_key.encrypt_string("originalpass").unwrap(),
            "uris": encrypted_uris,
        },
        "fields": encrypted_fields,
        "revisionDate": "2026-11-17T00:00:00.000Z"
    }));
    fs::write(&cache_path, data.to_string()).unwrap();
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

/// A simulated pre-v2 daemon socket listener (schema_version 1 / unversioned).
struct MockOldDaemon {
    received_actions: Arc<std::sync::Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockOldDaemon {
    fn start(
        socket_path: PathBuf,
        target_id: &'static str,
        target_name: &'static str,
        is_in_process_host: bool,
    ) -> Self {
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let received_actions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let actions_clone = Arc::clone(&received_actions);

        let handle = thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("Mock daemon accept error: {e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    continue;
                }
                let Ok(req) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };

                actions_clone.lock().unwrap().push(req.clone());
                let action = req.get("action").and_then(Value::as_str).unwrap_or("");

                let response = match action {
                    "ping" => json!({
                        "ok": true,
                        "pong": true,
                        "protocol_version": 1,
                        // Stale daemon: no schema_version (or schema_version 1)
                        "schema_version": 1,
                        "ssh_write_receipt": true,
                        "account_activation_v1": true,
                        "version": "0.12.0-dev",
                        "unlocked": true,
                        "quick_unlock": false,
                        "quick_unlock_enabled": false,
                        "memory_locked": true,
                    }),
                    "unlock" => json!({ "ok": true }),
                    "stop" => {
                        if is_in_process_host {
                            json!({
                                "ok": false,
                                "error": "Access denied: cannot terminate in-process daemon hosted by an external application",
                                "protocol_version": 1
                            })
                        } else {
                            json!({ "ok": true, "protocol_version": 1 })
                        }
                    }
                    "cipher_resolve" => json!({
                        "ok": true,
                        "item": {
                            "id": target_id,
                            "name": target_name,
                            "type": "login",
                            "organization_id": Value::Null,
                        }
                    }),
                    "get_item" => json!({
                        "ok": true,
                        "item": {
                            "id": target_id,
                            "name": target_name,
                            "type": 1,
                            "type_name": "login",
                            "organization_id": Value::Null,
                            "login": {
                                "username": "user",
                                "uris": [{ "uri": "https://original.example" }]
                            },
                            "fields": [{ "name": "Existing", "value": "original", "type": 0 }]
                        }
                    }),
                    "cipher_create" => json!({
                        "ok": true,
                        "outcome": "saved",
                        "item": { "id": "created-legacy-id", "revisionDate": "2026-11-17T00:00:00Z" }
                    }),
                    "cipher_update" => json!({
                        "ok": true,
                        "outcome": "saved",
                        "item": { "id": target_id, "revisionDate": "2026-11-17T00:00:00Z" }
                    }),
                    other => json!({
                        "ok": false,
                        "error": format!("Unknown action: {}", other),
                        "protocol_version": 1
                    }),
                };

                let mut writer = stream;
                let _ = writeln!(writer, "{}", response);
            }
        });

        Self {
            received_actions,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockOldDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn test_mixed_version_in_process_stale_daemon_rejected_cleanly() {
    let (temp, api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();
    let socket = dir.join("omawarden.sock");

    // Old in-process daemon cannot be stopped externally
    let mock_daemon = MockOldDaemon::start(socket, "seed-id", "Seed", true);

    let output = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "New Item",
            "--username",
            "octocat",
            "--password",
            "supersecret",
            "--uri",
            "https://new.example",
            "--field",
            "Extra=value",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "CLI must fail when mutation requires schema v2 but daemon is stale in-process host"
    );
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout_str).unwrap();

    assert_eq!(parsed["ok"], false);
    let err_msg = parsed["error"].as_str().unwrap();
    assert!(
        err_msg.contains(
            "The running daemon does not support custom fields or advanced URI mutations"
        ),
        "Expected daemon upgrade guidance, got: {err_msg}"
    );

    // Verify the CLI attempted auto-restart via stop with admin: true
    let actions = mock_daemon.received_actions.lock().unwrap();
    let stop_action = actions.iter().find(|a| {
        a.get("action")
            .and_then(Value::as_str)
            .is_some_and(|s| s == "stop")
    });
    assert!(
        stop_action.is_some(),
        "CLI must attempt stop before failing"
    );
    assert_eq!(stop_action.unwrap()["admin"], true);

    // Verify ZERO requests reached the upstream API server
    assert!(
        api.accept().is_err(),
        "Upstream API must receive zero requests"
    );
}

#[test]
fn test_mixed_version_edit_with_field_and_favorite_rejected_on_stale_in_process() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let socket = dir.join("omawarden.sock");

    seed_cipher_in_cache(
        dir,
        &user_key,
        "seed-id",
        "Seed",
        "octocat",
        &["https://original.example"],
        &[("Existing", "original", 0)],
    );

    let _mock_daemon = MockOldDaemon::start(socket, "seed-id", "Seed", true);

    let output = make_command(dir)
        .args([
            "vault",
            "edit",
            "seed-id",
            "--favorite",
            "true",
            "--field",
            "Extra=value",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "CLI must fail on unsupported v2 edit against stale daemon"
    );
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout_str).unwrap();

    assert_eq!(parsed["ok"], false);
    let err_msg = parsed["error"].as_str().unwrap();
    assert!(
        err_msg.contains(
            "The running daemon does not support custom fields or advanced URI mutations"
        ),
        "Expected daemon upgrade guidance, got: {err_msg}"
    );

    // Verify ZERO requests reached the upstream API server (no partial favorite write)
    assert!(
        api.accept().is_err(),
        "Upstream API must receive zero requests"
    );
}

#[test]
fn test_mixed_version_edit_add_uri_rejected_on_stale_in_process() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let socket = dir.join("omawarden.sock");

    seed_cipher_in_cache(
        dir,
        &user_key,
        "seed-id",
        "Seed",
        "octocat",
        &["https://original.example"],
        &[],
    );

    let _mock_daemon = MockOldDaemon::start(socket, "seed-id", "Seed", true);

    let output = make_command(dir)
        .args([
            "vault",
            "edit",
            "seed-id",
            "--add-uri",
            "https://added.example",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "CLI must fail when adding URI against stale daemon"
    );
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout_str).unwrap();

    assert_eq!(parsed["ok"], false);
    let err_msg = parsed["error"].as_str().unwrap();
    assert!(
        err_msg.contains(
            "The running daemon does not support custom fields or advanced URI mutations"
        ),
        "Expected daemon upgrade guidance, got: {err_msg}"
    );

    assert!(
        api.accept().is_err(),
        "Upstream API must receive zero requests"
    );
}

#[test]
fn test_legacy_plain_login_create_accepted_by_old_daemon() {
    let (temp, api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();
    let socket = dir.join("omawarden.sock");

    let mock_daemon = MockOldDaemon::start(socket, "seed-id", "Seed", false);

    let output = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "Legacy Plain",
            "--username",
            "octocat",
            "--password",
            "supersecret",
            "--uri",
            "https://plain.example",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "CLI must succeed on legacy create");
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout_str).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["outcome"], "saved");

    let actions = mock_daemon.received_actions.lock().unwrap();
    let create_action = actions.iter().find(|a| {
        a.get("action")
            .and_then(Value::as_str)
            .is_some_and(|s| s == "cipher_create")
    });
    assert!(create_action.is_some());
    let req = create_action.unwrap();
    assert_eq!(
        req["action"], "cipher_create",
        "Must use canonical action name cipher_create"
    );
    // Verify nested login.uris is provided so old daemons don't drop the URI
    assert_eq!(req["login"]["uris"][0], "https://plain.example");
    assert!(api.accept().is_err());
}

#[test]
fn test_daemon_deny_unknown_fields_on_create_and_update() {
    let (temp, api, _server_url, user_key) = setup_test_environment();
    let dir = temp.path();
    let socket = dir.join("omawarden.sock");

    seed_cipher_in_cache(
        dir,
        &user_key,
        "seed-id",
        "Seed",
        "octocat",
        &["https://original.example"],
        &[],
    );

    // Launch the REAL daemon compiled with #[serde(deny_unknown_fields)]
    let _daemon = ProcessGuard(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "New daemon did not start in time"
        );
        thread::sleep(Duration::from_millis(10));
    }

    // Unlock daemon
    let unlock_stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut reader = BufReader::new(unlock_stream.try_clone().unwrap());
    let mut writer = unlock_stream;
    writeln!(
        writer,
        "{}",
        json!({"action": "unlock", "password": "fixture"})
    )
    .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let unlock_res: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(unlock_res["ok"], true);

    // Send cipher_create with an unsupported unknown field
    let create_stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut c_reader = BufReader::new(create_stream.try_clone().unwrap());
    let mut c_writer = create_stream;
    let create_req = json!({
        "action": "cipher_create",
        "name": "Denied Item",
        "cipher_type": "login",
        "unknown_exploit_key": "some_value"
    });
    writeln!(c_writer, "{}", create_req).unwrap();
    line.clear();
    c_reader.read_line(&mut line).unwrap();
    let create_res: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        create_res["ok"], false,
        "Daemon must deny unknown fields on create"
    );
    assert!(create_res["error"]
        .as_str()
        .unwrap()
        .contains("Invalid cipher fields"));

    // Send cipher_update with an unsupported unknown field
    let update_stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut u_reader = BufReader::new(update_stream.try_clone().unwrap());
    let mut u_writer = update_stream;
    let update_req = json!({
        "action": "cipher_update",
        "id": "seed-id",
        "unknown_exploit_key": "some_value"
    });
    writeln!(u_writer, "{}", update_req).unwrap();
    line.clear();
    u_reader.read_line(&mut line).unwrap();
    let update_res: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        update_res["ok"], false,
        "Daemon must deny unknown fields on update"
    );
    assert!(update_res["error"]
        .as_str()
        .unwrap()
        .contains("Invalid cipher"));

    // Upstream server must receive ZERO requests
    assert!(
        api.accept().is_err(),
        "Upstream API must receive zero requests"
    );
}

#[test]
fn test_matching_version_create_and_edit_all_fields_saved() {
    let (temp, api, _server_url, _user_key) = setup_test_environment();
    let dir = temp.path();
    let socket = dir.join("omawarden.sock");

    // Launch the REAL new daemon compiled in this workspace
    let _daemon = ProcessGuard(
        make_command(dir)
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "New daemon did not start in time"
        );
        thread::sleep(Duration::from_millis(10));
    }

    // Ping check: new daemon advertises schema_version >= 2
    let ping_stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut reader = BufReader::new(ping_stream.try_clone().unwrap());
    let mut writer = ping_stream;
    writeln!(writer, "{}", json!({"action": "ping"})).unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let ping_res: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ping_res["ok"], true);
    assert_eq!(
        ping_res["schema_version"], 2,
        "New daemon must advertise schema_version: 2"
    );

    // Unlock daemon on a new socket connection
    let unlock_stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    let mut reader = BufReader::new(unlock_stream.try_clone().unwrap());
    let mut writer = unlock_stream;
    writeln!(
        writer,
        "{}",
        json!({"action": "unlock", "password": "fixture"})
    )
    .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let unlock_res: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(unlock_res["ok"], true);

    // Run new CLI: vault create login with custom fields and URI
    let mut cli = make_command(dir)
        .args([
            "vault",
            "create",
            "login",
            "--name",
            "V2 Item",
            "--username",
            "octocat",
            "--password",
            "secretpass",
            "--uri",
            "https://first.example",
            "--field",
            "CustomKey=CustomVal",
            "--json",
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
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };

        let mut req_reader = BufReader::new(&mut stream);
        let mut req_line = String::new();
        req_reader.read_line(&mut req_line).unwrap();
        let mut size = 0;
        loop {
            req_line.clear();
            assert_ne!(req_reader.read_line(&mut req_line).unwrap(), 0);
            if req_line == "\r\n" {
                break;
            }
            if let Some(v) = req_line.to_lowercase().strip_prefix("content-length:") {
                size = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; size];
        req_reader.read_exact(&mut body).unwrap();

        let payload: Value = serde_json::from_slice(&body).unwrap();
        // Assert upstream payload carries encrypted fields and URIs!
        assert!(payload["fields"].as_array().is_some_and(|a| !a.is_empty()));
        assert!(payload["login"]["uris"]
            .as_array()
            .is_some_and(|a| !a.is_empty()));

        // Return mock success receipt
        let resp_body = json!({
            "id": "item-12345",
            "revisionDate": "2026-11-17T00:00:00Z"
        })
        .to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(resp.as_bytes()).unwrap();
        posted = true;
        break;
    }

    assert!(
        posted,
        "Upstream mock server must have received the create request"
    );
    let cli_res = cli.wait_with_output().unwrap();
    assert!(cli_res.status.success());
    let stdout_val: Value = serde_json::from_slice(&cli_res.stdout).unwrap();
    assert_eq!(stdout_val["ok"], true);
    assert_eq!(stdout_val["item"]["id"], "item-12345");
}
