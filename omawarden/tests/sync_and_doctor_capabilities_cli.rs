use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn write_test_executable(path: &std::path::Path, content: impl AsRef<[u8]>) {
    let mut child = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content.as_ref())
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());
}

fn handle_connection(mut stream: TcpStream, config_status: u16, ssh_agent_v2_enabled: bool) {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let path = parts[1];

    if path == "/api/config" || path.starts_with("/api/config?") {
        if config_status == 200 {
            let body = json!({
                "version": "2026.10.1",
                "gitHash": "1234567890abcdef",
                "featureStates": {
                    "ssh-agent-v2": ssh_agent_v2_enabled,
                    "ssh-key-vault-item": true
                }
            })
            .to_string();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        } else {
            let response = format!(
                "HTTP/1.1 {} Internal Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                config_status
            );
            let _ = stream.write_all(response.as_bytes());
        }
    } else if path == "/accounts/prelogin"
        || path.starts_with("/accounts/prelogin?")
        || path == "/api/accounts/prelogin"
    {
        let body = json!({
            "kdf": 0,
            "kdfIterations": 100000
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    } else if path == "/api/sync" || path.starts_with("/api/sync?") {
        let body = json!({
            "profile": { "id": "user-id", "email": "user@example.com" },
            "ciphers": [],
            "folders": [],
            "collections": []
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    } else {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(response.as_bytes());
    }
}

#[test]
fn test_doctor_command_with_enabled_ssh_agent_v2() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let server_handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, 200, true),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let server_url = format!("http://{}", addr);

    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "server_url": server_url
        })
        .to_string(),
    )
    .unwrap();

    let fake_secret_tool = dir.join("secret-tool");
    write_test_executable(&fake_secret_tool, "#!/bin/sh\nexit 0\n");

    // 1. Test omawarden doctor --json
    let json_out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "doctor",
            "--json",
        ])
        .output()
        .expect("Failed to execute omawarden doctor --json");

    assert!(
        json_out.status.success(),
        "doctor --json failed: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let json_str = String::from_utf8_lossy(&json_out.stdout);
    let json_val: Value = serde_json::from_str(&json_str).expect("Valid JSON");

    assert_eq!(json_val["installed"], true);
    assert_eq!(json_val["ok"], true);
    assert_eq!(json_val["server_reachable"], true);

    let caps = &json_val["upstream_capabilities"];
    assert!(
        caps.is_object(),
        "upstream_capabilities must be present in doctor json"
    );
    assert_eq!(caps["server_version"], "2026.10.1");
    assert_eq!(caps["ssh_agent_v2_status"], "supported");

    // 2. Test human-readable omawarden doctor
    let human_out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "doctor"])
        .output()
        .expect("Failed to execute omawarden doctor");

    assert!(human_out.status.success());
    let human_str = String::from_utf8_lossy(&human_out.stdout);
    assert!(
        human_str.contains("Upstream Capabilities:"),
        "Missing section in: {}",
        human_str
    );
    assert!(
        human_str.contains("[OK] Upstream ssh-agent-v2 enabled"),
        "Missing flag in: {}",
        human_str
    );

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();
}

#[test]
fn test_doctor_command_with_disabled_ssh_agent_v2_outputs_info_and_guidance() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let server_handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, 200, false), // ssh_agent_v2 is disabled!
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let server_url = format!("http://{}", addr);

    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "server_url": server_url
        })
        .to_string(),
    )
    .unwrap();

    let fake_secret_tool = dir.join("secret-tool");
    write_test_executable(&fake_secret_tool, "#!/bin/sh\nexit 0\n");

    let human_out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "doctor"])
        .output()
        .expect("Failed to execute omawarden doctor");

    assert!(human_out.status.success());
    let human_str = String::from_utf8_lossy(&human_out.stdout);
    assert!(
        human_str.contains("[INFO] Upstream ssh-agent-v2 is not enabled"),
        "Expected [INFO] in: {}",
        human_str
    );
    assert!(
        human_str.contains(
            "EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent,ssh-agent-v2"
        ),
        "Expected Vaultwarden configuration guidance in: {}",
        human_str
    );

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();
}

#[test]
fn test_sync_updates_capabilities_and_is_resilient_to_config_500() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    // /api/config returns 500! Sync MUST succeed regardless.
    let server_handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, 500, true),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let server_url = format!("http://{}", addr);

    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "server_url": server_url
        })
        .to_string(),
    )
    .unwrap();

    let fake_secret_tool = dir.join("secret-tool");
    write_test_executable(
        &fake_secret_tool,
        "#!/bin/sh\ncase \"$*\" in\n*access_token*) echo 'fixture-jwt.eyJleHAiOjE5OTk5OTk5OTksInN1YiI6InVzZXItaWQifQ.sig';;\n*) exit 0;;\nesac\n",
    );

    let email = "user@example.com";
    let master = derive_master_key(
        email,
        "masterpw",
        KdfType::Pbkdf2Sha256,
        100_000,
        None,
        None,
    )
    .unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let cache_file = dir.join("data.json");
    let cache_data = json!({
        "user_id": "user-id",
        "user_email": email,
        "server_url": server_url,
        "credential_id": "11111111111111111111111111111111",
        "enc_user_key": wrap,
        "kdf": 0,
        "kdf_iterations": 100_000
    });
    fs::write(&cache_file, cache_data.to_string()).unwrap();

    // Start daemon
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
    cmd.env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "daemon"]);
    let daemon_proc = cmd.spawn().expect("failed to spawn daemon");
    let _guard = ChildGuard(daemon_proc);

    let socket_path = dir.join("omawarden.sock");
    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    // Unlock daemon before sync via IPC
    let mut stream = UnixStream::connect(&socket_path).expect("connect to socket");
    let unlock_req = json!({"action": "unlock", "password": "masterpw"}).to_string();
    stream.write_all(unlock_req.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut unlock_resp_line = String::new();
    let mut stream_reader = BufReader::new(stream);
    stream_reader.read_line(&mut unlock_resp_line).unwrap();
    let unlock_resp: Value = serde_json::from_str(&unlock_resp_line).expect("parse unlock resp");
    assert_eq!(
        unlock_resp["ok"], true,
        "Daemon unlock failed: {unlock_resp}"
    );

    // Run omawarden vault sync
    let sync_out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "vault", "sync"])
        .output()
        .expect("Failed to sync");

    // Sync MUST succeed even though /api/config returned 500!
    assert!(
        sync_out.status.success(),
        "Sync must succeed despite /api/config error: {}",
        String::from_utf8_lossy(&sync_out.stderr)
    );

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();
}

#[test]
fn test_sync_updates_capabilities_on_http_200() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let server_handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, 200, true),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let server_url = format!("http://{}", addr);

    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "server_url": server_url
        })
        .to_string(),
    )
    .unwrap();

    let fake_secret_tool = dir.join("secret-tool");
    write_test_executable(
        &fake_secret_tool,
        "#!/bin/sh\ncase \"$*\" in\n*access_token*) echo 'fixture-jwt.eyJleHAiOjE5OTk5OTk5OTksInN1YiI6InVzZXItaWQifQ.sig';;\n*) exit 0;;\nesac\n",
    );

    let email = "user@example.com";
    let master = derive_master_key(
        email,
        "masterpw",
        KdfType::Pbkdf2Sha256,
        100_000,
        None,
        None,
    )
    .unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let cache_file = dir.join("data.json");
    let cache_data = json!({
        "user_id": "user-id",
        "user_email": email,
        "server_url": server_url,
        "credential_id": "11111111111111111111111111111111",
        "enc_user_key": wrap,
        "kdf": 0,
        "kdf_iterations": 100_000
    });
    fs::write(&cache_file, cache_data.to_string()).unwrap();

    // Start daemon
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
    cmd.env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "daemon"]);
    let daemon_proc = cmd.spawn().expect("failed to spawn daemon");
    let _guard = ChildGuard(daemon_proc);

    let socket_path = dir.join("omawarden.sock");
    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    // Unlock daemon before sync via IPC
    let mut stream = UnixStream::connect(&socket_path).expect("connect to socket");
    let unlock_req = json!({"action": "unlock", "password": "masterpw"}).to_string();
    stream.write_all(unlock_req.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut unlock_resp_line = String::new();
    let mut stream_reader = BufReader::new(stream);
    stream_reader.read_line(&mut unlock_resp_line).unwrap();
    let unlock_resp: Value = serde_json::from_str(&unlock_resp_line).expect("parse unlock resp");
    assert_eq!(
        unlock_resp["ok"], true,
        "Daemon unlock failed: {unlock_resp}"
    );

    // Run omawarden vault sync
    let sync_out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "vault", "sync"])
        .output()
        .expect("Failed to sync");

    assert!(
        sync_out.status.success(),
        "Sync failed: {}",
        String::from_utf8_lossy(&sync_out.stderr)
    );

    // Capabilities discovery runs in a detached background thread spawned on successful sync.
    // Poll for the capabilities cache file.
    let caps_file = dir.join("server_capabilities.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut found = false;
    while Instant::now() < deadline {
        if caps_file.exists() {
            found = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(found, "server_capabilities.json was not created after sync");

    let caps_content = fs::read_to_string(&caps_file).unwrap();
    let caps_json: Value = serde_json::from_str(&caps_content).unwrap();
    assert_eq!(caps_json["server_version"], "2026.10.1");
    assert_eq!(caps_json["git_hash"], "1234567890abcdef");

    let matrix = caps_json["matrix"].as_array().expect("matrix array");
    let ssh_agent_v2 = matrix
        .iter()
        .find(|m| m["name"] == "ssh-agent-v2")
        .expect("ssh-agent-v2 feature in matrix");
    assert_eq!(ssh_agent_v2["status"], "supported");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();
}
