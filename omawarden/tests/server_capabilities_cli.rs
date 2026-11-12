use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn handle_connection(mut stream: TcpStream, fallback_only: bool) {
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

    if !fallback_only && (path == "/api/config" || path.starts_with("/api/config?")) {
        let body = json!({
            "version": "2026.10.1",
            "gitHash": "1234567890abcdef",
            "server": {
                "name": "Bitwarden",
                "url": "https://vault.example.com"
            },
            "environment": {
                "vault": "https://vault.example.com",
                "api": "https://api.example.com",
                "identity": "https://identity.example.com"
            },
            "featureStates": {
                "ssh-agent-v2": true,
                "ssh-key-vault-item": false,
                "ssh-agent": true,
                "new-unsupported-flag": true
            }
        })
        .to_string();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    } else if path == "/api/version" || path.starts_with("/api/version?") {
        let body = "\"2026.9.0\"";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
    } else {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response.as_bytes());
    }
}

#[test]
fn test_server_capabilities_refresh_cache_and_offline() {
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
                Ok((stream, _)) => handle_connection(stream, false),
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

    let run_cli = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .args(args);
        cmd.output().expect("Failed to execute omawarden binary")
    };

    // 1. First run with --refresh and --json
    let output = run_cli(&[
        "--config",
        config_path.to_str().unwrap(),
        "server",
        "capabilities",
        "--refresh",
        "--json",
    ]);

    assert!(
        output.status.success(),
        "Expected success, got stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let json_val: Value = serde_json::from_str(&stdout_str)
        .unwrap_or_else(|e| panic!("Failed to parse json stdout: {}\nRaw: {}", e, stdout_str));

    assert_eq!(json_val["ok"], true);
    assert_eq!(json_val["server_version"], "2026.10.1");
    assert_eq!(json_val["server_name"], "Bitwarden");
    assert_eq!(json_val["git_hash"], "1234567890abcdef");
    assert_eq!(json_val["feature_states"]["ssh-agent-v2"], true);

    // Verify matrix presence and statuses
    let matrix = json_val["matrix"]
        .as_array()
        .expect("matrix should be array");

    let ssh_agent_v2 = matrix
        .iter()
        .find(|item| item["name"] == "ssh-agent-v2")
        .expect("ssh-agent-v2 in matrix");
    assert_eq!(ssh_agent_v2["status"], "supported");
    assert_eq!(ssh_agent_v2["category"], "optional");

    let ssh_key = matrix
        .iter()
        .find(|item| item["name"] == "ssh-key-vault-item")
        .expect("ssh-key-vault-item in matrix");
    assert_eq!(ssh_key["status"], "disabled");

    let ssh_agent_v1 = matrix
        .iter()
        .find(|item| item["name"] == "ssh-agent")
        .expect("ssh-agent in matrix");
    assert_eq!(ssh_agent_v1["status"], "deprecated");

    let unsupported = matrix
        .iter()
        .find(|item| item["name"] == "new-unsupported-flag")
        .expect("new-unsupported-flag in matrix");
    assert_eq!(unsupported["status"], "unsupported");

    // Verify cache file created with 0600 permissions
    let cache_file = dir.join("server_capabilities.json");
    assert!(cache_file.exists(), "Cache file must exist");
    let perms = fs::metadata(&cache_file).unwrap().permissions();
    assert_eq!(perms.mode() & 0o777, 0o600, "Permissions must be 0600");

    // 2. Shut down the server to simulate offline state
    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    // 3. Second run without --refresh should read from cache even if server is offline
    let offline_output = run_cli(&[
        "--config",
        config_path.to_str().unwrap(),
        "server",
        "capabilities",
        "--json",
    ]);

    assert!(
        offline_output.status.success(),
        "Offline cache read should succeed, got stderr: {}",
        String::from_utf8_lossy(&offline_output.stderr)
    );

    let offline_json: Value =
        serde_json::from_str(&String::from_utf8_lossy(&offline_output.stdout)).unwrap();
    assert_eq!(offline_json["ok"], true);
    assert_eq!(offline_json["server_version"], "2026.10.1");

    // 4. Human-readable non-json output check
    let human_output = run_cli(&[
        "--config",
        config_path.to_str().unwrap(),
        "server",
        "capabilities",
    ]);
    assert!(human_output.status.success());
    let human_str = String::from_utf8_lossy(&human_output.stdout);
    assert!(human_str.contains("2026.10.1"));
    assert!(human_str.contains("ssh-agent-v2"));
    assert!(human_str.contains("[OK] supported"));
    assert!(human_str.contains("[--] disabled"));
    assert!(human_str.contains("[!!] deprecated"));
}

#[test]
fn test_server_capabilities_fallback_to_version_endpoint() {
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
                Ok((stream, _)) => handle_connection(stream, true), // fallback_only: true simulates /api/config 404
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

    let output = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "server",
            "capabilities",
            "--refresh",
            "--json",
        ])
        .output()
        .expect("Failed to execute omawarden binary");

    assert!(output.status.success());
    let json_val: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(json_val["ok"], true);
    assert_eq!(json_val["server_version"], "2026.9.0");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();
}

#[test]
fn test_server_capabilities_offline_without_cache_returns_error_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "server_url": "http://127.0.0.1:1" // unreachable port
        })
        .to_string(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "server",
            "capabilities",
            "--json",
        ])
        .output()
        .expect("Failed to execute omawarden binary");

    assert!(!output.status.success(), "Expected exit 1 on error");
    let json_val: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(json_val["ok"], false);
    assert!(json_val["error"].as_str().is_some());
}

#[test]
fn test_server_capabilities_daemon_ipc() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let _server_handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, false),
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

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
    cmd.env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .args(["--config", config_path.to_str().unwrap(), "daemon"]);
    let mut daemon_proc = cmd.spawn().expect("failed to spawn daemon");

    let socket_path = dir.join("omawarden.sock");
    let mut connected = false;
    for _ in 0..50 {
        if socket_path.exists() {
            connected = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(connected, "Daemon socket must be created");

    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path).unwrap();
    writeln!(
        stream,
        "{}",
        json!({ "action": "server_capabilities", "refresh": true })
    )
    .unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let res: Value = serde_json::from_str(&line).unwrap();

    assert_eq!(res["ok"], true);
    assert_eq!(res["server_version"], "2026.10.1");
    assert_eq!(res["feature_states"]["ssh-agent-v2"], true);

    let _ = daemon_proc.kill();
    let _ = daemon_proc.wait();
    running.store(false, Ordering::Relaxed);
}

/// Serves a caller-provided `/api/config` payload (and a `/api/version` fallback).
fn spawn_mock_server(config_body: Value) -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => handle_custom_connection(stream, &config_body),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (format!("http://{}", addr), running, handle)
}

fn handle_custom_connection(mut stream: TcpStream, config_body: &Value) {
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

    let body = if path == "/api/config" || path.starts_with("/api/config?") {
        config_body.to_string()
    } else if path == "/api/version" || path.starts_with("/api/version?") {
        "\"2026.9.0\"".to_string()
    } else {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(response.as_bytes());
        return;
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn run_capabilities(
    dir: &std::path::Path,
    config_path: &std::path::Path,
    extra: &[&str],
) -> (Value, std::process::Output) {
    let mut args = vec![
        "--config",
        config_path.to_str().unwrap(),
        "server",
        "capabilities",
    ];
    args.extend_from_slice(extra);

    let output = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .args(args)
        .output()
        .expect("Failed to execute omawarden binary");

    let json_val: Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap_or(Value::Null);
    (json_val, output)
}

fn write_config(dir: &std::path::Path, server_url: &str) -> std::path::PathBuf {
    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({ "server_url": server_url }).to_string(),
    )
    .unwrap();
    config_path
}

#[test]
fn test_server_capabilities_vaultwarden_1374_native_ssh_key() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let (server_url, running, handle) = spawn_mock_server(json!({
        "version": "2026.6.0",
        "gitHash": "vw123456",
        "server": { "name": "Vaultwarden", "version": "1.37.4" },
        "featureStates": {}
    }));
    let config_path = write_config(dir, &server_url);

    let (json_val, output) = run_capabilities(dir, &config_path, &["--refresh", "--json"]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(json_val["ok"], true);
    assert_eq!(json_val["server_name"], "Vaultwarden");
    assert_eq!(json_val["server_vendor_version"], "1.37.4");
    assert_eq!(json_val["server_version"], "2026.6.0");

    let matrix = json_val["matrix"].as_array().unwrap();
    let ssh_key = matrix
        .iter()
        .find(|m| m["name"] == "ssh-key-vault-item")
        .unwrap();
    assert_eq!(
        ssh_key["status"], "supported",
        "Vaultwarden 1.37.4 must support ssh-key-vault-item natively"
    );

    // Cached capabilities persist the identity metadata.
    let cache: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("server_capabilities.json")).unwrap())
            .unwrap();
    assert_eq!(cache["server_name"], "Vaultwarden");
    assert_eq!(cache["server_vendor_version"], "1.37.4");

    // Human-readable output shows identity and vendor version.
    let (_, human) = run_capabilities(dir, &config_path, &[]);
    let human_str = String::from_utf8_lossy(&human.stdout);
    assert!(
        human_str.contains("Vaultwarden"),
        "missing name: {human_str}"
    );
    assert!(human_str.contains("1.37.4"), "missing vendor: {human_str}");

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_server_capabilities_vaultwarden_1352_feature_flag_transition() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    // 1. Flag absent on 1.35.2 => disabled
    let (server_url, running, handle) = spawn_mock_server(json!({
        "version": "2026.6.0",
        "server": { "name": "Vaultwarden", "version": "1.35.2" },
        "featureStates": {}
    }));
    let config_path = write_config(dir, &server_url);

    let (json_val, _) = run_capabilities(dir, &config_path, &["--refresh", "--json"]);
    assert_eq!(json_val["server_name"], "Vaultwarden");
    assert_eq!(json_val["server_vendor_version"], "1.35.2");
    let ssh_key = json_val["matrix"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "ssh-key-vault-item")
        .unwrap()
        .clone();
    assert_eq!(ssh_key["status"], "disabled");

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();

    // 2. Explicit flag enabled on 1.35.2 => supported
    let (server_url2, running2, handle2) = spawn_mock_server(json!({
        "version": "2026.6.0",
        "server": { "name": "Vaultwarden", "version": "1.35.2" },
        "featureStates": { "ssh-key-vault-item": true }
    }));
    let config_path2 = write_config(dir, &server_url2);

    let (json_val2, _) = run_capabilities(dir, &config_path2, &["--refresh", "--json"]);
    let ssh_key2 = json_val2["matrix"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "ssh-key-vault-item")
        .unwrap()
        .clone();
    assert_eq!(ssh_key2["status"], "supported");

    running2.store(false, Ordering::Relaxed);
    let _ = handle2.join();
}

#[test]
fn test_server_capabilities_vaultwarden_legacy_unsupported() {
    for vendor in ["1.30.0", "1.26.0"] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();

        let (server_url, running, handle) = spawn_mock_server(json!({
            "version": "2026.6.0",
            "server": { "name": "Vaultwarden", "version": vendor },
            "featureStates": {}
        }));
        let config_path = write_config(dir, &server_url);

        let (json_val, _) = run_capabilities(dir, &config_path, &["--refresh", "--json"]);
        let ssh_key = json_val["matrix"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == "ssh-key-vault-item")
            .unwrap()
            .clone();
        assert_eq!(
            ssh_key["status"], "unsupported",
            "Vaultwarden {vendor} must be unsupported for ssh-key-vault-item"
        );

        running.store(false, Ordering::Relaxed);
        let _ = handle.join();
    }
}

#[test]
fn test_server_capabilities_official_bitwarden_defaults_and_override() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    // 1. Self-hosted official Bitwarden, flag absent => supported
    let (server_url, running, handle) = spawn_mock_server(json!({
        "version": "2026.5.0",
        "server": { "name": "Bitwarden", "version": "2026.5.0" },
        "featureStates": {}
    }));
    let config_path = write_config(dir, &server_url);

    let (json_val, _) = run_capabilities(dir, &config_path, &["--refresh", "--json"]);
    assert_eq!(json_val["server_name"], "Bitwarden");
    let ssh_key = json_val["matrix"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "ssh-key-vault-item")
        .unwrap()
        .clone();
    assert_eq!(ssh_key["status"], "supported");

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();

    // 2. Explicit false is always honored
    let (server_url2, running2, handle2) = spawn_mock_server(json!({
        "version": "2026.5.0",
        "server": { "name": "Bitwarden", "version": "2026.5.0" },
        "featureStates": { "ssh-key-vault-item": false }
    }));
    let config_path2 = write_config(dir, &server_url2);

    let (json_val2, _) = run_capabilities(dir, &config_path2, &["--refresh", "--json"]);
    let ssh_key2 = json_val2["matrix"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "ssh-key-vault-item")
        .unwrap()
        .clone();
    assert_eq!(ssh_key2["status"], "disabled");

    running2.store(false, Ordering::Relaxed);
    let _ = handle2.join();
}

#[test]
fn test_offline_cache_without_server_metadata_is_readable() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    // Simulate a cache written by an older Omawarden build (no server_name/vendor_version).
    let legacy = json!({
        "server_url": "http://127.0.0.1:1",
        "server_version": "2026.1.0",
        "git_hash": "legacy",
        "cached_at": "2026-11-10T12:00:00Z",
        "feature_states": { "ssh-key-vault-item": true },
        "matrix": [
            { "name": "ssh-key-vault-item", "category": "optional", "status": "supported", "description": "x" }
        ]
    });
    fs::write(
        dir.join("server_capabilities.json"),
        serde_json::to_string_pretty(&legacy).unwrap(),
    )
    .unwrap();

    let config_path = write_config(dir, "http://127.0.0.1:1");
    let (json_val, output) = run_capabilities(dir, &config_path, &["--json"]);

    assert!(output.status.success());
    assert_eq!(json_val["ok"], true);
    assert_eq!(json_val["server_version"], "2026.1.0");
    assert_eq!(json_val["server_name"], Value::Null);
}
