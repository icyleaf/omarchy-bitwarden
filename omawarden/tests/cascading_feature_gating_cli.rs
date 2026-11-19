use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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

fn seed_disabled_ssh_key_capabilities(dir: &std::path::Path, server_url: &str) {
    let caps = json!({
        "server_url": server_url,
        "server_version": "2026.10.1",
        "git_hash": "abcdef123456",
        "cached_at": "2026-11-10T12:00:00Z",
        "feature_states": {
            "ssh-agent-v2": true,
            "ssh-key-vault-item": false
        },
        "matrix": [
            {
                "name": "ssh-key-vault-item",
                "category": "optional",
                "status": "disabled",
                "description": "SSH Key vault storage (Cipher Type 5)"
            },
            {
                "name": "ssh-agent-v2",
                "category": "optional",
                "status": "supported",
                "description": "Modern SSH Agent signature negotiation protocol (v2)"
            }
        ]
    });

    let caps_file = dir.join("server_capabilities.json");
    fs::write(&caps_file, serde_json::to_string_pretty(&caps).unwrap()).unwrap();
}

#[test]
fn test_ssh_key_create_gating_and_override() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let server_url = "http://127.0.0.1:45099";
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

    seed_disabled_ssh_key_capabilities(dir, server_url);

    // 1. Without override flag, create MUST abort with actionable error
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-key",
            "create",
            "--name",
            "Test Key",
        ])
        .output()
        .expect("failed to run ssh-key create");

    assert!(!out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout_str).expect("JSON error envelope");
    assert_eq!(val["ok"], false);
    let err_msg = val["error"].as_str().unwrap();
    assert!(
        err_msg.contains("Upstream server does not support 'ssh-key-vault-item'"),
        "Unexpected error: {}",
        err_msg
    );
    assert!(
        err_msg.contains("EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item"),
        "Missing guidance: {}",
        err_msg
    );

    // 2. With --ignore-server-capabilities, the gating check is bypassed
    let out_bypass = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-key",
            "create",
            "--name",
            "Test Key",
            "--ignore-server-capabilities",
        ])
        .output()
        .expect("failed to run ssh-key create with bypass");

    let bypass_str = String::from_utf8_lossy(&out_bypass.stdout);
    assert!(!bypass_str.contains("Upstream server does not support 'ssh-key-vault-item'"));

    // 3. With --force alias, the gating check is also bypassed
    let out_force = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-key",
            "create",
            "--name",
            "Test Key",
            "--force",
        ])
        .output()
        .expect("failed to run ssh-key create with --force");

    let force_str = String::from_utf8_lossy(&out_force.stdout);
    assert!(!force_str.contains("Upstream server does not support 'ssh-key-vault-item'"));
}

#[test]
fn test_ssh_key_import_gating_and_override() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let server_url = "http://127.0.0.1:45098";
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

    seed_disabled_ssh_key_capabilities(dir, server_url);

    // 1. Without override flag, import MUST abort with actionable error
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-key",
            "import",
            "--name",
            "Import Key",
        ])
        .output()
        .expect("failed to run ssh-key import");

    assert!(!out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout_str).expect("JSON error envelope");
    assert_eq!(val["ok"], false);
    let err_msg = val["error"].as_str().unwrap();
    assert!(
        err_msg.contains("Upstream server does not support 'ssh-key-vault-item'"),
        "Unexpected error: {}",
        err_msg
    );
    assert!(
        err_msg.contains("EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item"),
        "Missing guidance: {}",
        err_msg
    );

    // 2. With --ignore-server-capabilities, the gating check is bypassed
    let out_bypass = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-key",
            "import",
            "--name",
            "Import Key",
            "--ignore-server-capabilities",
        ])
        .output()
        .expect("failed to run ssh-key import with bypass");

    let bypass_str = String::from_utf8_lossy(&out_bypass.stdout);
    assert!(!bypass_str.contains("Upstream server does not support 'ssh-key-vault-item'"));

    // 3. With --force, the gating check is bypassed
    let out_force = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-key",
            "import",
            "--name",
            "Import Key",
            "--force",
        ])
        .output()
        .expect("failed to run ssh-key import with --force");

    let force_str = String::from_utf8_lossy(&out_force.stdout);
    assert!(!force_str.contains("Upstream server does not support 'ssh-key-vault-item'"));
}

#[test]
fn test_ssh_agent_command_gating_and_override() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let server_url = "http://127.0.0.1:45097";
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

    seed_disabled_ssh_key_capabilities(dir, server_url);

    // 1. `omawarden ssh-agent` without bypass MUST abort
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(["--config", config_path.to_str().unwrap(), "ssh-agent"])
        .output()
        .expect("failed to run ssh-agent");

    assert!(!out.status.success());
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout_str).expect("JSON error envelope");
    assert_eq!(val["ok"], false);
    let err_msg = val["error"].as_str().unwrap();
    assert!(
        err_msg.contains("Refusing to launch SSH agent"),
        "Unexpected error: {}",
        err_msg
    );
    assert!(
        err_msg.contains("Upstream server does not support 'ssh-key-vault-item'"),
        "Unexpected error: {}",
        err_msg
    );

    // 2. `omawarden ssh-agent start` without bypass MUST also abort
    let out_start = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-agent",
            "start",
        ])
        .output()
        .expect("failed to run ssh-agent start");

    assert!(!out_start.status.success());
    let start_stdout = String::from_utf8_lossy(&out_start.stdout);
    let val_start: Value = serde_json::from_str(&start_stdout).expect("JSON error envelope");
    assert_eq!(val_start["ok"], false);
    assert!(val_start["error"]
        .as_str()
        .unwrap()
        .contains("Refusing to launch SSH agent"));

    // 3. `omawarden ssh-agent --ignore-server-capabilities` bypasses check
    let out_bypass = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-agent",
            "--ignore-server-capabilities",
        ])
        .output()
        .expect("failed to run ssh-agent --ignore-server-capabilities");

    let bypass_str = String::from_utf8_lossy(&out_bypass.stdout);
    assert!(!bypass_str.contains("Upstream server does not support 'ssh-key-vault-item'"));

    // 4. `omawarden ssh-agent --force` bypasses check
    let out_force = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-agent",
            "--force",
        ])
        .output()
        .expect("failed to run ssh-agent --force");

    let force_str = String::from_utf8_lossy(&out_force.stdout);
    assert!(!force_str.contains("Upstream server does not support 'ssh-key-vault-item'"));

    // 5. `omawarden ssh-agent start --ignore-server-capabilities` and `start --force` bypass check
    let out_start_bypass = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-agent",
            "start",
            "--ignore-server-capabilities",
        ])
        .output()
        .expect("failed to run ssh-agent start --ignore-server-capabilities");

    let start_bypass_str = String::from_utf8_lossy(&out_start_bypass.stdout);
    assert!(!start_bypass_str.contains("Upstream server does not support 'ssh-key-vault-item'"));

    let out_start_force = Command::new(env!("CARGO_BIN_EXE_omawarden"))
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
            "ssh-agent",
            "start",
            "--force",
        ])
        .output()
        .expect("failed to run ssh-agent start --force");

    let start_force_str = String::from_utf8_lossy(&out_start_force.stdout);
    assert!(!start_force_str.contains("Upstream server does not support 'ssh-key-vault-item'"));
}

#[test]
fn test_daemon_ssh_agent_apply_ipc_gating() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let server_url = "http://127.0.0.1:45096";
    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({
            "server_url": server_url,
            "ssh_agent_enabled": true
        })
        .to_string(),
    )
    .unwrap();

    let fake_secret_tool = dir.join("secret-tool");
    write_test_executable(&fake_secret_tool, "#!/bin/sh\nexit 0\n");

    seed_disabled_ssh_key_capabilities(dir, server_url);

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

    // 1. Send ssh_agent_apply without bypass - must fail
    let mut stream = UnixStream::connect(&socket_path).expect("connect to socket");
    let apply_req = json!({ "action": "ssh_agent_apply" }).to_string();
    stream.write_all(apply_req.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply_line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut reply_line).unwrap();
    let reply: Value = serde_json::from_str(&reply_line).unwrap();

    assert_eq!(reply["ok"], false, "Expected error but got: {reply}");
    let err_msg = reply["error"].as_str().unwrap();
    assert!(
        err_msg.contains("Refusing to launch SSH agent"),
        "Unexpected error in daemon IPC: {}",
        err_msg
    );

    // 2. Send ssh_agent_apply with ignore_server_capabilities: true - must succeed
    let mut stream2 = UnixStream::connect(&socket_path).expect("connect to socket");
    let apply_bypass_req =
        json!({ "action": "ssh_agent_apply", "ignore_server_capabilities": true }).to_string();
    stream2.write_all(apply_bypass_req.as_bytes()).unwrap();
    stream2.write_all(b"\n").unwrap();
    let mut reply_line2 = String::new();
    let mut reader2 = BufReader::new(stream2);
    reader2.read_line(&mut reply_line2).unwrap();
    let reply2: Value = serde_json::from_str(&reply_line2).unwrap();

    assert_eq!(reply2["ok"], true);
    assert_eq!(reply2["running"], true);
}

// ---------------------------------------------------------------------------
// Version-aware gating end-to-end tests (Vaultwarden 1.37.4 / 1.35.x / 1.30.0)
// ---------------------------------------------------------------------------

fn handle_capability_connection(mut stream: TcpStream, config_body: &Value, version_body: &str) {
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
        version_body.to_string()
    } else {
        "{}".to_string()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn spawn_capability_server(
    config_body: Value,
    version_body: &str,
) -> (String, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();

    let version_response = version_body.to_string();
    let handle = thread::spawn(move || {
        while r_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    handle_capability_connection(stream, &config_body, &version_response)
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (format!("http://{}", addr), running, handle)
}

fn setup_gating_env(dir: &std::path::Path, server_url: &str) -> std::path::PathBuf {
    let config_path = dir.join("config.json");
    fs::write(
        &config_path,
        json!({ "server_url": server_url }).to_string(),
    )
    .unwrap();

    let fake_secret_tool = dir.join("secret-tool");
    write_test_executable(&fake_secret_tool, "#!/bin/sh\nexit 0\n");

    config_path
}

fn run_cli(
    dir: &std::path::Path,
    config_path: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    let mut full_args = vec!["--config", config_path.to_str().unwrap()];
    full_args.extend_from_slice(args);

    Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .args(full_args)
        .output()
        .expect("failed to run omawarden")
}

const GATING_SENTINEL: &str = "Upstream server does not support 'ssh-key-vault-item'";

#[test]
fn test_gating_vaultwarden_1374_passes_without_flags() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let (server_url, running, handle) = spawn_capability_server(
        json!({
            "version": "2026.6.0",
            "gitHash": "vw123456",
            "server": { "name": "Vaultwarden" },
            "featureStates": {}
        }),
        "\"1.37.4\"",
    );
    let config_path = setup_gating_env(dir, &server_url);

    // ssh-key create / import and ssh-agent must all pass capability gating.
    for args in [
        vec!["ssh-key", "create", "--name", "Native Key"],
        vec!["ssh-key", "import", "--name", "Native Import"],
        vec!["ssh-agent"],
    ] {
        let out = run_cli(dir, &config_path, &args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains(GATING_SENTINEL),
            "Vaultwarden 1.37.4 must not be gated for {:?}, got: {stdout}",
            args
        );
    }

    // Non-vacuous proof that discovery evaluated the native tier rather than failing open.
    let cache: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("server_capabilities.json")).unwrap())
            .unwrap();
    assert_eq!(cache["server_name"], "Vaultwarden");
    assert_eq!(cache["server_vendor_version"], "1.37.4");
    assert!(
        cache["matrix"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "ssh-key-vault-item" && m["status"] == "supported"),
        "cache must record ssh-key-vault-item as supported: {cache}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_gating_vaultwarden_1352_recommends_flags() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let (server_url, running, handle) = spawn_capability_server(
        json!({
            "version": "2026.6.0",
            "server": { "name": "Vaultwarden" },
            "featureStates": {}
        }),
        "\"1.35.2\"",
    );
    let config_path = setup_gating_env(dir, &server_url);

    let out = run_cli(
        dir,
        &config_path,
        &["ssh-key", "create", "--name", "Flagged Key"],
    );
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout).expect("JSON error envelope");
    assert_eq!(val["ok"], false);
    let err = val["error"].as_str().unwrap();
    assert!(err.contains(GATING_SENTINEL), "unexpected error: {err}");
    assert!(
        err.contains("EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item"),
        "expected flag guidance: {err}"
    );
    assert!(
        !err.contains("predates native SSH Key Cipher support"),
        "must not advise upgrading an in-support release: {err}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_gating_vaultwarden_1300_recommends_upgrade() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let (server_url, running, handle) = spawn_capability_server(
        json!({
            "version": "2026.6.0",
            "server": { "name": "Vaultwarden" },
            "featureStates": {}
        }),
        "\"1.30.0\"",
    );
    let config_path = setup_gating_env(dir, &server_url);

    let out = run_cli(
        dir,
        &config_path,
        &["ssh-key", "import", "--name", "Legacy Import"],
    );
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout).expect("JSON error envelope");
    assert_eq!(val["ok"], false);
    let err = val["error"].as_str().unwrap();
    assert!(err.contains(GATING_SENTINEL), "unexpected error: {err}");
    assert!(
        err.contains("predates native SSH Key Cipher support"),
        "expected upgrade guidance: {err}"
    );
    assert!(
        err.contains(">= 1.33.0"),
        "expected minimum upgrade target: {err}"
    );
    assert!(
        !err.contains("EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item"),
        "must not recommend flags that do not exist on legacy releases: {err}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}

#[test]
fn test_gating_vaultwarden_1374_ssh_agent_passes() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();

    let (server_url, running, handle) = spawn_capability_server(
        json!({
            "version": "2026.6.0",
            "server": { "name": "Vaultwarden" },
            "featureStates": { "ssh-agent-v2": false }
        }),
        "\"1.37.4\"",
    );
    let config_path = setup_gating_env(dir, &server_url);

    let out = run_cli(dir, &config_path, &["ssh-agent", "start"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(GATING_SENTINEL),
        "ssh-agent start must not be gated on 1.37.4: {stdout}"
    );

    running.store(false, Ordering::Relaxed);
    let _ = handle.join();
}
