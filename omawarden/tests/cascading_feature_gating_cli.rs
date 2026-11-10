use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
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
