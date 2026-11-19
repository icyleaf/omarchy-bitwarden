//! Integration acceptance tests for daemon lifecycle authorization boundaries (ADR-0028).
//!
//! These tests exercise real separate OS child processes communicating across the
//! Unix domain socket to verify kernel `SO_PEERCRED` peer PID detection and access control:
//! 1. Host-Guarded In-Process Boundary:
//!    External child processes sending `{"action": "stop", "admin": true}` or invoking
//!    the CLI `omawarden daemon stop` against an in-process daemon host are strictly rejected.
//! 2. Standalone Same-UID Explicit-Intent Boundary:
//!    External child processes sending `{"action": "stop"}` without `admin: true` are rejected.
//!    External child processes sending `{"action": "stop", "admin": true}` or invoking
//!    the dedicated CLI `omawarden daemon stop` are accepted and shut down cleanly.
//! 3. Fail-Closed & Non-Destructive Guarantees:
//!    Upon any rejected stop request, the daemon listener, vault session state, and
//!    SSH agent socket remain intact and usable.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use omawarden::daemon::{DaemonServer, DaemonState};
use omawarden::storage::StorageManager;
use serde_json::{json, Value};
use tempfile::tempdir;

fn send_raw_ipc_from_child_process(socket_path: &Path, payload: &Value) -> Value {
    let script = r#"
import socket, sys
sock_path = sys.argv[1]
payload = sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.sendall(payload.encode('utf-8') + b'\n')
data = b''
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
    if b'\n' in data:
        break
print(data.decode('utf-8'))
"#;
    let output = Command::new("python3")
        .args([
            "-c",
            script,
            socket_path.to_str().unwrap(),
            &payload.to_string(),
        ])
        .output()
        .expect("Failed to spawn python3 child process to test IPC socket");

    assert!(
        output.status.success(),
        "Child process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("Failed to parse JSON response: {stdout:?}, error: {e}"))
}

#[test]
fn test_in_process_daemon_rejects_external_child_processes() {
    let runtime_dir = tempdir().unwrap();
    let socket_path = runtime_dir.path().join("omawarden.sock");
    let data_path = runtime_dir.path().join("daemon_data.json");

    let storage_mgr = StorageManager::new(data_path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    // Set vault as unlocked to verify state preservation upon rejection
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    let server = DaemonServer::new(state.clone())
        .with_socket_path(socket_path.clone())
        .in_process(true);
    let handle = server.spawn().expect("Failed to spawn in-process daemon");

    // 1. External child process sending {"action": "stop", "admin": true} MUST be rejected
    let resp =
        send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "stop", "admin": true }));
    assert_eq!(resp["ok"], false);
    assert!(
        resp["error"]
            .as_str()
            .unwrap()
            .contains("cannot terminate in-process daemon"),
        "Unexpected error: {:?}",
        resp["error"]
    );

    // Verify vault session and listener remain intact
    assert!(state.vault_mgr.is_unlocked());
    assert!(!handle.is_shutting_down());

    // Verify daemon listener is still responsive
    let ping_resp = send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "ping" }));
    assert_eq!(ping_resp["ok"], true);
    assert_eq!(ping_resp["unlocked"], true);

    let agent_status =
        send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "ssh_agent_status" }));
    assert!(agent_status.get("socket").is_some());

    // 2. Real CLI child process `omawarden daemon stop` MUST also be rejected
    let cli_output = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["daemon", "stop"])
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .output()
        .expect("Failed to execute omawarden CLI");

    assert!(
        !cli_output.status.success(),
        "CLI stop should fail against in-process daemon"
    );
    let stderr = String::from_utf8_lossy(&cli_output.stderr);
    assert!(
        stderr.contains("cannot terminate in-process daemon"),
        "CLI stderr should indicate in-process denial: {stderr}"
    );

    // Verify listener and session state still intact after CLI attempt
    assert!(state.vault_mgr.is_unlocked());
    assert!(!handle.is_shutting_down());

    // Cleanly shut down from host process
    handle.stop();
    handle.join().unwrap().unwrap();
}

#[test]
fn test_standalone_daemon_requires_admin_from_external_child_process() {
    let runtime_dir = tempdir().unwrap();
    let socket_path = runtime_dir.path().join("omawarden.sock");
    let data_path = runtime_dir.path().join("daemon_data.json");

    let storage_mgr = StorageManager::new(data_path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    // Set vault as unlocked
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    let server = DaemonServer::new(state.clone())
        .with_socket_path(socket_path.clone())
        .in_process(false);
    let handle = server.spawn().expect("Failed to spawn standalone daemon");

    // 1. External child process sending {"action": "stop"} (no admin) MUST be rejected
    let resp = send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "stop" }));
    assert_eq!(resp["ok"], false);
    assert!(
        resp["error"]
            .as_str()
            .unwrap()
            .contains("stopping the daemon requires explicit administrative authorization"),
        "Unexpected error: {:?}",
        resp["error"]
    );

    // Verify session and listener remain intact
    assert!(state.vault_mgr.is_unlocked());
    assert!(!handle.is_shutting_down());

    // Verify listener is still active
    let ping_resp = send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "ping" }));
    assert_eq!(ping_resp["ok"], true);
    assert_eq!(ping_resp["unlocked"], true);

    let agent_status =
        send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "ssh_agent_status" }));
    assert!(agent_status.get("socket").is_some());

    // 2. Dedicated CLI child process `omawarden daemon stop` sends admin: true and stops daemon
    let cli_output = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["daemon", "stop"])
        .env("XDG_RUNTIME_DIR", runtime_dir.path())
        .output()
        .expect("Failed to execute omawarden CLI");

    assert!(
        cli_output.status.success(),
        "CLI stop should succeed with admin authorization: {}",
        String::from_utf8_lossy(&cli_output.stderr)
    );

    // Wait for daemon thread to exit
    handle.join().unwrap().unwrap();

    // Verify socket file was removed
    assert!(!socket_path.exists());
    // Verify vault is locked upon shutdown
    assert!(!state.vault_mgr.is_unlocked());
}

#[test]
fn test_standalone_daemon_accepts_raw_admin_stop_from_external_child() {
    let runtime_dir = tempdir().unwrap();
    let socket_path = runtime_dir.path().join("omawarden.sock");
    let data_path = runtime_dir.path().join("daemon_data.json");

    let storage_mgr = StorageManager::new(data_path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    let server = DaemonServer::new(state.clone())
        .with_socket_path(socket_path.clone())
        .in_process(false);
    let handle = server.spawn().expect("Failed to spawn standalone daemon");

    // External child process sending {"action": "stop", "admin": true} is accepted
    let resp =
        send_raw_ipc_from_child_process(&socket_path, &json!({ "action": "stop", "admin": true }));
    assert_eq!(resp["ok"], true);

    handle.join().unwrap().unwrap();
    assert!(!socket_path.exists());
    assert!(!state.vault_mgr.is_unlocked());
}
