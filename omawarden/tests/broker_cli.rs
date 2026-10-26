//! Integration tests for `omawarden broker` CLI commands.

use std::process::Command;

#[test]
fn test_broker_cli_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("exec"));
}

#[test]
fn test_broker_exec_child_exit_code_propagation() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "exec", "--", "sh", "-c", "exit 17"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(17));
}

#[test]
fn test_broker_exec_simple_command_execution() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "exec", "--", "sh", "-c", "echo HelloVaultBroker"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().contains("HelloVaultBroker"));
}

#[test]
fn test_broker_exec_no_network_local_command_succeeds() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "broker",
            "exec",
            "--no-network",
            "--",
            "echo",
            "NoNetworkLocalOk",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("NoNetworkLocalOk"));
}

#[test]
fn test_broker_exec_no_network_blocks_socket_connections() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "broker",
            "exec",
            "--no-network",
            "--",
            "python3",
            "-c",
            "import socket; socket.create_connection(('1.1.1.1', 80), timeout=1)",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn test_broker_exec_no_redact_flag_allowed() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "broker",
            "exec",
            "--no-redact",
            "--",
            "sh",
            "-c",
            "echo UnredactedOutput",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("UnredactedOutput"));
}

#[test]
fn test_broker_exec_signal_exit_code_propagation() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "exec", "--", "sh", "-c", "kill -9 $$"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(128 + 9));
}

#[test]
fn test_broker_allow_cli_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "allow", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cipher-ref") || stdout.contains("CIPHER_REF"));
}

#[test]
fn test_broker_pending_cli_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "pending", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn test_broker_reply_cli_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "reply", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--allow") || stdout.contains("--always"));
}

#[test]
fn test_broker_allow_json_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "allow", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--json"));
}

#[test]
fn test_broker_reply_json_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "reply", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--json"));
}

#[test]
fn test_broker_exec_malformed_omawarden_toml_fails_closed() {
    let temp_dir = tempfile::tempdir().unwrap();
    let toml_path = temp_dir.path().join(".omawarden.toml");
    std::fs::write(&toml_path, "invalid_toml = [unclosed").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .current_dir(temp_dir.path())
        .args(["broker", "exec", "--", "echo", "test"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Failed to parse manifest TOML"));
}

#[test]
fn test_broker_exec_omawarden_toml_ancestor_discovery() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("my_proj");
    let deep_nested = root.join("src").join("nested").join("sub");
    std::fs::create_dir_all(&deep_nested).unwrap();

    // Place malformed .omawarden.toml at the root directory
    let toml_path = root.join(".omawarden.toml");
    std::fs::write(&toml_path, "invalid = [bad").unwrap();

    // Execute from the deeply nested subdirectory: should traverse up and fail on invalid TOML
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .current_dir(&deep_nested)
        .args(["broker", "exec", "--", "echo", "test"])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Failed to parse manifest TOML"));
}

#[test]
fn test_broker_exec_cli_env_composites_with_omawarden_toml() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().join("my_proj_with_cli");
    let deep_nested = root.join("services").join("worker");
    std::fs::create_dir_all(&deep_nested).unwrap();

    // Valid .omawarden.toml at root referencing a non-existent item to test daemon pass-through
    let toml_path = root.join(".omawarden.toml");
    std::fs::write(
        &toml_path,
        r#"
items = ["NonExistentTestItemA"]
"#,
    )
    .unwrap();

    // Execute with an extra CLI -e flag: CLI -e should NOT disable .omawarden.toml
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .current_dir(&deep_nested)
        .args([
            "broker",
            "exec",
            "-e",
            "EXTRA_KEY=NonExistentTestItemB",
            "--",
            "true",
        ])
        .output()
        .unwrap();

    // Must fail closed because items from either manifest or CLI were evaluated by the broker
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NonExistentTestItem")
            || stderr.contains("Vault is locked")
            || stderr.contains("Failed to")
    );
}
