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
fn test_broker_exec_no_network_flag_fails_closed() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "exec", "--no-network", "--", "true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--no-network is not yet implemented"));
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
