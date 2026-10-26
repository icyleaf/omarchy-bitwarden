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
