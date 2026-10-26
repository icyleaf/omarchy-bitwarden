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

#[test]
fn test_broker_import_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "import", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--dir"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--yes"));
    assert!(stdout.contains("--wipe"));
    assert!(stdout.contains("--no-wipe"));
    assert!(stdout.contains("--json"));
}

#[test]
fn test_broker_import_no_files_found_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "broker",
            "import",
            "--dir",
            tmp.path().to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("No legacy .env files found"));
}

#[test]
fn test_broker_import_dry_run_scans_and_groups_secrets_without_leaking() {
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join(".env");
    let secret_val = "sk-super-secret-key-999888";
    std::fs::write(
        &env_file,
        format!(
            "OPENAI_API_KEY={}\nDATABASE_URL=postgres://localhost/db\nCUSTOM_PORT=5000\n",
            secret_val
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "broker",
            "import",
            "--dir",
            tmp.path().to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Verifies categorized sections
    assert!(stdout.contains("[Dry-Run]"));
    assert!(stdout.contains("OpenAI:"));
    assert!(stdout.contains("Database:"));
    assert!(stdout.contains("CUSTOM_PORT"));
    assert!(stdout.contains(".omawarden.toml"));

    // Critical security invariant: secret value MUST NOT be printed!
    assert!(!stdout.contains(secret_val));

    // File must NOT be deleted in dry-run
    assert!(env_file.exists());
}

#[test]
fn test_broker_import_dry_run_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join(".env");
    std::fs::write(
        &env_file,
        "ANTHROPIC_API_KEY=ant-key-123\nAWS_SECRET_ACCESS_KEY=aws-secret-456\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "broker",
            "import",
            "--dir",
            tmp.path().to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["dry_run"], true);
    assert!(parsed["categories"]["Anthropic"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("ANTHROPIC_API_KEY")));
    assert!(parsed["categories"]["AWS"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("AWS_SECRET_ACCESS_KEY")));
}

#[test]
fn test_broker_import_non_interactive_without_yes_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join(".env");
    std::fs::write(&env_file, "OPENAI_API_KEY=sk-test\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "import", "--dir", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Interactive confirmation required"));
}

#[test]
fn test_broker_mcp_cli_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "mcp", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Model Context Protocol"));
}

#[test]
fn test_broker_mcp_stdio_roundtrip_initialize_and_tools_list() {
    use std::io::{BufRead, BufReader, Write};

    let mut child = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["broker", "mcp"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // 1. Send initialize
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    let resp1: serde_json::Value = serde_json::from_str(&line1).unwrap();
    assert_eq!(resp1["id"], 1);
    assert_eq!(resp1["result"]["serverInfo"]["name"], "omawarden-broker");

    // 2. Send tools/list
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line2 = String::new();
    reader.read_line(&mut line2).unwrap();
    let resp2: serde_json::Value = serde_json::from_str(&line2).unwrap();
    assert_eq!(resp2["id"], 2);
    let tools = resp2["result"]["tools"].as_array().unwrap();

    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
        .collect();

    assert!(tool_names.contains(&"list_available_tokens"));
    assert!(tool_names.contains(&"exec_with_token"));

    // Strict No-Read Invariant
    assert!(!tool_names.contains(&"read_secret"));
    assert!(!tool_names.contains(&"get_token"));

    // 3. Send tools/call exec_with_token
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"exec_with_token","arguments":{{"command":["echo","McpEchoIntegrationOk"]}}}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    let mut line3 = String::new();
    reader.read_line(&mut line3).unwrap();
    let resp3: serde_json::Value = serde_json::from_str(&line3).unwrap();
    assert_eq!(resp3["id"], 3);
    assert_eq!(resp3["result"]["isError"], false);
    let text = resp3["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("McpEchoIntegrationOk"));

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());
}
