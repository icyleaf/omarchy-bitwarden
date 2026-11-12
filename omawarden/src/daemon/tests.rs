use super::*;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::storage::StorageManager;
use crate::vault::VaultManager;
use serde_json::{json, Value};
use tempfile::tempdir;

#[test]
fn test_daemon_state_lifecycle() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);

    let state = DaemonState::new(storage_mgr, 15);
    assert!(!state.vault_mgr.is_unlocked());

    // Lock
    state.lock();
    assert!(!state.vault_mgr.is_unlocked());
    assert_eq!(state.vault_mgr.decrypted_items.read().unwrap().len(), 0);
}

#[test]
fn test_daemon_totp_action() {
    let res = crate::totp::generate_totp("JBSWY3DPEHPK3PXP", None, 6, 30);
    assert!(res.is_some());
    let totp_res = res.unwrap();
    assert_eq!(totp_res.code.len(), 6);
}

#[test]
fn test_daemon_totp_action_with_item_query() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);

    let state = DaemonState::new(storage_mgr, 15);
    let test_item = crate::vault::VaultItem {
        id: "item-totp-123".to_string(),
        name: "Github 2FA".to_string(),
        item_type: 1,
        type_name: "login".to_string(),
        sub_title: "user@github.com".to_string(),
        notes: None,
        favorite: false,
        created_at: None,
        updated_at: None,
        folder_id: None,
        folder_name: None,
        organization_id: None,
        organization_name: None,
        collection_ids: None,
        login: Some(serde_json::json!({
            "username": "user",
            "totp": "JBSWY3DPEHPK3PXP"
        })),
        card: None,
        identity: None,
        ssh_key: None,
        fields: vec![],
        attachments: vec![],
        search_text: "github 2fa user".to_string(),
    };

    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    state
        .vault_mgr
        .decrypted_items
        .write()
        .unwrap()
        .push(test_item);

    // Find by ID
    let found = state.vault_mgr.find_item("item-totp-123", None);
    assert!(found.is_some());
    let seed = found
        .unwrap()
        .login
        .unwrap()
        .get("totp")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let res = crate::totp::generate_totp(&seed, None, 6, 30);
    assert!(res.is_some());
    assert_eq!(res.unwrap().code.len(), 6);

    // Find by Name
    let found_name = state.vault_mgr.find_item("Github", None);
    assert!(found_name.is_some());
}

#[test]
fn test_should_touch_activity_classification() {
    // Passive actions must not touch activity
    for action in &[
        "ping",
        "status",
        "stop",
        "lock",
        "totp",
        "set_auto_lock",
        "unknown_action",
        "",
    ] {
        assert!(
            !should_touch_activity(action, &json!({ "action": action })),
            "Action '{}' should not touch activity",
            action
        );
    }

    // Active user actions must touch activity
    for action in &[
        "sync",
        "list",
        "search",
        "ssh_key_create",
        "cipher_create",
        "cipher_update",
        "cipher_delete",
        "cipher_resolve",
        "get_item",
        "get_ssh_key",
        "get_attachment_key",
        "copy",
    ] {
        assert!(
            should_touch_activity(action, &json!({ "action": action })),
            "Action '{}' should touch activity",
            action
        );
    }

    // Explicit touch: false must override active actions
    let req_touch_false = json!({ "action": "list", "touch": false });
    assert!(!should_touch_activity("list", &req_touch_false));

    // Explicit touch: true must override passive actions
    let req_touch_true = json!({ "action": "ping", "touch": true });
    assert!(should_touch_activity("ping", &req_touch_true));
}

#[test]
fn test_handle_client_selective_activity_touch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    // Set initial activity to a known point in the past
    let past = Instant::now() - Duration::from_secs(10);
    *state.last_activity.lock().unwrap() = past;

    // Helper to send a request via UnixStream pair and receive response
    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", req);
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // 1. "ping" without touch should not touch activity
    let res = send_req(json!({ "action": "ping" }));
    assert_eq!(res.get("pong").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(*state.last_activity.lock().unwrap(), past);

    // 2. "status" without touch should not touch activity
    let _ = send_req(json!({ "action": "status" }));
    assert_eq!(*state.last_activity.lock().unwrap(), past);

    // 3. "totp" with raw secret should not touch activity
    let _ = send_req(json!({ "action": "totp", "secret": "JBSWY3DPEHPK3PXP" }));
    assert_eq!(*state.last_activity.lock().unwrap(), past);

    // 4. "get_item" with explicit touch: false should not touch activity
    let _ = send_req(json!({ "action": "get_item", "query": "none", "touch": false }));
    assert_eq!(*state.last_activity.lock().unwrap(), past);

    // 5. "ping" with explicit touch: true DOES touch activity
    let ping_touch_res = send_req(json!({ "action": "ping", "touch": true }));
    assert_eq!(
        ping_touch_res.get("pong").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(*state.last_activity.lock().unwrap() > past);

    // Reset past activity for subsequent test
    *state.last_activity.lock().unwrap() = past;

    // 6. Active action (e.g. "search") should touch activity
    let search_res = send_req(json!({ "action": "search", "query": "test" }));
    assert!(search_res.is_array());
    assert!(*state.last_activity.lock().unwrap() > past);
}

#[test]
fn test_ssh_agent_ipc_actions() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    let state = Arc::new(DaemonState::new(
        StorageManager::new(dir.path().join("daemon_data.json")),
        15,
    ));
    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        client.write_all(format!("{}\n", req).as_bytes()).unwrap();
        client.flush().unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // Disabled by default: applying starts nothing.
    let res = send_req(json!({ "action": "ssh_agent_apply" }));
    assert_eq!(res["ok"], true);
    assert_eq!(res["running"], false);
    let res = send_req(json!({ "action": "ssh_agent_status" }));
    assert_eq!(res["running"], false);
    assert_eq!(
        res["socket"],
        json!(runtime.path().join("omawarden-ssh-agent.sock"))
    );

    // Enabled: applying binds the socket.
    let mut cfg = crate::config::ConfigManager::default().load();
    cfg.ssh_agent_enabled = true;
    fs::write(
        dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
        serde_json::to_string(&cfg).unwrap(),
    )
    .unwrap();
    let res = send_req(json!({ "action": "ssh_agent_apply" }));
    assert_eq!(
        (res["ok"].clone(), res["running"].clone()),
        (json!(true), json!(true))
    );
    assert_eq!(
        send_req(json!({ "action": "ssh_agent_status" }))["running"],
        true
    );

    // Nothing is waiting for an answer.
    let res = send_req(json!({ "action": "ssh_agent_pending" }));
    assert_eq!(res["prompts"], json!([]));
    let res = send_req(json!({ "action": "ssh_agent_reply", "id": 42, "approve": true }));
    assert_eq!(res["ok"], true);
    assert_eq!(res["delivered"], false);
    let res = send_req(json!({ "action": "ssh_agent_reply" }));
    assert_eq!(
        res["delivered"], false,
        "missing id and approve are tolerated"
    );

    // Disabled again: applying stops it and removes the socket.
    let write_enabled = |on: bool| {
        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.ssh_agent_enabled = on;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
    };
    write_enabled(false);
    let res = send_req(json!({ "action": "ssh_agent_apply" }));
    assert_eq!(res["running"], false);
    assert!(!crate::ssh_agent::socket_path().exists());

    // A path that can't be bound is reported.
    std::os::unix::fs::symlink("/tmp/elsewhere", crate::ssh_agent::socket_path()).unwrap();
    write_enabled(true);
    let res = send_req(json!({ "action": "ssh_agent_apply" }));
    assert_eq!(res["ok"], false);
    assert!(res["error"].as_str().unwrap().starts_with("SSH agent: "));

    for (k, v) in [
        ("XDG_RUNTIME_DIR", old_runtime),
        ("OMAWARDEN_CONFIG_DIR", old_config),
    ] {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
}

#[test]
fn test_ensure_daemon_running_keeps_a_running_daemon_it_should_not_replace() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_data = std::env::var_os("OMAWARDEN_DATA_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    std::env::set_var("OMAWARDEN_DATA_DIR", runtime.path());
    StorageManager::default()
        .save(&crate::storage::VaultStorage {
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
            ..Default::default()
        })
        .unwrap();

    // A daemon that answers every ping the same way; if it were replaced,
    // a second daemon would be spawned and the connection count would
    // show it.
    let listener = std::os::unix::net::UnixListener::bind(get_socket_path()).unwrap();
    for reply in [
        json!({ "ok": true, "protocol_version": 1, "commit": env!("GIT_HASH"), "unlocked": false }),
        json!({ "ok": true, "protocol_version": 1, "commit": "another-build", "unlocked": true }),
        // ADR-0028: matching protocol version 1 is kept even when locked and commit differs!
        json!({ "ok": true, "protocol_version": 1, "commit": "foreign-commit", "unlocked": false }),
    ] {
        let server = {
            let listener = listener.try_clone().unwrap();
            let reply = reply.clone();
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap()["action"],
                    "ping"
                );
                writeln!(stream, "{reply}").unwrap();
            })
        };
        let _ = ensure_daemon_running();
        server.join().unwrap();
    }

    for (key, old) in [
        ("XDG_RUNTIME_DIR", old_runtime),
        ("OMAWARDEN_DATA_DIR", old_data),
    ] {
        match old {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn test_incompatible_protocol_version_fails_closed_without_stop() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_data = std::env::var_os("OMAWARDEN_DATA_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    std::env::set_var("OMAWARDEN_DATA_DIR", runtime.path());

    let listener = std::os::unix::net::UnixListener::bind(get_socket_path()).unwrap();
    // Server answers ping with incompatible protocol_version: 99
    let server = {
        let listener = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["action"],
                "ping"
            );
            writeln!(
                stream,
                "{}",
                json!({ "ok": true, "protocol_version": 99, "commit": "future" })
            )
            .unwrap();
            // Ensure no stop request is transmitted
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut next_line = String::new();
            let read_res = BufReader::new(stream).read_line(&mut next_line);
            if let Ok(n) = read_res {
                if n > 0 {
                    assert_ne!(
                        serde_json::from_str::<Value>(&next_line).unwrap()["action"],
                        "stop",
                        "Incompatible protocol version must NOT trigger stop action"
                    );
                }
            }
        })
    };

    let _ = ensure_daemon_running();
    server.join().unwrap();

    for (key, old) in [
        ("XDG_RUNTIME_DIR", old_runtime),
        ("OMAWARDEN_DATA_DIR", old_data),
    ] {
        match old {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn test_ping_advertises_protocol_version_1() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    let (mut client, server) = UnixStream::pair().unwrap();
    let st = state.clone();
    let handle = std::thread::spawn(move || {
        let _ = handle_client(server, st);
    });
    let payload = format!("{}\n", json!({ "action": "ping" }));
    client.write_all(payload.as_bytes()).unwrap();
    client.flush().unwrap();
    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    handle.join().unwrap();
    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(
        resp.get("protocol_version").and_then(Value::as_u64),
        Some(CURRENT_PROTOCOL_VERSION as u64)
    );
}

#[test]
fn test_protocol_version_negotiation() {
    let compatible = json!({ "ok": true, "protocol_version": 1 });
    assert_eq!(
        check_protocol_version(&compatible),
        ProtocolCheck::Compatible
    );

    // Missing protocol_version defaults to 0 (legacy unversioned) -> Compatible when MIN is 0
    let legacy = json!({ "ok": true, "commit": "old" });
    assert_eq!(check_protocol_version(&legacy), ProtocolCheck::Compatible);

    let explicit_zero = json!({ "ok": true, "protocol_version": 0 });
    assert_eq!(
        check_protocol_version(&explicit_zero),
        ProtocolCheck::Compatible
    );

    // Future protocol version 99 -> Incompatible
    let future = json!({ "ok": true, "protocol_version": 99 });
    assert_eq!(
        check_protocol_version(&future),
        ProtocolCheck::Incompatible {
            running: 99,
            min_supported: 0,
            current: 1
        }
    );
}

#[test]
fn test_daemon_client_send_fail_closed_on_incompatible_protocol() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());

    let listener = std::os::unix::net::UnixListener::bind(get_socket_path()).unwrap();
    let server = {
        let listener = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            // 1. Client sends ping -> respond with incompatible protocol_version: 99
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["action"],
                "ping"
            );
            writeln!(
                stream,
                "{}",
                json!({ "ok": true, "protocol_version": 99, "commit": "future" })
            )
            .unwrap();

            // 2. Client sends status -> mock responds with protocol_version: 99
            let (mut stream2, _) = listener.accept().unwrap();
            let mut line2 = String::new();
            BufReader::new(stream2.try_clone().unwrap())
                .read_line(&mut line2)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line2).unwrap()["action"],
                "status"
            );
            writeln!(
                stream2,
                "{}",
                json!({ "ok": true, "unlocked": false, "protocol_version": 99 })
            )
            .unwrap();
        })
    };

    let client = DaemonClient::new();
    // Ping returns IncompatibleProtocol
    let ping_res = client.send(&json!({ "action": "ping" }));
    assert_eq!(
        ping_res,
        Err(DispatchError::IncompatibleProtocol {
            running: 99,
            min_supported: 0,
            current: 1,
        })
    );

    // Status response advertising protocol_version 99 also fails closed with IncompatibleProtocol
    let status_res = client.send(&json!({ "action": "status" }));
    assert_eq!(
        status_res,
        Err(DispatchError::IncompatibleProtocol {
            running: 99,
            min_supported: 0,
            current: 1,
        })
    );

    server.join().unwrap();

    match old_runtime {
        Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
        None => std::env::remove_var("XDG_RUNTIME_DIR"),
    }
}

#[test]
fn test_daemon_client_send_legacy_v0_unversioned_payload_compatibility() {
    let runtime = tempdir().unwrap();
    let socket_path = runtime.path().join("omawarden.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let server = {
        let listener = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            // 1. Client sends ping to legacy v0 daemon without protocol_version
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["action"],
                "ping"
            );
            writeln!(
                stream,
                "{}",
                json!({ "ok": true, "pong": true, "unlocked": true, "version": "0.10.0" })
            )
            .unwrap();
            let _ = stream.flush();
            drop(stream);

            // 2. Client sends status to legacy v0 daemon without protocol_version
            let (mut stream2, _) = listener.accept().unwrap();
            let mut line2 = String::new();
            BufReader::new(stream2.try_clone().unwrap())
                .read_line(&mut line2)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line2).unwrap()["action"],
                "status"
            );
            writeln!(
                stream2,
                "{}",
                json!({ "ok": true, "is_unlocked": true, "unlocked": true })
            )
            .unwrap();
            let _ = stream2.flush();
            drop(stream2);
        })
    };

    let client = DaemonClient::new().with_socket_path(&socket_path);
    // Ping succeeds and accepts unversioned legacy v0
    let ping_res = client.send(&json!({ "action": "ping" })).unwrap();
    assert_eq!(ping_res["ok"], true);
    assert_eq!(ping_res["pong"], true);

    // Status succeeds and accepts unversioned legacy v0
    let status_res = client.send(&json!({ "action": "status" })).unwrap();
    assert_eq!(status_res["ok"], true);
    assert_eq!(status_res["is_unlocked"], true);

    server.join().unwrap();
}

#[test]
fn test_background_pings_do_not_prevent_idle_auto_lock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    // Configure a short timeout (100ms) for testing
    state.set_auto_lock_duration(Duration::from_millis(100));

    // Unlock the vault
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    assert!(state.vault_mgr.is_unlocked());

    // Send repeated pings over 150ms (crossing the 100ms threshold)
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(150) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", json!({ "action": "ping" }));
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();
        handle.join().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }

    // Auto-lock check must lock the vault despite the continuous background pings
    assert!(state.check_auto_lock());
    assert!(!state.vault_mgr.is_unlocked());
}

#[test]
fn test_set_auto_lock_action() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", req);
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // Update with minutes
    let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_minutes": 5 }));
    assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        *state.auto_lock_duration.lock().unwrap(),
        Duration::from_secs(300)
    );

    // Update with seconds
    let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_seconds": 45 }));
    assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        *state.auto_lock_duration.lock().unwrap(),
        Duration::from_secs(45)
    );
}

#[test]
fn test_verify_peer_credentials() {
    let (client, server) = UnixStream::pair().unwrap();
    assert!(verify_peer_credentials(&client).is_ok());
    assert!(verify_peer_credentials(&server).is_ok());
}

#[test]
fn test_suspend_happened_predicate() {
    fn f(prev: Option<u64>, current: Option<u64>) -> bool {
        DaemonState::suspend_happened(prev, current)
    }
    assert!(!f(None, Some(100)), "first sample is never an event");
    assert!(
        !f(Some(100), Some(100)),
        "equal deltas: awake the whole time"
    );
    assert!(
        !f(Some(100), Some(101)),
        "one second of clock skew is not suspend"
    );
    assert!(f(Some(100), Some(103)), "grew by 3s: suspend happened");
    assert!(!f(Some(100), Some(99)), "shrinkage ignored");
    assert!(!f(Some(100), None), "clock unavailable is not an event");
}

#[test]
fn test_suspend_drift_wipes_retained_key_while_soft_locked() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
    let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    // The daemon caches the setting at startup; tests mirror the
    // set_quick_unlock IPC instead of rewriting config.json (which the
    // hot paths no longer read).
    state.set_quick_unlock_enabled(true);

    // Soft-locked with a retained key: the dominant quick-unlock state.
    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    assert!(state.vault_mgr.soft_lock());
    assert!(state.vault_mgr.quick_unlock_available());

    // First tick primes the cache; second tick observes the drift.
    assert!(!state.check_suspend_drift_with(Some(1_000)));
    assert!(
        state.check_suspend_drift_with(Some(1_900)),
        "900s of accumulated suspend time must be detected"
    );
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "suspend must wipe the retained key even while soft-locked"
    );
    assert!(!state.vault_mgr.is_unlocked());

    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_suspend_drift_hard_locks_unlocked_vault() {
    let dir = tempdir().unwrap();
    let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    assert!(!state.check_suspend_drift_with(Some(10)));
    assert!(state.check_suspend_drift_with(Some(600)));
    assert!(!state.vault_mgr.is_unlocked());
}

#[test]
fn test_session_anchor_ceiling_wipes_retained_key_while_soft_locked() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
    let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    state.set_quick_unlock_enabled(true);

    // Unlocked 13h ago (session anchor), then soft-locked with retention.
    *state.session_anchor.lock().unwrap() = Some(Instant::now() - Duration::from_secs(13 * 3600));
    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    assert!(state.vault_mgr.soft_lock());

    assert!(
        state.check_auto_lock(),
        "the 12h ceiling must fire for a retained key past the session anchor"
    );
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "ceiling must wipe the retained key"
    );
    assert!(
        state.session_anchor.lock().unwrap().is_none(),
        "hard lock clears the anchor"
    );

    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_quick_unlock_re_arms_unlocked_at_but_not_session_anchor() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
    let mut daemon_state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

    let pk = dir.path().join("mock-pkcheck");
    crate::write_test_executable(&pk, "#!/bin/sh\nexit 0\n");
    daemon_state.polkit_binary = pk;
    daemon_state.polkit_policy_registered = true;
    let state = Arc::new(daemon_state);
    // Mirror the set_quick_unlock IPC the CLI sends after a config write.
    state.set_quick_unlock_enabled(true);

    // Session anchored 13h ago by the master-password unlock.
    *state.session_anchor.lock().unwrap() = Some(Instant::now() - Duration::from_secs(13 * 3600));
    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    assert!(state.vault_mgr.soft_lock());

    assert!(state.perform_quick_unlock().is_ok());
    assert!(
        state.unlocked_at.lock().unwrap().is_some(),
        "quick unlock must re-arm the per-unlock anchor (Rule 9 while unlocked)"
    );

    // The session anchor is untouched, so the ceiling still fires even
    // though the vault was just quick-unlocked.
    assert!(
        state.check_auto_lock(),
        "quick unlock must not extend the 12h session ceiling"
    );
    assert!(!state.vault_mgr.is_unlocked());

    old_runtime.map_or_else(
        || std::env::remove_var("XDG_RUNTIME_DIR"),
        |v| std::env::set_var("XDG_RUNTIME_DIR", v),
    );
    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_check_screen_lock_custom_detector() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = DaemonState::new(storage_mgr, 15);

    // Vault is initially locked: detector should not be invoked or return false
    let mut called = false;
    assert!(!state.check_screen_lock_with(|| {
        called = true;
        LockSignal::Screen
    }));
    assert!(!called);
    assert!(!state.vault_mgr.is_unlocked());

    // Unlock the vault
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    assert!(state.vault_mgr.is_unlocked());

    // No lock signal -> vault remains unlocked
    assert!(!state.check_screen_lock_with(|| LockSignal::None));
    assert!(state.vault_mgr.is_unlocked());

    // Screen signal -> locks
    assert!(state.check_screen_lock_with(|| LockSignal::Screen));
    assert!(!state.vault_mgr.is_unlocked());

    // Subsequent call returns false because already locked
    assert!(!state.check_screen_lock_with(|| LockSignal::Screen));
}

#[test]
fn test_soft_lock_hard_locks_when_quick_unlock_disabled() {
    // ADR-0025: retention exists only when opted in. With quick_unlock
    // disabled, a soft lock must HARD lock: no key may survive in the
    // slot for any later restore to pick up.
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    let mut cfg = crate::config::ConfigManager::default().load();
    cfg.quick_unlock = false;
    fs::write(
        dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
        serde_json::to_string(&cfg).unwrap(),
    )
    .unwrap();

    let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    assert!(!state.quick_unlock_enabled());

    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    state.soft_lock();

    assert!(!state.vault_mgr.is_unlocked());
    assert!(
        state.vault_mgr.user_key.read().unwrap().is_none(),
        "the user key must be purged from the session"
    );
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "with quick unlock disabled a soft lock must be a hard lock: nothing retained"
    );
    assert!(
        !state.quick_unlock_ready(),
        "readiness must stay false while the feature is disabled"
    );

    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_soft_lock_hard_locks_when_quick_unlock_is_unusable() {
    // ADR-0025: retention is only worth its exposure when the polkit
    // check can actually run. Enabled-but-unusable (policy missing, no
    // pkcheck) must hard-lock, exactly like disabled: the retained key
    // could never be spent and would just sit in memory.
    let _lock = crate::env_lock();
    let dir = tempfile::tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    let mut daemon_state =
        DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    daemon_state.set_quick_unlock_enabled(true);
    // No resolvable pkcheck, no registered policy.
    daemon_state.polkit_binary = std::path::PathBuf::new();
    daemon_state.polkit_policy_registered = false;
    let state = Arc::new(daemon_state);
    assert!(state.quick_unlock_enabled());
    assert!(!state.quick_unlock_usable());

    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    state.soft_lock();

    assert!(!state.vault_mgr.is_unlocked());
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "an unusable feature must not retain a key nobody can spend"
    );
    assert!(!state.quick_unlock_ready());

    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_sleep_signal_hard_locks_and_screen_signal_soft_locks() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
    let mut daemon_state =
        DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    // Retention requires a usable feature, not just the setting: pin the
    // startup-resolved binary and policy so the host cannot decide this.
    daemon_state.polkit_binary = dir.path().join("pkcheck");
    daemon_state.polkit_policy_registered = true;
    let state = Arc::new(daemon_state);
    let key = crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap();

    // Screen lock with quick unlock enabled: key must survive in the slot.
    state.set_quick_unlock_enabled(true);

    *state.vault_mgr.user_key.write().unwrap() = Some(key.clone());
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    assert!(state.check_screen_lock_with(|| LockSignal::Screen));
    assert!(!state.vault_mgr.is_unlocked());
    assert!(
        state.vault_mgr.quick_unlock_available(),
        "screen lock must retain the key when quick unlock is on"
    );

    // Sleep signal: retention must be wiped even while quick unlock is on.
    *state.vault_mgr.user_key.write().unwrap() = Some(key);
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    assert!(state.check_screen_lock_with(|| LockSignal::Sleep));
    assert!(!state.vault_mgr.is_unlocked());
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "sleep must hard-lock: no key may survive a suspend"
    );

    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_quick_unlock_ipc_disabled_and_unavailable() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("runtime"));
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
    let state = Arc::new(DaemonState::new(
        StorageManager::new(dir.path().join("daemon_data.json")),
        15,
    ));

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        client.write_all(format!("{}\n", req).as_bytes()).unwrap();
        client.flush().unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    let res = send_req(json!({ "action": "quick_unlock" }));
    assert_eq!(res["ok"], false);
    assert!(
        res["error"].as_str().unwrap().contains("disabled"),
        "got: {res}"
    );

    // Enabled but nothing retained (hard-locked vault) must fail closed.
    // Mirror the set_quick_unlock IPC the CLI sends after a config write.
    state.set_quick_unlock_enabled(true);
    let res = send_req(json!({ "action": "quick_unlock" }));
    assert_eq!(res["ok"], false);
    assert!(
        res["error"].as_str().unwrap().contains("unavailable"),
        "got: {res}"
    );

    old_runtime.map_or_else(
        || std::env::remove_var("XDG_RUNTIME_DIR"),
        |v| std::env::set_var("XDG_RUNTIME_DIR", v),
    );
    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_set_quick_unlock_ipc_refreshes_cache_and_ping_reports_enabled() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("runtime"));
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
    let mut daemon_state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);
    daemon_state.polkit_binary = std::path::PathBuf::new();
    let state = Arc::new(daemon_state);

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        client.write_all(format!("{}\n", req).as_bytes()).unwrap();
        client.flush().unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // Default cached at startup from config.json: off.
    let ping = send_req(json!({ "action": "ping" }));
    assert_eq!(ping["quick_unlock_enabled"], false);

    // `config set --quick-unlock` writes the file, then sends this IPC;
    // the daemon must never re-read config.json on its hot paths.
    let res = send_req(json!({ "action": "set_quick_unlock", "enabled": true }));
    assert_eq!(res["ok"], true);
    let ping = send_req(json!({ "action": "ping" }));
    assert_eq!(ping["quick_unlock_enabled"], true);
    assert_eq!(
        ping["quick_unlock"], false,
        "enabled alone is not readiness (nothing retained here)"
    );

    // Prime retention, then disable via the IPC: the handler owns the
    // wipe (same trigger family as strikes/suspend/logout), so turning
    // the feature off must not leave a retained key behind even though
    // the caller sent no separate wipe request.
    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    assert!(state.vault_mgr.soft_lock());
    assert!(state.vault_mgr.quick_unlock_available());
    send_req(json!({ "action": "set_quick_unlock", "enabled": false }));
    let ping = send_req(json!({ "action": "ping" }));
    assert_eq!(ping["quick_unlock_enabled"], false);
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "disabling through the IPC must wipe the retained key"
    );

    old_runtime.map_or_else(
        || std::env::remove_var("XDG_RUNTIME_DIR"),
        |v| std::env::set_var("XDG_RUNTIME_DIR", v),
    );
    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_quick_unlock_ipc_authorized_and_three_denies_wipe() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    // A real login on disk so a successful polkit check can restore.
    let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
    let mut daemon_state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

    // Mock pkcheck whose exit code is driven by a file the test flips.
    let pk = dir.path().join("mock-pkcheck");
    crate::write_test_executable(
        &pk,
        format!(
            r#"#!/bin/sh
exit $(cat {})
"#,
            dir.path().join("pk_code").display()
        ),
    );
    daemon_state.polkit_binary = pk.clone();
    daemon_state.polkit_policy_registered = true;
    let state = Arc::new(daemon_state);
    // Mirror the set_quick_unlock IPC the CLI sends after a config write.
    state.set_quick_unlock_enabled(true);

    // Prime retention the way a soft lock would.
    *state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    assert!(state.vault_mgr.soft_lock());
    assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        client.write_all(format!("{}\n", req).as_bytes()).unwrap();
        client.flush().unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // 1. polkit authorizes: IPC reports an unlocked vault.
    fs::write(dir.path().join("pk_code"), "0").unwrap();
    let res = send_req(json!({ "action": "quick_unlock" }));
    assert_eq!(res["ok"], true, "got: {res}");
    assert_eq!(res["status"], "unlocked");
    assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

    // 1b. While unlocked the action must not re-prompt (state-machine
    // hole closed in review): it fails fast without touching polkit.
    fs::write(dir.path().join("pk_code"), "0").unwrap();
    let res = send_req(json!({ "action": "quick_unlock" }));
    assert_eq!(res["ok"], false, "got: {res}");
    assert!(
        res["error"].as_str().unwrap().contains("already unlocked"),
        "got: {res}"
    );

    // Back to the soft-locked state for the denial loop.
    assert!(state.vault_mgr.soft_lock());

    // 2. Three denials in a row wipe the retained key.
    fs::write(dir.path().join("pk_code"), "1").unwrap();
    for i in 1..=3 {
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false, "attempt {i}: {res}");
        assert!(
            res["error"].as_str().unwrap().contains("denied"),
            "attempt {i}: {res}"
        );
    }
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "three denials must wipe the retained key"
    );
    assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

    // 3. After the wipe the action fails closed without calling polkit.
    fs::write(dir.path().join("pk_code"), "0").unwrap();
    let res = send_req(json!({ "action": "quick_unlock" }));
    assert_eq!(res["ok"], false);
    assert!(res["error"].as_str().unwrap().contains("unavailable"));

    // 4. wipe_quick_unlock action is a harmless explicit no-op.
    let res = send_req(json!({ "action": "wipe_quick_unlock" }));
    assert_eq!(res["ok"], true);

    old_runtime.map_or_else(
        || std::env::remove_var("XDG_RUNTIME_DIR"),
        |v| std::env::set_var("XDG_RUNTIME_DIR", v),
    );
    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_logout_requests_end_retention_with_readiness_false() {
    // ADR-0025 decision 4: logout must zeroize the retained key. The
    // logout flow (AuthManager::logout) sends "lock" followed by
    // an explicit "wipe_quick_unlock"; pin the daemon contract both
    // requests rely on: slot empty, readiness false in the ping payload.
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    let state = Arc::new(DaemonState::new(
        StorageManager::new(dir.path().join("daemon_data.json")),
        15,
    ));
    state.set_quick_unlock_enabled(true);

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        client.write_all(format!("{}\n", req).as_bytes()).unwrap();
        client.flush().unwrap();
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    let prime_retention = |key_byte: u8| {
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[key_byte; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());
        assert!(state.vault_mgr.quick_unlock_available());
    };

    // 1. The "lock" half of the logout flow must already end retention.
    prime_retention(7u8);
    let res = send_req(json!({ "action": "lock" }));
    assert_eq!(res["ok"], true, "got: {res}");
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "the retained key must be gone after logout's lock request"
    );
    assert!(
        !state.quick_unlock_ready(),
        "readiness must be false after logout's lock request"
    );

    // 2. The explicit "wipe_quick_unlock" half must zeroize on its own.
    prime_retention(9u8);
    let res = send_req(json!({ "action": "wipe_quick_unlock" }));
    assert_eq!(res["ok"], true, "got: {res}");
    assert!(
        !state.vault_mgr.quick_unlock_available(),
        "the retained key must be gone after the explicit wipe request"
    );
    assert!(
        !state.quick_unlock_ready(),
        "readiness must be false after the explicit wipe request"
    );

    // 3. And the ping payload stops advertising quick unlock. It also
    // always carries the memory-protection bit (mlock degradation must
    // be discoverable even though the daemon's stderr is discarded).
    let res = send_req(json!({ "action": "ping" }));
    assert_eq!(res["quick_unlock"], false, "got: {res}");
    assert!(
        res["memory_locked"].is_boolean(),
        "ping must report memory protection state: {res}"
    );

    old_runtime.map_or_else(
        || std::env::remove_var("XDG_RUNTIME_DIR"),
        |v| std::env::set_var("XDG_RUNTIME_DIR", v),
    );
    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_poisoned_busy_mutex_does_not_jam_quick_unlock() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

    // A real login on disk so the post-polkit restore can succeed.
    let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
    let mut daemon_state = DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

    let pk = dir.path().join("mock-pkcheck");
    crate::write_test_executable(&pk, "#!/bin/sh\nexit 0\n");
    daemon_state.polkit_binary = pk;
    daemon_state.polkit_policy_registered = true;
    // Mirror the set_quick_unlock IPC the CLI sends after a config write.
    daemon_state.set_quick_unlock_enabled(true);

    // Prime retention the way a soft lock would.
    *daemon_state.vault_mgr.user_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
    assert!(daemon_state.vault_mgr.soft_lock());

    // Poison the busy guard the way a panic during an earlier prompt
    // would (the panicking thread held the mutex).
    let state = Arc::new(daemon_state);
    let poisoner = state.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = poisoner.quick_unlock_busy.lock().unwrap();
        panic!("simulated panic while the polkit prompt was up");
    }));
    assert!(
        state.quick_unlock_busy.lock().is_err(),
        "the busy mutex must actually be poisoned by the setup"
    );

    // The next quick unlock must recover instead of failing forever with
    // "already in progress".
    assert!(
        state.perform_quick_unlock().is_ok(),
        "a poisoned busy mutex must not jam quick unlock"
    );

    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_ping_advertises_quick_unlock_only_when_ready() {
    let _lock = crate::env_lock();
    let dir = tempdir().unwrap();
    let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
    std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
    let mut daemon_state =
        DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
    // No polkit binary resolvable at startup: never ready, even with the
    // feature enabled and a key retained (readiness honesty — the button
    // must not advertise a prompt that can only fail). Forced empty so
    // the test does not depend on the host having pkcheck.
    daemon_state.polkit_binary = std::path::PathBuf::new();
    daemon_state.polkit_policy_registered = true;
    let state = Arc::new(daemon_state);
    // Disabled by default and nothing retained.
    assert!(!state.quick_unlock_ready());
    // Write the enabled setting to disk and mirror the CLI's
    // set_quick_unlock IPC, so the assert below fails for the reason it
    // names (later constructions reload this file at startup).
    let mut cfg = crate::config::ConfigManager::default().load();
    cfg.quick_unlock = true;
    fs::write(
        dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
        serde_json::to_string(&cfg).unwrap(),
    )
    .unwrap();
    state.set_quick_unlock_enabled(true);
    // Enabled but no retained key: still not ready.
    assert!(!state.quick_unlock_ready());
    *state.vault_mgr.quick_unlock_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
    assert!(
        !state.quick_unlock_ready(),
        "no resolvable polkit binary must keep readiness false"
    );

    // With a binary resolved at startup, retention alone completes it.
    drop(state);
    let runtime = tempdir().unwrap();
    let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
    std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
    // This construction caches quick_unlock=true from the config file
    // written above: the daemon-startup half of the caching contract.
    daemon_state = DaemonState::new(
        StorageManager::new(dir.path().join("daemon2_data.json")),
        15,
    );
    daemon_state.polkit_binary = dir.path().join("pkcheck");
    // Retention + enabled setting are not enough: an unregistered
    // policy (missing package file) must keep readiness false.
    daemon_state.polkit_policy_registered = false;
    let state = Arc::new(daemon_state);
    assert!(state.quick_unlock_enabled());
    *state.vault_mgr.quick_unlock_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
    assert!(
        !state.quick_unlock_ready(),
        "an unregistered policy must keep readiness false"
    );
    drop(state);

    daemon_state = DaemonState::new(
        StorageManager::new(dir.path().join("daemon3_data.json")),
        15,
    );
    daemon_state.polkit_binary = dir.path().join("pkcheck");
    daemon_state.polkit_policy_registered = true;
    let state = Arc::new(daemon_state);
    *state.vault_mgr.quick_unlock_key.write().unwrap() =
        Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
    assert!(state.quick_unlock_ready());

    old_runtime.map_or_else(
        || std::env::remove_var("XDG_RUNTIME_DIR"),
        |v| std::env::set_var("XDG_RUNTIME_DIR", v),
    );
    old_config.map_or_else(
        || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
        |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
    );
}

#[test]
fn test_screen_lock_detection_functions_safe() {
    // Ensure detection functions execute safely without panicking
    let _ = is_omarchy_locked();
    let _ = is_screen_locker_running();
    let _ = is_logind_locked_or_sleeping();
    let _ = is_system_or_screen_locked();
}

#[test]
fn test_validate_socket_path_valid_and_symlink_rejection() {
    let dir = tempdir().unwrap();
    let real_socket = dir.path().join("real.sock");
    fs::write(&real_socket, b"").unwrap();

    // Valid socket file owned by current user
    assert!(validate_socket_path(&real_socket).is_ok());

    // Symlink pointing to the real socket must be rejected
    let symlink_socket = dir.path().join("symlink.sock");
    std::os::unix::fs::symlink(&real_socket, &symlink_socket).unwrap();
    let err = validate_socket_path(&symlink_socket);
    assert!(err.is_err());
    assert_eq!(
        err.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn test_validate_socket_path_parent_symlink_rejection() {
    let dir = tempdir().unwrap();
    let real_dir = dir.path().join("real_runtime");
    fs::create_dir_all(&real_dir).unwrap();

    let symlink_dir = dir.path().join("symlink_runtime");
    std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

    let socket_in_symlink_parent = symlink_dir.join("omawarden.sock");
    let err = validate_socket_path(&socket_in_symlink_parent);
    assert!(err.is_err());
    assert_eq!(
        err.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn test_get_runtime_dir_permissions_and_ownership() {
    let runtime_dir = get_runtime_dir();
    assert!(runtime_dir.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&runtime_dir).unwrap();
        assert_eq!(meta.uid(), unsafe { libc::getuid() });
    }
}

#[test]
fn test_privileged_actions_require_unlocked_vault() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", req);
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    let privileged_actions = vec![
        json!({ "action": "list" }),
        json!({ "action": "search", "query": "test" }),
        json!({ "action": "get_item", "query": "test" }),
        json!({ "action": "get_ssh_key", "query": "test" }),
        json!({ "action": "get_attachment_key", "item_id": "i", "attachment_id": "a" }),
        json!({ "action": "sync" }),
        json!({ "action": "totp", "query": "test" }),
    ];

    // 1. While locked, all privileged actions fail with locked error
    for req in &privileged_actions {
        let res = send_req(req.clone());
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert!(
            res.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("locked"),
            "Action '{}' should fail when vault is locked",
            req.get("action").unwrap()
        );
    }

    // 2. Unlock vault
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    // 3. When unlocked, privileged actions proceed without needing any session token
    let list_res = send_req(json!({ "action": "list" }));
    assert!(list_res.is_array(), "List should succeed when unlocked");

    let search_res = send_req(json!({ "action": "search", "query": "test" }));
    assert!(search_res.is_array(), "Search should succeed when unlocked");
}

#[test]
fn test_max_session_lifetime_auto_lock() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = DaemonState::new(storage_mgr, 15);

    // Vault unlocked 2 hours ago with max lifetime of 1 hour
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    *state.unlocked_at.lock().unwrap() = Some(Instant::now() - Duration::from_secs(7200));
    *state.max_session_lifetime.lock().unwrap() = Duration::from_secs(3600);

    // Keep last_activity brand new (just now) so idle timeout would NOT trigger
    *state.last_activity.lock().unwrap() = Instant::now();

    // check_auto_lock must trigger because max_session_lifetime has elapsed!
    assert!(state.check_auto_lock());
    assert!(!state.vault_mgr.is_unlocked());
    assert!(state.unlocked_at.lock().unwrap().is_none());
}

#[test]
fn test_handle_client_client_context_parsing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    *state.vault_mgr.is_unlocked.write().unwrap() = true;

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", req);
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // 1. Valid client context in sync request (fails with missing session token error, proving sync_with_client was called)
    let res_valid = send_req(json!({
        "action": "sync",
        "client": {
            "name": "Omarchy_Bitwarden",
            "version": "0.11.2"
        }
    }));
    assert_eq!(res_valid.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert!(res_valid.get("error").is_some());

    // 2. Invalid client context with CRLF injection is rejected/filtered
    let res_injection = send_req(json!({
        "action": "sync",
        "client": {
            "name": "evil\r\nHeader: foo",
            "version": "0.11.2"
        }
    }));
    assert_eq!(
        res_injection.get("ok").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert!(res_injection.get("error").is_some());
}

#[test]
fn test_daemon_generate_password_action() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", req);
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // 1. Password generation while locked
    let res_pwd = send_req(json!({
        "action": "generate_password",
        "length": 25,
        "uppercase": true,
        "lowercase": true,
        "numbers": true,
        "special": true
    }));
    assert_eq!(res_pwd.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        res_pwd.get("type").and_then(|v| v.as_str()),
        Some("password")
    );
    let pwd_str = res_pwd
        .get("password")
        .and_then(|v| v.as_str())
        .expect("missing password");
    assert_eq!(pwd_str.len(), 25);
    assert!(res_pwd.get("entropy").and_then(|v| v.as_f64()).unwrap() > 100.0);

    // 2. Passphrase generation while locked
    let res_phrase = send_req(json!({
        "action": "generate_password",
        "passphrase": true,
        "words": 5,
        "separator": ".",
        "capitalize": true
    }));
    assert_eq!(res_phrase.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        res_phrase.get("type").and_then(|v| v.as_str()),
        Some("passphrase")
    );
    let phrase_str = res_phrase
        .get("password")
        .and_then(|v| v.as_str())
        .expect("missing passphrase");
    assert_eq!(phrase_str.split('.').count(), 5);
    assert!(res_phrase.get("entropy").and_then(|v| v.as_f64()).unwrap() > 60.0);
}

#[test]
fn test_stop_action_graceful_shutdown_without_process_exit() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = env::var_os("XDG_RUNTIME_DIR");
    env::set_var("XDG_RUNTIME_DIR", runtime.path());

    let storage_dir = tempdir().unwrap();
    let storage_mgr = StorageManager::new(storage_dir.path().join("data.json"));
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let server = DaemonServer::new(state.clone());
    let handle = server.spawn().expect("failed to spawn daemon server");

    // Ping to ensure daemon is ready
    let ping_res = send_daemon_request(&json!({ "action": "ping" })).expect("ping failed");
    assert_eq!(ping_res["ok"], true);
    assert_eq!(ping_res["pong"], true);

    // Send stop request
    let stop_res = send_daemon_request(&json!({ "action": "stop" })).expect("stop failed");
    assert_eq!(stop_res["ok"], true);

    // Wait for server thread to join cleanly
    let join_res = handle.join().expect("daemon thread panicked");
    assert!(
        join_res.is_ok(),
        "daemon server returned error: {:?}",
        join_res
    );

    // Verify vault is locked and socket removed
    assert!(!state.vault_mgr.is_unlocked());
    assert!(!get_socket_path().exists());

    match old_runtime {
        Some(val) => env::set_var("XDG_RUNTIME_DIR", val),
        None => env::remove_var("XDG_RUNTIME_DIR"),
    }
}

#[test]
fn test_in_process_daemon_rejects_external_stop() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    state.set_in_process(true);

    let (mut client, server) = UnixStream::pair().unwrap();
    let st = state.clone();
    // Simulate external caller PID: 99999
    let handle = std::thread::spawn(move || {
        let _ = handle_client_with_peer(server, st, Some(99999));
    });

    let payload = format!("{}\n", json!({ "action": "stop", "admin": true }));
    client.write_all(payload.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    handle.join().unwrap();

    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("cannot terminate in-process daemon"));
    assert!(!state.shutdown.is_shutting_down());
}

#[test]
fn test_standalone_daemon_rejects_stop_without_admin() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    state.set_in_process(false);

    let (mut client, server) = UnixStream::pair().unwrap();
    let st = state.clone();
    // Simulate external caller PID: 99999
    let handle = std::thread::spawn(move || {
        let _ = handle_client_with_peer(server, st, Some(99999));
    });

    let payload = format!("{}\n", json!({ "action": "stop" }));
    client.write_all(payload.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    handle.join().unwrap();

    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("stopping the daemon requires explicit administrative authorization"));
    assert!(!state.shutdown.is_shutting_down());
}

#[test]
fn test_standalone_daemon_accepts_stop_with_admin() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    state.set_in_process(false);

    let (mut client, server) = UnixStream::pair().unwrap();
    let st = state.clone();
    // Simulate external caller PID: 99999 with admin: true
    let handle = std::thread::spawn(move || {
        let _ = handle_client_with_peer(server, st, Some(99999));
    });

    let payload = format!("{}\n", json!({ "action": "stop", "admin": true }));
    client.write_all(payload.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    handle.join().unwrap();

    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert!(state.shutdown.is_shutting_down());
}

#[test]
fn test_same_process_caller_authorized_to_stop() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    state.set_in_process(true);

    let (mut client, server) = UnixStream::pair().unwrap();
    let st = state.clone();
    // Caller PID is current process PID
    let my_pid = std::process::id();
    let handle = std::thread::spawn(move || {
        let _ = handle_client_with_peer(server, st, Some(my_pid));
    });

    // Does not require admin: true because caller is in the same process
    let payload = format!("{}\n", json!({ "action": "stop" }));
    client.write_all(payload.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    handle.join().unwrap();

    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], true);
    assert!(state.shutdown.is_shutting_down());
}

#[test]
fn test_daemon_fail_closed_when_peer_pid_none() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));
    state.set_in_process(true);

    // 1. In-process daemon with peer_pid == None fails closed (rejects external stop)
    let (mut client, server) = UnixStream::pair().unwrap();
    let st = state.clone();
    let handle = std::thread::spawn(move || {
        let _ = handle_client_with_peer(server, st, None);
    });

    let payload = format!("{}\n", json!({ "action": "stop", "admin": true }));
    client.write_all(payload.as_bytes()).unwrap();
    client.flush().unwrap();

    let mut reader = BufReader::new(client);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    handle.join().unwrap();

    let resp: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(resp["ok"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("cannot terminate in-process daemon"));
    assert!(!state.shutdown.is_shutting_down());

    // 2. Standalone daemon with peer_pid == None without admin fails closed
    state.set_in_process(false);
    let (mut client2, server2) = UnixStream::pair().unwrap();
    let st2 = state.clone();
    let handle2 = std::thread::spawn(move || {
        let _ = handle_client_with_peer(server2, st2, None);
    });

    let payload2 = format!("{}\n", json!({ "action": "stop" }));
    client2.write_all(payload2.as_bytes()).unwrap();
    client2.flush().unwrap();

    let mut reader2 = BufReader::new(client2);
    let mut line2 = String::new();
    reader2.read_line(&mut line2).unwrap();
    handle2.join().unwrap();

    let resp2: Value = serde_json::from_str(&line2).unwrap();
    assert_eq!(resp2["ok"], false);
    assert!(resp2["error"]
        .as_str()
        .unwrap()
        .contains("stopping the daemon requires explicit administrative authorization"));
    assert!(!state.shutdown.is_shutting_down());
}

#[test]
fn test_programmatic_shutdown_via_handle() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = env::var_os("XDG_RUNTIME_DIR");
    env::set_var("XDG_RUNTIME_DIR", runtime.path());

    let storage_dir = tempdir().unwrap();
    let storage_mgr = StorageManager::new(storage_dir.path().join("data.json"));
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let server = DaemonServer::new(state.clone());
    let handle = server.spawn().expect("failed to spawn daemon server");

    // Ping to ensure daemon is ready
    let ping_res = send_daemon_request(&json!({ "action": "ping" })).expect("ping failed");
    assert_eq!(ping_res["ok"], true);

    // Trigger programmatic shutdown
    assert!(!handle.is_shutting_down());
    handle.stop();
    assert!(handle.is_shutting_down());

    let join_res = handle.join().expect("daemon thread panicked");
    assert!(join_res.is_ok());

    assert!(!get_socket_path().exists());

    match old_runtime {
        Some(val) => env::set_var("XDG_RUNTIME_DIR", val),
        None => env::remove_var("XDG_RUNTIME_DIR"),
    }
}

#[test]
fn test_server_url_switch_does_not_abort_process() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = env::var_os("XDG_RUNTIME_DIR");
    env::set_var("XDG_RUNTIME_DIR", runtime.path());

    let config_dir = tempdir().unwrap();
    let config_path = config_dir.path().join("config.json");
    let storage_path = config_dir.path().join("data.json");

    let storage_mgr = StorageManager::new(storage_path);
    let state = Arc::new(DaemonState::new(storage_mgr.clone(), 15));
    let handle = DaemonServer::new(state.clone())
        .spawn()
        .expect("failed to spawn daemon");

    // Ping to ensure daemon is running
    let ping_res = send_daemon_request(&json!({ "action": "ping" })).expect("ping failed");
    assert_eq!(ping_res["ok"], true);

    // Perform server URL update (ADR 0008 flow sends wipe_quick_unlock + stop)
    let config_mgr = crate::config::ConfigManager::new(Some(&config_path));
    let keyring_mgr = crate::keyring::KeyringManager::default();
    let update_opts = crate::config::ConfigUpdateOptions {
        server_url: Some("https://new.vault.example.com".to_string()),
        ..Default::default()
    };
    let res = config_mgr.update_config(update_opts, &storage_mgr, &keyring_mgr);
    assert!(res.is_ok(), "config update failed: {:?}", res);

    // Daemon thread joins cleanly and host test continues executing
    let join_res = handle.join().expect("daemon thread panicked");
    assert!(join_res.is_ok());

    match old_runtime {
        Some(val) => env::set_var("XDG_RUNTIME_DIR", val),
        None => env::remove_var("XDG_RUNTIME_DIR"),
    }
}

#[test]
fn test_is_omawarden_binary() {
    assert!(is_omawarden_binary(Path::new("/usr/bin/omawarden")));
    assert!(is_omawarden_binary(Path::new("/usr/local/bin/omawarden")));
    assert!(is_omawarden_binary(Path::new("omawarden")));
    assert!(is_omawarden_binary(Path::new("omawarden.exe")));
    assert!(is_omawarden_binary(Path::new("/opt/bin/omawarden.exe")));

    assert!(!is_omawarden_binary(Path::new(
        "/usr/bin/nsh-app-omawarden-app"
    )));
    assert!(!is_omawarden_binary(Path::new("/usr/bin/omawarden-app")));
    assert!(!is_omawarden_binary(Path::new(
        "/target/debug/deps/omawarden-f3624269721e171b"
    )));
    assert!(!is_omawarden_binary(Path::new("/bin/bash")));
}

#[test]
fn test_resolve_daemon_binary_foreign_host_resolves_path() {
    let foreign_exe = Path::new("/usr/bin/nsh-app-omawarden-app");
    let canonical_cli = PathBuf::from("/usr/bin/omawarden");

    let res =
        resolve_daemon_binary_custom(&DaemonLaunchStrategy::Auto, Some(foreign_exe), |name| {
            if name == "omawarden" {
                Ok(canonical_cli.clone())
            } else {
                Err(which::Error::CannotFindBinaryPath)
            }
        });

    assert_eq!(res.unwrap(), canonical_cli);
}

#[test]
fn test_resolve_daemon_binary_foreign_host_not_found_fails_cleanly() {
    let foreign_exe = Path::new("/usr/bin/nsh-app-omawarden-app");

    let res = resolve_daemon_binary_custom(&DaemonLaunchStrategy::Auto, Some(foreign_exe), |_| {
        Err(which::Error::CannotFindBinaryPath)
    });

    let err = res.expect_err("foreign host should fail when omawarden is not in PATH");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert!(err.to_string().contains("Could not locate 'omawarden'"));
}

#[test]
fn test_resolve_daemon_binary_strategies() {
    // Disabled strategy
    let dis_res = resolve_daemon_binary_custom(
        &DaemonLaunchStrategy::Disabled,
        Some(Path::new("/usr/bin/omawarden")),
        |_| Ok(PathBuf::from("/usr/bin/omawarden")),
    );
    assert_eq!(dis_res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);

    // InProcess strategy
    let inp_res = resolve_daemon_binary_custom(
        &DaemonLaunchStrategy::InProcess,
        Some(Path::new("/usr/bin/omawarden")),
        |_| Ok(PathBuf::from("/usr/bin/omawarden")),
    );
    assert_eq!(inp_res.unwrap_err().kind(), io::ErrorKind::Unsupported);

    // Explicit strategy - existing file
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let exp_res = resolve_daemon_binary_custom(
        &DaemonLaunchStrategy::Explicit(tmp.path().to_path_buf()),
        None,
        |_| Err(which::Error::CannotFindBinaryPath),
    );
    assert_eq!(exp_res.unwrap(), tmp.path());

    // Explicit strategy - missing file
    let missing = PathBuf::from("/tmp/nonexistent-omawarden-binary-for-test");
    let exp_missing =
        resolve_daemon_binary_custom(&DaemonLaunchStrategy::Explicit(missing), None, |_| {
            Err(which::Error::CannotFindBinaryPath)
        });
    assert_eq!(exp_missing.unwrap_err().kind(), io::ErrorKind::NotFound);
}

#[test]
fn test_daemon_launch_strategy_env_and_global_config() {
    let _lock = crate::env_lock();
    reset_daemon_launch_strategy();

    // 1. Programmatic global setting
    set_daemon_launch_strategy(DaemonLaunchStrategy::Disabled);
    assert_eq!(daemon_launch_strategy(), DaemonLaunchStrategy::Disabled);

    set_daemon_launch_strategy(DaemonLaunchStrategy::InProcess);
    assert_eq!(daemon_launch_strategy(), DaemonLaunchStrategy::InProcess);

    reset_daemon_launch_strategy();
    assert_eq!(daemon_launch_strategy(), DaemonLaunchStrategy::Auto);

    // 2. OMA_DAEMON_LAUNCH_STRATEGY env keywords
    let old_strat = env::var_os("OMA_DAEMON_LAUNCH_STRATEGY");
    let old_bin = env::var_os("OMA_DAEMON_BIN");
    env::remove_var("OMA_DAEMON_BIN");

    for val in &["system", "system-cli", "cli", "auto"] {
        env::set_var("OMA_DAEMON_LAUNCH_STRATEGY", val);
        assert_eq!(daemon_launch_strategy(), DaemonLaunchStrategy::Auto);
    }

    for val in &["disabled", "none", "off", "false"] {
        env::set_var("OMA_DAEMON_LAUNCH_STRATEGY", val);
        assert_eq!(daemon_launch_strategy(), DaemonLaunchStrategy::Disabled);
    }

    for val in &["in-process", "inprocess", "host"] {
        env::set_var("OMA_DAEMON_LAUNCH_STRATEGY", val);
        assert_eq!(daemon_launch_strategy(), DaemonLaunchStrategy::InProcess);
    }

    // Explicit path with uppercase preserving
    env::set_var("OMA_DAEMON_LAUNCH_STRATEGY", "/Opt/OmaWarden/omawarden");
    assert_eq!(
        daemon_launch_strategy(),
        DaemonLaunchStrategy::Explicit(PathBuf::from("/Opt/OmaWarden/omawarden"))
    );

    // OMA_DAEMON_BIN overrides OMA_DAEMON_LAUNCH_STRATEGY
    env::set_var("OMA_DAEMON_BIN", "/Custom/Bin/omawarden");
    assert_eq!(
        daemon_launch_strategy(),
        DaemonLaunchStrategy::Explicit(PathBuf::from("/Custom/Bin/omawarden"))
    );

    match old_strat {
        Some(v) => env::set_var("OMA_DAEMON_LAUNCH_STRATEGY", v),
        None => env::remove_var("OMA_DAEMON_LAUNCH_STRATEGY"),
    }
    match old_bin {
        Some(v) => env::set_var("OMA_DAEMON_BIN", v),
        None => env::remove_var("OMA_DAEMON_BIN"),
    }
    reset_daemon_launch_strategy();
}

#[test]
fn test_ensure_daemon_running_in_foreign_host_refuses_to_spawn_foreign_host() {
    let _lock = crate::env_lock();
    let runtime = tempdir().unwrap();
    let old_runtime = env::var_os("XDG_RUNTIME_DIR");
    env::set_var("XDG_RUNTIME_DIR", runtime.path());

    // Ensure no daemon is running at this socket
    assert!(!get_socket_path().exists());

    // Create a simulated foreign host executable (e.g. nsh-app-omawarden-app)
    // that writes a sentinel file if ever invoked with arguments.
    let host_dir = tempdir().unwrap();
    let sentinel_path = host_dir.path().join("sentinel.txt");
    let foreign_host_path = host_dir.path().join("nsh-app-omawarden-app");
    let script = format!(
        "#!/bin/sh\necho 'invoked' > {}\nexit 0\n",
        sentinel_path.display()
    );
    fs::write(&foreign_host_path, script).unwrap();
    fs::set_permissions(&foreign_host_path, fs::Permissions::from_mode(0o755)).unwrap();

    // 1. Resolution inside simulated foreign host refuses to return the foreign host executable
    let res = resolve_daemon_binary_custom(
        &DaemonLaunchStrategy::Auto,
        Some(&foreign_host_path),
        |_| Err(which::Error::CannotFindBinaryPath),
    );
    let err = res.expect_err("foreign host should never be returned as daemon executable");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);

    // Verify the simulated foreign host binary was never executed
    assert!(
        !sentinel_path.exists(),
        "foreign host binary must not be invoked during resolution"
    );

    // 2. Calling with Disabled strategy fails closed immediately without spawning
    let res = ensure_daemon_running_with_strategy(&DaemonLaunchStrategy::Disabled);
    match res {
        Err(DispatchError::LaunchFailed(msg)) => {
            assert!(msg.contains("disabled"));
        }
        other => panic!("expected LaunchFailed error, got: {:?}", other),
    }

    assert!(!get_socket_path().exists());
    assert!(!sentinel_path.exists());

    match old_runtime {
        Some(val) => env::set_var("XDG_RUNTIME_DIR", val),
        None => env::remove_var("XDG_RUNTIME_DIR"),
    }
}

#[test]
fn test_daemon_client_builder_and_methods() {
    let _lock = crate::env_lock();
    let default_client = DaemonClient::new();
    assert_eq!(default_client.socket_path(), get_socket_path());
    assert_eq!(
        default_client.launch_strategy(),
        &DaemonLaunchStrategy::Auto
    );

    let custom_path = PathBuf::from("/tmp/custom_omawarden.sock");
    let custom_client = DaemonClient::new()
        .with_socket_path(&custom_path)
        .with_launch_strategy(DaemonLaunchStrategy::InProcess)
        .with_timeout(Some(Duration::from_secs(5)));

    assert_eq!(custom_client.socket_path(), custom_path);
    assert_eq!(
        custom_client.launch_strategy(),
        &DaemonLaunchStrategy::InProcess
    );
    assert_eq!(custom_client.timeout(), Some(Duration::from_secs(5)));
    assert_eq!(custom_client.with_timeout(None).timeout(), None);

    // Connect on non-existent socket returns NotSent
    let missing_client = DaemonClient::new().with_socket_path("/tmp/nonexistent-omawarden.sock");
    assert_eq!(
        missing_client.connect().unwrap_err(),
        DispatchError::NotSent
    );
}

#[test]
fn test_multi_client_differing_commits_coexistence() {
    let runtime = tempdir().unwrap();
    let storage_dir = tempdir().unwrap();
    let storage_mgr = StorageManager::new(storage_dir.path().join("data.json"));
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let socket_path = runtime.path().join("omawarden.sock");
    let server = DaemonServer::new(state.clone()).with_socket_path(socket_path.clone());
    let handle = server.spawn().expect("failed to spawn daemon server");

    // Client 1: Simulating omawarden-app built from commit "commit-app-v1"
    let app_client = DaemonClient::new().with_socket_path(&socket_path);
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(ping) = app_client.ping() {
            assert_eq!(ping["ok"], true);
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(ready, "daemon did not become ready in time");

    let app_ping = app_client
        .send(&json!({
            "action": "ping",
            "client": { "name": "omawarden-app", "version": "1.0.0", "commit": "commit-app-v1" }
        }))
        .expect("app client ping failed");
    assert_eq!(app_ping["ok"], true);
    assert_eq!(app_ping["protocol_version"], 1);

    // Client 2: Simulating Overlay CLI built from commit "commit-cli-v2"
    let cli_client = DaemonClient::new().with_socket_path(&socket_path);
    let cli_ping = cli_client
        .send(&json!({
            "action": "ping",
            "client": { "name": "omawarden-cli", "version": "0.11.0", "commit": "commit-cli-v2" }
        }))
        .expect("cli client ping failed");
    assert_eq!(cli_ping["ok"], true);
    assert_eq!(cli_ping["protocol_version"], 1);

    // Both clients can query status without stopping or replacing the server
    let app_status = app_client
        .send(&json!({ "action": "status" }))
        .expect("app client status failed");
    assert_eq!(app_status["ok"], true);

    let cli_status = cli_client
        .send(&json!({ "action": "status" }))
        .expect("cli client status failed");
    assert_eq!(cli_status["ok"], true);

    // Daemon server is still alive and handling requests
    assert!(!handle.is_shutting_down());

    // Clean programmatic shutdown at end of test
    handle.stop();
    let join_res = handle.join().expect("daemon thread panicked");
    assert!(join_res.is_ok());
}

#[test]
fn test_daemon_cipher_resolve_and_delete_privileged_gating() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("daemon_data.json");
    let storage_mgr = StorageManager::new(path);
    let state = Arc::new(DaemonState::new(storage_mgr, 15));

    let send_req = |req: Value| -> Value {
        let (mut client, server) = UnixStream::pair().unwrap();
        let st = state.clone();
        let handle = std::thread::spawn(move || {
            let _ = handle_client(server, st);
        });
        let payload = format!("{}\n", req);
        client.write_all(payload.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        handle.join().unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // 1. Locked: cipher_resolve & cipher_delete must fail closed
    *state.vault_mgr.is_unlocked.write().unwrap() = false;
    let res_resolve_locked = send_req(json!({ "action": "cipher_resolve", "target": "site" }));
    assert_eq!(res_resolve_locked["ok"], false);
    assert_eq!(res_resolve_locked["outcome"], "rejected");
    assert_eq!(
        res_resolve_locked["error"],
        "Unlock the vault before deleting a cipher."
    );

    let res_delete_locked = send_req(json!({ "action": "cipher_delete", "id": "uuid-1" }));
    assert_eq!(res_delete_locked["ok"], false);
    assert_eq!(res_delete_locked["outcome"], "rejected");
    assert_eq!(
        res_delete_locked["error"],
        "Unlock the vault before deleting a cipher."
    );

    let res_update_locked = send_req(json!({ "action": "cipher_update", "id": "uuid-1" }));
    assert_eq!(res_update_locked["ok"], false);
    assert_eq!(res_update_locked["outcome"], "rejected");
    assert_eq!(
        res_update_locked["error"],
        "Unlock the vault before editing a cipher."
    );

    let res_resolve_edit_locked =
        send_req(json!({ "action": "cipher_resolve", "target": "site", "purpose": "edit" }));
    assert_eq!(res_resolve_edit_locked["ok"], false);
    assert_eq!(res_resolve_edit_locked["outcome"], "rejected");
    assert_eq!(
        res_resolve_edit_locked["error"],
        "Unlock the vault before editing a cipher."
    );

    // 2. Unlocked: cipher_resolve returns redacted metadata (no credentials)
    *state.vault_mgr.is_unlocked.write().unwrap() = true;
    let raw_item = json!({
        "id": "cipher-uuid-9999",
        "name": "Secret Bank Account",
        "type": 1,
        "login": {
            "username": "user",
            "password": "plaintext_password_that_must_not_leak",
            "totp": "seed123"
        }
    });
    let items = state.vault_mgr.parse_raw_items(&[raw_item]);
    *state.vault_mgr.decrypted_items.write().unwrap() = items;

    let res_resolve_ok =
        send_req(json!({ "action": "cipher_resolve", "target": "Secret Bank Account" }));
    assert_eq!(res_resolve_ok["ok"], true);
    let resolved_item = &res_resolve_ok["item"];
    assert_eq!(resolved_item["id"], "cipher-uuid-9999");
    assert_eq!(resolved_item["name"], "Secret Bank Account");
    assert_eq!(resolved_item["type"], "login");
    // Verify password, totp, and login details are NOT exposed over IPC
    assert!(resolved_item.get("login").is_none());
    assert!(resolved_item.get("password").is_none());

    // 3. Unlocked: cipher_resolve for nonexistent returns error
    let res_resolve_not_found =
        send_req(json!({ "action": "cipher_resolve", "target": "Nonexistent" }));
    assert_eq!(res_resolve_not_found["ok"], false);
    assert_eq!(
        res_resolve_not_found["error"],
        "Cipher 'Nonexistent' not found in vault."
    );
}

#[test]
fn test_lock_ipc_reports_the_shared_epoch() {
    let _environment = crate::env_lock();
    let runtime = tempdir().unwrap();
    let epoch_dir = tempdir().unwrap();
    let config_dir = tempdir().unwrap();
    let mut env = crate::test_support::EnvGuard::new();
    env.set("XDG_RUNTIME_DIR", runtime.path());
    env.set("OMAWARDEN_CONFIG_DIR", config_dir.path());
    env.remove("WAYLAND_DISPLAY");
    env.remove("WAYLAND_SOCKET");
    std::fs::write(epoch_dir.path().join("omawarden.lock-epoch"), "10").unwrap();

    let mut vault = VaultManager::new(
        "",
        Some(StorageManager::new(runtime.path().join("data.json"))),
        None,
    );
    vault.lock_epoch_dir = Some(epoch_dir.path().to_path_buf());
    let mut state = DaemonState::new(StorageManager::new(runtime.path().join("data.json")), 15);
    state.vault_mgr = Arc::new(vault);
    let state = Arc::new(state);
    let (mut client, server) = UnixStream::pair().unwrap();
    let handled = {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = handle_client(server, state);
        })
    };
    writeln!(client, "{}", json!({"action": "lock"})).unwrap();
    client.flush().unwrap();
    let mut line = String::new();
    BufReader::new(client).read_line(&mut line).unwrap();
    handled.join().unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["outputs_cleared"], true);
    assert_eq!(reply["lock_epoch"], 11);
    assert_eq!(
        std::fs::read_to_string(epoch_dir.path().join("omawarden.lock-epoch")).unwrap(),
        "11"
    );
}

#[test]
fn test_lock_advances_epoch_even_when_cleanup_is_pending() {
    let _environment = crate::env_lock();
    let runtime = tempdir().unwrap();
    let cache_dir = tempdir().unwrap();
    let epoch_dir = tempdir().unwrap();
    let config_dir = tempdir().unwrap();
    let mut env = crate::test_support::EnvGuard::new();
    env.set("XDG_RUNTIME_DIR", runtime.path());
    env.set("OMAWARDEN_CONFIG_DIR", config_dir.path());
    env.set("WAYLAND_DISPLAY", "fixture-wayland");
    env.set(
        "PATH",
        format!("{}:/usr/bin:/bin", runtime.path().display()),
    );

    let wl_copy = runtime.path().join("wl-copy");
    crate::write_test_executable(
        &wl_copy,
        "#!/bin/sh\n\
         if [ \"${1:-}\" = --clear ]; then\n\
           [ -e \"$XDG_RUNTIME_DIR/fail-clear\" ] && exit 1\n\
           exec /usr/bin/rm -f \"$XDG_RUNTIME_DIR/selection\"\n\
         fi\n\
         exec /usr/bin/cat > \"$XDG_RUNTIME_DIR/selection\"\n",
    );
    std::fs::write(runtime.path().join("fail-clear"), "").unwrap();
    std::fs::write(epoch_dir.path().join("omawarden.lock-epoch"), "80").unwrap();

    let mut vault = crate::vault::tests::seeded_vault(cache_dir.path(), "master-pw");
    vault.lock_epoch_dir = Some(epoch_dir.path().to_path_buf());
    vault.unlock("master-pw").unwrap();
    let storage_mgr = vault.storage_mgr.clone();
    let mut state = DaemonState::new(storage_mgr, 0);
    state.vault_mgr = Arc::new(vault);

    let (outputs_cleared, lock_epoch) = state.lock_with_epoch();
    assert!(!outputs_cleared, "the failing clear must be reported");
    assert_eq!(lock_epoch, Some(81));
    assert_eq!(
        std::fs::read_to_string(epoch_dir.path().join("omawarden.lock-epoch")).unwrap(),
        "81"
    );
}
