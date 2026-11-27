use omawarden_engine::config::Config;
use omawarden_engine::daemon::{run_daemon_server, DaemonState};
use omawarden_engine::storage::StorageManager;
use serde_json::{json, Value};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

pub(crate) fn run(
    auto_lock: Option<u64>,
    stop: bool,
    action: Option<String>,
    cfg: &Config,
    config_path: Option<&Path>,
) -> ExitCode {
    if stop || action.as_deref() == Some("stop") {
        let client = omawarden_engine::daemon::DaemonClient::new();
        let resp = client.send_raw(&json!({ "action": "stop", "admin": true }));
        match resp {
            Ok(val) if val.get("ok") == Some(&Value::Bool(true)) => {
                println!("{}", serde_json::to_string_pretty(&val).unwrap());
                ExitCode::SUCCESS
            }
            Ok(val) => {
                eprintln!("{}", serde_json::to_string_pretty(&val).unwrap());
                ExitCode::FAILURE
            }
            Err(omawarden_engine::daemon::DispatchError::NotSent) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "status": "stopped",
                        "message": "Daemon is not running."
                    }))
                    .unwrap()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": e.to_string(),
                    }))
                    .unwrap()
                );
                ExitCode::FAILURE
            }
        }
    } else {
        let default_auto_lock = if cfg.auto_lock_minutes >= 0 {
            cfg.auto_lock_minutes as u64
        } else {
            15
        };
        let auto_lock_mins = auto_lock.unwrap_or(default_auto_lock);
        let storage_mgr = match config_path {
            Some(cp) => {
                if let Some(parent) = cp.parent() {
                    StorageManager::new(
                        parent.join(omawarden_engine::storage::DEFAULT_STORAGE_FILENAME),
                    )
                } else {
                    StorageManager::default()
                }
            }
            None => StorageManager::default(),
        };
        let state = Arc::new(DaemonState::new(storage_mgr, auto_lock_mins));
        println!(
            "Starting omawarden daemon (auto_lock: {}m)...",
            auto_lock_mins
        );
        if let Err(e) = run_daemon_server(state) {
            eprintln!("Daemon server error: {}", e);
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    }
}
