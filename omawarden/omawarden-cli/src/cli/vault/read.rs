use omawarden_engine::daemon::send_daemon_request;
use omawarden_engine::vault::VaultManager;
use serde_json::{json, Value};
use std::process::ExitCode;

pub(crate) fn run_sync() -> ExitCode {
    let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
    if let Err(e @ omawarden_engine::daemon::DispatchError::IncompatibleProtocol { .. }) =
        omawarden_engine::daemon::ensure_daemon_running()
    {
        let resp_val = json!({
            "ok": false,
            "error": e.to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&resp_val).unwrap());
        return ExitCode::FAILURE;
    }
    let mut sync_req = json!({ "action": "sync" });
    if let Some(ref ctx) = client_ctx {
        sync_req["client"] = json!(ctx);
    }
    let resp_val = match omawarden_engine::daemon::dispatch_daemon_request(&sync_req) {
        Ok(response) => response,
        Err(omawarden_engine::daemon::DispatchError::NotSent) => json!({
            "ok": false,
            "error": "Cannot reach the vault daemon. Restart it and retry synchronization."
        }),
        Err(omawarden_engine::daemon::DispatchError::Unconfirmed) => json!({
            "ok": false,
            "error": "Could not confirm synchronization. Check the vault before retrying."
        }),
        Err(omawarden_engine::daemon::DispatchError::IncompatibleProtocol {
            running,
            min_supported,
            current,
        }) => json!({
            "ok": false,
            "error": format!("Incompatible daemon protocol version {running} (supported: {min_supported}..={current}). Please restart the daemon.")
        }),
        Err(omawarden_engine::daemon::DispatchError::LaunchFailed(msg)) => json!({
            "ok": false,
            "error": format!("Could not start the daemon: {msg}")
        }),
    };
    let ok = resp_val["ok"].as_bool().unwrap_or(false);
    println!("{}", serde_json::to_string_pretty(&resp_val).unwrap());
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub(crate) fn run_list(
    vault_mgr: &VaultManager,
    category: Option<String>,
    trash: bool,
) -> ExitCode {
    if let Err(e @ omawarden_engine::daemon::DispatchError::IncompatibleProtocol { .. }) =
        omawarden_engine::daemon::ensure_daemon_running()
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": e.to_string(),
            }))
            .unwrap()
        );
        return ExitCode::FAILURE;
    }
    let st = send_daemon_request(&json!({ "action": "status" }));
    let is_unlocked = st
        .as_ref()
        .and_then(|v| v.get("is_unlocked"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_unlocked && !vault_mgr.is_unlocked() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "Vault is locked. Please unlock using 'omawarden auth unlock' first."
            }))
            .unwrap()
        );
        return ExitCode::FAILURE;
    }
    if is_unlocked && !vault_mgr.is_unlocked() {
        if let Some(daemon_resp) = send_daemon_request(&json!({ "action": "list", "trash": trash }))
        {
            if daemon_resp.get("ok") == Some(&Value::Bool(false)) {
                println!("{}", serde_json::to_string_pretty(&daemon_resp).unwrap());
                return ExitCode::FAILURE;
            }
            if let Ok(items) =
                serde_json::from_value::<Vec<omawarden_engine::vault::VaultItem>>(daemon_resp)
            {
                let filtered = vault_mgr.search(&items, "", category.as_deref());
                println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                return ExitCode::SUCCESS;
            }
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "error": "Cannot reach the vault daemon to list items."
                }))
                .unwrap()
            );
            return ExitCode::FAILURE;
        }
    }
    let items = vault_mgr.get_items_by_state(trash);
    let filtered = vault_mgr.search(&items, "", category.as_deref());
    println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
    ExitCode::SUCCESS
}

pub(crate) fn run_search(
    vault_mgr: &VaultManager,
    query: String,
    query_flag: Option<String>,
    category: Option<String>,
    trash: bool,
) -> ExitCode {
    let query = if query.is_empty() {
        query_flag.unwrap_or(query)
    } else {
        query
    };
    if let Err(e @ omawarden_engine::daemon::DispatchError::IncompatibleProtocol { .. }) =
        omawarden_engine::daemon::ensure_daemon_running()
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": e.to_string(),
            }))
            .unwrap()
        );
        return ExitCode::FAILURE;
    }
    let st = send_daemon_request(&json!({ "action": "status" }));
    let is_unlocked = st
        .as_ref()
        .and_then(|v| v.get("is_unlocked"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !is_unlocked && !vault_mgr.is_unlocked() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "Vault is locked. Please unlock using 'omawarden auth unlock' first."
            }))
            .unwrap()
        );
        return ExitCode::FAILURE;
    }
    if is_unlocked && !vault_mgr.is_unlocked() {
        if let Some(daemon_resp) = send_daemon_request(&json!({
            "action": "search",
            "query": query,
            "category": category,
            "trash": trash
        })) {
            if daemon_resp.get("ok") == Some(&Value::Bool(false)) {
                println!("{}", serde_json::to_string_pretty(&daemon_resp).unwrap());
                return ExitCode::FAILURE;
            }
            if let Ok(items) =
                serde_json::from_value::<Vec<omawarden_engine::vault::VaultItem>>(daemon_resp)
            {
                println!("{}", serde_json::to_string_pretty(&items).unwrap());
                return ExitCode::SUCCESS;
            }
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "error": "Cannot reach the vault daemon to search items."
                }))
                .unwrap()
            );
            return ExitCode::FAILURE;
        }
    }
    let results = vault_mgr.search_items_by_state(&query, category.as_deref(), trash);
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
    ExitCode::SUCCESS
}
