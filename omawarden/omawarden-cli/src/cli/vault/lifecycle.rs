use omawarden_engine::daemon::ensure_daemon_capability;
use omawarden_engine::vault::validate_org_share_scope;
use serde_json::{json, Value};
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use super::super::client::{resolve_target_cipher, submit_cipher_mutation};
use super::super::io::emit_vault_error;

pub(crate) fn run_delete(
    target: String,
    permanent: bool,
    trash: bool,
    yes: bool,
    json: bool,
) -> ExitCode {
    let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
    let is_interactive = (std::io::stdin().is_terminal()
        || std::env::var_os("OMA_FORCE_PROMPT").is_some())
        && !yes
        && !json;

    let resolved = match resolve_target_cipher(
        &target,
        "delete",
        client_ctx.as_ref(),
        is_interactive,
        json,
        trash,
    ) {
        Ok(item) => item,
        Err(code) => return code,
    };

    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
    let item_name = resolved["name"].as_str().unwrap_or("").to_string();

    let is_org = resolved
        .get("organization_id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if is_org {
        let can_delete = resolved
            .get("can_delete")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !can_delete {
            emit_vault_error(
                json,
                "You do not have permission to delete this Organization cipher.",
            );
            return ExitCode::FAILURE;
        }
        if let Err(err_msg) =
            ensure_daemon_capability(omawarden_engine::daemon::CAPABILITY_ORG_WRITE)
        {
            emit_vault_error(json, &err_msg);
            return ExitCode::FAILURE;
        }
    }

    // When --trash is passed, permanent deletion is implied (DELETE /ciphers/{id})
    let is_permanent = trash || permanent;
    let action_verb = if is_permanent {
        "Permanently delete"
    } else {
        "Delete"
    };

    if is_interactive {
        eprint!("{action_verb} item '{item_name}'? [y/N] ");
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Deletion aborted.");
            return ExitCode::FAILURE;
        }
        let trimmed = input.trim();
        if !trimmed.eq_ignore_ascii_case("y") && !trimmed.eq_ignore_ascii_case("yes") {
            eprintln!("Deletion aborted.");
            return ExitCode::FAILURE;
        }
    }

    let action = if trash {
        "cipher_delete_trash"
    } else {
        "cipher_delete"
    };
    let mut daemon_req = json!({
        "action": action,
        "id": item_id,
        "permanent": is_permanent,
    });
    if let Some(ref ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            } else {
                let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
                let name = receipt["item"]["name"].as_str().unwrap_or(&item_name);
                if is_permanent {
                    println!("Permanently deleted cipher \"{}\" ({}).", name, id);
                } else {
                    println!("Deleted cipher \"{}\" ({}).", name, id);
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to delete cipher");
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": err_msg,
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("Error: {}", err_msg);
            }
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_restore(target: String, json: bool) -> ExitCode {
    let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
    let is_interactive =
        (std::io::stdin().is_terminal() || std::env::var_os("OMA_FORCE_PROMPT").is_some()) && !json;

    let resolved = match resolve_target_cipher(
        &target,
        "restore",
        client_ctx.as_ref(),
        is_interactive,
        json,
        true,
    ) {
        Ok(item) => item,
        Err(code) => return code,
    };

    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
    let item_name = resolved["name"].as_str().unwrap_or("").to_string();

    let is_org = resolved
        .get("organization_id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if is_org {
        let can_restore = resolved
            .get("can_restore")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !can_restore {
            emit_vault_error(
                json,
                "You do not have permission to restore this Organization cipher.",
            );
            return ExitCode::FAILURE;
        }
        if let Err(err_msg) =
            ensure_daemon_capability(omawarden_engine::daemon::CAPABILITY_ORG_WRITE)
        {
            emit_vault_error(json, &err_msg);
            return ExitCode::FAILURE;
        }
    }

    let mut daemon_req = json!({
        "action": "cipher_restore",
        "id": item_id,
    });
    if let Some(ref ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            } else {
                let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
                let name = receipt["item"]["name"].as_str().unwrap_or(&item_name);
                println!("Restored cipher \"{}\" ({}).", name, id);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to restore cipher");
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": err_msg,
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("Error: {}", err_msg);
            }
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn run_share(
    target: String,
    organization_id: String,
    collection_ids: Vec<String>,
    yes: bool,
    json: bool,
) -> ExitCode {
    if json && !yes {
        emit_vault_error(
            true,
            "Sharing a cipher transfers ownership irreversibly to the Organization. Pass --yes to confirm in --json mode.",
        );
        return ExitCode::FAILURE;
    }

    let (trimmed_org_id, clean_cols) =
        match validate_org_share_scope(&organization_id, &collection_ids) {
            Ok(scope) => scope,
            Err(err_msg) => {
                emit_vault_error(json, &err_msg);
                return ExitCode::FAILURE;
            }
        };

    if let Err(err_msg) = ensure_daemon_capability(omawarden_engine::daemon::CAPABILITY_ORG_WRITE) {
        emit_vault_error(json, &err_msg);
        return ExitCode::FAILURE;
    }

    let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
    let is_interactive = (std::io::stdin().is_terminal()
        || std::env::var_os("OMA_FORCE_PROMPT").is_some())
        && !yes
        && !json;

    if !yes && !is_interactive {
        emit_vault_error(
            json,
            "Sharing a cipher transfers ownership irreversibly to the Organization. Pass --yes to confirm in non-interactive mode.",
        );
        return ExitCode::FAILURE;
    }

    let resolved = match resolve_target_cipher(
        &target,
        "share",
        client_ctx.as_ref(),
        is_interactive,
        json,
        false,
    ) {
        Ok(item) => item,
        Err(code) => return code,
    };

    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
    let item_name = resolved["name"].as_str().unwrap_or("").to_string();

    let is_org = resolved
        .get("organization_id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if is_org {
        emit_vault_error(
            json,
            "Cipher already belongs to an Organization and cannot be shared again.",
        );
        return ExitCode::FAILURE;
    }

    if is_interactive {
        eprintln!(
            "Warning: Sharing '{}' transfers ownership permanently to Organization '{}'. This action is irreversible.",
            item_name, trimmed_org_id
        );
        eprint!(
            "Transfer ownership to Organization '{}'? [y/N] ",
            trimmed_org_id
        );
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            eprintln!("Share aborted.");
            return ExitCode::FAILURE;
        }
        let trimmed = input.trim();
        if !trimmed.eq_ignore_ascii_case("y") && !trimmed.eq_ignore_ascii_case("yes") {
            eprintln!("Share aborted.");
            return ExitCode::FAILURE;
        }
    }

    let mut daemon_req = json!({
        "action": "cipher_share",
        "id": item_id,
        "organization_id": trimmed_org_id,
        "collection_ids": clean_cols,
    });
    if let Some(ref ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            } else {
                let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
                let name = receipt["item"]["name"].as_str().unwrap_or(&item_name);
                println!(
                    "Shared cipher \"{}\" ({}) to Organization {}.",
                    name, id, trimmed_org_id
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to share cipher");
            emit_vault_error(json, err_msg);
            ExitCode::FAILURE
        }
    }
}
