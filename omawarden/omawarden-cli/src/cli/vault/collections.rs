use omawarden_engine::daemon::ensure_daemon_capability;
use omawarden_engine::vault::{
    validate_collection_reassignment_flags, CollectionReassignmentInput,
};
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::process::ExitCode;

use super::super::client::{resolve_target_cipher, submit_cipher_mutation};
use super::super::io::emit_vault_error;

pub(crate) fn run(
    target: String,
    collection_ids: Vec<String>,
    add: Vec<String>,
    remove: Vec<String>,
    json: bool,
) -> ExitCode {
    let reassignment = match validate_collection_reassignment_flags(&collection_ids, &add, &remove)
    {
        Ok(input) => input,
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
    let is_interactive =
        (std::io::stdin().is_terminal() || std::env::var_os("OMA_FORCE_PROMPT").is_some()) && !json;

    let resolved = match resolve_target_cipher(
        &target,
        "collections",
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
    if !is_org {
        emit_vault_error(
            json,
            "Collection assignment is only supported for Organization ciphers.",
        );
        return ExitCode::FAILURE;
    }

    let can_edit = resolved
        .get("edit")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !can_edit {
        emit_vault_error(
            json,
            "You do not have permission to edit collections on this Organization cipher.",
        );
        return ExitCode::FAILURE;
    }

    let can_view_password = resolved
        .get("view_password")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !can_view_password {
        emit_vault_error(
            json,
            "Cannot modify collections on this Organization cipher because passwords are hidden.",
        );
        return ExitCode::FAILURE;
    }

    let mut daemon_req = match reassignment {
        CollectionReassignmentInput::Replace(cols) => json!({
            "action": "cipher_collections",
            "id": item_id,
            "collection_ids": cols,
        }),
        CollectionReassignmentInput::Delta { add, remove } => json!({
            "action": "cipher_collections",
            "id": item_id,
            "add": add,
            "remove": remove,
        }),
    };
    if let Some(ref ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            } else {
                let unavailable = receipt
                    .get("unavailable")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if unavailable {
                    let id = receipt["id"].as_str().unwrap_or(&item_id);
                    let name = receipt["name"].as_str().unwrap_or(&item_name);
                    println!(
                        "Updated collections for cipher \"{}\" ({}). You no longer have access to this cipher; it has been removed from the local vault cache.",
                        name, id
                    );
                } else {
                    let id = receipt["item"]["id"]
                        .as_str()
                        .or_else(|| receipt["id"].as_str())
                        .unwrap_or(&item_id);
                    let name = receipt["item"]["name"].as_str().unwrap_or(&item_name);
                    println!("Updated collections for cipher \"{}\" ({}).", name, id);
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to update cipher collections");
            emit_vault_error(json, err_msg);
            ExitCode::FAILURE
        }
    }
}
