use clap::Subcommand;
use serde_json::json;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use super::client::submit_cipher_mutation;
use super::io::emit_vault_error;

#[derive(Subcommand)]
pub(crate) enum FolderAction {
    #[command(about = "List all folders in the vault", alias = "ls")]
    List {
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Create a new folder in the vault")]
    Create {
        #[arg(value_name = "NAME", help = "Name of the new folder")]
        name: String,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Rename an existing folder", alias = "rename")]
    Edit {
        #[arg(value_name = "TARGET", help = "Folder UUID or name")]
        target: String,
        #[arg(long, value_name = "NEW_NAME", help = "New name for the folder")]
        name: String,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(
        about = "Delete a folder (moves its ciphers to No Folder)",
        aliases = ["rm", "remove"]
    )]
    Delete {
        #[arg(value_name = "TARGET", help = "Folder UUID or name")]
        target: String,
        #[arg(long, short = 'y', help = "Skip interactive confirmation prompt")]
        yes: bool,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
}

pub(crate) fn run(action: FolderAction) -> ExitCode {
    match action {
        FolderAction::List { json } => {
            let req = json!({ "action": "folder_list" });
            match submit_cipher_mutation(&req) {
                Ok(resp) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else {
                        let folders = resp["folders"].as_array().cloned().unwrap_or_default();
                        if folders.is_empty() {
                            println!("No folders found.");
                        } else {
                            for f in folders {
                                let id = f["id"].as_str().unwrap_or("");
                                let name = f["name"].as_str().unwrap_or("");
                                let count = f["count"].as_u64().unwrap_or(0);
                                println!("{name} ({count}) [{id}]");
                            }
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    let msg = error["error"].as_str().unwrap_or("Failed to list folders.");
                    emit_vault_error(json, msg);
                    ExitCode::FAILURE
                }
            }
        }
        FolderAction::Create { name, json } => {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                emit_vault_error(json, "Folder name cannot be empty.");
                return ExitCode::FAILURE;
            }
            let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
            let mut req = json!({
                "action": "folder_create",
                "name": trimmed,
            });
            if let Some(ref ctx) = client_ctx {
                req["client"] = json!(ctx);
            }
            match submit_cipher_mutation(&req) {
                Ok(receipt) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                    } else {
                        let id = receipt["folder"]["id"].as_str().unwrap_or("");
                        let created_name = receipt["folder"]["name"].as_str().unwrap_or(trimmed);
                        println!("Created folder \"{created_name}\" ({id}).");
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    let msg = error["error"]
                        .as_str()
                        .unwrap_or("Failed to create folder.");
                    emit_vault_error(json, msg);
                    ExitCode::FAILURE
                }
            }
        }
        FolderAction::Edit { target, name, json } => {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                emit_vault_error(json, "Folder name cannot be empty.");
                return ExitCode::FAILURE;
            }
            let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
            let mut req = json!({
                "action": "folder_update",
                "target": target,
                "name": trimmed,
            });
            if let Some(ref ctx) = client_ctx {
                req["client"] = json!(ctx);
            }
            match submit_cipher_mutation(&req) {
                Ok(receipt) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                    } else {
                        let id = receipt["folder"]["id"].as_str().unwrap_or("");
                        let updated_name = receipt["folder"]["name"].as_str().unwrap_or(trimmed);
                        println!("Renamed folder \"{updated_name}\" ({id}).");
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    let msg = error["error"]
                        .as_str()
                        .unwrap_or("Failed to rename folder.");
                    emit_vault_error(json, msg);
                    ExitCode::FAILURE
                }
            }
        }
        FolderAction::Delete { target, yes, json } => {
            let is_interactive = (io::stdin().is_terminal()
                || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                && !json;
            if !yes && !is_interactive {
                emit_vault_error(
                    json,
                    "Confirmation required to delete a folder. Pass --yes to confirm in non-interactive mode.",
                );
                return ExitCode::FAILURE;
            }

            let resolve_req = json!({
                "action": "folder_resolve",
                "target": target,
            });
            let resolved = match submit_cipher_mutation(&resolve_req) {
                Ok(resp) => resp["folder"].clone(),
                Err(error) => {
                    let msg = error["error"]
                        .as_str()
                        .unwrap_or("Failed to resolve folder.");
                    emit_vault_error(json, msg);
                    return ExitCode::FAILURE;
                }
            };
            let folder_id = resolved["id"].as_str().unwrap_or("").to_string();
            let folder_name = resolved["name"].as_str().unwrap_or("").to_string();
            let count = resolved["count"].as_u64().unwrap_or(0);

            if !yes {
                let suffix = if count == 0 {
                    "empty folder".to_string()
                } else if count == 1 {
                    "1 cipher will be moved to No Folder".to_string()
                } else {
                    format!("{count} ciphers will be moved to No Folder")
                };
                eprint!("Delete folder '{folder_name}' ({suffix})? [y/N]: ");
                let _ = io::stderr().flush();
                let mut answer = String::new();
                if io::stdin().read_line(&mut answer).is_err() {
                    eprintln!("Aborted.");
                    return ExitCode::FAILURE;
                }
                let trimmed = answer.trim().to_ascii_lowercase();
                if trimmed != "y" && trimmed != "yes" {
                    eprintln!("Aborted.");
                    return ExitCode::FAILURE;
                }
            }

            let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);
            let mut req = json!({
                "action": "folder_delete",
                "id": folder_id,
            });
            if let Some(ref ctx) = client_ctx {
                req["client"] = json!(ctx);
            }
            match submit_cipher_mutation(&req) {
                Ok(receipt) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                    } else {
                        println!("Deleted folder \"{folder_name}\" ({folder_id}).");
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    let msg = error["error"]
                        .as_str()
                        .unwrap_or("Failed to delete folder.");
                    emit_vault_error(json, msg);
                    ExitCode::FAILURE
                }
            }
        }
    }
}
