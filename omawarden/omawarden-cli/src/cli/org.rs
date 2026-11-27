use clap::Subcommand;
use omawarden_engine::daemon::{
    dispatch_daemon_request, ensure_daemon_capability, DispatchError, CAPABILITY_ORG_WRITE,
};
use serde_json::json;
use std::process::ExitCode;

use super::io::emit_vault_error;

#[derive(Subcommand)]
pub(crate) enum OrgAction {
    #[command(
        about = "List joined Organizations and Collections with permission metadata",
        alias = "ls"
    )]
    List {
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
}

pub(crate) fn run(action: OrgAction) -> ExitCode {
    match action {
        OrgAction::List { json } => {
            let ping = match ensure_daemon_capability(CAPABILITY_ORG_WRITE) {
                Ok(p) => p,
                Err(err_msg) => {
                    emit_vault_error(json, &err_msg);
                    return ExitCode::FAILURE;
                }
            };
            if ping["unlocked"] != true {
                emit_vault_error(json, "Unlock the vault before listing organizations.");
                return ExitCode::FAILURE;
            }
            match dispatch_daemon_request(&json!({ "action": "org_list" })) {
                Ok(resp) if resp["ok"] == true => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else {
                        let orgs = resp["organizations"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        let cols = resp["collections"].as_array().cloned().unwrap_or_default();
                        if orgs.is_empty() {
                            println!("No organizations found.");
                        } else {
                            for org in &orgs {
                                let org_id = org["id"].as_str().unwrap_or("");
                                let org_name = org["name"].as_str().unwrap_or("Organization");
                                println!("{org_name} [{org_id}]");
                                for col in cols
                                    .iter()
                                    .filter(|c| c["organization_id"].as_str() == Some(org_id))
                                {
                                    let col_id = col["id"].as_str().unwrap_or("");
                                    let col_name = col["name"].as_str().unwrap_or("Collection");
                                    let read_only = col["read_only"].as_bool().unwrap_or(true);
                                    let hide_passwords =
                                        col["hide_passwords"].as_bool().unwrap_or(true);
                                    let manage = col["manage"].as_bool().unwrap_or(false);
                                    let mut perms = Vec::new();
                                    if manage {
                                        perms.push("manage");
                                    }
                                    if read_only {
                                        perms.push("read-only");
                                    } else {
                                        perms.push("writable");
                                    }
                                    if hide_passwords {
                                        perms.push("hide-passwords");
                                    }
                                    println!("  - {col_name} [{}] ({})", col_id, perms.join(", "));
                                }
                            }
                        }
                    }
                    ExitCode::SUCCESS
                }
                Ok(resp) => {
                    let msg = resp["error"]
                        .as_str()
                        .unwrap_or("Failed to list organizations.");
                    emit_vault_error(json, msg);
                    ExitCode::FAILURE
                }
                Err(DispatchError::IncompatibleProtocol { .. }) => {
                    emit_vault_error(
                        json,
                        "Daemon protocol version is incompatible with this client.",
                    );
                    ExitCode::FAILURE
                }
                Err(e) => {
                    emit_vault_error(json, &format!("Daemon request failed: {e}"));
                    ExitCode::FAILURE
                }
            }
        }
    }
}
