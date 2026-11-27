use clap::Subcommand;
use omawarden_engine::attachment::get_attachment;
use serde_json::{json, Value};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use super::client::submit_attachment_upload;
use super::io::emit_vault_error;

#[derive(Subcommand)]
pub(crate) enum AttachmentAction {
    #[command(about = "Encrypt and upload a file attachment to a vault cipher")]
    Upload {
        #[arg(long, required = true, help = "Target cipher ID")]
        item_id: String,
        #[arg(long, required = true, help = "Path to local file to upload")]
        file: PathBuf,
        #[arg(
            long,
            help = "Override stored attachment filename (single basename without separators)"
        )]
        name: Option<String>,
        #[arg(long, help = "Output result in JSON format")]
        json: bool,
        #[arg(long, hide = true)]
        expected_lock_generation: Option<u64>,
    },
    #[command(about = "Download or preview an attachment")]
    Download {
        #[arg(long, required = true)]
        item_id: String,
        #[arg(long, required = true)]
        attachment_id: String,
        #[arg(long, required = true)]
        filename: String,
        #[arg(long)]
        output_dir: Option<String>,
        #[arg(long)]
        preview: bool,
        #[arg(long, hide = true)]
        expected_lock_generation: Option<String>,
    },
    #[command(about = "Clean temporary preview attachments")]
    Clean {
        #[arg(long)]
        item_id: Option<String>,
    },
}

pub(crate) fn run(action: AttachmentAction) -> ExitCode {
    match action {
        AttachmentAction::Upload {
            item_id,
            file,
            name,
            json,
            expected_lock_generation,
        } => {
            let resolved_path = if file.is_relative() {
                env::current_dir()
                    .map(|cwd| cwd.join(&file))
                    .unwrap_or(file)
            } else {
                file
            };
            let Some(file_path_str) = resolved_path.to_str() else {
                emit_vault_error(json, "Attachment file path must be valid UTF-8.");
                return ExitCode::FAILURE;
            };

            match submit_attachment_upload(
                &item_id,
                file_path_str,
                name.as_deref(),
                expected_lock_generation,
            ) {
                Ok(resp) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else {
                        let att_name = resp["attachment"]["fileName"]
                            .as_str()
                            .unwrap_or("attachment");
                        let att_id = resp["attachment"]["id"].as_str().unwrap_or("");
                        let size_name = resp["attachment"]["sizeName"]
                            .as_str()
                            .or_else(|| resp["attachment"]["size"].as_str())
                            .unwrap_or("0 B");
                        let item_name = resp["item"]["name"].as_str().unwrap_or(&item_id);
                        println!(
                            "Uploaded attachment '{}' ({}) to '{}' [{}] (attachment ID: {})",
                            att_name, size_name, item_name, item_id, att_id
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(err_val) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&err_val).unwrap());
                    } else {
                        let msg = err_val
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("Failed to upload attachment.");
                        eprintln!("Error: {msg}");
                    }
                    ExitCode::FAILURE
                }
            }
        }
        AttachmentAction::Download {
            item_id,
            attachment_id,
            filename,
            output_dir,
            preview,
            expected_lock_generation,
        } => {
            let res = get_attachment(
                &item_id,
                &attachment_id,
                &filename,
                output_dir.as_deref(),
                preview,
                None,
                expected_lock_generation.as_deref(),
            );
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
            if res.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        AttachmentAction::Clean { item_id } => {
            match omawarden_engine::attachment::clean_previews(item_id.as_deref()) {
                Ok(()) => {
                    println!("{}", json!({ "ok": true, "status": "cleaned" }));
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    println!("{}", json!({ "ok": false, "error": error.to_string() }));
                    ExitCode::FAILURE
                }
            }
        }
    }
}
