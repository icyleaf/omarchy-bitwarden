use clap::Subcommand;
use omawarden_engine::attachment::get_attachment;
use serde_json::json;
use std::process::ExitCode;

#[derive(Subcommand)]
pub(crate) enum AttachmentAction {
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
