use clap::Subcommand;
use omawarden_engine::hook::install_lock_hook;
use std::process::ExitCode;

#[derive(Subcommand)]
pub(crate) enum HookAction {
    #[command(
        about = "Install optional system-lock hook into Omarchy hooks directory (daemon also auto-detects locks natively)"
    )]
    Install,
}

pub(crate) fn run(action: HookAction) -> ExitCode {
    match action {
        HookAction::Install => match install_lock_hook(None, None) {
            Ok(path) => {
                let json_val = serde_json::json!({
                    "ok": true,
                    "installed_path": path.to_string_lossy(),
                    "note": "Lock hook installed. omawarden daemon also natively auto-detects screen lock, sleep, and Omarchy shell lock."
                });
                println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                ExitCode::SUCCESS
            }
            Err(e) => {
                let json_val = serde_json::json!({
                    "ok": false,
                    "error": e.to_string()
                });
                println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                ExitCode::FAILURE
            }
        },
    }
}
