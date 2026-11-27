use clap::Subcommand;
use omawarden_engine::config::Config;
use omawarden_engine::daemon::{ensure_daemon_running, send_daemon_request};
use serde_json::json;
use std::process::ExitCode;

#[derive(Subcommand)]
pub(crate) enum SshAgentAction {
    #[command(about = "Show whether the agent is enabled and running, and its socket (JSON)")]
    Status,
    #[command(about = "Start the SSH agent")]
    Start {
        #[arg(long, alias = "force", help = "Bypass server capability gating checks")]
        ignore_server_capabilities: bool,
    },
    #[command(about = "List signatures waiting for confirmation (JSON)")]
    Pending,
    #[command(about = "Answer a pending confirmation")]
    Reply {
        #[arg(help = "Prompt id from `ssh-agent pending`")]
        id: u64,
        #[arg(long, conflicts_with = "deny", required_unless_present = "deny")]
        allow: bool,
        #[arg(long)]
        deny: bool,
    },
}

pub(crate) fn run(
    ignore_server_capabilities: bool,
    action: Option<SshAgentAction>,
    cfg: &Config,
) -> ExitCode {
    match action {
        None | Some(SshAgentAction::Start { .. }) => {
            let bypass = ignore_server_capabilities
                || matches!(
                    action,
                    Some(SshAgentAction::Start {
                        ignore_server_capabilities: true
                    })
                );

            if let Err(e) = omawarden_engine::capabilities::check_feature_gating(
                &cfg.server_url,
                "ssh-key-vault-item",
                bypass,
            ) {
                let err_msg = format!("Refusing to launch SSH agent: {e}");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": err_msg,
                    }))
                    .unwrap()
                );
                return ExitCode::FAILURE;
            }

            let _ = ensure_daemon_running();
            let request = json!({
                "action": "ssh_agent_apply",
                "ignore_server_capabilities": bypass
            });
            match send_daemon_request(&request) {
                Some(resp) => {
                    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                None => {
                    eprintln!("The omawarden daemon is not responding.");
                    ExitCode::FAILURE
                }
            }
        }
        Some(sub_action) => {
            let request = match sub_action {
                SshAgentAction::Status => json!({ "action": "ssh_agent_status" }),
                SshAgentAction::Pending => json!({ "action": "ssh_agent_pending" }),
                SshAgentAction::Reply { id, allow, deny: _ } => {
                    json!({ "action": "ssh_agent_reply", "id": id, "approve": allow })
                }
                SshAgentAction::Start { .. } => unreachable!(),
            };
            let _ = ensure_daemon_running();
            match send_daemon_request(&request) {
                Some(mut resp) => {
                    if let Some(obj) = resp.as_object_mut() {
                        obj.insert("enabled".into(), json!(cfg.ssh_agent_enabled));
                        obj.insert("confirm".into(), json!(cfg.ssh_agent_confirm));
                    }
                    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    let delivered = resp
                        .get("delivered")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) && delivered {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                None => {
                    eprintln!("The omawarden daemon is not responding.");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
