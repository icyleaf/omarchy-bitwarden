use clap::Subcommand;
use omawarden_engine::config::Config;
use serde_json::json;
use std::process::ExitCode;

#[derive(Subcommand)]
pub(crate) enum ServerAction {
    #[command(about = "Inspect upstream server version and feature capabilities")]
    Capabilities {
        #[arg(long, help = "Force refresh capabilities from upstream server")]
        refresh: bool,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
}

pub(crate) fn run(action: ServerAction, cfg: &Config) -> ExitCode {
    match action {
        ServerAction::Capabilities { refresh, json } => {
            let client_ctx = omawarden_engine::api::probe_plugin_context();
            let mut daemon_req = json!({
                "action": "server_capabilities",
                "refresh": refresh,
            });
            if let Some(ref ctx) = client_ctx {
                daemon_req["client"] = json!(ctx);
            }

            let response_val = match omawarden_engine::daemon::dispatch_daemon_request(&daemon_req)
            {
                Ok(val) => val,
                Err(_) => match omawarden_engine::capabilities::get_or_discover_capabilities(
                    &cfg.server_url,
                    refresh,
                    client_ctx.as_ref(),
                    Some(cfg),
                ) {
                    Ok(c) => json!({
                        "ok": true,
                        "server_url": c.server_url,
                        "server_version": c.server_version,
                        "server_name": c.server_name,
                        "server_vendor_version": c.server_vendor_version,
                        "git_hash": c.git_hash,
                        "cached_at": c.cached_at,
                        "feature_states": c.feature_states,
                        "matrix": c.matrix,
                    }),
                    Err(e) => json!({
                        "ok": false,
                        "error": e,
                    }),
                },
            };

            if response_val["ok"] == true {
                if json {
                    println!("{}", serde_json::to_string_pretty(&response_val).unwrap());
                } else {
                    let server_url = response_val["server_url"]
                        .as_str()
                        .unwrap_or(&cfg.server_url);
                    println!("Server URL:     {}", server_url);
                    if let Some(n) = response_val["server_name"].as_str() {
                        println!("Server Name:    {}", n);
                    }
                    if let Some(v) = response_val["server_version"].as_str() {
                        println!("Server Version: {}", v);
                    }
                    if let Some(v) = response_val["server_vendor_version"].as_str() {
                        println!("Vendor Version: {}", v);
                    }
                    if let Some(g) = response_val["git_hash"].as_str() {
                        println!("Git Hash:       {}", g);
                    }
                    if let Some(cat) = response_val["cached_at"].as_str() {
                        println!("Cached At:      {}", cat);
                    }
                    println!("\nCapabilities Matrix:");
                    if let Some(matrix) = response_val["matrix"].as_array() {
                        for item in matrix {
                            let name = item["name"].as_str().unwrap_or("");
                            let status = item["status"].as_str().unwrap_or("");
                            let desc = item["description"].as_str().unwrap_or("");
                            let status_str = match status {
                                "supported" => "[OK] supported",
                                "disabled" => "[--] disabled",
                                "unsupported" => "[??] unsupported",
                                "deprecated" => "[!!] deprecated",
                                _ => "[??] unknown",
                            };
                            println!("  {:24} {:16} {}", name, status_str, desc);
                        }
                    }
                }
                ExitCode::SUCCESS
            } else {
                let err = response_val["error"]
                    .as_str()
                    .unwrap_or("Failed to query server capabilities");
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": err,
                        }))
                        .unwrap()
                    );
                } else {
                    eprintln!("Error: {}", err);
                }
                ExitCode::FAILURE
            }
        }
    }
}
