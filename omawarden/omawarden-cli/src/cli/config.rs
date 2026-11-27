use clap::Subcommand;
use omawarden_engine::config::{Config, ConfigManager, ConfigUpdateOptions};
use omawarden_engine::daemon::send_daemon_request;
use omawarden_engine::keyring::KeyringManager;
use omawarden_engine::storage::StorageManager;
use serde_json::json;
use std::path::Path;
use std::process::ExitCode;

use super::io::parse_cli_bool;

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum ConfigAction {
    #[command(about = "Get current configuration or a specific key")]
    Get {
        #[arg(help = "Optional configuration key to query")]
        key: Option<String>,
    },
    #[command(about = "Set configuration options")]
    Set {
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        identity_url: Option<String>,
        #[arg(long)]
        download_dir: Option<String>,
        #[arg(long)]
        auto_lock: Option<i64>,
        #[arg(long)]
        clipboard_clear: Option<i64>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        remember_email: Option<String>,
        #[arg(long)]
        check_updates: Option<String>,
        #[arg(long)]
        log_level: Option<String>,
        #[arg(long)]
        show_website_icons: Option<String>,
        #[arg(long)]
        remember_last_search: Option<String>,
        #[arg(long, help = "Maximum allowed attachment size in MB (default: 500)")]
        max_attachment_size: Option<u64>,
        #[arg(
            long,
            help = "Path to client certificate PEM file for mTLS (pass \"\" to clear)"
        )]
        client_cert: Option<String>,
        #[arg(long, help = "Path to separate client private key PEM file for mTLS")]
        client_key: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Serve vault SSH keys as an SSH agent (true/false)"
        )]
        ssh_agent: Option<bool>,
        #[arg(long, help = "Confirm SSH signatures: always, first-use or never")]
        ssh_agent_confirm: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Unlock via system authentication after a soft lock (true/false; ADR-0025)"
        )]
        quick_unlock: Option<bool>,
    },
}

pub(crate) fn run(
    action: ConfigAction,
    cfg: &mut Config,
    config_mgr: &ConfigManager,
    config_path: Option<&Path>,
) -> ExitCode {
    match action {
        ConfigAction::Get { key } => {
            if let Some(k) = key {
                if let Some(val) = cfg.get_value(&k) {
                    println!("{val}");
                } else {
                    eprintln!("Unknown configuration key: {}", k);
                    return ExitCode::FAILURE;
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
            }
            ExitCode::SUCCESS
        }
        ConfigAction::Set {
            server_url,
            identity_url,
            download_dir,
            auto_lock,
            clipboard_clear,
            email,
            remember_email,
            check_updates,
            log_level,
            show_website_icons,
            remember_last_search,
            max_attachment_size,
            client_cert,
            client_key,
            ssh_agent,
            ssh_agent_confirm,
            quick_unlock,
        } => {
            let storage_mgr = match config_path {
                Some(cp) => {
                    if let Some(parent) = cp.parent() {
                        StorageManager::new(
                            parent.join(omawarden_engine::storage::DEFAULT_STORAGE_FILENAME),
                        )
                    } else {
                        StorageManager::default()
                    }
                }
                None => StorageManager::default(),
            };
            let keyring_mgr = KeyringManager::default();

            let parsed_remember_email = remember_email.map(|v| {
                let lower = v.trim().to_lowercase();
                matches!(lower.as_str(), "true" | "1" | "yes")
            });
            let parsed_check_updates = check_updates.map(|v| {
                let lower = v.trim().to_lowercase();
                matches!(lower.as_str(), "true" | "1" | "yes")
            });

            let parsed_show_website_icons = show_website_icons.map(|v| {
                let lower = v.trim().to_lowercase();
                matches!(lower.as_str(), "true" | "1" | "yes")
            });

            let parsed_remember_last_search = remember_last_search.map(|v| {
                let lower = v.trim().to_lowercase();
                matches!(lower.as_str(), "true" | "1" | "yes")
            });

            if let Some(ref cert_str) = client_cert {
                let trimmed = cert_str.trim();
                if !trimmed.is_empty() {
                    let cert_path = std::path::Path::new(trimmed);
                    if !cert_path.exists() {
                        eprintln!(
                            "Error: Client certificate file not found: '{}'",
                            cert_path.display()
                        );
                        return ExitCode::FAILURE;
                    }
                    let key_target = if let Some(ref key_str) = client_key {
                        let key_trimmed = key_str.trim();
                        if !key_trimmed.is_empty() {
                            std::path::Path::new(key_trimmed)
                        } else {
                            cert_path
                        }
                    } else {
                        cert_path
                    };

                    if !key_target.exists() {
                        eprintln!(
                            "Error: Client private key file not found: '{}'",
                            key_target.display()
                        );
                        return ExitCode::FAILURE;
                    }

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(meta) = std::fs::metadata(key_target) {
                            let mode = meta.permissions().mode() & 0o777;
                            if mode & 0o077 != 0 {
                                eprintln!(
                                    "Error: Insecure permissions ({:#o}) on client private key '{}': file must be restricted to 0600 or 0400 (run `chmod 600 {}`)",
                                    mode,
                                    key_target.display(),
                                    key_target.display()
                                );
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                }
            }

            let options = ConfigUpdateOptions {
                server_url,
                identity_url,
                download_dir,
                auto_lock_minutes: auto_lock,
                clipboard_clear_seconds: clipboard_clear,
                email,
                remember_email: parsed_remember_email,
                check_updates: parsed_check_updates,
                log_level,
                show_website_icons: parsed_show_website_icons,
                remember_last_search: parsed_remember_last_search,
                max_attachment_size_mb: max_attachment_size,
                client_cert_path: client_cert,
                client_key_path: client_key,
                ssh_agent_enabled: ssh_agent,
                ssh_agent_confirm: ssh_agent_confirm.clone(),
                quick_unlock,
            };

            let (updated_cfg, _server_changed) =
                match config_mgr.update_config(options, &storage_mgr, &keyring_mgr) {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("Failed to save configuration: {}", e);
                        return ExitCode::FAILURE;
                    }
                };
            *cfg = updated_cfg;
            if ssh_agent.is_some() {
                // Start or stop the agent in the running daemon (no restart, so no lock).
                let _ = send_daemon_request(&json!({ "action": "ssh_agent_apply" }));
            }
            if let Some(lock_mins) = auto_lock {
                let _ = send_daemon_request(&json!({
                    "action": "set_auto_lock",
                    "auto_lock_minutes": lock_mins
                }));
            }
            let safe_url = if cfg.server_url.is_empty() {
                "default (official)".to_string()
            } else if let Ok(parsed) = url::Url::parse(&cfg.server_url) {
                if let Some(host) = parsed.host_str() {
                    if host == "vault.bitwarden.com"
                        || host == "api.bitwarden.com"
                        || host == "bitwarden.com"
                        || host == "vault.bitwarden.eu"
                        || host == "api.bitwarden.eu"
                        || host == "bitwarden.eu"
                    {
                        format!("{}://{}", parsed.scheme(), host)
                    } else {
                        "<REDACTED_CUSTOM_HOST>".to_string()
                    }
                } else {
                    "<REDACTED_CUSTOM_HOST>".to_string()
                }
            } else {
                "<REDACTED_CUSTOM_HOST>".to_string()
            };
            let safe_id_url = if let Some(ref u) = cfg.identity_url {
                if let Ok(parsed) = url::Url::parse(u) {
                    if let Some(host) = parsed.host_str() {
                        if host == "identity.bitwarden.com" || host == "identity.bitwarden.eu" {
                            format!("{}://{}", parsed.scheme(), host)
                        } else {
                            "<REDACTED_CUSTOM_HOST>".to_string()
                        }
                    } else {
                        "<REDACTED_CUSTOM_HOST>".to_string()
                    }
                } else {
                    "<REDACTED_CUSTOM_HOST>".to_string()
                }
            } else {
                "auto".to_string()
            };
            omawarden_engine::log_info!(
                "omawarden:config",
                "Updated configuration (log_level: {}, server_url: {}, identity_url: {}).",
                cfg.log_level,
                safe_url,
                safe_id_url
            );
            println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
            ExitCode::SUCCESS
        }
    }
}
