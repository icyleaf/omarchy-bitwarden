use clap::Subcommand;
use omawarden_engine::auth::{complete_interactive_two_factor, AuthManager};
use omawarden_engine::config::{Config, ConfigManager};
use serde_json::{json, Value};
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use super::io::{print_json_redacting_session, read_auth_payload, read_secret_stdin};

#[derive(Subcommand)]
pub(crate) enum AuthAction {
    #[command(about = "Get current authentication and vault lock status")]
    Status,
    #[command(about = "Login using Master Password (credentials read from stdin)")]
    LoginPassword {
        #[arg(long, required = true)]
        email: String,
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            help = "Remember email address in configuration"
        )]
        remember_email: Option<String>,
    },
    #[command(about = "Login using API Key (client_secret read from stdin)")]
    LoginApikey {
        #[arg(long, required = true)]
        client_id: String,
    },
    #[command(
        about = "Send or resend two-factor verification code to email (password read from stdin)"
    )]
    SendTwoFactorEmail {
        #[arg(long, required = true)]
        email: String,
    },
    #[command(about = "Check current FIDO2 / WebAuthn environment and device status")]
    Fido2Status,
    #[command(about = "Unlock vault with master password (password read from stdin)")]
    Unlock,
    #[command(about = "Unlock vault via system authentication, polkit-backed (ADR-0025)")]
    QuickUnlock,
    #[command(about = "Report whether quick unlock is enabled and a retained key is available")]
    QuickUnlockCheck,
    #[command(about = "Lock vault and clear session")]
    Lock,
    #[command(about = "Logout from Bitwarden account")]
    Logout,
}

pub(crate) fn run(action: AuthAction, cfg: &Config, config_mgr: &ConfigManager) -> ExitCode {
    let auth_mgr = AuthManager::with_config(
        &cfg.server_url,
        cfg.identity_url.as_deref(),
        None,
        None,
        Some(config_mgr.clone()),
    );
    match action {
        AuthAction::Status => {
            if let Err(e @ omawarden_engine::daemon::DispatchError::IncompatibleProtocol { .. }) =
                omawarden_engine::daemon::ensure_daemon_running()
            {
                let st = json!({
                    "status": "incompatible_daemon",
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&st).unwrap());
                return ExitCode::FAILURE;
            }
            let st = auth_mgr.get_status(false);
            println!("{}", serde_json::to_string_pretty(&st).unwrap());
            ExitCode::SUCCESS
        }
        AuthAction::LoginPassword {
            email,
            remember_email,
        } => {
            let (pwd, stdin_code, stdin_provider, stdin_new_device_otp) = if io::stdin()
                .is_terminal()
            {
                let p = rpassword::prompt_password("Enter Master Password: ").unwrap_or_default();
                (p, None, None, None)
            } else {
                read_auth_payload()
            };
            let effective_code = stdin_code;
            let effective_provider = stdin_provider;
            let mut effective_new_device_otp = stdin_new_device_otp;
            let mut res = auth_mgr.login_password(
                &email,
                &pwd,
                effective_code.as_deref(),
                effective_provider,
                effective_new_device_otp.as_deref(),
            );
            if !res.ok
                && effective_code.is_none()
                && effective_new_device_otp.is_none()
                && io::stdin().is_terminal()
            {
                if res.new_device_verification_required == Some(true) {
                    let prompt_code = rpassword::prompt_password(
                        "Enter New Device Verification Code (check your email): ",
                    )
                    .unwrap_or_default();
                    if !prompt_code.trim().is_empty() {
                        effective_new_device_otp = Some(prompt_code.trim().to_string());
                        res = auth_mgr.login_password(
                            &email,
                            &pwd,
                            None,
                            None,
                            effective_new_device_otp.as_deref(),
                        );
                    }
                } else if res.two_factor_required == Some(true) {
                    let mut providers = res.two_factor_providers.clone().unwrap_or_else(|| vec![0]);
                    // A server reporting two_factor_required with an empty
                    // providers list would panic on providers[default_idx]
                    // below; fall back to the authenticator-app provider.
                    if providers.is_empty() {
                        providers.push(0);
                    }
                    let default_idx = if let Some(pref) = res.two_factor_provider {
                        providers.iter().position(|p| *p == pref).unwrap_or(0)
                    } else {
                        0
                    };
                    let chosen_provider = if providers.len() == 1 {
                        providers[0]
                    } else {
                        eprintln!("\nTwo-Factor Authentication Methods:");
                        for (idx, p) in providers.iter().enumerate() {
                            let label = match p {
                                0 => "Authenticator App (TOTP)".to_string(),
                                1 => "Email Verification Code".to_string(),
                                3 => "YubiKey OTP".to_string(),
                                7 => match res.fido2_status.as_deref() {
                                    Some("tool_not_found") => {
                                        "WebAuthn / Passkey / Security Key (libfido2 not installed)"
                                            .to_string()
                                    }
                                    Some("no_device") => {
                                        "WebAuthn / Passkey / Security Key (no key detected)"
                                            .to_string()
                                    }
                                    _ => "WebAuthn / Passkey / Security Key".to_string(),
                                },
                                _ => "Other".to_string(),
                            };
                            eprintln!("  [{}] {}", idx + 1, label);
                        }
                        eprint!(
                            "Select method [1-{}, default: {}]: ",
                            providers.len(),
                            default_idx + 1
                        );
                        let _ = io::stderr().flush();
                        let mut choice = String::new();
                        let _ = io::stdin().read_line(&mut choice);
                        let idx = choice
                            .trim()
                            .parse::<usize>()
                            .unwrap_or(default_idx + 1)
                            .saturating_sub(1);
                        *providers.get(idx).unwrap_or(&providers[default_idx])
                    };

                    res = complete_interactive_two_factor(
                        chosen_provider,
                        res,
                        || {
                            eprintln!("Sending two-factor verification code to your email...");
                            auth_mgr
                                .send_two_factor_email(&email, &pwd)
                                .map_err(|e| e.to_string())
                        },
                        |prompt_label| rpassword::prompt_password(prompt_label).unwrap_or_default(),
                        |code, provider| {
                            auth_mgr.login_password(&email, &pwd, code, Some(provider), None)
                        },
                    );
                }
            }
            if res.ok {
                if let Some(ref rem) = remember_email {
                    let should_remember =
                        matches!(rem.to_lowercase().as_str(), "true" | "1" | "yes");
                    let mut latest_cfg = config_mgr.load();
                    latest_cfg.remember_email = should_remember;
                    if should_remember {
                        latest_cfg.email = email.trim().to_lowercase();
                    } else {
                        latest_cfg.email.clear();
                    }
                    let _ = config_mgr.save(&latest_cfg);
                }
            }
            print_json_redacting_session(&res);
            if res.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        AuthAction::LoginApikey { client_id } => {
            let actual_secret = if io::stdin().is_terminal() {
                rpassword::prompt_password("Enter Client Secret: ").unwrap_or_default()
            } else {
                let raw_secret = read_secret_stdin();
                let mut secret = raw_secret.clone();
                if raw_secret.starts_with('{') && raw_secret.ends_with('}') {
                    if let Ok(val) = serde_json::from_str::<Value>(&raw_secret) {
                        if let Some(s) = val.get("client_secret").and_then(|v| v.as_str()) {
                            secret = s.to_string();
                        }
                    }
                }
                secret
            };
            let res = auth_mgr.login_apikey(&client_id, &actual_secret);
            print_json_redacting_session(&res);
            if res.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        AuthAction::SendTwoFactorEmail { email } => {
            let (pwd, _, _, _) = if io::stdin().is_terminal() {
                let p = rpassword::prompt_password("Enter Master Password: ").unwrap_or_default();
                (p, None, None, None)
            } else {
                read_auth_payload()
            };
            if pwd.is_empty() {
                let res = serde_json::json!({
                    "ok": false,
                    "error": "Password is required to send verification code."
                });
                print_json_redacting_session(&res);
                ExitCode::FAILURE
            } else {
                match auth_mgr.send_two_factor_email(&email, &pwd) {
                    Ok(()) => {
                        let res = serde_json::json!({
                            "ok": true,
                            "message": "Two-factor verification code sent to your email."
                        });
                        print_json_redacting_session(&res);
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        let res = serde_json::json!({
                            "ok": false,
                            "error": e.to_string()
                        });
                        print_json_redacting_session(&res);
                        ExitCode::FAILURE
                    }
                }
            }
        }
        AuthAction::Fido2Status => {
            let status = omawarden_engine::webauthn::check_fido2_status();
            let res = serde_json::json!({
                "ok": true,
                "status": status.as_str()
            });
            print_json_redacting_session(&res);
            ExitCode::SUCCESS
        }
        AuthAction::Unlock => {
            let pwd = if io::stdin().is_terminal() {
                rpassword::prompt_password("Enter Master Password: ").unwrap_or_default()
            } else {
                read_secret_stdin()
            };
            let res = auth_mgr.unlock(&pwd);
            print_json_redacting_session(&res);
            if res.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        AuthAction::QuickUnlock => {
            if let Err(e @ omawarden_engine::daemon::DispatchError::IncompatibleProtocol { .. }) =
                omawarden_engine::daemon::ensure_daemon_running()
            {
                let resp = json!({
                    "ok": false,
                    "status": "locked",
                    "error": e.to_string(),
                });
                print_json_redacting_session(&resp);
                return ExitCode::FAILURE;
            }
            let client = omawarden_engine::daemon::DaemonClient::new()
                .with_timeout(Some(Duration::from_secs(130)));
            let resp = match client.send(&json!({ "action": "quick_unlock" })) {
                Ok(resp) => resp,
                Err(omawarden_engine::daemon::DispatchError::IncompatibleProtocol {
                    running,
                    min_supported,
                    current,
                }) => json!({
                    "ok": false,
                    "status": "locked",
                    "error": format!("Incompatible daemon protocol version {running} (supported: {min_supported}..={current}). Please restart the daemon.")
                }),
                Err(_) => json!({
                    "ok": false,
                    "status": "locked",
                    "error": "omawarden daemon is not running."
                }),
            };
            print_json_redacting_session(&resp);
            if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        AuthAction::QuickUnlockCheck => {
            // Prefer the daemon as the single source: its ping carries
            // both the cached setting and the readiness it gates, so
            // the two can no longer come from disagreeing files. The
            // fields degrade independently: a daemon older than this
            // feature reports readiness (quick_unlock) but not the
            // cached setting (quick_unlock_enabled), which then falls
            // back to the config file; no daemon at all means no
            // readiness and a config-file setting.
            let ping = match omawarden_engine::daemon::dispatch_daemon_request(
                &json!({ "action": "ping" }),
            ) {
                Ok(p) => Some(p),
                Err(e @ omawarden_engine::daemon::DispatchError::IncompatibleProtocol { .. }) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": e.to_string(),
                        }))
                        .unwrap()
                    );
                    return ExitCode::FAILURE;
                }
                Err(_) => None,
            };
            let field = |name: &str| {
                ping.as_ref()
                    .and_then(|r| r.get(name))
                    .and_then(Value::as_bool)
            };
            let available = field("quick_unlock").unwrap_or(false);
            let enabled = field("quick_unlock_enabled")
                .unwrap_or_else(|| ConfigManager::default().load().quick_unlock);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "enabled": enabled,
                    "available": available,
                }))
                .unwrap()
            );
            ExitCode::SUCCESS
        }
        AuthAction::Lock => {
            let res = auth_mgr.lock();
            print_json_redacting_session(&res);
            ExitCode::SUCCESS
        }
        AuthAction::Logout => {
            let res = auth_mgr.logout();
            print_json_redacting_session(&res);
            if res.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
