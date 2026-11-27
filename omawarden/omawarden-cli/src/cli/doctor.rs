use omawarden_engine::config::Config;
use omawarden_engine::health::check_system_health;
use omawarden_engine::keyring::KeyringManager;
use std::process::ExitCode;

pub(crate) fn run_health(cfg: &Config) -> ExitCode {
    let status = check_system_health(&cfg.server_url);
    println!("{}", serde_json::to_string_pretty(&status).unwrap());
    ExitCode::SUCCESS
}

pub(crate) fn run_doctor(json: bool, cfg: &Config) -> ExitCode {
    let status = check_system_health(&cfg.server_url);
    if json {
        println!("{}", serde_json::to_string_pretty(&status).unwrap());
    } else {
        println!("System Diagnostics:");
        let ver_str = status.version.as_deref().unwrap_or("unknown");
        let commit_str = status
            .commit
            .as_deref()
            .map(|c| format!(" (commit {})", c))
            .unwrap_or_default();
        println!("  CLI Version:        v{}{}", ver_str, commit_str);
        let keyring_mgr = KeyringManager::default();
        let keyring_provider_name = keyring_mgr.provider().name();
        println!(
            "  Keyring:            {}",
            if status.keyring_available {
                format!("[OK] Available ({keyring_provider_name})")
            } else if let Some(reason) = keyring_mgr.unavailable_reason() {
                format!("[FAIL] Unavailable ({reason})")
            } else {
                "[FAIL] Unavailable".to_string()
            }
        );
        println!(
            "  Clipboard Guard:    {}",
            if status.clipboard_available {
                "[OK] Available"
            } else {
                "[FAIL] Unavailable"
            }
        );

        println!("\nUpstream Capabilities:");
        println!("  Server URL:         {}", status.server_url);
        println!(
            "  Server Reachable:   {}",
            if status.server_reachable {
                "[OK] Yes"
            } else {
                "[FAIL] No"
            }
        );

        if let Some(ref caps) = status.upstream_capabilities {
            if let Some(ref n) = caps.server_name {
                println!("  Server Name:        {}", n);
            }
            if let Some(ref v) = caps.server_version {
                println!("  Server Version:     {}", v);
            }
            if let Some(ref v) = caps.server_vendor_version {
                println!("  Vendor Version:     {}", v);
            }
            if let Some(ref g) = caps.git_hash {
                println!("  Git Hash:           {}", g);
            }
            println!("  Features:");
            for detail in &caps.details {
                println!("    - {}", detail);
            }
            if !caps.recommendations.is_empty() {
                println!("  Recommendations:");
                for rec in &caps.recommendations {
                    println!("    - {}", rec);
                }
            }
        } else if !status.server_reachable {
            println!("  Capabilities:       [--] Skipped (server unreachable)");
        } else {
            println!("  Capabilities:       [--] Detection failed or unavailable");
        }

        println!(
            "\nHealth Verdict:       {}",
            if status.ok {
                "[OK] All checks passed."
            } else {
                "[WARN] Some health checks failed or degraded."
            }
        );
        if let Some(ref err) = status.error {
            println!("  Failure Reason:     {}", err);
        }
    }
    if status.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
