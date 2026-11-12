use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamCapabilitiesReport {
    pub server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_vendor_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_hash: Option<String>,
    pub ssh_agent_v2_status: String,
    pub ssh_key_vault_item_status: String,
    pub details: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthStatus {
    pub installed: bool,
    pub ok: bool,
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,
    pub server_url: String,
    pub server_reachable: bool,
    pub keyring_available: bool,
    pub clipboard_available: bool,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_capabilities: Option<UpstreamCapabilitiesReport>,
}

pub fn check_system_health(server_url: &str) -> HealthStatus {
    let version = env!("CARGO_PKG_VERSION").to_string();
    let commit = env!("GIT_HASH").to_string();
    let build_date = env!("BUILD_DATE").to_string();
    let server_clean = server_url.trim_end_matches('/');

    // 1. Check server reachability
    let client =
        match crate::api::build_http_client_for_url(Duration::from_secs(4), None, Some(server_url))
        {
            Ok(c) => c,
            Err(e) => {
                return HealthStatus {
                    installed: true,
                    ok: false,
                    version: Some(version),
                    commit: if commit != "unknown" {
                        Some(commit)
                    } else {
                        None
                    },
                    build_date: if build_date != "unknown" {
                        Some(build_date)
                    } else {
                        None
                    },
                    server_url: server_url.to_string(),
                    server_reachable: false,
                    keyring_available: which::which("secret-tool").is_ok(),
                    clipboard_available: crate::clipboard::ClipboardGuard::default().is_available(),
                    error: Some(format!("Client mTLS certificate error: {}", e)),
                    upstream_capabilities: None,
                };
            }
        };

    let env_urls = crate::api::EnvironmentUrls::resolve(server_url, None);
    let prelogin_url = format!("{}/accounts/prelogin", env_urls.identity_url);
    let legacy_prelogin_url = format!("{}/accounts/prelogin", env_urls.api_url);

    let format_req_error = |mut err: &dyn std::error::Error| -> String {
        let mut s = err.to_string();
        while let Some(src) = err.source() {
            s.push_str(" -> ");
            s.push_str(&src.to_string());
            err = src;
        }
        s
    };

    let reachability_err = match client.get(&prelogin_url).send() {
        Ok(_) => None,
        Err(e) => match client.get(&legacy_prelogin_url).send() {
            Ok(_) => None,
            Err(_) => match client.get(&env_urls.base_url).send() {
                Ok(_) => None,
                Err(_) => match client.get(server_clean).send() {
                    Ok(_) => None,
                    Err(_) => Some(format!(
                        "Cannot reach Bitwarden server: {}",
                        format_req_error(&e)
                    )),
                },
            },
        },
    };
    let server_reachable = reachability_err.is_none();

    // 2. Check Keyring (secret-tool)
    let keyring_available = which::which("secret-tool").is_ok();

    // 3. Check clipboard provider
    let clipboard = crate::clipboard::ClipboardGuard::default();
    let clipboard_available = clipboard.is_available();
    let clipboard_err = clipboard.unavailable_reason();

    // 4. Query / evaluate upstream capabilities
    let upstream_capabilities = if server_reachable {
        let caps =
            crate::capabilities::get_or_discover_capabilities(server_url, false, None, None).ok();

        caps.map(|c| {
            let mut details = Vec::new();
            let mut recommendations = Vec::new();

            let identity = crate::capabilities::ServerIdentity {
                server_url: Some(&c.server_url),
                server_name: c.server_name.as_deref(),
                server_vendor_version: c.server_vendor_version.as_deref(),
                server_version: c.server_version.as_deref(),
            };
            let flavor = crate::capabilities::classify_server(&identity);
            let vaultwarden_version = crate::capabilities::vaultwarden_version(&identity);
            let is_vaultwarden = flavor == crate::capabilities::ServerFlavor::Vaultwarden;
            let format_version =
                |v: (u64, u64, u64)| format!("{}.{}.{}", v.0, v.1, v.2);

            let ssh_agent_v2_status = c
                .matrix
                .iter()
                .find(|m| m.name == "ssh-agent-v2")
                .map(|m| m.status.as_str().to_string())
                .unwrap_or_else(|| "disabled".to_string());

            let ssh_key_status = c
                .matrix
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .map(|m| m.status.as_str().to_string())
                .unwrap_or_else(|| "disabled".to_string());

            // Minimum supported Vaultwarden baseline warning (>= 1.28.0 for Argon2id KDF and
            // modern identity prelogin).
            if is_vaultwarden {
                if let Some(v) = vaultwarden_version {
                    if v < (1, 28, 0) {
                        details.push(format!(
                            "[WARN] Vaultwarden {} is below the minimum supported baseline (>= 1.28.0 for Argon2id KDF and modern identity prelogin).",
                            format_version(v)
                        ));
                        recommendations.push(
                            "Upgrade Vaultwarden to >= 1.37.4 (minimum >= 1.28.0) for Argon2id KDF and modern identity prelogin support."
                                .to_string(),
                        );
                    }
                }
            }

            if ssh_agent_v2_status == "supported" {
                details.push("[OK] Upstream ssh-agent-v2 enabled".to_string());
            } else {
                details.push("[INFO] Upstream ssh-agent-v2 is not enabled (optional)".to_string());
            }

            match ssh_key_status.as_str() {
                "supported" => details.push("[OK] Upstream ssh-key-vault-item enabled".to_string()),
                "unsupported" => details.push(
                    "[WARN] Upstream ssh-key-vault-item is unsupported on this server version"
                        .to_string(),
                ),
                _ => details.push(
                    "[INFO] Upstream ssh-key-vault-item is not enabled (optional)".to_string(),
                ),
            }

            // An old Vaultwarden predates the experimental flag entirely; never recommend
            // configuring flags that do not exist on that release.
            let below_flag_tier =
                is_vaultwarden && vaultwarden_version.map(|v| v < (1, 33, 0)).unwrap_or(false);
            let native_ssh_key = is_vaultwarden
                && vaultwarden_version.map(|v| v >= (1, 37, 4)).unwrap_or(false);
            let ssh_key_needs_flag = ssh_key_status == "disabled" && !native_ssh_key;

            if ssh_key_status == "unsupported" && is_vaultwarden {
                recommendations.push(
                    "Upgrade Vaultwarden to >= 1.33.0 for SSH Key Cipher support (>= 1.37.4 recommended for native support without experimental flags)."
                        .to_string(),
                );
            } else if ssh_key_needs_flag && is_vaultwarden {
                recommendations.push(
                    "For Vaultwarden self-hosters: enable SSH Key vault storage by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent in your environment."
                        .to_string(),
                );
            }

            if ssh_agent_v2_status != "supported" {
                if below_flag_tier {
                    recommendations.push(
                        "Upgrade Vaultwarden to >= 1.33.0 to enable ssh-agent-v2 (>= 1.37.4 recommended)."
                            .to_string(),
                    );
                } else if is_vaultwarden && native_ssh_key {
                    // Native SSH Key support is present; only the agent flag remains relevant.
                    recommendations.push(
                        "For Vaultwarden self-hosters: enable modern agent support by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-agent-v2 in your environment."
                            .to_string(),
                    );
                } else if is_vaultwarden && ssh_key_needs_flag {
                    recommendations.push(
                        "For Vaultwarden self-hosters: enable modern agent and SSH key storage by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent,ssh-agent-v2 in your environment."
                            .to_string(),
                    );
                } else if is_vaultwarden {
                    recommendations.push(
                        "For Vaultwarden self-hosters: enable modern agent support by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-agent-v2 in your environment."
                            .to_string(),
                    );
                } else {
                    recommendations.push(
                        "For Vaultwarden self-hosters: enable modern agent and SSH key storage by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent,ssh-agent-v2 in your environment."
                            .to_string(),
                    );
                }
            }

            UpstreamCapabilitiesReport {
                server_url: c.server_url,
                server_version: c.server_version,
                server_name: c.server_name,
                server_vendor_version: c.server_vendor_version,
                git_hash: c.git_hash,
                ssh_agent_v2_status,
                ssh_key_vault_item_status: ssh_key_status,
                details,
                recommendations,
            }
        })
    } else {
        None
    };

    let all_ok = server_reachable && keyring_available && clipboard_available;

    HealthStatus {
        installed: true,
        ok: all_ok,
        version: Some(version),
        commit: if commit != "unknown" {
            Some(commit)
        } else {
            None
        },
        build_date: if !build_date.is_empty() {
            Some(build_date)
        } else {
            None
        },
        server_url: server_url.to_string(),
        server_reachable,
        keyring_available,
        clipboard_available,
        error: if let Some(err) = reachability_err {
            Some(err)
        } else if !keyring_available {
            Some("Linux Secret Service (secret-tool) is not available.".to_string())
        } else if !clipboard_available {
            clipboard_err
        } else {
            None
        },
        upstream_capabilities,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_health() {
        let status = check_system_health("https://vault.bitwarden.com");
        assert!(status.installed);
        assert!(status.version.is_some());
    }
}
