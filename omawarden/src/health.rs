use serde::{Deserialize, Serialize};
use std::time::Duration;

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
