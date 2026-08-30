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
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .unwrap_or_default();

    let prelogin_url = format!("{}/api/accounts/prelogin", server_clean);
    let server_reachable =
        client.get(&prelogin_url).send().is_ok() || client.get(server_clean).send().is_ok();

    // 2. Check Keyring (secret-tool)
    let keyring_available = which::which("secret-tool").is_ok();

    // 3. Check Wayland clipboard (wl-copy)
    let clipboard_available = which::which("wl-copy").is_ok();

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
        error: if !server_reachable {
            Some(
                "Cannot reach Bitwarden server. Please check your network or server URL."
                    .to_string(),
            )
        } else if !keyring_available {
            Some("Linux Secret Service (secret-tool) is not available.".to_string())
        } else if !clipboard_available {
            Some("Wayland clipboard utility (wl-copy) not found.".to_string())
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
