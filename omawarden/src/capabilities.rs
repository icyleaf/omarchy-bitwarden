use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_CAPABILITIES_FILENAME: &str = "server_capabilities.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeatureStatus {
    Supported,
    Disabled,
    Unsupported,
    Deprecated,
}

impl FeatureStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Disabled => "disabled",
            Self::Unsupported => "unsupported",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeatureCategory {
    Mandatory,
    Optional,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureEvaluation {
    pub name: String,
    pub category: FeatureCategory,
    pub status: FeatureStatus,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerCapabilities {
    pub server_url: String,
    pub server_version: Option<String>,
    pub git_hash: Option<String>,
    pub cached_at: String,
    pub feature_states: HashMap<String, Value>,
    pub matrix: Vec<FeatureEvaluation>,
}

struct KnownFeatureSpec {
    name: &'static str,
    aliases: &'static [&'static str],
    category: FeatureCategory,
    description: &'static str,
}

const KNOWN_FEATURES: &[KnownFeatureSpec] = &[
    KnownFeatureSpec {
        name: "ssh-agent-v2",
        aliases: &[],
        category: FeatureCategory::Optional,
        description: "Modern SSH Agent v2 signature negotiation and process binding",
    },
    KnownFeatureSpec {
        name: "ssh-key-vault-item",
        aliases: &[],
        category: FeatureCategory::Optional,
        description: "Cipher Type 5 native SSH key storage and generation",
    },
    KnownFeatureSpec {
        name: "bitwarden-send",
        aliases: &["send"],
        category: FeatureCategory::Optional,
        description: "Bitwarden Send ephemeral transmission",
    },
    KnownFeatureSpec {
        name: "fido2-vault-credentials",
        aliases: &["passkeys"],
        category: FeatureCategory::Optional,
        description: "Passkey and WebAuthn credential storage",
    },
];

pub fn evaluate_matrix(
    server_url: Option<&str>,
    feature_states: &HashMap<String, Value>,
) -> Vec<FeatureEvaluation> {
    let is_cloud = server_url
        .map(|u| crate::api::EnvironmentUrls::resolve(u, None).is_cloud)
        .unwrap_or(false);

    let mut matrix = Vec::new();
    let mut recognized_keys = std::collections::HashSet::new();

    // 1. Evaluate known supported/optional features
    for spec in KNOWN_FEATURES {
        recognized_keys.insert(spec.name.to_string());
        for alias in spec.aliases {
            recognized_keys.insert(alias.to_string());
        }

        let explicit_status = feature_states
            .get(spec.name)
            .or_else(|| {
                spec.aliases
                    .iter()
                    .find_map(|alias| feature_states.get(*alias))
            })
            .and_then(Value::as_bool);

        let is_active = match explicit_status {
            Some(active) => active,
            None => {
                // Official Bitwarden cloud natively supports GA features like ssh-key-vault-item
                is_cloud && spec.name == "ssh-key-vault-item"
            }
        };

        matrix.push(FeatureEvaluation {
            name: spec.name.to_string(),
            category: spec.category,
            status: if is_active {
                FeatureStatus::Supported
            } else {
                FeatureStatus::Disabled
            },
            description: spec.description.to_string(),
        });
    }

    // 2. Evaluate deprecated features
    recognized_keys.insert("ssh-agent".to_string());
    if let Some(v1_active) = feature_states.get("ssh-agent").and_then(Value::as_bool) {
        if v1_active {
            matrix.push(FeatureEvaluation {
                name: "ssh-agent".to_string(),
                category: FeatureCategory::Optional,
                status: FeatureStatus::Deprecated,
                description: "Superseded by modern ssh-agent-v2 protocol".to_string(),
            });
        }
    }

    // 3. Mark unhandled active upstream flags as unsupported
    let mut extra_keys: Vec<&String> = feature_states
        .keys()
        .filter(|k| !recognized_keys.contains(k.as_str()))
        .collect();
    extra_keys.sort();

    for key in extra_keys {
        if let Some(true) = feature_states.get(key).and_then(Value::as_bool) {
            matrix.push(FeatureEvaluation {
                name: key.clone(),
                category: FeatureCategory::Optional,
                status: FeatureStatus::Unsupported,
                description: "Upstream feature not yet implemented in omawarden".to_string(),
            });
        }
    }

    matrix
}

pub fn resolve_capabilities_cache_path() -> PathBuf {
    if let Ok(custom_dir) = std::env::var("OMAWARDEN_DATA_DIR") {
        if !custom_dir.trim().is_empty() {
            return PathBuf::from(custom_dir.trim()).join(DEFAULT_CAPABILITIES_FILENAME);
        }
    }

    let xdg_data = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".local").join("share")
        });
    xdg_data
        .join("omawarden")
        .join(DEFAULT_CAPABILITIES_FILENAME)
}

pub fn load_cached_capabilities() -> Option<ServerCapabilities> {
    load_cached_capabilities_for(None)
}

pub fn load_cached_capabilities_for(
    expected_server_url: Option<&str>,
) -> Option<ServerCapabilities> {
    let path = resolve_capabilities_cache_path();
    if !path.exists() {
        return None;
    }
    let data = fs::read_to_string(&path).ok()?;
    let caps: ServerCapabilities = serde_json::from_str(&data).ok()?;

    if let Some(expected) = expected_server_url {
        if !crate::attachment::is_same_origin(&caps.server_url, expected) {
            return None;
        }
    }

    Some(caps)
}

pub fn save_capabilities(caps: &ServerCapabilities) -> Result<(), String> {
    let path = resolve_capabilities_cache_path();
    if let Some(parent) = path.parent() {
        crate::fs_util::create_secure_dir_all(parent, 0o700)
            .map_err(|e| format!("Failed to create capabilities directory: {}", e))?;
    }
    let json_bytes = serde_json::to_vec_pretty(caps)
        .map_err(|e| format!("Failed to serialize capabilities: {}", e))?;

    crate::fs_util::atomic_write_file(&path, &json_bytes, 0o600)
        .map_err(|e| format!("Failed to persist capabilities cache: {}", e))?;

    Ok(())
}

pub fn discover_capabilities(
    server_url: &str,
    client_context: Option<&crate::api::ClientContext>,
    config_override: Option<&crate::config::Config>,
) -> Result<ServerCapabilities, String> {
    let builder = crate::api::http_client_builder(
        Duration::from_secs(6),
        client_context,
        Some(server_url),
        config_override,
    )
    .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let client = builder
        .build()
        .map_err(|e| format!("Failed to initialize HTTP client: {}", e))?;

    let env_urls = crate::api::EnvironmentUrls::resolve(server_url, None);
    let api_base = env_urls.api_url.trim_end_matches('/');
    let config_url = format!("{}/config", api_base);
    let ver_url = format!("{}/version", api_base);

    let mut server_version = None;
    let mut git_hash = None;
    let mut feature_states = HashMap::new();

    // 1. Try /config
    if let Ok(mut resp) = client.get(&config_url).send() {
        if resp.status().is_success() {
            if let Ok(val) =
                crate::api::read_response_json::<Value>(&mut resp, crate::api::MAX_API_BODY_SIZE)
            {
                if let Some(v) = val.get("version").and_then(Value::as_str) {
                    server_version = Some(v.to_string());
                }
                if let Some(g) = val.get("gitHash").and_then(Value::as_str) {
                    git_hash = Some(g.to_string());
                }
                if let Some(features) = val.get("featureStates").and_then(Value::as_object) {
                    for (k, v) in features {
                        feature_states.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    // 2. If version was missing or /config failed, fallback to /version
    if server_version.is_none() {
        if let Ok(mut resp) = client.get(&ver_url).send() {
            if resp.status().is_success() {
                if let Ok(text) =
                    crate::api::read_response_text(&mut resp, crate::api::MAX_API_BODY_SIZE)
                {
                    if let Ok(ver_val) = serde_json::from_str::<Value>(&text) {
                        if let Some(v) = ver_val.as_str() {
                            server_version = Some(v.to_string());
                        } else if let Some(v) = ver_val.get("version").and_then(Value::as_str) {
                            server_version = Some(v.to_string());
                        }
                    } else {
                        let trimmed = text.trim().trim_matches('"');
                        if !trimmed.is_empty() {
                            server_version = Some(trimmed.to_string());
                        }
                    }
                }
            }
        }
    }

    if server_version.is_none() && feature_states.is_empty() {
        return Err(format!(
            "Could not query capabilities from server {}",
            server_url
        ));
    }

    let cached_at = Utc::now().to_rfc3339();
    let matrix = evaluate_matrix(Some(server_url), &feature_states);

    let caps = ServerCapabilities {
        server_url: server_url.to_string(),
        server_version,
        git_hash,
        cached_at,
        feature_states,
        matrix,
    };

    Ok(caps)
}

pub fn get_or_discover_capabilities(
    server_url: &str,
    refresh: bool,
    client_context: Option<&crate::api::ClientContext>,
    config_override: Option<&crate::config::Config>,
) -> Result<ServerCapabilities, String> {
    if !refresh {
        if let Some(c) = load_cached_capabilities_for(Some(server_url)) {
            return Ok(c);
        }
    }

    match discover_capabilities(server_url, client_context, config_override) {
        Ok(discovered) => {
            let _ = save_capabilities(&discovered);
            Ok(discovered)
        }
        Err(e) => {
            if let Some(c) = load_cached_capabilities_for(Some(server_url)) {
                Ok(c)
            } else {
                Err(e)
            }
        }
    }
}

/// Check whether an upstream feature is supported based on cached server capabilities
/// or a best-effort check. If the feature is explicitly disabled or unsupported,
/// returns an actionable `Err(String)` unless `ignore_server_capabilities` is true.
pub fn check_feature_gating(
    server_url: &str,
    feature_name: &str,
    ignore_server_capabilities: bool,
) -> Result<(), String> {
    if ignore_server_capabilities {
        return Ok(());
    }

    let caps = load_cached_capabilities_for(Some(server_url))
        .or_else(|| get_or_discover_capabilities(server_url, false, None, None).ok());

    if let Some(c) = caps {
        if let Some(eval) = c.matrix.iter().find(|m| m.name == feature_name) {
            if eval.status == FeatureStatus::Disabled || eval.status == FeatureStatus::Unsupported {
                let status_str = eval.status.as_str();
                let recommendation = if feature_name == "ssh-key-vault-item" {
                    " For Vaultwarden self-hosters: enable SSH Key vault storage by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item in your server environment."
                } else if feature_name == "ssh-agent-v2" {
                    " For Vaultwarden self-hosters: enable modern agent support by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent,ssh-agent-v2 in your server environment."
                } else {
                    ""
                };
                return Err(format!(
                    "Upstream server does not support '{feature_name}' (feature status: {status_str}).{recommendation} Use --ignore-server-capabilities to bypass this check."
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_matrix_classifications() {
        let mut states = HashMap::new();
        states.insert("ssh-agent-v2".to_string(), Value::Bool(true));
        states.insert("ssh-key-vault-item".to_string(), Value::Bool(false));
        states.insert("ssh-agent".to_string(), Value::Bool(true));
        states.insert("future-experimental-flag".to_string(), Value::Bool(true));

        let matrix = evaluate_matrix(None, &states);

        let v2 = matrix.iter().find(|m| m.name == "ssh-agent-v2").unwrap();
        assert_eq!(v2.status, FeatureStatus::Supported);
        assert_eq!(v2.category, FeatureCategory::Optional);

        let key = matrix
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(key.status, FeatureStatus::Disabled);

        let v1 = matrix.iter().find(|m| m.name == "ssh-agent").unwrap();
        assert_eq!(v1.status, FeatureStatus::Deprecated);

        let future = matrix
            .iter()
            .find(|m| m.name == "future-experimental-flag")
            .unwrap();
        assert_eq!(future.status, FeatureStatus::Unsupported);
    }

    #[test]
    fn test_evaluate_matrix_cloud_vs_self_hosted_defaults() {
        let empty_states = HashMap::new();

        // 1. Official Bitwarden cloud defaults ssh-key-vault-item to Supported
        let cloud_matrix = evaluate_matrix(Some("https://vault.bitwarden.com"), &empty_states);
        let cloud_ssh_key = cloud_matrix
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(cloud_ssh_key.status, FeatureStatus::Supported);

        // 2. Non-cloud self-hosted (Vaultwarden) defaults unconfigured flag to Disabled
        let self_hosted_matrix = evaluate_matrix(Some("https://vaultwarden.local"), &empty_states);
        let sh_ssh_key = self_hosted_matrix
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(sh_ssh_key.status, FeatureStatus::Disabled);

        // 3. Explicit false on cloud or self-hosted is respected
        let mut explicit_false = HashMap::new();
        explicit_false.insert("ssh-key-vault-item".to_string(), Value::Bool(false));
        let matrix_false = evaluate_matrix(Some("https://vault.bitwarden.com"), &explicit_false);
        let false_key = matrix_false
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(false_key.status, FeatureStatus::Disabled);
    }

    #[test]
    fn test_cross_server_cache_isolation() {
        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("OMAWARDEN_DATA_DIR", temp.path());

        let caps = ServerCapabilities {
            server_url: "https://vault.corp.local".to_string(),
            server_version: Some("2026.1.0".to_string()),
            git_hash: None,
            cached_at: Utc::now().to_rfc3339(),
            feature_states: HashMap::new(),
            matrix: Vec::new(),
        };

        save_capabilities(&caps).expect("save must succeed");

        // Cache hit for same origin
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local")).is_some());
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local/")).is_some());

        // Cache miss for different origin
        assert!(load_cached_capabilities_for(Some("https://vault.bitwarden.com")).is_none());

        std::env::remove_var("OMAWARDEN_DATA_DIR");
    }
}
