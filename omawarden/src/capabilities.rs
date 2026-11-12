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
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub server_vendor_version: Option<String>,
    pub git_hash: Option<String>,
    pub cached_at: String,
    pub feature_states: HashMap<String, Value>,
    pub matrix: Vec<FeatureEvaluation>,
}

/// Classified upstream server flavor used to evaluate version-aware capability tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFlavor {
    /// Official Bitwarden Cloud (`bitwarden.com` / `bitwarden.eu`) or self-hosted official Bitwarden.
    BitwardenOfficial,
    /// Vaultwarden (self-hosted; reports `server.name = "Vaultwarden"`, with its release
    /// version discovered from the flavor-gated `/api/version` probe).
    Vaultwarden,
    /// Self-hosted server whose flavor cannot be determined from URL or metadata.
    UnknownSelfHosted,
}

/// Metadata used to classify the upstream server and evaluate its capability matrix.
#[derive(Debug, Clone, Copy)]
pub struct ServerIdentity<'a> {
    pub server_url: Option<&'a str>,
    pub server_name: Option<&'a str>,
    pub server_vendor_version: Option<&'a str>,
    pub server_version: Option<&'a str>,
}

/// Parses a release string into a `(major, minor, patch)` tuple.
///
/// Handles `v` prefixes (`v1.37.4-testing`), dirty/git suffixes (`1.37.4-2a3b4c`),
/// and missing minor/patch components. Unparseable or empty input degrades to `None`.
pub fn parse_version_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let stripped = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);

    // Keep only the leading `N[.N[.N]]` core, discarding any `-suffix` or trailing junk.
    let core: String = stripped
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let core = core.trim_matches('.');
    if core.is_empty() {
        return None;
    }

    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// Classifies the upstream server into a [`ServerFlavor`] from resolved URLs and discovered metadata.
pub fn classify_server(identity: &ServerIdentity<'_>) -> ServerFlavor {
    let is_cloud = identity
        .server_url
        .map(|u| crate::api::EnvironmentUrls::resolve(u, None).is_cloud)
        .unwrap_or(false);
    if is_cloud {
        return ServerFlavor::BitwardenOfficial;
    }

    if let Some(name) = identity.server_name {
        let name = name.trim();
        if name.eq_ignore_ascii_case("vaultwarden") {
            return ServerFlavor::Vaultwarden;
        }
        if name.eq_ignore_ascii_case("bitwarden") {
            return ServerFlavor::BitwardenOfficial;
        }
    }

    // A vendor version (or compatibility version) with major `1` identifies Vaultwarden.
    if identity
        .server_vendor_version
        .and_then(parse_version_tuple)
        .map(|v| v.0 == 1)
        .unwrap_or(false)
    {
        return ServerFlavor::Vaultwarden;
    }

    // Absent metadata: a calendar-style compatibility version (`>= 2024.12.0`) identifies
    // official Bitwarden; a major-`1` version identifies Vaultwarden.
    if identity.server_name.is_none() && identity.server_vendor_version.is_none() {
        if let Some(v) = identity.server_version.and_then(parse_version_tuple) {
            if v.0 == 1 {
                return ServerFlavor::Vaultwarden;
            }
            if v.0 >= 2024 {
                return ServerFlavor::BitwardenOfficial;
            }
        }
    }

    ServerFlavor::UnknownSelfHosted
}

/// Returns the Vaultwarden release tuple, preferring the `/api/version`-sourced
/// `server_vendor_version` and falling back to a major-`1` compatibility version.
/// Returns `None` when no Vaultwarden release can be parsed.
pub fn vaultwarden_version(identity: &ServerIdentity<'_>) -> Option<(u64, u64, u64)> {
    if let Some(v) = identity.server_vendor_version.and_then(parse_version_tuple) {
        return Some(v);
    }
    identity
        .server_version
        .and_then(parse_version_tuple)
        .filter(|v| v.0 == 1)
}

fn format_version_tuple(v: (u64, u64, u64)) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

/// Resolves the default `ssh-key-vault-item` status when `featureStates` omits the flag.
fn default_ssh_key_status(identity: &ServerIdentity<'_>, flavor: ServerFlavor) -> FeatureStatus {
    match flavor {
        ServerFlavor::BitwardenOfficial => {
            match identity.server_version.and_then(parse_version_tuple) {
                Some(v) if v < (2024, 12, 0) => FeatureStatus::Unsupported,
                _ => FeatureStatus::Supported,
            }
        }
        ServerFlavor::Vaultwarden => match vaultwarden_version(identity) {
            Some(v) if v >= (1, 37, 4) => FeatureStatus::Supported,
            Some(v) if v >= (1, 33, 0) => FeatureStatus::Disabled,
            Some(_) => FeatureStatus::Unsupported,
            None => FeatureStatus::Disabled,
        },
        ServerFlavor::UnknownSelfHosted => FeatureStatus::Disabled,
    }
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
    identity: ServerIdentity<'_>,
    feature_states: &HashMap<String, Value>,
) -> Vec<FeatureEvaluation> {
    let flavor = classify_server(&identity);

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

        // Explicit boolean values always take precedence; otherwise the version-aware
        // matrix default applies (notably for `ssh-key-vault-item`).
        let status = match explicit_status {
            Some(true) => FeatureStatus::Supported,
            Some(false) => FeatureStatus::Disabled,
            None if spec.name == "ssh-key-vault-item" => default_ssh_key_status(&identity, flavor),
            None => FeatureStatus::Disabled,
        };

        matrix.push(FeatureEvaluation {
            name: spec.name.to_string(),
            category: spec.category,
            status,
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

/// Canonicalizes a configured server URL to its resolved API base, **including any
/// sub-path**, so the capability cache is keyed by full deployment rather than origin.
///
/// Two deployments that share a scheme and host but differ by path (e.g. `/old` and
/// `/new`) resolve to distinct bases; a trailing slash is not significant.
fn canonical_api_base(server_url: &str) -> String {
    crate::api::EnvironmentUrls::resolve(server_url, None)
        .api_url
        .trim_end_matches('/')
        .to_string()
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
        if canonical_api_base(&caps.server_url) != canonical_api_base(expected) {
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

/// Fetches `GET /api/version` and returns the reported version string.
///
/// The endpoint is answered with a bare JSON string (e.g. `"1.37.4"`), though some
/// deployments wrap it in an object; both shapes are tolerated. Returns `None` on any
/// network, non-200, or parse failure so callers can degrade gracefully.
fn fetch_version_endpoint(client: &reqwest::blocking::Client, ver_url: &str) -> Option<String> {
    let mut resp = client.get(ver_url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = crate::api::read_response_text(&mut resp, crate::api::MAX_API_BODY_SIZE).ok()?;

    if let Ok(ver_val) = serde_json::from_str::<Value>(&text) {
        if let Some(v) = ver_val.as_str() {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        } else if let Some(v) = ver_val.get("version").and_then(Value::as_str) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
        None
    } else {
        let trimmed = text.trim().trim_matches('"');
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
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
    let mut server_name = None;
    let mut git_hash = None;
    let mut feature_states = HashMap::new();

    // 1. Interrogate /api/config for the Bitwarden compatibility version, git hash,
    //    nested server identity, and active feature flags. The nested `server.version`
    //    is intentionally ignored: Vaultwarden removed it in 1.32.1 (see ADR 0031 §1.1).
    if let Ok(mut resp) = client.get(&config_url).send() {
        if resp.status().is_success() {
            if let Ok(val) =
                crate::api::read_response_json::<Value>(&mut resp, crate::api::MAX_API_BODY_SIZE)
            {
                if let Some(v) = val.get("version").and_then(Value::as_str) {
                    let v = v.trim();
                    if !v.is_empty() {
                        server_version = Some(v.to_string());
                    }
                }
                if let Some(g) = val.get("gitHash").and_then(Value::as_str) {
                    git_hash = Some(g.to_string());
                }
                if let Some(server) = val.get("server").and_then(Value::as_object) {
                    if let Some(n) = server.get("name").and_then(Value::as_str) {
                        let n = n.trim();
                        if !n.is_empty() {
                            server_name = Some(n.to_string());
                        }
                    }
                }
                if let Some(features) = val.get("featureStates").and_then(Value::as_object) {
                    for (k, v) in features {
                        feature_states.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    // 2. Classify the flavor from the `/api/config`-derived metadata alone. The vendor
    //    version is deliberately excluded here: it is discovered from `/api/version`,
    //    which is only consulted once the flavor is known.
    let flavor = classify_server(&ServerIdentity {
        server_url: Some(server_url),
        server_name: server_name.as_deref(),
        server_vendor_version: None,
        server_version: server_version.as_deref(),
    });

    // 3. Vendor release version: flavor-gated, best-effort `/api/version` probe.
    //    On Vaultwarden this endpoint reports its release tag (e.g. `1.37.4`). It is
    //    never consulted for official Bitwarden, whose `/api/version` carries a
    //    calendar-style version that must not be recorded as a vendor version.
    let mut server_vendor_version = None;
    if flavor == ServerFlavor::Vaultwarden {
        server_vendor_version = fetch_version_endpoint(&client, &ver_url);
    }

    // 4. Compatibility-version fallback: only for non-Vaultwarden servers whose
    //    `/api/config` did not report a version.
    if server_version.is_none() && flavor != ServerFlavor::Vaultwarden {
        server_version = fetch_version_endpoint(&client, &ver_url);
    }

    if server_version.is_none() && server_name.is_none() && feature_states.is_empty() {
        return Err(format!(
            "Could not query capabilities from server {}",
            server_url
        ));
    }

    let cached_at = Utc::now().to_rfc3339();
    let matrix = evaluate_matrix(
        ServerIdentity {
            server_url: Some(server_url),
            server_name: server_name.as_deref(),
            server_vendor_version: server_vendor_version.as_deref(),
            server_version: server_version.as_deref(),
        },
        &feature_states,
    );

    let caps = ServerCapabilities {
        server_url: server_url.to_string(),
        server_version,
        server_name,
        server_vendor_version,
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
                let recommendation = feature_remediation(&c, feature_name);
                return Err(format!(
                    "Upstream server does not support '{feature_name}' (feature status: {status_str}).{recommendation} Use --ignore-server-capabilities to bypass this check."
                ));
            }
        }
    }

    Ok(())
}

/// Produces server-flavor and version aware remediation guidance for a gated feature.
fn feature_remediation(caps: &ServerCapabilities, feature_name: &str) -> String {
    let identity = ServerIdentity {
        server_url: Some(&caps.server_url),
        server_name: caps.server_name.as_deref(),
        server_vendor_version: caps.server_vendor_version.as_deref(),
        server_version: caps.server_version.as_deref(),
    };
    let flavor = classify_server(&identity);
    let status = caps
        .matrix
        .iter()
        .find(|m| m.name == feature_name)
        .map(|m| m.status);

    match feature_name {
        "ssh-key-vault-item" => {
            if status == Some(FeatureStatus::Unsupported) {
                match flavor {
                    ServerFlavor::Vaultwarden => {
                        let version = vaultwarden_version(&identity)
                            .map(format_version_tuple)
                            .unwrap_or_else(|| "release".to_string());
                        format!(
                            " The connected Vaultwarden {version} predates native SSH Key Cipher support. Upgrade Vaultwarden to >= 1.33.0 for SSH Key support (>= 1.37.4 recommended for native support without experimental flags)."
                        )
                    }
                    _ => " Upgrade the connected Bitwarden server to >= 2024.12.0 for native SSH Key Cipher support.".to_string(),
                }
            } else {
                " For Vaultwarden self-hosters: enable SSH Key vault storage by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item in your server environment.".to_string()
            }
        }
        "ssh-agent-v2" => {
            let below_flag_tier = flavor == ServerFlavor::Vaultwarden
                && vaultwarden_version(&identity)
                    .map(|v| v < (1, 33, 0))
                    .unwrap_or(false);
            if below_flag_tier {
                " Upgrade Vaultwarden to >= 1.33.0 to enable ssh-agent-v2 (>= 1.37.4 recommended)."
                    .to_string()
            } else {
                " For Vaultwarden self-hosters: enable modern agent support by configuring EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-agent-v2 in your server environment.".to_string()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity<'a>(
        url: Option<&'a str>,
        name: Option<&'a str>,
        vendor: Option<&'a str>,
        compat: Option<&'a str>,
    ) -> ServerIdentity<'a> {
        ServerIdentity {
            server_url: url,
            server_name: name,
            server_vendor_version: vendor,
            server_version: compat,
        }
    }

    #[test]
    fn test_evaluate_matrix_classifications() {
        let mut states = HashMap::new();
        states.insert("ssh-agent-v2".to_string(), Value::Bool(true));
        states.insert("ssh-key-vault-item".to_string(), Value::Bool(false));
        states.insert("ssh-agent".to_string(), Value::Bool(true));
        states.insert("future-experimental-flag".to_string(), Value::Bool(true));

        let matrix = evaluate_matrix(identity(None, None, None, None), &states);

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
        let cloud_matrix = evaluate_matrix(
            identity(
                Some("https://vault.bitwarden.com"),
                None,
                None,
                Some("2026.10.1"),
            ),
            &empty_states,
        );
        let cloud_ssh_key = cloud_matrix
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(cloud_ssh_key.status, FeatureStatus::Supported);

        // 2. Non-cloud self-hosted (Vaultwarden) defaults unconfigured flag to Disabled
        let self_hosted_matrix = evaluate_matrix(
            identity(Some("https://vaultwarden.local"), None, None, None),
            &empty_states,
        );
        let sh_ssh_key = self_hosted_matrix
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(sh_ssh_key.status, FeatureStatus::Disabled);

        // 3. Explicit false on cloud or self-hosted is respected
        let mut explicit_false = HashMap::new();
        explicit_false.insert("ssh-key-vault-item".to_string(), Value::Bool(false));
        let matrix_false = evaluate_matrix(
            identity(
                Some("https://vault.bitwarden.com"),
                None,
                None,
                Some("2026.10.1"),
            ),
            &explicit_false,
        );
        let false_key = matrix_false
            .iter()
            .find(|m| m.name == "ssh-key-vault-item")
            .unwrap();
        assert_eq!(false_key.status, FeatureStatus::Disabled);
    }

    #[test]
    fn test_parse_version_tuple_edge_cases() {
        assert_eq!(parse_version_tuple("1.37.4"), Some((1, 37, 4)));
        assert_eq!(parse_version_tuple("  v1.37.4-testing "), Some((1, 37, 4)));
        assert_eq!(parse_version_tuple("1.37.4-2a3b4c"), Some((1, 37, 4)));
        assert_eq!(parse_version_tuple("2026.7.0"), Some((2026, 7, 0)));
        assert_eq!(parse_version_tuple("2024.12.0"), Some((2024, 12, 0)));
        assert_eq!(parse_version_tuple("1.33"), Some((1, 33, 0)));
        assert_eq!(parse_version_tuple("1"), Some((1, 0, 0)));
        assert_eq!(parse_version_tuple("V2026.10.1"), Some((2026, 10, 1)));
        assert_eq!(parse_version_tuple(""), None);
        assert_eq!(parse_version_tuple("v"), None);
        assert_eq!(parse_version_tuple("testing"), None);
        assert_eq!(parse_version_tuple("garbage-1.2.3"), None);
    }

    #[test]
    fn test_vaultwarden_version_tier_evaluation() {
        // Table of (vendor_version, expected ssh-key-vault-item status when flag is absent).
        let cases: &[(&str, FeatureStatus)] = &[
            ("1.37.4", FeatureStatus::Supported),
            ("1.37.5", FeatureStatus::Supported),
            ("1.38.0", FeatureStatus::Supported),
            ("1.37.3", FeatureStatus::Disabled),
            ("1.35.2", FeatureStatus::Disabled),
            ("1.33.0", FeatureStatus::Disabled),
            ("1.32.9", FeatureStatus::Unsupported),
            ("1.30.0", FeatureStatus::Unsupported),
            ("1.26.0", FeatureStatus::Unsupported),
        ];

        for (vendor, expected) in cases {
            let matrix = evaluate_matrix(
                identity(
                    Some("https://vaultwarden.corp"),
                    Some("Vaultwarden"),
                    Some(vendor),
                    Some("2026.6.0"),
                ),
                &HashMap::new(),
            );
            let ssh_key = matrix
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap();
            assert_eq!(
                ssh_key.status, *expected,
                "vendor {vendor} should map to {expected:?}"
            );
        }

        // `v1.37.4-testing` parses to the GA tier.
        let testing = evaluate_matrix(
            identity(
                Some("https://vaultwarden.corp"),
                Some("Vaultwarden"),
                Some("v1.37.4-testing"),
                None,
            ),
            &HashMap::new(),
        );
        assert_eq!(
            testing
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap()
                .status,
            FeatureStatus::Supported
        );
    }

    #[test]
    fn test_vaultwarden_without_vendor_version_falls_back_to_disabled() {
        // server.name identifies Vaultwarden but no vendor version is present; the simulated
        // Bitwarden compatibility version (2026.x) must NOT be treated as a Vaultwarden release.
        let matrix = evaluate_matrix(
            identity(
                Some("https://vaultwarden.corp"),
                Some("Vaultwarden"),
                None,
                Some("2026.6.0"),
            ),
            &HashMap::new(),
        );
        assert_eq!(
            matrix
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap()
                .status,
            FeatureStatus::Disabled
        );
    }

    #[test]
    fn test_official_bitwarden_falls_back_to_compat_version_tier() {
        // Self-hosted official Bitwarden identified by server.name, compatibility < 2024.12.0.
        let old_official = evaluate_matrix(
            identity(
                Some("https://bitwarden.corp"),
                Some("Bitwarden"),
                None,
                Some("2024.6.0"),
            ),
            &HashMap::new(),
        );
        assert_eq!(
            old_official
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap()
                .status,
            FeatureStatus::Unsupported
        );

        // Non-Vaultwarden calendar version >= 2024.12.0 with no server block.
        let calendar = evaluate_matrix(
            identity(
                Some("https://bitwarden.corp"),
                None,
                None,
                Some("2024.12.0"),
            ),
            &HashMap::new(),
        );
        assert_eq!(
            calendar
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap()
                .status,
            FeatureStatus::Supported
        );
    }

    #[test]
    fn test_explicit_false_override_wins_over_version_defaults() {
        let mut states = HashMap::new();
        states.insert("ssh-key-vault-item".to_string(), Value::Bool(false));

        // Vaultwarden 1.37.4 would default to supported, but explicit `false` overrides it.
        let matrix = evaluate_matrix(
            identity(
                Some("https://vaultwarden.corp"),
                Some("Vaultwarden"),
                Some("1.37.4"),
                Some("2026.6.0"),
            ),
            &states,
        );
        assert_eq!(
            matrix
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap()
                .status,
            FeatureStatus::Disabled
        );
    }

    #[test]
    fn test_evaluate_matrix_without_server_block_does_not_panic() {
        let matrix = evaluate_matrix(identity(None, None, None, None), &HashMap::new());
        assert_eq!(
            matrix
                .iter()
                .find(|m| m.name == "ssh-key-vault-item")
                .unwrap()
                .status,
            FeatureStatus::Disabled
        );
    }

    #[test]
    fn test_cross_server_cache_isolation() {
        let temp = tempfile::tempdir().unwrap();
        std::env::set_var("OMAWARDEN_DATA_DIR", temp.path());

        let caps = ServerCapabilities {
            server_url: "https://vault.corp.local".to_string(),
            server_version: Some("2026.1.0".to_string()),
            server_name: Some("Vaultwarden".to_string()),
            server_vendor_version: Some("1.35.2".to_string()),
            git_hash: None,
            cached_at: Utc::now().to_rfc3339(),
            feature_states: HashMap::new(),
            matrix: Vec::new(),
        };

        save_capabilities(&caps).expect("save must succeed");

        // Cache hit for same origin (trailing slash is not significant)
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local")).is_some());
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local/")).is_some());

        // Cache miss for different origin
        assert!(load_cached_capabilities_for(Some("https://vault.bitwarden.com")).is_none());

        // The cache is keyed on the API base *including path*: a sub-path deployment is
        // distinct from the path-less origin and from a sibling path.
        let subpath_caps = ServerCapabilities {
            server_url: "https://vault.corp.local/old".to_string(),
            ..caps
        };
        save_capabilities(&subpath_caps).expect("save must succeed");

        assert!(load_cached_capabilities_for(Some("https://vault.corp.local/old")).is_some());
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local/old/")).is_some());
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local/new")).is_none());
        assert!(load_cached_capabilities_for(Some("https://vault.corp.local")).is_none());

        std::env::remove_var("OMAWARDEN_DATA_DIR");
    }

    #[test]
    fn test_legacy_cache_without_server_metadata_deserializes() {
        // Simulate a `server_capabilities.json` written by an older Omawarden build.
        let legacy = r#"{
            "server_url": "https://vault.corp.local",
            "server_version": "2026.1.0",
            "git_hash": "abc",
            "cached_at": "2026-11-10T12:00:00Z",
            "feature_states": { "ssh-key-vault-item": true },
            "matrix": []
        }"#;

        let caps: ServerCapabilities =
            serde_json::from_str(legacy).expect("legacy cache must load");
        assert_eq!(caps.server_name, None);
        assert_eq!(caps.server_vendor_version, None);
        assert_eq!(caps.server_version.as_deref(), Some("2026.1.0"));
    }
}
