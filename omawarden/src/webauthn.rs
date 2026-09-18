use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::process::{Command, Stdio};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnChallenge {
    pub challenge: String,
    pub rp_id: String,
    pub origin: String,
    pub allow_credentials: Vec<String>,
}

/// Converts a Base64URL string (RFC 4648 §5) to standard Base64.
pub fn base64url_to_base64(s: &str) -> String {
    let mut b64 = s.replace('-', "+").replace('_', "/");
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    b64
}

/// Converts a standard Base64 string to unpadded Base64URL (RFC 4648 §5).
pub fn base64_to_base64url(s: &str) -> String {
    s.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Parses WebAuthn challenge parameters from Bitwarden/Vaultwarden `TwoFactorProviders2["7"]`.
pub fn parse_webauthn_challenge(
    val: &serde_json::Value,
    server_url: &str,
) -> Option<WebAuthnChallenge> {
    let target = val.get("7").unwrap_or(val);
    let obj = target.get("publicKey").unwrap_or(target);

    let challenge = obj
        .get("challenge")
        .or_else(|| obj.get("Challenge"))
        .and_then(|v| v.as_str())?
        .to_string();

    let parsed_url = Url::parse(server_url).ok();
    let fallback_rp = parsed_url
        .as_ref()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "localhost".to_string());

    let rp_id = obj
        .get("rpId")
        .or_else(|| obj.get("RelyingPartyId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or(fallback_rp);

    let origin = parsed_url
        .as_ref()
        .map(|u| u.origin().ascii_serialization())
        .filter(|o| o != "null")
        .unwrap_or_else(|| format!("https://{}", rp_id));

    let mut allow_credentials = Vec::new();
    let creds_arr = obj
        .get("allowCredentials")
        .or_else(|| obj.get("AllowCredentials"))
        .and_then(|v| v.as_array());

    if let Some(arr) = creds_arr {
        for item in arr {
            if let Some(id_str) = item.as_str() {
                allow_credentials.push(id_str.to_string());
            } else if let Some(id_str) = item.get("id").and_then(|v| v.as_str()) {
                allow_credentials.push(id_str.to_string());
            }
        }
    }

    Some(WebAuthnChallenge {
        challenge,
        rp_id,
        origin,
        allow_credentials,
    })
}

/// Discovers connected FIDO2 USB devices using `fido2-token -L`.
pub fn find_fido2_device() -> Result<String, String> {
    let output = Command::new("fido2-token")
        .arg("-L")
        .output()
        .map_err(|e| format!("Failed to execute fido2-token: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "fido2-token exited with error: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(pos) = trimmed.find(':') {
            let dev = &trimmed[..pos];
            if dev.starts_with("/dev/hidraw") {
                return Ok(dev.to_string());
            }
        }
    }

    Err("No FIDO2 security key found. Please insert your security key.".to_string())
}

/// Executes `fido2-assert -G` to perform a WebAuthn CTAP2 assertion with the physical key.
pub fn perform_fido2_assertion(
    challenge_data: &WebAuthnChallenge,
    device_path: &str,
) -> Result<serde_json::Value, String> {
    let origin = &challenge_data.origin;
    let client_data_json = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_data.challenge,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_bytes = serde_json::to_vec(&client_data_json)
        .map_err(|e| format!("Failed to serialize clientDataJSON: {}", e))?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data_bytes);
    let client_data_hash = hasher.finalize();
    let cd_hash_b64 = BASE64.encode(client_data_hash);

    let cred_id_raw = challenge_data
        .allow_credentials
        .first()
        .ok_or_else(|| "No credential ID found in WebAuthn challenge".to_string())?;
    let cred_id_b64 = base64url_to_base64(cred_id_raw);

    let stdin_payload = format!(
        "{}\n{}\n{}\n",
        cd_hash_b64, challenge_data.rp_id, cred_id_b64
    );

    let mut child = Command::new("fido2-assert")
        .arg("-G")
        .arg("-t")
        .arg("pin=false")
        .arg(device_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute fido2-assert: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_payload.as_bytes())
            .map_err(|e| format!("Failed to write to fido2-assert stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for fido2-assert: {}", e))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("FIDO2 assertion failed: {}", err_msg.trim()));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str.lines().map(|s| s.trim()).collect();
    if lines.len() < 4 {
        return Err(format!(
            "Unexpected output format from fido2-assert: {:?}",
            lines
        ));
    }

    // Line 0: cd_hash
    // Line 1: rp_id
    // Line 2: authenticator_data (base64)
    // Line 3: signature (base64)
    let auth_data_b64url = base64_to_base64url(lines[2]);
    let signature_b64url = base64_to_base64url(lines[3]);
    let client_data_b64url = base64_to_base64url(&BASE64.encode(&client_data_bytes));
    let cred_id_b64url = base64_to_base64url(&cred_id_b64);

    let token_payload = serde_json::json!({
        "id": cred_id_b64url,
        "rawId": cred_id_b64url,
        "type": "public-key",
        "response": {
            "authenticatorData": auth_data_b64url,
            "clientDataJSON": client_data_b64url,
            "signature": signature_b64url,
            "userHandle": null
        },
        "clientExtensionResults": {}
    });

    Ok(token_payload)
}

/// Convenience function to discover FIDO2 key, execute assertion, and generate WebAuthn 2FA token.
pub fn create_webauthn_two_factor_token(
    challenge_data: &WebAuthnChallenge,
) -> Result<String, String> {
    let device = find_fido2_device()?;
    let payload = perform_fido2_assertion(challenge_data, &device)?;
    Ok(payload.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_base64url_roundtrip() {
        // Valid Base64 for 10 bytes: 14 chars + 2 padding '='
        let original_2pad = "SGVsbG8gV29ybA==";
        let url_safe_2pad = base64_to_base64url(original_2pad);
        assert_eq!(url_safe_2pad, "SGVsbG8gV29ybA");
        let restored_2pad = base64url_to_base64(&url_safe_2pad);
        assert_eq!(restored_2pad, original_2pad);

        // Valid Base64 with + and /
        let original_chars = "Hello+World/Te==";
        let url_safe_chars = base64_to_base64url(original_chars);
        assert_eq!(url_safe_chars, "Hello-World_Te");
        let restored_chars = base64url_to_base64(&url_safe_chars);
        assert_eq!(restored_chars, original_chars);
    }

    #[test]
    fn test_parse_webauthn_challenge_vaultwarden_format() {
        let json_val = serde_json::json!({
            "7": {
                "publicKey": {
                    "challenge": "dGVzdF9jaGFsbGVuZ2U",
                    "rpId": "vault.example.com",
                    "allowCredentials": [
                        { "id": "Y3JlZF8x", "type": "public-key" },
                        { "id": "Y3JlZF8y", "type": "public-key" }
                    ]
                }
            }
        });

        let parsed = parse_webauthn_challenge(&json_val, "https://vault.example.com").unwrap();
        assert_eq!(parsed.challenge, "dGVzdF9jaGFsbGVuZ2U");
        assert_eq!(parsed.rp_id, "vault.example.com");
        assert_eq!(parsed.origin, "https://vault.example.com");
        assert_eq!(parsed.allow_credentials, vec!["Y3JlZF8x", "Y3JlZF8y"]);
    }

    #[test]
    fn test_parse_webauthn_challenge_official_format() {
        let json_val = serde_json::json!({
            "7": {
                "Challenge": "b2ZmaWNpYWxfY2hhbGxlbmdl",
                "RelyingPartyId": "bitwarden.com",
                "AllowCredentials": ["Y3JlZF9h", "Y3JlZF9i"]
            }
        });

        let parsed = parse_webauthn_challenge(&json_val, "https://vault.bitwarden.com").unwrap();
        assert_eq!(parsed.challenge, "b2ZmaWNpYWxfY2hhbGxlbmdl");
        assert_eq!(parsed.rp_id, "bitwarden.com");
        assert_eq!(parsed.origin, "https://vault.bitwarden.com");
        assert_eq!(parsed.allow_credentials, vec!["Y3JlZF9h", "Y3JlZF9i"]);
    }
}
