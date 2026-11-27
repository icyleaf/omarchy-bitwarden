use serde_json::{json, Value};
use std::io::{self, BufRead, IsTerminal, Read};

/// Strict boolean for CLI flags: anything outside true/false/1/0/yes/no is a
/// parse error instead of silently becoming `false`. `--quick-unlock ture`
/// used to report success, persist `quick_unlock: false` and immediately
/// wipe the retained key.
pub(crate) fn parse_cli_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => Err(format!(
            "invalid boolean '{other}': expected one of true|false|1|0|yes|no"
        )),
    }
}

/// Parse one `NAME=VALUE` custom field declaration, rejecting a missing
/// separator or an empty name before the payload reaches the daemon.
pub(crate) fn parse_custom_field_name_value(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err(format!(
            "Invalid custom field '{raw}': expected NAME=VALUE."
        ));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(format!(
            "Invalid custom field '{raw}': name cannot be empty."
        ));
    }
    Ok((name.to_string(), value.to_string()))
}

/// Build the encrypted-ready `fields` array (plaintext, encrypted by the
/// daemon) from the repeatable typed field flags. Text fields map to type 0,
/// hidden fields to type 1 and boolean fields to type 2.
pub(crate) fn build_custom_fields(
    fields: &[String],
    hidden_fields: &[String],
    bool_fields: &[String],
) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for raw in fields {
        let (name, value) = parse_custom_field_name_value(raw)?;
        out.push(json!({ "name": name, "value": value, "type": 0 }));
    }
    for raw in hidden_fields {
        let (name, value) = parse_custom_field_name_value(raw)?;
        out.push(json!({ "name": name, "value": value, "type": 1 }));
    }
    for raw in bool_fields {
        let (name, value) = parse_custom_field_name_value(raw)?;
        let canonical = match value.to_lowercase().as_str() {
            "true" => "true",
            "false" => "false",
            other => {
                return Err(format!(
                    "Invalid boolean value '{other}' for custom field '{name}': expected true or false."
                ));
            }
        };
        out.push(json!({ "name": name, "value": canonical, "type": 2 }));
    }
    Ok(out)
}

/// Emit a vault command failure in whichever envelope the caller asked for.
pub(crate) fn emit_vault_error(json: bool, message: &str) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": message,
            }))
            .unwrap()
        );
    } else {
        eprintln!("Error: {message}");
    }
}

/// Auth output can carry a raw access token in `session`. Piped callers (the
/// QML helper) depend on it; an interactive terminal would only leave it
/// behind in scrollback, so redact it there.
pub(crate) fn print_json_redacting_session<T: serde::Serialize>(value: &T) {
    let mut val = serde_json::to_value(value).unwrap_or(Value::Null);
    if io::stdout().is_terminal() {
        if let Some(session) = val.get("session").and_then(Value::as_str) {
            if !session.is_empty() {
                val["session"] = json!("[redacted; pipe stdout to keep the token]");
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&val).unwrap());
}

pub(crate) fn read_secret_stdin() -> String {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return String::new();
    }
    let mut buffer = String::new();
    if stdin.lock().read_line(&mut buffer).is_ok() {
        return buffer.trim_end_matches(&['\r', '\n'][..]).to_string();
    }
    String::new()
}

pub(crate) fn read_json_payload_stdin() -> zeroize::Zeroizing<String> {
    let stdin = io::stdin();
    let mut raw = String::new();
    if stdin.lock().read_line(&mut raw).is_ok() {
        let trimmed = raw.trim_end_matches(&['\r', '\n'][..]).trim();
        // If the first line is already valid complete JSON (e.g. from Quickshell/scripts
        // which don't close the stdin pipe), parse it directly without blocking on EOF.
        if serde_json::from_str::<Value>(trimmed).is_ok() {
            return zeroize::Zeroizing::new(trimmed.to_string());
        }
        let mut rest = String::new();
        let _ = stdin.lock().read_to_string(&mut rest);
        return zeroize::Zeroizing::new(format!("{}{}", raw, rest));
    }
    zeroize::Zeroizing::new(String::new())
}

pub(crate) fn read_clipboard_stdin() -> String {
    let stdin = io::stdin();
    let mut raw = String::new();
    if stdin.lock().read_line(&mut raw).is_ok() {
        let trimmed = raw.trim_end_matches(&['\r', '\n'][..]);
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
                return text.to_string();
            }
        }
        let mut rest = String::new();
        let _ = stdin.lock().read_to_string(&mut rest);
        if rest.is_empty() {
            return trimmed.to_string();
        } else {
            return format!("{}{}", raw, rest);
        }
    }
    String::new()
}

pub(crate) fn parse_auth_payload(
    raw: &str,
) -> (String, Option<String>, Option<i32>, Option<String>) {
    let trimmed = raw.trim_end_matches(&['\r', '\n'][..]).trim();
    if trimmed.is_empty() {
        return (String::new(), None, None, None);
    }

    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        if let Some(map) = val.as_object() {
            let pwd = map
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let code_val = map
                .get("code")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let two_factor_provider = map
                .get("two_factor_provider")
                .or_else(|| map.get("twoFactorProvider"))
                .or_else(|| map.get("provider"))
                .and_then(|v| {
                    if let Some(n) = v.as_i64() {
                        Some(n as i32)
                    } else if let Some(s) = v.as_str() {
                        s.parse::<i32>().ok()
                    } else {
                        None
                    }
                });
            let new_device_otp = map
                .get("new_device_otp")
                .or_else(|| map.get("newDeviceOtp"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return (pwd, code_val, two_factor_provider, new_device_otp);
        }
    }

    let mut pwd = trimmed.to_string();
    if pwd.starts_with('"') && pwd.ends_with('"') && pwd.len() >= 2 {
        if let Ok(unescaped) = serde_json::from_str::<String>(&pwd) {
            pwd = unescaped;
        }
    }

    (pwd, None, None, None)
}

pub(crate) fn read_auth_payload() -> (String, Option<String>, Option<i32>, Option<String>) {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return (String::new(), None, None, None);
    }
    let mut buffer = String::new();
    if stdin.lock().read_line(&mut buffer).is_err() {
        return (String::new(), None, None, None);
    }
    parse_auth_payload(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cli_bool_accepts_known_values() {
        for v in ["true", "TRUE", "1", "yes", " Yes "] {
            assert!(matches!(parse_cli_bool(v), Ok(true)), "{v}");
        }
        for v in ["false", "0", "NO", " no "] {
            assert!(matches!(parse_cli_bool(v), Ok(false)), "{v}");
        }
    }

    #[test]
    fn test_parse_cli_bool_rejects_typos() {
        // "ture" must be a hard error: coerced to false it would persist a
        // disabled setting and wipe the retained quick-unlock key.
        for v in ["ture", "flase", "on", "off", ""] {
            assert!(parse_cli_bool(v).is_err(), "{v} should not parse");
        }
    }

    #[test]
    fn test_parse_auth_payload_plain() {
        let (pwd, code, provider, ndv) = parse_auth_payload("mypassword\n");
        assert_eq!(pwd, "mypassword");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_json_with_code() {
        let (pwd, code, provider, ndv) =
            parse_auth_payload("{\"password\": \"secret123\", \"code\": \"654321\"}\n");
        assert_eq!(pwd, "secret123");
        assert_eq!(code.as_deref(), Some("654321"));
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_json_with_new_device_otp() {
        let (pwd, code, provider, ndv) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"111222\", \"new_device_otp\": \"111222\"}\n",
        );
        assert_eq!(pwd, "secret123");
        assert_eq!(code.as_deref(), Some("111222"));
        assert_eq!(provider, None);
        assert_eq!(ndv.as_deref(), Some("111222"));

        let (pwd2, code2, provider2, ndv2) =
            parse_auth_payload("{\"password\": \"secret123\", \"newDeviceOtp\": \"333444\"}\n");
        assert_eq!(pwd2, "secret123");
        assert_eq!(code2, None);
        assert_eq!(provider2, None);
        assert_eq!(ndv2.as_deref(), Some("333444"));
    }

    #[test]
    fn test_parse_auth_payload_json_with_provider() {
        let (pwd, code, provider, ndv) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"123456\", \"two_factor_provider\": 1}\n",
        );
        assert_eq!(pwd, "secret123");
        assert_eq!(code.as_deref(), Some("123456"));
        assert_eq!(provider, Some(1));
        assert_eq!(ndv, None);

        let (pwd2, code2, provider2, ndv2) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"999888\", \"provider\": \"3\"}\n",
        );
        assert_eq!(pwd2, "secret123");
        assert_eq!(code2.as_deref(), Some("999888"));
        assert_eq!(provider2, Some(3));
        assert_eq!(ndv2, None);
    }

    #[test]
    fn test_parse_auth_payload_json_without_code() {
        let (pwd, code, provider, ndv) = parse_auth_payload("{\"password\": \"secret123\"}\n");
        assert_eq!(pwd, "secret123");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_empty() {
        let (pwd, code, provider, ndv) = parse_auth_payload("  \r\n");
        assert_eq!(pwd, "");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_build_custom_fields_typed_flags() {
        let fields = build_custom_fields(
            &["Cluster=Prod".to_string()],
            &["API_KEY=secret-tok".to_string()],
            &["Requires VPN=true".to_string(), "Retired=false".to_string()],
        )
        .unwrap();
        assert_eq!(
            fields,
            vec![
                json!({"name": "Cluster", "value": "Prod", "type": 0}),
                json!({"name": "API_KEY", "value": "secret-tok", "type": 1}),
                json!({"name": "Requires VPN", "value": "true", "type": 2}),
                json!({"name": "Retired", "value": "false", "type": 2}),
            ]
        );
    }

    #[test]
    fn test_build_custom_fields_keeps_equals_in_value() {
        let fields = build_custom_fields(&["Equation=a=b".to_string()], &[], &[]).unwrap();
        assert_eq!(fields[0]["name"], "Equation");
        assert_eq!(fields[0]["value"], "a=b");
    }

    #[test]
    fn test_build_custom_fields_rejects_missing_separator() {
        let err = build_custom_fields(&["NoSeparator".to_string()], &[], &[]).unwrap_err();
        assert!(err.contains("expected NAME=VALUE"), "unexpected: {err}");
    }

    #[test]
    fn test_build_custom_fields_rejects_empty_name() {
        let err = build_custom_fields(&[], &["=oops".to_string()], &[]).unwrap_err();
        assert!(err.contains("name cannot be empty"), "unexpected: {err}");
    }

    #[test]
    fn test_build_custom_fields_rejects_malformed_boolean() {
        let err = build_custom_fields(&[], &[], &["Active=maybe".to_string()]).unwrap_err();
        assert!(
            err.contains("Invalid boolean value 'maybe' for custom field 'Active'"),
            "unexpected: {err}"
        );
    }
}
