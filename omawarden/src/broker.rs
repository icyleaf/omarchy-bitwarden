use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use zeroize::Zeroize;

use crate::vault::{VaultItem, VaultManager};

/// Placeholder text substituted in place of detected secret tokens.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED:VAULT_SECRET]";

/// Prohibited environment variable names that must not be injected to prevent hijacking.
pub const PROHIBITED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PATH",
    "IFS",
    "SHELLOPTS",
    "BASH_ENV",
    "ENV",
];

/// Validates whether a string is a valid POSIX environment variable identifier:
/// starts with `[A-Za-z_]` followed by `[A-Za-z0-9_]*`.
pub fn is_valid_env_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Checks if an environment variable name is prohibited for security reasons.
pub fn is_prohibited_env_var(name: &str) -> bool {
    PROHIBITED_ENV_VARS
        .iter()
        .any(|b| b.eq_ignore_ascii_case(name))
}

/// Resolves environment variables from a single VaultItem.
///
/// Injects all custom fields where field name becomes the environment variable name.
/// If the item is a Login with a password, and no field named `PASSWORD` or `API_KEY` is present,
/// it will also expose `PASSWORD`.
pub fn resolve_item_env(item: &VaultItem) -> HashMap<String, String> {
    let mut env = HashMap::new();

    for field in &item.fields {
        let name = field
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let value = field
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        if !name.is_empty()
            && !value.is_empty()
            && is_valid_env_var_name(name)
            && !is_prohibited_env_var(name)
        {
            env.insert(name.to_string(), value.to_string());
        }
    }

    if let Some(ref login) = item.login {
        if let Some(password) = login.get("password").and_then(|v| v.as_str()) {
            if !password.is_empty() && !env.contains_key("PASSWORD") && !env.contains_key("API_KEY")
            {
                // If it looks like an API key or token, prefer API_KEY unless defined
                if password.starts_with("sk-") || password.starts_with("ghp_") {
                    env.insert("API_KEY".to_string(), password.to_string());
                } else {
                    env.insert("PASSWORD".to_string(), password.to_string());
                }
            }
        }
    }

    env
}

/// Resolves requested environment variables from the vault according to item and explicit mappings.
pub fn resolve_broker_env(
    vault_mgr: &VaultManager,
    item_query: Option<&str>,
    env_mappings: &[String],
) -> Result<HashMap<String, String>, String> {
    let mut resolved = HashMap::new();

    if let Some(query) = item_query {
        let item = vault_mgr
            .find_item(query, None)
            .ok_or_else(|| format!("Vault item '{}' not found", query))?;
        let item_env = resolve_item_env(&item);
        resolved.extend(item_env);
    }

    for mapping in env_mappings {
        let parts: Vec<&str> = mapping.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid env mapping '{}': expected format VAR=item or VAR=item#field",
                mapping
            ));
        }

        let var_name = parts[0].trim();
        let target = parts[1].trim();

        if !is_valid_env_var_name(var_name) {
            return Err(format!(
                "Invalid environment variable name '{}' in mapping '{}'",
                var_name, mapping
            ));
        }
        if is_prohibited_env_var(var_name) {
            return Err(format!(
                "Prohibited environment variable name '{}' in mapping '{}'",
                var_name, mapping
            ));
        }

        let (item_name, field_name) = if let Some(idx) = target.find('#') {
            (&target[..idx], Some(&target[idx + 1..]))
        } else {
            (target, None)
        };

        let item = vault_mgr.find_item(item_name, None).ok_or_else(|| {
            format!(
                "Vault item '{}' not found for mapping '{}'",
                item_name, mapping
            )
        })?;

        let val = if let Some(field) = field_name {
            if field.eq_ignore_ascii_case("password") {
                item.login
                    .as_ref()
                    .and_then(|l| l.get("password").and_then(|p| p.as_str()))
                    .ok_or_else(|| format!("Item '{}' has no password", item_name))?
                    .to_string()
            } else if field.eq_ignore_ascii_case("username") {
                item.login
                    .as_ref()
                    .and_then(|l| l.get("username").and_then(|u| u.as_str()))
                    .ok_or_else(|| format!("Item '{}' has no username", item_name))?
                    .to_string()
            } else {
                item.fields
                    .iter()
                    .find(|f| {
                        f.get("name")
                            .and_then(|n| n.as_str())
                            .map(|n| n.eq_ignore_ascii_case(field))
                            .unwrap_or(false)
                    })
                    .and_then(|f| f.get("value").and_then(|v| v.as_str()))
                    .ok_or_else(|| format!("Field '{}' not found in item '{}'", field, item_name))?
                    .to_string()
            }
        } else {
            // No field specified: check fields or password
            let item_env = resolve_item_env(&item);
            if let Some(v) = item_env.get(var_name) {
                v.clone()
            } else if item_env.len() == 1 {
                item_env.into_values().next().unwrap()
            } else if item_env.is_empty() {
                return Err(format!(
                    "Item '{}' has no fields or secret value",
                    item_name
                ));
            } else {
                return Err(format!(
                    "Item '{}' has multiple fields; please specify the field using format {}=item#field",
                    item_name, var_name
                ));
            }
        };

        resolved.insert(var_name.to_string(), val);
    }

    Ok(resolved)
}

/// Builds an Aho-Corasick automaton from secret values and all their substrings of length >= 6.
pub fn build_redaction_filter(secrets: &[&str]) -> Option<(aho_corasick::AhoCorasick, usize)> {
    let mut patterns = std::collections::HashSet::new();
    let mut max_len = 0;

    for &secret in secrets {
        let trimmed = secret.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Always include the full secret value
        patterns.insert(trimmed.to_string());
        if trimmed.len() > max_len {
            max_len = trimmed.len();
        }

        // For secrets of length >= 6, generate all substrings with length >= 6
        if trimmed.len() >= 6 {
            let bytes = trimmed.as_bytes();
            let limit = bytes.len().min(128);
            for len in 6..=limit {
                for window in bytes.windows(len) {
                    if let Ok(s) = std::str::from_utf8(window) {
                        if !s.trim().is_empty() {
                            patterns.insert(s.to_string());
                        }
                    }
                }
            }
        }
    }

    if patterns.is_empty() {
        return None;
    }

    let mut pattern_list: Vec<String> = patterns.into_iter().collect();
    // Sort longest first to guarantee optimal leftmost longest match preference
    pattern_list.sort_by_key(|a| std::cmp::Reverse(a.len()));

    aho_corasick::AhoCorasick::builder()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(pattern_list)
        .ok()
        .map(|ac| (ac, max_len))
}

/// Streams data from `reader` to `writer`, replacing matched secrets with `REDACTION_PLACEHOLDER`.
pub fn stream_redacted<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    filter: &aho_corasick::AhoCorasick,
    max_pattern_len: usize,
) -> std::io::Result<()> {
    let replacement = REDACTION_PLACEHOLDER.as_bytes();
    let replacements = vec![replacement; filter.patterns_len()];
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            // EOF: scrub any remaining pending bytes and flush
            if !pending.is_empty() {
                let redacted = filter.replace_all_bytes(&pending, &replacements);
                writer.write_all(&redacted)?;
                writer.flush()?;
            }
            break;
        }

        pending.extend_from_slice(&buf[..n]);

        if let Some(last_nl) = pending.iter().rposition(|&b| b == b'\n') {
            let chunk = &pending[..=last_nl];
            let redacted = filter.replace_all_bytes(chunk, &replacements);
            writer.write_all(&redacted)?;
            writer.flush()?;
            pending.drain(..=last_nl);
        } else if pending.len() >= 8192 {
            let split_at = pending.len().saturating_sub(max_pattern_len);
            if split_at > 0 {
                let chunk = &pending[..split_at];
                let redacted = filter.replace_all_bytes(chunk, &replacements);
                writer.write_all(&redacted)?;
                writer.flush()?;
                pending.drain(..split_at);
            }
        }
    }

    Ok(())
}

/// Spawns the child command with injected environment variables, zeroes out in-memory secrets,
/// streams and redacts stdout and stderr in real-time (unless `redact == false`), and waits for completion.
pub fn execute_child_process(
    cmd: &[String],
    mut env_vars: HashMap<String, String>,
    redact: bool,
) -> Result<ExitStatus, std::io::Error> {
    if cmd.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "No command provided",
        ));
    }

    let filter_opt = if redact {
        let secret_values: Vec<&str> = env_vars.values().map(|s| s.as_str()).collect();
        build_redaction_filter(&secret_values)
    } else {
        None
    };

    let mut command = Command::new(&cmd[0]);
    if cmd.len() > 1 {
        command.args(&cmd[1..]);
    }

    for (k, v) in &env_vars {
        command.env(k, v);
    }

    if filter_opt.is_some() {
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
    }

    let mut child = command.spawn()?;

    // Scrub secret strings in memory immediately after child process spawn
    for v in env_vars.values_mut() {
        v.zeroize();
    }
    drop(env_vars);

    if let Some((filter, max_pattern_len)) = filter_opt {
        let filter_arc = Arc::new(filter);
        let mut child_stdout = child.stdout.take().expect("Piped child stdout");
        let mut child_stderr = child.stderr.take().expect("Piped child stderr");

        let filter_out = Arc::clone(&filter_arc);
        let t_out = std::thread::spawn(move || {
            let mut out = std::io::stdout();
            let _ = stream_redacted(&mut child_stdout, &mut out, &filter_out, max_pattern_len);
        });

        let filter_err = Arc::clone(&filter_arc);
        let t_err = std::thread::spawn(move || {
            let mut err = std::io::stderr();
            let _ = stream_redacted(&mut child_stderr, &mut err, &filter_err, max_pattern_len);
        });

        let status = child.wait()?;
        let _ = t_out.join();
        let _ = t_err.join();
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        Ok(status)
    } else {
        child.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_resolve_item_env_from_fields() {
        let item = VaultItem {
            id: "test-id".into(),
            name: "OpenAI".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "OPENAI_API_KEY", "value": "sk-12345", "type": 1 }),
                json!({ "name": "BASE_URL", "value": "https://api.openai.com", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        let env = resolve_item_env(&item);
        assert_eq!(env.get("OPENAI_API_KEY"), Some(&"sk-12345".to_string()));
        assert_eq!(
            env.get("BASE_URL"),
            Some(&"https://api.openai.com".to_string())
        );
    }

    #[test]
    fn test_resolve_broker_env_multi_item_and_explicit_mappings() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let note = VaultItem {
            id: "note-1".into(),
            name: "OpenAI".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "OPENAI_API_KEY", "value": "sk-proj-test", "type": 1 }),
                json!({ "name": "ORG_ID", "value": "org-999", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        let login = VaultItem {
            id: "login-1".into(),
            name: "GitHub".into(),
            item_type: 1,
            type_name: "login".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(json!({
                "username": "octocat",
                "password": "ghp_super_secret_token"
            })),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![note, login];

        let mappings = vec![
            "GH_TOKEN=GitHub#password".to_string(),
            "GH_USER=GitHub#username".to_string(),
        ];
        let resolved = resolve_broker_env(&vault_mgr, Some("OpenAI"), &mappings).unwrap();

        assert_eq!(
            resolved.get("OPENAI_API_KEY"),
            Some(&"sk-proj-test".to_string())
        );
        assert_eq!(resolved.get("ORG_ID"), Some(&"org-999".to_string()));
        assert_eq!(
            resolved.get("GH_TOKEN"),
            Some(&"ghp_super_secret_token".to_string())
        );
        assert_eq!(resolved.get("GH_USER"), Some(&"octocat".to_string()));
    }

    #[test]
    fn test_execute_child_process_injection_and_exit_code() {
        let mut env = HashMap::new();
        env.insert(
            "INJECTED_TEST_VAR".to_string(),
            "MAGIC_VALUE_42".to_string(),
        );

        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"if [ "$INJECTED_TEST_VAR" = "MAGIC_VALUE_42" ]; then exit 42; else exit 1; fi"#
                .to_string(),
        ];

        let status = execute_child_process(&cmd, env, false).unwrap();
        assert_eq!(status.code(), Some(42));
    }

    #[test]
    fn test_execute_child_process_with_redaction() {
        let mut env = HashMap::new();
        env.insert(
            "API_SECRET_KEY".to_string(),
            "sk-proj-secret-99999".to_string(),
        );

        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            r#"echo "KEY is $API_SECRET_KEY""#.to_string(),
        ];

        let status = execute_child_process(&cmd, env, true).unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_stream_redacted_full_and_substring() {
        use aho_corasick::{AhoCorasick, MatchKind};
        let secret = "sk-proj-1234567890abcdef";
        // Build patterns with full secret and substrings >= 6
        let mut patterns = std::collections::HashSet::new();
        patterns.insert(secret.to_string());
        let bytes = secret.as_bytes();
        for len in 6..=bytes.len().min(64) {
            for window in bytes.windows(len) {
                if let Ok(s) = std::str::from_utf8(window) {
                    patterns.insert(s.to_string());
                }
            }
        }
        let mut pattern_list: Vec<String> = patterns.into_iter().collect();
        pattern_list.sort_by_key(|a| std::cmp::Reverse(a.len()));

        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&pattern_list)
            .unwrap();

        // Test 1: Full secret
        let input1 = b"LOG: token=sk-proj-1234567890abcdef\n";
        let mut out1 = Vec::new();
        stream_redacted(&input1[..], &mut out1, &ac, 64).unwrap();
        assert_eq!(
            String::from_utf8(out1).unwrap(),
            "LOG: token=[REDACTED:VAULT_SECRET]\n"
        );

        // Test 2: Substring >= 6
        let input2 = b"DEBUG: prefix=sk-proj suffix=0abcdef\n";
        let mut out2 = Vec::new();
        stream_redacted(&input2[..], &mut out2, &ac, 64).unwrap();
        assert_eq!(
            String::from_utf8(out2).unwrap(),
            "DEBUG: prefix=[REDACTED:VAULT_SECRET] suffix=[REDACTED:VAULT_SECRET]\n"
        );

        // Test 3: Substring < 6 (should NOT be redacted)
        let input3 = b"INFO: small=sk-\n";
        let mut out3 = Vec::new();
        stream_redacted(&input3[..], &mut out3, &ac, 64).unwrap();
        assert_eq!(String::from_utf8(out3).unwrap(), "INFO: small=sk-\n");
    }

    #[test]
    fn test_build_redaction_filter_and_heavy_streaming() {
        let secrets = ["sk-proj-heavy-secret-token-123456"];
        let (filter, max_len) = build_redaction_filter(&secrets).expect("Build filter");
        assert_eq!(max_len, "sk-proj-heavy-secret-token-123456".len());

        // Generate 2MB of streaming chunks mixing secrets and padding
        let mut large_input = Vec::new();
        for i in 0..1000 {
            large_input.extend_from_slice(
                format!(
                    "chunk {} containing sk-proj-heavy-secret-token-123456 and padding {:01000}\n",
                    i, 0
                )
                .as_bytes(),
            );
        }

        let mut output = Vec::new();
        stream_redacted(&large_input[..], &mut output, &filter, max_len)
            .expect("Stream redacts without error");

        let out_str = String::from_utf8(output).expect("Valid utf8 output");
        assert!(!out_str.contains("sk-proj-heavy-secret-token-123456"));
        assert!(out_str.contains("[REDACTED:VAULT_SECRET]"));
    }

    #[test]
    fn test_execute_child_process_heavy_streaming_no_deadlock() {
        let mut env = HashMap::new();
        env.insert(
            "MY_HEAVY_SECRET".to_string(),
            "sk-proj-secret-token-xyz".to_string(),
        );

        // Child process outputs 500 lines to stdout and stderr concurrently
        let cmd = vec![
            "sh".to_string(),
            "-c".to_string(),
            "for i in $(seq 1 500); do echo stdout $i $MY_HEAVY_SECRET; echo stderr $i $MY_HEAVY_SECRET >&2; done".to_string(),
        ];

        let status = execute_child_process(&cmd, env, true).unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_valid_and_prohibited_env_vars() {
        assert!(is_valid_env_var_name("MY_KEY"));
        assert!(is_valid_env_var_name("_SECRET_123"));
        assert!(!is_valid_env_var_name("123_KEY"));
        assert!(!is_valid_env_var_name("KEY=VAL"));
        assert!(!is_valid_env_var_name("KEY-WITH-DASH"));
        assert!(!is_valid_env_var_name(""));

        assert!(is_prohibited_env_var("LD_PRELOAD"));
        assert!(is_prohibited_env_var("ld_preload"));
        assert!(is_prohibited_env_var("PATH"));
        assert!(!is_prohibited_env_var("OPENAI_API_KEY"));
    }

    #[test]
    fn test_resolve_broker_env_rejects_dangerous_and_invalid_names() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let note = VaultItem {
            id: "note-1".into(),
            name: "OpenAI".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "OPENAI_API_KEY", "value": "sk-proj-test", "type": 1 }),
                json!({ "name": "LD_PRELOAD", "value": "/tmp/evil.so", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![note];

        // 1. Prohibited field in item is filtered out automatically by resolve_item_env
        let resolved = resolve_broker_env(&vault_mgr, Some("OpenAI"), &[]).unwrap();
        assert_eq!(
            resolved.get("OPENAI_API_KEY"),
            Some(&"sk-proj-test".to_string())
        );
        assert!(!resolved.contains_key("LD_PRELOAD"));

        // 2. Explicit mapping trying to inject LD_PRELOAD should error
        let err = resolve_broker_env(
            &vault_mgr,
            None,
            &["LD_PRELOAD=OpenAI#OPENAI_API_KEY".to_string()],
        )
        .unwrap_err();
        assert!(err.contains("Prohibited environment variable name"));

        // 3. Explicit mapping with invalid identifier should error
        let err2 = resolve_broker_env(
            &vault_mgr,
            None,
            &["INVALID-NAME=OpenAI#OPENAI_API_KEY".to_string()],
        )
        .unwrap_err();
        assert!(err2.contains("Invalid environment variable name"));
    }

    #[test]
    fn test_resolve_broker_env_multi_field_requires_field_specifier() {
        let vault_mgr = VaultManager::new("", None, None);
        *vault_mgr.is_unlocked.write().unwrap() = true;

        let note = VaultItem {
            id: "note-1".into(),
            name: "MultiField".into(),
            item_type: 2,
            type_name: "secure_note".into(),
            sub_title: "".into(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![
                json!({ "name": "FIELD_A", "value": "val-a", "type": 0 }),
                json!({ "name": "FIELD_B", "value": "val-b", "type": 0 }),
            ],
            attachments: vec![],
            search_text: "".into(),
        };

        *vault_mgr.decrypted_items.write().unwrap() = vec![note];

        // Mapping to MultiField with non-matching var_name must fail closed
        let err =
            resolve_broker_env(&vault_mgr, None, &["MY_VAR=MultiField".to_string()]).unwrap_err();
        assert!(err.contains("has multiple fields; please specify the field"));

        // If var_name matches one of the fields, it resolves cleanly
        let resolved =
            resolve_broker_env(&vault_mgr, None, &["FIELD_A=MultiField".to_string()]).unwrap();
        assert_eq!(resolved.get("FIELD_A"), Some(&"val-a".to_string()));
    }
}
