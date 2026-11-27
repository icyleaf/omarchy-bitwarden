use omawarden_engine::config::Config;
use omawarden_engine::daemon::ensure_daemon_capability;
use serde_json::{json, Value};
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use super::super::client::{resolve_target_cipher, submit_cipher_mutation};
use super::super::io::{build_custom_fields, emit_vault_error, read_json_payload_stdin};
use super::editor::handle_editor_edit;

/// Transport keys that a stdin/`--from-json` update payload may echo back but
/// that must never override the CLI-resolved target or daemon routing.
const CIPHER_UPDATE_RESERVED_KEYS: [&str; 4] = ["action", "id", "target", "client"];

/// Keys that only make sense on Login ciphers. The daemon enforces this too,
/// but rejecting before dispatch keeps Secure Note edits from surfacing a
/// confusing IPC error.
const CIPHER_UPDATE_LOGIN_KEYS: [&str; 7] = [
    "username",
    "password",
    "totp",
    "uri",
    "uris",
    "add_uris",
    "clear_uris",
];

/// Parse a JSON cipher-update payload piped over stdin or read from a file.
/// Reserved transport keys and `null` values are stripped, and a payload with
/// nothing left is rejected so an empty diff never reaches the daemon.
fn parse_cipher_update_payload(raw: &str) -> Result<Value, String> {
    let parsed: Value =
        serde_json::from_str(raw).map_err(|err| format!("Invalid JSON payload: {err}"))?;
    let Some(object) = parsed.as_object() else {
        return Err("Invalid JSON payload: expected a JSON object.".into());
    };

    let mut payload = serde_json::Map::new();
    for (key, value) in object {
        if CIPHER_UPDATE_RESERVED_KEYS.contains(&key.as_str()) || value.is_null() {
            continue;
        }
        payload.insert(key.clone(), value.clone());
    }

    if payload.is_empty() {
        return Err(
            "No fields specified to edit. Provide at least one field to update in the JSON payload."
                .into(),
        );
    }

    Ok(Value::Object(payload))
}

fn cipher_update_payload_has_login_fields(payload: &Value) -> bool {
    CIPHER_UPDATE_LOGIN_KEYS
        .iter()
        .any(|key| payload.get(*key).is_some())
}

pub(crate) struct EditArgs {
    pub(crate) target: String,
    pub(crate) name: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) password_stdin: bool,
    pub(crate) generate_password: bool,
    pub(crate) generate_passphrase: bool,
    pub(crate) totp_stdin: bool,
    pub(crate) clear_totp: bool,
    pub(crate) notes: Option<String>,
    pub(crate) notes_stdin: bool,
    pub(crate) uris: Vec<String>,
    pub(crate) add_uris: Vec<String>,
    pub(crate) clear_uris: bool,
    pub(crate) fields: Vec<String>,
    pub(crate) hidden_fields: Vec<String>,
    pub(crate) bool_fields: Vec<String>,
    pub(crate) remove_fields: Vec<String>,
    pub(crate) folder_id: Option<String>,
    pub(crate) favorite: Option<bool>,
    pub(crate) stdin: bool,
    pub(crate) from_json: Option<PathBuf>,
    pub(crate) json: bool,
}

pub(crate) fn run(args: EditArgs, cfg: &Config) -> ExitCode {
    let EditArgs {
        target,
        name,
        username,
        password,
        password_stdin,
        generate_password,
        generate_passphrase,
        totp_stdin,
        clear_totp,
        notes,
        notes_stdin,
        uris,
        add_uris,
        clear_uris,
        fields,
        hidden_fields,
        bool_fields,
        remove_fields,
        folder_id,
        favorite,
        stdin,
        from_json,
        json,
    } = args;

    let has_field_flags = name.is_some()
        || username.is_some()
        || password.is_some()
        || password_stdin
        || generate_password
        || generate_passphrase
        || totp_stdin
        || clear_totp
        || notes.is_some()
        || notes_stdin
        || !uris.is_empty()
        || !add_uris.is_empty()
        || clear_uris
        || !fields.is_empty()
        || !hidden_fields.is_empty()
        || !bool_fields.is_empty()
        || !remove_fields.is_empty()
        || folder_id.is_some()
        || favorite.is_some();

    let has_json_payload = stdin || from_json.is_some();

    let is_interactive =
        (std::io::stdin().is_terminal() || std::env::var_os("OMA_FORCE_PROMPT").is_some()) && !json;

    if !has_field_flags && !has_json_payload && !is_interactive {
        let err_msg = "No fields specified to edit. Provide at least one field to update (e.g. --password) or run in an interactive terminal to use $EDITOR.";
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "error": err_msg,
                }))
                .unwrap()
            );
        } else {
            eprintln!("Error: {err_msg}");
        }
        return ExitCode::FAILURE;
    }

    let client_ctx = omawarden_engine::api::resolve_effective_client_context(None);

    let resolved = match resolve_target_cipher(
        &target,
        "edit",
        client_ctx.as_ref(),
        is_interactive,
        json,
        false,
    ) {
        Ok(item) => item,
        Err(code) => return code,
    };

    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
    let item_name = resolved["name"].as_str().unwrap_or("").to_string();
    let item_type = resolved["type"].as_str().unwrap_or("");

    let is_org = resolved
        .get("organization_id")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let org_can_edit = resolved
        .get("edit")
        .and_then(Value::as_bool)
        .unwrap_or(!is_org);
    let org_can_view_password = resolved
        .get("view_password")
        .and_then(Value::as_bool)
        .unwrap_or(!is_org);

    if !has_field_flags && !has_json_payload {
        if is_org {
            if !org_can_edit {
                emit_vault_error(
                    json,
                    "You do not have permission to edit this Organization cipher.",
                );
                return ExitCode::FAILURE;
            }
            if !org_can_view_password {
                emit_vault_error(
                    json,
                    "Cannot edit Organization cipher while passwords are hidden (viewPassword is false).",
                );
                return ExitCode::FAILURE;
            }
            if let Err(err_msg) =
                ensure_daemon_capability(omawarden_engine::daemon::CAPABILITY_ORG_WRITE)
            {
                emit_vault_error(json, &err_msg);
                return ExitCode::FAILURE;
            }
        }
        return handle_editor_edit(cfg, &resolved, client_ctx.as_ref());
    }

    let mut daemon_req = if has_json_payload {
        let raw_json = if stdin {
            read_json_payload_stdin()
        } else if let Some(path) = from_json.as_ref() {
            match std::fs::read_to_string(path) {
                Ok(content) => zeroize::Zeroizing::new(content),
                Err(err) => {
                    emit_vault_error(
                        json,
                        &format!("Cannot read file '{}': {err}", path.display()),
                    );
                    return ExitCode::FAILURE;
                }
            }
        } else {
            unreachable!("clap guarantees one update payload source")
        };

        let mut payload = match parse_cipher_update_payload(&raw_json) {
            Ok(payload) => payload,
            Err(err_msg) => {
                emit_vault_error(json, &err_msg);
                return ExitCode::FAILURE;
            }
        };

        if item_type != "login" && cipher_update_payload_has_login_fields(&payload) {
            emit_vault_error(
                json,
                "Username, password, and URI can only be updated on login ciphers.",
            );
            return ExitCode::FAILURE;
        }
        if item_type != "card" && payload.get("card").is_some() {
            emit_vault_error(json, "Card fields can only be updated on card ciphers.");
            return ExitCode::FAILURE;
        }
        if item_type != "identity" && payload.get("identity").is_some() {
            emit_vault_error(
                json,
                "Identity fields can only be updated on identity ciphers.",
            );
            return ExitCode::FAILURE;
        }

        // Target routing is owned by the CLI-resolved cipher, never
        // by keys the caller could smuggle through the payload.
        payload["action"] = json!("cipher_update");
        payload["id"] = json!(item_id.as_str());
        payload
    } else {
        if (username.is_some()
            || password.is_some()
            || password_stdin
            || generate_password
            || generate_passphrase
            || totp_stdin
            || clear_totp
            || !uris.is_empty()
            || !add_uris.is_empty()
            || clear_uris)
            && item_type != "login"
        {
            emit_vault_error(
                json,
                "Username, password, and URI can only be updated on login ciphers.",
            );
            return ExitCode::FAILURE;
        }

        let custom_fields = match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
            Ok(list) => list,
            Err(err_msg) => {
                emit_vault_error(json, &err_msg);
                return ExitCode::FAILURE;
            }
        };

        let password_val = if generate_password {
            let opts = omawarden_engine::generator::PasswordOptions {
                length: 16,
                ..Default::default()
            };
            let pwd = match omawarden_engine::generator::generate_password(&opts) {
                Ok(s) => s.value.clone(),
                Err(e) => {
                    eprintln!("Error generating password: {e}");
                    return ExitCode::FAILURE;
                }
            };
            Some(zeroize::Zeroizing::new(pwd))
        } else if generate_passphrase {
            let opts = omawarden_engine::generator::PassphraseOptions::default();
            let pass = match omawarden_engine::generator::generate_passphrase(&opts) {
                Ok(s) => s.value.clone(),
                Err(e) => {
                    eprintln!("Error generating passphrase: {e}");
                    return ExitCode::FAILURE;
                }
            };
            Some(zeroize::Zeroizing::new(pass))
        } else if password_stdin {
            let mut buf = zeroize::Zeroizing::new(String::new());
            io::stdin().read_to_string(&mut buf).unwrap_or_default();
            let trimmed = buf.trim_end_matches(['\r', '\n']);
            Some(zeroize::Zeroizing::new(trimmed.to_string()))
        } else {
            password.map(zeroize::Zeroizing::new)
        };

        let notes_val = if notes_stdin {
            let mut buf = zeroize::Zeroizing::new(String::new());
            io::stdin().read_to_string(&mut buf).unwrap_or_default();
            let trimmed = buf.trim_end_matches(['\r', '\n']);
            Some(zeroize::Zeroizing::new(trimmed.to_string()))
        } else {
            notes.map(zeroize::Zeroizing::new)
        };

        let totp_val = if clear_totp {
            Some(zeroize::Zeroizing::new(String::new()))
        } else if totp_stdin {
            let mut buf = zeroize::Zeroizing::new(String::new());
            io::stdin().read_to_string(&mut buf).unwrap_or_default();
            let trimmed = buf.trim_end_matches(['\r', '\n']);
            Some(zeroize::Zeroizing::new(trimmed.to_string()))
        } else {
            None
        };

        let mut req = json!({
            "action": "cipher_update",
            "id": item_id.as_str(),
            "name": name,
            "username": username,
            "password": password_val.as_deref(),
            "notes": notes_val.as_deref(),
            "folder_id": folder_id,
            "favorite": favorite,
        });
        if let Some(ref totp) = totp_val {
            req["totp"] = json!(totp.as_str());
        }
        if !uris.is_empty() {
            req["uris"] = json!(uris);
        }
        if !add_uris.is_empty() {
            req["add_uris"] = json!(add_uris);
        }
        if clear_uris {
            req["clear_uris"] = json!(true);
        }
        if !custom_fields.is_empty() {
            req["fields"] = json!(custom_fields);
        }
        if !remove_fields.is_empty() {
            req["remove_fields"] = json!(remove_fields);
        }
        req
    };
    if let Some(ref ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    if is_org {
        let is_partial_only = daemon_req.as_object().is_some_and(|obj| {
            let has_partial_key = obj.get("favorite").is_some_and(|v| !v.is_null())
                || obj.get("folder_id").is_some_and(|v| !v.is_null());
            let only_partial_keys = obj.iter().all(|(k, v)| {
                v.is_null()
                    || matches!(
                        k.as_str(),
                        "action" | "id" | "target" | "client" | "favorite" | "folder_id"
                    )
            });
            has_partial_key && only_partial_keys
        });
        if !is_partial_only {
            if !org_can_edit {
                emit_vault_error(
                    json,
                    "You do not have permission to edit this Organization cipher.",
                );
                return ExitCode::FAILURE;
            }
            if !org_can_view_password {
                emit_vault_error(
                    json,
                    "Cannot edit Organization cipher while passwords are hidden (viewPassword is false).",
                );
                return ExitCode::FAILURE;
            }
        }
        if let Err(err_msg) =
            ensure_daemon_capability(omawarden_engine::daemon::CAPABILITY_ORG_WRITE)
        {
            emit_vault_error(json, &err_msg);
            return ExitCode::FAILURE;
        }
    }

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            } else {
                let id = receipt["item"]["id"].as_str().unwrap_or(item_id.as_str());
                let name = receipt["item"]["name"]
                    .as_str()
                    .unwrap_or(item_name.as_str());
                println!("Updated cipher \"{}\" ({}).", name, id);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to update cipher");
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": err_msg,
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("Error: {}", err_msg);
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cipher_update_payload_strips_reserved_and_null_keys() {
        let payload = parse_cipher_update_payload(
            r#"{
                "action": "cipher_create",
                "id": "attacker-id",
                "target": "other",
                "client": {"kind": "evil"},
                "name": "Renamed",
                "notes": null,
                "password": "secret",
                "folder_id": "",
                "fields": [{"name": "a", "value": "b", "type": 0}],
                "remove_fields": ["old"]
            }"#,
        )
        .unwrap();

        assert!(payload.get("action").is_none());
        assert!(payload.get("id").is_none());
        assert!(payload.get("target").is_none());
        assert!(payload.get("client").is_none());
        assert!(payload.get("notes").is_none());
        assert_eq!(payload["name"], "Renamed");
        assert_eq!(payload["password"], "secret");
        assert_eq!(payload["folder_id"], "");
        assert_eq!(payload["fields"][0]["name"], "a");
        assert_eq!(payload["remove_fields"][0], "old");
    }

    #[test]
    fn test_parse_cipher_update_payload_rejects_empty_and_invalid() {
        let empty = parse_cipher_update_payload("{}").unwrap_err();
        assert!(empty.contains("No fields specified to edit."), "{empty}");

        let null_only =
            parse_cipher_update_payload(r#"{"name": null, "notes": null}"#).unwrap_err();
        assert!(
            null_only.contains("No fields specified to edit."),
            "{null_only}"
        );

        let not_object = parse_cipher_update_payload("[]").unwrap_err();
        assert!(
            not_object.contains("expected a JSON object"),
            "{not_object}"
        );

        let invalid = parse_cipher_update_payload("not json").unwrap_err();
        assert!(invalid.contains("Invalid JSON payload"), "{invalid}");
    }

    #[test]
    fn test_cipher_update_payload_has_login_fields() {
        assert!(cipher_update_payload_has_login_fields(
            &json!({"username": "alice"})
        ));
        assert!(cipher_update_payload_has_login_fields(
            &json!({"clear_uris": false})
        ));
        assert!(cipher_update_payload_has_login_fields(&json!({"uris": []})));
        assert!(!cipher_update_payload_has_login_fields(
            &json!({"name": "Renamed", "notes": "body", "folder_id": ""})
        ));
    }
}
