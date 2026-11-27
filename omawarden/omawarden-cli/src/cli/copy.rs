use omawarden_engine::clipboard::ClipboardGuard;
use omawarden_engine::config::Config;
use omawarden_engine::vault::{resolve_copy_field, CopyFieldSelector, VaultOutputItem};
use serde_json::json;
use std::process::ExitCode;

use super::client::vault_output_item;
use super::io::read_clipboard_stdin;

pub(crate) struct CopyArgs {
    pub(crate) query: Option<String>,
    pub(crate) clear: bool,
    pub(crate) stdin: bool,
    pub(crate) sensitive: bool,
    pub(crate) password: bool,
    pub(crate) username: bool,
    pub(crate) totp: bool,
    pub(crate) notes: bool,
    pub(crate) private_key: bool,
    pub(crate) public_key: bool,
    pub(crate) field: Option<String>,
    pub(crate) timeout: Option<i64>,
    pub(crate) expected_lock_generation: Option<u64>,
}

pub(crate) fn run(args: CopyArgs, cfg: &Config) -> ExitCode {
    let CopyArgs {
        query,
        clear,
        stdin,
        sensitive,
        password,
        username,
        totp,
        notes,
        private_key,
        public_key,
        field,
        timeout,
        expected_lock_generation,
    } = args;

    let guard = ClipboardGuard::default();
    if !guard.is_available() {
        let err_msg = guard
            .unavailable_reason()
            .unwrap_or_else(|| "Clipboard utility not found.".to_string());
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": err_msg
            }))
            .unwrap()
        );
        return ExitCode::FAILURE;
    }

    if clear {
        let ok = guard.clear();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "ok": ok })).unwrap()
        );
        return if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    if stdin {
        let text_val = read_clipboard_stdin();
        let timeout_val = timeout.unwrap_or(cfg.clipboard_clear_seconds);
        let ok = match expected_lock_generation {
            Some(generation) => {
                guard.copy_in_session(&text_val, sensitive, timeout_val, generation)
            }
            None => guard.copy(&text_val, sensitive, timeout_val),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": ok,
                "copied": "stdin",
                "timeout": if sensitive { timeout_val } else { 0 }
            }))
            .unwrap()
        );
        return if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    let query = match query {
        Some(q) if !q.trim().is_empty() => q,
        _ => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "error": "Missing item query or action flag (--clear / --stdin). See 'omawarden copy --help'."
                }))
                .unwrap()
            );
            return ExitCode::FAILURE;
        }
    };

    // --field cannot be combined with other field selection flags
    let field_flags = [username, totp, notes, public_key, private_key, password];
    if field.is_some() && field_flags.iter().any(|&f| f) {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "--field cannot be combined with --username, --totp, --notes, --public-key, --private-key, or --password"
            }))
            .unwrap()
        );
        return ExitCode::FAILURE;
    }

    let (item, scope) = match vault_output_item(cfg, &query, true) {
        Ok(Some(VaultOutputItem {
            item,
            scope: Some(scope),
        })) => (item, scope),
        result => {
            let error = match result {
                Ok(Some(_)) => "Could not verify the clipboard source session.".into(),
                Ok(None) => format!("Item '{}' not found in vault", query),
                Err(error) => error,
            };
            println!("{}", json!({ "ok": false, "error": error }));
            return ExitCode::FAILURE;
        }
    };

    let selector = if username {
        CopyFieldSelector::Username
    } else if totp {
        CopyFieldSelector::Totp
    } else if notes {
        CopyFieldSelector::Notes
    } else if public_key {
        CopyFieldSelector::PublicKey
    } else if private_key {
        CopyFieldSelector::PrivateKey
    } else if let Some(ref field_name_query) = field {
        CopyFieldSelector::CustomField(field_name_query)
    } else if password {
        CopyFieldSelector::Password
    } else {
        CopyFieldSelector::Default
    };

    let resolved_copy = match resolve_copy_field(&item, selector) {
        Ok(r) => r,
        Err(error_msg) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": false,
                    "error": error_msg
                }))
                .unwrap()
            );
            return ExitCode::FAILURE;
        }
    };
    let (field_name, text_to_copy, is_sensitive) = (
        resolved_copy.field_name,
        resolved_copy.value,
        resolved_copy.sensitive,
    );

    let timeout_val = timeout.unwrap_or(cfg.clipboard_clear_seconds);
    let ok = guard.copy_vault_output(&text_to_copy, is_sensitive, timeout_val, &scope);
    if ok {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "name": item.name,
                "copied": field_name,
                "timeout": if is_sensitive { timeout_val } else { 0 }
            }))
            .unwrap()
        );
        ExitCode::SUCCESS
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "error": "Failed to copy content to clipboard"
            }))
            .unwrap()
        );
        ExitCode::FAILURE
    }
}
