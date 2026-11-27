use omawarden_engine::config::Config;
use omawarden_engine::daemon::ResolvedCipherTarget;
use omawarden_engine::storage::VaultStorage;
use omawarden_engine::vault::{
    resolve_totp_for_query, resolve_totp_from_daemon, TotpOutput, VaultManager, VaultOutputItem,
};
use serde_json::Value;
use std::io::{self, Write};
use std::process::ExitCode;

use super::io::{emit_vault_error, read_auth_payload, read_secret_stdin};

pub(crate) fn submit_cipher_mutation(request: &Value) -> Result<Value, Value> {
    omawarden_engine::daemon::submit_cipher_mutation(request, || {
        Some(zeroize::Zeroizing::new(read_auth_payload().0))
    })
}

/// Unlock before dispatch when a caller provides the master password on stdin.
/// Once dispatched, a missing reply cannot justify another create.
pub(crate) fn submit_ssh_cipher(request: &Value) -> Result<Value, Value> {
    omawarden_engine::daemon::submit_ssh_cipher(request, || {
        Some(zeroize::Zeroizing::new(read_auth_payload().0))
    })
}

pub(crate) fn submit_attachment_upload(
    item_id: &str,
    file_path: &str,
    file_name: Option<&str>,
    expected_lock_generation: Option<u64>,
) -> Result<Value, Value> {
    omawarden_engine::daemon::submit_attachment_upload(
        item_id,
        file_path,
        file_name,
        expected_lock_generation,
        None,
        || Some(zeroize::Zeroizing::new(read_auth_payload().0)),
    )
}

pub(crate) fn vault_output_item(
    cfg: &Config,
    query: &str,
    touch: bool,
) -> Result<Option<VaultOutputItem>, String> {
    omawarden_engine::vault::vault_output_item(cfg, query, touch, || {
        Some(zeroize::Zeroizing::new(read_auth_payload().0))
    })
}

fn prompt_candidate_selection(candidates: &[Value], target: &str) -> Option<Value> {
    eprintln!("Multiple ciphers matched '{}':", target);
    for (idx, item) in candidates.iter().enumerate() {
        let num = idx + 1;
        let name = item["name"].as_str().unwrap_or("unnamed");
        let item_type = item["type"].as_str().unwrap_or("unknown");
        let id = item["id"].as_str().unwrap_or("");
        let sub = item
            .get("sub_title")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        if let Some(sub) = sub {
            eprintln!("  {num}) {name} ({item_type} - {sub}) [{id}]");
        } else {
            eprintln!("  {num}) {name} ({item_type}) [{id}]");
        }
    }
    eprint!(
        "Select cipher [1-{}] (or 'q' to cancel): ",
        candidates.len()
    );
    let _ = io::stderr().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return None;
    }
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("q") {
        return None;
    }
    if let Ok(choice) = trimmed.parse::<usize>() {
        if (1..=candidates.len()).contains(&choice) {
            return Some(candidates[choice - 1].clone());
        }
    }
    eprintln!("Invalid selection.");
    None
}

pub(crate) fn resolve_target_cipher(
    target: &str,
    purpose: &str,
    client_ctx: Option<&omawarden_engine::api::ClientContext>,
    is_interactive: bool,
    json: bool,
    trash: bool,
) -> Result<Value, ExitCode> {
    match omawarden_engine::daemon::resolve_target_cipher(
        target,
        purpose,
        client_ctx,
        trash,
        || Some(zeroize::Zeroizing::new(read_auth_payload().0)),
    ) {
        Ok(ResolvedCipherTarget::Resolved(item)) => Ok(item),
        Ok(ResolvedCipherTarget::Ambiguous { error, candidates }) => {
            if is_interactive {
                if !candidates.is_empty() {
                    if let Some(selected) = prompt_candidate_selection(&candidates, target) {
                        return Ok(selected);
                    }
                }
                eprintln!("Selection cancelled.");
                Err(ExitCode::FAILURE)
            } else {
                emit_vault_error(json, &error);
                Err(ExitCode::FAILURE)
            }
        }
        Err(err_msg) => {
            emit_vault_error(json, &err_msg);
            Err(ExitCode::FAILURE)
        }
    }
}

pub(crate) fn totp_output(
    cfg: &Config,
    query: Option<&str>,
    copy: bool,
) -> Result<Option<TotpOutput>, String> {
    if let Some(query) = query {
        return resolve_totp_for_query(cfg, query, copy, || {
            Some(zeroize::Zeroizing::new(read_auth_payload().0))
        });
    }

    let text = read_secret_stdin();
    let input = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    if let Some(secret) = input["secret"].as_str() {
        return Ok(TotpOutput::standalone(secret));
    }
    let Some(query) = input["query"].as_str().or_else(|| input["id"].as_str()) else {
        return Ok(TotpOutput::standalone(&text));
    };
    resolve_totp_from_daemon(query, copy)
}

pub(crate) fn ensure_unlocked_user_key(
    vault_mgr: &VaultManager,
    st: &VaultStorage,
) -> Result<omawarden_engine::crypto::SymmetricCryptoKey, String> {
    omawarden_engine::vault::ensure_unlocked_user_key(vault_mgr, st, || {
        Some(zeroize::Zeroizing::new(read_auth_payload().0))
    })
}
