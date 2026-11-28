use omawarden_engine::daemon::{
    dispatch_daemon_request, ensure_daemon_capability, DispatchError,
    CAPABILITY_VAULT_EXPORT_IMPORT,
};
use omawarden_engine::vault_import::{inspect_import_file, VaultImportFormat};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use super::super::io::emit_vault_error;

fn send_vault_import(
    abs_path: &Path,
    format: VaultImportFormat,
    folder: Option<&str>,
    dry_run: bool,
    json_mode: bool,
) -> Result<Value, ExitCode> {
    let mut req = json!({
        "action": "vault_import",
        "file_path": abs_path.to_string_lossy(),
        "format": format.as_str(),
        "dry_run": dry_run,
    });
    if let Some(f) = folder {
        req["folder"] = json!(f);
    }

    let reply = match dispatch_daemon_request(&req) {
        Ok(r) => r,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            emit_vault_error(
                json_mode,
                "Daemon protocol version is incompatible with this client.",
            );
            return Err(ExitCode::FAILURE);
        }
        Err(e) => {
            emit_vault_error(json_mode, &format!("Daemon request failed: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };

    if reply["ok"] != true {
        let err = reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Failed to import vault.");
        emit_vault_error(json_mode, err);
        return Err(ExitCode::FAILURE);
    }

    Ok(reply)
}

fn emit_human_warnings(warnings_val: &Value) {
    if let Some(arr) = warnings_val.as_array() {
        for w in arr {
            if let Some(msg) = w.as_str() {
                eprintln!("Warning: {msg}");
            }
        }
    }
}

pub(crate) fn handle_vault_import(
    file: &Path,
    format_raw: &str,
    folder: Option<&str>,
    dry_run: bool,
    yes: bool,
    json_mode: bool,
) -> ExitCode {
    let format = match VaultImportFormat::parse(format_raw) {
        Ok(f) => f,
        Err(err) => {
            emit_vault_error(json_mode, &err);
            return ExitCode::FAILURE;
        }
    };

    if let Some(f) = folder {
        if f.trim().is_empty() {
            emit_vault_error(
                json_mode,
                "Invalid --folder target: folder name or ID cannot be empty.",
            );
            return ExitCode::FAILURE;
        }
    }

    let stdin_is_tty = io::stdin().is_terminal() || std::env::var_os("OMA_FORCE_PROMPT").is_some();
    if !dry_run && !yes && (!stdin_is_tty || json_mode) {
        emit_vault_error(
            json_mode,
            "Refusing to import into your Vault without confirmation. Pass --yes to confirm or --dry-run to preview.",
        );
        return ExitCode::FAILURE;
    }

    let abs_path = match fs::canonicalize(file) {
        Ok(p) => p,
        Err(e) => {
            emit_vault_error(
                json_mode,
                &format!("Failed to locate import file '{}': {e}", file.display()),
            );
            return ExitCode::FAILURE;
        }
    };

    // Lightweight local pre-flight check (50 MiB cap, format detection, explicit --format mismatch)
    if let Err(err) = inspect_import_file(&abs_path, format) {
        emit_vault_error(json_mode, &err);
        return ExitCode::FAILURE;
    }

    let ping = match ensure_daemon_capability(CAPABILITY_VAULT_EXPORT_IMPORT) {
        Ok(p) => p,
        Err(err) => {
            emit_vault_error(json_mode, &err);
            return ExitCode::FAILURE;
        }
    };

    if ping["unlocked"] != true {
        emit_vault_error(json_mode, "Vault is locked. Please unlock the vault first.");
        return ExitCode::FAILURE;
    }

    // For interactive non-dry-run imports without --yes, run dry-run preview first
    // to display exact item and folder counts before confirming.
    if !dry_run && !yes {
        let preview = match send_vault_import(&abs_path, format, folder, true, false) {
            Ok(r) => r,
            Err(code) => return code,
        };
        let cipher_count = preview
            .get("cipher_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let folders_reused = preview
            .get("folders_reused")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let folders_created = preview
            .get("folders_created")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let detected = preview
            .get("detected_format")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if let Some(warnings) = preview.get("warnings") {
            emit_human_warnings(warnings);
        }

        eprint!(
            "Import {cipher_count} item(s) ({folders_reused} folder(s) reused, {folders_created} new folder(s), format: {detected}) into your Vault?\nContinue? [y/N] "
        );
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            emit_vault_error(false, "Import aborted.");
            return ExitCode::FAILURE;
        }
        let trimmed = input.trim();
        if !trimmed.eq_ignore_ascii_case("y") && !trimmed.eq_ignore_ascii_case("yes") {
            emit_vault_error(false, "Import aborted.");
            return ExitCode::FAILURE;
        }
    }

    let reply = match send_vault_import(&abs_path, format, folder, dry_run, json_mode) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let detected_format = reply
        .get("detected_format")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let cipher_count = reply
        .get("cipher_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let folders_reused = reply
        .get("folders_reused")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let folders_created = reply
        .get("folders_created")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let skipped_unsupported = reply
        .get("skipped_unsupported")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let warnings = reply.get("warnings").cloned().unwrap_or_else(|| json!([]));

    if json_mode {
        let envelope = json!({
            "ok": true,
            "dry_run": dry_run,
            "detected_format": detected_format,
            "cipher_count": cipher_count,
            "folders_reused": folders_reused,
            "folders_created": folders_created,
            "skipped_unsupported": skipped_unsupported,
            "warnings": warnings,
        });
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
    } else if dry_run {
        println!(
            "Dry-run (detected format: {detected_format}): would import {cipher_count} item(s) ({folders_reused} folder(s) reused, {folders_created} new folder(s))."
        );
        emit_human_warnings(&warnings);
    } else {
        println!(
            "Imported {cipher_count} item(s) ({folders_reused} folder(s) reused, {folders_created} new folder(s)) and synced Vault."
        );
        emit_human_warnings(&warnings);
    }

    ExitCode::SUCCESS
}
