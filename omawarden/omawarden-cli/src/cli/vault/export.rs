use omawarden_engine::daemon::{
    dispatch_daemon_request, ensure_daemon_capability, DispatchError,
    CAPABILITY_VAULT_EXPORT_IMPORT,
};
use omawarden_engine::fs_util::atomic_write_file;
use omawarden_engine::vault_export::VaultExportFormat;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

use super::super::io::emit_vault_error;

fn resolve_output_path(output: Option<&Path>, format: VaultExportFormat) -> PathBuf {
    match output {
        None => PathBuf::from(format.default_filename()),
        Some(p) => {
            let raw = p.to_string_lossy();
            let ends_with_sep = raw.ends_with('/') || raw.ends_with(std::path::MAIN_SEPARATOR);
            if p.is_dir() || ends_with_sep {
                p.join(format.default_filename())
            } else {
                p.to_path_buf()
            }
        }
    }
}

fn ensure_overwrite_allowed(path: &Path, force: bool, json_mode: bool) -> Result<(), ExitCode> {
    if fs::symlink_metadata(path).is_ok() && !force {
        emit_vault_error(
            json_mode,
            &format!(
                "Refusing to overwrite existing file '{}'. Pass --force to overwrite.",
                path.display()
            ),
        );
        return Err(ExitCode::FAILURE);
    }
    Ok(())
}

pub(crate) fn handle_vault_export(
    format_raw: &str,
    output: Option<&Path>,
    allow_plaintext: bool,
    force: bool,
    json_mode: bool,
) -> ExitCode {
    let format = match VaultExportFormat::parse(format_raw) {
        Ok(f) => f,
        Err(err) => {
            emit_vault_error(json_mode, &err);
            return ExitCode::FAILURE;
        }
    };

    let to_stdout = output == Some(Path::new("-"));

    if to_stdout && json_mode {
        emit_vault_error(true, "Cannot combine --output - (stdout) with --json.");
        return ExitCode::FAILURE;
    }

    let stdout_is_tty = io::stdout().is_terminal();
    if to_stdout && format.is_plaintext() && stdout_is_tty && !force {
        emit_vault_error(
            false,
            "Refusing to write plaintext export to an interactive terminal. Redirect stdout, specify --output <path>, or pass --force.",
        );
        return ExitCode::FAILURE;
    }

    let dest_path = if to_stdout {
        None
    } else {
        let resolved = resolve_output_path(output, format);
        if let Err(code) = ensure_overwrite_allowed(&resolved, force, json_mode) {
            return code;
        }
        Some(resolved)
    };

    if format.is_plaintext() && !allow_plaintext {
        let stdin_is_tty =
            io::stdin().is_terminal() || std::env::var_os("OMA_FORCE_PROMPT").is_some();
        if !stdin_is_tty || json_mode {
            emit_vault_error(
                json_mode,
                "Refusing to export unencrypted plaintext Vault without confirmation. Pass --allow-plaintext to confirm.",
            );
            return ExitCode::FAILURE;
        }

        eprint!(
            "Warning: Exporting your Vault in unencrypted plaintext JSON will expose all secrets without encryption.\nContinue? [y/N] "
        );
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            emit_vault_error(false, "Export aborted.");
            return ExitCode::FAILURE;
        }
        let trimmed = input.trim();
        if !trimmed.eq_ignore_ascii_case("y") && !trimmed.eq_ignore_ascii_case("yes") {
            emit_vault_error(false, "Export aborted.");
            return ExitCode::FAILURE;
        }
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

    let req = json!({
        "action": "vault_export",
        "format": format.as_str(),
    });

    let reply = match dispatch_daemon_request(&req) {
        Ok(r) => r,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            emit_vault_error(
                json_mode,
                "Daemon protocol version is incompatible with this client.",
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            emit_vault_error(json_mode, &format!("Daemon request failed: {e}"));
            return ExitCode::FAILURE;
        }
    };

    if reply["ok"] != true {
        let err = reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Failed to export vault.");
        emit_vault_error(json_mode, err);
        return ExitCode::FAILURE;
    }

    let content = Zeroizing::new(
        reply
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    );
    let item_count = reply.get("item_count").and_then(Value::as_u64).unwrap_or(0);
    let folder_count = reply
        .get("folder_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let skipped = reply.get("skipped").cloned().unwrap_or_else(|| json!({}));
    let warnings = reply.get("warnings").cloned().unwrap_or_else(|| json!([]));

    if to_stdout {
        let mut stdout = io::stdout().lock();
        if let Err(e) = stdout
            .write_all(content.as_bytes())
            .and_then(|_| stdout.write_all(b"\n"))
            .and_then(|_| stdout.flush())
        {
            emit_vault_error(false, &format!("Failed to write export to stdout: {e}"));
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let target = dest_path.expect("non-stdout export must have resolved destination path");
    if let Err(code) = ensure_overwrite_allowed(&target, force, json_mode) {
        return code;
    }

    if let Err(e) = atomic_write_file(&target, content.as_bytes(), 0o600) {
        emit_vault_error(
            json_mode,
            &format!("Failed to write export file '{}': {e}", target.display()),
        );
        return ExitCode::FAILURE;
    }

    if json_mode {
        let envelope = json!({
            "ok": true,
            "format": format.as_str(),
            "output": target.display().to_string(),
            "item_count": item_count,
            "folder_count": folder_count,
            "skipped": skipped,
            "warnings": warnings,
        });
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
    } else {
        println!(
            "Exported {item_count} item(s) and {folder_count} folder(s) to {}.",
            target.display()
        );
    }

    ExitCode::SUCCESS
}
