use omawarden_engine::daemon::{
    dispatch_daemon_request, ensure_daemon_capability, DispatchError, CAPABILITY_VAULT_GET,
};
use omawarden_engine::vault::{resolve_vault_get_field, VaultItem};
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::process::ExitCode;

fn emit_vault_get_error(json_mode: bool, error: &str, candidates: Option<&[Value]>) -> ExitCode {
    if json_mode {
        let payload = match candidates {
            Some(cands) => json!({
                "ok": false,
                "error": error,
                "candidates": cands,
            }),
            None => json!({
                "ok": false,
                "error": error,
            }),
        };
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        eprintln!("Error: {error}");
        if let Some(cands) = candidates {
            for cand in cands {
                let id = cand["id"].as_str().unwrap_or("");
                let name = cand["name"].as_str().unwrap_or("");
                let ty = cand["type"].as_str().unwrap_or("");
                let sub = cand["sub_title"].as_str().unwrap_or("");
                if sub.is_empty() {
                    eprintln!("  - {id}  {name} ({ty})");
                } else {
                    eprintln!("  - {id}  {name} ({ty}) — {sub}");
                }
            }
        }
    }
    ExitCode::FAILURE
}

fn render_vault_get_summary_card(item: &VaultItem, redact_sensitive: bool) -> String {
    let mask = |val: &str, sensitive: bool| -> String {
        if sensitive && redact_sensitive {
            "••••••••".to_string()
        } else {
            val.to_string()
        }
    };

    let mut lines = Vec::new();
    lines.push(format!("Name:     {}", item.name));
    lines.push(format!("ID:       {}", item.id));
    lines.push(format!("Type:     {}", item.type_name));
    if let Some(ref folder) = item.folder_name {
        if !folder.is_empty() {
            lines.push(format!("Folder:   {folder}"));
        }
    }
    if item.favorite {
        lines.push("Favorite: true".to_string());
    }

    match item.item_type {
        1 => {
            if let Some(ref login) = item.login {
                if let Some(u) = login
                    .get("username")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    lines.push(format!("Username: {u}"));
                }
                if let Some(p) = login
                    .get("password")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    lines.push(format!("Password: {}", mask(p, true)));
                }
                if let Some(seed) = login
                    .get("totp")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                {
                    if let Some(totp_res) = omawarden_engine::totp::generate_totp(seed, None, 6, 30)
                    {
                        lines.push(format!("TOTP:     {}", mask(&totp_res.code, true)));
                    }
                }
                if let Some(uris) = login.get("uris").and_then(Value::as_array) {
                    for u in uris {
                        if let Some(uri_str) = u
                            .get("uri")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                        {
                            lines.push(format!("URI:      {uri_str}"));
                        }
                    }
                }
            }
        }
        3 => {
            if let Some(ref card) = item.card {
                for (label, key, sensitive) in [
                    ("Holder", "cardholderName", false),
                    ("Brand", "brand", false),
                    ("Number", "number", true),
                    ("ExpMonth", "expMonth", false),
                    ("ExpYear", "expYear", false),
                    ("Code", "code", true),
                ] {
                    if let Some(v) = card
                        .get(key)
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        lines.push(format!("{label:<9} {}", mask(v, sensitive)));
                    }
                }
            }
        }
        4 => {
            if let Some(ref ident) = item.identity {
                for (label, key, sensitive) in [
                    ("Title", "title", false),
                    ("First", "firstName", false),
                    ("Middle", "middleName", false),
                    ("Last", "lastName", false),
                    ("Company", "company", false),
                    ("Email", "email", false),
                    ("Phone", "phone", false),
                    ("Username", "username", false),
                    ("SSN", "ssn", true),
                    ("Passport", "passportNumber", true),
                    ("License", "licenseNumber", true),
                ] {
                    if let Some(v) = ident
                        .get(key)
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        lines.push(format!("{label:<9} {}", mask(v, sensitive)));
                    }
                }
            }
        }
        5 => {
            if let Some(ref ssh) = item.ssh_key {
                if let Some(ref fp) = ssh.fingerprint.as_deref().filter(|s| !s.is_empty()) {
                    lines.push(format!("Fingerpr: {fp}"));
                }
                if let Some(ref pk) = ssh.public_key.as_deref().filter(|s| !s.is_empty()) {
                    lines.push(format!("Public:   {pk}"));
                }
                if let Some(privk) = ssh.private_key.as_deref().filter(|s| !s.is_empty()) {
                    lines.push(format!("Private:  {}", mask(privk, true)));
                }
                if let Some(pp) = ssh.passphrase.as_deref().filter(|s| !s.is_empty()) {
                    lines.push(format!("Passphr:  {}", mask(pp, true)));
                }
            }
        }
        _ => {}
    }

    if let Some(notes) = item.notes.as_deref().filter(|s| !s.is_empty()) {
        let sensitive_notes = item.item_type == 2;
        lines.push(format!("Notes:    {}", mask(notes, sensitive_notes)));
    }

    for field in &item.fields {
        let fname = field.get("name").and_then(Value::as_str).unwrap_or("");
        let fval = field.get("value").and_then(Value::as_str).unwrap_or("");
        let ftype = field.get("type").and_then(Value::as_i64).unwrap_or(0);
        if !fname.is_empty() {
            lines.push(format!("Field[{fname}]: {}", mask(fval, ftype == 1)));
        }
    }

    lines.join("\n")
}

pub(crate) fn handle_vault_get(
    target: &str,
    selector: Option<&str>,
    cipher_type: Option<&str>,
    trash: bool,
    json_mode: bool,
    reveal: bool,
) -> ExitCode {
    const TTY_REVEAL_HINT: &str = "Refusing to print sensitive output to an interactive terminal. Pass --reveal to display in a terminal, pipe stdout, or use 'omawarden copy'.";
    let stdout_is_tty = std::io::stdout().is_terminal();

    if json_mode && stdout_is_tty && !reveal {
        return emit_vault_get_error(true, TTY_REVEAL_HINT, None);
    }

    let ping = match ensure_daemon_capability(CAPABILITY_VAULT_GET) {
        Ok(p) => p,
        Err(err) => return emit_vault_get_error(json_mode, &err, None),
    };

    if ping["unlocked"] != true {
        return emit_vault_get_error(
            json_mode,
            "Vault is locked. Please unlock the vault first.",
            None,
        );
    }

    let mut req = json!({
        "action": "vault_get",
        "target": target,
        "trash": trash,
    });
    if let Some(ty) = cipher_type {
        req["type"] = json!(ty);
    }

    let reply = match dispatch_daemon_request(&req) {
        Ok(r) => r,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            return emit_vault_get_error(
                json_mode,
                "Daemon protocol version is incompatible with this client.",
                None,
            );
        }
        Err(e) => {
            return emit_vault_get_error(json_mode, &format!("Daemon request failed: {e}"), None);
        }
    };

    if reply["ok"] != true {
        let err = reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Failed to retrieve cipher.");
        let candidates = reply.get("candidates").and_then(Value::as_array);
        return emit_vault_get_error(json_mode, err, candidates.map(Vec::as_slice));
    }

    let item: VaultItem = match serde_json::from_value(reply["item"].clone()) {
        Ok(i) => i,
        Err(e) => {
            return emit_vault_get_error(
                json_mode,
                &format!("Failed to parse cipher payload: {e}"),
                None,
            );
        }
    };

    if let Some(sel) = selector {
        let resolved = match resolve_vault_get_field(&item, sel) {
            Ok(r) => r,
            Err(err) => return emit_vault_get_error(json_mode, &err, None),
        };
        if resolved.sensitive && stdout_is_tty && !reveal {
            return emit_vault_get_error(json_mode, TTY_REVEAL_HINT, None);
        }
        if json_mode {
            let mut env = json!({
                "ok": true,
                "id": item.id,
                "name": item.name,
                "type": item.type_name,
                "field": resolved.field_name,
                "sensitive": resolved.sensitive,
                "value": resolved.json_value,
            });
            if let Some((ttl, period)) = resolved.totp_meta {
                env["ttl"] = json!(ttl);
                env["period"] = json!(period);
            }
            println!("{}", serde_json::to_string_pretty(&env).unwrap());
        } else if resolved.text.ends_with('\n') {
            print!("{}", resolved.text);
        } else {
            println!("{}", resolved.text);
        }
        return ExitCode::SUCCESS;
    }

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "item": item,
            }))
            .unwrap()
        );
    } else {
        println!(
            "{}",
            render_vault_get_summary_card(&item, stdout_is_tty && !reveal)
        );
    }
    ExitCode::SUCCESS
}
