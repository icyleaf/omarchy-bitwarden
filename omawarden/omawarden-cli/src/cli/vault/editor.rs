use omawarden_engine::config::Config;
use omawarden_engine::vault::VaultItem;
use serde_json::{json, Value};
use std::io::Write;
use std::process::ExitCode;

use super::super::client::{read_vault_item, submit_cipher_mutation};
use super::super::io::parse_cli_bool;

#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ParsedEditorField {
    name: String,
    value: String,
    field_type: i64,
}

const CARD_EDITOR_FIELDS: &[(&str, &str)] = &[
    ("cardholderName", "Cardholder Name"),
    ("brand", "Brand"),
    ("number", "Number"),
    ("expMonth", "Expiration Month"),
    ("expYear", "Expiration Year"),
    ("code", "Security Code"),
];

const IDENTITY_EDITOR_FIELDS: &[(&str, &str)] = &[
    ("title", "Title"),
    ("firstName", "First Name"),
    ("middleName", "Middle Name"),
    ("lastName", "Last Name"),
    ("username", "Username"),
    ("company", "Company"),
    ("ssn", "SSN"),
    ("passportNumber", "Passport Number"),
    ("licenseNumber", "License Number"),
    ("email", "Email"),
    ("phone", "Phone"),
    ("address1", "Address 1"),
    ("address2", "Address 2"),
    ("address3", "Address 3"),
    ("city", "City"),
    ("state", "State"),
    ("postalCode", "Postal Code"),
    ("country", "Country"),
];

#[derive(Debug, Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ParsedEditorUri {
    uri: String,
    #[zeroize(skip)]
    match_type: Option<u32>,
}

fn uri_match_rule_label(match_type: Option<u32>) -> Option<&'static str> {
    match match_type {
        None => None,
        Some(0) => Some("domain"),
        Some(1) => Some("host"),
        Some(2) => Some("starts_with"),
        Some(3) => Some("exact"),
        Some(4) => Some("regex"),
        Some(5) => Some("never"),
        _ => None,
    }
}

fn parse_editor_uri_line(val: &str, line_number: usize) -> Result<ParsedEditorUri, String> {
    let trimmed = val.trim();
    if let Some(without_close) = trimmed.strip_suffix(']') {
        if let Some(open_idx) = without_close.rfind(" [") {
            let uri_part = without_close[..open_idx].trim();
            let rule_part = without_close[open_idx + 2..].trim().to_ascii_lowercase();
            let match_type = match rule_part.as_str() {
                "default" => None,
                "domain" => Some(0),
                "host" => Some(1),
                "starts_with" => Some(2),
                "exact" => Some(3),
                "regex" => Some(4),
                "never" => Some(5),
                other => {
                    return Err(format!(
                        "Invalid URI match rule '[{other}]' on line {line_number}: expected default, domain, host, starts_with, exact, regex, or never."
                    ));
                }
            };
            return Ok(ParsedEditorUri {
                uri: uri_part.to_string(),
                match_type,
            });
        }
    }
    Ok(ParsedEditorUri {
        uri: trimmed.to_string(),
        match_type: None,
    })
}

#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ParsedEditorCipher {
    name: String,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Vec<ParsedEditorUri>,
    card: Vec<(String, String)>,
    identity: Vec<(String, String)>,
    fields: Vec<ParsedEditorField>,
    folder_id: Option<String>,
    favorite: bool,
    notes: String,
}

fn format_editor_template(
    item_id: &str,
    item_name: &str,
    item_type: &str,
    item_details: Option<&VaultItem>,
) -> zeroize::Zeroizing<String> {
    use std::fmt::Write as _;
    let mut out = zeroize::Zeroizing::new(String::new());
    let _ = writeln!(out, "# Editing {item_type} cipher: {item_name} ({item_id})");
    out.push_str("# Lines starting with '#' before the notes section are ignored.\n");
    out.push_str(
        "# Save and exit the editor to apply changes, or exit without changes to abort.\n",
    );
    if item_type == "ssh_key" {
        out.push_str(
            "# SSH key material is immutable here; only metadata, custom fields, and notes are editable.\n",
        );
    }
    out.push('\n');

    let _ = writeln!(out, "Name: {item_name}");
    if item_type == "login" {
        let username = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let password = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("password"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let totp = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("totp"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let _ = writeln!(out, "Username: {username}");
        let _ = writeln!(out, "Password: {password}");
        let _ = writeln!(out, "TOTP: {totp}");
        let uris = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for uri in &uris {
            let value = uri.get("uri").and_then(Value::as_str).unwrap_or("");
            let match_type = uri
                .get("match")
                .and_then(Value::as_u64)
                .and_then(|m| u32::try_from(m).ok());
            if let Some(rule) = uri_match_rule_label(match_type) {
                let _ = writeln!(out, "URI: {value} [{rule}]");
            } else {
                let _ = writeln!(out, "URI: {value}");
            }
        }
    } else if item_type == "card" {
        let card = item_details.and_then(|i| i.card.as_ref());
        for (wire_key, label) in CARD_EDITOR_FIELDS {
            let val = card
                .and_then(|c| c.get(*wire_key))
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = writeln!(out, "{label}: {val}");
        }
    } else if item_type == "identity" {
        let identity = item_details.and_then(|i| i.identity.as_ref());
        for (wire_key, label) in IDENTITY_EDITOR_FIELDS {
            let val = identity
                .and_then(|id| id.get(*wire_key))
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = writeln!(out, "{label}: {val}");
        }
    }
    let folder_id = item_details
        .and_then(|i| i.folder_id.as_deref())
        .unwrap_or("");
    let favorite = item_details.map(|i| i.favorite).unwrap_or(false);
    let _ = writeln!(out, "Folder: {folder_id}");
    let _ = writeln!(out, "Favorite: {favorite}");

    out.push_str("\n# Custom Fields:\n");
    if let Some(details) = item_details {
        for field in &details.fields {
            let name = field.get("name").and_then(Value::as_str).unwrap_or("");
            let value = field.get("value").and_then(Value::as_str).unwrap_or("");
            match field.get("type").and_then(Value::as_i64).unwrap_or(0) {
                0 => {
                    let _ = writeln!(out, "Field: {name} = {value}");
                }
                1 => {
                    let _ = writeln!(out, "Hidden Field: {name} = {value}");
                }
                2 => {
                    let _ = writeln!(out, "Bool Field: {name} = {value}");
                }
                // Linked custom fields are read-only here and preserved untouched.
                _ => {}
            }
        }
    }

    out.push_str("\n# Notes (everything below this line is treated as notes):\n");
    if let Some(notes) = item_details.and_then(|i| i.notes.as_deref()) {
        out.push_str(notes);
    }
    out
}

fn parse_editor_field(
    value: &str,
    field_type: i64,
    line_number: usize,
    key: &str,
) -> Result<ParsedEditorField, String> {
    let Some((name, field_value)) = value.split_once('=') else {
        return Err(format!(
            "Invalid custom field on line {line_number}: expected '{key}: NAME = VALUE'."
        ));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(format!(
            "Invalid custom field on line {line_number}: name cannot be empty."
        ));
    }
    let mut field_value = field_value.trim().to_string();
    if field_type == 2 {
        match parse_cli_bool(&field_value) {
            Ok(parsed) => field_value = parsed.to_string(),
            Err(_) => {
                return Err(format!(
                    "Invalid boolean value '{field_value}' for custom field '{name}' on line {line_number}: expected true or false."
                ));
            }
        }
    }
    Ok(ParsedEditorField {
        name: name.to_string(),
        value: field_value,
        field_type,
    })
}

fn parse_editor_template(content: &str, item_type: &str) -> Result<ParsedEditorCipher, String> {
    let mut in_notes = false;
    let mut notes_lines = Vec::new();

    let mut name = String::new();
    let mut username = String::new();
    let mut password = String::new();
    let mut totp = String::new();
    let mut uris: Vec<ParsedEditorUri> = Vec::new();
    let mut card_values: Vec<(String, String)> = if item_type == "card" {
        CARD_EDITOR_FIELDS
            .iter()
            .map(|(wire_key, _)| ((*wire_key).to_string(), String::new()))
            .collect()
    } else {
        Vec::new()
    };
    let mut identity_values: Vec<(String, String)> = if item_type == "identity" {
        IDENTITY_EDITOR_FIELDS
            .iter()
            .map(|(wire_key, _)| ((*wire_key).to_string(), String::new()))
            .collect()
    } else {
        Vec::new()
    };
    let mut fields: Vec<ParsedEditorField> = Vec::new();
    let mut folder_id = String::new();
    let mut favorite = false;

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if in_notes {
            notes_lines.push(line);
            continue;
        }

        let trimmed = line.trim();
        if trimmed.starts_with("# Notes") {
            in_notes = true;
            continue;
        }

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let val = val.trim();
            match key.as_str() {
                "name" => name = val.to_string(),
                "username" if item_type == "login" => username = val.to_string(),
                "password" => password = val.to_string(),
                "totp" if item_type == "login" => {
                    if !val.is_empty() {
                        omawarden_engine::totp::validate_totp_seed(val)
                            .map_err(|e| format!("Invalid TOTP on line {line_number}: {e}"))?;
                    }
                    totp = val.to_string();
                }
                "uri" => {
                    if !val.is_empty() {
                        let parsed_uri = parse_editor_uri_line(val, line_number)?;
                        if !parsed_uri.uri.is_empty() {
                            uris.push(parsed_uri);
                        }
                    }
                }
                "field" => fields.push(parse_editor_field(val, 0, line_number, "Field")?),
                "hidden field" => {
                    fields.push(parse_editor_field(val, 1, line_number, "Hidden Field")?)
                }
                "bool field" => fields.push(parse_editor_field(val, 2, line_number, "Bool Field")?),
                "folder" | "folder_id" | "folder id" => folder_id = val.to_string(),
                "favorite" => {
                    favorite =
                        parse_cli_bool(val).map_err(|e| format!("Invalid favorite value: {e}"))?;
                }
                other => {
                    if item_type == "card" {
                        if let Some((wire_key, _)) = CARD_EDITOR_FIELDS.iter().find(|(wk, lbl)| {
                            lbl.eq_ignore_ascii_case(other) || wk.eq_ignore_ascii_case(other)
                        }) {
                            if let Some((_, slot)) =
                                card_values.iter_mut().find(|(k, _)| k == wire_key)
                            {
                                *slot = val.to_string();
                            }
                        }
                    } else if item_type == "identity" {
                        if let Some((wire_key, _)) =
                            IDENTITY_EDITOR_FIELDS.iter().find(|(wk, lbl)| {
                                lbl.eq_ignore_ascii_case(other) || wk.eq_ignore_ascii_case(other)
                            })
                        {
                            if let Some((_, slot)) =
                                identity_values.iter_mut().find(|(k, _)| k == wire_key)
                            {
                                *slot = val.to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    let has_login = item_type == "login";
    let notes = notes_lines.join("\n");
    let folder_opt = if folder_id.is_empty() {
        None
    } else {
        Some(folder_id)
    };

    Ok(ParsedEditorCipher {
        name,
        username: if has_login { Some(username) } else { None },
        password: if has_login { Some(password) } else { None },
        totp: if has_login { Some(totp) } else { None },
        uris: if has_login { uris } else { Vec::new() },
        card: card_values,
        identity: identity_values,
        fields,
        folder_id: folder_opt,
        favorite,
        notes,
    })
}

fn spawn_editor(path: &std::path::Path) -> Result<std::process::ExitStatus, std::io::Error> {
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| {
            if which::which("nano").is_ok() {
                "nano".to_string()
            } else {
                "vi".to_string()
            }
        });

    let parts: Vec<&str> = editor.split_whitespace().collect();
    if parts.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Editor not set",
        ));
    }

    let mut cmd = std::process::Command::new(parts[0]);
    for arg in &parts[1..] {
        cmd.arg(arg);
    }
    cmd.arg(path);
    cmd.status()
}

fn securely_wipe_and_remove(mut temp: tempfile::NamedTempFile) {
    use std::io::Seek;
    let path = temp.path().to_path_buf();

    // 1. Wipe the open file handle starting from offset 0
    if let Ok(meta) = temp.as_file().metadata() {
        let len = (meta.len() as usize).max(4096);
        let zeroes = vec![0u8; len];
        if temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).is_ok() {
            let _ = temp.as_file_mut().write_all(&zeroes);
            let _ = temp.as_file_mut().flush();
            let _ = temp.as_file().sync_all();
        }
    }

    // 2. Also re-open path directly in case editor performed atomic save (new inode)
    if path.exists() {
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
            if let Ok(meta) = file.metadata() {
                let len = (meta.len() as usize).max(4096);
                let zeroes = vec![0u8; len];
                let _ = file.write_all(&zeroes);
                let _ = file.flush();
                let _ = file.sync_all();
            }
        }
    }

    // 3. Close handle and delete from disk
    let _ = temp.close();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
}

pub(crate) fn handle_editor_edit(
    cfg: &Config,
    resolved: &Value,
    client_ctx: Option<&omawarden_engine::api::ClientContext>,
) -> ExitCode {
    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
    let item_name = resolved["name"].as_str().unwrap_or("").to_string();
    let item_type = resolved["type"].as_str().unwrap_or("login");

    let full_item = read_vault_item(cfg, &item_id, false).ok().flatten();

    let initial_template =
        format_editor_template(&item_id, &item_name, item_type, full_item.as_ref());

    let mut builder = tempfile::Builder::new();
    builder.prefix("omawarden-edit-").suffix(".txt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }

    let mut temp_file = match builder.tempfile() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: Failed to create temporary file for editor: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = temp_file.write_all(initial_template.as_bytes()) {
        securely_wipe_and_remove(temp_file);
        eprintln!("Error: Failed to write to temporary file: {e}");
        return ExitCode::FAILURE;
    }
    let _ = temp_file.flush();

    let status = match spawn_editor(temp_file.path()) {
        Ok(s) => s,
        Err(e) => {
            securely_wipe_and_remove(temp_file);
            eprintln!("Error: Failed to launch editor: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !status.success() {
        securely_wipe_and_remove(temp_file);
        eprintln!("Editor exited with non-zero status.");
        return ExitCode::FAILURE;
    }

    let edited_content = match std::fs::read_to_string(temp_file.path()) {
        Ok(c) => zeroize::Zeroizing::new(c),
        Err(e) => {
            securely_wipe_and_remove(temp_file);
            eprintln!("Error: Failed to read edited temporary file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let parsed = match parse_editor_template(&edited_content, item_type) {
        Ok(p) => p,
        Err(e) => {
            // A formatting mistake must never discard the user's draft: keep
            // the 0600 temp file and point the user at it instead of wiping.
            let draft_path = temp_file.path().to_path_buf();
            let _ = temp_file.keep();
            eprintln!("Error: {e}");
            eprintln!(
                "Your edits were kept at {} so no changes are lost; fix the format and re-run.",
                draft_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if parsed.name.trim().is_empty() {
        let draft_path = temp_file.path().to_path_buf();
        let _ = temp_file.keep();
        eprintln!("Error: Cipher name cannot be empty.");
        eprintln!(
            "Your edits were kept at {} so no changes are lost; fix the name and re-run.",
            draft_path.display()
        );
        return ExitCode::FAILURE;
    }

    let orig_name = &item_name;
    let orig_notes = full_item
        .as_ref()
        .and_then(|i| i.notes.as_deref())
        .unwrap_or("");
    let orig_favorite = full_item.as_ref().map(|i| i.favorite).unwrap_or(false);
    let orig_folder_id = full_item.as_ref().and_then(|i| i.folder_id.as_deref());

    let (orig_user, orig_pass, orig_totp) = if item_type == "login" {
        let u = full_item
            .as_ref()
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let p = full_item
            .as_ref()
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("password"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let t = zeroize::Zeroizing::new(
            full_item
                .as_ref()
                .and_then(|i| i.login.as_ref())
                .and_then(|l| l.get("totp"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        );
        (u, p, t)
    } else {
        (
            String::new(),
            String::new(),
            zeroize::Zeroizing::new(String::new()),
        )
    };

    let orig_uris: Vec<ParsedEditorUri> = if item_type == "login" {
        full_item
            .as_ref()
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .map(|uris| {
                uris.iter()
                    .filter_map(|u| {
                        let uri = u.get("uri").and_then(Value::as_str)?.to_string();
                        let match_type = u
                            .get("match")
                            .and_then(Value::as_u64)
                            .and_then(|m| u32::try_from(m).ok());
                        Some(ParsedEditorUri { uri, match_type })
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Only Text/Hidden/Boolean fields are editable here; Linked fields stay
    // read-only and are therefore excluded from both template and diff.
    let orig_fields: Vec<(String, String, i64)> = full_item
        .as_ref()
        .map(|item| {
            item.fields
                .iter()
                .filter_map(|field| {
                    let field_type = field.get("type").and_then(Value::as_i64).unwrap_or(0);
                    if field_type == 3 {
                        return None;
                    }
                    Some((
                        field.get("name").and_then(Value::as_str)?.to_string(),
                        field
                            .get("value")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        field_type,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let name_changed = parsed.name != *orig_name;
    let username_changed =
        item_type == "login" && parsed.username.as_deref() != Some(orig_user.as_str());
    let password_changed =
        item_type == "login" && parsed.password.as_deref() != Some(orig_pass.as_str());
    let totp_changed = item_type == "login" && parsed.totp.as_deref() != Some(orig_totp.as_str());
    let uris_changed = item_type == "login" && parsed.uris != orig_uris;
    let folder_changed = parsed.folder_id.as_deref() != orig_folder_id;
    let favorite_changed = parsed.favorite != orig_favorite;
    let notes_changed =
        parsed.notes.trim_end_matches(['\r', '\n']) != orig_notes.trim_end_matches(['\r', '\n']);

    // Fields absent from the edited buffer are removed; fields whose value or
    // type changed (or that are new) are upserted. Untouched and read-only
    // fields are left alone.
    let mut upsert_fields: Vec<Value> = Vec::new();
    for field in &parsed.fields {
        let unchanged = orig_fields.iter().any(|(name, value, field_type)| {
            *name == field.name && *value == field.value && *field_type == field.field_type
        });
        if !unchanged {
            upsert_fields.push(json!({
                "name": field.name,
                "value": field.value,
                "type": field.field_type,
            }));
        }
    }
    let remove_field_names: Vec<String> = orig_fields
        .iter()
        .filter(|(name, _, _)| !parsed.fields.iter().any(|f| f.name == *name))
        .map(|(name, _, _)| name.clone())
        .collect();
    let fields_changed = !upsert_fields.is_empty() || !remove_field_names.is_empty();

    let mut card_diff = serde_json::Map::new();
    if item_type == "card" {
        let orig_card = full_item.as_ref().and_then(|i| i.card.as_ref());
        for (wire_key, new_val) in &parsed.card {
            let orig_val = orig_card
                .and_then(|c| c.get(wire_key.as_str()))
                .and_then(Value::as_str)
                .unwrap_or("");
            if new_val != orig_val {
                card_diff.insert(wire_key.clone(), json!(new_val));
            }
        }
    }
    let card_changed = !card_diff.is_empty();

    let mut identity_diff = serde_json::Map::new();
    if item_type == "identity" {
        let orig_identity = full_item.as_ref().and_then(|i| i.identity.as_ref());
        for (wire_key, new_val) in &parsed.identity {
            let orig_val = orig_identity
                .and_then(|id| id.get(wire_key.as_str()))
                .and_then(Value::as_str)
                .unwrap_or("");
            if new_val != orig_val {
                identity_diff.insert(wire_key.clone(), json!(new_val));
            }
        }
    }
    let identity_changed = !identity_diff.is_empty();

    if !name_changed
        && !username_changed
        && !password_changed
        && !totp_changed
        && !uris_changed
        && !card_changed
        && !identity_changed
        && !folder_changed
        && !favorite_changed
        && !notes_changed
        && !fields_changed
    {
        securely_wipe_and_remove(temp_file);
        println!("No changes made.");
        return ExitCode::SUCCESS;
    }

    let mut daemon_req = json!({
        "action": "cipher_update",
        "id": item_id,
    });
    if name_changed {
        daemon_req["name"] = json!(parsed.name);
    }
    if username_changed {
        daemon_req["username"] = json!(parsed.username);
    }
    if password_changed {
        daemon_req["password"] = json!(parsed.password);
    }
    if totp_changed {
        daemon_req["totp"] = json!(parsed.totp.as_deref().unwrap_or(""));
    }
    if uris_changed {
        if parsed.uris.is_empty() && !orig_uris.is_empty() {
            daemon_req["clear_uris"] = json!(true);
        } else {
            let uri_objs: Vec<Value> = parsed
                .uris
                .iter()
                .map(|u| json!({ "uri": u.uri, "match": u.match_type }))
                .collect();
            daemon_req["uris"] = json!(uri_objs);
        }
    }
    if card_changed {
        daemon_req["card"] = Value::Object(card_diff);
    }
    if identity_changed {
        daemon_req["identity"] = Value::Object(identity_diff);
    }
    if !upsert_fields.is_empty() {
        daemon_req["fields"] = json!(upsert_fields);
    }
    if !remove_field_names.is_empty() {
        daemon_req["remove_fields"] = json!(remove_field_names);
    }
    if folder_changed {
        daemon_req["folder_id"] = json!(parsed.folder_id.as_deref().unwrap_or(""));
    }
    if favorite_changed {
        daemon_req["favorite"] = json!(parsed.favorite);
    }
    if notes_changed {
        daemon_req["notes"] = json!(parsed.notes.trim_end_matches(['\r', '\n']));
    }
    if let Some(ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    securely_wipe_and_remove(temp_file);

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
            let name = receipt["item"]["name"].as_str().unwrap_or(&parsed.name);
            println!("Updated cipher \"{}\" ({}).", name, id);
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to update cipher");
            eprintln!("Error: {}", err_msg);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_editor_template_login() {
        let details = VaultItem {
            id: "uuid-1".into(),
            type_name: "login".into(),
            name: "GitHub".into(),
            notes: Some("Special note".into()),
            favorite: true,
            folder_id: Some("folder-1".into()),
            login: Some(json!({
                "username": "octocat",
                "password": "supersecret",
                "uris": [{"uri": "https://github.com"}]
            })),
            ..Default::default()
        };
        let tpl = format_editor_template("uuid-1", "GitHub", "login", Some(&details));
        assert!(tpl.contains("Name: GitHub"));
        assert!(tpl.contains("Username: octocat"));
        assert!(tpl.contains("Password: supersecret"));
        assert!(tpl.contains("URI: https://github.com"));
        assert!(tpl.contains("Folder: folder-1"));
        assert!(tpl.contains("Favorite: true"));
        assert!(tpl.contains("Special note"));
    }

    #[test]
    fn test_parse_editor_template_valid() {
        let content = "\
# Comment
Name: Updated Name
Username: updated_user
Password: new_password
URI: https://example.com/updated
Folder: folder-2
Favorite: true

# Notes (everything below this line is treated as notes):
Note line 1
Note line 2 with: colons and # symbols
";
        let parsed = parse_editor_template(content, "login").unwrap();
        assert_eq!(parsed.name, "Updated Name");
        assert_eq!(parsed.username.as_deref(), Some("updated_user"));
        assert_eq!(parsed.password.as_deref(), Some("new_password"));
        assert_eq!(
            parsed.uris,
            vec![ParsedEditorUri {
                uri: "https://example.com/updated".to_string(),
                match_type: None,
            }]
        );
        assert_eq!(parsed.folder_id.as_deref(), Some("folder-2"));
        assert!(parsed.favorite);
        assert_eq!(
            parsed.notes,
            "Note line 1\nNote line 2 with: colons and # symbols"
        );
    }

    #[test]
    fn test_format_editor_template_multi_uri_and_fields() {
        let details = VaultItem {
            id: "uuid-1".into(),
            type_name: "login".into(),
            name: "GitHub".into(),
            notes: None,
            favorite: false,
            login: Some(json!({
                "username": "octocat",
                "password": "supersecret",
                "uris": [
                    {"uri": "https://github.com"},
                    {"uri": "https://api.github.com"}
                ]
            })),
            fields: vec![
                json!({"name": "PIN", "value": "1234", "type": 0}),
                json!({"name": "Recovery Code", "value": "sec-98765", "type": 1}),
                json!({"name": "Requires VPN", "value": "true", "type": 2}),
                json!({"name": "Linked", "value": "cipher-uuid", "type": 3}),
            ],
            ..Default::default()
        };
        let tpl = format_editor_template("uuid-1", "GitHub", "login", Some(&details));
        assert!(tpl.contains("URI: https://github.com\n"));
        assert!(tpl.contains("URI: https://api.github.com\n"));
        assert!(tpl.contains("# Custom Fields:\n"));
        assert!(tpl.contains("Field: PIN = 1234\n"));
        assert!(tpl.contains("Hidden Field: Recovery Code = sec-98765\n"));
        assert!(tpl.contains("Bool Field: Requires VPN = true\n"));
        // Linked fields are read-only and never rendered.
        assert!(!tpl.contains("Linked"));
    }

    #[test]
    fn test_parse_editor_template_multi_uri_and_fields() {
        let content = "\
Name: Updated
Username: user
Password: pass
URI: https://one.example
URI: https://two.example

# Custom Fields:
Field: PIN = 1234
Hidden Field: Recovery Code = sec-98765
Bool Field: Requires VPN = true
Bool Field: Retired = false

# Notes (everything below this line is treated as notes):
body
";
        let parsed = parse_editor_template(content, "login").unwrap();
        assert_eq!(
            parsed.uris,
            vec![
                ParsedEditorUri {
                    uri: "https://one.example".to_string(),
                    match_type: None,
                },
                ParsedEditorUri {
                    uri: "https://two.example".to_string(),
                    match_type: None,
                },
            ]
        );
        assert_eq!(parsed.fields.len(), 4);
        assert_eq!(parsed.fields[0].name, "PIN");
        assert_eq!(parsed.fields[0].value, "1234");
        assert_eq!(parsed.fields[0].field_type, 0);
        assert_eq!(parsed.fields[1].name, "Recovery Code");
        assert_eq!(parsed.fields[1].field_type, 1);
        assert_eq!(parsed.fields[2].name, "Requires VPN");
        assert_eq!(parsed.fields[2].value, "true");
        assert_eq!(parsed.fields[2].field_type, 2);
        assert_eq!(parsed.fields[3].name, "Retired");
        assert_eq!(parsed.fields[3].value, "false");
        assert_eq!(parsed.notes, "body");
    }

    #[test]
    fn test_parse_editor_template_rejects_malformed_custom_field_with_line() {
        let content = "\
Name: Updated
# Custom Fields:
Field: NoSeparator
# Notes:
";
        let err = parse_editor_template(content, "login").unwrap_err();
        assert!(
            err.contains("line 3") && err.contains("Field: NAME = VALUE"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_parse_editor_template_rejects_invalid_bool_field_with_line() {
        let content = "\
Name: Updated
# Custom Fields:
Bool Field: Active = maybe
# Notes:
";
        let err = parse_editor_template(content, "login").unwrap_err();
        assert!(
            err.contains("line 3")
                && err.contains("Invalid boolean value 'maybe'")
                && err.contains("'Active'"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_parse_editor_template_rejects_invalid_favorite() {
        let content = "Name: Foo\nFavorite: not_a_bool\n# Notes:\n";
        let res = parse_editor_template(content, "login");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid favorite value"));
    }

    #[test]
    fn test_securely_wipe_and_remove() {
        let mut builder = tempfile::Builder::new();
        builder.prefix("test-wipe-").suffix(".txt");
        let mut temp = builder.tempfile().unwrap();
        let path = temp.path().to_path_buf();
        temp.write_all(b"SUPER_SECRET_PLAINTEXT_PASSWORD_12345")
            .unwrap();
        temp.flush().unwrap();

        securely_wipe_and_remove(temp);

        assert!(!path.exists());
    }

    #[test]
    fn test_editor_template_ssh_key_metadata_only() {
        let ssh_item = VaultItem {
            id: "ssh-1".into(),
            name: "Prod Deploy".into(),
            item_type: 5,
            type_name: "ssh_key".into(),
            sub_title: "ed25519".into(),
            notes: Some("Used for CI deploy".into()),
            favorite: true,
            created_at: None,
            updated_at: None,
            deleted_at: None,
            folder_id: Some("folder-1".into()),
            folder_name: Some("Infra".into()),
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            edit: true,
            view_password: true,
            can_delete: true,
            can_restore: true,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![json!({"name": "Env", "value": "prod", "type": 0})],
            attachments: vec![],
            search_text: String::new(),
        };

        let tpl = format_editor_template("ssh-1", "Prod Deploy", "ssh_key", Some(&ssh_item));
        assert!(tpl.contains("SSH key material is immutable"));
        assert!(tpl.contains("Name: Prod Deploy"));
        assert!(tpl.contains("Field: Env = prod"));
        assert!(tpl.contains("Used for CI deploy"));

        let parsed = parse_editor_template(&tpl, "ssh_key").unwrap();
        assert_eq!(parsed.name, "Prod Deploy");
        assert!(parsed.username.is_none());
        assert!(parsed.password.is_none());
        assert!(parsed.uris.is_empty());
        assert_eq!(parsed.folder_id.as_deref(), Some("folder-1"));
        assert!(parsed.favorite);
        assert_eq!(parsed.fields.len(), 1);
        assert_eq!(parsed.fields[0].name, "Env");
        assert_eq!(parsed.fields[0].value, "prod");
        assert_eq!(parsed.notes, "Used for CI deploy");
    }

    #[test]
    fn test_editor_template_roundtrip_card() {
        let card_item = VaultItem {
            id: "card-1".into(),
            name: "Corp Visa".into(),
            item_type: 3,
            type_name: "card".into(),
            sub_title: "Visa".into(),
            notes: Some("Card notes".into()),
            favorite: true,
            created_at: None,
            updated_at: None,
            deleted_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            edit: true,
            view_password: true,
            can_delete: true,
            can_restore: true,
            login: None,
            card: Some(json!({
                "cardholderName": "Jane Doe",
                "brand": "Visa",
                "number": "4111111111111111",
                "expMonth": "08",
                "expYear": "2029",
                "code": "123"
            })),
            identity: None,
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: String::new(),
        };
        let tpl = format_editor_template("card-1", "Corp Visa", "card", Some(&card_item));
        assert!(tpl.contains("Cardholder Name: Jane Doe"));
        assert!(tpl.contains("Brand: Visa"));
        assert!(tpl.contains("Number: 4111111111111111"));
        assert!(tpl.contains("Expiration Month: 08"));
        assert!(tpl.contains("Expiration Year: 2029"));
        assert!(tpl.contains("Security Code: 123"));

        let parsed = parse_editor_template(&tpl, "card").unwrap();
        assert_eq!(parsed.name, "Corp Visa");
        assert!(parsed.card.iter().any(|(k, v)| k == "brand" && v == "Visa"));
        assert!(parsed.card.iter().any(|(k, v)| k == "code" && v == "123"));
        assert_eq!(parsed.notes, "Card notes");
    }

    #[test]
    fn test_editor_template_roundtrip_identity() {
        let id_item = VaultItem {
            id: "id-1".into(),
            name: "Work ID".into(),
            item_type: 4,
            type_name: "identity".into(),
            sub_title: "Ada".into(),
            notes: Some("Identity notes".into()),
            favorite: false,
            created_at: None,
            updated_at: None,
            deleted_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            edit: true,
            view_password: true,
            can_delete: true,
            can_restore: true,
            login: None,
            card: None,
            identity: Some(json!({
                "title": "Dr",
                "firstName": "Ada",
                "username": "ada_lovelace",
                "ssn": "123-45-6789",
                "address3": "Suite B",
                "country": "UK"
            })),
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: String::new(),
        };
        let tpl = format_editor_template("id-1", "Work ID", "identity", Some(&id_item));
        assert!(tpl.contains("Title: Dr"));
        assert!(tpl.contains("Username: ada_lovelace"));
        assert!(tpl.contains("Address 3: Suite B"));

        let parsed = parse_editor_template(&tpl, "identity").unwrap();
        assert_eq!(parsed.name, "Work ID");
        assert!(parsed.username.is_none());
        assert!(parsed
            .identity
            .iter()
            .any(|(k, v)| k == "username" && v == "ada_lovelace"));
        assert!(parsed
            .identity
            .iter()
            .any(|(k, v)| k == "address3" && v == "Suite B"));
        assert_eq!(parsed.notes, "Identity notes");
    }
}
