use clap::Subcommand;
use omawarden_engine::daemon::ensure_daemon_capability;
use omawarden_engine::vault::validate_org_create_scope;
use serde_json::{json, Value};
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use super::super::client::submit_cipher_mutation;
use super::super::io::{build_custom_fields, emit_vault_error, read_json_payload_stdin};

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum CreateItemAction {
    #[command(about = "Create a new Login cipher")]
    Login {
        #[arg(long, help = "Name of the login cipher")]
        name: String,
        #[arg(long, help = "Username")]
        username: String,
        #[arg(
            long,
            conflicts_with_all = ["password_stdin", "generate_password", "generate_passphrase"],
            help = "Password (prefer --password-stdin in automation/pipelines)"
        )]
        password: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["password", "generate_password", "generate_passphrase"],
            help = "Read password from standard input"
        )]
        password_stdin: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_passphrase"],
            help = "Automatically generate a 16-character high-entropy password"
        )]
        generate_password: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_password"],
            help = "Automatically generate a 4-word Diceware passphrase"
        )]
        generate_passphrase: bool,
        #[arg(
            long,
            conflicts_with = "password_stdin",
            help = "Read TOTP seed or otpauth:// URI from standard input (Zero-Argv compliant)"
        )]
        totp_stdin: bool,
        #[arg(long, help = "Optional notes")]
        notes: Option<String>,
        #[arg(
            long = "uri",
            action = clap::ArgAction::Append,
            help = "Optional URI (repeatable for multiple URLs)"
        )]
        uris: Vec<String>,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Text custom field (repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Hidden custom field (repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(long, help = "Optional folder ID")]
        folder_id: Option<String>,
        #[arg(long, help = "Organization ID for creating an Organization cipher")]
        organization_id: Option<String>,
        #[arg(
            long = "collection-id",
            action = clap::ArgAction::Append,
            help = "Collection ID for Organization cipher (repeatable; required when --organization-id is set)"
        )]
        collection_ids: Vec<String>,
    },
    #[command(about = "Create a new Secure Note cipher", alias = "secure-note")]
    Note {
        #[arg(long, help = "Name of the secure note")]
        name: String,
        #[arg(
            long,
            required_unless_present = "notes_stdin",
            help = "Content of the secure note (prefer --notes-stdin for sensitive data)"
        )]
        notes: Option<String>,
        #[arg(
            long,
            conflicts_with = "notes",
            help = "Read note content from standard input"
        )]
        notes_stdin: bool,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Text custom field (repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Hidden custom field (repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(long, help = "Optional folder ID")]
        folder_id: Option<String>,
        #[arg(long, help = "Organization ID for creating an Organization cipher")]
        organization_id: Option<String>,
        #[arg(
            long = "collection-id",
            action = clap::ArgAction::Append,
            help = "Collection ID for Organization cipher (repeatable; required when --organization-id is set)"
        )]
        collection_ids: Vec<String>,
    },
    #[command(about = "Create a new Card cipher")]
    Card {
        #[arg(long, help = "Name of the card cipher")]
        name: String,
        #[arg(long, help = "Cardholder name")]
        cardholder_name: Option<String>,
        #[arg(long, help = "Card brand (e.g. Visa, Mastercard, Amex)")]
        brand: Option<String>,
        #[arg(long, help = "Expiration month (01-12)")]
        exp_month: Option<String>,
        #[arg(long, help = "Expiration year (4-digit, e.g. 2029)")]
        exp_year: Option<String>,
        #[arg(long, help = "Optional notes")]
        notes: Option<String>,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Text custom field (repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Hidden custom field (repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(long, help = "Optional folder ID")]
        folder_id: Option<String>,
        #[arg(long, help = "Organization ID for creating an Organization cipher")]
        organization_id: Option<String>,
        #[arg(
            long = "collection-id",
            action = clap::ArgAction::Append,
            help = "Collection ID for Organization cipher (repeatable; required when --organization-id is set)"
        )]
        collection_ids: Vec<String>,
    },
    #[command(about = "Create a new Identity cipher")]
    Identity {
        #[arg(long, help = "Name of the identity cipher")]
        name: String,
        #[arg(long, help = "Title (e.g. Mr, Mrs, Ms, Mx, Dr)")]
        title: Option<String>,
        #[arg(long, help = "First name")]
        first_name: Option<String>,
        #[arg(long, help = "Middle name")]
        middle_name: Option<String>,
        #[arg(long, help = "Last name")]
        last_name: Option<String>,
        #[arg(long, help = "Username")]
        username: Option<String>,
        #[arg(long, help = "Company")]
        company: Option<String>,
        #[arg(long, help = "Email address")]
        email: Option<String>,
        #[arg(long, help = "Phone number")]
        phone: Option<String>,
        #[arg(long, help = "Address line 1")]
        address1: Option<String>,
        #[arg(long, help = "Address line 2")]
        address2: Option<String>,
        #[arg(long, help = "Address line 3")]
        address3: Option<String>,
        #[arg(long, help = "City / town")]
        city: Option<String>,
        #[arg(long, help = "State / province")]
        state: Option<String>,
        #[arg(long, help = "Zip / postal code")]
        postal_code: Option<String>,
        #[arg(long, help = "Country")]
        country: Option<String>,
        #[arg(long, help = "Optional notes")]
        notes: Option<String>,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Text custom field (repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Hidden custom field (repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(long, help = "Optional folder ID")]
        folder_id: Option<String>,
        #[arg(long, help = "Organization ID for creating an Organization cipher")]
        organization_id: Option<String>,
        #[arg(
            long = "collection-id",
            action = clap::ArgAction::Append,
            help = "Collection ID for Organization cipher (repeatable; required when --organization-id is set)"
        )]
        collection_ids: Vec<String>,
    },
}

pub(crate) fn run(
    item: Option<CreateItemAction>,
    from_json: Option<PathBuf>,
    stdin: bool,
    json: bool,
) -> ExitCode {
    if item.is_some() && (stdin || from_json.is_some()) {
        let err_msg = "Cannot combine a cipher type subcommand with --stdin or --from-json.";
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
    let (mut daemon_req, label, cipher_name) = match item {
        Some(CreateItemAction::Login {
            name,
            username,
            password,
            password_stdin,
            generate_password,
            generate_passphrase,
            totp_stdin,
            notes,
            uris,
            fields,
            hidden_fields,
            bool_fields,
            folder_id,
            organization_id,
            collection_ids,
        }) => {
            let (org_id, collection_ids) =
                match validate_org_create_scope(organization_id.as_deref(), &collection_ids) {
                    Ok(scope) => scope,
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
                zeroize::Zeroizing::new(pwd)
            } else if generate_passphrase {
                let opts = omawarden_engine::generator::PassphraseOptions::default();
                let pass = match omawarden_engine::generator::generate_passphrase(&opts) {
                    Ok(s) => s.value.clone(),
                    Err(e) => {
                        eprintln!("Error generating passphrase: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                zeroize::Zeroizing::new(pass)
            } else if password_stdin {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf).unwrap_or_default();
                zeroize::Zeroizing::new(buf.trim_end_matches(['\r', '\n']).to_string())
            } else if let Some(p) = password {
                zeroize::Zeroizing::new(p)
            } else {
                let is_interactive = (io::stdin().is_terminal()
                    || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                    && !json;
                if !is_interactive {
                    let err_msg = "Password is required. Provide --password, --password-stdin, --generate-password, or run interactively in a terminal.";
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

                let prompt_msg = "Enter password (or press Enter to generate): ";
                let entered = if io::stdin().is_terminal() {
                    rpassword::prompt_password(prompt_msg).unwrap_or_default()
                } else {
                    eprint!("{prompt_msg}");
                    let _ = io::stderr().flush();
                    let mut buf = String::new();
                    let _ = io::stdin().read_line(&mut buf);
                    buf.trim_end_matches(['\r', '\n']).to_string()
                };

                if entered.trim().is_empty() {
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
                    zeroize::Zeroizing::new(pwd)
                } else {
                    zeroize::Zeroizing::new(entered)
                }
            };

            let custom_fields = match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                Ok(list) => list,
                Err(err_msg) => {
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
            };

            let totp_val = if totp_stdin {
                let mut buf = zeroize::Zeroizing::new(String::new());
                io::stdin().read_to_string(&mut buf).unwrap_or_default();
                let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
                Some(zeroize::Zeroizing::new(trimmed))
            } else {
                None
            };

            let mut req = json!({
                "action": "cipher_create",
                "cipher_type": "login",
                "name": name,
                "username": username,
                "password": *password_val,
                "notes": notes,
                "folder_id": folder_id,
            });
            if let Some(ref totp) = totp_val {
                req["totp"] = json!(totp.as_str());
            }
            if !uris.is_empty() {
                req["uris"] = json!(uris);
                req["login"] = json!({ "uris": uris });
            }
            if let Some(ref oid) = org_id {
                req["organization_id"] = json!(oid);
                req["collection_ids"] = json!(collection_ids);
            }
            if !custom_fields.is_empty() {
                req["fields"] = json!(custom_fields);
            }
            (req, "login cipher", name)
        }
        Some(CreateItemAction::Note {
            name,
            notes,
            notes_stdin,
            fields,
            hidden_fields,
            bool_fields,
            folder_id,
            organization_id,
            collection_ids,
        }) => {
            let (org_id, collection_ids) =
                match validate_org_create_scope(organization_id.as_deref(), &collection_ids) {
                    Ok(scope) => scope,
                    Err(err_msg) => {
                        emit_vault_error(json, &err_msg);
                        return ExitCode::FAILURE;
                    }
                };

            let notes_val = if notes_stdin {
                let mut buf = String::new();
                io::stdin().read_to_string(&mut buf).unwrap_or_default();
                zeroize::Zeroizing::new(buf.trim_end_matches(['\r', '\n']).to_string())
            } else {
                zeroize::Zeroizing::new(notes.unwrap_or_default())
            };

            let custom_fields = match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                Ok(list) => list,
                Err(err_msg) => {
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
            };

            let mut req = json!({
                "action": "cipher_create",
                "type": 2,
                "cipher_type": "note",
                "name": name,
                "notes": *notes_val,
                "folder_id": folder_id,
            });
            if !custom_fields.is_empty() {
                req["fields"] = json!(custom_fields);
            }
            if let Some(ref oid) = org_id {
                req["organization_id"] = json!(oid);
                req["collection_ids"] = json!(collection_ids);
            }
            (req, "note cipher", name)
        }
        Some(CreateItemAction::Card {
            name,
            cardholder_name,
            brand,
            exp_month,
            exp_year,
            notes,
            fields,
            hidden_fields,
            bool_fields,
            folder_id,
            organization_id,
            collection_ids,
        }) => {
            let (org_id, collection_ids) =
                match validate_org_create_scope(organization_id.as_deref(), &collection_ids) {
                    Ok(scope) => scope,
                    Err(err_msg) => {
                        emit_vault_error(json, &err_msg);
                        return ExitCode::FAILURE;
                    }
                };

            let custom_fields = match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                Ok(list) => list,
                Err(err_msg) => {
                    emit_vault_error(json, &err_msg);
                    return ExitCode::FAILURE;
                }
            };

            let is_interactive = (io::stdin().is_terminal()
                || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                && !json;

            let read_card_secret = |prompt_msg: &str| -> zeroize::Zeroizing<String> {
                if io::stdin().is_terminal() {
                    zeroize::Zeroizing::new(
                        rpassword::prompt_password(prompt_msg).unwrap_or_default(),
                    )
                } else {
                    eprint!("{prompt_msg}");
                    let _ = io::stderr().flush();
                    let mut buf = zeroize::Zeroizing::new(String::new());
                    let _ = io::stdin().read_line(&mut buf);
                    zeroize::Zeroizing::new(buf.trim_end_matches(['\r', '\n']).to_string())
                }
            };

            let number_val = if is_interactive {
                let v = read_card_secret("Enter card number (optional, Enter to skip): ");
                if v.trim().is_empty() {
                    None
                } else {
                    Some(v)
                }
            } else {
                None
            };
            let code_val = if is_interactive {
                let v = read_card_secret("Enter security code / CVV (optional, Enter to skip): ");
                if v.trim().is_empty() {
                    None
                } else {
                    Some(v)
                }
            } else {
                None
            };

            let mut card_obj = serde_json::Map::new();
            if let Some(v) = cardholder_name {
                card_obj.insert("cardholderName".into(), json!(v));
            }
            if let Some(v) = brand {
                card_obj.insert("brand".into(), json!(v));
            }
            if let Some(ref v) = number_val {
                card_obj.insert("number".into(), json!(v.as_str()));
            }
            if let Some(v) = exp_month {
                card_obj.insert("expMonth".into(), json!(v));
            }
            if let Some(v) = exp_year {
                card_obj.insert("expYear".into(), json!(v));
            }
            if let Some(ref v) = code_val {
                card_obj.insert("code".into(), json!(v.as_str()));
            }

            let mut req = json!({
                "action": "cipher_create",
                "type": 3,
                "cipher_type": "card",
                "name": name,
                "notes": notes,
                "folder_id": folder_id,
                "card": Value::Object(card_obj),
            });
            if !custom_fields.is_empty() {
                req["fields"] = json!(custom_fields);
            }
            if let Some(ref oid) = org_id {
                req["organization_id"] = json!(oid);
                req["collection_ids"] = json!(collection_ids);
            }
            (req, "card cipher", name)
        }
        Some(CreateItemAction::Identity {
            name,
            title,
            first_name,
            middle_name,
            last_name,
            username,
            company,
            email,
            phone,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            notes,
            fields,
            hidden_fields,
            bool_fields,
            folder_id,
            organization_id,
            collection_ids,
        }) => {
            let (org_id, collection_ids) =
                match validate_org_create_scope(organization_id.as_deref(), &collection_ids) {
                    Ok(scope) => scope,
                    Err(err_msg) => {
                        emit_vault_error(json, &err_msg);
                        return ExitCode::FAILURE;
                    }
                };

            let custom_fields = match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                Ok(list) => list,
                Err(err_msg) => {
                    emit_vault_error(json, &err_msg);
                    return ExitCode::FAILURE;
                }
            };

            let is_interactive = (io::stdin().is_terminal()
                || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                && !json;

            let read_id_secret = |prompt_msg: &str| -> zeroize::Zeroizing<String> {
                if io::stdin().is_terminal() {
                    zeroize::Zeroizing::new(
                        rpassword::prompt_password(prompt_msg).unwrap_or_default(),
                    )
                } else {
                    eprint!("{prompt_msg}");
                    let _ = io::stderr().flush();
                    let mut buf = zeroize::Zeroizing::new(String::new());
                    let _ = io::stdin().read_line(&mut buf);
                    zeroize::Zeroizing::new(buf.trim_end_matches(['\r', '\n']).to_string())
                }
            };

            let ssn_val = if is_interactive {
                let v = read_id_secret("Enter SSN (optional, Enter to skip): ");
                (!v.trim().is_empty()).then_some(v)
            } else {
                None
            };
            let passport_val = if is_interactive {
                let v = read_id_secret("Enter passport number (optional, Enter to skip): ");
                (!v.trim().is_empty()).then_some(v)
            } else {
                None
            };
            let license_val = if is_interactive {
                let v = read_id_secret("Enter license number (optional, Enter to skip): ");
                (!v.trim().is_empty()).then_some(v)
            } else {
                None
            };

            let mut id_obj = serde_json::Map::new();
            for (wire_key, val) in [
                ("title", title),
                ("firstName", first_name),
                ("middleName", middle_name),
                ("lastName", last_name),
                ("username", username),
                ("company", company),
                ("email", email),
                ("phone", phone),
                ("address1", address1),
                ("address2", address2),
                ("address3", address3),
                ("city", city),
                ("state", state),
                ("postalCode", postal_code),
                ("country", country),
            ] {
                if let Some(v) = val {
                    id_obj.insert(wire_key.into(), json!(v));
                }
            }
            if let Some(ref v) = ssn_val {
                id_obj.insert("ssn".into(), json!(v.as_str()));
            }
            if let Some(ref v) = passport_val {
                id_obj.insert("passportNumber".into(), json!(v.as_str()));
            }
            if let Some(ref v) = license_val {
                id_obj.insert("licenseNumber".into(), json!(v.as_str()));
            }

            let mut req = json!({
                "action": "cipher_create",
                "type": 4,
                "cipher_type": "identity",
                "name": name,
                "notes": notes,
                "folder_id": folder_id,
                "identity": Value::Object(id_obj),
            });
            if !custom_fields.is_empty() {
                req["fields"] = json!(custom_fields);
            }
            if let Some(ref oid) = org_id {
                req["organization_id"] = json!(oid);
                req["collection_ids"] = json!(collection_ids);
            }
            (req, "identity cipher", name)
        }
        None => {
            let raw_json = if stdin {
                read_json_payload_stdin()
            } else if let Some(path) = from_json {
                match std::fs::read_to_string(&path) {
                    Ok(content) => zeroize::Zeroizing::new(content),
                    Err(err) => {
                        let err_msg = format!("Cannot read file '{}': {err}", path.display());
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
                }
            } else {
                let err_msg = "Specify a cipher type subcommand (e.g. 'login', 'note', 'card', 'identity') or pass --stdin / --from-json.";
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
            };

            let mut val: Value = match serde_json::from_str(&raw_json) {
                Ok(v) => v,
                Err(err) => {
                    let err_msg = format!("Invalid JSON payload: {err}");
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
            };

            let has_org = val
                .get("organizationId")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .is_some()
                || val
                    .get("organization_id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some();
            let has_cols = val
                .get("collectionIds")
                .and_then(|v| v.as_array())
                .filter(|a| !a.is_empty())
                .is_some()
                || val
                    .get("collection_ids")
                    .and_then(|v| v.as_array())
                    .filter(|a| !a.is_empty())
                    .is_some()
                || val
                    .get("collectionIds")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some()
                || val
                    .get("collection_ids")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some()
                || val
                    .get("collectionId")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some()
                || val
                    .get("collection_id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .is_some();
            if has_org && !has_cols {
                emit_vault_error(
                    json,
                    "You must select at least one collection for an Organization cipher.",
                );
                return ExitCode::FAILURE;
            }
            if !has_org && has_cols {
                emit_vault_error(json, "Collection IDs require an Organization ID.");
                return ExitCode::FAILURE;
            }

            val["action"] = json!("cipher_create");
            let is_login = match val.get("type") {
                Some(Value::Number(n)) => n.as_u64() == Some(1),
                Some(Value::String(s)) => s == "1" || s.eq_ignore_ascii_case("login"),
                _ => val
                    .get("cipher_type")
                    .and_then(Value::as_str)
                    .is_none_or(|t| t == "login"),
            };
            if is_login
                && val
                    .get("fields")
                    .and_then(Value::as_array)
                    .is_none_or(|a| a.is_empty())
            {
                if let Some(uris) = val.get("uris") {
                    if val.get("login").is_none() {
                        val["login"] = json!({ "uris": uris });
                    } else if val["login"].get("uris").is_none() {
                        val["login"]["uris"] = uris.clone();
                    }
                }
            }
            let name = val
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed")
                .to_string();
            (val, "cipher", name)
        }
    };

    if let Some(ref ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }
    let is_org_create = daemon_req
        .get("organization_id")
        .or_else(|| daemon_req.get("organizationId"))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    if is_org_create {
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
                let id = receipt["item"]["id"].as_str().unwrap_or("unknown");
                println!("Created {} \"{}\" ({}).", label, cipher_name, id);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to create cipher");
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
