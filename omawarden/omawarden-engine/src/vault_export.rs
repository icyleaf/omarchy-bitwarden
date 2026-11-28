use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::api::decrypt_cipher_string;
use crate::crypto::{parse_symmetric_key_from_decrypted_bytes, EncString, SymmetricCryptoKey};
use crate::storage::VaultStorage;

/// Supported Vault export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultExportFormat {
    Json,
}

impl VaultExportFormat {
    /// Parses a CLI or Daemon Protocol export format identifier.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            other => Err(format!(
                "Unsupported export format '{other}'. Supported format: json."
            )),
        }
    }

    /// Canonical wire/CLI identifier for this export format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
        }
    }

    /// Returns `true` when this format writes unencrypted secrets.
    pub fn is_plaintext(self) -> bool {
        matches!(self, Self::Json)
    }

    /// Generates the official Bitwarden-style timestamped default filename.
    pub fn default_filename(self) -> String {
        let ts = chrono::Local::now().format("%Y%m%d%H%M%S");
        match self {
            Self::Json => format!("bitwarden_export_{ts}.json"),
        }
    }
}

/// Result of exporting a personal Vault inside the Omawarden Engine.
#[derive(Debug)]
pub struct VaultExportResult {
    pub format: VaultExportFormat,
    pub content: Zeroizing<String>,
    pub item_count: usize,
    pub folder_count: usize,
    pub skipped: Map<String, Value>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct PlaintextExportDocument {
    encrypted: bool,
    folders: Vec<ExportFolder>,
    items: Vec<ExportCipher>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportFolder {
    id: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportPasswordHistoryEntry {
    last_used_date: Option<String>,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    field_type: i64,
    linked_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportLoginUri {
    #[serde(rename = "match")]
    uri_match: Option<i64>,
    uri: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportFido2Credential {
    credential_id: Option<String>,
    key_type: Option<String>,
    key_algorithm: Option<String>,
    key_curve: Option<String>,
    key_value: Option<String>,
    rp_id: Option<String>,
    user_handle: Option<String>,
    user_name: Option<String>,
    counter: Option<String>,
    rp_name: Option<String>,
    user_display_name: Option<String>,
    discoverable: Option<String>,
    creation_date: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportLogin {
    #[serde(skip_serializing_if = "Option::is_none")]
    fido2_credentials: Option<Vec<ExportFido2Credential>>,
    uris: Vec<ExportLoginUri>,
    username: Option<String>,
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_revision_date: Option<String>,
    totp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_authentication_enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportSecureNote {
    #[serde(rename = "type")]
    note_type: i64,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportIdentity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportSshKey {
    private_key: Option<String>,
    public_key: Option<String>,
    key_fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ExportCipher {
    password_history: Option<Vec<ExportPasswordHistoryEntry>>,
    revision_date: Option<String>,
    creation_date: Option<String>,
    deleted_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archived_date: Option<String>,
    id: String,
    organization_id: Option<String>,
    folder_id: Option<String>,
    #[serde(rename = "type")]
    cipher_type: i64,
    reprompt: i64,
    name: String,
    notes: Option<String>,
    favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<Vec<ExportField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<ExportLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_note: Option<ExportSecureNote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<ExportCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<ExportIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_key: Option<ExportSshKey>,
    collection_ids: Option<Vec<String>>,
}

/// Exports the unlocked personal Vault in the requested format.
pub fn export_personal_vault(
    storage: &VaultStorage,
    user_key: &SymmetricCryptoKey,
    format: VaultExportFormat,
) -> Result<VaultExportResult, String> {
    match format {
        VaultExportFormat::Json => export_personal_vault_plaintext_json(storage, user_key),
    }
}

fn non_empty_str(val: Option<&Value>) -> Option<String> {
    val.and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn decrypt_opt_field(obj: &Value, key: &str, cipher_key: &SymmetricCryptoKey) -> Option<String> {
    decrypt_cipher_string(obj.get(key).and_then(Value::as_str), cipher_key)
}

fn resolve_personal_cipher_key(
    cipher: &Value,
    cipher_id: &str,
    user_key: &SymmetricCryptoKey,
) -> Result<SymmetricCryptoKey, String> {
    if let Some(enc_key_str) = cipher
        .get("key")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let parsed = EncString::parse(enc_key_str)
            .map_err(|e| format!("Failed to parse per-item key for cipher '{cipher_id}': {e:?}"))?;
        let raw_bytes = parsed.decrypt(user_key).map_err(|e| {
            format!("Failed to decrypt per-item key for cipher '{cipher_id}': {e:?}")
        })?;
        let key = parse_symmetric_key_from_decrypted_bytes(&raw_bytes).ok_or_else(|| {
            format!("Invalid symmetric key length for per-item key on cipher '{cipher_id}'")
        })?;
        Ok(key)
    } else {
        Ok(user_key.clone())
    }
}

/// Serializes the personal Vault into official Bitwarden 2-space pretty-printed Plaintext JSON.
///
/// Strictly excludes Trash ciphers, Organization ciphers, Attachments, and per-cipher `key`.
pub fn export_personal_vault_plaintext_json(
    storage: &VaultStorage,
    user_key: &SymmetricCryptoKey,
) -> Result<VaultExportResult, String> {
    let mut folders = Vec::new();
    for f in &storage.folders {
        let Some(id) = non_empty_str(f.get("id")) else {
            continue;
        };
        let name = decrypt_cipher_string(f.get("name").and_then(Value::as_str), user_key)
            .unwrap_or_default();
        folders.push(ExportFolder { id, name });
    }

    let mut items = Vec::new();
    for c in &storage.ciphers {
        // Strictly exclude Trash ciphers
        let deleted = c
            .get("deletedDate")
            .or_else(|| c.get("DeletedDate"))
            .or_else(|| c.get("deleted_at"))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if deleted {
            continue;
        }

        // Strictly exclude Organization ciphers
        let is_org = c
            .get("organizationId")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if is_org {
            continue;
        }

        let id = c
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let cipher_type = c.get("type").and_then(Value::as_i64).unwrap_or(1);
        let cipher_key = resolve_personal_cipher_key(c, &id, user_key)?;

        let name = decrypt_cipher_string(c.get("name").and_then(Value::as_str), &cipher_key)
            .unwrap_or_default();
        let notes = decrypt_cipher_string(c.get("notes").and_then(Value::as_str), &cipher_key);
        let favorite = c.get("favorite").and_then(Value::as_bool).unwrap_or(false);
        let reprompt = c.get("reprompt").and_then(Value::as_i64).unwrap_or(0);
        let folder_id = non_empty_str(c.get("folderId"));
        let creation_date = non_empty_str(
            c.get("creationDate")
                .or_else(|| c.get("creation_date"))
                .or_else(|| c.get("created_at")),
        );
        let revision_date = non_empty_str(
            c.get("revisionDate")
                .or_else(|| c.get("revision_date"))
                .or_else(|| c.get("updated_at")),
        );
        let archived_date = non_empty_str(c.get("archivedDate").or_else(|| c.get("archived_date")));

        // Custom Fields (all 4 types: Text=0, Hidden=1, Boolean=2, Linked=3)
        let mut fields_vec = Vec::new();
        if let Some(fields_arr) = c.get("fields").and_then(Value::as_array) {
            for f in fields_arr {
                let fname = decrypt_opt_field(f, "name", &cipher_key);
                let fval = decrypt_opt_field(f, "value", &cipher_key);
                let ftype = f.get("type").and_then(Value::as_i64).unwrap_or(0);
                let linked_id = f.get("linkedId").and_then(Value::as_i64);
                fields_vec.push(ExportField {
                    name: fname,
                    value: fval,
                    field_type: ftype,
                    linked_id,
                });
            }
        }
        let fields = if fields_vec.is_empty() {
            None
        } else {
            Some(fields_vec)
        };

        // Password History
        let login_obj = c.get("login").or_else(|| c.get("Login"));
        let raw_hist = c
            .get("passwordHistory")
            .or_else(|| c.get("password_history"))
            .or_else(|| c.get("PasswordHistory"))
            .or_else(|| {
                login_obj.and_then(|l| {
                    l.get("passwordHistory")
                        .or_else(|| l.get("password_history"))
                        .or_else(|| l.get("PasswordHistory"))
                })
            })
            .and_then(Value::as_array);

        let mut hist_vec = Vec::new();
        if let Some(arr) = raw_hist {
            for h in arr {
                if let Some(password) =
                    decrypt_cipher_string(h.get("password").and_then(Value::as_str), &cipher_key)
                {
                    let last_used_date = non_empty_str(
                        h.get("lastUsedDate")
                            .or_else(|| h.get("last_used_date"))
                            .or_else(|| h.get("LastUsedDate")),
                    );
                    hist_vec.push(ExportPasswordHistoryEntry {
                        last_used_date,
                        password,
                    });
                }
            }
        }
        let password_history = if hist_vec.is_empty() {
            None
        } else {
            Some(hist_vec)
        };

        // Type-specific sub-objects
        let mut login = None;
        let mut secure_note = None;
        let mut card = None;
        let mut identity = None;
        let mut ssh_key = None;

        match cipher_type {
            1 => {
                if let Some(l) = login_obj.filter(|v| !v.is_null()) {
                    let mut uris = Vec::new();
                    if let Some(uris_arr) = l.get("uris").and_then(Value::as_array) {
                        for u in uris_arr {
                            let uri = decrypt_opt_field(u, "uri", &cipher_key);
                            let uri_match = u.get("match").and_then(Value::as_i64);
                            uris.push(ExportLoginUri { uri_match, uri });
                        }
                    }

                    let mut fido2_vec = Vec::new();
                    if let Some(fido2_arr) = l
                        .get("fido2Credentials")
                        .or_else(|| l.get("fido2_credentials"))
                        .and_then(Value::as_array)
                    {
                        for f in fido2_arr {
                            fido2_vec.push(ExportFido2Credential {
                                credential_id: decrypt_opt_field(f, "credentialId", &cipher_key),
                                key_type: decrypt_opt_field(f, "keyType", &cipher_key),
                                key_algorithm: decrypt_opt_field(f, "keyAlgorithm", &cipher_key),
                                key_curve: decrypt_opt_field(f, "keyCurve", &cipher_key),
                                key_value: decrypt_opt_field(f, "keyValue", &cipher_key),
                                rp_id: decrypt_opt_field(f, "rpId", &cipher_key),
                                user_handle: decrypt_opt_field(f, "userHandle", &cipher_key),
                                user_name: decrypt_opt_field(f, "userName", &cipher_key),
                                counter: decrypt_opt_field(f, "counter", &cipher_key),
                                rp_name: decrypt_opt_field(f, "rpName", &cipher_key),
                                user_display_name: decrypt_opt_field(
                                    f,
                                    "userDisplayName",
                                    &cipher_key,
                                ),
                                discoverable: decrypt_opt_field(f, "discoverable", &cipher_key),
                                creation_date: non_empty_str(
                                    f.get("creationDate").or_else(|| f.get("creation_date")),
                                ),
                            });
                        }
                    }

                    login = Some(ExportLogin {
                        fido2_credentials: if fido2_vec.is_empty() {
                            None
                        } else {
                            Some(fido2_vec)
                        },
                        uris,
                        username: decrypt_opt_field(l, "username", &cipher_key),
                        password: decrypt_opt_field(l, "password", &cipher_key),
                        password_revision_date: non_empty_str(l.get("passwordRevisionDate")),
                        totp: decrypt_opt_field(l, "totp", &cipher_key),
                        http_authentication_enabled: l
                            .get("httpAuthenticationEnabled")
                            .and_then(Value::as_bool),
                    });
                }
            }
            2 => {
                let note_type = c
                    .get("secureNote")
                    .or_else(|| c.get("SecureNote"))
                    .and_then(|sn| sn.get("type"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                secure_note = Some(ExportSecureNote { note_type });
            }
            3 => {
                if let Some(card_obj) = c
                    .get("card")
                    .or_else(|| c.get("Card"))
                    .filter(|v| !v.is_null())
                {
                    card = Some(ExportCard {
                        cardholder_name: decrypt_opt_field(card_obj, "cardholderName", &cipher_key),
                        brand: decrypt_opt_field(card_obj, "brand", &cipher_key),
                        number: decrypt_opt_field(card_obj, "number", &cipher_key),
                        exp_month: decrypt_opt_field(card_obj, "expMonth", &cipher_key),
                        exp_year: decrypt_opt_field(card_obj, "expYear", &cipher_key),
                        code: decrypt_opt_field(card_obj, "code", &cipher_key),
                    });
                }
            }
            4 => {
                if let Some(id_obj) = c
                    .get("identity")
                    .or_else(|| c.get("Identity"))
                    .filter(|v| !v.is_null())
                {
                    identity = Some(ExportIdentity {
                        title: decrypt_opt_field(id_obj, "title", &cipher_key),
                        first_name: decrypt_opt_field(id_obj, "firstName", &cipher_key),
                        middle_name: decrypt_opt_field(id_obj, "middleName", &cipher_key),
                        last_name: decrypt_opt_field(id_obj, "lastName", &cipher_key),
                        address1: decrypt_opt_field(id_obj, "address1", &cipher_key),
                        address2: decrypt_opt_field(id_obj, "address2", &cipher_key),
                        address3: decrypt_opt_field(id_obj, "address3", &cipher_key),
                        city: decrypt_opt_field(id_obj, "city", &cipher_key),
                        state: decrypt_opt_field(id_obj, "state", &cipher_key),
                        postal_code: decrypt_opt_field(id_obj, "postalCode", &cipher_key),
                        country: decrypt_opt_field(id_obj, "country", &cipher_key),
                        company: decrypt_opt_field(id_obj, "company", &cipher_key),
                        email: decrypt_opt_field(id_obj, "email", &cipher_key),
                        phone: decrypt_opt_field(id_obj, "phone", &cipher_key),
                        ssn: decrypt_opt_field(id_obj, "ssn", &cipher_key),
                        username: decrypt_opt_field(id_obj, "username", &cipher_key),
                        passport_number: decrypt_opt_field(id_obj, "passportNumber", &cipher_key),
                        license_number: decrypt_opt_field(id_obj, "licenseNumber", &cipher_key),
                    });
                }
            }
            5 => {
                if let Some(ssh_obj) = c
                    .get("sshKey")
                    .or_else(|| c.get("SshKey"))
                    .filter(|v| !v.is_null())
                {
                    let key_fingerprint = decrypt_opt_field(ssh_obj, "keyFingerprint", &cipher_key)
                        .or_else(|| decrypt_opt_field(ssh_obj, "fingerprint", &cipher_key));
                    ssh_key = Some(ExportSshKey {
                        private_key: decrypt_opt_field(ssh_obj, "privateKey", &cipher_key),
                        public_key: decrypt_opt_field(ssh_obj, "publicKey", &cipher_key),
                        key_fingerprint,
                    });
                }
            }
            _ => {}
        }

        items.push(ExportCipher {
            password_history,
            revision_date,
            creation_date,
            deleted_date: None,
            archived_date,
            id,
            organization_id: None,
            folder_id,
            cipher_type,
            reprompt,
            name,
            notes,
            favorite,
            fields,
            login,
            secure_note,
            card,
            identity,
            ssh_key,
            collection_ids: None,
        });
    }

    let folder_count = folders.len();
    let item_count = items.len();
    let doc = PlaintextExportDocument {
        encrypted: false,
        folders,
        items,
    };

    let json_text = serde_json::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize plaintext JSON export: {e}"))?;

    Ok(VaultExportResult {
        format: VaultExportFormat::Json,
        content: Zeroizing::new(json_text),
        item_count,
        folder_count,
        skipped: Map::new(),
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_key(byte: u8) -> SymmetricCryptoKey {
        SymmetricCryptoKey::from_raw_bytes(&[byte; 64]).unwrap()
    }

    #[test]
    fn plaintext_json_exports_all_five_cipher_types_and_excludes_trash_org_attachments() {
        let user_key = make_key(0x2A);
        let item_key_raw = [0x55u8; 64];
        let item_key = SymmetricCryptoKey::from_raw_bytes(&item_key_raw).unwrap();
        let enc_item_key = user_key.encrypt(&item_key_raw).unwrap();
        let enc = |s: &str| user_key.encrypt_string(s).unwrap();
        let enc_with_item = |s: &str| item_key.encrypt_string(s).unwrap();

        let storage = VaultStorage {
            folders: vec![json!({
                "id": "folder-1",
                "name": enc("Work")
            })],
            ciphers: vec![
                // 1. Login with per-item key, URIs/match, TOTP, passkeys, httpAuthenticationEnabled,
                //    all 4 custom field types, passwordHistory, attachments (must be stripped)
                json!({
                    "id": "cipher-login",
                    "organizationId": null,
                    "folderId": "folder-1",
                    "type": 1,
                    "reprompt": 1,
                    "key": enc_item_key,
                    "name": enc_with_item("GitHub"),
                    "notes": enc_with_item("Main account"),
                    "favorite": true,
                    "creationDate": "2026-01-01T00:00:00Z",
                    "revisionDate": "2026-02-01T00:00:00Z",
                    "deletedDate": null,
                    "login": {
                        "username": enc_with_item("octocat"),
                        "password": enc_with_item("s3cr3t"),
                        "totp": enc_with_item("JBSWY3DPEHPK3PXP"),
                        "httpAuthenticationEnabled": true,
                        "uris": [
                            { "uri": enc_with_item("https://github.com"), "match": 0 },
                            { "uri": enc_with_item("https://api.github.com"), "match": null }
                        ],
                        "fido2Credentials": [
                            {
                                "credentialId": enc_with_item("cred-123"),
                                "keyType": enc_with_item("public-key"),
                                "keyAlgorithm": enc_with_item("ECDSA"),
                                "keyCurve": enc_with_item("P-256"),
                                "keyValue": enc_with_item("base64-pkcs8-key"),
                                "rpId": enc_with_item("github.com"),
                                "userHandle": enc_with_item("handle-1"),
                                "userName": enc_with_item("octocat"),
                                "counter": enc_with_item("0"),
                                "rpName": enc_with_item("GitHub"),
                                "userDisplayName": enc_with_item("Octo Cat"),
                                "discoverable": enc_with_item("true"),
                                "creationDate": "2026-01-15T12:00:00Z"
                            }
                        ]
                    },
                    "fields": [
                        { "name": enc_with_item("Env"), "value": enc_with_item("prod"), "type": 0, "linkedId": null },
                        { "name": enc_with_item("Token"), "value": enc_with_item("tok-999"), "type": 1, "linkedId": null },
                        { "name": enc_with_item("MFA"), "value": enc_with_item("true"), "type": 2, "linkedId": null },
                        { "name": enc_with_item("LinkedUser"), "value": null, "type": 3, "linkedId": 100 }
                    ],
                    "passwordHistory": [
                        { "lastUsedDate": "2025-12-01T00:00:00Z", "password": enc_with_item("old-pw") }
                    ],
                    "attachments": [
                        { "id": "att-1", "fileName": enc_with_item("secret.txt"), "size": "42" }
                    ]
                }),
                // 2. Secure Note
                json!({
                    "id": "cipher-note",
                    "organizationId": null,
                    "folderId": null,
                    "type": 2,
                    "reprompt": 0,
                    "name": enc("Recovery"),
                    "notes": enc("code-123"),
                    "favorite": false,
                    "creationDate": "2026-01-02T00:00:00Z",
                    "revisionDate": "2026-02-02T00:00:00Z",
                    "deletedDate": null,
                    "secureNote": { "type": 0 }
                }),
                // 3. Card
                json!({
                    "id": "cipher-card",
                    "organizationId": null,
                    "folderId": null,
                    "type": 3,
                    "name": enc("Visa"),
                    "notes": null,
                    "favorite": false,
                    "deletedDate": null,
                    "card": {
                        "cardholderName": enc("Alice"),
                        "brand": enc("Visa"),
                        "number": enc("4111222233334444"),
                        "expMonth": enc("12"),
                        "expYear": enc("2030"),
                        "code": enc("987")
                    }
                }),
                // 4. Identity
                json!({
                    "id": "cipher-identity",
                    "organizationId": null,
                    "folderId": null,
                    "type": 4,
                    "name": enc("Alice ID"),
                    "notes": null,
                    "favorite": false,
                    "deletedDate": null,
                    "identity": {
                        "title": enc("Dr"),
                        "firstName": enc("Alice"),
                        "lastName": enc("Example"),
                        "email": enc("alice@example.com"),
                        "ssn": enc("123-45-6789")
                    }
                }),
                // 5. SSH Key
                json!({
                    "id": "cipher-ssh",
                    "organizationId": null,
                    "folderId": null,
                    "type": 5,
                    "name": enc("Prod Key"),
                    "notes": enc("Bastion"),
                    "favorite": false,
                    "deletedDate": null,
                    "sshKey": {
                        "privateKey": enc("-----BEGIN OPENSSH PRIVATE KEY-----\nBODY\n-----END OPENSSH PRIVATE KEY-----\n"),
                        "publicKey": enc("ssh-ed25519 AAAA alice@host"),
                        "keyFingerprint": enc("SHA256:FakeFP")
                    }
                }),
                // 6. Trash cipher (MUST be excluded)
                json!({
                    "id": "cipher-trash",
                    "organizationId": null,
                    "folderId": null,
                    "type": 1,
                    "name": enc("Deleted Login"),
                    "deletedDate": "2026-02-10T00:00:00Z",
                    "login": { "username": enc("gone"), "password": enc("gone") }
                }),
                // 7. Organization cipher (MUST be excluded)
                json!({
                    "id": "cipher-org",
                    "organizationId": "org-1234",
                    "folderId": null,
                    "type": 1,
                    "name": enc("Org Login"),
                    "deletedDate": null,
                    "login": { "username": enc("orguser"), "password": enc("orgpw") }
                }),
            ],
            ..Default::default()
        };

        let result = export_personal_vault_plaintext_json(&storage, &user_key).unwrap();
        assert_eq!(result.format, VaultExportFormat::Json);
        assert_eq!(result.folder_count, 1);
        assert_eq!(result.item_count, 5);
        assert!(result.skipped.is_empty());
        assert!(result.warnings.is_empty());

        // Verify 2-space pretty-printed JSON formatting
        assert!(result.content.starts_with("{\n  \"encrypted\": false,\n"));

        let parsed: Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(parsed["encrypted"], false);
        assert_eq!(parsed["folders"][0]["id"], "folder-1");
        assert_eq!(parsed["folders"][0]["name"], "Work");

        let items = parsed["items"].as_array().unwrap();
        assert_eq!(items.len(), 5);

        // Login assertions
        let login = &items[0];
        assert_eq!(login["id"], "cipher-login");
        assert_eq!(login["name"], "GitHub");
        assert_eq!(login["reprompt"], 1);
        assert_eq!(login["favorite"], true);
        assert_eq!(login["organizationId"], Value::Null);
        assert_eq!(login["collectionIds"], Value::Null);
        assert!(
            login.get("key").is_none(),
            "plaintext export must omit per-cipher key"
        );
        assert!(
            login.get("attachments").is_none(),
            "plaintext export must exclude attachments"
        );
        assert_eq!(login["login"]["username"], "octocat");
        assert_eq!(login["login"]["password"], "s3cr3t");
        assert_eq!(login["login"]["totp"], "JBSWY3DPEHPK3PXP");
        assert_eq!(login["login"]["httpAuthenticationEnabled"], true);
        assert_eq!(login["login"]["uris"][0]["uri"], "https://github.com");
        assert_eq!(login["login"]["uris"][0]["match"], 0);
        assert_eq!(login["login"]["uris"][1]["match"], Value::Null);
        assert_eq!(
            login["login"]["fido2Credentials"][0]["credentialId"],
            "cred-123"
        );
        assert_eq!(login["login"]["fido2Credentials"][0]["rpId"], "github.com");
        assert_eq!(
            login["login"]["fido2Credentials"][0]["creationDate"],
            "2026-01-15T12:00:00Z"
        );
        assert_eq!(login["fields"][0]["type"], 0);
        assert_eq!(login["fields"][1]["type"], 1);
        assert_eq!(login["fields"][2]["type"], 2);
        assert_eq!(login["fields"][3]["type"], 3);
        assert_eq!(login["fields"][3]["linkedId"], 100);
        assert_eq!(login["passwordHistory"][0]["password"], "old-pw");
        assert_eq!(
            login["passwordHistory"][0]["lastUsedDate"],
            "2025-12-01T00:00:00Z"
        );

        // Secure Note
        assert_eq!(items[1]["type"], 2);
        assert_eq!(items[1]["secureNote"]["type"], 0);
        assert_eq!(items[1]["notes"], "code-123");

        // Card
        assert_eq!(items[2]["type"], 3);
        assert_eq!(items[2]["card"]["number"], "4111222233334444");
        assert_eq!(items[2]["card"]["code"], "987");

        // Identity
        assert_eq!(items[3]["type"], 4);
        assert_eq!(items[3]["identity"]["firstName"], "Alice");
        assert_eq!(items[3]["identity"]["ssn"], "123-45-6789");

        // SSH Key
        assert_eq!(items[4]["type"], 5);
        assert_eq!(
            items[4]["sshKey"]["privateKey"],
            "-----BEGIN OPENSSH PRIVATE KEY-----\nBODY\n-----END OPENSSH PRIVATE KEY-----\n"
        );
        assert_eq!(
            items[4]["sshKey"]["publicKey"],
            "ssh-ed25519 AAAA alice@host"
        );
        assert_eq!(items[4]["sshKey"]["keyFingerprint"], "SHA256:FakeFP");
    }

    #[test]
    fn default_filename_matches_official_bitwarden_pattern() {
        let name = VaultExportFormat::Json.default_filename();
        assert!(name.starts_with("bitwarden_export_"));
        assert!(name.ends_with(".json"));
        let ts = &name["bitwarden_export_".len()..name.len() - ".json".len()];
        assert_eq!(ts.len(), 14);
        assert!(ts.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn format_parse_rejects_unknown_formats_fail_closed() {
        assert_eq!(
            VaultExportFormat::parse("json").unwrap(),
            VaultExportFormat::Json
        );
        assert_eq!(
            VaultExportFormat::parse(" JSON ").unwrap(),
            VaultExportFormat::Json
        );
        assert!(VaultExportFormat::parse("xml").is_err());
    }
}
