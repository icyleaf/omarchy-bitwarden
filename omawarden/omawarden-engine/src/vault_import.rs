use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::api::decrypt_cipher_string;
use crate::crypto::SymmetricCryptoKey;
use crate::storage::VaultStorage;

/// Hard upper bound on import file size (50 MiB) enforced before parsing.
pub const MAX_IMPORT_FILE_BYTES: u64 = 50 * 1024 * 1024;

/// Bitwarden Cloud maximum ciphers per single import batch.
pub const BITWARDEN_CLOUD_MAX_CIPHERS: usize = 7_000;

/// Bitwarden Cloud maximum folders per single import batch.
pub const BITWARDEN_CLOUD_MAX_FOLDERS: usize = 2_000;

/// Maximum number of `passwordHistory` entries retained per imported cipher
/// (Vaultwarden / Bitwarden compatibility cap).
pub const MAX_PASSWORD_HISTORY_ENTRIES: usize = 5;

const REQUIRED_CSV_HEADERS: [&str; 11] = [
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
];

/// Requested Vault import format from CLI or Daemon Protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultImportFormat {
    Auto,
    EncryptedJson,
    AccountEncryptedJson,
    Json,
    Csv,
}

impl VaultImportFormat {
    /// Parses a CLI or Daemon Protocol import format identifier.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "encrypted_json" => Ok(Self::EncryptedJson),
            "account_encrypted_json" => Ok(Self::AccountEncryptedJson),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            other => Err(format!(
                "Unsupported import format '{other}'. Supported formats: auto, encrypted_json, account_encrypted_json, json, csv."
            )),
        }
    }

    /// Canonical wire/CLI identifier for this import format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::EncryptedJson => "encrypted_json",
            Self::AccountEncryptedJson => "account_encrypted_json",
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

/// Concrete format detected from an import file's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedImportFormat {
    EncryptedJson,
    AccountEncryptedJson,
    Json,
    Csv,
}

impl DetectedImportFormat {
    /// Canonical wire/CLI identifier for the detected format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedJson => "encrypted_json",
            Self::AccountEncryptedJson => "account_encrypted_json",
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }

    /// Returns `true` if this detected format matches the requested format.
    pub fn matches_requested(self, requested: VaultImportFormat) -> bool {
        match requested {
            VaultImportFormat::Auto => true,
            VaultImportFormat::EncryptedJson => self == Self::EncryptedJson,
            VaultImportFormat::AccountEncryptedJson => self == Self::AccountEncryptedJson,
            VaultImportFormat::Json => self == Self::Json,
            VaultImportFormat::Csv => self == Self::Csv,
        }
    }
}

/// Metadata for an unsupported newer Bitwarden cipher type (Types 6–8) skipped during import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedUnsupportedCipher {
    pub index: usize,
    pub name: String,
    #[serde(rename = "type")]
    pub cipher_type: i64,
}

/// Summary returned by both dry-run and real Vault import operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultImportSummary {
    pub dry_run: bool,
    pub detected_format: String,
    pub cipher_count: usize,
    pub folders_reused: usize,
    pub folders_created: usize,
    pub skipped_unsupported: Vec<SkippedUnsupportedCipher>,
    pub warnings: Vec<String>,
}

/// Full local import plan ready for either `--dry-run` reporting or `POST /api/ciphers/import`.
#[derive(Debug)]
pub struct PlannedVaultImport {
    pub detected_format: DetectedImportFormat,
    pub cipher_count: usize,
    pub folders_reused: usize,
    pub folders_created: usize,
    pub skipped_unsupported: Vec<SkippedUnsupportedCipher>,
    pub warnings: Vec<String>,
    /// Plaintext cipher names aligned 1:1 with `request_payload["ciphers"]` for server
    /// `validationErrors` index -> item name resolution.
    pub cipher_names: Vec<String>,
    /// Encrypted `POST /api/ciphers/import` JSON body (`folders`, `ciphers`, `folderRelationships`).
    pub request_payload: Value,
}

impl PlannedVaultImport {
    pub fn to_summary(&self, dry_run: bool) -> VaultImportSummary {
        VaultImportSummary {
            dry_run,
            detected_format: self.detected_format.as_str().to_string(),
            cipher_count: self.cipher_count,
            folders_reused: self.folders_reused,
            folders_created: self.folders_created,
            skipped_unsupported: self.skipped_unsupported.clone(),
            warnings: self.warnings.clone(),
        }
    }
}

/// Reads an import file into a zeroizing buffer while enforcing the 50 MiB hard cap
/// before any parsing occurs.
pub fn read_bounded_import_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("Failed to inspect import file '{}': {e}", path.display()))?;
    if meta.is_dir() {
        return Err(format!(
            "Import path '{}' is a directory; expected a regular file.",
            path.display()
        ));
    }
    if meta.len() > MAX_IMPORT_FILE_BYTES {
        return Err(format!(
            "Import file '{}' ({} bytes) exceeds maximum allowed size of {} bytes (50 MiB).",
            path.display(),
            meta.len(),
            MAX_IMPORT_FILE_BYTES
        ));
    }

    let file = fs::File::open(path)
        .map_err(|e| format!("Failed to open import file '{}': {e}", path.display()))?;
    let mut buf = Zeroizing::new(Vec::new());
    file.take(MAX_IMPORT_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read import file '{}': {e}", path.display()))?;
    if buf.len() as u64 > MAX_IMPORT_FILE_BYTES {
        return Err(format!(
            "Import file '{}' exceeds maximum allowed size of {} bytes (50 MiB).",
            path.display(),
            MAX_IMPORT_FILE_BYTES
        ));
    }
    Ok(buf)
}

fn strip_utf8_bom(s: &str) -> &str {
    s.strip_prefix('\u{feff}').unwrap_or(s)
}

/// Lightweight local pre-flight inspection of an import file: enforces the 50 MiB cap,
/// detects the format, and verifies compatibility with any explicit `--format`.
pub fn inspect_import_file(
    path: &Path,
    requested: VaultImportFormat,
) -> Result<DetectedImportFormat, String> {
    let bytes = read_bounded_import_file(path)?;
    inspect_import_bytes(&bytes, requested)
}

/// Inspects raw import bytes (enforcing the 50 MiB cap), detects the Bitwarden export format,
/// and fails closed if an explicit `requested` format mismatches the detected content.
pub fn inspect_import_bytes(
    raw: &[u8],
    requested: VaultImportFormat,
) -> Result<DetectedImportFormat, String> {
    if raw.len() as u64 > MAX_IMPORT_FILE_BYTES {
        return Err(format!(
            "Import payload ({} bytes) exceeds maximum allowed size of {} bytes (50 MiB).",
            raw.len(),
            MAX_IMPORT_FILE_BYTES
        ));
    }
    let text =
        std::str::from_utf8(raw).map_err(|_| "Import file is not valid UTF-8.".to_string())?;
    let stripped = strip_utf8_bom(text);
    let trimmed = stripped.trim_start();
    if trimmed.is_empty() {
        return Err("Import file is empty.".to_string());
    }

    let detected = if trimmed.starts_with('{') {
        let doc: Value = serde_json::from_str(stripped)
            .map_err(|e| format!("Invalid JSON syntax in import file: {e}"))?;
        let obj = doc.as_object().ok_or_else(|| {
            "Invalid JSON import file: top-level value must be a JSON object.".to_string()
        })?;
        match obj.get("encrypted").and_then(Value::as_bool) {
            Some(true) => {
                let password_protected = obj
                    .get("passwordProtected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if password_protected {
                    DetectedImportFormat::EncryptedJson
                } else {
                    DetectedImportFormat::AccountEncryptedJson
                }
            }
            Some(false) => {
                if !obj.contains_key("items") {
                    return Err(
                        "Invalid Plaintext JSON import file: missing required 'items' array."
                            .to_string(),
                    );
                }
                DetectedImportFormat::Json
            }
            None => {
                if obj.contains_key("items") && obj.get("items").is_some_and(Value::is_array) {
                    DetectedImportFormat::Json
                } else {
                    return Err(
                        "Unrecognized JSON import file: expected Bitwarden export with 'encrypted' flag or 'items' array."
                            .to_string(),
                    );
                }
            }
        }
    } else if is_bitwarden_csv_header(stripped)? {
        DetectedImportFormat::Csv
    } else {
        return Err(
            "Unrecognized import format. Expected a Bitwarden JSON export or Bitwarden RFC 4180 CSV with standard headers."
                .to_string(),
        );
    };

    if !detected.matches_requested(requested) {
        return Err(format!(
            "Format mismatch: --format {} was specified, but file content was detected as {}.",
            requested.as_str(),
            detected.as_str()
        ));
    }

    Ok(detected)
}

fn is_bitwarden_csv_header(content: &str) -> Result<bool, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(content.as_bytes());
    let headers = match reader.headers() {
        Ok(h) => h,
        Err(e) => return Err(format!("Invalid CSV header row: {e}")),
    };
    let header_set: HashSet<&str> = headers.iter().collect();
    if REQUIRED_CSV_HEADERS
        .iter()
        .all(|required| header_set.contains(required))
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedFolder {
    /// Original ID from JSON export (if any); used for UUID reuse matching.
    source_id: Option<String>,
    name: String,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedField {
    name: Option<String>,
    value: Option<String>,
    field_type: i64,
    linked_id: Option<i64>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedLoginUri {
    uri: Option<String>,
    uri_match: Option<i64>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedFido2Credential {
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

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    password_revision_date: Option<String>,
    http_authentication_enabled: Option<bool>,
    uris: Vec<NormalizedLoginUri>,
    fido2_credentials: Vec<NormalizedFido2Credential>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedSecureNote {
    note_type: i64,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedCard {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedIdentity {
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

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedSshKey {
    private_key: String,
    public_key: String,
    key_fingerprint: String,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedPasswordHistoryEntry {
    last_used_date: Option<String>,
    password: String,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
struct NormalizedCipher {
    cipher_type: i64,
    name: String,
    notes: Option<String>,
    favorite: bool,
    reprompt: i64,
    archived_date: Option<String>,
    /// Index into `ParsedImportData.folders` (if the cipher belongs to an imported folder).
    imported_folder_idx: Option<usize>,
    /// Raw folder ID when referencing a folder UUID not listed in `folders` (may still match an existing Vault folder UUID).
    raw_folder_id: Option<String>,
    fields: Vec<NormalizedField>,
    password_history: Vec<NormalizedPasswordHistoryEntry>,
    login: Option<NormalizedLogin>,
    secure_note: Option<NormalizedSecureNote>,
    card: Option<NormalizedCard>,
    identity: Option<NormalizedIdentity>,
    ssh_key: Option<NormalizedSshKey>,
}

struct ParsedImportData {
    folders: Vec<NormalizedFolder>,
    ciphers: Vec<NormalizedCipher>,
    skipped_unsupported: Vec<SkippedUnsupportedCipher>,
    warnings: Vec<String>,
}

fn cipher_label(index: usize, name: Option<&str>) -> String {
    match name.filter(|s| !s.trim().is_empty()) {
        Some(n) => format!("item #{index} ('{n}')"),
        None => format!("item #{index} ('<unnamed>')"),
    }
}

fn opt_non_empty_str(
    obj: &Map<String, Value>,
    key: &str,
    ctx: &str,
) -> Result<Option<String>, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s.clone()))
            }
        }
        Some(_) => Err(format!(
            "Malformed {ctx}: field '{key}' must be a string or null."
        )),
    }
}

fn parse_plaintext_json(content: &str) -> Result<ParsedImportData, String> {
    let doc: Value = serde_json::from_str(content)
        .map_err(|e| format!("Invalid JSON syntax in import file: {e}"))?;
    let obj = doc.as_object().ok_or_else(|| {
        "Invalid JSON import file: top-level value must be a JSON object.".to_string()
    })?;

    let mut folders = Vec::new();
    let mut folder_id_to_idx: HashMap<String, usize> = HashMap::new();

    if let Some(folders_val) = obj.get("folders") {
        if !folders_val.is_null() {
            let arr = folders_val.as_array().ok_or_else(|| {
                "Invalid JSON import file: 'folders' must be an array.".to_string()
            })?;
            for (idx, f) in arr.iter().enumerate() {
                let fobj = f
                    .as_object()
                    .ok_or_else(|| format!("Malformed folder #{idx}: expected a JSON object."))?;
                let name = fobj
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| format!("Malformed folder #{idx}: missing or empty 'name'."))?;
                let source_id = opt_non_empty_str(fobj, "id", &format!("folder #{idx}"))?;
                let folder_idx = folders.len();
                if let Some(ref sid) = source_id {
                    folder_id_to_idx.entry(sid.clone()).or_insert(folder_idx);
                }
                folders.push(NormalizedFolder { source_id, name });
            }
        }
    }

    let items_arr = obj
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "Invalid JSON import file: missing or invalid 'items' array.".to_string())?;

    let mut ciphers = Vec::new();
    let mut skipped_unsupported = Vec::new();

    for (idx, item) in items_arr.iter().enumerate() {
        let Some(iobj) = item.as_object() else {
            return Err(format!(
                "Malformed {}: expected a JSON object.",
                cipher_label(idx, None)
            ));
        };

        let raw_name = iobj.get("name").and_then(Value::as_str);
        let label = cipher_label(idx, raw_name);

        let cipher_type = iobj
            .get("type")
            .and_then(Value::as_i64)
            .ok_or_else(|| format!("Malformed {label}: missing or non-integer 'type'."))?;

        // Unsupported newer Bitwarden cipher types (6: Bank Account, 7: Driver's License, 8: Passport)
        if matches!(cipher_type, 6..=8) {
            skipped_unsupported.push(SkippedUnsupportedCipher {
                index: idx,
                name: raw_name.unwrap_or("<unnamed>").to_string(),
                cipher_type,
            });
            continue;
        }

        if !matches!(cipher_type, 1..=5) {
            return Err(format!(
                "Malformed {label}: unsupported cipher type {cipher_type} (expected 1-5)."
            ));
        }

        let name = raw_name
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| format!("Malformed {label}: missing or empty 'name'."))?
            .to_string();

        let notes = opt_non_empty_str(iobj, "notes", &label)?;
        let favorite = match iobj.get("favorite") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(format!("Malformed {label}: 'favorite' must be a boolean.")),
        };
        let reprompt = match iobj.get("reprompt") {
            None | Some(Value::Null) => 0,
            Some(v) => v
                .as_i64()
                .ok_or_else(|| format!("Malformed {label}: 'reprompt' must be an integer."))?,
        };
        let archived_date = opt_non_empty_str(iobj, "archivedDate", &label)?;
        let raw_folder_id = opt_non_empty_str(iobj, "folderId", &label)?;
        let imported_folder_idx = raw_folder_id
            .as_ref()
            .and_then(|fid| folder_id_to_idx.get(fid).copied());

        // Custom fields
        let mut fields = Vec::new();
        if let Some(fields_val) = iobj.get("fields") {
            if !fields_val.is_null() {
                let farr = fields_val
                    .as_array()
                    .ok_or_else(|| format!("Malformed {label}: 'fields' must be an array."))?;
                for (fidx, fv) in farr.iter().enumerate() {
                    let fobj = fv.as_object().ok_or_else(|| {
                        format!("Malformed {label}: field[{fidx}] must be a JSON object.")
                    })?;
                    let ftype = match fobj.get("type") {
                        None | Some(Value::Null) => 0,
                        Some(v) => v.as_i64().ok_or_else(|| {
                            format!("Malformed {label}: field[{fidx}].type must be an integer.")
                        })?,
                    };
                    let linked_id = match fobj.get("linkedId") {
                        None | Some(Value::Null) => None,
                        Some(v) => Some(v.as_i64().ok_or_else(|| {
                            format!(
                                "Malformed {label}: field[{fidx}].linkedId must be an integer or null."
                            )
                        })?),
                    };
                    fields.push(NormalizedField {
                        name: opt_non_empty_str(fobj, "name", &label)?,
                        value: opt_non_empty_str(fobj, "value", &label)?,
                        field_type: ftype,
                        linked_id,
                    });
                }
            }
        }

        // Password history: filter out null/empty entries and cap at 5
        let mut password_history = Vec::new();
        if let Some(hist_val) = iobj.get("passwordHistory") {
            if !hist_val.is_null() {
                let harr = hist_val.as_array().ok_or_else(|| {
                    format!("Malformed {label}: 'passwordHistory' must be an array.")
                })?;
                for entry in harr {
                    let Some(hobj) = entry.as_object() else {
                        continue;
                    };
                    let Some(pw) = hobj
                        .get("password")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    else {
                        continue;
                    };
                    let last_used_date = hobj
                        .get("lastUsedDate")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string);
                    password_history.push(NormalizedPasswordHistoryEntry {
                        last_used_date,
                        password: pw.to_string(),
                    });
                    if password_history.len() >= MAX_PASSWORD_HISTORY_ENTRIES {
                        break;
                    }
                }
            }
        }

        let mut login = None;
        let mut secure_note = None;
        let mut card = None;
        let mut identity = None;
        let mut ssh_key = None;

        match cipher_type {
            1 => {
                let lobj = iobj
                    .get("login")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        format!(
                            "Malformed {label}: Login cipher (type 1) is missing 'login' object."
                        )
                    })?;
                let mut uris = Vec::new();
                if let Some(uris_val) = lobj.get("uris") {
                    if !uris_val.is_null() {
                        let uarr = uris_val.as_array().ok_or_else(|| {
                            format!("Malformed {label}: 'login.uris' must be an array.")
                        })?;
                        for (uidx, uv) in uarr.iter().enumerate() {
                            let uobj = uv.as_object().ok_or_else(|| {
                                format!(
                                    "Malformed {label}: login.uris[{uidx}] must be a JSON object."
                                )
                            })?;
                            let uri_match = match uobj.get("match") {
                                None | Some(Value::Null) => None,
                                Some(v) => Some(v.as_i64().ok_or_else(|| {
                                    format!(
                                        "Malformed {label}: login.uris[{uidx}].match must be an integer or null."
                                    )
                                })?),
                            };
                            uris.push(NormalizedLoginUri {
                                uri: opt_non_empty_str(uobj, "uri", &label)?,
                                uri_match,
                            });
                        }
                    }
                }

                let mut fido2_credentials = Vec::new();
                if let Some(fido_val) = lobj.get("fido2Credentials") {
                    if !fido_val.is_null() {
                        let farr = fido_val.as_array().ok_or_else(|| {
                            format!("Malformed {label}: 'login.fido2Credentials' must be an array.")
                        })?;
                        for (fidx, fv) in farr.iter().enumerate() {
                            let fobj = fv.as_object().ok_or_else(|| {
                                format!(
                                    "Malformed {label}: login.fido2Credentials[{fidx}] must be a JSON object."
                                )
                            })?;
                            fido2_credentials.push(NormalizedFido2Credential {
                                credential_id: opt_non_empty_str(fobj, "credentialId", &label)?,
                                key_type: opt_non_empty_str(fobj, "keyType", &label)?,
                                key_algorithm: opt_non_empty_str(fobj, "keyAlgorithm", &label)?,
                                key_curve: opt_non_empty_str(fobj, "keyCurve", &label)?,
                                key_value: opt_non_empty_str(fobj, "keyValue", &label)?,
                                rp_id: opt_non_empty_str(fobj, "rpId", &label)?,
                                user_handle: opt_non_empty_str(fobj, "userHandle", &label)?,
                                user_name: opt_non_empty_str(fobj, "userName", &label)?,
                                counter: opt_non_empty_str(fobj, "counter", &label)?,
                                rp_name: opt_non_empty_str(fobj, "rpName", &label)?,
                                user_display_name: opt_non_empty_str(
                                    fobj,
                                    "userDisplayName",
                                    &label,
                                )?,
                                discoverable: opt_non_empty_str(fobj, "discoverable", &label)?,
                                creation_date: opt_non_empty_str(fobj, "creationDate", &label)?,
                            });
                        }
                    }
                }

                let http_authentication_enabled = match lobj.get("httpAuthenticationEnabled") {
                    None | Some(Value::Null) => None,
                    Some(Value::Bool(b)) => Some(*b),
                    Some(_) => {
                        return Err(format!(
                        "Malformed {label}: 'login.httpAuthenticationEnabled' must be a boolean."
                    ))
                    }
                };

                login = Some(NormalizedLogin {
                    username: opt_non_empty_str(lobj, "username", &label)?,
                    password: opt_non_empty_str(lobj, "password", &label)?,
                    totp: opt_non_empty_str(lobj, "totp", &label)?,
                    password_revision_date: opt_non_empty_str(
                        lobj,
                        "passwordRevisionDate",
                        &label,
                    )?,
                    http_authentication_enabled,
                    uris,
                    fido2_credentials,
                });
            }
            2 => {
                let note_type = match iobj.get("secureNote") {
                    None | Some(Value::Null) => 0,
                    Some(Value::Object(sn)) => match sn.get("type") {
                        None | Some(Value::Null) => 0,
                        Some(v) => v.as_i64().ok_or_else(|| {
                            format!("Malformed {label}: 'secureNote.type' must be an integer.")
                        })?,
                    },
                    Some(_) => {
                        return Err(format!(
                            "Malformed {label}: 'secureNote' must be a JSON object."
                        ))
                    }
                };
                secure_note = Some(NormalizedSecureNote { note_type });
            }
            3 => {
                let cobj = iobj.get("card").and_then(Value::as_object).ok_or_else(|| {
                    format!("Malformed {label}: Card cipher (type 3) is missing 'card' object.")
                })?;
                card = Some(NormalizedCard {
                    cardholder_name: opt_non_empty_str(cobj, "cardholderName", &label)?,
                    brand: opt_non_empty_str(cobj, "brand", &label)?,
                    number: opt_non_empty_str(cobj, "number", &label)?,
                    exp_month: opt_non_empty_str(cobj, "expMonth", &label)?,
                    exp_year: opt_non_empty_str(cobj, "expYear", &label)?,
                    code: opt_non_empty_str(cobj, "code", &label)?,
                });
            }
            4 => {
                let idobj = iobj
                    .get("identity")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        format!(
                            "Malformed {label}: Identity cipher (type 4) is missing 'identity' object."
                        )
                    })?;
                identity = Some(NormalizedIdentity {
                    title: opt_non_empty_str(idobj, "title", &label)?,
                    first_name: opt_non_empty_str(idobj, "firstName", &label)?,
                    middle_name: opt_non_empty_str(idobj, "middleName", &label)?,
                    last_name: opt_non_empty_str(idobj, "lastName", &label)?,
                    address1: opt_non_empty_str(idobj, "address1", &label)?,
                    address2: opt_non_empty_str(idobj, "address2", &label)?,
                    address3: opt_non_empty_str(idobj, "address3", &label)?,
                    city: opt_non_empty_str(idobj, "city", &label)?,
                    state: opt_non_empty_str(idobj, "state", &label)?,
                    postal_code: opt_non_empty_str(idobj, "postalCode", &label)?,
                    country: opt_non_empty_str(idobj, "country", &label)?,
                    company: opt_non_empty_str(idobj, "company", &label)?,
                    email: opt_non_empty_str(idobj, "email", &label)?,
                    phone: opt_non_empty_str(idobj, "phone", &label)?,
                    ssn: opt_non_empty_str(idobj, "ssn", &label)?,
                    username: opt_non_empty_str(idobj, "username", &label)?,
                    passport_number: opt_non_empty_str(idobj, "passportNumber", &label)?,
                    license_number: opt_non_empty_str(idobj, "licenseNumber", &label)?,
                });
            }
            5 => {
                let sobj = iobj
                    .get("sshKey")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        format!(
                            "Malformed {label}: SSH Key cipher (type 5) is missing 'sshKey' object."
                        )
                    })?;
                let private_key = opt_non_empty_str(sobj, "privateKey", &label)?.ok_or_else(|| {
                    format!(
                        "Malformed {label}: SSH Key cipher requires non-empty 'privateKey', 'publicKey', and 'keyFingerprint'."
                    )
                })?;
                let public_key = opt_non_empty_str(sobj, "publicKey", &label)?.ok_or_else(|| {
                    format!(
                        "Malformed {label}: SSH Key cipher requires non-empty 'privateKey', 'publicKey', and 'keyFingerprint'."
                    )
                })?;
                let key_fingerprint = opt_non_empty_str(sobj, "keyFingerprint", &label)?
                    .or(opt_non_empty_str(sobj, "fingerprint", &label)?)
                    .ok_or_else(|| {
                        format!(
                            "Malformed {label}: SSH Key cipher requires non-empty 'privateKey', 'publicKey', and 'keyFingerprint'."
                        )
                    })?;
                ssh_key = Some(NormalizedSshKey {
                    private_key,
                    public_key,
                    key_fingerprint,
                });
            }
            _ => unreachable!("filtered above"),
        }

        ciphers.push(NormalizedCipher {
            cipher_type,
            name,
            notes,
            favorite,
            reprompt,
            archived_date,
            imported_folder_idx,
            raw_folder_id,
            fields,
            password_history,
            login,
            secure_note,
            card,
            identity,
            ssh_key,
        });
    }

    let mut warnings = Vec::new();
    if !skipped_unsupported.is_empty() {
        let names: Vec<String> = skipped_unsupported
            .iter()
            .map(|s| format!("'{}' (type {})", s.name, s.cipher_type))
            .collect();
        warnings.push(format!(
            "Skipped {} unsupported cipher(s) (Types 6-8): {}.",
            skipped_unsupported.len(),
            names.join(", ")
        ));
    }

    Ok(ParsedImportData {
        folders,
        ciphers,
        skipped_unsupported,
        warnings,
    })
}

fn parse_bitwarden_csv(content: &str) -> Result<ParsedImportData, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("Invalid CSV header row: {e}"))?
        .clone();

    let mut col_idx: HashMap<String, usize> = HashMap::new();
    for (idx, h) in headers.iter().enumerate() {
        col_idx.insert(h.to_string(), idx);
    }

    for required in REQUIRED_CSV_HEADERS {
        if !col_idx.contains_key(required) {
            return Err(format!(
                "Invalid Bitwarden CSV header: missing required column '{required}'."
            ));
        }
    }

    fn get_cell<'a>(
        record: &'a csv::StringRecord,
        col_idx: &HashMap<String, usize>,
        name: &str,
    ) -> &'a str {
        col_idx.get(name).and_then(|&i| record.get(i)).unwrap_or("")
    }

    let mut folders: Vec<NormalizedFolder> = Vec::new();
    let mut folder_name_to_idx: HashMap<String, usize> = HashMap::new();
    let mut ciphers: Vec<NormalizedCipher> = Vec::new();

    for (idx, record_res) in reader.records().enumerate() {
        let record = record_res.map_err(|e| format!("Invalid CSV syntax at item #{idx}: {e}"))?;

        let raw_name = get_cell(&record, &col_idx, "name");
        let label = cipher_label(idx, Some(raw_name));
        if raw_name.trim().is_empty() {
            return Err(format!("Malformed {label}: missing or empty 'name'."));
        }

        let raw_type = get_cell(&record, &col_idx, "type")
            .trim()
            .to_ascii_lowercase();
        let cipher_type = match raw_type.as_str() {
            "" | "login" => 1,
            "note" => 2,
            other => {
                return Err(format!(
                    "Malformed {label}: unsupported CSV cipher type '{other}' (expected 'login' or 'note')."
                ))
            }
        };

        let folder_cell = get_cell(&record, &col_idx, "folder");
        let imported_folder_idx = if folder_cell.is_empty() {
            None
        } else {
            let fidx = if let Some(&existing) = folder_name_to_idx.get(folder_cell) {
                existing
            } else {
                let new_idx = folders.len();
                folders.push(NormalizedFolder {
                    source_id: None,
                    name: folder_cell.to_string(),
                });
                folder_name_to_idx.insert(folder_cell.to_string(), new_idx);
                new_idx
            };
            Some(fidx)
        };

        let fav_cell = get_cell(&record, &col_idx, "favorite").trim();
        let favorite = fav_cell == "1" || fav_cell.eq_ignore_ascii_case("true");

        let reprompt_cell = get_cell(&record, &col_idx, "reprompt").trim();
        let reprompt = match reprompt_cell {
            "" | "0" => 0,
            "1" => 1,
            other => {
                return Err(format!(
                    "Malformed {label}: invalid CSV reprompt value '{other}' (expected '0' or '1')."
                ))
            }
        };

        let notes_cell = get_cell(&record, &col_idx, "notes");
        let notes = if notes_cell.is_empty() {
            None
        } else {
            Some(notes_cell.to_string())
        };

        let archived_cell = get_cell(&record, &col_idx, "archivedDate");
        let archived_date = if archived_cell.is_empty() {
            None
        } else {
            Some(archived_cell.to_string())
        };

        // Custom fields: `Name: Value` lines parsed via `rfind(": ")` (`lastIndexOf(": ")`)
        let mut fields = Vec::new();
        let fields_cell = get_cell(&record, &col_idx, "fields");
        if !fields_cell.is_empty() {
            for raw_line in fields_cell.split('\n') {
                let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
                if line.is_empty() {
                    continue;
                }
                if let Some(pos) = line.rfind(": ") {
                    let fname = &line[..pos];
                    let fval = &line[pos + 2..];
                    fields.push(NormalizedField {
                        name: if fname.is_empty() {
                            None
                        } else {
                            Some(fname.to_string())
                        },
                        value: if fval.is_empty() {
                            None
                        } else {
                            Some(fval.to_string())
                        },
                        field_type: 0,
                        linked_id: None,
                    });
                } else {
                    fields.push(NormalizedField {
                        name: Some(line.to_string()),
                        value: None,
                        field_type: 0,
                        linked_id: None,
                    });
                }
            }
        }

        let (login, secure_note) = if cipher_type == 1 {
            let uri_cell = get_cell(&record, &col_idx, "login_uri");
            let uris: Vec<NormalizedLoginUri> = uri_cell
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|u| NormalizedLoginUri {
                    uri: Some(u.to_string()),
                    uri_match: None,
                })
                .collect();
            let username = {
                let s = get_cell(&record, &col_idx, "login_username");
                (!s.is_empty()).then(|| s.to_string())
            };
            let password = {
                let s = get_cell(&record, &col_idx, "login_password");
                (!s.is_empty()).then(|| s.to_string())
            };
            let totp = {
                let s = get_cell(&record, &col_idx, "login_totp");
                (!s.is_empty()).then(|| s.to_string())
            };
            (
                Some(NormalizedLogin {
                    username,
                    password,
                    totp,
                    password_revision_date: None,
                    http_authentication_enabled: None,
                    uris,
                    fido2_credentials: Vec::new(),
                }),
                None,
            )
        } else {
            (None, Some(NormalizedSecureNote { note_type: 0 }))
        };

        ciphers.push(NormalizedCipher {
            cipher_type,
            name: raw_name.to_string(),
            notes,
            favorite,
            reprompt,
            archived_date,
            imported_folder_idx,
            raw_folder_id: None,
            fields,
            password_history: Vec::new(),
            login,
            secure_note,
            card: None,
            identity: None,
            ssh_key: None,
        });
    }

    Ok(ParsedImportData {
        folders,
        ciphers,
        skipped_unsupported: Vec::new(),
        warnings: Vec::new(),
    })
}

#[derive(Debug, Clone)]
enum FolderAssignment {
    None,
    ExistingUuid(String),
    NewFolderIdx(usize),
}

fn enc_opt(val: Option<&str>, user_key: &SymmetricCryptoKey) -> Result<Value, String> {
    match val {
        Some(s) if !s.is_empty() => {
            Ok(Value::String(user_key.encrypt_string(s).map_err(|e| {
                format!("Failed to encrypt import field: {e}")
            })?))
        }
        _ => Ok(Value::Null),
    }
}

fn encrypt_cipher_for_import(
    cipher: &NormalizedCipher,
    folder_id: Option<&str>,
    user_key: &SymmetricCryptoKey,
) -> Result<Value, String> {
    let enc_name = user_key
        .encrypt_string(&cipher.name)
        .map_err(|e| format!("Failed to encrypt cipher name '{}': {e}", cipher.name))?;
    let enc_notes = enc_opt(cipher.notes.as_deref(), user_key)?;

    let fields_val = if cipher.fields.is_empty() {
        Value::Null
    } else {
        let mut arr = Vec::with_capacity(cipher.fields.len());
        for f in &cipher.fields {
            arr.push(json!({
                "name": enc_opt(f.name.as_deref(), user_key)?,
                "value": enc_opt(f.value.as_deref(), user_key)?,
                "type": f.field_type,
                "linkedId": f.linked_id,
            }));
        }
        Value::Array(arr)
    };

    let password_history_val = if cipher.password_history.is_empty() {
        Value::Null
    } else {
        let mut arr = Vec::with_capacity(cipher.password_history.len());
        for h in &cipher.password_history {
            arr.push(json!({
                "lastUsedDate": h.last_used_date,
                "password": user_key
                    .encrypt_string(&h.password)
                    .map_err(|e| format!("Failed to encrypt passwordHistory entry: {e}"))?,
            }));
        }
        Value::Array(arr)
    };

    let mut obj = Map::new();
    obj.insert("type".to_string(), json!(cipher.cipher_type));
    obj.insert("organizationId".to_string(), Value::Null);
    obj.insert("collectionIds".to_string(), Value::Null);
    obj.insert(
        "folderId".to_string(),
        match folder_id {
            Some(fid) => Value::String(fid.to_string()),
            None => Value::Null,
        },
    );
    obj.insert("name".to_string(), Value::String(enc_name));
    obj.insert("notes".to_string(), enc_notes);
    obj.insert("favorite".to_string(), json!(cipher.favorite));
    obj.insert("reprompt".to_string(), json!(cipher.reprompt));
    obj.insert("fields".to_string(), fields_val);
    obj.insert("passwordHistory".to_string(), password_history_val);
    if let Some(ref archived) = cipher.archived_date {
        obj.insert("archivedDate".to_string(), Value::String(archived.clone()));
    }

    if let Some(ref l) = cipher.login {
        let mut uris = Vec::with_capacity(l.uris.len());
        for u in &l.uris {
            uris.push(json!({
                "uri": enc_opt(u.uri.as_deref(), user_key)?,
                "match": u.uri_match,
            }));
        }
        let mut login_obj = Map::new();
        login_obj.insert(
            "username".to_string(),
            enc_opt(l.username.as_deref(), user_key)?,
        );
        login_obj.insert(
            "password".to_string(),
            enc_opt(l.password.as_deref(), user_key)?,
        );
        login_obj.insert("totp".to_string(), enc_opt(l.totp.as_deref(), user_key)?);
        login_obj.insert("uris".to_string(), Value::Array(uris));
        if let Some(ref rev) = l.password_revision_date {
            login_obj.insert(
                "passwordRevisionDate".to_string(),
                Value::String(rev.clone()),
            );
        }
        if let Some(http_auth) = l.http_authentication_enabled {
            login_obj.insert("httpAuthenticationEnabled".to_string(), json!(http_auth));
        }
        if !l.fido2_credentials.is_empty() {
            let mut fido_arr = Vec::with_capacity(l.fido2_credentials.len());
            for f in &l.fido2_credentials {
                fido_arr.push(json!({
                    "credentialId": enc_opt(f.credential_id.as_deref(), user_key)?,
                    "keyType": enc_opt(f.key_type.as_deref(), user_key)?,
                    "keyAlgorithm": enc_opt(f.key_algorithm.as_deref(), user_key)?,
                    "keyCurve": enc_opt(f.key_curve.as_deref(), user_key)?,
                    "keyValue": enc_opt(f.key_value.as_deref(), user_key)?,
                    "rpId": enc_opt(f.rp_id.as_deref(), user_key)?,
                    "userHandle": enc_opt(f.user_handle.as_deref(), user_key)?,
                    "userName": enc_opt(f.user_name.as_deref(), user_key)?,
                    "counter": enc_opt(f.counter.as_deref(), user_key)?,
                    "rpName": enc_opt(f.rp_name.as_deref(), user_key)?,
                    "userDisplayName": enc_opt(f.user_display_name.as_deref(), user_key)?,
                    "discoverable": enc_opt(f.discoverable.as_deref(), user_key)?,
                    "creationDate": f.creation_date,
                }));
            }
            login_obj.insert("fido2Credentials".to_string(), Value::Array(fido_arr));
        }
        obj.insert("login".to_string(), Value::Object(login_obj));
    }

    if let Some(ref sn) = cipher.secure_note {
        obj.insert("secureNote".to_string(), json!({ "type": sn.note_type }));
    }

    if let Some(ref c) = cipher.card {
        obj.insert(
            "card".to_string(),
            json!({
                "cardholderName": enc_opt(c.cardholder_name.as_deref(), user_key)?,
                "brand": enc_opt(c.brand.as_deref(), user_key)?,
                "number": enc_opt(c.number.as_deref(), user_key)?,
                "expMonth": enc_opt(c.exp_month.as_deref(), user_key)?,
                "expYear": enc_opt(c.exp_year.as_deref(), user_key)?,
                "code": enc_opt(c.code.as_deref(), user_key)?,
            }),
        );
    }

    if let Some(ref id) = cipher.identity {
        obj.insert(
            "identity".to_string(),
            json!({
                "title": enc_opt(id.title.as_deref(), user_key)?,
                "firstName": enc_opt(id.first_name.as_deref(), user_key)?,
                "middleName": enc_opt(id.middle_name.as_deref(), user_key)?,
                "lastName": enc_opt(id.last_name.as_deref(), user_key)?,
                "address1": enc_opt(id.address1.as_deref(), user_key)?,
                "address2": enc_opt(id.address2.as_deref(), user_key)?,
                "address3": enc_opt(id.address3.as_deref(), user_key)?,
                "city": enc_opt(id.city.as_deref(), user_key)?,
                "state": enc_opt(id.state.as_deref(), user_key)?,
                "postalCode": enc_opt(id.postal_code.as_deref(), user_key)?,
                "country": enc_opt(id.country.as_deref(), user_key)?,
                "company": enc_opt(id.company.as_deref(), user_key)?,
                "email": enc_opt(id.email.as_deref(), user_key)?,
                "phone": enc_opt(id.phone.as_deref(), user_key)?,
                "ssn": enc_opt(id.ssn.as_deref(), user_key)?,
                "username": enc_opt(id.username.as_deref(), user_key)?,
                "passportNumber": enc_opt(id.passport_number.as_deref(), user_key)?,
                "licenseNumber": enc_opt(id.license_number.as_deref(), user_key)?,
            }),
        );
    }

    if let Some(ref ssh) = cipher.ssh_key {
        obj.insert(
            "sshKey".to_string(),
            json!({
                "privateKey": user_key
                    .encrypt_string(&ssh.private_key)
                    .map_err(|e| format!("Failed to encrypt sshKey.privateKey: {e}"))?,
                "publicKey": user_key
                    .encrypt_string(&ssh.public_key)
                    .map_err(|e| format!("Failed to encrypt sshKey.publicKey: {e}"))?,
                "keyFingerprint": user_key
                    .encrypt_string(&ssh.key_fingerprint)
                    .map_err(|e| format!("Failed to encrypt sshKey.keyFingerprint: {e}"))?,
            }),
        );
    }

    Ok(Value::Object(obj))
}

/// Validates, normalizes, reconciles Folders, checks Bitwarden Cloud batch limits, and
/// builds the encrypted `POST /api/ciphers/import` payload strictly inside the engine.
pub fn plan_personal_vault_import(
    storage: &VaultStorage,
    user_key: &SymmetricCryptoKey,
    raw_bytes: &[u8],
    requested_format: VaultImportFormat,
    folder_override: Option<&str>,
) -> Result<PlannedVaultImport, String> {
    let detected = inspect_import_bytes(raw_bytes, requested_format)?;

    let text = std::str::from_utf8(raw_bytes)
        .map_err(|_| "Import file is not valid UTF-8.".to_string())?;
    let stripped = strip_utf8_bom(text);

    let parsed = match detected {
        DetectedImportFormat::Json => parse_plaintext_json(stripped)?,
        DetectedImportFormat::Csv => parse_bitwarden_csv(stripped)?,
        DetectedImportFormat::EncryptedJson | DetectedImportFormat::AccountEncryptedJson => {
            return Err(format!(
                "Detected format '{}' is encrypted; encrypted JSON import is not yet supported in this release.",
                detected.as_str()
            ));
        }
    };

    // Decrypt existing personal folders for UUID and verbatim name reconciliation.
    let mut existing_by_id: HashMap<String, String> = HashMap::new();
    let mut existing_by_name: HashMap<String, String> = HashMap::new();
    for f in &storage.folders {
        let Some(id) = f
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let name = decrypt_cipher_string(f.get("name").and_then(Value::as_str), user_key)
            .unwrap_or_default();
        existing_by_id.insert(id.to_string(), name.clone());
        if !name.is_empty() {
            existing_by_name
                .entry(name)
                .or_insert_with(|| id.to_string());
        }
    }

    let mut new_folder_names: Vec<String> = Vec::new();
    let mut new_folder_name_to_idx: HashMap<String, usize> = HashMap::new();
    let mut reused_folder_ids: HashSet<String> = HashSet::new();
    let mut cipher_assignments: Vec<FolderAssignment> = Vec::with_capacity(parsed.ciphers.len());

    if let Some(target_raw) = folder_override {
        let target = target_raw.trim();
        if target.is_empty() {
            return Err("Invalid --folder target: folder name or ID cannot be empty.".to_string());
        }
        if !parsed.ciphers.is_empty() {
            let assignment = if existing_by_id.contains_key(target) {
                reused_folder_ids.insert(target.to_string());
                FolderAssignment::ExistingUuid(target.to_string())
            } else if let Some(existing_id) = existing_by_name.get(target) {
                reused_folder_ids.insert(existing_id.clone());
                FolderAssignment::ExistingUuid(existing_id.clone())
            } else {
                new_folder_names.push(target.to_string());
                FolderAssignment::NewFolderIdx(0)
            };
            for _ in &parsed.ciphers {
                cipher_assignments.push(assignment.clone());
            }
        }
    } else {
        // Reconcile every imported folder: match by existing UUID first, then verbatim name.
        let mut imported_folder_resolution: Vec<FolderAssignment> =
            Vec::with_capacity(parsed.folders.len());
        for f in &parsed.folders {
            if let Some(ref sid) = f.source_id {
                if existing_by_id.contains_key(sid) {
                    reused_folder_ids.insert(sid.clone());
                    imported_folder_resolution.push(FolderAssignment::ExistingUuid(sid.clone()));
                    continue;
                }
            }
            if let Some(existing_id) = existing_by_name.get(&f.name) {
                reused_folder_ids.insert(existing_id.clone());
                imported_folder_resolution
                    .push(FolderAssignment::ExistingUuid(existing_id.clone()));
                continue;
            }
            let new_idx = if let Some(&idx) = new_folder_name_to_idx.get(&f.name) {
                idx
            } else {
                let idx = new_folder_names.len();
                new_folder_names.push(f.name.clone());
                new_folder_name_to_idx.insert(f.name.clone(), idx);
                idx
            };
            imported_folder_resolution.push(FolderAssignment::NewFolderIdx(new_idx));
        }

        for c in &parsed.ciphers {
            if let Some(fidx) = c.imported_folder_idx {
                cipher_assignments.push(imported_folder_resolution[fidx].clone());
            } else if let Some(ref raw_fid) = c.raw_folder_id {
                if existing_by_id.contains_key(raw_fid) {
                    reused_folder_ids.insert(raw_fid.clone());
                    cipher_assignments.push(FolderAssignment::ExistingUuid(raw_fid.clone()));
                } else {
                    cipher_assignments.push(FolderAssignment::None);
                }
            } else {
                cipher_assignments.push(FolderAssignment::None);
            }
        }
    }

    // Bitwarden Cloud batch-limit checks (> 7,000 ciphers or > 2,000 folders in payload)
    if parsed.ciphers.len() > BITWARDEN_CLOUD_MAX_CIPHERS {
        return Err(format!(
            "Import batch contains {} ciphers, exceeding the Bitwarden Cloud limit of {} ciphers per import.",
            parsed.ciphers.len(),
            BITWARDEN_CLOUD_MAX_CIPHERS
        ));
    }
    if new_folder_names.len() > BITWARDEN_CLOUD_MAX_FOLDERS {
        return Err(format!(
            "Import batch creates {} folders, exceeding the Bitwarden Cloud limit of {} folders per import.",
            new_folder_names.len(),
            BITWARDEN_CLOUD_MAX_FOLDERS
        ));
    }

    // Build encrypted POST /api/ciphers/import payload
    let mut enc_folders = Vec::with_capacity(new_folder_names.len());
    for fname in &new_folder_names {
        let enc_name = user_key
            .encrypt_string(fname)
            .map_err(|e| format!("Failed to encrypt folder name '{fname}': {e}"))?;
        enc_folders.push(json!({ "name": enc_name }));
    }

    let mut enc_ciphers = Vec::with_capacity(parsed.ciphers.len());
    let mut folder_relationships = Vec::new();
    let mut cipher_names = Vec::with_capacity(parsed.ciphers.len());

    for (cipher_idx, (cipher, assignment)) in parsed
        .ciphers
        .iter()
        .zip(cipher_assignments.iter())
        .enumerate()
    {
        let existing_folder_id = match assignment {
            FolderAssignment::ExistingUuid(uuid) => Some(uuid.as_str()),
            FolderAssignment::NewFolderIdx(folder_idx) => {
                folder_relationships.push(json!({
                    "key": cipher_idx,
                    "value": folder_idx,
                }));
                None
            }
            FolderAssignment::None => None,
        };
        enc_ciphers.push(encrypt_cipher_for_import(
            cipher,
            existing_folder_id,
            user_key,
        )?);
        cipher_names.push(cipher.name.clone());
    }

    let request_payload = json!({
        "folders": enc_folders,
        "ciphers": enc_ciphers,
        "folderRelationships": folder_relationships,
    });

    Ok(PlannedVaultImport {
        detected_format: detected,
        cipher_count: parsed.ciphers.len(),
        folders_reused: reused_folder_ids.len(),
        folders_created: new_folder_names.len(),
        skipped_unsupported: parsed.skipped_unsupported,
        warnings: parsed.warnings,
        cipher_names,
        request_payload,
    })
}

/// Parses Bitwarden / Vaultwarden server `validationErrors` (or `ValidationErrors`) from an
/// HTTP error response body and enriches cipher-indexed keys (e.g. `Ciphers[2].Notes`) with
/// the corresponding imported item name.
pub fn format_import_validation_errors(err_body: &str, cipher_names: &[String]) -> Option<String> {
    let parsed: Value = serde_json::from_str(err_body).ok()?;
    let val_errors = parsed
        .get("validationErrors")
        .or_else(|| parsed.get("ValidationErrors"))
        .and_then(Value::as_object)?;

    if val_errors.is_empty() {
        return None;
    }

    let mut details = Vec::new();
    for (key, msgs) in val_errors {
        let msg_text = match msgs {
            Value::Array(arr) => arr
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; "),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        if let Some(idx) = extract_cipher_index_from_validation_key(key) {
            let name = cipher_names
                .get(idx)
                .map(String::as_str)
                .unwrap_or("<unknown>");
            details.push(format!("item #{idx} ('{name}') [{key}]: {msg_text}"));
        } else {
            details.push(format!("{key}: {msg_text}"));
        }
    }

    let top_msg = parsed
        .get("message")
        .or_else(|| parsed.get("Message"))
        .and_then(Value::as_str);

    if let Some(msg) = top_msg {
        Some(format!(
            "Server rejected import ({msg}): {}",
            details.join(" | ")
        ))
    } else {
        Some(format!("Server rejected import: {}", details.join(" | ")))
    }
}

fn extract_cipher_index_from_validation_key(key: &str) -> Option<usize> {
    let lower = key.to_ascii_lowercase();
    let start = lower.find("ciphers[")? + "ciphers[".len();
    let rest = &lower[start..];
    let end = rest.find(']')?;
    rest[..end].parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::decrypt_cipher_string;
    use crate::vault_export::{export_personal_vault_csv, export_personal_vault_plaintext_json};

    fn test_user_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap()
    }

    fn empty_storage() -> VaultStorage {
        VaultStorage::default()
    }

    #[test]
    fn format_auto_detection_and_mismatch_rejection() {
        let json_doc = br#"{"encrypted":false,"folders":[],"items":[]}"#;
        assert_eq!(
            inspect_import_bytes(json_doc, VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::Json
        );
        assert_eq!(
            inspect_import_bytes(json_doc, VaultImportFormat::Json).unwrap(),
            DetectedImportFormat::Json
        );
        let err = inspect_import_bytes(json_doc, VaultImportFormat::Csv).unwrap_err();
        assert!(err.contains("Format mismatch"), "got: {err}");

        let csv_with_archived = b"folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp\n";
        assert_eq!(
            inspect_import_bytes(csv_with_archived, VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::Csv
        );

        // archivedDate is optional
        let csv_without_archived = b"\xEF\xBB\xBFfolder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n";
        assert_eq!(
            inspect_import_bytes(csv_without_archived, VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::Csv
        );
        let err = inspect_import_bytes(csv_without_archived, VaultImportFormat::Json).unwrap_err();
        assert!(err.contains("Format mismatch"), "got: {err}");

        // Encrypted formats are detected accurately and fail closed on --format json mismatch
        let enc_pw = br#"{"encrypted":true,"passwordProtected":true,"salt":"abc","kdfType":0,"kdfIterations":600000,"encKeyValidation_DO_NOT_EDIT":"x","data":"y"}"#;
        assert_eq!(
            inspect_import_bytes(enc_pw, VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::EncryptedJson
        );
        assert!(inspect_import_bytes(enc_pw, VaultImportFormat::Json).is_err());

        let enc_acct =
            br#"{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"x","folders":[],"items":[]}"#;
        assert_eq!(
            inspect_import_bytes(enc_acct, VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::AccountEncryptedJson
        );
    }

    #[test]
    fn enforces_50_mib_size_cap_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let big_path = dir.path().join("oversized.json");
        let file = fs::File::create(&big_path).unwrap();
        file.set_len(MAX_IMPORT_FILE_BYTES + 1).unwrap();

        let err = inspect_import_file(&big_path, VaultImportFormat::Auto).unwrap_err();
        assert!(err.contains("50 MiB"), "got: {err}");
    }

    #[test]
    fn ssh_key_fingerprint_fallback_and_non_empty_validation() {
        let key = test_user_key();
        let storage = empty_storage();

        // Fallback to `fingerprint` succeeds
        let valid_json = json!({
            "encrypted": false,
            "folders": [],
            "items": [{
                "type": 5,
                "name": "Deploy Key",
                "organizationId": "should-be-stripped",
                "sshKey": {
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
                    "publicKey": "ssh-ed25519 AAAA test@host",
                    "fingerprint": "SHA256:fallbackfp123"
                }
            }]
        });
        let raw = serde_json::to_vec(&valid_json).unwrap();
        let plan = plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Json, None)
            .unwrap();
        assert_eq!(plan.cipher_count, 1);
        let c = &plan.request_payload["ciphers"][0];
        assert!(c["organizationId"].is_null());
        assert_eq!(
            decrypt_cipher_string(c["sshKey"]["keyFingerprint"].as_str(), &key).as_deref(),
            Some("SHA256:fallbackfp123")
        );

        // Missing/empty field fails closed with exact item index and name
        let invalid_json = json!({
            "encrypted": false,
            "folders": [],
            "items": [
                { "type": 2, "name": "Valid Note", "secureNote": { "type": 0 } },
                {
                    "type": 5,
                    "name": "Broken SSH Key",
                    "sshKey": {
                        "privateKey": "priv",
                        "publicKey": "",
                        "keyFingerprint": "SHA256:fp"
                    }
                }
            ]
        });
        let raw_bad = serde_json::to_vec(&invalid_json).unwrap();
        let err =
            plan_personal_vault_import(&storage, &key, &raw_bad, VaultImportFormat::Json, None)
                .unwrap_err();
        assert!(err.contains("#1"), "expected index 1, got: {err}");
        assert!(
            err.contains("Broken SSH Key"),
            "expected item name, got: {err}"
        );
    }

    #[test]
    fn password_history_filters_null_empty_and_caps_at_5() {
        let key = test_user_key();
        let storage = empty_storage();

        let doc = json!({
            "encrypted": false,
            "folders": [],
            "items": [{
                "type": 1,
                "name": "History Login",
                "login": { "username": "u", "password": "p", "uris": [] },
                "passwordHistory": [
                    null,
                    { "password": "", "lastUsedDate": "2026-01-01T00:00:00Z" },
                    { "password": null, "lastUsedDate": "2026-01-01T00:00:00Z" },
                    { "password": "pw1", "lastUsedDate": "2026-01-01T00:00:00Z" },
                    { "password": "pw2", "lastUsedDate": "2026-01-02T00:00:00Z" },
                    { "password": "pw3", "lastUsedDate": "2026-01-03T00:00:00Z" },
                    { "password": "pw4", "lastUsedDate": "2026-01-04T00:00:00Z" },
                    { "password": "pw5", "lastUsedDate": "2026-01-05T00:00:00Z" },
                    { "password": "pw6", "lastUsedDate": "2026-01-06T00:00:00Z" }
                ]
            }]
        });
        let raw = serde_json::to_vec(&doc).unwrap();
        let plan = plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, None)
            .unwrap();
        let hist = plan.request_payload["ciphers"][0]["passwordHistory"]
            .as_array()
            .unwrap();
        assert_eq!(hist.len(), 5);
        assert_eq!(
            decrypt_cipher_string(hist[0]["password"].as_str(), &key).as_deref(),
            Some("pw1")
        );
        assert_eq!(
            decrypt_cipher_string(hist[4]["password"].as_str(), &key).as_deref(),
            Some("pw5")
        );
    }

    #[test]
    fn skips_types_6_to_8_with_warnings_and_rejects_malformed_types_1_to_5() {
        let key = test_user_key();
        let storage = empty_storage();

        let doc = json!({
            "encrypted": false,
            "folders": [],
            "items": [
                { "type": 1, "name": "Good Login", "login": { "username": "a", "password": "b", "uris": [] } },
                { "type": 6, "name": "My Bank Account" },
                { "type": 7, "name": "My License" },
                { "type": 8, "name": "My Passport" },
                { "type": 2, "name": "Good Note", "secureNote": { "type": 0 } }
            ]
        });
        let raw = serde_json::to_vec(&doc).unwrap();
        let plan = plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, None)
            .unwrap();
        assert_eq!(plan.cipher_count, 2);
        assert_eq!(plan.skipped_unsupported.len(), 3);
        assert_eq!(plan.warnings.len(), 1);
        assert!(plan.warnings[0].contains("3 unsupported"));
        assert!(plan.warnings[0].contains("My Bank Account"));
        assert!(plan.warnings[0].contains("My License"));
        assert!(plan.warnings[0].contains("My Passport"));

        // Malformed Type 3 (missing card object) fails closed for the entire batch
        let bad = json!({
            "encrypted": false,
            "folders": [],
            "items": [
                { "type": 1, "name": "Good Login", "login": { "username": "a" } },
                { "type": 3, "name": "Broken Card" }
            ]
        });
        let err = plan_personal_vault_import(
            &storage,
            &key,
            &serde_json::to_vec(&bad).unwrap(),
            VaultImportFormat::Auto,
            None,
        )
        .unwrap_err();
        assert!(err.contains("#1"), "got: {err}");
        assert!(err.contains("Broken Card"), "got: {err}");
    }

    #[test]
    fn folder_reconciliation_reuses_uuid_and_name_and_supports_override() {
        let key = test_user_key();
        let mut storage = empty_storage();
        storage.folders = vec![
            json!({ "id": "existing-uuid-1", "name": key.encrypt_string("Work").unwrap() }),
            json!({ "id": "existing-uuid-2", "name": key.encrypt_string("Personal").unwrap() }),
        ];

        let doc = json!({
            "encrypted": false,
            "folders": [
                { "id": "existing-uuid-1", "name": "Renamed In Export" },
                { "id": "different-uuid", "name": "Personal" },
                { "id": "brand-new-uuid", "name": "Travel" }
            ],
            "items": [
                { "type": 2, "name": "Item A", "folderId": "existing-uuid-1", "secureNote": { "type": 0 } },
                { "type": 2, "name": "Item B", "folderId": "different-uuid", "secureNote": { "type": 0 } },
                { "type": 2, "name": "Item C", "folderId": "brand-new-uuid", "secureNote": { "type": 0 } }
            ]
        });
        let raw = serde_json::to_vec(&doc).unwrap();
        let plan = plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, None)
            .unwrap();

        assert_eq!(plan.folders_reused, 2);
        assert_eq!(plan.folders_created, 1);
        assert_eq!(plan.request_payload["folders"].as_array().unwrap().len(), 1);
        assert_eq!(
            decrypt_cipher_string(plan.request_payload["folders"][0]["name"].as_str(), &key)
                .as_deref(),
            Some("Travel")
        );
        assert_eq!(
            plan.request_payload["ciphers"][0]["folderId"].as_str(),
            Some("existing-uuid-1")
        );
        assert_eq!(
            plan.request_payload["ciphers"][1]["folderId"].as_str(),
            Some("existing-uuid-2")
        );
        assert!(plan.request_payload["ciphers"][2]["folderId"].is_null());
        assert_eq!(
            plan.request_payload["folderRelationships"],
            json!([{ "key": 2, "value": 0 }])
        );

        // --folder override matching existing folder by name
        let plan_existing =
            plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, Some("Work"))
                .unwrap();
        assert_eq!(plan_existing.folders_reused, 1);
        assert_eq!(plan_existing.folders_created, 0);
        assert!(plan_existing.request_payload["folders"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(plan_existing.request_payload["folderRelationships"]
            .as_array()
            .unwrap()
            .is_empty());
        for c in plan_existing.request_payload["ciphers"].as_array().unwrap() {
            assert_eq!(c["folderId"].as_str(), Some("existing-uuid-1"));
        }

        // --folder override creating a new folder
        let plan_new = plan_personal_vault_import(
            &storage,
            &key,
            &raw,
            VaultImportFormat::Auto,
            Some("Quarantine"),
        )
        .unwrap();
        assert_eq!(plan_new.folders_reused, 0);
        assert_eq!(plan_new.folders_created, 1);
        assert_eq!(
            decrypt_cipher_string(
                plan_new.request_payload["folders"][0]["name"].as_str(),
                &key
            )
            .as_deref(),
            Some("Quarantine")
        );
        assert_eq!(
            plan_new.request_payload["folderRelationships"],
            json!([
                { "key": 0, "value": 0 },
                { "key": 1, "value": 0 },
                { "key": 2, "value": 0 }
            ])
        );
    }

    #[test]
    fn enforces_cloud_batch_limits() {
        let key = test_user_key();
        let storage = empty_storage();

        let many_ciphers: Vec<Value> = (0..=BITWARDEN_CLOUD_MAX_CIPHERS)
            .map(|i| json!({ "type": 2, "name": format!("N{i}"), "secureNote": { "type": 0 } }))
            .collect();
        let doc = json!({ "encrypted": false, "folders": [], "items": many_ciphers });
        let err = plan_personal_vault_import(
            &storage,
            &key,
            &serde_json::to_vec(&doc).unwrap(),
            VaultImportFormat::Json,
            None,
        )
        .unwrap_err();
        assert!(err.contains("7000"), "got: {err}");

        let many_folders: Vec<Value> = (0..=BITWARDEN_CLOUD_MAX_FOLDERS)
            .map(|i| json!({ "id": format!("f-{i}"), "name": format!("Folder {i}") }))
            .collect();
        let doc_f = json!({ "encrypted": false, "folders": many_folders, "items": [] });
        let err_f = plan_personal_vault_import(
            &storage,
            &key,
            &serde_json::to_vec(&doc_f).unwrap(),
            VaultImportFormat::Json,
            None,
        )
        .unwrap_err();
        assert!(err_f.contains("2000"), "got: {err_f}");
    }

    #[test]
    fn csv_parsing_edge_cases_and_round_trip() {
        let key = test_user_key();
        let storage = empty_storage();

        let csv_data = concat!(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
            "Work,1,login,\"GitHub, Inc.\",\"Line 1\nLine \"\"2\"\"\",\"Key: With: Colon: Val1\nSimple: Val2\",1,\"https://github.com,https://api.github.com\",octo,s3cr3t,JBSWY3DPEHPK3PXP\n",
            ",0,note,Recovery,\"My note\",\"\",0,,,,\n"
        );

        let plan = plan_personal_vault_import(
            &storage,
            &key,
            csv_data.as_bytes(),
            VaultImportFormat::Auto,
            None,
        )
        .unwrap();
        assert_eq!(plan.detected_format, DetectedImportFormat::Csv);
        assert_eq!(plan.cipher_count, 2);
        assert_eq!(plan.folders_created, 1);

        let c0 = &plan.request_payload["ciphers"][0];
        assert_eq!(c0["type"], 1);
        assert_eq!(c0["favorite"], true);
        assert_eq!(c0["reprompt"], 1);
        assert_eq!(
            decrypt_cipher_string(c0["name"].as_str(), &key).as_deref(),
            Some("GitHub, Inc.")
        );
        assert_eq!(
            decrypt_cipher_string(c0["notes"].as_str(), &key).as_deref(),
            Some("Line 1\nLine \"2\"")
        );
        let fields = c0["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(
            decrypt_cipher_string(fields[0]["name"].as_str(), &key).as_deref(),
            Some("Key: With: Colon")
        );
        assert_eq!(
            decrypt_cipher_string(fields[0]["value"].as_str(), &key).as_deref(),
            Some("Val1")
        );
        let uris = c0["login"]["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(
            decrypt_cipher_string(uris[1]["uri"].as_str(), &key).as_deref(),
            Some("https://api.github.com")
        );

        // Verify export -> import round-trip for both Plaintext JSON and CSV
        let mut exported_storage = empty_storage();
        exported_storage.folders =
            vec![json!({ "id": "f1", "name": key.encrypt_string("Work").unwrap() })];
        exported_storage.ciphers = vec![json!({
            "id": "c1",
            "organizationId": null,
            "folderId": "f1",
            "type": 1,
            "name": key.encrypt_string("RoundTrip").unwrap(),
            "notes": key.encrypt_string("Notes").unwrap(),
            "favorite": true,
            "reprompt": 0,
            "login": {
                "username": key.encrypt_string("alice").unwrap(),
                "password": key.encrypt_string("hunter2").unwrap(),
                "totp": key.encrypt_string("JBSWY3DPEHPK3PXP").unwrap(),
                "uris": [{ "uri": key.encrypt_string("https://example.com").unwrap(), "match": 0 }]
            }
        })];

        let json_export = export_personal_vault_plaintext_json(&exported_storage, &key).unwrap();
        let json_plan = plan_personal_vault_import(
            &empty_storage(),
            &key,
            json_export.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
        )
        .unwrap();
        assert_eq!(json_plan.cipher_count, 1);
        assert_eq!(json_plan.folders_created, 1);

        let csv_export = export_personal_vault_csv(&exported_storage, &key).unwrap();
        let csv_plan = plan_personal_vault_import(
            &empty_storage(),
            &key,
            csv_export.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
        )
        .unwrap();
        assert_eq!(csv_plan.cipher_count, 1);
        assert_eq!(csv_plan.folders_created, 1);
    }

    #[test]
    fn formats_server_validation_errors_with_item_index_and_name() {
        let body = r#"{
            "message": "The model state is invalid.",
            "validationErrors": {
                "Ciphers[1].Notes": ["The field Notes must be a string with a maximum length of 10000."]
            }
        }"#;
        let names = vec!["First Item".to_string(), "Oversized Note".to_string()];
        let formatted = format_import_validation_errors(body, &names).unwrap();
        assert!(
            formatted.contains("item #1 ('Oversized Note')"),
            "got: {formatted}"
        );
        assert!(
            formatted.contains("maximum length of 10000"),
            "got: {formatted}"
        );
    }
}
