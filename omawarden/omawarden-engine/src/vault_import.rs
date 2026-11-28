use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::api::decrypt_cipher_string;
use crate::crypto::{
    derive_export_key, parse_symmetric_key_from_decrypted_bytes, CryptoError, EncString,
    ExportKdfConfig, SymmetricCryptoKey, ARGON2_EXPORT_MAX_ITERATIONS, ARGON2_EXPORT_MAX_MEMORY_MB,
    ARGON2_EXPORT_MAX_PARALLELISM, ARGON2_EXPORT_MIN_ITERATIONS, ARGON2_EXPORT_MIN_MEMORY_MB,
    ARGON2_EXPORT_MIN_PARALLELISM, PBKDF2_EXPORT_MAX_ITERATIONS, PBKDF2_EXPORT_MIN_ITERATIONS,
};
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

    let mut parsed_json_doc: Option<Value> = None;
    let detected = if trimmed.starts_with('{') {
        let doc: Value = serde_json::from_str(stripped)
            .map_err(|e| format!("Invalid JSON syntax in import file: {e}"))?;
        let obj = doc.as_object().ok_or_else(|| {
            "Invalid JSON import file: top-level value must be a JSON object.".to_string()
        })?;
        let d = match obj.get("encrypted").and_then(Value::as_bool) {
            Some(true) => {
                let password_protected = match obj.get("passwordProtected") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => {
                        return Err(
                            "Invalid encrypted JSON import file: 'passwordProtected' must be a boolean."
                                .to_string(),
                        )
                    }
                };
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
        };
        parsed_json_doc = Some(doc);
        d
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

    if let Some(obj) = parsed_json_doc.as_ref().and_then(Value::as_object) {
        match detected {
            DetectedImportFormat::EncryptedJson => {
                validate_password_protected_preflight(obj)?;
            }
            DetectedImportFormat::AccountEncryptedJson => {
                validate_account_encrypted_v1_preflight(obj)?;
            }
            DetectedImportFormat::Json | DetectedImportFormat::Csv => {}
        }
    }

    Ok(detected)
}

fn is_cose_enc_string(raw: &str) -> bool {
    raw.trim_start().starts_with("7.")
}

fn v2_cose_unsupported_error(detail: &str) -> String {
    format!(
        "Unsupported export format: V2 Account-Restricted COSE exports ({detail}) are not supported. Re-export using Password-Protected Encrypted JSON or V1 Account-Restricted Encrypted JSON."
    )
}

fn parse_strict_u32(obj: &Map<String, Value>, key: &str) -> Result<u32, String> {
    let val = obj.get(key).ok_or_else(|| {
        format!("Invalid encrypted_json export: missing required integer '{key}'.")
    })?;
    let n = val.as_u64().ok_or_else(|| {
        format!("Invalid encrypted_json export: '{key}' must be a non-negative integer.")
    })?;
    u32::try_from(n).map_err(|_| {
        format!("Invalid encrypted_json export: '{key}' value {n} is out of allowed range.")
    })
}

fn parse_and_validate_export_kdf(obj: &Map<String, Value>) -> Result<ExportKdfConfig, String> {
    let kdf_type = parse_strict_u32(obj, "kdfType")?;
    let config = match kdf_type {
        0 => {
            let iterations = parse_strict_u32(obj, "kdfIterations")?;
            if !(PBKDF2_EXPORT_MIN_ITERATIONS..=PBKDF2_EXPORT_MAX_ITERATIONS).contains(&iterations)
            {
                return Err(format!(
                    "Invalid PBKDF2 kdfIterations ({iterations}): must be an integer between {PBKDF2_EXPORT_MIN_ITERATIONS} and {PBKDF2_EXPORT_MAX_ITERATIONS}."
                ));
            }
            ExportKdfConfig::Pbkdf2Sha256 { iterations }
        }
        1 => {
            let iterations = parse_strict_u32(obj, "kdfIterations")?;
            if !(ARGON2_EXPORT_MIN_ITERATIONS..=ARGON2_EXPORT_MAX_ITERATIONS).contains(&iterations)
            {
                return Err(format!(
                    "Invalid Argon2id kdfIterations ({iterations}): must be an integer between {ARGON2_EXPORT_MIN_ITERATIONS} and {ARGON2_EXPORT_MAX_ITERATIONS}."
                ));
            }
            let memory_mb = parse_strict_u32(obj, "kdfMemory")?;
            if !(ARGON2_EXPORT_MIN_MEMORY_MB..=ARGON2_EXPORT_MAX_MEMORY_MB).contains(&memory_mb) {
                return Err(format!(
                    "Invalid Argon2id kdfMemory ({memory_mb} MiB): must be an integer between {ARGON2_EXPORT_MIN_MEMORY_MB} and {ARGON2_EXPORT_MAX_MEMORY_MB} MiB."
                ));
            }
            let parallelism = parse_strict_u32(obj, "kdfParallelism")?;
            if !(ARGON2_EXPORT_MIN_PARALLELISM..=ARGON2_EXPORT_MAX_PARALLELISM)
                .contains(&parallelism)
            {
                return Err(format!(
                    "Invalid Argon2id kdfParallelism ({parallelism}): must be an integer between {ARGON2_EXPORT_MIN_PARALLELISM} and {ARGON2_EXPORT_MAX_PARALLELISM}."
                ));
            }
            ExportKdfConfig::Argon2id {
                iterations,
                memory_mb,
                parallelism,
            }
        }
        other => {
            return Err(format!(
                "Unsupported encrypted_json kdfType ({other}): expected 0 (PBKDF2-HMAC-SHA256) or 1 (Argon2id)."
            ));
        }
    };

    config
        .validate()
        .map_err(|e| format!("Invalid encrypted_json KDF parameters: {e}"))?;
    Ok(config)
}

fn validate_password_protected_preflight(
    obj: &Map<String, Value>,
) -> Result<ExportKdfConfig, String> {
    let kdf = parse_and_validate_export_kdf(obj)?;

    for req_field in ["salt", "encKeyValidation_DO_NOT_EDIT", "data"] {
        let present = obj
            .get(req_field)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if !present {
            return Err(format!(
                "Invalid encrypted_json export: missing or empty required string '{req_field}'."
            ));
        }
    }

    Ok(kdf)
}

fn validate_account_encrypted_v1_preflight(obj: &Map<String, Value>) -> Result<(), String> {
    if let Some(validation) = obj
        .get("encKeyValidation_DO_NOT_EDIT")
        .and_then(Value::as_str)
    {
        if is_cose_enc_string(validation) {
            return Err(v2_cose_unsupported_error(
                "enc_type = 7 on encKeyValidation_DO_NOT_EDIT",
            ));
        }
    }

    if let Some(data_val) = obj.get("data").filter(|v| !v.is_null()) {
        match data_val {
            Value::String(s) => {
                if is_cose_enc_string(s) {
                    return Err(v2_cose_unsupported_error("enc_type = 7 sealed blob data"));
                }
                if s.contains("\"format_version\"") || s.contains("format_version") {
                    return Err(v2_cose_unsupported_error(
                        "sealed blob data containing format_version",
                    ));
                }
                if !obj.contains_key("items") {
                    return Err(v2_cose_unsupported_error("sealed blob data"));
                }
            }
            Value::Object(map) => {
                if map.contains_key("format_version") || !obj.contains_key("items") {
                    return Err(v2_cose_unsupported_error(
                        "sealed blob data containing format_version",
                    ));
                }
            }
            _ => {
                if !obj.contains_key("items") {
                    return Err(v2_cose_unsupported_error("sealed blob data"));
                }
            }
        }
    }

    if let Some(folders) = obj.get("folders").and_then(Value::as_array) {
        for (idx, f) in folders.iter().enumerate() {
            if let Some(name) = f.get("name").and_then(Value::as_str) {
                if is_cose_enc_string(name) {
                    return Err(v2_cose_unsupported_error(&format!(
                        "enc_type = 7 on folder #{idx} name"
                    )));
                }
            }
        }
    }

    if let Some(items) = obj.get("items").and_then(Value::as_array) {
        for (idx, item) in items.iter().enumerate() {
            if let Some(key) = item.get("key").and_then(Value::as_str) {
                if is_cose_enc_string(key) {
                    return Err(v2_cose_unsupported_error(&format!(
                        "enc_type = 7 on cipher #{idx} key"
                    )));
                }
            }
            if let Some(name) = item.get("name").and_then(Value::as_str) {
                if is_cose_enc_string(name) {
                    return Err(v2_cose_unsupported_error(&format!(
                        "enc_type = 7 on cipher #{idx} name"
                    )));
                }
            }
        }
    }

    let has_validation = obj
        .get("encKeyValidation_DO_NOT_EDIT")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !has_validation {
        return Err(
            "Invalid account_encrypted_json export: missing or empty 'encKeyValidation_DO_NOT_EDIT'."
                .to_string(),
        );
    }

    if !obj.get("items").is_some_and(Value::is_array) {
        return Err(
            "Invalid account_encrypted_json export: missing or invalid 'items' array.".to_string(),
        );
    }

    Ok(())
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

fn decrypt_authenticated_bytes(
    raw: &str,
    key: &SymmetricCryptoKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let enc = EncString::parse(raw)?;
    if enc.enc_type != 2 {
        return Err(CryptoError::UnsupportedCipherType(enc.enc_type));
    }
    enc.decrypt(key).map(Zeroizing::new)
}

fn decrypt_authenticated_string(
    raw: &str,
    key: &SymmetricCryptoKey,
) -> Result<Zeroizing<String>, CryptoError> {
    let mut bytes = decrypt_authenticated_bytes(raw, key)?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            let mut bad = e.into_bytes();
            bad.zeroize();
            Err(CryptoError::Utf8Error)
        }
    }
}

fn decrypt_opt_enc_str(
    obj: &Map<String, Value>,
    field: &str,
    cipher_key: &SymmetricCryptoKey,
    ctx: &str,
) -> Result<Option<String>, String> {
    match obj.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.is_empty() {
                return Ok(None);
            }
            if is_cose_enc_string(s) {
                return Err(v2_cose_unsupported_error(&format!(
                    "enc_type = 7 on {ctx}.{field}"
                )));
            }
            let decrypted = decrypt_authenticated_string(s, cipher_key)
                .map_err(|e| format!("Failed to decrypt {ctx} field '{field}': {e}"))?;
            if decrypted.is_empty() {
                Ok(None)
            } else {
                Ok(Some(decrypted.as_str().to_string()))
            }
        }
        Some(_) => Err(format!(
            "Malformed {ctx}: field '{field}' must be an encrypted string or null."
        )),
    }
}

fn parse_password_protected_encrypted_json(
    content: &str,
    import_password: Option<&str>,
) -> Result<ParsedImportData, String> {
    let doc: Value = serde_json::from_str(content)
        .map_err(|e| format!("Invalid JSON syntax in import file: {e}"))?;
    let obj = doc.as_object().ok_or_else(|| {
        "Invalid JSON import file: top-level value must be a JSON object.".to_string()
    })?;

    let kdf_config = validate_password_protected_preflight(obj)?;

    let password = import_password.filter(|s| !s.is_empty()).ok_or_else(|| {
        "Import password is required for password-protected encrypted_json import.".to_string()
    })?;

    let salt = obj
        .get("salt")
        .and_then(Value::as_str)
        .ok_or_else(|| "Invalid encrypted_json export: missing 'salt'.".to_string())?;
    let enc_validation = obj
        .get("encKeyValidation_DO_NOT_EDIT")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "Invalid encrypted_json export: missing 'encKeyValidation_DO_NOT_EDIT'.".to_string()
        })?;
    let enc_data = obj
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| "Invalid encrypted_json export: missing 'data'.".to_string())?;

    let mut derived_key = derive_export_key(password, salt, &kdf_config)
        .map_err(|e| format!("Failed to derive import decryption key: {e}"))?;

    let validation_res = decrypt_authenticated_string(enc_validation, &derived_key);
    if let Err(err) = validation_res {
        derived_key.zeroize();
        return Err(match err {
            CryptoError::MacMismatch | CryptoError::DecryptionFailed(_) => {
                "Invalid import password: key validation failed (MAC mismatch).".to_string()
            }
            other => format!(
                "Invalid import password: failed to validate 'encKeyValidation_DO_NOT_EDIT': {other}"
            ),
        });
    }

    let plaintext_json = decrypt_authenticated_string(enc_data, &derived_key)
        .map_err(|e| format!("Failed to decrypt encrypted_json payload: {e}"));
    derived_key.zeroize();
    let plaintext_json = plaintext_json?;

    parse_plaintext_json(plaintext_json.as_str())
}

fn resolve_account_export_item_key(
    iobj: &Map<String, Value>,
    user_key: &SymmetricCryptoKey,
    ctx: &str,
) -> Result<SymmetricCryptoKey, String> {
    match iobj.get("key") {
        None | Some(Value::Null) => Ok(user_key.clone()),
        Some(Value::String(s)) if s.is_empty() => Ok(user_key.clone()),
        Some(Value::String(enc_key_str)) => {
            if is_cose_enc_string(enc_key_str) {
                return Err(v2_cose_unsupported_error(&format!(
                    "enc_type = 7 on {ctx} key"
                )));
            }
            let raw_bytes = decrypt_authenticated_bytes(enc_key_str, user_key)
                .map_err(|e| format!("Failed to decrypt per-item key for {ctx}: {e}"))?;
            parse_symmetric_key_from_decrypted_bytes(raw_bytes.as_slice())
                .ok_or_else(|| format!("Invalid symmetric key length for per-item key on {ctx}."))
        }
        Some(_) => Err(format!(
            "Malformed {ctx}: field 'key' must be an encrypted string or null."
        )),
    }
}

fn parse_account_encrypted_json_v1(
    content: &str,
    user_key: &SymmetricCryptoKey,
) -> Result<ParsedImportData, String> {
    let doc: Value = serde_json::from_str(content)
        .map_err(|e| format!("Invalid JSON syntax in import file: {e}"))?;
    let obj = doc.as_object().ok_or_else(|| {
        "Invalid JSON import file: top-level value must be a JSON object.".to_string()
    })?;

    validate_account_encrypted_v1_preflight(obj)?;

    let enc_validation = obj
        .get("encKeyValidation_DO_NOT_EDIT")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "Invalid account_encrypted_json export: missing 'encKeyValidation_DO_NOT_EDIT'."
                .to_string()
        })?;
    if decrypt_authenticated_string(enc_validation, user_key).is_err() {
        return Err(
            "Account key validation failed: this account-restricted export belongs to a different Bitwarden account or encryption key."
                .to_string(),
        );
    }

    let mut folders = Vec::new();
    let mut folder_id_to_idx: HashMap<String, usize> = HashMap::new();

    if let Some(folders_val) = obj.get("folders") {
        if !folders_val.is_null() {
            let arr = folders_val.as_array().ok_or_else(|| {
                "Invalid account_encrypted_json import file: 'folders' must be an array."
                    .to_string()
            })?;
            for (idx, f) in arr.iter().enumerate() {
                let fobj = f
                    .as_object()
                    .ok_or_else(|| format!("Malformed folder #{idx}: expected a JSON object."))?;
                let fctx = format!("folder #{idx}");
                let name = decrypt_opt_enc_str(fobj, "name", user_key, &fctx)?
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| format!("Malformed {fctx}: missing or empty 'name'."))?;
                let source_id = opt_non_empty_str(fobj, "id", &fctx)?;
                let folder_idx = folders.len();
                if let Some(ref sid) = source_id {
                    folder_id_to_idx.entry(sid.clone()).or_insert(folder_idx);
                }
                folders.push(NormalizedFolder { source_id, name });
            }
        }
    }

    let items_arr = obj.get("items").and_then(Value::as_array).ok_or_else(|| {
        "Invalid account_encrypted_json import file: missing or invalid 'items' array.".to_string()
    })?;

    let mut ciphers = Vec::new();
    let mut skipped_unsupported = Vec::new();

    for (idx, item) in items_arr.iter().enumerate() {
        let Some(iobj) = item.as_object() else {
            return Err(format!(
                "Malformed {}: expected a JSON object.",
                cipher_label(idx, None)
            ));
        };

        let raw_ctx = cipher_label(idx, None);
        let cipher_type = iobj
            .get("type")
            .and_then(Value::as_i64)
            .ok_or_else(|| format!("Malformed {raw_ctx}: missing or non-integer 'type'."))?;

        // Unsupported newer Bitwarden cipher types (6: Bank Account, 7: Driver's License, 8: Passport)
        if matches!(cipher_type, 6..=8) {
            let skipped_name = resolve_account_export_item_key(iobj, user_key, &raw_ctx)
                .ok()
                .and_then(|ck| {
                    decrypt_opt_enc_str(iobj, "name", &ck, &raw_ctx)
                        .ok()
                        .flatten()
                })
                .unwrap_or_else(|| "<unnamed>".to_string());
            skipped_unsupported.push(SkippedUnsupportedCipher {
                index: idx,
                name: skipped_name,
                cipher_type,
            });
            continue;
        }

        if !matches!(cipher_type, 1..=5) {
            return Err(format!(
                "Malformed {raw_ctx}: unsupported cipher type {cipher_type} (expected 1-5)."
            ));
        }

        let mut cipher_key = resolve_account_export_item_key(iobj, user_key, &raw_ctx)?;
        let dec_name = decrypt_opt_enc_str(iobj, "name", &cipher_key, &raw_ctx)?;
        let label = cipher_label(idx, dec_name.as_deref());
        let name = dec_name
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| format!("Malformed {label}: missing or empty 'name'."))?;

        let notes = decrypt_opt_enc_str(iobj, "notes", &cipher_key, &label)?;
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
                        name: decrypt_opt_enc_str(fobj, "name", &cipher_key, &label)?,
                        value: decrypt_opt_enc_str(fobj, "value", &cipher_key, &label)?,
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
                    let Some(pw) = decrypt_opt_enc_str(hobj, "password", &cipher_key, &label)?
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
                        password: pw,
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
                                uri: decrypt_opt_enc_str(uobj, "uri", &cipher_key, &label)?,
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
                                credential_id: decrypt_opt_enc_str(
                                    fobj,
                                    "credentialId",
                                    &cipher_key,
                                    &label,
                                )?,
                                key_type: decrypt_opt_enc_str(
                                    fobj,
                                    "keyType",
                                    &cipher_key,
                                    &label,
                                )?,
                                key_algorithm: decrypt_opt_enc_str(
                                    fobj,
                                    "keyAlgorithm",
                                    &cipher_key,
                                    &label,
                                )?,
                                key_curve: decrypt_opt_enc_str(
                                    fobj,
                                    "keyCurve",
                                    &cipher_key,
                                    &label,
                                )?,
                                key_value: decrypt_opt_enc_str(
                                    fobj,
                                    "keyValue",
                                    &cipher_key,
                                    &label,
                                )?,
                                rp_id: decrypt_opt_enc_str(fobj, "rpId", &cipher_key, &label)?,
                                user_handle: decrypt_opt_enc_str(
                                    fobj,
                                    "userHandle",
                                    &cipher_key,
                                    &label,
                                )?,
                                user_name: decrypt_opt_enc_str(
                                    fobj,
                                    "userName",
                                    &cipher_key,
                                    &label,
                                )?,
                                counter: decrypt_opt_enc_str(fobj, "counter", &cipher_key, &label)?,
                                rp_name: decrypt_opt_enc_str(fobj, "rpName", &cipher_key, &label)?,
                                user_display_name: decrypt_opt_enc_str(
                                    fobj,
                                    "userDisplayName",
                                    &cipher_key,
                                    &label,
                                )?,
                                discoverable: decrypt_opt_enc_str(
                                    fobj,
                                    "discoverable",
                                    &cipher_key,
                                    &label,
                                )?,
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
                        ));
                    }
                };

                login = Some(NormalizedLogin {
                    username: decrypt_opt_enc_str(lobj, "username", &cipher_key, &label)?,
                    password: decrypt_opt_enc_str(lobj, "password", &cipher_key, &label)?,
                    totp: decrypt_opt_enc_str(lobj, "totp", &cipher_key, &label)?,
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
                    cardholder_name: decrypt_opt_enc_str(
                        cobj,
                        "cardholderName",
                        &cipher_key,
                        &label,
                    )?,
                    brand: decrypt_opt_enc_str(cobj, "brand", &cipher_key, &label)?,
                    number: decrypt_opt_enc_str(cobj, "number", &cipher_key, &label)?,
                    exp_month: decrypt_opt_enc_str(cobj, "expMonth", &cipher_key, &label)?,
                    exp_year: decrypt_opt_enc_str(cobj, "expYear", &cipher_key, &label)?,
                    code: decrypt_opt_enc_str(cobj, "code", &cipher_key, &label)?,
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
                    title: decrypt_opt_enc_str(idobj, "title", &cipher_key, &label)?,
                    first_name: decrypt_opt_enc_str(idobj, "firstName", &cipher_key, &label)?,
                    middle_name: decrypt_opt_enc_str(idobj, "middleName", &cipher_key, &label)?,
                    last_name: decrypt_opt_enc_str(idobj, "lastName", &cipher_key, &label)?,
                    address1: decrypt_opt_enc_str(idobj, "address1", &cipher_key, &label)?,
                    address2: decrypt_opt_enc_str(idobj, "address2", &cipher_key, &label)?,
                    address3: decrypt_opt_enc_str(idobj, "address3", &cipher_key, &label)?,
                    city: decrypt_opt_enc_str(idobj, "city", &cipher_key, &label)?,
                    state: decrypt_opt_enc_str(idobj, "state", &cipher_key, &label)?,
                    postal_code: decrypt_opt_enc_str(idobj, "postalCode", &cipher_key, &label)?,
                    country: decrypt_opt_enc_str(idobj, "country", &cipher_key, &label)?,
                    company: decrypt_opt_enc_str(idobj, "company", &cipher_key, &label)?,
                    email: decrypt_opt_enc_str(idobj, "email", &cipher_key, &label)?,
                    phone: decrypt_opt_enc_str(idobj, "phone", &cipher_key, &label)?,
                    ssn: decrypt_opt_enc_str(idobj, "ssn", &cipher_key, &label)?,
                    username: decrypt_opt_enc_str(idobj, "username", &cipher_key, &label)?,
                    passport_number: decrypt_opt_enc_str(
                        idobj,
                        "passportNumber",
                        &cipher_key,
                        &label,
                    )?,
                    license_number: decrypt_opt_enc_str(
                        idobj,
                        "licenseNumber",
                        &cipher_key,
                        &label,
                    )?,
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
                let private_key =
                    decrypt_opt_enc_str(sobj, "privateKey", &cipher_key, &label)?.ok_or_else(
                        || {
                            format!(
                                "Malformed {label}: SSH Key cipher requires non-empty 'privateKey', 'publicKey', and 'keyFingerprint'."
                            )
                        },
                    )?;
                let public_key =
                    decrypt_opt_enc_str(sobj, "publicKey", &cipher_key, &label)?.ok_or_else(
                        || {
                            format!(
                                "Malformed {label}: SSH Key cipher requires non-empty 'privateKey', 'publicKey', and 'keyFingerprint'."
                            )
                        },
                    )?;
                let key_fingerprint =
                    decrypt_opt_enc_str(sobj, "keyFingerprint", &cipher_key, &label)?
                        .or(decrypt_opt_enc_str(sobj, "fingerprint", &cipher_key, &label)?)
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

        cipher_key.zeroize();

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

/// Validates, normalizes, reconciles Folders, checks Bitwarden Cloud batch limits, and
/// builds the encrypted `POST /api/ciphers/import` payload strictly inside the engine.
pub fn plan_personal_vault_import(
    storage: &VaultStorage,
    user_key: &SymmetricCryptoKey,
    raw_bytes: &[u8],
    requested_format: VaultImportFormat,
    folder_override: Option<&str>,
    import_password: Option<&str>,
) -> Result<PlannedVaultImport, String> {
    let detected = inspect_import_bytes(raw_bytes, requested_format)?;

    let text = std::str::from_utf8(raw_bytes)
        .map_err(|_| "Import file is not valid UTF-8.".to_string())?;
    let stripped = strip_utf8_bom(text);

    if detected != DetectedImportFormat::EncryptedJson && import_password.is_some() {
        return Err(format!(
            "Import password is not used for {} import.",
            detected.as_str()
        ));
    }

    let parsed = match detected {
        DetectedImportFormat::Json => parse_plaintext_json(stripped)?,
        DetectedImportFormat::Csv => parse_bitwarden_csv(stripped)?,
        DetectedImportFormat::EncryptedJson => {
            parse_password_protected_encrypted_json(stripped, import_password)?
        }
        DetectedImportFormat::AccountEncryptedJson => {
            parse_account_encrypted_json_v1(stripped, user_key)?
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
    use crate::vault_export::{
        export_personal_vault_account_encrypted_json, export_personal_vault_csv,
        export_personal_vault_encrypted_json, export_personal_vault_plaintext_json,
    };

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
        let plan =
            plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Json, None, None)
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
        let err = plan_personal_vault_import(
            &storage,
            &key,
            &raw_bad,
            VaultImportFormat::Json,
            None,
            None,
        )
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
        let plan =
            plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, None, None)
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
        let plan =
            plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, None, None)
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
        let plan =
            plan_personal_vault_import(&storage, &key, &raw, VaultImportFormat::Auto, None, None)
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
        let plan_existing = plan_personal_vault_import(
            &storage,
            &key,
            &raw,
            VaultImportFormat::Auto,
            Some("Work"),
            None,
        )
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
            None,
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

    #[test]
    fn enforces_pre_kdf_dos_bounds_fail_closed() {
        let make_pbkdf2 = |iters: Value| {
            serde_json::to_vec(&json!({
                "encrypted": true,
                "passwordProtected": true,
                "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                "kdfType": 0,
                "kdfIterations": iters,
                "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
                "data": "2.iv|ct|mac"
            }))
            .unwrap()
        };

        // PBKDF2 valid boundaries: 5,000 and 2,000,000
        assert_eq!(
            inspect_import_bytes(&make_pbkdf2(json!(5_000)), VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::EncryptedJson
        );
        assert_eq!(
            inspect_import_bytes(&make_pbkdf2(json!(2_000_000)), VaultImportFormat::Auto).unwrap(),
            DetectedImportFormat::EncryptedJson
        );

        // PBKDF2 out-of-bounds & non-integer rejected fail-closed
        for bad in [
            json!(4_999),
            json!(2_000_001),
            json!(0),
            json!(-1),
            json!(600_000.5),
            json!("600000"),
            json!(null),
        ] {
            let err = inspect_import_bytes(&make_pbkdf2(bad.clone()), VaultImportFormat::Auto)
                .unwrap_err();
            assert!(
                err.contains("kdfIterations") || err.contains("PBKDF2"),
                "expected PBKDF2 KDF error for {bad}, got: {err}"
            );
        }

        let make_argon2 = |iters: Value, mem: Value, par: Value| {
            serde_json::to_vec(&json!({
                "encrypted": true,
                "passwordProtected": true,
                "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                "kdfType": 1,
                "kdfIterations": iters,
                "kdfMemory": mem,
                "kdfParallelism": par,
                "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
                "data": "2.iv|ct|mac"
            }))
            .unwrap()
        };

        // Argon2id valid boundaries
        assert_eq!(
            inspect_import_bytes(
                &make_argon2(json!(2), json!(16), json!(1)),
                VaultImportFormat::Auto
            )
            .unwrap(),
            DetectedImportFormat::EncryptedJson
        );
        assert_eq!(
            inspect_import_bytes(
                &make_argon2(json!(10), json!(1_024), json!(16)),
                VaultImportFormat::Auto
            )
            .unwrap(),
            DetectedImportFormat::EncryptedJson
        );

        // Argon2id out-of-bounds & non-integer rejected fail-closed
        let bad_argon2_cases = [
            (json!(1), json!(64), json!(4)),
            (json!(11), json!(64), json!(4)),
            (json!(3.5), json!(64), json!(4)),
            (json!(3), json!(15), json!(4)),
            (json!(3), json!(1_025), json!(4)),
            (json!(3), json!("64"), json!(4)),
            (json!(3), json!(64), json!(0)),
            (json!(3), json!(64), json!(17)),
            (json!(3), json!(64), json!(null)),
        ];
        for (i, m, p) in bad_argon2_cases {
            let err = inspect_import_bytes(
                &make_argon2(i.clone(), m.clone(), p.clone()),
                VaultImportFormat::Auto,
            )
            .unwrap_err();
            assert!(
                err.contains("Argon2id") || err.contains("kdf"),
                "expected Argon2id KDF error for ({i}, {m}, {p}), got: {err}"
            );
        }

        // Unsupported kdfType
        let bad_type = serde_json::to_vec(&json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "kdfType": 2,
            "kdfIterations": 600_000,
            "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
            "data": "2.iv|ct|mac"
        }))
        .unwrap();
        let err = inspect_import_bytes(&bad_type, VaultImportFormat::Auto).unwrap_err();
        assert!(err.contains("kdfType"), "got: {err}");
    }

    #[test]
    fn rejects_v2_account_restricted_cose_exports_fail_closed() {
        // 1. enc_type = 7 on encKeyValidation_DO_NOT_EDIT
        let v2_validation = serde_json::to_vec(&json!({
            "encrypted": true,
            "encKeyValidation_DO_NOT_EDIT": "7.hEShAQ==",
            "folders": [],
            "items": []
        }))
        .unwrap();
        let err = inspect_import_bytes(&v2_validation, VaultImportFormat::Auto).unwrap_err();
        assert!(
            err.contains("V2") && err.contains("COSE"),
            "expected V2 COSE error, got: {err}"
        );

        // 2. enc_type = 7 on folder name
        let v2_folder = serde_json::to_vec(&json!({
            "encrypted": true,
            "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
            "folders": [{ "id": "f1", "name": "7.hEShAQ==" }],
            "items": []
        }))
        .unwrap();
        let err = inspect_import_bytes(&v2_folder, VaultImportFormat::Auto).unwrap_err();
        assert!(
            err.contains("V2") && err.contains("COSE"),
            "expected V2 COSE error, got: {err}"
        );

        // 3. enc_type = 7 on cipher key
        let v2_cipher_key = serde_json::to_vec(&json!({
            "encrypted": true,
            "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
            "folders": [],
            "items": [{
                "type": 2,
                "name": "2.iv|ct|mac",
                "key": "7.hEShAQ=="
            }]
        }))
        .unwrap();
        let err = inspect_import_bytes(&v2_cipher_key, VaultImportFormat::Auto).unwrap_err();
        assert!(
            err.contains("V2") && err.contains("COSE"),
            "expected V2 COSE error, got: {err}"
        );

        // 4. Sealed blob `data` containing "format_version"
        let v2_blob_str = serde_json::to_vec(&json!({
            "encrypted": true,
            "encKeyValidation_DO_NOT_EDIT": "2.iv|ct|mac",
            "data": "{\"format_version\":2,\"cose\":\"7.abc\"}"
        }))
        .unwrap();
        let err = inspect_import_bytes(&v2_blob_str, VaultImportFormat::Auto).unwrap_err();
        assert!(
            err.contains("V2") && err.contains("COSE"),
            "expected V2 COSE error, got: {err}"
        );

        let v2_blob_obj = serde_json::to_vec(&json!({
            "encrypted": true,
            "data": { "format_version": 2 }
        }))
        .unwrap();
        let err = inspect_import_bytes(&v2_blob_obj, VaultImportFormat::Auto).unwrap_err();
        assert!(
            err.contains("V2") && err.contains("COSE"),
            "expected V2 COSE error, got: {err}"
        );
    }

    #[test]
    fn encrypted_json_pbkdf2_and_argon2id_import_round_trip_and_wrong_password() {
        let key = test_user_key();
        let mut src_storage = empty_storage();
        src_storage.kdf = Some(0);
        src_storage.kdf_iterations = Some(5_000);
        src_storage.folders =
            vec![json!({ "id": "f1", "name": key.encrypt_string("Work").unwrap() })];
        src_storage.ciphers = vec![
            json!({
                "id": "c1",
                "organizationId": null,
                "folderId": "f1",
                "type": 1,
                "name": key.encrypt_string("Encrypted Login").unwrap(),
                "notes": key.encrypt_string("Secret note").unwrap(),
                "favorite": true,
                "reprompt": 1,
                "login": {
                    "username": key.encrypt_string("alice").unwrap(),
                    "password": key.encrypt_string("correct-horse-battery").unwrap(),
                    "totp": key.encrypt_string("JBSWY3DPEHPK3PXP").unwrap(),
                    "uris": [{ "uri": key.encrypt_string("https://example.com").unwrap(), "match": 0 }]
                }
            }),
            json!({
                "id": "c2",
                "organizationId": null,
                "folderId": null,
                "type": 5,
                "name": key.encrypt_string("SSH Prod").unwrap(),
                "favorite": false,
                "reprompt": 0,
                "sshKey": {
                    "privateKey": key.encrypt_string("-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----").unwrap(),
                    "publicKey": key.encrypt_string("ssh-ed25519 AAAA user@host").unwrap(),
                    "keyFingerprint": key.encrypt_string("SHA256:abc123").unwrap()
                }
            }),
        ];

        // 1. PBKDF2 export -> import round-trip
        let exported_pbkdf2 =
            export_personal_vault_encrypted_json(&src_storage, &key, "export-pass-123").unwrap();

        // Missing password fails closed
        let err_missing = plan_personal_vault_import(
            &empty_storage(),
            &key,
            exported_pbkdf2.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err_missing.to_ascii_lowercase().contains("password"),
            "got: {err_missing}"
        );

        // Wrong password fails immediately on encKeyValidation_DO_NOT_EDIT MAC check
        let err_wrong = plan_personal_vault_import(
            &empty_storage(),
            &key,
            exported_pbkdf2.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
            Some("wrong-password"),
        )
        .unwrap_err();
        assert!(
            err_wrong.to_ascii_lowercase().contains("invalid")
                && err_wrong.to_ascii_lowercase().contains("password"),
            "got: {err_wrong}"
        );

        // Correct password succeeds and decrypts/re-encrypts into a fresh account key
        let dest_key = SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap();
        let plan = plan_personal_vault_import(
            &empty_storage(),
            &dest_key,
            exported_pbkdf2.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
            Some("export-pass-123"),
        )
        .unwrap();
        assert_eq!(plan.detected_format, DetectedImportFormat::EncryptedJson);
        assert_eq!(plan.cipher_count, 2);
        assert_eq!(plan.folders_created, 1);
        assert_eq!(
            decrypt_cipher_string(
                plan.request_payload["ciphers"][0]["name"].as_str(),
                &dest_key
            )
            .as_deref(),
            Some("Encrypted Login")
        );
        assert_eq!(
            decrypt_cipher_string(
                plan.request_payload["ciphers"][0]["login"]["password"].as_str(),
                &dest_key
            )
            .as_deref(),
            Some("correct-horse-battery")
        );
        assert_eq!(
            decrypt_cipher_string(
                plan.request_payload["ciphers"][1]["sshKey"]["keyFingerprint"].as_str(),
                &dest_key
            )
            .as_deref(),
            Some("SHA256:abc123")
        );

        // 2. Argon2id export -> import round-trip
        src_storage.kdf = Some(1);
        src_storage.kdf_iterations = Some(2);
        src_storage.kdf_memory = Some(16);
        src_storage.kdf_parallelism = Some(1);
        let exported_argon2 =
            export_personal_vault_encrypted_json(&src_storage, &key, "argon-pass-456").unwrap();
        let argon_plan = plan_personal_vault_import(
            &empty_storage(),
            &dest_key,
            exported_argon2.content.as_bytes(),
            VaultImportFormat::EncryptedJson,
            Some("Restored"),
            Some("argon-pass-456"),
        )
        .unwrap();
        assert_eq!(argon_plan.cipher_count, 2);
        assert_eq!(argon_plan.folders_created, 1);
        assert_eq!(
            decrypt_cipher_string(
                argon_plan.request_payload["folders"][0]["name"].as_str(),
                &dest_key
            )
            .as_deref(),
            Some("Restored")
        );

        // 3. Independently precomputed fixed Bitwarden interoperability vector
        // (PBKDF2-HMAC-SHA256 5,000 iters, raw UTF-8 Base64 salt, RFC 5869 HKDF-Expand-only,
        // AES-256-CBC + HMAC-SHA256; computed independently outside Rust via Python + OpenSSL).
        let vector_doc = serde_json::to_vec(&json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": "Oy0xcgVRzxQ+9NpB5GLehw==",
            "kdfType": 0,
            "kdfIterations": 5_000,
            "encKeyValidation_DO_NOT_EDIT": "2.AQIDBAUGBwgJCgsMDQ4PEA==|AEl6C4y/SBquQMYHYE+pu9LYEUE8n07aM9gVd1rcpLLpXEM/lsK2B4doQLelSVaf|/4TeysufgifF0NwMogvYY3sjt9V9HV+m4t3WTnWhHX0=",
            "data": "2.ERITFBUWFxgZGhscHR4fIA==|/AfDF53N9Voo2wJsYSUoFGZ7XYszH6FerplpWu481KQ/Ha5sfp7oNXTpe4rSGeyi0fqRFqeDVduDnH+FcRdjNx1IDxDdWA3eRC0BpVETirOWlOzfdKBJSXGdnd0BlndguqpwK10Wjod6nf0jCPezO4XDsyVSaBmI60UcDcCLBdhjTO1nYF08/NiuquC9P/JEZ2BnQXTh0B5wnh3nozx82sHAwU4sxR/7LRgJCpc58gA=|7tzP1h1LYxEi9CDc6zcqHmS0E82PxHwB3/+NmSxWlGk="
        }))
        .unwrap();
        let vec_plan = plan_personal_vault_import(
            &empty_storage(),
            &dest_key,
            &vector_doc,
            VaultImportFormat::Auto,
            None,
            Some("correct horse battery staple"),
        )
        .unwrap();
        assert_eq!(vec_plan.cipher_count, 1);
        assert_eq!(
            decrypt_cipher_string(
                vec_plan.request_payload["ciphers"][0]["notes"].as_str(),
                &dest_key
            )
            .as_deref(),
            Some("Verified via independent Python HKDF-Expand-only")
        );
    }

    #[test]
    fn account_encrypted_json_v1_import_unkeyed_and_per_item_keyed_and_wrong_account() {
        let account_key = test_user_key();
        let other_account_key = SymmetricCryptoKey::from_raw_bytes(&[42u8; 64]).unwrap();

        let item_key_bytes = [13u8; 64];
        let item_key = SymmetricCryptoKey::from_raw_bytes(&item_key_bytes).unwrap();
        let wrapped_item_key = account_key.encrypt(&item_key_bytes).unwrap();

        let mut src_storage = empty_storage();
        src_storage.folders = vec![json!({
            "id": "folder-v1",
            "name": account_key.encrypt_string("Banking").unwrap()
        })];
        src_storage.ciphers = vec![
            // Legacy unkeyed cipher (encrypted directly with user_key)
            json!({
                "id": "legacy-1",
                "organizationId": null,
                "folderId": "folder-v1",
                "type": 1,
                "name": account_key.encrypt_string("Legacy Login").unwrap(),
                "notes": account_key.encrypt_string("Old format").unwrap(),
                "favorite": false,
                "reprompt": 0,
                "login": {
                    "username": account_key.encrypt_string("legacy_user").unwrap(),
                    "password": account_key.encrypt_string("legacy_pass").unwrap(),
                    "uris": [{ "uri": account_key.encrypt_string("https://legacy.test").unwrap(), "match": 0 }]
                }
            }),
            // Modern per-item-keyed cipher (fields encrypted with item_key, key wrapped under user_key)
            json!({
                "id": "keyed-1",
                "organizationId": null,
                "folderId": "folder-v1",
                "type": 3,
                "key": wrapped_item_key,
                "name": item_key.encrypt_string("Corporate Card").unwrap(),
                "favorite": true,
                "reprompt": 1,
                "card": {
                    "cardholderName": item_key.encrypt_string("Alice").unwrap(),
                    "brand": item_key.encrypt_string("Visa").unwrap(),
                    "number": item_key.encrypt_string("4111111111111111").unwrap(),
                    "expMonth": item_key.encrypt_string("12").unwrap(),
                    "expYear": item_key.encrypt_string("2030").unwrap(),
                    "code": item_key.encrypt_string("123").unwrap()
                }
            }),
        ];

        let exported =
            export_personal_vault_account_encrypted_json(&src_storage, &account_key).unwrap();

        // Wrong account key fails immediately on encKeyValidation_DO_NOT_EDIT
        let err_wrong_acct = plan_personal_vault_import(
            &empty_storage(),
            &other_account_key,
            exported.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err_wrong_acct.to_ascii_lowercase().contains("account")
                || err_wrong_acct.to_ascii_lowercase().contains("key"),
            "got: {err_wrong_acct}"
        );

        // Providing an import_password for account_encrypted_json fails closed
        let err_pw = plan_personal_vault_import(
            &empty_storage(),
            &account_key,
            exported.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
            Some("unused-pass"),
        )
        .unwrap_err();
        assert!(err_pw.contains("not used"), "got: {err_pw}");

        // Same account key succeeds, unwraps per-item key, and re-encrypts fresh under user_key
        let plan = plan_personal_vault_import(
            &empty_storage(),
            &account_key,
            exported.content.as_bytes(),
            VaultImportFormat::Auto,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            plan.detected_format,
            DetectedImportFormat::AccountEncryptedJson
        );
        assert_eq!(plan.cipher_count, 2);
        assert_eq!(plan.folders_created, 1);
        assert_eq!(
            decrypt_cipher_string(
                plan.request_payload["folders"][0]["name"].as_str(),
                &account_key
            )
            .as_deref(),
            Some("Banking")
        );

        let c0 = &plan.request_payload["ciphers"][0];
        assert!(c0["organizationId"].is_null());
        assert_eq!(
            decrypt_cipher_string(c0["login"]["password"].as_str(), &account_key).as_deref(),
            Some("legacy_pass")
        );

        let c1 = &plan.request_payload["ciphers"][1];
        assert!(c1.get("key").is_none());
        assert_eq!(
            decrypt_cipher_string(c1["name"].as_str(), &account_key).as_deref(),
            Some("Corporate Card")
        );
        assert_eq!(
            decrypt_cipher_string(c1["card"]["number"].as_str(), &account_key).as_deref(),
            Some("4111111111111111")
        );
    }
}
