//! Daemon-owned Attachment V2 upload guardrails, encryption, two-phase HTTP
//! upload with rollback, and local cache publication.
//!
//! Zero terminal I/O: all inputs arrive via structured parameters and all
//! outcomes return structured values (ADR-0039).

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use base64::Engine as _;
use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, Utc};
use rand_core::RngCore;
use serde_json::{json, Value};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::api::{
    decrypt_sync_ciphers_with_context, is_loopback_host, ApiError, BitwardenApiClient,
    ClientContext,
};
use crate::attachment::is_safe_path_component;
use crate::config::{ConfigManager, DEFAULT_MAX_ATTACHMENT_SIZE_MB};
use crate::crypto::{
    encrypt_attachment_blob, parse_symmetric_key_from_decrypted_bytes, EncString,
    SymmetricCryptoKey,
};
use crate::locked::LockedKey64;
use crate::storage::VaultStorage;
use crate::vault::VaultManager;
use crate::vault_cache::{CacheSession, IndexUpdate};

/// Bitwarden server hard ceiling for plaintext attachment uploads (500 MiB).
pub const HARD_MAX_ATTACHMENT_SIZE_MB: u64 = 500;

/// Bitwarden `FileUploadType::Direct` (Bitwarden Self-Hosted & Vaultwarden).
pub const FILE_UPLOAD_TYPE_DIRECT: u64 = 0;

/// Bitwarden `FileUploadType::Azure` (Bitwarden Cloud Azure Blob Storage).
pub const FILE_UPLOAD_TYPE_AZURE: u64 = 1;

/// Maximum encrypted payload size for a single Azure `BlockBlob` PUT (256 MiB).
pub const AZURE_SINGLE_PUT_MAX_BYTES: usize = 256 * 1024 * 1024;

/// Default sequential block size for Azure multi-block uploads (`> 256 MiB`).
pub const AZURE_DEFAULT_BLOCK_SIZE_BYTES: usize = 100 * 1024 * 1024;

/// Safety margin in seconds before SAS `se` expiration to proactively renew the SAS URL.
pub const AZURE_SAS_RENEWAL_MARGIN_SECS: i64 = 5;

/// Internal configuration for Azure Attachment V2 uploads, allowing tests to
/// exercise multi-block splitting without allocating 256+ MiB in memory.
#[derive(Debug, Clone, Copy)]
pub struct AzureUploadConfig {
    pub single_put_max_bytes: usize,
    pub block_size_bytes: usize,
    pub sas_renewal_margin_secs: i64,
    pub allow_loopback_http: bool,
}

impl Default for AzureUploadConfig {
    fn default() -> Self {
        Self {
            single_put_max_bytes: AZURE_SINGLE_PUT_MAX_BYTES,
            block_size_bytes: AZURE_DEFAULT_BLOCK_SIZE_BYTES,
            sas_renewal_margin_secs: AZURE_SAS_RENEWAL_MARGIN_SECS,
            allow_loopback_http: cfg!(test),
        }
    }
}

impl AzureUploadConfig {
    /// Resolves Azure upload parameters for an active upload session.
    /// Test-only threshold overrides are honored strictly when `allow_loopback_http`
    /// is true (local loopback test servers); production HTTPS origins always use
    /// the canonical 256 MiB / 100 MiB constants.
    pub fn for_api_origin(allow_loopback_http: bool) -> Self {
        let mut cfg = Self {
            allow_loopback_http,
            ..Self::default()
        };
        if allow_loopback_http {
            if let Some(v) = std::env::var("OMA_TEST_AZURE_SINGLE_PUT_MAX_BYTES")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
            {
                cfg.single_put_max_bytes = v;
            }
            if let Some(v) = std::env::var("OMA_TEST_AZURE_BLOCK_SIZE_BYTES")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
            {
                cfg.block_size_bytes = v;
            }
        }
        cfg
    }
}

/// Validates an Azure Blob Storage SAS upload URL fail-closed.
///
/// Requires `https://` in all production environments. Loopback `http://`
/// (`localhost`, `127.0.0.0/8`, `::1`) is permitted ONLY when `allow_loopback_http`
/// is true (test environments). Remote plaintext `http://` and all non-HTTP(S)
/// schemes are always rejected.
pub fn validate_azure_upload_url(raw_url: &str, allow_loopback_http: bool) -> Result<Url, String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err("Azure attachment upload URL is empty.".to_string());
    }
    let parsed =
        Url::parse(trimmed).map_err(|e| format!("Invalid Azure attachment upload URL: {e}"))?;
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "Azure attachment upload URL is missing a host.".to_string())?;
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if allow_loopback_http && is_loopback_host(host) => Ok(parsed),
        "http" => Err(format!(
            "Refusing insecure non-HTTPS Azure attachment upload URL for host '{host}'."
        )),
        scheme => Err(format!(
            "Unsupported scheme '{scheme}' in Azure attachment upload URL; https:// is required."
        )),
    }
}

/// Parses the Azure SAS `se` (signed expiry) query parameter as a UTC timestamp.
pub fn parse_azure_sas_expiry(url: &Url) -> Option<DateTime<Utc>> {
    let raw = url
        .query_pairs()
        .find(|(k, _)| k.eq_ignore_ascii_case("se"))
        .map(|(_, v)| v.into_owned())?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%MZ") {
        return Some(ndt.and_utc());
    }
    if let Ok(nd) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        return nd.and_hms_opt(0, 0, 0).map(|ndt| ndt.and_utc());
    }
    None
}

/// Returns true when the Azure SAS URL carries a `se` expiry timestamp that is
/// already expired or within `margin_secs` of expiring.
pub fn azure_sas_needs_renewal(url: &Url, now: DateTime<Utc>, margin_secs: i64) -> bool {
    match parse_azure_sas_expiry(url) {
        Some(expiry) => expiry <= now + Duration::seconds(margin_secs),
        None => false,
    }
}

/// Encodes a sequential block index into a fixed-length Base64 Azure `blockid`
/// matching Bitwarden's 48-character zero-padded decimal convention.
pub fn azure_block_id(block_index: usize) -> String {
    let padded = format!("{block_index:048}");
    base64::engine::general_purpose::STANDARD.encode(padded.as_bytes())
}

/// Builds the Azure Put Block List XML commit payload (`<BlockList><Latest>...</Latest></BlockList>`).
pub fn build_azure_block_list_xml(block_ids: &[String]) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
    for id in block_ids {
        xml.push_str("<Latest>");
        xml.push_str(id);
        xml.push_str("</Latest>");
    }
    xml.push_str("</BlockList>");
    xml
}

/// Appends `comp=block&blockid=<block_id>` to an Azure SAS URL while preserving
/// existing SAS query parameters.
pub fn build_azure_block_url(sas_url: &Url, block_id: &str) -> Url {
    let mut url = sas_url.clone();
    url.query_pairs_mut()
        .append_pair("comp", "block")
        .append_pair("blockid", block_id);
    url
}

/// Appends `comp=blocklist` to an Azure SAS URL while preserving existing SAS query parameters.
pub fn build_azure_block_list_url(sas_url: &Url) -> Url {
    let mut url = sas_url.clone();
    url.query_pairs_mut().append_pair("comp", "blocklist");
    url
}

/// Ensures `current_url` is not expired or within `config.sas_renewal_margin_secs`
/// of expiring; when renewal is needed, invokes `renew_sas_url`, validates the
/// returned URL fail-closed, and updates `current_url`.
fn ensure_fresh_azure_sas_url<F>(
    current_url: &mut Url,
    config: AzureUploadConfig,
    renew_sas_url: &mut F,
) -> Result<(), String>
where
    F: FnMut() -> Result<String, String>,
{
    if !azure_sas_needs_renewal(current_url, Utc::now(), config.sas_renewal_margin_secs) {
        return Ok(());
    }
    let renewed_raw = renew_sas_url()?;
    let renewed = validate_azure_upload_url(&renewed_raw, config.allow_loopback_http)?;
    *current_url = renewed;
    Ok(())
}

/// Executes Step 2 (`FileUploadType::Azure (1)`) upload against Azure Blob Storage.
///
/// - Validates the initial (and any renewed) SAS URL with `validate_azure_upload_url`.
/// - Uses a single `BlockBlob` PUT when `encrypted_blob.len() <= config.single_put_max_bytes`.
/// - Splits into sequential `comp=block` PUTs followed by `comp=blocklist` XML commit
///   when `encrypted_blob.len() > config.single_put_max_bytes`.
/// - Checks the SAS `se` query parameter before single PUT, before each block, and
///   before `comp=blocklist`, calling `renew_sas_url` when expired or nearing expiration.
/// - Never attaches an `Authorization` header to any Azure request.
pub fn upload_attachment_azure_with_config<F>(
    client: &BitwardenApiClient,
    initial_sas_url: &str,
    encrypted_blob: &[u8],
    config: AzureUploadConfig,
    mut renew_sas_url: F,
) -> Result<(), String>
where
    F: FnMut() -> Result<String, String>,
{
    let mut current_url = validate_azure_upload_url(initial_sas_url, config.allow_loopback_http)?;

    if encrypted_blob.len() <= config.single_put_max_bytes {
        ensure_fresh_azure_sas_url(&mut current_url, config, &mut renew_sas_url)?;
        return client
            .upload_attachment_azure_single(&current_url, encrypted_blob)
            .map_err(|err| format_api_error("Attachment upload step 2 (Azure) failed", &err));
    }

    let block_size = config.block_size_bytes.max(1);
    let mut block_ids = Vec::new();
    for (idx, chunk) in encrypted_blob.chunks(block_size).enumerate() {
        ensure_fresh_azure_sas_url(&mut current_url, config, &mut renew_sas_url)?;
        let block_id = azure_block_id(idx);
        client
            .upload_attachment_azure_block(&current_url, &block_id, chunk)
            .map_err(|err| {
                format_api_error(
                    &format!("Attachment upload step 2 (Azure block {idx}) failed"),
                    &err,
                )
            })?;
        block_ids.push(block_id);
    }

    ensure_fresh_azure_sas_url(&mut current_url, config, &mut renew_sas_url)?;
    client
        .commit_attachment_azure_block_list(&current_url, &block_ids)
        .map_err(|err| format_api_error("Attachment upload step 2 (Azure blocklist) failed", &err))
}

/// Computes the effective maximum attachment upload size in MiB as
/// `min(configured_mb, 500)`, falling back to the default when `configured_mb == 0`.
pub fn effective_max_attachment_size_mb(configured_mb: u64) -> u64 {
    if configured_mb == 0 {
        DEFAULT_MAX_ATTACHMENT_SIZE_MB.min(HARD_MAX_ATTACHMENT_SIZE_MB)
    } else {
        configured_mb.min(HARD_MAX_ATTACHMENT_SIZE_MB)
    }
}

/// Validates an attachment filename fail-closed as a non-empty single basename.
///
/// Rejects empty or whitespace-only names, path separators (`/` or `\`),
/// `.` and `..`, NUL bytes, and ASCII/Unicode control characters.
pub fn validate_attachment_filename(name: &str) -> Result<String, String> {
    if name.trim().is_empty() {
        return Err("Attachment filename cannot be empty or whitespace-only.".to_string());
    }
    if name == "." || name == ".." {
        return Err(format!(
            "Invalid attachment filename '{name}': '.' and '..' are not allowed."
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!(
            "Invalid attachment filename '{name}': must be a single basename without path separators."
        ));
    }
    if name.contains('\0') || name.chars().any(char::is_control) {
        return Err(
            "Invalid attachment filename: NUL and control characters are not allowed.".to_string(),
        );
    }
    Ok(name.to_string())
}

/// Resolves the attachment filename from an explicit override (`--name`) or the
/// input path's basename, validating fail-closed in both cases.
pub fn resolve_attachment_filename(
    file_path: &Path,
    override_name: Option<&str>,
) -> Result<String, String> {
    if let Some(raw) = override_name {
        return validate_attachment_filename(raw);
    }
    let basename = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            format!(
                "Could not derive a valid UTF-8 filename from '{}'. Specify --name explicitly.",
                file_path.display()
            )
        })?;
    validate_attachment_filename(basename)
}

fn format_size_limit_error(actual_bytes: u64, max_bytes: u64) -> String {
    let max_mb = max_bytes / (1024 * 1024);
    if max_mb > 0 && max_bytes == max_mb * 1024 * 1024 {
        format!(
            "Attachment file size ({actual_bytes} bytes) exceeds the maximum allowed size of {max_mb} MiB (allowed range: 0 to {max_mb} MiB / {max_bytes} bytes)."
        )
    } else {
        format!(
            "Attachment file size ({actual_bytes} bytes) exceeds the maximum allowed size of {max_bytes} bytes (allowed range: 0 to {max_bytes} bytes)."
        )
    }
}

/// Reads from `reader` through `Read::take(max_bytes + 1)` into a zeroizing
/// buffer so TOCTOU file growth past `max_bytes` fails closed without exhausting memory.
pub fn read_attachment_reader_bounded<R: Read>(
    reader: R,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let limit = max_bytes.saturating_add(1);
    let mut limited = reader.take(limit);
    let mut buf = Zeroizing::new(Vec::new());
    limited
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read attachment file: {e}"))?;
    if (buf.len() as u64) > max_bytes {
        return Err(format_size_limit_error(buf.len() as u64, max_bytes));
    }
    Ok(buf)
}

/// Validates that `path` is a regular file, pre-checks its metadata size against
/// `max_bytes`, and reads its bytes through `Read::take(max_bytes + 1)` into
/// zeroizing memory. Allows 0-byte regular files.
pub fn read_attachment_file_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("Cannot access attachment file '{}': {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!(
            "Attachment path '{}' is not a regular file (directories, FIFOs, sockets, and device nodes are not supported).",
            path.display()
        ));
    }
    if meta.len() > max_bytes {
        return Err(format_size_limit_error(meta.len(), max_bytes));
    }

    let file = File::open(path)
        .map_err(|e| format!("Cannot open attachment file '{}': {e}", path.display()))?;
    let opened_meta = file.metadata().map_err(|e| {
        format!(
            "Cannot inspect opened attachment file '{}': {e}",
            path.display()
        )
    })?;
    if !opened_meta.is_file() {
        return Err(format!(
            "Attachment path '{}' is not a regular file.",
            path.display()
        ));
    }
    if opened_meta.len() > max_bytes {
        return Err(format_size_limit_error(opened_meta.len(), max_bytes));
    }

    read_attachment_reader_bounded(file, max_bytes)
}

/// Encrypted attachment artifacts ready for the two-phase Attachment V2 API.
#[derive(Debug, Clone)]
pub struct PreparedAttachmentUpload {
    pub resolved_file_name: String,
    pub encrypted_file_name: String,
    pub wrapped_key: String,
    pub encrypted_blob: Vec<u8>,
}

/// Generates a fresh 64-byte random per-attachment symmetric key in `mlock`-protected
/// memory (`LockedKey64`), wraps the key and encrypts `file_name` as `EncString` type 2
/// under `target_key`, encrypts `plaintext` as binary `EncArrayBuffer`, and immediately
/// zeroizes `plaintext` and `LockedKey64`.
pub fn prepare_encrypted_attachment(
    mut plaintext: Zeroizing<Vec<u8>>,
    file_name: String,
    target_key: &SymmetricCryptoKey,
) -> Result<PreparedAttachmentUpload, String> {
    let mut raw_att_key = LockedKey64::new_zeroed();
    rand_core::OsRng.fill_bytes(raw_att_key.as_mut_slice());

    let mut att_key = SymmetricCryptoKey::from_raw_bytes(raw_att_key.as_slice())
        .map_err(|e| format!("Failed to initialize per-attachment key: {e}"))?;

    let wrapped_key = target_key
        .encrypt(raw_att_key.as_slice())
        .map_err(|e| format!("Failed to wrap per-attachment key: {e}"))?;
    let encrypted_file_name = target_key
        .encrypt_string(&file_name)
        .map_err(|e| format!("Failed to encrypt attachment filename: {e}"))?;
    let encrypted_blob = encrypt_attachment_blob(&plaintext, &att_key)
        .map_err(|e| format!("Failed to encrypt attachment payload: {e}"))?;

    // Immediately scrub plaintext buffer and per-attachment key material before any I/O.
    plaintext.zeroize();
    drop(plaintext);
    raw_att_key.zeroize();
    drop(raw_att_key);
    att_key.zeroize();
    drop(att_key);

    Ok(PreparedAttachmentUpload {
        resolved_file_name: file_name,
        encrypted_file_name,
        wrapped_key,
        encrypted_blob,
    })
}

/// Builds an RFC 7578 `multipart/form-data` payload containing a single `"data"`
/// part with `encrypted_blob`. Returns `(content_type_header, body_bytes)`.
pub(crate) fn build_attachment_multipart_body(
    encrypted_file_name: &str,
    encrypted_blob: &[u8],
) -> (String, Vec<u8>) {
    let mut rand_bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut rand_bytes);
    let mut boundary = String::from("omawarden-att-");
    for b in rand_bytes {
        use std::fmt::Write;
        let _ = write!(&mut boundary, "{b:02x}");
    }

    let safe_enc_name: String = encrypted_file_name
        .chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '"')
        .collect();

    let mut body = Vec::with_capacity(encrypted_blob.len() + 256);
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"data\"; filename=\"{safe_enc_name}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(encrypted_blob);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    (format!("multipart/form-data; boundary={boundary}"), body)
}

/// Resolves the target encryption key for a personal Cipher:
/// unwraps `cipher.key` under `user_key` when present, or falls back to `user_key`
/// for legacy unkeyed personal Ciphers. Fails closed if `cipher.key` is present
/// but malformed or undecryptable.
fn resolve_personal_cipher_key(
    cipher: &Value,
    user_key: &SymmetricCryptoKey,
) -> Result<SymmetricCryptoKey, String> {
    let Some(enc_cipher_key) = cipher
        .get("key")
        .or_else(|| cipher.get("Key"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return Ok(user_key.clone());
    };

    let parsed = EncString::parse(enc_cipher_key)
        .map_err(|_| "Malformed cipher encryption key; cannot wrap attachment key.".to_string())?;
    let decrypted = Zeroizing::new(
        parsed
            .decrypt(user_key)
            .map_err(|_| "Could not decrypt cipher encryption key.".to_string())?,
    );
    parse_symmetric_key_from_decrypted_bytes(&decrypted)
        .ok_or_else(|| "Invalid decrypted cipher encryption key length.".to_string())
}

fn format_api_error(prefix: &str, err: &ApiError) -> String {
    match err {
        ApiError::HttpStatus(status, msg) => format!("{prefix} (HTTP {status}): {msg}"),
        other => format!("{prefix}: {other}"),
    }
}

impl VaultManager {
    /// Encrypts and uploads a local file as an Attachment V2 (`Direct (0)`) to an
    /// active personal Cipher, rolling back on Step 2 failure and updating local
    /// cache and in-memory index only after Step 2 succeeds.
    pub(crate) fn upload_attachment(
        &self,
        item_id: &str,
        file_path: &str,
        file_name_override: Option<&str>,
        context: Option<&ClientContext>,
    ) -> Result<Value, String> {
        let item_id = item_id.trim();
        if item_id.is_empty() {
            return Err("Item ID is required.".to_string());
        }
        if !is_safe_path_component(item_id) {
            return Err("Item ID contains invalid path characters.".to_string());
        }
        if file_path.trim().is_empty() {
            return Err("Attachment file path is required.".to_string());
        }

        let path = Path::new(file_path);
        let resolved_file_name = resolve_attachment_filename(path, file_name_override)?;

        let cfg = ConfigManager::new(None).load();
        let max_mb = effective_max_attachment_size_mb(cfg.max_attachment_size_mb);
        let max_bytes = max_mb.saturating_mul(1024 * 1024);

        let generation = self.lock_generation();
        let storage = self
            .storage_mgr
            .load_existing()
            .map_err(|_| "Cannot read the vault cache.".to_string())?;

        // Validate target cipher and resolve encryption key BEFORE reading file or making HTTP calls.
        let (target_key, last_known_revision_date) = {
            let unlocked = self
                .is_unlocked
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            let active = self
                .storage
                .read()
                .map_err(|_| "Vault state unavailable".to_string())?;
            if !*unlocked
                || generation != self.lock_generation()
                || !active.same_active_slot(&storage)
            {
                return Err("Vault session changed.".to_string());
            }

            let cipher = active
                .ciphers
                .iter()
                .find(|c| c.get("id").and_then(Value::as_str) == Some(item_id))
                .ok_or_else(|| {
                    format!("Cipher '{item_id}' not found in local vault cache. Sync the vault and try again.")
                })?;

            // Fail closed on trashed Ciphers before any HTTP request.
            if cipher
                .get("deletedDate")
                .or_else(|| cipher.get("DeletedDate"))
                .is_some_and(|v| !v.is_null())
            {
                return Err(
                    "Cannot upload an attachment to a trashed cipher. Restore the cipher first."
                        .to_string(),
                );
            }

            // Fail closed on Organization Ciphers before any HTTP request (until org unlock slice lands).
            if cipher
                .get("organizationId")
                .or_else(|| cipher.get("OrganizationId"))
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())
            {
                return Err(
                    "Organization cipher attachment upload is not yet supported.".to_string(),
                );
            }

            let rev = cipher
                .get("revisionDate")
                .or_else(|| cipher.get("RevisionDate"))
                .and_then(Value::as_str)
                .map(str::to_string);

            let user_key_guard = self
                .user_key
                .read()
                .map_err(|_| "Vault key unavailable".to_string())?;
            let user_key = user_key_guard
                .as_ref()
                .ok_or_else(|| "Vault is locked. Please unlock the vault first.".to_string())?;
            let key = resolve_personal_cipher_key(cipher, user_key)?;
            (key, rev)
        };

        // Read plaintext file with metadata pre-check + regular-file check + Read::take(max + 1) TOCTOU guard.
        let plaintext = read_attachment_file_bounded(path, max_bytes)?;

        // Encrypt payload and metadata, immediately zeroizing plaintext and LockedKey64.
        let prepared = prepare_encrypted_attachment(plaintext, resolved_file_name, &target_key)?;
        drop(target_key);

        let server = if storage.server_url.is_empty() {
            &self.server_url
        } else {
            &storage.server_url
        };
        let client = BitwardenApiClient::for_attachment_upload(server, context)
            .map_err(|e| format!("Could not initialize attachment upload HTTP client: {e}"))?;

        let token = self.keyring_mgr.for_storage(&storage).access_token();
        let renew = || {
            self.renew_for_account(&storage, context, generation)
                .map_err(|_| "Vault session expired. Please log in again.".to_string())
        };
        let mut active_token = match token.filter(|t| !crate::auth::is_jwt_expired(t)) {
            Some(t) => t,
            None => renew()?,
        };

        // Step 1: POST /api/ciphers/{id}/attachment/v2
        let mut renewed_after_rejection = false;
        let step1_resp = loop {
            match client.create_attachment_v2(
                &active_token,
                item_id,
                &prepared.wrapped_key,
                &prepared.encrypted_file_name,
                prepared.encrypted_blob.len() as u64,
                last_known_revision_date.as_deref(),
            ) {
                Ok(resp) => break resp,
                Err(ApiError::HttpStatus(status, _))
                    if matches!(status.as_u16(), 401 | 403) && !renewed_after_rejection =>
                {
                    renewed_after_rejection = true;
                    active_token = renew()?;
                }
                Err(err) => {
                    return Err(format_api_error("Attachment upload step 1 failed", &err));
                }
            }
        };

        let attachment_id = step1_resp
            .get("attachmentId")
            .or_else(|| step1_resp.get("AttachmentId"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "Server attachment upload response is missing 'attachmentId'.".to_string()
            })?
            .to_string();

        if !is_safe_path_component(&attachment_id) {
            return Err("Server returned an invalid attachmentId.".to_string());
        }

        let file_upload_type = step1_resp
            .get("fileUploadType")
            .or_else(|| step1_resp.get("FileUploadType"))
            .and_then(Value::as_u64);

        let cipher_response = step1_resp
            .get("cipherResponse")
            .or_else(|| step1_resp.get("CipherResponse"))
            .filter(|v| v.is_object())
            .cloned();

        // Step 2: Direct (0) multipart POST or Azure (1) BlockBlob / multi-block PUT;
        // rollback on any failure or unsupported upload type.
        let step2_result: Result<(), String> = match file_upload_type {
            Some(FILE_UPLOAD_TYPE_DIRECT) => client
                .upload_attachment_direct(
                    &active_token,
                    item_id,
                    &attachment_id,
                    &prepared.encrypted_file_name,
                    &prepared.encrypted_blob,
                )
                .map_err(|err| format_api_error("Attachment upload step 2 failed", &err)),
            Some(FILE_UPLOAD_TYPE_AZURE) => {
                let raw_azure_url = step1_resp
                    .get("url")
                    .or_else(|| step1_resp.get("Url"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                match raw_azure_url {
                    None => Err(
                        "Server attachment upload response is missing Azure upload 'url'."
                            .to_string(),
                    ),
                    Some(azure_url) => {
                        let azure_cfg =
                            AzureUploadConfig::for_api_origin(client.is_loopback_http_api());
                        upload_attachment_azure_with_config(
                            &client,
                            azure_url,
                            &prepared.encrypted_blob,
                            azure_cfg,
                            || {
                                let renew_resp = loop {
                                    match client.renew_attachment_upload_url(
                                        &active_token,
                                        item_id,
                                        &attachment_id,
                                    ) {
                                        Ok(resp) => break resp,
                                        Err(ApiError::HttpStatus(status, _))
                                            if matches!(status.as_u16(), 401 | 403)
                                                && !renewed_after_rejection =>
                                        {
                                            renewed_after_rejection = true;
                                            active_token = renew()?;
                                        }
                                        Err(err) => {
                                            return Err(format_api_error(
                                                "Attachment SAS URL renewal failed",
                                                &err,
                                            ));
                                        }
                                    }
                                };
                                renew_resp
                                    .get("url")
                                    .or_else(|| renew_resp.get("Url"))
                                    .and_then(Value::as_str)
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_string)
                                    .ok_or_else(|| {
                                        "Server attachment SAS renewal response is missing 'url'."
                                            .to_string()
                                    })
                            },
                        )
                    }
                }
            }
            Some(other) => Err(format!(
                "Unsupported attachment fileUploadType ({other}); only Direct (0) and Azure (1) are supported."
            )),
            None => {
                Err("Server attachment upload response is missing 'fileUploadType'.".to_string())
            }
        };

        if let Err(primary_err) = step2_result {
            // Rollback unvalidated attachment slot on the server and leave local cache untouched.
            match client.delete_attachment(&active_token, item_id, &attachment_id) {
                Ok(_) => return Err(primary_err),
                Err(rollback_err) => {
                    return Err(format!(
                        "{primary_err}. Warning: rollback DELETE for attachment slot '{attachment_id}' also failed ({rollback_err}); an unvalidated attachment slot may remain on the server."
                    ));
                }
            }
        }

        let cipher_json = cipher_response.ok_or_else(|| {
            "Server attachment upload response is missing 'cipherResponse'.".to_string()
        })?;

        // Step 3 (only after Step 2 succeeds): upsert cipherResponse into 0600 storage and refresh index.
        let updated_item = self
            .cache_uploaded_attachment_cipher(&storage, generation, &cipher_json, item_id)
            .ok_or_else(|| {
                "Attachment uploaded, but local vault cache could not be updated. Sync the vault to refresh."
                    .to_string()
            })?;

        let attachment_meta = updated_item
            .attachments
            .iter()
            .find(|a| a.get("id").and_then(Value::as_str) == Some(attachment_id.as_str()))
            .cloned()
            .unwrap_or_else(|| {
                let enc_size = prepared.encrypted_blob.len();
                json!({
                    "id": attachment_id,
                    "fileName": prepared.resolved_file_name,
                    "size": enc_size.to_string(),
                    "sizeName": format!("{enc_size} B"),
                })
            });

        Ok(json!({
            "ok": true,
            "item_id": item_id,
            "attachment": attachment_meta,
            "item": updated_item,
        }))
    }

    fn cache_uploaded_attachment_cipher(
        &self,
        account: &VaultStorage,
        generation: u64,
        cipher: &Value,
        id: &str,
    ) -> Option<crate::vault::VaultItem> {
        let base = self.storage_mgr.cache_snapshot().ok()?;
        if !base.storage.same_active_slot(account) {
            return None;
        }
        let mut updated = base.storage.clone();
        updated
            .ciphers
            .retain(|c| c.get("id").and_then(Value::as_str) != Some(id));
        updated.ciphers.push(cipher.clone());
        let item = {
            let key = self.user_key.read().ok()?;
            decrypt_sync_ciphers_with_context(
                std::slice::from_ref(cipher),
                &updated.folders,
                &updated.organizations,
                key.as_ref()?,
                updated.enc_private_key.as_deref(),
            )
            .pop()?
        };
        self.commit_cache(
            &base,
            updated,
            IndexUpdate::Upsert(Box::new(item.clone())),
            CacheSession {
                generation,
                unlocked: true,
            },
        )
        .ok()?;
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::decrypt_attachment_blob;
    use std::io::Cursor;

    #[test]
    fn test_validate_attachment_filename_accepts_valid_basenames() {
        for valid in [
            "recovery-codes.txt",
            "cert.pem",
            "my file (1).pdf",
            "日本語.txt",
            ".env",
            "a..b",
        ] {
            assert_eq!(validate_attachment_filename(valid).unwrap(), valid);
        }
    }

    #[test]
    fn test_validate_attachment_filename_rejects_malformed_and_traversal() {
        for invalid in [
            "",
            "   ",
            "\t\n",
            ".",
            "..",
            "a/b.txt",
            "/etc/passwd",
            "a\\b.txt",
            "bad\0name.txt",
            "bad\nname.txt",
            "bad\rname.txt",
            "bad\x07name.txt",
        ] {
            assert!(
                validate_attachment_filename(invalid).is_err(),
                "Expected '{invalid:?}' to be rejected"
            );
        }
    }

    #[test]
    fn test_resolve_attachment_filename_derives_basename_or_validates_override() {
        let p = Path::new("/tmp/nested/dir/secret.key");
        assert_eq!(resolve_attachment_filename(p, None).unwrap(), "secret.key");
        assert_eq!(
            resolve_attachment_filename(p, Some("renamed.pem")).unwrap(),
            "renamed.pem"
        );
        assert!(resolve_attachment_filename(p, Some("../escape.pem")).is_err());
        assert!(resolve_attachment_filename(Path::new("/"), None).is_err());
    }

    #[test]
    fn test_effective_max_attachment_size_mb_caps_at_500() {
        assert_eq!(effective_max_attachment_size_mb(0), 500);
        assert_eq!(effective_max_attachment_size_mb(10), 10);
        assert_eq!(effective_max_attachment_size_mb(500), 500);
        assert_eq!(effective_max_attachment_size_mb(1024), 500);
    }

    #[test]
    fn test_read_attachment_file_bounded_allows_zero_byte_and_rejects_oversized_and_dir() {
        let dir = tempfile::tempdir().unwrap();

        // 0-byte regular file is allowed
        let empty_path = dir.path().join("empty.txt");
        fs::write(&empty_path, b"").unwrap();
        let bytes = read_attachment_file_bounded(&empty_path, 1024).unwrap();
        assert!(bytes.is_empty());

        // Exact boundary file is allowed
        let exact_path = dir.path().join("exact.bin");
        fs::write(&exact_path, vec![0xAB; 16]).unwrap();
        let bytes = read_attachment_file_bounded(&exact_path, 16).unwrap();
        assert_eq!(bytes.len(), 16);

        // Oversized file fails with explicit allowed-range error
        let big_path = dir.path().join("big.bin");
        fs::write(&big_path, vec![0xCD; 17]).unwrap();
        let err = read_attachment_file_bounded(&big_path, 16).unwrap_err();
        assert!(err.contains("exceeds the maximum allowed size"), "{err}");
        assert!(err.contains("allowed range: 0 to 16 bytes"), "{err}");

        // Directory is rejected as non-regular file
        let err = read_attachment_file_bounded(dir.path(), 1024).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn test_read_attachment_reader_bounded_defeats_toctou_growth() {
        // Simulates a file whose metadata was <= 32 bytes at pre-check time,
        // but grew to 64 bytes during streaming read.
        let growing_stream = Cursor::new(vec![b'A'; 64]);
        let err = read_attachment_reader_bounded(growing_stream, 32).unwrap_err();
        assert!(err.contains("exceeds the maximum allowed size"), "{err}");
        assert!(
            err.contains("33 bytes"),
            "Should stop at max_bytes + 1: {err}"
        );
    }

    #[test]
    fn test_prepare_encrypted_attachment_roundtrips_with_wrapped_key_and_zero_byte() {
        let target_key = SymmetricCryptoKey::from_raw_bytes(&[91u8; 64]).unwrap();

        // Non-empty payload
        let plaintext = Zeroizing::new(b"top secret attachment bytes".to_vec());
        let prepared =
            prepare_encrypted_attachment(plaintext, "notes.txt".to_string(), &target_key).unwrap();

        let decrypted_name = EncString::parse(&prepared.encrypted_file_name)
            .unwrap()
            .decrypt_string(&target_key)
            .unwrap();
        assert_eq!(decrypted_name, "notes.txt");

        let unwrapped_raw = EncString::parse(&prepared.wrapped_key)
            .unwrap()
            .decrypt(&target_key)
            .unwrap();
        assert_eq!(unwrapped_raw.len(), 64);
        let att_key = SymmetricCryptoKey::from_raw_bytes(&unwrapped_raw).unwrap();
        let decrypted_blob = decrypt_attachment_blob(&prepared.encrypted_blob, &att_key).unwrap();
        assert_eq!(decrypted_blob, b"top secret attachment bytes");

        // 0-byte payload produces 65-byte EncArrayBuffer
        let empty_prepared = prepare_encrypted_attachment(
            Zeroizing::new(Vec::new()),
            "empty.txt".to_string(),
            &target_key,
        )
        .unwrap();
        assert_eq!(empty_prepared.encrypted_blob.len(), 65);
        let empty_raw_key = EncString::parse(&empty_prepared.wrapped_key)
            .unwrap()
            .decrypt(&target_key)
            .unwrap();
        let empty_att_key = SymmetricCryptoKey::from_raw_bytes(&empty_raw_key).unwrap();
        assert!(
            decrypt_attachment_blob(&empty_prepared.encrypted_blob, &empty_att_key)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_build_attachment_multipart_body_contains_data_field_and_binary_payload() {
        let blob = vec![0x02, 0x00, 0xFF, 0x10, 0x20];
        let (ct, body) = build_attachment_multipart_body("2.iv|ct|mac", &blob);
        assert!(ct.starts_with("multipart/form-data; boundary=omawarden-att-"));
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str
            .contains("Content-Disposition: form-data; name=\"data\"; filename=\"2.iv|ct|mac\""));
        assert!(body_str.contains("Content-Type: application/octet-stream"));
        assert!(body.windows(blob.len()).any(|w| w == blob.as_slice()));
    }

    #[test]
    fn test_validate_azure_upload_url_enforces_https_and_loopback_gate() {
        assert!(validate_azure_upload_url(
            "https://bitwardenstorage.blob.core.windows.net/attachments-v2/c1/a1?sv=2020-08-04&se=2026-11-27T17:00:00Z&sig=abc",
            false
        )
        .is_ok());

        // Remote plaintext HTTP is always rejected (even when loopback test mode is enabled)
        assert!(validate_azure_upload_url(
            "http://bitwardenstorage.blob.core.windows.net/attachments-v2/c1/a1?sig=abc",
            false
        )
        .is_err());
        assert!(validate_azure_upload_url(
            "http://bitwardenstorage.blob.core.windows.net/attachments-v2/c1/a1?sig=abc",
            true
        )
        .is_err());

        // Loopback HTTP is rejected in production mode, allowed only when loopback test mode is enabled
        assert!(validate_azure_upload_url("http://127.0.0.1:8080/blob?sig=abc", false).is_err());
        assert!(validate_azure_upload_url("http://localhost:8080/blob?sig=abc", false).is_err());
        assert!(validate_azure_upload_url("http://[::1]:8080/blob?sig=abc", false).is_err());
        assert!(validate_azure_upload_url("http://127.0.0.1:8080/blob?sig=abc", true).is_ok());
        assert!(validate_azure_upload_url("http://localhost:8080/blob?sig=abc", true).is_ok());
        assert!(validate_azure_upload_url("http://[::1]:8080/blob?sig=abc", true).is_ok());

        // Non-HTTP(S) schemes and empty/malformed URLs fail closed
        assert!(validate_azure_upload_url("file:///etc/passwd", true).is_err());
        assert!(validate_azure_upload_url("ftp://example.com/blob", true).is_err());
        assert!(validate_azure_upload_url("", true).is_err());
        assert!(validate_azure_upload_url("not-a-url", true).is_err());
    }

    #[test]
    fn test_azure_sas_expiry_parsing_and_renewal_detection() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-11-27T16:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        // Fresh token (60s left) does not need renewal with 5s margin
        let fresh = url::Url::parse(
            "https://acct.blob.core.windows.net/attachments-v2/c/a?sv=2020-08-04&se=2026-11-27T16:31:00Z&sig=x",
        )
        .unwrap();
        assert!(!azure_sas_needs_renewal(&fresh, now, 5));

        // Near-expiry token (3s left <= 5s margin) triggers renewal
        let near = url::Url::parse(
            "https://acct.blob.core.windows.net/attachments-v2/c/a?sv=2020-08-04&se=2026-11-27T16%3A30%3A03Z&sig=x",
        )
        .unwrap();
        assert!(azure_sas_needs_renewal(&near, now, 5));

        // Already-expired token triggers renewal
        let expired = url::Url::parse(
            "https://acct.blob.core.windows.net/attachments-v2/c/a?sv=2020-08-04&se=2026-11-27T16:29:50Z&sig=x",
        )
        .unwrap();
        assert!(azure_sas_needs_renewal(&expired, now, 5));

        // Fractional seconds format supported
        let frac = url::Url::parse(
            "https://acct.blob.core.windows.net/attachments-v2/c/a?se=2026-11-27T16:30:04.500Z",
        )
        .unwrap();
        assert!(azure_sas_needs_renewal(&frac, now, 5));

        // Missing se parameter does not spuriously renew
        let no_se =
            url::Url::parse("https://acct.blob.core.windows.net/attachments-v2/c/a?sig=x").unwrap();
        assert!(!azure_sas_needs_renewal(&no_se, now, 5));
    }

    #[test]
    fn test_azure_block_id_and_block_list_xml_and_query_urls() {
        let id0 = azure_block_id(0);
        let id1 = azure_block_id(1);
        assert_eq!(id0.len(), id1.len());
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &id0).unwrap(),
            format!("{:048}", 0).as_bytes()
        );
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &id1).unwrap(),
            format!("{:048}", 1).as_bytes()
        );

        let xml = build_azure_block_list_xml(&[id0.clone(), id1.clone()]);
        assert_eq!(
            xml,
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>{id0}</Latest><Latest>{id1}</Latest></BlockList>"
            )
        );

        let sas = url::Url::parse(
            "https://acct.blob.core.windows.net/attachments-v2/c1/a1?sv=2020-08-04&sig=abc%2B123",
        )
        .unwrap();
        let block_url = build_azure_block_url(&sas, &id0);
        let block_params: std::collections::HashMap<String, String> = block_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(block_params.get("comp").map(String::as_str), Some("block"));
        assert_eq!(
            block_params.get("blockid").map(String::as_str),
            Some(id0.as_str())
        );
        assert_eq!(
            block_params.get("sv").map(String::as_str),
            Some("2020-08-04")
        );
        assert_eq!(block_params.get("sig").map(String::as_str), Some("abc+123"));

        let list_url = build_azure_block_list_url(&sas);
        let list_params: std::collections::HashMap<String, String> = list_url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            list_params.get("comp").map(String::as_str),
            Some("blocklist")
        );
        assert_eq!(list_params.get("sig").map(String::as_str), Some("abc+123"));
    }

    struct MockAzureReq {
        method: String,
        target: String,
        headers: std::collections::HashMap<String, String>,
        body: Vec<u8>,
    }

    fn read_mock_http(stream: &mut std::net::TcpStream) -> MockAzureReq {
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap().to_string();
        let target = parts.next().unwrap().to_string();
        let mut headers = std::collections::HashMap::new();
        let mut len = 0usize;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().to_string();
                if key == "content-length" {
                    len = val.parse().unwrap();
                }
                headers.insert(key, val);
            }
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).unwrap();
        MockAzureReq {
            method,
            target,
            headers,
            body,
        }
    }

    #[test]
    fn test_upload_attachment_azure_single_put_and_zero_auth_header() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let req = read_mock_http(&mut stream);
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            req
        });

        let api_client =
            BitwardenApiClient::for_attachment_upload(&format!("http://{addr}"), None).unwrap();
        let sas_url = format!(
            "http://{addr}/attachments-v2/c1/a1?sv=2020-08-04&se=2099-01-01T00%3A00%3A00Z&sig=ok"
        );
        let payload = vec![0x02, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut renew_calls = 0usize;

        upload_attachment_azure_with_config(
            &api_client,
            &sas_url,
            &payload,
            AzureUploadConfig {
                single_put_max_bytes: 64,
                block_size_bytes: 32,
                sas_renewal_margin_secs: 5,
                allow_loopback_http: true,
            },
            || {
                renew_calls += 1;
                Ok(sas_url.clone())
            },
        )
        .unwrap();

        let req = server.join().unwrap();
        assert_eq!(renew_calls, 0);
        assert_eq!(req.method, "PUT");
        assert_eq!(
            req.headers.get("x-ms-blob-type").map(String::as_str),
            Some("BlockBlob")
        );
        assert_eq!(
            req.headers.get("x-ms-version").map(String::as_str),
            Some("2020-08-04")
        );
        assert!(req.headers.contains_key("x-ms-date"));
        assert!(
            !req.headers.contains_key("authorization"),
            "Authorization header MUST NEVER be sent to Azure"
        );
        assert_eq!(req.body, payload);
    }

    #[test]
    fn test_upload_attachment_azure_multiblock_reassembly_and_sas_renewal() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut reqs = Vec::new();
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                let req = read_mock_http(&mut stream);
                stream
                    .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
                reqs.push(req);
            }
            reqs
        });

        let api_client =
            BitwardenApiClient::for_attachment_upload(&format!("http://{addr}"), None).unwrap();
        // Start with an already-expired SAS URL to trigger immediate renewal before block 0
        let expired_sas = format!(
            "http://{addr}/attachments-v2/c1/a1?sv=2020-08-04&se=2020-01-01T00%3A00%3A00Z&sig=old"
        );
        let fresh_sas = format!(
            "http://{addr}/attachments-v2/c1/a1?sv=2020-08-04&se=2099-01-01T00%3A00%3A00Z&sig=renewed"
        );
        let payload: Vec<u8> = (0u8..100).collect();
        let mut renew_calls = 0usize;

        upload_attachment_azure_with_config(
            &api_client,
            &expired_sas,
            &payload,
            AzureUploadConfig {
                single_put_max_bytes: 64,
                block_size_bytes: 30,
                sas_renewal_margin_secs: 5,
                allow_loopback_http: true,
            },
            || {
                renew_calls += 1;
                Ok(fresh_sas.clone())
            },
        )
        .unwrap();

        let reqs = server.join().unwrap();
        assert_eq!(renew_calls, 1);
        assert_eq!(reqs.len(), 5);

        // Verify 4 sequential comp=block PUTs with renewed SAS and zero Authorization header
        let mut blocks = std::collections::HashMap::new();
        for (idx, req) in reqs[..4].iter().enumerate() {
            assert_eq!(req.method, "PUT");
            assert!(!req.headers.contains_key("authorization"));
            assert!(!req.headers.contains_key("x-ms-blob-type"));
            let parsed = Url::parse(&format!("http://{addr}{}", req.target)).unwrap();
            let params: std::collections::HashMap<String, String> = parsed
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            assert_eq!(params.get("comp").map(String::as_str), Some("block"));
            assert_eq!(params.get("sig").map(String::as_str), Some("renewed"));
            let bid = params.get("blockid").unwrap().clone();
            assert_eq!(bid, azure_block_id(idx));
            blocks.insert(bid, req.body.clone());
        }

        // Verify final comp=blocklist commit and reassemble blocks in committed XML order
        let commit = &reqs[4];
        assert_eq!(commit.method, "PUT");
        assert!(!commit.headers.contains_key("authorization"));
        let commit_url = Url::parse(&format!("http://{addr}{}", commit.target)).unwrap();
        assert!(commit_url
            .query_pairs()
            .any(|(k, v)| k == "comp" && v == "blocklist"));
        let xml = String::from_utf8(commit.body.clone()).unwrap();
        let expected_ids: Vec<String> = (0..4).map(azure_block_id).collect();
        assert_eq!(xml, build_azure_block_list_xml(&expected_ids));

        let mut reassembled = Vec::new();
        for bid in &expected_ids {
            reassembled.extend_from_slice(blocks.get(bid).unwrap());
        }
        assert_eq!(reassembled, payload);
    }

    #[test]
    fn test_upload_attachment_azure_rejects_renewed_non_https_url_fail_closed() {
        let api_client =
            BitwardenApiClient::for_attachment_upload("http://127.0.0.1:9", None).unwrap();
        let expired_sas =
            "http://127.0.0.1:9/attachments-v2/c1/a1?sv=2020-08-04&se=2020-01-01T00%3A00%3A00Z";
        let err = upload_attachment_azure_with_config(
            &api_client,
            expired_sas,
            b"secret",
            AzureUploadConfig {
                single_put_max_bytes: 64,
                block_size_bytes: 32,
                sas_renewal_margin_secs: 5,
                allow_loopback_http: true,
            },
            || Ok("http://evil.example.com/attachments-v2/c1/a1?sig=bad".to_string()),
        )
        .unwrap_err();
        assert!(
            err.contains("Refusing insecure non-HTTPS Azure"),
            "Unexpected error: {err}"
        );
    }
}
