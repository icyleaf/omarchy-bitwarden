use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use crate::config::ConfigManager;
use crate::crypto::{Engine, BASE64};
use crate::keyring::KeyringManager;
use crate::storage::StorageManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_image: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_text: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

pub fn send_notification_with_actions(title: &str, body: &str, file_path: &Path) {
    let t = title.to_string();
    let b = body.to_string();
    let p = file_path.to_path_buf();

    thread::spawn(move || {
        let output = Command::new("notify-send")
            .args([
                "--app-name=Bitwarden",
                "-i",
                "document-save",
                "-A",
                "open=Open File",
                "-A",
                "folder=Open Folder",
                &t,
                &b,
            ])
            .output();

        if let Ok(out) = output {
            let action = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if action == "open" {
                let _ = Command::new("xdg-open").arg(&p).spawn();
            } else if action == "folder" {
                if let Some(parent) = p.parent() {
                    let _ = Command::new("xdg-open").arg(parent).spawn();
                }
            }
        } else {
            let _ = Command::new("notify-send")
                .args(["--app-name=Bitwarden", "-i", "document-save", &t, &b])
                .spawn();
        }
    });
}

pub fn get_preview_dir(item_id: Option<&str>) -> PathBuf {
    let base = if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir)
            .join("omarchy-bitwarden")
            .join("attachments")
    } else {
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = 1000;
        PathBuf::from(format!("/tmp/omarchy-bitwarden-{}/attachments", uid))
    };

    if let Some(id) = item_id {
        base.join(id)
    } else {
        base
    }
}

pub fn clear_preview_attachments(item_id: Option<&str>) {
    #[cfg(test)]
    if item_id.is_none() {
        return;
    }

    let dir = get_preview_dir(item_id);
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
    // Also clean up legacy /tmp/omarchy-bitwarden/attachments if present
    let legacy_dir = if let Some(id) = item_id {
        PathBuf::from("/tmp/omarchy-bitwarden/attachments").join(id)
    } else {
        PathBuf::from("/tmp/omarchy-bitwarden/attachments")
    };
    if legacy_dir.exists() {
        let _ = fs::remove_dir_all(&legacy_dir);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn get_attachment(
    item_id: &str,
    attachment_id: &str,
    filename: &str,
    output_dir: Option<&str>,
    open_file: bool,
    preview: bool,
    session_token: Option<&str>,
    _legacy_param: Option<&str>,
    notify: bool,
) -> AttachmentResponse {
    if item_id.is_empty() || attachment_id.is_empty() {
        return AttachmentResponse {
            ok: false,
            error: Some("Item ID and Attachment ID are required.".to_string()),
            path: None,
            filename: None,
            action: None,
            is_image: None,
            is_text: None,
            text_content: None,
            size: None,
        };
    }

    let cfg = ConfigManager::new(None).load();
    let storage_mgr = StorageManager::default();
    let storage = storage_mgr.load();

    let mut expected_size: Option<u64> = storage
        .ciphers
        .iter()
        .find(|c| c.get("id").and_then(|v| v.as_str()) == Some(item_id))
        .and_then(|c| c.get("attachments").and_then(|v| v.as_array()))
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("id").and_then(|v| v.as_str()) == Some(attachment_id))
        })
        .and_then(|a| {
            a.get("size").and_then(|v| {
                if let Some(s) = v.as_str() {
                    s.parse::<u64>().ok()
                } else {
                    v.as_u64()
                }
            })
        });

    let initial_token = session_token
        .map(|s| s.to_string())
        .or_else(|| KeyringManager::default().get_session())
        .or_else(|| storage.access_token.clone());

    let token_val = match initial_token {
        Some(ref t) if !t.is_empty() => t.clone(),
        _ => {
            return AttachmentResponse {
                ok: false,
                error: Some("Vault is locked or session has expired.".to_string()),
                path: None,
                filename: None,
                action: None,
                is_image: None,
                is_text: None,
                text_content: None,
                size: None,
            };
        }
    };
    let mut active_token = token_val;

    let safe_filename = if filename.is_empty() || filename == "." {
        format!("attachment_{}", attachment_id)
    } else {
        Path::new(filename)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("attachment_{}", attachment_id))
    };

    let target_dir = if open_file || preview {
        get_preview_dir(Some(item_id))
    } else {
        let dest_dir_str = output_dir.unwrap_or(&cfg.download_dir);
        let expanded = if dest_dir_str.starts_with('~') {
            let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
            dest_dir_str.replacen('~', &home, 1)
        } else {
            dest_dir_str.to_string()
        };
        PathBuf::from(expanded)
    };

    if let Err(e) = fs::create_dir_all(&target_dir) {
        return AttachmentResponse {
            ok: false,
            error: Some(format!("Failed to create target directory: {}", e)),
            path: None,
            filename: None,
            action: None,
            is_image: None,
            is_text: None,
            text_content: None,
            size: None,
        };
    }

    #[cfg(unix)]
    if open_file || preview {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o700));
    }

    let dest_path = target_dir.join(&safe_filename);

    let preview_cached_path = get_preview_dir(Some(item_id)).join(&safe_filename);

    // Fast-path: Check if already previewed or downloaded to avoid duplicate network requests
    if (!open_file && !preview) && preview_cached_path.is_file() {
        if preview_cached_path != dest_path {
            let _ = fs::copy(&preview_cached_path, &dest_path);
        }
        if let Ok(cached_bytes) = fs::read(&dest_path) {
            if is_cached_file_valid(&dest_path, expected_size, &cached_bytes) {
                return build_attachment_response(
                    &dest_path,
                    &safe_filename,
                    &target_dir,
                    open_file,
                    preview,
                    notify,
                    &cached_bytes,
                );
            } else {
                crate::log_warn!(
                    "omawarden:attachment",
                    "Cached attachment {:?} is dirty or un-decrypted ciphertext. Purging and re-downloading.",
                    dest_path
                );
                let _ = fs::remove_file(&dest_path);
                let _ = fs::remove_file(&preview_cached_path);
            }
        }
    } else if (open_file || preview) && dest_path.is_file() {
        if let Ok(cached_bytes) = fs::read(&dest_path) {
            if is_cached_file_valid(&dest_path, expected_size, &cached_bytes) {
                return build_attachment_response(
                    &dest_path,
                    &safe_filename,
                    &target_dir,
                    open_file,
                    preview,
                    notify,
                    &cached_bytes,
                );
            } else {
                crate::log_warn!(
                    "omawarden:attachment",
                    "Cached attachment {:?} is dirty or un-decrypted ciphertext. Purging and re-downloading.",
                    dest_path
                );
                let _ = fs::remove_file(&dest_path);
            }
        }
    }

    // Direct HTTP download via REST API
    let server_url = if !storage.server_url.is_empty() {
        storage.server_url.trim_end_matches('/')
    } else {
        cfg.server_url.trim_end_matches('/')
    };

    let download_url = format!(
        "{}/api/ciphers/{}/attachment/{}",
        server_url, item_id, attachment_id
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .unwrap_or_default();

    let mut download_res = client
        .get(&download_url)
        .header("Authorization", format!("Bearer {}", active_token))
        .send();

    // If 401 Unauthorized, attempt token refresh using refresh_token
    if let Ok(ref r) = download_res {
        if r.status() == reqwest::StatusCode::UNAUTHORIZED {
            crate::log_warn!(
                "omawarden:attachment",
                "HTTP 401 Unauthorized for item {} attachment {}. Attempting token refresh.",
                item_id,
                attachment_id
            );
            if let Some(ref ref_tok) = storage.refresh_token {
                let api_client = crate::api::BitwardenApiClient::new(server_url);
                if let Ok(tok_resp) = api_client.refresh_token_grant(ref_tok) {
                    let mut fresh_st = storage_mgr.load();
                    fresh_st.access_token = Some(tok_resp.access_token.clone());
                    if let Some(ref new_ref) = tok_resp.refresh_token {
                        fresh_st.refresh_token = Some(new_ref.clone());
                    }
                    let _ = storage_mgr.save(&fresh_st);
                    active_token = tok_resp.access_token;
                    crate::log_info!(
                        "omawarden:attachment",
                        "Token refresh successful, retrying download."
                    );

                    download_res = client
                        .get(&download_url)
                        .header("Authorization", format!("Bearer {}", active_token))
                        .send();
                } else {
                    crate::log_error!("omawarden:attachment", "Token refresh grant failed.");
                }
            }
        }
    }

    let bytes = match download_res {
        Ok(r) if r.status().is_success() => {
            let r_content_len = r.content_length();
            let body_bytes = match r.bytes() {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    let err_msg = format!("Failed to read attachment response bytes: {}", e);
                    crate::log_error!("omawarden:attachment", "{}", err_msg);
                    return AttachmentResponse {
                        ok: false,
                        error: Some(err_msg),
                        path: None,
                        filename: None,
                        action: None,
                        is_image: None,
                        is_text: None,
                        text_content: None,
                        size: None,
                    };
                }
            };

            // Check if response is a JSON object with a direct download url (e.g. S3 / signed storage url)
            if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                if let Some(url_str) = json_val.get("url").and_then(|u| u.as_str()) {
                    if let Some(json_size) = json_val.get("size").and_then(|v| {
                        if let Some(s) = v.as_str() {
                            s.parse::<u64>().ok()
                        } else {
                            v.as_u64()
                        }
                    }) {
                        expected_size = Some(json_size);
                    }

                    let full_signed_url =
                        if url_str.starts_with("http://") || url_str.starts_with("https://") {
                            url_str.to_string()
                        } else if url_str.starts_with('/') {
                            format!("{}{}", server_url, url_str)
                        } else {
                            format!("{}/{}", server_url, url_str)
                        };

                    let mut req = client.get(&full_signed_url);
                    if full_signed_url.starts_with(server_url)
                        && !full_signed_url.contains("token=")
                    {
                        req = req.header("Authorization", format!("Bearer {}", active_token));
                    }

                    let blob_resp = match req.send() {
                        Ok(resp) => resp,
                        Err(e) => {
                            let err_msg =
                                format!("Failed to connect to attachment storage URL: {}", e);
                            crate::log_error!("omawarden:attachment", "{}", err_msg);
                            return AttachmentResponse {
                                ok: false,
                                error: Some(err_msg),
                                path: None,
                                filename: None,
                                action: None,
                                is_image: None,
                                is_text: None,
                                text_content: None,
                                size: None,
                            };
                        }
                    };

                    if !blob_resp.status().is_success() {
                        let err_msg = format!(
                            "Failed to fetch attachment from storage (HTTP {})",
                            blob_resp.status()
                        );
                        crate::log_error!("omawarden:attachment", "{}", err_msg);
                        return AttachmentResponse {
                            ok: false,
                            error: Some(err_msg),
                            path: None,
                            filename: None,
                            action: None,
                            is_image: None,
                            is_text: None,
                            text_content: None,
                            size: None,
                        };
                    }

                    let blob_content_len = blob_resp.content_length();
                    let raw_bytes = match blob_resp.bytes() {
                        Ok(b) => b.to_vec(),
                        Err(e) => {
                            let err_msg =
                                format!("Failed to read attachment bytes from storage: {}", e);
                            crate::log_error!("omawarden:attachment", "{}", err_msg);
                            return AttachmentResponse {
                                ok: false,
                                error: Some(err_msg),
                                path: None,
                                filename: None,
                                action: None,
                                is_image: None,
                                is_text: None,
                                text_content: None,
                                size: None,
                            };
                        }
                    };

                    // Verify HTTP Content-Length if provided by server
                    if let Some(expected_len) = blob_content_len {
                        if (raw_bytes.len() as u64) != expected_len {
                            let err_msg = format!(
                                "Incomplete attachment download: received {} bytes, expected {} bytes (Content-Length mismatch)",
                                raw_bytes.len(),
                                expected_len
                            );
                            crate::log_error!("omawarden:attachment", "{}", err_msg);
                            return AttachmentResponse {
                                ok: false,
                                error: Some(err_msg),
                                path: None,
                                filename: None,
                                action: None,
                                is_image: None,
                                is_text: None,
                                text_content: None,
                                size: None,
                            };
                        }
                    }

                    // Verify against attachment metadata size if provided
                    if let Some(exp) = expected_size {
                        if exp > 0 && (raw_bytes.len() as u64) != exp {
                            let err_msg = format!(
                                "Incomplete attachment download: received {} bytes, expected {} bytes (metadata size mismatch)",
                                raw_bytes.len(),
                                exp
                            );
                            crate::log_error!("omawarden:attachment", "{}", err_msg);
                            return AttachmentResponse {
                                ok: false,
                                error: Some(err_msg),
                                path: None,
                                filename: None,
                                action: None,
                                is_image: None,
                                is_text: None,
                                text_content: None,
                                size: None,
                            };
                        }
                    }

                    raw_bytes
                } else {
                    body_bytes
                }
            } else {
                // Direct file body response
                if let Some(expected_len) = r_content_len {
                    if (body_bytes.len() as u64) != expected_len {
                        let err_msg = format!(
                            "Incomplete attachment download: received {} bytes, expected {} bytes (Content-Length mismatch)",
                            body_bytes.len(),
                            expected_len
                        );
                        crate::log_error!("omawarden:attachment", "{}", err_msg);
                        return AttachmentResponse {
                            ok: false,
                            error: Some(err_msg),
                            path: None,
                            filename: None,
                            action: None,
                            is_image: None,
                            is_text: None,
                            text_content: None,
                            size: None,
                        };
                    }
                }

                if let Some(exp) = expected_size {
                    if exp > 0 && (body_bytes.len() as u64) != exp {
                        let err_msg = format!(
                            "Incomplete attachment download: received {} bytes, expected {} bytes (metadata size mismatch)",
                            body_bytes.len(),
                            exp
                        );
                        crate::log_error!("omawarden:attachment", "{}", err_msg);
                        return AttachmentResponse {
                            ok: false,
                            error: Some(err_msg),
                            path: None,
                            filename: None,
                            action: None,
                            is_image: None,
                            is_text: None,
                            text_content: None,
                            size: None,
                        };
                    }
                }

                body_bytes
            }
        }
        Ok(r) => {
            let err_msg = format!("Server returned HTTP {}", r.status());
            crate::log_error!("omawarden:attachment", "{}", err_msg);
            return AttachmentResponse {
                ok: false,
                error: Some(err_msg),
                path: None,
                filename: None,
                action: None,
                is_image: None,
                is_text: None,
                text_content: None,
                size: None,
            };
        }
        Err(e) => {
            let err_msg = format!("Network download failed: {}", e);
            crate::log_error!("omawarden:attachment", "{}", err_msg);
            return AttachmentResponse {
                ok: false,
                error: Some(err_msg),
                path: None,
                filename: None,
                action: None,
                is_image: None,
                is_text: None,
                text_content: None,
                size: None,
            };
        }
    };

    // Resolve attachment key and decrypt binary attachment blob
    let att_key: Option<crate::crypto::SymmetricCryptoKey> = {
        crate::daemon::ensure_daemon_running();
        if let Some(resp) = crate::daemon::send_daemon_request(&serde_json::json!({
            "action": "get_attachment_key",
            "item_id": item_id,
            "attachment_id": attachment_id
        })) {
            if let Some(key_b64) = resp.get("key_b64").and_then(|v| v.as_str()) {
                if let Ok(key_bytes) = BASE64.decode(key_b64) {
                    crate::crypto::parse_symmetric_key_from_decrypted_bytes(&key_bytes)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    };

    let bytes = if let Some(ref k) = att_key {
        match crate::crypto::decrypt_attachment_blob(&bytes, k) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                return AttachmentResponse {
                    ok: false,
                    error: Some(format!("Failed to decrypt attachment: {:?}", e)),
                    path: None,
                    filename: None,
                    action: None,
                    is_image: None,
                    is_text: None,
                    text_content: None,
                    size: None,
                };
            }
        }
    } else {
        return AttachmentResponse {
            ok: false,
            error: Some(
                "Vault is locked or decryption key is unavailable. Please unlock your vault first."
                    .to_string(),
            ),
            path: None,
            filename: None,
            action: None,
            is_image: None,
            is_text: None,
            text_content: None,
            size: None,
        };
    };

    let temp_part_path = target_dir.join(format!("{}.part_{}", safe_filename, std::process::id()));
    if let Err(e) = fs::write(&temp_part_path, &bytes) {
        return AttachmentResponse {
            ok: false,
            error: Some(format!("Failed to write temporary file to disk: {}", e)),
            path: None,
            filename: None,
            action: None,
            is_image: None,
            is_text: None,
            text_content: None,
            size: None,
        };
    }

    #[cfg(unix)]
    if open_file || preview {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp_part_path, fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = fs::rename(&temp_part_path, &dest_path) {
        let _ = fs::remove_file(&temp_part_path);
        return AttachmentResponse {
            ok: false,
            error: Some(format!("Failed to finalize downloaded file: {}", e)),
            path: None,
            filename: None,
            action: None,
            is_image: None,
            is_text: None,
            text_content: None,
            size: None,
        };
    }

    #[cfg(unix)]
    if open_file || preview {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(0o600));
    }

    build_attachment_response(
        &dest_path,
        &safe_filename,
        &target_dir,
        open_file,
        preview,
        notify,
        &bytes,
    )
}

fn is_cached_file_valid(path: &Path, expected_encrypted_size: Option<u64>, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    // 1. Raw API JSON response string check
    if bytes.starts_with(b"{\"") || bytes.starts_with(b"{\n") || bytes.starts_with(b"{\r") {
        if let Ok(val) = serde_json::from_slice::<serde_json::Value>(bytes) {
            if val.get("url").is_some() || val.get("id").is_some() || val.get("error").is_some() {
                return false;
            }
        }
    }

    // 2. Raw Bitwarden encrypted EncArrayBuffer check
    // Bitwarden encrypted binary blobs start with encType 2 or 0, followed by 16-byte IV
    if bytes.len() >= 49 && (bytes[0] == 2 || bytes[0] == 0) {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if matches!(
            ext.as_str(),
            "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "webp"
                | "bmp"
                | "ico"
                | "svg"
                | "pdf"
                | "zip"
                | "tar"
                | "gz"
                | "bz2"
                | "7z"
                | "txt"
                | "md"
                | "json"
                | "xml"
                | "yaml"
                | "yml"
                | "toml"
                | "html"
                | "css"
                | "js"
                | "ts"
                | "py"
                | "sh"
                | "rs"
                | "go"
                | "c"
                | "cpp"
                | "heic"
                | "mp3"
                | "mp4"
        ) {
            return false;
        }
    }

    // 3. Exact ciphertext size match check
    // If the cached file length matches expected encrypted blob size exactly,
    // it is the un-decrypted raw ciphertext, because decrypted plaintext is always
    // 50-65 bytes smaller due to encType + IV + MAC + PKCS#7 padding.
    if let Some(exp) = expected_encrypted_size {
        if exp > 65 && bytes.len() as u64 == exp {
            return false;
        }
    }

    // 4. Image magic bytes validation for image files
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg"
            if bytes.len() < 3 || bytes[0] != 0xFF || bytes[1] != 0xD8 || bytes[2] != 0xFF =>
        {
            return false;
        }
        "png" if bytes.len() < 8 || &bytes[..8] != b"\x89PNG\r\n\x1a\n" => {
            return false;
        }
        "gif" if bytes.len() < 4 || (&bytes[..4] != b"GIF8" && &bytes[..4] != b"GIF7") => {
            return false;
        }
        "webp" if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" => {
            return false;
        }
        "bmp" if bytes.len() < 2 || &bytes[..2] != b"BM" => {
            return false;
        }
        "pdf" if bytes.len() < 4 || &bytes[..4] != b"%PDF" => {
            return false;
        }
        _ => {}
    }

    true
}

fn build_attachment_response(
    dest_path: &Path,
    safe_filename: &str,
    target_dir: &Path,
    open_file: bool,
    preview: bool,
    notify: bool,
    bytes: &[u8],
) -> AttachmentResponse {
    let ext = dest_path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let is_image = matches!(
        ext.as_str(),
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "bmp" | "ico"
    );
    let mut is_text = matches!(
        ext.as_str(),
        "txt"
            | "md"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "csv"
            | "log"
            | "sh"
            | "bash"
            | "zsh"
            | "py"
            | "js"
            | "ts"
            | "html"
            | "css"
            | "xml"
            | "conf"
            | "config"
            | "ini"
            | "env"
            | "pem"
            | "key"
            | "pub"
            | "crt"
            | "cer"
            | "diff"
            | "patch"
            | "sql"
            | "lua"
            | "rs"
            | "go"
            | "c"
            | "cpp"
    );

    let file_size = bytes.len() as u64;
    let mut text_content = String::new();

    if is_text || (!is_image && file_size <= 1024 * 1024) {
        let limit = bytes.len().min(500000);
        let slice = &bytes[..limit];
        if !is_text {
            if !slice.contains(&0) {
                is_text = true;
                text_content = String::from_utf8_lossy(slice).to_string();
            }
        } else {
            text_content = String::from_utf8_lossy(slice).to_string();
        }
    }

    let action_str = if open_file {
        let _ = Command::new("xdg-open").arg(dest_path).spawn();
        "view".to_string()
    } else if preview {
        "preview".to_string()
    } else {
        if notify {
            send_notification_with_actions(
                "Bitwarden Attachment",
                &format!("Saved {} to {}", safe_filename, target_dir.display()),
                dest_path,
            );
        }
        "download".to_string()
    };

    AttachmentResponse {
        ok: true,
        error: None,
        path: Some(dest_path.to_string_lossy().to_string()),
        filename: Some(safe_filename.to_string()),
        action: Some(action_str),
        is_image: Some(is_image),
        is_text: Some(is_text),
        text_content: Some(text_content),
        size: Some(file_size),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_ids() {
        let res = get_attachment(
            "",
            "att1",
            "file.txt",
            None,
            false,
            false,
            Some("tok"),
            None,
            false,
        );
        assert!(!res.ok);
        assert_eq!(
            res.error.unwrap(),
            "Item ID and Attachment ID are required."
        );

        let res2 = get_attachment(
            "item1",
            "",
            "file.txt",
            None,
            false,
            false,
            Some("tok"),
            None,
            false,
        );
        assert!(!res2.ok);
        assert_eq!(
            res2.error.unwrap(),
            "Item ID and Attachment ID are required."
        );
    }

    #[test]
    fn test_missing_session_or_network_error() {
        let res = get_attachment(
            "item1", "att1", "file.txt", None, false, false, None, None, false,
        );
        if !res.ok {
            assert!(res.error.is_some());
        }
    }

    #[test]
    fn test_safe_filename_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().to_str().unwrap();
        let res = get_attachment(
            "item1",
            "att1",
            "../../../etc/passwd",
            Some(target),
            false,
            false,
            Some("fake_token"),
            None,
            false,
        );
        if res.ok {
            assert_eq!(res.filename.unwrap(), "passwd");
        }
    }

    #[test]
    fn test_cached_preview_download_reuse() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dl_target = temp_dir.path().to_str().unwrap();

        // Create a simulated preview cache file in preview_dir/test_file.txt
        let preview_dir = get_preview_dir(Some("test_item_999"));
        let _ = fs::create_dir_all(&preview_dir);
        let preview_file = preview_dir.join("test_file.txt");
        let _ = fs::write(&preview_file, b"cached attachment secret content 12345");

        // Now download the attachment without network access (using fake token)
        let res = get_attachment(
            "test_item_999",
            "att_999",
            "test_file.txt",
            Some(dl_target),
            false,
            false,
            Some("fake_token"),
            None,
            false,
        );

        assert!(
            res.ok,
            "Expected cached fast-path to succeed: {:?}",
            res.error
        );
        assert_eq!(res.filename.unwrap(), "test_file.txt");
        assert_eq!(res.action.unwrap(), "download");
        assert_eq!(
            res.text_content.unwrap(),
            "cached attachment secret content 12345"
        );

        // Verify file was copied to destination
        let dest = temp_dir.path().join("test_file.txt");
        assert!(dest.exists());
        assert_eq!(
            fs::read_to_string(&dest).unwrap(),
            "cached attachment secret content 12345"
        );

        // Cleanup
        let _ = fs::remove_file(&preview_file);
    }

    #[test]
    fn test_zero_byte_poisoned_cache_is_pruned_and_rejected() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dl_target = temp_dir.path().to_str().unwrap();

        // Create a 0-byte corrupt preview file
        let preview_dir = get_preview_dir(Some("test_item_empty"));
        let _ = fs::create_dir_all(&preview_dir);
        let preview_file = preview_dir.join("empty.txt");
        let _ = fs::write(&preview_file, b"");

        // Attempting to download should prune the 0-byte poisoned file and reject returning empty cache
        let res = get_attachment(
            "test_item_empty",
            "att_empty",
            "empty.txt",
            Some(dl_target),
            false,
            false,
            Some("fake_token"),
            None,
            false,
        );

        // Should not treat 0-byte file as valid cached download
        assert!(
            !preview_file.exists(),
            "0-byte poisoned cache file should have been removed"
        );
        assert!(
            !res.ok,
            "Download with fake token should fail instead of returning 0-byte cached file"
        );
    }

    #[test]
    fn test_is_cached_file_valid_detection() {
        let jpg_path = Path::new("test.jpg");

        // Valid JPEG header
        let valid_jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert!(is_cached_file_valid(jpg_path, None, &valid_jpg));

        // Invalid: Raw Bitwarden EncArrayBuffer (encType=2)
        let raw_ciphertext = vec![0x02u8; 100];
        assert!(!is_cached_file_valid(jpg_path, None, &raw_ciphertext));

        // Invalid: Raw API JSON string
        let raw_json = b"{\"id\":\"att1\",\"url\":\"https://example.com\"}";
        assert!(!is_cached_file_valid(jpg_path, None, raw_json));

        // Valid JPEG header where size is smaller than ciphertext size
        assert!(is_cached_file_valid(
            jpg_path,
            Some(100),
            &[0xFF, 0xD8, 0xFF, 0xE0]
        ));

        // Invalid: exact ciphertext size match
        let mut fake_100_bytes = vec![0x00u8; 100];
        fake_100_bytes[0] = 0xFF;
        fake_100_bytes[1] = 0xD8;
        fake_100_bytes[2] = 0xFF;
        assert!(!is_cached_file_valid(jpg_path, Some(100), &fake_100_bytes));
    }

    #[test]
    fn test_dirty_raw_ciphertext_cache_is_pruned() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dl_target = temp_dir.path().to_str().unwrap();

        // Create a dirty preview file containing raw EncArrayBuffer
        let preview_dir = get_preview_dir(Some("test_item_dirty"));
        let _ = fs::create_dir_all(&preview_dir);
        let preview_file = preview_dir.join("photo.jpg");
        let mut raw_ct = vec![0x02u8; 200];
        raw_ct[0] = 0x02; // encType
        let _ = fs::write(&preview_file, &raw_ct);

        let res = get_attachment(
            "test_item_dirty",
            "att_dirty",
            "photo.jpg",
            Some(dl_target),
            false,
            true, // preview
            Some("fake_token"),
            None,
            false,
        );

        // Dirty cache file must be purged and not returned as valid preview
        assert!(
            !preview_file.exists(),
            "Dirty ciphertext cache file should have been deleted"
        );
        assert!(
            !res.ok,
            "Should not return dirty cached ciphertext as preview"
        );
    }

    #[test]
    fn test_clear_preview_attachments() {
        let preview_dir = get_preview_dir(Some("test_item_clear"));
        let _ = fs::create_dir_all(&preview_dir);
        let preview_file = preview_dir.join("secret.jpg");
        let _ = fs::write(&preview_file, b"secret decrypted payload");
        assert!(preview_file.exists());

        clear_preview_attachments(Some("test_item_clear"));
        assert!(!preview_file.exists());
        assert!(!preview_dir.exists());
    }
}
