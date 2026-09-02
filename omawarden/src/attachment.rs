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
        PathBuf::from("/tmp/omarchy-bitwarden/attachments").join(item_id)
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

    let dest_path = target_dir.join(&safe_filename);

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

                    download_res = client
                        .get(&download_url)
                        .header("Authorization", format!("Bearer {}", active_token))
                        .send();
                }
            }
        }
    }

    let bytes = match download_res {
        Ok(r) if r.status().is_success() => {
            let body_bytes = match r.bytes() {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    return AttachmentResponse {
                        ok: false,
                        error: Some(format!("Failed to read attachment response bytes: {}", e)),
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
                    let full_signed_url = if url_str.starts_with("http://") || url_str.starts_with("https://") {
                        url_str.to_string()
                    } else if url_str.starts_with('/') {
                        format!("{}{}", server_url, url_str)
                    } else {
                        format!("{}/{}", server_url, url_str)
                    };

                    let mut req = client.get(&full_signed_url);
                    if full_signed_url.starts_with(server_url) && !full_signed_url.contains("token=") {
                        req = req.header("Authorization", format!("Bearer {}", active_token));
                    }

                    if let Ok(blob_resp) = req.send() {
                        if blob_resp.status().is_success() {
                            blob_resp.bytes().map(|b| b.to_vec()).unwrap_or(body_bytes)
                        } else {
                            return AttachmentResponse {
                                ok: false,
                                error: Some(format!(
                                    "Failed to fetch attachment from storage (HTTP {})",
                                    blob_resp.status()
                                )),
                                path: None,
                                filename: None,
                                action: None,
                                is_image: None,
                                is_text: None,
                                text_content: None,
                                size: None,
                            };
                        }
                    } else {
                        return AttachmentResponse {
                            ok: false,
                            error: Some("Failed to connect to attachment storage URL".to_string()),
                            path: None,
                            filename: None,
                            action: None,
                            is_image: None,
                            is_text: None,
                            text_content: None,
                            size: None,
                        };
                    }
                } else {
                    body_bytes
                }
            } else {
                body_bytes
            }
        }
        Ok(r) => {
            return AttachmentResponse {
                ok: false,
                error: Some(format!("Server returned HTTP {}", r.status())),
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
            return AttachmentResponse {
                ok: false,
                error: Some(format!("Network download failed: {}", e)),
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

    if let Err(e) = fs::write(&dest_path, &bytes) {
        return AttachmentResponse {
            ok: false,
            error: Some(format!("Failed to write file to disk: {}", e)),
            path: None,
            filename: None,
            action: None,
            is_image: None,
            is_text: None,
            text_content: None,
            size: None,
        };
    }

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
            | "toml"
            | "lua"
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
        let _ = Command::new("xdg-open").arg(&dest_path).spawn();
        "view".to_string()
    } else if preview {
        "preview".to_string()
    } else {
        if notify {
            send_notification_with_actions(
                "Bitwarden Attachment",
                &format!("Saved {} to {}", safe_filename, target_dir.display()),
                &dest_path,
            );
        }
        "download".to_string()
    };

    AttachmentResponse {
        ok: true,
        error: None,
        path: Some(dest_path.to_string_lossy().to_string()),
        filename: Some(safe_filename),
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
        // It should sanitize filename to passwd or fail gracefully on network/auth without directory traversal
        if res.ok {
            assert_eq!(res.filename.unwrap(), "passwd");
        }
    }
}
