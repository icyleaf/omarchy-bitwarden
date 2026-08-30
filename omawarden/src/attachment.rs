use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use crate::config::ConfigManager;
use crate::keyring::KeyringManager;

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

pub fn get_attachment(
    item_id: &str,
    attachment_id: &str,
    filename: &str,
    output_dir: Option<&str>,
    open_file: bool,
    preview: bool,
    session_token: Option<&str>,
    bw_path: Option<&str>,
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
    let bw_bin = bw_path.unwrap_or(&cfg.bw_path);

    let token = session_token
        .map(|s| s.to_string())
        .or_else(|| KeyringManager::default().get_session());
    let token = match token {
        Some(t) if !t.is_empty() => t,
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

    let output = Command::new(bw_bin)
        .args([
            "get",
            "attachment",
            attachment_id,
            "--itemid",
            item_id,
            "--output",
            &dest_path.to_string_lossy(),
        ])
        .env("BW_SESSION", token)
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            return AttachmentResponse {
                ok: false,
                error: Some(format!("Failed to execute download command: {}", e)),
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

    if !output.status.success() {
        let err_raw = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let lower = err_raw.to_lowercase();
        let err_msg = if lower.contains("not found") {
            "Attachment not found on server.".to_string()
        } else if lower.contains("session") || lower.contains("unauthorized") {
            "Session expired. Please unlock your vault.".to_string()
        } else {
            let first = err_raw.trim().lines().next().unwrap_or("Failed to download attachment.");
            first.to_string()
        };

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

    if !dest_path.exists() {
        return AttachmentResponse {
            ok: false,
            error: Some("Downloaded file was not created on disk.".to_string()),
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

    let file_size = dest_path.metadata().map(|m| m.len()).unwrap_or(0);
    let mut text_content = String::new();

    if is_text || (!is_image && file_size <= 1024 * 1024) {
        if let Ok(bytes) = fs::read(&dest_path) {
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
