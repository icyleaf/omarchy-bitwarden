use regex::Regex;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use crate::health::resolve_executable;
use crate::keyring::KeyringManager;

pub const MAX_AUTH_OUTPUT_BYTES: usize = 5 * 1024 * 1024;

pub fn sanitize_auth_error(err_str: Option<&str>) -> String {
    let raw = match err_str {
        Some(s) if !s.trim().is_empty() => s,
        _ => return "Authentication operation failed.".to_string(),
    };

    let lower = raw.to_lowercase();
    if lower.contains("invalid")
        && (lower.contains("password") || lower.contains("username") || lower.contains("email"))
    {
        return "Invalid username, email, or master password.".to_string();
    }
    if lower.contains("decryption") || lower.contains("not the expected type") {
        return "Decryption failed. Incorrect master password.".to_string();
    }
    if lower.contains("two-step") || lower.contains("two-factor") || lower.contains("code") {
        return "Two-factor authentication required or invalid code.".to_string();
    }
    if lower.contains("already logged in") {
        return "Already logged in.".to_string();
    }
    if lower.contains("network")
        || lower.contains("failed to fetch")
        || lower.contains("econnrefused")
        || lower.contains("timeout")
    {
        return "Network error: unable to reach Bitwarden server.".to_string();
    }
    if lower.contains("vault is locked") {
        return "Vault is locked.".to_string();
    }

    let first_line = raw.lines().next().unwrap_or("").trim();
    let re = Regex::new(r"[A-Za-z0-9+/=_-]{20,}").unwrap();
    let redacted = re.replace_all(first_line, "[REDACTED]");
    let truncated: String = redacted.chars().take(120).collect();
    truncated.trim().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthStatus {
    pub status: String,
    pub server_url: Option<String>,
    pub last_sync: Option<String>,
    pub user_email: Option<String>,
    pub user_id: Option<String>,
    pub has_session: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResult {
    pub ok: bool,
    pub status: Option<String>,
    pub session: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct BwStatusJson {
    pub status: Option<String>,
    #[serde(rename = "serverUrl")]
    pub server_url: Option<String>,
    #[serde(rename = "lastSync")]
    pub last_sync: Option<String>,
    #[serde(rename = "userEmail")]
    pub user_email: Option<String>,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
}

pub struct AuthManager {
    pub bw_path: String,
    pub keyring_mgr: KeyringManager,
    pub max_output_bytes: usize,
}

impl AuthManager {
    pub fn new(
        bw_path: &str,
        keyring_mgr: Option<KeyringManager>,
        max_output_bytes: Option<usize>,
    ) -> Self {
        let resolved = resolve_executable(bw_path).unwrap_or_else(|| bw_path.to_string());
        Self {
            bw_path: resolved,
            keyring_mgr: keyring_mgr.unwrap_or_default(),
            max_output_bytes: max_output_bytes.unwrap_or(MAX_AUTH_OUTPUT_BYTES),
        }
    }

    pub fn verify_session(&self, session_token: &str) -> bool {
        if session_token.is_empty() {
            return false;
        }
        let status = Command::new(&self.bw_path)
            .arg("sync")
            .env("BW_SESSION", session_token)
            .status();
        match status {
            Ok(s) => s.success(),
            Err(_) => false,
        }
    }

    pub fn get_status(&self, verify: bool) -> AuthStatus {
        let mut session = self.keyring_mgr.get_session();
        let output = Command::new(&self.bw_path).arg("status").output();

        if let Ok(out) = output {
            if out.status.success() && !out.stdout.is_empty() {
                let limit = out.stdout.len().min(self.max_output_bytes);
                let slice = &out.stdout[..limit];
                if let Ok(data) = serde_json::from_slice::<BwStatusJson>(slice) {
                    let mut status_val = data.status.unwrap_or_else(|| "unauthenticated".to_string());
                    if session.is_some() && status_val != "unauthenticated" {
                        if verify {
                            if !self.verify_session(session.as_deref().unwrap_or_default()) {
                                self.keyring_mgr.clear_session();
                                session = None;
                                status_val = "locked".to_string();
                            } else {
                                status_val = "unlocked".to_string();
                            }
                        } else {
                            status_val = "unlocked".to_string();
                        }
                    }
                    return AuthStatus {
                        status: status_val,
                        server_url: data.server_url,
                        last_sync: data.last_sync,
                        user_email: data.user_email,
                        user_id: data.user_id,
                        has_session: session.is_some(),
                    };
                }
            }
        }

        let fallback_status = if session.is_some() {
            "unlocked"
        } else {
            "unauthenticated"
        };
        AuthStatus {
            status: fallback_status.to_string(),
            server_url: None,
            last_sync: None,
            user_email: None,
            user_id: None,
            has_session: session.is_some(),
        }
    }

    pub fn login_password(
        &self,
        email: &str,
        password: &str,
        code: Option<&str>,
    ) -> AuthResult {
        let mut child = match Command::new(&self.bw_path)
            .args(["login", email, "--passwordfile", "/proc/self/fd/0", "--raw"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                }
            }
        };

        let mut input_data = Zeroizing::new(format!("{}\n", password));
        if let Some(c) = code {
            input_data.push_str(&format!("{}\n", c));
        }

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input_data.as_bytes());
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                }
            }
        };

        if output.status.success() {
            let session = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !session.is_empty() {
                self.keyring_mgr.store_session(&session);
            }
            AuthResult {
                ok: true,
                status: Some("unlocked".to_string()),
                session: Some(session),
                error: None,
            }
        } else {
            let err_raw = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
            AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some(sanitize_auth_error(Some(&err_raw))),
            }
        }
    }

    pub fn login_apikey(&self, client_id: &str, client_secret: &str) -> AuthResult {
        let mut child = match Command::new(&self.bw_path)
            .args(["login", "--apikey"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                }
            }
        };

        let input_data = Zeroizing::new(format!("{}\n{}\n", client_id, client_secret));
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input_data.as_bytes());
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("unauthenticated".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                }
            }
        };

        if output.status.success() {
            AuthResult {
                ok: true,
                status: Some("locked".to_string()),
                session: None,
                error: None,
            }
        } else {
            let err_raw = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
            AuthResult {
                ok: false,
                status: Some("unauthenticated".to_string()),
                session: None,
                error: Some(sanitize_auth_error(Some(&err_raw))),
            }
        }
    }

    pub fn unlock(&self, password: &str) -> AuthResult {
        let mut child = match Command::new(&self.bw_path)
            .args(["unlock", "--passwordfile", "/proc/self/fd/0", "--raw"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("locked".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                }
            }
        };

        let input_data = Zeroizing::new(format!("{}\n", password));
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input_data.as_bytes());
        }

        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                return AuthResult {
                    ok: false,
                    status: Some("locked".to_string()),
                    session: None,
                    error: Some(sanitize_auth_error(Some(&e.to_string()))),
                }
            }
        };

        if output.status.success() {
            let session = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !session.is_empty() {
                self.keyring_mgr.store_session(&session);
            }
            AuthResult {
                ok: true,
                status: Some("unlocked".to_string()),
                session: Some(session),
                error: None,
            }
        } else {
            let err_raw = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
            AuthResult {
                ok: false,
                status: Some("locked".to_string()),
                session: None,
                error: Some(sanitize_auth_error(Some(&err_raw))),
            }
        }
    }

    pub fn lock(&self) -> AuthResult {
        self.keyring_mgr.clear_session();
        let _ = Command::new(&self.bw_path).arg("lock").output();
        AuthResult {
            ok: true,
            status: Some("locked".to_string()),
            session: None,
            error: None,
        }
    }

    pub fn logout(&self) -> AuthResult {
        self.keyring_mgr.clear_session();
        let _ = Command::new(&self.bw_path).arg("logout").output();
        AuthResult {
            ok: true,
            status: Some("unauthenticated".to_string()),
            session: None,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn test_sanitize_auth_error_patterns() {
        assert_eq!(
            sanitize_auth_error(Some("Invalid password")),
            "Invalid username, email, or master password."
        );
        assert_eq!(
            sanitize_auth_error(Some("Decryption failed on item cipher")),
            "Decryption failed. Incorrect master password."
        );
        assert_eq!(
            sanitize_auth_error(Some("Two-factor code required")),
            "Two-factor authentication required or invalid code."
        );
        assert_eq!(
            sanitize_auth_error(Some("Already logged in")),
            "Already logged in."
        );
        assert_eq!(
            sanitize_auth_error(Some("network error ECONNREFUSED")),
            "Network error: unable to reach Bitwarden server."
        );
        assert_eq!(
            sanitize_auth_error(Some("Vault is locked")),
            "Vault is locked."
        );
        assert_eq!(
            sanitize_auth_error(Some("Random error with token a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6")),
            "Random error with token [REDACTED]"
        );
    }

    #[test]
    fn test_mock_auth_unlock_and_lock() {
        let dir = tempdir().unwrap();
        let session_file = dir.path().join("session.txt");
        let bw_script = dir.path().join("mock-bw");
        let secret_tool_script = dir.path().join("mock-secret-tool");

        // Mock secret tool
        let secret_tool_code = format!(
            r#"#!/bin/sh
SF="{}"
case "$1" in
    store)
        cat > "$SF"
        exit 0
        ;;
    lookup)
        if [ -f "$SF" ]; then
            cat "$SF"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        rm -f "$SF"
        exit 0
        ;;
esac
"#,
            session_file.display()
        );
        fs::write(&secret_tool_script, secret_tool_code).unwrap();
        let mut perms = fs::metadata(&secret_tool_script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&secret_tool_script, perms).unwrap();

        // Mock bw
        let bw_code = r#"#!/bin/sh
case "$1" in
    status)
        echo '{"status": "locked", "serverUrl": "https://vault.bitwarden.com", "userEmail": "user@test.com"}'
        exit 0
        ;;
    unlock)
        cat > /dev/null
        echo "dummy_unlocked_session_token_12345"
        exit 0
        ;;
    lock)
        exit 0
        ;;
    logout)
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#;
        fs::write(&bw_script, bw_code).unwrap();
        let mut perms2 = fs::metadata(&bw_script).unwrap().permissions();
        perms2.set_mode(0o755);
        fs::set_permissions(&bw_script, perms2).unwrap();

        let keyring = KeyringManager::new(secret_tool_script.to_str().unwrap());
        let auth_mgr = AuthManager::new(bw_script.to_str().unwrap(), Some(keyring.clone()), None);

        // Initially status is locked
        let st = auth_mgr.get_status(false);
        assert_eq!(st.status, "locked");
        assert!(!st.has_session);

        // Unlock
        let res = auth_mgr.unlock("my_master_password");
        assert!(res.ok);
        assert_eq!(res.status, Some("unlocked".to_string()));
        assert_eq!(res.session, Some("dummy_unlocked_session_token_12345".to_string()));

        // Status is now unlocked
        let st_unlocked = auth_mgr.get_status(false);
        assert_eq!(st_unlocked.status, "unlocked");
        assert!(st_unlocked.has_session);

        // Lock
        let lock_res = auth_mgr.lock();
        assert!(lock_res.ok);
        assert_eq!(keyring.get_session(), None);
    }
}
