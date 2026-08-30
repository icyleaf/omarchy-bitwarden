use std::io::Write;
use std::process::{Command, Stdio};

pub const SERVICE_NAME: &str = "omarchy-bitwarden";
pub const ACCOUNT_NAME: &str = "session";
pub const LABEL: &str = "Omarchy Bitwarden Session";

#[derive(Debug, Clone)]
pub struct KeyringManager {
    pub secret_tool_path: String,
}

impl Default for KeyringManager {
    fn default() -> Self {
        Self::new("secret-tool")
    }
}

impl KeyringManager {
    pub fn new(secret_tool_path: &str) -> Self {
        let path = which::which(secret_tool_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| secret_tool_path.to_string());
        Self {
            secret_tool_path: path,
        }
    }

    pub fn store_session(&self, session_token: &str) -> bool {
        if session_token.is_empty() {
            return false;
        }
        let mut child = match Command::new(&self.secret_tool_path)
            .args([
                "store",
                &format!("--label={}", LABEL),
                "service",
                SERVICE_NAME,
                "account",
                ACCOUNT_NAME,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(session_token.as_bytes());
        }

        match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    pub fn get_session(&self) -> Option<String> {
        let output = Command::new(&self.secret_tool_path)
            .args(["lookup", "service", SERVICE_NAME, "account", ACCOUNT_NAME])
            .output()
            .ok()?;

        if output.status.success() {
            let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }
        None
    }

    pub fn clear_session(&self) -> bool {
        match Command::new(&self.secret_tool_path)
            .args(["clear", "service", SERVICE_NAME, "account", ACCOUNT_NAME])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
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
    fn test_empty_token_store() {
        let mgr = KeyringManager::default();
        assert!(!mgr.store_session(""));
    }

    #[test]
    fn test_mock_keyring_lifecycle() {
        let dir = tempdir().unwrap();
        let db_file = dir.path().join("session_db.txt");
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
DB="{}"
case "$1" in
    store)
        cat > "$DB"
        exit 0
        ;;
    lookup)
        if [ -f "$DB" ]; then
            cat "$DB"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        rm -f "$DB"
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            db_file.display()
        );

        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mgr = KeyringManager::new(script_path.to_str().unwrap());

        // Initial lookup should be None
        assert_eq!(mgr.get_session(), None);

        // Store session
        assert!(mgr.store_session("test_session_token_12345"));
        assert_eq!(
            mgr.get_session(),
            Some("test_session_token_12345".to_string())
        );

        // Clear session
        assert!(mgr.clear_session());
        assert_eq!(mgr.get_session(), None);
    }
}
