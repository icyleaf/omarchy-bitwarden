use std::io::Write;
use std::process::{Command, Stdio};

pub const SERVICE_NAME: &str = "omarchy-bitwarden";
pub const ACCOUNT_NAME: &str = "session";
pub const LABEL: &str = "Omarchy Bitwarden Session";
pub const KIND_ACCESS_TOKEN: &str = "access_token";
pub const KIND_REFRESH_TOKEN: &str = "refresh_token";
pub const KIND_API_SECRET: &str = "api_secret";

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

    pub fn is_available(&self) -> bool {
        which::which(&self.secret_tool_path).is_ok()
    }

    pub fn store_token(&self, kind: &str, token: &str) -> bool {
        if token.is_empty() || kind.is_empty() {
            return false;
        }
        let label = format!(
            "Omarchy Bitwarden {}",
            if kind == KIND_REFRESH_TOKEN {
                "Refresh Token"
            } else {
                "Access Token"
            }
        );
        let mut child = match Command::new(&self.secret_tool_path)
            .args([
                "store",
                &format!("--label={}", label),
                "service",
                SERVICE_NAME,
                "kind",
                kind,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(token.as_bytes());
        }

        match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    pub fn get_token(&self, kind: &str) -> Option<String> {
        if kind.is_empty() {
            return None;
        }
        let output = Command::new(&self.secret_tool_path)
            .args(["lookup", "service", SERVICE_NAME, "kind", kind])
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

    pub fn clear_token(&self, kind: &str) -> bool {
        if kind.is_empty() {
            return false;
        }
        match Command::new(&self.secret_tool_path)
            .args(["clear", "service", SERVICE_NAME, "kind", kind])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn store_api_secret(&self, server_url: &str, client_id: &str, secret: &str) -> bool {
        if secret.is_empty() || client_id.is_empty() || server_url.is_empty() {
            return false;
        }
        let label = "Omarchy Bitwarden API Secret";
        let mut child = match Command::new(&self.secret_tool_path)
            .args([
                "store",
                &format!("--label={}", label),
                "service",
                SERVICE_NAME,
                "kind",
                KIND_API_SECRET,
                "server_url",
                server_url,
                "client_id",
                client_id,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(secret.as_bytes());
        }

        match child.wait() {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    pub fn get_api_secret(&self, server_url: &str, client_id: &str) -> Option<String> {
        if client_id.is_empty() || server_url.is_empty() {
            return None;
        }
        let output = Command::new(&self.secret_tool_path)
            .args([
                "lookup",
                "service",
                SERVICE_NAME,
                "kind",
                KIND_API_SECRET,
                "server_url",
                server_url,
                "client_id",
                client_id,
            ])
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

    pub fn clear_api_secret(&self, server_url: &str, client_id: &str) -> bool {
        if client_id.is_empty() || server_url.is_empty() {
            return false;
        }
        match Command::new(&self.secret_tool_path)
            .args([
                "clear",
                "service",
                SERVICE_NAME,
                "kind",
                KIND_API_SECRET,
                "server_url",
                server_url,
                "client_id",
                client_id,
            ])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn clear_all(&self) -> bool {
        match Command::new(&self.secret_tool_path)
            .args(["clear", "service", SERVICE_NAME])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn store_session(&self, session_token: &str) -> bool {
        if session_token.is_empty() {
            return false;
        }
        let _ = self.store_token(KIND_ACCESS_TOKEN, session_token);

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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        // Prefer modern kind=access_token first to avoid stale tokens shadowing active ones
        if let Some(tok) = self.get_token(KIND_ACCESS_TOKEN) {
            return Some(tok);
        }

        // Fallback to legacy account=session
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
        let _ = self.clear_token(KIND_ACCESS_TOKEN);
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
        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mgr = KeyringManager::new(script_path.to_str().unwrap());
        assert!(mgr.is_available());

        // Initial lookup should be None
        assert_eq!(mgr.get_session(), None);
        assert_eq!(mgr.get_token("access_token"), None);
        assert_eq!(mgr.get_token("refresh_token"), None);
        assert_eq!(mgr.get_api_secret("https://bw.local", "user.123"), None);

        // Store tokens
        assert!(mgr.store_token("access_token", "jwt_access_123"));
        assert_eq!(
            mgr.get_token("access_token"),
            Some("jwt_access_123".to_string())
        );
        assert_eq!(mgr.get_session(), Some("jwt_access_123".to_string()));

        assert!(mgr.store_token("refresh_token", "jwt_refresh_456"));
        assert_eq!(
            mgr.get_token("refresh_token"),
            Some("jwt_refresh_456".to_string())
        );

        // Store API secret
        assert!(mgr.store_api_secret("https://bw.local", "user.123", "secret_abc_xyz"));
        assert_eq!(
            mgr.get_api_secret("https://bw.local", "user.123"),
            Some("secret_abc_xyz".to_string())
        );
        assert_eq!(mgr.get_api_secret("https://bw.local", "other.456"), None);

        // Clear specific token
        assert!(mgr.clear_token("access_token"));
        assert_eq!(mgr.get_token("access_token"), None);
        assert_eq!(
            mgr.get_token("refresh_token"),
            Some("jwt_refresh_456".to_string())
        );
        assert_eq!(
            mgr.get_api_secret("https://bw.local", "user.123"),
            Some("secret_abc_xyz".to_string())
        );

        // Clear API secret
        assert!(mgr.clear_api_secret("https://bw.local", "user.123"));
        assert_eq!(mgr.get_api_secret("https://bw.local", "user.123"), None);

        // Store again and test clear_all
        assert!(mgr.store_token(KIND_ACCESS_TOKEN, "jwt_access_999"));
        assert!(mgr.store_api_secret("https://bw.local", "user.123", "secret_999"));
        assert!(mgr.clear_all());
        assert_eq!(mgr.get_token(KIND_ACCESS_TOKEN), None);
        assert_eq!(mgr.get_token(KIND_REFRESH_TOKEN), None);
        assert_eq!(mgr.get_api_secret("https://bw.local", "user.123"), None);
        assert_eq!(mgr.get_session(), None);
    }

    #[test]
    fn test_legacy_session_and_priority() {
        let dir = tempdir().unwrap();
        let store_dir = dir.path().join("store");
        fs::create_dir_all(&store_dir).unwrap();
        let script_path = dir.path().join("mock-secret-tool");

        let script = format!(
            r#"#!/bin/sh
STORE_DIR="{}"
cmd="$1"
shift
case "$1" in
    --label=*)
        shift
        ;;
esac

key=""
while [ $# -gt 0 ]; do
    k="$1"
    v="$2"
    safe_v=$(printf '%s' "$v" | tr '/:' '_')
    key="${{key}}__${{k}}=${{safe_v}}"
    shift 2 2>/dev/null || shift 1
done

case "$cmd" in
    store)
        cat > "${{STORE_DIR}}/${{key}}"
        exit 0
        ;;
    lookup)
        if [ -f "${{STORE_DIR}}/${{key}}" ]; then
            cat "${{STORE_DIR}}/${{key}}"
            exit 0
        else
            exit 1
        fi
        ;;
    clear)
        if [ -z "$key" ] || [ "$key" = "__service=omarchy-bitwarden" ]; then
            rm -f "${{STORE_DIR}}"/*
        else
            rm -f "${{STORE_DIR}}/${{key}}"*
        fi
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"#,
            store_dir.display()
        );

        fs::write(&script_path, script).unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let mgr = KeyringManager::new(script_path.to_str().unwrap());

        // 1. Store via legacy store_session
        assert!(mgr.store_session("token_initial"));
        assert_eq!(mgr.get_session(), Some("token_initial".to_string()));
        assert_eq!(
            mgr.get_token(KIND_ACCESS_TOKEN),
            Some("token_initial".to_string())
        );

        // 2. Overwrite via modern store_token
        assert!(mgr.store_token(KIND_ACCESS_TOKEN, "token_refreshed"));
        // get_session MUST return the refreshed token (priority inversion fixed)
        assert_eq!(mgr.get_session(), Some("token_refreshed".to_string()));

        // 3. Clear session
        assert!(mgr.clear_session());
        assert_eq!(mgr.get_session(), None);
        assert_eq!(mgr.get_token(KIND_ACCESS_TOKEN), None);
    }

    #[test]
    fn test_validation_rejects_empty_inputs() {
        let mgr = KeyringManager::default();
        assert!(!mgr.store_token("", "token"));
        assert!(!mgr.store_token("kind", ""));
        assert_eq!(mgr.get_token(""), None);
        assert!(!mgr.clear_token(""));

        assert!(!mgr.store_api_secret("", "client_id", "secret"));
        assert!(!mgr.store_api_secret("https://bw.local", "", "secret"));
        assert!(!mgr.store_api_secret("https://bw.local", "client_id", ""));
        assert_eq!(mgr.get_api_secret("", "client_id"), None);
        assert_eq!(mgr.get_api_secret("https://bw.local", ""), None);
        assert!(!mgr.clear_api_secret("", "client_id"));
        assert!(!mgr.clear_api_secret("https://bw.local", ""));
    }
}
