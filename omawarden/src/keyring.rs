use std::io::Write;
use std::process::{Command, Stdio};

pub const SERVICE_NAME: &str = "omarchy-bitwarden";
pub const ACCOUNT_NAME: &str = "session";
pub const LABEL: &str = "Omarchy Bitwarden Session";
pub const KIND_ACCESS_TOKEN: &str = "access_token";
pub const KIND_REFRESH_TOKEN: &str = "refresh_token";
pub const KIND_API_SECRET: &str = "api_secret";

pub fn normalize_server_url(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

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

    pub fn store_token(&self, server_url: &str, kind: &str, token: &str) -> bool {
        let norm_url = normalize_server_url(server_url);
        if token.is_empty() || kind.is_empty() || norm_url.is_empty() {
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
                "server_url",
                norm_url,
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

    pub fn get_token(&self, server_url: &str, kind: &str) -> Option<String> {
        let norm_url = normalize_server_url(server_url);
        if kind.is_empty() || norm_url.is_empty() {
            return None;
        }
        let output = Command::new(&self.secret_tool_path)
            .args([
                "lookup",
                "service",
                SERVICE_NAME,
                "kind",
                kind,
                "server_url",
                norm_url,
            ])
            .output()
            .ok()?;

        if output.status.success() {
            let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }

        // Backwards compatibility fallback: lookup un-scoped token from older versions
        let legacy = Command::new(&self.secret_tool_path)
            .args(["lookup", "service", SERVICE_NAME, "kind", kind])
            .output()
            .ok()?;

        if legacy.status.success() {
            let val = String::from_utf8_lossy(&legacy.stdout).trim().to_string();
            if !val.is_empty() {
                return Some(val);
            }
        }

        None
    }

    pub fn clear_token(&self, server_url: &str, kind: &str) -> bool {
        let norm_url = normalize_server_url(server_url);
        if kind.is_empty() || norm_url.is_empty() {
            return false;
        }
        match Command::new(&self.secret_tool_path)
            .args([
                "clear",
                "service",
                SERVICE_NAME,
                "kind",
                kind,
                "server_url",
                norm_url,
            ])
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    pub fn store_api_secret(&self, server_url: &str, client_id: &str, secret: &str) -> bool {
        let norm_url = normalize_server_url(server_url);
        let norm_cid = client_id.trim();
        if secret.is_empty() || norm_cid.is_empty() || norm_url.is_empty() {
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
                norm_url,
                "client_id",
                norm_cid,
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
        let norm_url = normalize_server_url(server_url);
        let norm_cid = client_id.trim();
        if norm_cid.is_empty() || norm_url.is_empty() {
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
                norm_url,
                "client_id",
                norm_cid,
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
        let norm_url = normalize_server_url(server_url);
        let norm_cid = client_id.trim();
        if norm_cid.is_empty() || norm_url.is_empty() {
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
                norm_url,
                "client_id",
                norm_cid,
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

    pub fn store_session(&self, server_url: &str, session_token: &str) -> bool {
        let norm_url = normalize_server_url(server_url);
        if session_token.is_empty() || norm_url.is_empty() {
            return false;
        }
        let _ = self.store_token(norm_url, KIND_ACCESS_TOKEN, session_token);

        let mut child = match Command::new(&self.secret_tool_path)
            .args([
                "store",
                &format!("--label={}", LABEL),
                "service",
                SERVICE_NAME,
                "account",
                ACCOUNT_NAME,
                "server_url",
                norm_url,
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

    pub fn get_session(&self, server_url: &str) -> Option<String> {
        let norm_url = normalize_server_url(server_url);
        if norm_url.is_empty() {
            return None;
        }
        // Prefer modern kind=access_token scoped to server_url first
        if let Some(tok) = self.get_token(norm_url, KIND_ACCESS_TOKEN) {
            return Some(tok);
        }

        // Look up server_url scoped legacy account=session
        if let Ok(output) = Command::new(&self.secret_tool_path)
            .args([
                "lookup",
                "service",
                SERVICE_NAME,
                "account",
                ACCOUNT_NAME,
                "server_url",
                norm_url,
            ])
            .output()
        {
            if output.status.success() {
                let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }

        // Fallback to legacy un-scoped account=session
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

    pub fn clear_session(&self, server_url: &str) -> bool {
        let norm_url = normalize_server_url(server_url);
        if norm_url.is_empty() {
            return false;
        }
        let _ = self.clear_token(norm_url, KIND_ACCESS_TOKEN);
        match Command::new(&self.secret_tool_path)
            .args([
                "clear",
                "service",
                SERVICE_NAME,
                "account",
                ACCOUNT_NAME,
                "server_url",
                norm_url,
            ])
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
        assert!(!mgr.store_session("https://vault.bitwarden.com", ""));
        assert!(!mgr.store_session("", "some_token"));
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

        let server_url = "https://bw.local";

        // Initial lookup should be None
        assert_eq!(mgr.get_session(server_url), None);
        assert_eq!(mgr.get_token(server_url, "access_token"), None);
        assert_eq!(mgr.get_token(server_url, "refresh_token"), None);
        assert_eq!(mgr.get_api_secret(server_url, "user.123"), None);

        // Store tokens
        assert!(mgr.store_token(server_url, "access_token", "jwt_access_123"));
        assert_eq!(
            mgr.get_token(server_url, "access_token"),
            Some("jwt_access_123".to_string())
        );
        assert_eq!(
            mgr.get_session(server_url),
            Some("jwt_access_123".to_string())
        );

        assert!(mgr.store_token(server_url, "refresh_token", "jwt_refresh_456"));
        assert_eq!(
            mgr.get_token(server_url, "refresh_token"),
            Some("jwt_refresh_456".to_string())
        );

        // Store API secret
        assert!(mgr.store_api_secret(server_url, "user.123", "secret_abc_xyz"));
        assert_eq!(
            mgr.get_api_secret(server_url, "user.123"),
            Some("secret_abc_xyz".to_string())
        );
        assert_eq!(mgr.get_api_secret(server_url, "other.456"), None);

        // Clear specific token
        assert!(mgr.clear_token(server_url, "access_token"));
        assert_eq!(mgr.get_token(server_url, "access_token"), None);
        assert_eq!(
            mgr.get_token(server_url, "refresh_token"),
            Some("jwt_refresh_456".to_string())
        );
        assert_eq!(
            mgr.get_api_secret(server_url, "user.123"),
            Some("secret_abc_xyz".to_string())
        );

        // Clear API secret
        assert!(mgr.clear_api_secret(server_url, "user.123"));
        assert_eq!(mgr.get_api_secret(server_url, "user.123"), None);

        // Store again and test clear_all
        assert!(mgr.store_token(server_url, KIND_ACCESS_TOKEN, "jwt_access_999"));
        assert!(mgr.store_api_secret(server_url, "user.123", "secret_999"));
        assert!(mgr.clear_all());
        assert_eq!(mgr.get_token(server_url, KIND_ACCESS_TOKEN), None);
        assert_eq!(mgr.get_token(server_url, KIND_REFRESH_TOKEN), None);
        assert_eq!(mgr.get_api_secret(server_url, "user.123"), None);
        assert_eq!(mgr.get_session(server_url), None);
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
        let server_url = "https://vault.bitwarden.com";

        // 1. Store via legacy store_session
        assert!(mgr.store_session(server_url, "token_initial"));
        assert_eq!(
            mgr.get_session(server_url),
            Some("token_initial".to_string())
        );
        assert_eq!(
            mgr.get_token(server_url, KIND_ACCESS_TOKEN),
            Some("token_initial".to_string())
        );

        // 2. Overwrite via modern store_token
        assert!(mgr.store_token(server_url, KIND_ACCESS_TOKEN, "token_refreshed"));
        // get_session MUST return the refreshed token (priority inversion fixed)
        assert_eq!(
            mgr.get_session(server_url),
            Some("token_refreshed".to_string())
        );

        // 3. Clear session
        assert!(mgr.clear_session(server_url));
        assert_eq!(mgr.get_session(server_url), None);
        assert_eq!(mgr.get_token(server_url, KIND_ACCESS_TOKEN), None);
    }

    #[test]
    fn test_server_url_isolation_in_keyring() {
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
        let server_a = "https://server-a.com";
        let server_b = "https://server-b.com";

        // Store tokens on server A
        assert!(mgr.store_token(server_a, KIND_ACCESS_TOKEN, "token_a_access"));
        assert!(mgr.store_token(server_a, KIND_REFRESH_TOKEN, "token_a_refresh"));

        // Store tokens on server B
        assert!(mgr.store_token(server_b, KIND_ACCESS_TOKEN, "token_b_access"));
        assert!(mgr.store_token(server_b, KIND_REFRESH_TOKEN, "token_b_refresh"));

        // Ensure Server A returns only its own tokens
        assert_eq!(
            mgr.get_token(server_a, KIND_ACCESS_TOKEN),
            Some("token_a_access".to_string())
        );
        assert_eq!(
            mgr.get_token(server_a, KIND_REFRESH_TOKEN),
            Some("token_a_refresh".to_string())
        );

        // Ensure Server B returns only its own tokens
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("token_b_access".to_string())
        );
        assert_eq!(
            mgr.get_token(server_b, KIND_REFRESH_TOKEN),
            Some("token_b_refresh".to_string())
        );

        // Clear token on server A and verify server B is intact
        assert!(mgr.clear_token(server_a, KIND_ACCESS_TOKEN));
        assert_eq!(mgr.get_token(server_a, KIND_ACCESS_TOKEN), None);
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("token_b_access".to_string())
        );
    }

    #[test]
    fn test_validation_rejects_empty_inputs() {
        let mgr = KeyringManager::default();
        assert!(!mgr.store_token("", "access_token", "token"));
        assert!(!mgr.store_token("https://bw.local", "", "token"));
        assert!(!mgr.store_token("https://bw.local", "kind", ""));
        assert_eq!(mgr.get_token("", "kind"), None);
        assert_eq!(mgr.get_token("https://bw.local", ""), None);
        assert!(!mgr.clear_token("", "kind"));
        assert!(!mgr.clear_token("https://bw.local", ""));

        assert!(!mgr.store_api_secret("", "client_id", "secret"));
        assert!(!mgr.store_api_secret("https://bw.local", "", "secret"));
        assert!(!mgr.store_api_secret("https://bw.local", "client_id", ""));
        assert_eq!(mgr.get_api_secret("", "client_id"), None);
        assert_eq!(mgr.get_api_secret("https://bw.local", ""), None);
        assert!(!mgr.clear_api_secret("", "client_id"));
        assert!(!mgr.clear_api_secret("https://bw.local", ""));
    }

    #[test]
    fn test_keyring_trailing_slash_normalization() {
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

        // Store with trailing slash
        assert!(mgr.store_api_secret("https://vault.example.com/", "user.123 ", "secret_val"));

        // Lookup without trailing slash
        assert_eq!(
            mgr.get_api_secret("https://vault.example.com", "user.123"),
            Some("secret_val".to_string())
        );

        // Clear with trailing slash
        assert!(mgr.clear_api_secret("https://vault.example.com/", "user.123"));
        assert_eq!(
            mgr.get_api_secret("https://vault.example.com", "user.123"),
            None
        );
    }
}
