use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::credential_slots::CredentialSlot;
use crate::storage::VaultStorage;

pub const SERVICE_NAME: &str = "omarchy-bitwarden";
const SCOPED_SERVICE_NAME: &str = "omarchy-bitwarden-v2";
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

    fn store(
        &self,
        label: &str,
        attributes: &[&str],
        secret: &str,
        lease: Option<&CredentialSlot>,
    ) -> bool {
        if secret.is_empty() {
            return false;
        }
        let mut command = Command::new(&self.secret_tool_path);
        command
            .arg("store")
            .arg(format!("--label={label}"))
            .args(attributes)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if lease.is_some_and(|slot| slot.inherit_in(&mut command).is_err()) {
            return false;
        }
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        let written = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(secret.as_bytes()).is_ok());
        child.wait().is_ok_and(|status| status.success()) && written
    }

    fn lookup(&self, attributes: &[&str]) -> Option<String> {
        let output = Command::new(&self.secret_tool_path)
            .arg("lookup")
            .args(attributes)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let secret = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        (!secret.is_empty()).then_some(secret)
    }

    fn clear(&self, attributes: &[&str]) -> bool {
        self.clear_command(attributes)
            .status()
            .is_ok_and(|status| status.success())
    }

    fn clear_command(&self, attributes: &[&str]) -> Command {
        let mut command = Command::new(&self.secret_tool_path);
        command
            .arg("clear")
            .args(attributes)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    pub(crate) fn erase_credential_slot(
        &self,
        credential_id: Option<&str>,
        deadline: Instant,
    ) -> io::Result<()> {
        let scoped;
        let attributes: &[&str] = if let Some(id) = credential_id {
            scoped = ["service", SCOPED_SERVICE_NAME, "credential_id", id];
            &scoped
        } else {
            &["service", SERVICE_NAME]
        };
        cleanup_time_left(deadline)?;
        wait_for_cleanup(self.clear_command(attributes).spawn()?, deadline)?;

        // clear may find nothing or leave locked entries behind. Confirm
        // absence without capturing or logging the search output.
        let (mut output, writer) = UnixStream::pair()?;
        let search = Command::new(&self.secret_tool_path)
            .args(["search", "--all"])
            .args(attributes)
            .stdin(Stdio::null())
            .stdout(Stdio::from(OwnedFd::from(writer)))
            .stderr(Stdio::null())
            .spawn()?;
        let read = cleanup_time_left(deadline)
            .and_then(|remaining| output.set_read_timeout(Some(remaining)))
            .and_then(|()| output.read(&mut [0]));
        match read {
            Ok(0) => {
                if wait_for_cleanup(search, deadline)?.success() {
                    return Ok(());
                }
            }
            read => {
                stop_and_reap(search);
                if let Err(error) = read {
                    return Err(match error.kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => cleanup_timeout(),
                        _ => error,
                    });
                }
            }
        }
        Err(io::Error::other("Could not confirm keyring cleanup"))
    }

    pub fn store_token(&self, server_url: &str, kind: &str, token: &str) -> bool {
        legacy_token_attributes(server_url, kind)
            .is_some_and(|attrs| self.store(credential_label(kind), &attrs, token, None))
    }

    pub fn get_token(&self, server_url: &str, kind: &str) -> Option<String> {
        self.lookup(&legacy_token_attributes(server_url, kind)?)
    }

    pub fn clear_token(&self, server_url: &str, kind: &str) -> bool {
        legacy_token_attributes(server_url, kind).is_some_and(|attrs| self.clear(&attrs))
    }

    pub fn store_api_secret(&self, server_url: &str, client_id: &str, secret: &str) -> bool {
        legacy_api_attributes(server_url, client_id).is_some_and(|attrs| {
            self.store(credential_label(KIND_API_SECRET), &attrs, secret, None)
        })
    }

    pub fn get_api_secret(&self, server_url: &str, client_id: &str) -> Option<String> {
        self.lookup(&legacy_api_attributes(server_url, client_id)?)
    }

    pub fn clear_api_secret(&self, server_url: &str, client_id: &str) -> bool {
        legacy_api_attributes(server_url, client_id).is_some_and(|attrs| self.clear(&attrs))
    }

    pub fn clear_all(&self) -> bool {
        self.clear(&["service", SERVICE_NAME])
    }

    pub fn store_session(&self, server_url: &str, session_token: &str) -> bool {
        let Some(attrs) = legacy_session_attributes(server_url) else {
            return false;
        };
        let _ = self.store_token(server_url, KIND_ACCESS_TOKEN, session_token);
        self.store(LABEL, &attrs, session_token, None)
    }

    pub fn get_session(&self, server_url: &str) -> Option<String> {
        self.get_token(server_url, KIND_ACCESS_TOKEN)
            .or_else(|| self.lookup(&legacy_session_attributes(server_url)?))
    }

    pub fn clear_session(&self, server_url: &str) -> bool {
        let Some(attrs) = legacy_session_attributes(server_url) else {
            return false;
        };
        let _ = self.clear_token(server_url, KIND_ACCESS_TOKEN);
        self.clear(&attrs)
    }

    pub(crate) fn for_storage<'a>(&'a self, storage: &'a VaultStorage) -> AccountKeyring<'a> {
        AccountKeyring {
            keyring: self,
            storage,
            lease: None,
        }
    }
}

fn cleanup_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Keyring cleanup timed out")
}

fn cleanup_time_left(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(cleanup_timeout());
    }
    Ok(remaining)
}

fn stop_and_reap(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_cleanup(mut child: Child, deadline: Instant) -> io::Result<ExitStatus> {
    let error = loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Err(error) => break error,
            Ok(None) => match cleanup_time_left(deadline) {
                Ok(remaining) => std::thread::sleep(remaining.min(Duration::from_millis(5))),
                Err(error) => break error,
            },
        }
    };
    stop_and_reap(child);
    Err(error)
}

fn credential_label(kind: &str) -> &'static str {
    match kind {
        KIND_REFRESH_TOKEN => "Omarchy Bitwarden Refresh Token",
        KIND_API_SECRET => "Omarchy Bitwarden API Secret",
        _ => "Omarchy Bitwarden Access Token",
    }
}

fn legacy_token_attributes<'a>(server: &'a str, kind: &'a str) -> Option<[&'a str; 6]> {
    let server = normalize_server_url(server);
    (!server.is_empty() && !kind.is_empty()).then_some([
        "service",
        SERVICE_NAME,
        "kind",
        kind,
        "server_url",
        server,
    ])
}

fn legacy_api_attributes<'a>(server: &'a str, client_id: &'a str) -> Option<[&'a str; 8]> {
    let server = normalize_server_url(server);
    let client_id = client_id.trim();
    (!server.is_empty() && !client_id.is_empty()).then_some([
        "service",
        SERVICE_NAME,
        "kind",
        KIND_API_SECRET,
        "server_url",
        server,
        "client_id",
        client_id,
    ])
}

fn legacy_session_attributes(server: &str) -> Option<[&str; 6]> {
    let server = normalize_server_url(server);
    (!server.is_empty()).then_some([
        "service",
        SERVICE_NAME,
        "account",
        ACCOUNT_NAME,
        "server_url",
        server,
    ])
}

pub(crate) struct AccountKeyring<'a> {
    keyring: &'a KeyringManager,
    storage: &'a VaultStorage,
    lease: Option<&'a CredentialSlot>,
}

impl<'a> AccountKeyring<'a> {
    pub(crate) fn with_lease(mut self, lease: &'a CredentialSlot) -> Self {
        self.lease = Some(lease);
        self
    }

    fn slot(&self) -> Option<[&str; 10]> {
        let id = self.storage.scoped_credential_id()?;
        let server = normalize_server_url(&self.storage.server_url);
        let account = self
            .storage
            .user_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .unwrap_or(&self.storage.user_email);
        if server.is_empty() || account.is_empty() {
            return None;
        }
        Some([
            "service",
            SCOPED_SERVICE_NAME,
            "server_url",
            server,
            "account",
            account,
            "credential_id",
            id,
            "identity_url",
            self.storage.identity_url.as_deref().unwrap_or(""),
        ])
    }

    fn attributes<'b>(&'b self, kind: &'b str) -> Option<Vec<&'b str>> {
        let mut attributes = self.slot()?.to_vec();
        attributes.extend(["kind", kind]);
        if kind == KIND_API_SECRET {
            let client_id = self.storage.client_id.as_deref()?.trim();
            if client_id.is_empty() {
                return None;
            }
            attributes.extend(["client_id", client_id]);
        }
        Some(attributes)
    }

    pub(crate) fn access_token(&self) -> Option<String> {
        self.keyring.lookup(&self.attributes(KIND_ACCESS_TOKEN)?)
    }

    pub(crate) fn refresh_token(&self) -> Option<String> {
        self.keyring.lookup(&self.attributes(KIND_REFRESH_TOKEN)?)
    }

    pub(crate) fn api_secret(&self) -> Option<String> {
        self.keyring.lookup(&self.attributes(KIND_API_SECRET)?)
    }

    pub(crate) fn store_token(&self, kind: &str, token: &str) -> bool {
        self.attributes(kind).is_some_and(|attrs| {
            self.keyring
                .store(credential_label(kind), &attrs, token, self.lease)
        })
    }

    pub(crate) fn clear_token(&self, kind: &str) {
        if let Some(attrs) = self.attributes(kind) {
            self.keyring.clear(&attrs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    #[test]
    fn test_empty_token_store() {
        let mgr = KeyringManager::default();
        assert!(!mgr.store_session("https://vault.bitwarden.com", ""));
        assert!(!mgr.store_session("", "some_token"));
    }

    #[test]
    fn cleanup_reaps_stalled_keyring_commands() {
        for action in ["clear", "search"] {
            let dir = tempdir().unwrap();
            let started = dir.path().join("started");
            let secret_tool = dir.path().join("secret-tool");
            crate::write_test_executable(
                &secret_tool,
                format!(
                    "#!/bin/sh\nif [ \"$1\" = '{action}' ]; then echo $$ > '{}'; exec /bin/sleep 15; fi\n",
                    started.display()
                ),
            );
            let keyring = KeyringManager::new(secret_tool.to_str().unwrap());
            let deadline = Instant::now() + Duration::from_millis(750);
            let error = keyring
                .erase_credential_slot(Some(crate::test_support::CREDENTIAL_ID), deadline)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{action}");
            let pid = fs::read_to_string(&started).unwrap();
            assert!(
                !std::path::Path::new("/proc").join(pid.trim()).exists(),
                "{action} was not reaped"
            );
        }
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

        crate::write_test_executable(&script_path, script);

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

        crate::write_test_executable(&script_path, script);

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

        crate::write_test_executable(&script_path, script);

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

        crate::write_test_executable(&script_path, script);

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
