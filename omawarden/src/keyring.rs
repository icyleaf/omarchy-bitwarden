use std::io::Write;
use std::process::{Command, Stdio};

pub const SERVICE_NAME: &str = "omarchy-bitwarden";
pub const ACCOUNT_NAME: &str = "session";
pub const LABEL: &str = "Omarchy Bitwarden Session";

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
        Self { secret_tool_path: path }
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
