use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthStatus {
    pub installed: bool,
    pub ok: bool,
    pub executable_path: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
}

pub fn resolve_executable(bw_path: &str) -> Option<String> {
    let candidate = if bw_path.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(bw_path.replacen('~', &home, 1))
        } else {
            PathBuf::from(bw_path)
        }
    } else {
        PathBuf::from(bw_path)
    };

    if candidate.is_file() {
        if let Ok(metadata) = candidate.metadata() {
            if metadata.permissions().mode() & 0o111 != 0 {
                if let Ok(canonical) = candidate.canonicalize() {
                    return Some(canonical.to_string_lossy().to_string());
                }
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    if let Ok(found) = which::which(bw_path) {
        return Some(found.to_string_lossy().to_string());
    }

    None
}

pub fn check_cli_health(bw_path: &str) -> HealthStatus {
    let resolved = match resolve_executable(bw_path) {
        Some(r) => r,
        None => {
            return HealthStatus {
                installed: false,
                ok: false,
                executable_path: None,
                version: None,
                error: Some(format!(
                    "Bitwarden CLI executable '{}' not found in PATH or filesystem.",
                    bw_path
                )),
            };
        }
    };

    match Command::new(&resolved).arg("--version").output() {
        Ok(output) => {
            if output.status.success() {
                let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
                HealthStatus {
                    installed: true,
                    ok: true,
                    executable_path: Some(resolved),
                    version: Some(ver),
                    error: None,
                }
            } else {
                let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let err_msg = if err.is_empty() {
                    format!("Process returned exit code {}", output.status.code().unwrap_or(1))
                } else {
                    err
                };
                HealthStatus {
                    installed: true,
                    ok: false,
                    executable_path: Some(resolved),
                    version: None,
                    error: Some(err_msg),
                }
            }
        }
        Err(e) => HealthStatus {
            installed: true,
            ok: false,
            executable_path: Some(resolved.clone()),
            version: None,
            error: Some(format!("Failed to execute '{}': {}", resolved, e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_non_existent_executable() {
        let status = check_cli_health("non_existent_bw_binary_12345");
        assert!(!status.installed);
        assert!(!status.ok);
        assert!(status.executable_path.is_none());
        assert!(status.version.is_none());
        assert!(status.error.unwrap().contains("not found in PATH"));
    }

    #[test]
    fn test_mock_working_executable() {
        let dir = tempdir().unwrap();
        let script_path = dir.path().join("mock-bw");
        fs::write(&script_path, "#!/bin/sh\necho '2024.1.0'\n").unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let status = check_cli_health(script_path.to_str().unwrap());
        assert!(status.installed);
        assert!(status.ok);
        assert_eq!(status.version, Some("2024.1.0".to_string()));
        assert!(status.error.is_none());
    }

    #[test]
    fn test_mock_failing_executable() {
        let dir = tempdir().unwrap();
        let script_path = dir.path().join("failing-bw");
        fs::write(&script_path, "#!/bin/sh\nexit 1\n").unwrap();
        let mut perms = fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).unwrap();

        let status = check_cli_health(script_path.to_str().unwrap());
        assert!(status.installed);
        assert!(!status.ok);
        assert!(status.error.is_some());
    }
}
