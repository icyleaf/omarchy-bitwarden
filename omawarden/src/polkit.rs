use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// polkit action registered by the packaged policy file. Keep in sync with
/// `packaging/org.omarchy.bitwarden.policy`.
pub const POLKIT_ACTION_ID: &str = "org.omarchy.bitwarden.unlock";
/// Interactive checks wait for the user to answer the agent's dialog.
pub const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, PartialEq, Eq)]
pub enum PolkitOutcome {
    /// The subject authenticated for the action.
    Authorized,
    /// The user answered the dialog negatively (or closed it).
    Denied,
    /// polkit itself could not answer: missing binary, no agent, timeout.
    Unavailable(String),
}

/// Run `pkcheck` for the daemon's own process subject.
///
/// The daemon runs inside the user session, so the session's polkit agent
/// (Omarchy's shell ships one) shows the system unlock dialog, which honours
/// fingerprint auth where PAM is configured for it. Exit code 1 means the
/// subject is not authorized; anything else is treated as polkit being
/// unavailable rather than a denial.
pub fn check(action_id: &str, binary: &Path, timeout: Duration) -> PolkitOutcome {
    let mut child = match Command::new(binary)
        .args([
            "--action-id",
            action_id,
            "--process",
            &std::process::id().to_string(),
            "--allow-user-interaction",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return PolkitOutcome::Unavailable(format!("failed to spawn pkcheck: {e}")),
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    PolkitOutcome::Authorized
                } else if status.code() == Some(1) {
                    PolkitOutcome::Denied
                } else {
                    PolkitOutcome::Unavailable(format!("pkcheck exited with {status}"))
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return PolkitOutcome::Unavailable(
                        "pkcheck timed out (no polkit agent answered?)".to_string(),
                    );
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return PolkitOutcome::Unavailable(format!("pkcheck wait failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn mock_pkcheck(
        dir: &Path,
        name: &str,
        exit_code: &str,
        delay_secs: u64,
    ) -> std::path::PathBuf {
        let path = dir.join(name);
        let script = format!(
            r#"#!/bin/sh
sleep {delay_secs}
echo "$@" >> "{}/args.log"
exit {exit_code}
"#,
            dir.display()
        );
        crate::write_test_executable(&path, script);
        path
    }

    #[test]
    fn test_check_authorized_on_exit_zero() {
        let dir = tempfile::tempdir().unwrap();
        let bin = mock_pkcheck(dir.path(), "pk-ok", "0", 0);
        assert_eq!(
            check(POLKIT_ACTION_ID, &bin, Duration::from_secs(5)),
            PolkitOutcome::Authorized
        );
        let args = fs::read_to_string(dir.path().join("args.log")).unwrap();
        assert!(
            args.contains("--action-id org.omarchy.bitwarden.unlock"),
            "{args}"
        );
        assert!(args.contains("--allow-user-interaction"), "{args}");
        assert!(args.contains("--process"), "{args}");
    }

    #[test]
    fn test_check_denied_on_exit_one() {
        let dir = tempfile::tempdir().unwrap();
        let bin = mock_pkcheck(dir.path(), "pk-deny", "1", 0);
        assert_eq!(
            check(POLKIT_ACTION_ID, &bin, Duration::from_secs(5)),
            PolkitOutcome::Denied
        );
    }

    #[test]
    fn test_check_unavailable_on_unexpected_exit() {
        let dir = tempfile::tempdir().unwrap();
        let bin = mock_pkcheck(dir.path(), "pk-err", "3", 0);
        assert!(matches!(
            check(POLKIT_ACTION_ID, &bin, Duration::from_secs(5)),
            PolkitOutcome::Unavailable(_)
        ));
    }

    #[test]
    fn test_check_unavailable_on_missing_binary() {
        let outcome = check(
            POLKIT_ACTION_ID,
            Path::new("/nonexistent/pkcheck-xyz"),
            Duration::from_secs(1),
        );
        assert!(matches!(outcome, PolkitOutcome::Unavailable(_)));
    }

    #[test]
    fn test_check_unavailable_on_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let bin = mock_pkcheck(dir.path(), "pk-slow", "0", 30);
        let start = Instant::now();
        let outcome = check(POLKIT_ACTION_ID, &bin, Duration::from_millis(200));
        assert!(matches!(outcome, PolkitOutcome::Unavailable(_)));
        // The kill must not wait out the full child sleep.
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_check_custom_action_id_is_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let bin = mock_pkcheck(dir.path(), "pk-custom", "0", 0);
        assert_eq!(
            check("org.example.other", &bin, Duration::from_secs(5)),
            PolkitOutcome::Authorized
        );
        let args = fs::read_to_string(dir.path().join("args.log")).unwrap();
        assert!(args.contains("--action-id org.example.other"), "{args}");
    }
}
