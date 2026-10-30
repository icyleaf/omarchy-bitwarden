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

/// Extract field 22 (starttime, clock ticks since boot) from a
/// `/proc/<pid>/stat` line. `comm` (field 2) may contain spaces and
/// parentheses, so parsing starts after the last ')'; the tokens that
/// follow are fields 3.., making starttime token index 19.
fn parse_start_time(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// This process's start time, which (together with the PID) makes the
/// pkcheck subject unambiguous.
fn process_start_time() -> Option<u64> {
    parse_start_time(&std::fs::read_to_string("/proc/self/stat").ok()?)
}

/// The `--process` subject pkcheck(1) expects. A bare PID is explicitly
/// documented as racy (the PID may be recycled before polkit resolves it,
/// potentially attributing the authorization to a different process), so
/// the subject always carries pid,start-time,uid.
fn process_subject() -> Option<String> {
    let start_time = process_start_time()?;
    Some(format!(
        "{},{},{}",
        std::process::id(),
        start_time,
        unsafe { libc::getuid() }
    ))
}

/// Run `pkcheck` for the daemon's own process subject.
///
/// The daemon runs inside the user session, so the session's polkit agent
/// (Omarchy's shell ships one) shows the system unlock dialog, which honours
/// fingerprint auth where PAM is configured for it. Exit code 1 means the
/// subject is not authorized; anything else is treated as polkit being
/// unavailable rather than a denial.
pub fn check(action_id: &str, binary: &Path, timeout: Duration) -> PolkitOutcome {
    // Fail closed when the unambiguous subject cannot be built: a bare-pid
    // fallback would be the racy form pkcheck(1) warns about.
    let subject = match process_subject() {
        Some(s) => s,
        None => {
            return PolkitOutcome::Unavailable(
                "cannot read /proc/self/stat start time; pkcheck subject would be ambiguous"
                    .to_string(),
            )
        }
    };
    let mut child = match Command::new(binary)
        .args([
            "--action-id",
            action_id,
            "--process",
            &subject,
            "--allow-user-interaction",
        ])
        // pkcheck only needs to talk to the polkit daemon over D-Bus: strip
        // the inherited environment so a hostile variable cannot influence
        // the helper, keeping only the bare PATH it may need to locate things.
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
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
                } else if matches!(status.code(), Some(1) | Some(3)) {
                    // pkcheck exit codes: 1 = not authorized (negative answer),
                    // 3 = the user dismissed the authentication dialog. Both
                    // are user denials and both count toward the 3-strike
                    // wipe; everything else (2 = no agent / polkit error, ...)
                    // is treated as polkit being unavailable.
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
    fn test_check_dismissed_dialog_counts_as_denied() {
        let dir = tempfile::tempdir().unwrap();
        // pkcheck exit 3 = "the authentication dialog was dismissed by the
        // user" — a denial, not an infrastructure failure.
        let bin = mock_pkcheck(dir.path(), "pk-dismiss", "3", 0);
        assert_eq!(
            check(POLKIT_ACTION_ID, &bin, Duration::from_secs(5)),
            PolkitOutcome::Denied
        );
    }

    #[test]
    fn test_check_unavailable_on_unexpected_exit() {
        let dir = tempfile::tempdir().unwrap();
        // Exit 4+: not authorized for an unspecified reason beyond deny (1)
        // and dismiss (3) — treat as polkit being unavailable.
        let bin = mock_pkcheck(dir.path(), "pk-err", "4", 0);
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

    #[test]
    fn test_parse_start_time_field_22() {
        // A real-shaped /proc/<pid>/stat line whose comm contains spaces,
        // parentheses and a ')': parsing must start after the LAST ')'.
        let stat = "2925545 (tmux: server) R 2925453 2925545 2925453 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 6510279 6414336 528 18446744073709551615 93886024716288 93886024742833 140722543115744 0 0 0 0 0 0 0 0 0 17 10 0 0 0 0 0 93886024759792 93887044706304 140722543118666 140722543118686 140722543118686 140722543128554 0";
        // Field 22 (starttime) is the 20th token after ')': 6510279.
        assert_eq!(parse_start_time(stat), Some(6_510_279));
        assert_eq!(parse_start_time("12 (a) S 1 2 3"), None, "too short");
        assert_eq!(parse_start_time("12 no-comm here"), None);
    }

    #[test]
    fn test_process_subject_is_pid_starttime_uid() {
        let subject = process_subject().expect("/proc/self/stat must be parseable on Linux");
        let parts: Vec<&str> = subject.split(',').collect();
        assert_eq!(
            parts.len(),
            3,
            "subject must be pid,start-time,uid: {subject}"
        );
        assert_eq!(parts[0], std::process::id().to_string(), "pid first");
        let start_time: u64 = parts[1].parse().expect("start time must be numeric");
        assert!(start_time > 0, "start time must be non-zero: {subject}");
        let uid: u32 = parts[2].parse().expect("uid must be numeric");
        assert_eq!(uid, unsafe { libc::getuid() }, "uid last");
    }

    #[test]
    fn test_check_passes_unambiguous_process_subject() {
        let dir = tempfile::tempdir().unwrap();
        let bin = mock_pkcheck(dir.path(), "pk-subject", "0", 0);
        assert_eq!(
            check(POLKIT_ACTION_ID, &bin, Duration::from_secs(5)),
            PolkitOutcome::Authorized
        );
        let args = fs::read_to_string(dir.path().join("args.log")).unwrap();
        // The bare-pid form is racy per pkcheck(1); the shipped subject must
        // carry start time and uid: "--process <pid>,<start-time>,<uid>".
        let subject = args
            .split("--process ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("--process argument present");
        let parts: Vec<&str> = subject.split(',').collect();
        assert_eq!(parts.len(), 3, "pid,start-time,uid expected: {args}");
        assert_eq!(parts[0], std::process::id().to_string());
        assert!(parts[1].parse::<u64>().map(|t| t > 0).unwrap_or(false));
        assert_eq!(parts[2], unsafe { libc::getuid() }.to_string());
    }
}
