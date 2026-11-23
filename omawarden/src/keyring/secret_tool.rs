use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use crate::credential_slots::CredentialSlot;

use super::provider::KeyringProvider;
use super::{SCOPED_SERVICE_NAME, SERVICE_NAME};

/// Linux FreeDesktop Secret Service keyring provider backed by `secret-tool`.
#[derive(Debug, Clone)]
pub struct SecretToolKeyringProvider {
    pub path: PathBuf,
}

impl Default for SecretToolKeyringProvider {
    fn default() -> Self {
        Self::new_with_path(None)
    }
}

impl SecretToolKeyringProvider {
    pub fn new(path: &str) -> Self {
        Self::new_with_path(Some(Path::new(path)))
    }

    pub fn new_with_path(explicit_path: Option<&Path>) -> Self {
        let path = if let Some(p) = explicit_path {
            which::which(p).unwrap_or_else(|_| p.to_path_buf())
        } else if let Ok(env_path) = std::env::var("OMA_SECRET_TOOL_PATH") {
            let p = PathBuf::from(env_path);
            which::which(&p).unwrap_or(p)
        } else {
            which::which("secret-tool").unwrap_or_else(|_| PathBuf::from("secret-tool"))
        };
        Self { path }
    }

    fn clear_command(&self, attributes: &[&str]) -> Command {
        let mut command = Command::new(&self.path);
        command
            .arg("clear")
            .args(attributes)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
}

impl KeyringProvider for SecretToolKeyringProvider {
    fn name(&self) -> &'static str {
        "secret-tool"
    }

    fn is_available(&self) -> bool {
        which::which(&self.path).is_ok()
    }

    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            None
        } else {
            Some("Linux Secret Service (secret-tool) is not available.".to_string())
        }
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
        let mut command = Command::new(&self.path);
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
        let output = Command::new(&self.path)
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

    fn erase_credential_slot(
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
        let search = Command::new(&self.path)
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
