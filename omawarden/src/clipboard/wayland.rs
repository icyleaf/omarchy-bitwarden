use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::provider::ClipboardProvider;
use super::CLIPBOARD_SETUP_TIMEOUT;

/// Wayland clipboard provider backed by `wl-clipboard` (`wl-copy`).
#[derive(Debug, Clone)]
pub struct WlClipboardProvider {
    pub path: PathBuf,
}

impl Default for WlClipboardProvider {
    fn default() -> Self {
        Self::new_with_path(None)
    }
}

impl WlClipboardProvider {
    pub fn new(path: &str) -> Self {
        Self::new_with_path(Some(Path::new(path)))
    }

    pub fn new_with_path(explicit_path: Option<&Path>) -> Self {
        let path = if let Some(p) = explicit_path {
            which::which(p).unwrap_or_else(|_| p.to_path_buf())
        } else if let Ok(env_path) = std::env::var("OMA_WL_COPY_PATH") {
            let p = PathBuf::from(env_path);
            which::which(&p).unwrap_or(p)
        } else {
            which::which("wl-copy").unwrap_or_else(|_| PathBuf::from("wl-copy"))
        };
        Self { path }
    }
}

impl ClipboardProvider for WlClipboardProvider {
    fn name(&self) -> &'static str {
        "wayland"
    }

    fn is_available(&self) -> bool {
        which::which(&self.path).is_ok()
    }

    fn is_configured(&self) -> io::Result<bool> {
        if !self.is_available() {
            return Ok(false);
        }
        super::wayland_configured()
    }

    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            None
        } else {
            Some(
                "Wayland clipboard utility 'wl-copy' not found. Please install 'wl-clipboard'."
                    .to_string(),
            )
        }
    }

    fn monitors_selection(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn binary_path(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn copy(&self, text: &str, sensitive: bool) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.args(["--type", "text/plain"]);
        if sensitive {
            cmd.arg("--sensitive");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let written = child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(text.as_bytes());
        let status = child.wait()?;
        written?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("wl-copy execution failed"))
        }
    }

    fn copy_from_stdin(&self, sensitive: bool) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.args(["--type", "text/plain"]);
        if sensitive {
            cmd.arg("--sensitive");
        }
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                "wl-copy failed to set selection from stdin",
            ))
        }
    }

    fn clear(&self) -> io::Result<()> {
        let mut child = Command::new(&self.path)
            .arg("--clear")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let deadline = Instant::now() + CLIPBOARD_SETUP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        return Ok(());
                    } else {
                        return Err(io::Error::other("wl-copy --clear failed"));
                    }
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(result.err().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::TimedOut, "wl-copy --clear timed out")
                    }));
                }
            }
        }
    }
}
