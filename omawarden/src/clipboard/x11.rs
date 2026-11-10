use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::provider::ClipboardProvider;

/// X11 clipboard provider backed by `xclip`.
#[derive(Debug, Clone)]
pub struct X11ClipboardProvider {
    pub path: PathBuf,
}

impl Default for X11ClipboardProvider {
    fn default() -> Self {
        Self::new_with_path(None)
    }
}

impl X11ClipboardProvider {
    pub fn new(path: &str) -> Self {
        Self::new_with_path(Some(Path::new(path)))
    }

    pub fn new_with_path(explicit_path: Option<&Path>) -> Self {
        let path = if let Some(p) = explicit_path {
            p.to_path_buf()
        } else {
            PathBuf::from("xclip")
        };
        Self { path }
    }
}

impl ClipboardProvider for X11ClipboardProvider {
    fn name(&self) -> &'static str {
        "x11"
    }

    fn is_available(&self) -> bool {
        std::env::var_os("DISPLAY").is_some() && which::which(&self.path).is_ok()
    }

    fn unavailable_reason(&self) -> Option<String> {
        if std::env::var_os("DISPLAY").is_none() {
            Some("X11 display ($DISPLAY) is not configured.".to_string())
        } else if which::which(&self.path).is_err() {
            Some("X11 clipboard utility 'xclip' not found. Please install 'xclip'.".to_string())
        } else {
            None
        }
    }

    fn monitors_selection(&self) -> bool {
        false
    }

    fn binary_path(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn copy(&self, text: &str, _sensitive: bool) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.args(["-selection", "clipboard"]);
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
            Err(io::Error::other("xclip failed"))
        }
    }

    fn copy_from_stdin(&self, _sensitive: bool) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.args(["-selection", "clipboard"]);
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("xclip from stdin failed"))
        }
    }

    fn clear(&self) -> io::Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.args(["-selection", "clipboard"]);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let written = child.stdin.take().expect("stdin was piped").write_all(b"");
        let status = child.wait()?;
        written?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("xclip clear failed"))
        }
    }
}
