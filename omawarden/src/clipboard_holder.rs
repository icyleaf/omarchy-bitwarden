//! Lifetime of a clipboard source, isolated from the CLI and daemon.
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use omawarden::clipboard::ClipboardScope;

/// Runs in a dedicated CLI process with the clipboard text on stdin.
pub(super) fn hold_selection(
    wl_copy: &Path,
    timeout: Duration,
    sensitive: bool,
    scope: Option<&ClipboardScope>,
) -> io::Result<()> {
    // The holder must own its session before it can signal its process group.
    // SAFETY: setsid takes no arguments and affects only the calling process.
    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error());
    }
    // Adopt the source wl-copy forks so a takeover can end the holder early.
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_CHILD_SUBREAPER takes an integer flag, not a pointer.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // The detached worker owns this gate. Stopping the GUI or the calling CLI
    // does not let activation clear the selection before this copy is ready.
    let output = scope.map(ClipboardScope::begin_output).transpose()?;
    let revoke = || {
        // SAFETY: setsid succeeded above. Group zero can only reach this
        // holder and its private wl-copy descendants, even after a takeover.
        unsafe { libc::kill(0, libc::SIGKILL) };
    };
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("clipboard-expiry".into())
        .spawn(move || {
            if ready_rx
                .recv_timeout(omawarden::clipboard::CLIPBOARD_SETUP_TIMEOUT)
                .is_ok()
            {
                if timeout.is_zero() {
                    return;
                }
                std::thread::sleep(timeout);
            }
            revoke();
        })?;

    // wl-copy exits its launcher only after synchronizing the selection with
    // the compositor. Bound setup as well as the life of a timed selection.
    let mut command = Command::new(wl_copy);
    command.args(["--type", "text/plain"]);
    if sensitive {
        command.arg("--sensitive");
    }
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .status();
    let mut ready = io::stdout().lock();
    if !status.is_ok_and(|status| status.success())
        || ready_tx.send(()).is_err()
        || ready.write_all(&[1]).and_then(|()| ready.flush()).is_err()
    {
        revoke();
    }
    drop(ready);
    drop(output);
    if timeout.is_zero() {
        return Ok(());
    }

    // Other Unix systems do not adopt the forked source. Keep its session
    // leader around until expiry so the process group can never be reused.
    #[cfg(not(target_os = "linux"))]
    loop {
        std::thread::park();
    }

    // Losing the selection makes wl-copy exit. Reap it and release the
    // timer immediately, even for a very long configured TTL.
    #[cfg(target_os = "linux")]
    loop {
        // SAFETY: the holder is dedicated to this one copy; status is unused.
        if unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            if err.kind() != io::ErrorKind::Interrupted {
                revoke();
                return Err(err);
            }
        }
    }
}
