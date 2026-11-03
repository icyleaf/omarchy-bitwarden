//! Lifetime of a single timed clipboard source, isolated from the CLI and daemon.
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Runs in a dedicated CLI process with the clipboard text on stdin.
pub(super) fn hold_selection(wl_copy: &Path, timeout: Duration) -> io::Result<()> {
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
    // Normal wl-copy exits its launcher successfully only after setting the
    // selection and synchronizing with the compositor. Keep that ready signal.
    let status = Command::new(wl_copy)
        .arg("--sensitive")
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("wl-copy could not set the selection"));
    }

    let revoke = || {
        // SAFETY: setsid succeeded above. Group zero can only reach this
        // holder and its private wl-copy descendants, even after a takeover.
        unsafe { libc::kill(0, libc::SIGKILL) };
    };
    let expiry = std::thread::Builder::new()
        .name("clipboard-expiry".into())
        .spawn(move || {
            std::thread::sleep(timeout);
            revoke();
        });
    let mut ready = io::stdout().lock();
    if expiry.is_err() || ready.write_all(&[1]).and_then(|()| ready.flush()).is_err() {
        revoke();
    }
    drop(ready);

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
