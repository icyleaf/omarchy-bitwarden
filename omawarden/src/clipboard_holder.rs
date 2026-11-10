//! Lifetime of a clipboard source, isolated from the CLI and daemon.
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use omawarden::clipboard::{ClipboardProvider, ClipboardScope};

/// Runs in a dedicated CLI process with the clipboard text on stdin.
pub(super) fn hold_selection(
    provider: Arc<dyn ClipboardProvider>,
    timeout: Duration,
    sensitive: bool,
    scope: Option<&ClipboardScope>,
) -> io::Result<()> {
    // The holder must own its session before it can signal its process group.
    // SAFETY: setsid takes no arguments and affects only the calling process.
    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error());
    }
    // Adopt child forks (such as wl-copy) so a takeover can end the holder early.
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_CHILD_SUBREAPER takes an integer flag, not a pointer.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong, 0, 0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // The detached worker owns this gate. Stopping the GUI or the calling CLI
    // does not let activation clear the selection before this copy is ready.
    let output = scope
        .map(|s| s.begin_output_with_provider(&*provider))
        .transpose()?;
    let revoke = || {
        // SAFETY: setsid succeeded above. Group zero can only reach this
        // holder and its private descendants, even after a takeover.
        unsafe { libc::kill(0, libc::SIGKILL) };
    };

    let expiry_provider = provider.clone();
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
                let _ = expiry_provider.clear();
            }
            revoke();
        })?;

    let copy_result = provider.copy_from_stdin(sensitive);
    let mut ready = io::stdout().lock();
    if copy_result.is_err()
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

    if provider.monitors_selection() {
        // Other Unix systems do not adopt the forked source. Keep its session
        // leader around until expiry so the process group can never be reused.
        #[cfg(not(target_os = "linux"))]
        loop {
            std::thread::park();
        }

        // Losing the selection makes selection-monitoring providers (e.g. wl-copy) exit.
        // Reap it and release the timer immediately, even for a very long configured TTL.
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
    } else {
        // Providers that do not monitor selection (e.g. macOS pbcopy, mock) park
        // until the expiry thread triggers clear and revoke.
        loop {
            std::thread::park();
        }
    }
}
