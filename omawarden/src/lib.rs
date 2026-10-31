pub mod api;
pub mod attachment;
pub mod auth;
pub mod clipboard;
pub mod config;
pub mod crypto;
pub mod daemon;
pub mod fs_util;
pub mod generator;
pub mod health;
pub mod hook;
pub mod keyring;
pub mod locked;
pub mod logging;
pub mod polkit;
pub mod ssh;
pub mod ssh_agent;
pub mod storage;
pub mod totp;
pub mod vault;
pub mod webauthn;

/// Serialises tests that change process-wide environment variables, and tests
/// whose result depends on them, so they don't race under the parallel runner.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Writes an executable test script from a child process.
///
/// Writing it from the test process races with other tests spawning commands:
/// a child forked in between inherits the open write handle, and running the
/// script then fails with ETXTBSY ("Text file busy").
#[cfg(test)]
pub(crate) fn write_test_executable(path: &std::path::Path, content: impl AsRef<[u8]>) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("sh")
        .args(["-c", r#"cat > "$1" && chmod 755 "$1""#, "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content.as_ref())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
