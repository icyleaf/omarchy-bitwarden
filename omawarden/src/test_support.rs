//! One-shot pause points for deterministic publication interleavings.
use std::sync::{mpsc, Mutex};
use std::time::Duration;

pub(crate) const CREDENTIAL_ID: &str = "11111111111111111111111111111111";

#[derive(Default)]
pub(crate) struct PausePoint(Mutex<Option<Box<dyn FnOnce() + Send>>>);

impl PausePoint {
    pub(crate) fn arm(&self) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let mut hook = self.0.lock().unwrap();
        assert!(hook.is_none(), "pause point already armed");
        *hook = Some(Box::new(move || {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("publication pause was not released");
        }));
        (entered_rx, release_tx)
    }

    pub(crate) fn reach(&self) {
        let hook = self.0.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

/// Serve real daemon requests using the test vault and an isolated socket.
/// The caller holds env_lock for the lifetime of the server.
pub(crate) struct TestDaemon {
    pub(crate) state: std::sync::Arc<crate::daemon::DaemonState>,
    runtime: tempfile::TempDir,
    previous_runtime: Option<std::ffi::OsString>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl TestDaemon {
    pub(crate) fn for_auth(auth: &crate::auth::AuthManager) -> Self {
        Self::start(std::sync::Arc::new(crate::vault::VaultManager::new(
            &auth.server_url,
            Some(auth.storage_mgr.clone()),
            Some(auth.keyring_mgr.clone()),
        )))
    }

    pub(crate) fn start(vault: std::sync::Arc<crate::vault::VaultManager>) -> Self {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let runtime = tempfile::tempdir().unwrap();
        let previous_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        let socket = crate::daemon::get_socket_path();
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut state = crate::daemon::DaemonState::new(vault.storage_mgr.clone(), 0);
        state.vault_mgr = vault;
        let state = Arc::new(state);
        let daemon = Arc::clone(&state);
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut clients = Vec::new();
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                if done.load(Ordering::Relaxed) {
                    break;
                }
                let state = Arc::clone(&daemon);
                clients.push(std::thread::spawn(move || {
                    let _ = crate::daemon::handle_client(stream, state);
                }));
            }
            for client in clients {
                client.join().unwrap();
            }
        });
        Self {
            state,
            runtime,
            previous_runtime,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let socket = self.runtime.path().join("omawarden.sock");
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _wake = std::os::unix::net::UnixStream::connect(socket).unwrap();
        self.worker.take().unwrap().join().unwrap();
        match self.previous_runtime.take() {
            Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
}
