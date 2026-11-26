//! Shared test isolation, bounded mock listeners, and pause points.
use std::ffi::{OsStr, OsString};
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const CREDENTIAL_ID: &str = "11111111111111111111111111111111";
pub(crate) const MOCK_IO_TIMEOUT: Duration = Duration::from_secs(10);

fn poll_accept<T>(
    timeout: Duration,
    label: &str,
    mut accept_fn: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let deadline = Instant::now() + timeout;
    loop {
        match accept_fn() {
            Ok(stream) => return Ok(stream),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("mock {label} listener timed out waiting for connection"),
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
}

/// Accepts a single TCP connection within `timeout` and configures bounded read/write timeouts.
pub(crate) fn accept_tcp_bounded(
    listener: &TcpListener,
    timeout: Duration,
) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let stream = poll_accept(timeout, "TCP", || listener.accept().map(|(s, _)| s))?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Accepts a single Unix socket connection within `timeout` and configures bounded read/write timeouts.
pub(crate) fn accept_unix_bounded(
    listener: &UnixListener,
    timeout: Duration,
) -> io::Result<UnixStream> {
    listener.set_nonblocking(true)?;
    let stream = poll_accept(timeout, "Unix", || listener.accept().map(|(s, _)| s))?;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Inner undo-stack for environment variables modified while [`crate::env_lock`] is held.
struct ScopedEnv {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl ScopedEnv {
    fn new() -> Self {
        Self {
            saved: Vec::with_capacity(16),
        }
    }

    fn set_var(&mut self, key: &'static str, value: impl AsRef<OsStr>) {
        if !self.saved.iter().any(|(k, _)| *k == key) {
            self.saved.push((key, std::env::var_os(key)));
        }
        std::env::set_var(key, value);
    }

    fn remove_var(&mut self, key: &'static str) {
        if !self.saved.iter().any(|(k, _)| *k == key) {
            self.saved.push((key, std::env::var_os(key)));
        }
        std::env::remove_var(key);
    }

    fn isolate_root(&mut self, root: &Path, preserve_explicit_dirs: bool) {
        let runtime_dir = root.join("runtime");
        let config_dir = root.join("config");
        let data_dir = root.join("data");
        crate::fs_util::create_secure_dir_all(&runtime_dir, 0o700).expect("create runtime dir");
        crate::fs_util::create_secure_dir_all(&config_dir, 0o700).expect("create config dir");
        crate::fs_util::create_secure_dir_all(&data_dir, 0o700).expect("create data dir");

        self.set_var("XDG_RUNTIME_DIR", &runtime_dir);
        if !preserve_explicit_dirs || std::env::var_os("OMAWARDEN_CONFIG_DIR").is_none() {
            self.remove_var("OMAWARDEN_CONFIG_DIR");
            self.set_var("XDG_CONFIG_HOME", &config_dir);
        }
        if !preserve_explicit_dirs || std::env::var_os("OMAWARDEN_DATA_DIR").is_none() {
            self.remove_var("OMAWARDEN_DATA_DIR");
            self.set_var("XDG_DATA_HOME", &data_dir);
        }
        self.set_var("OMA_DAEMON_LAUNCH_STRATEGY", "disabled");
        self.remove_var("OMA_DAEMON_BIN");
        self.set_var("OMA_KEYRING_PROVIDER", "mock");
        self.remove_var("OMA_SECRET_TOOL_PATH");
        self.set_var("OMA_CLIPBOARD_PROVIDER", "mock");
        self.remove_var("WAYLAND_DISPLAY");
        self.remove_var("WAYLAND_SOCKET");
        self.remove_var("DISPLAY");
        self.remove_var("OMAWARDEN_PLUGIN_MANIFEST_PATH");
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        for (key, previous) in self.saved.drain(..).rev() {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// RAII test environment guard holding [`crate::env_lock`] and isolating runtime,
/// configuration, data directories, daemon launch strategy, Keyring Provider, and
/// Clipboard Provider from the developer's live desktop session.
pub(crate) struct TestEnv {
    _root: tempfile::TempDir,
    scoped: ScopedEnv,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl TestEnv {
    pub(crate) fn isolated() -> Self {
        let lock = crate::env_lock();
        crate::daemon::reset_daemon_launch_strategy();

        let root = tempfile::tempdir().expect("create isolated test root");
        let mut scoped = ScopedEnv::new();
        scoped.isolate_root(root.path(), false);

        Self {
            _root: root,
            scoped,
            _lock: lock,
        }
    }

    pub(crate) fn set_var(&mut self, key: &'static str, value: impl AsRef<OsStr>) {
        self.scoped.set_var(key, value);
    }

    pub(crate) fn remove_var(&mut self, key: &'static str) {
        self.scoped.remove_var(key);
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        crate::daemon::reset_daemon_launch_strategy();
    }
}

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
/// The caller holds env_lock (or TestEnv) for the lifetime of the server.
pub(crate) struct TestDaemon {
    pub(crate) state: std::sync::Arc<crate::daemon::DaemonState>,
    socket: std::path::PathBuf,
    _root: tempfile::TempDir,
    _scoped_env: ScopedEnv,
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
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let mut scoped_env = ScopedEnv::new();
        scoped_env.isolate_root(root.path(), true);

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
                let Ok(stream) = stream else {
                    break;
                };
                if done.load(Ordering::Relaxed) {
                    break;
                }
                let _ = stream.set_read_timeout(Some(MOCK_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(MOCK_IO_TIMEOUT));
                let state = Arc::clone(&daemon);
                clients.push(std::thread::spawn(move || {
                    let _ = crate::daemon::handle_client(stream, state);
                }));
            }
            for client in clients {
                let _ = client.join();
            }
        });
        Self {
            state,
            socket,
            _root: root,
            _scoped_env: scoped_env,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.state.shutdown.trigger();
        let _ = UnixStream::connect(&self.socket);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
