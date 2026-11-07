use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::handlers::handle_client;
use super::protocol::{get_socket_path, validate_socket_path};
use super::state::{DaemonState, ShutdownSignal};

pub(crate) fn open_daemon_lock(path: &Path) -> io::Result<fs::File> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && !p.exists())
    {
        crate::fs_util::create_secure_dir_all(parent, 0o700)?;
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid daemon instance lock",
        ));
    }
    Ok(file)
}

pub(crate) fn lock_daemon_instance(path: &Path) -> io::Result<fs::File> {
    use std::io::{Error, ErrorKind};

    let file = open_daemon_lock(path)?;
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => {
            Error::new(ErrorKind::AlreadyExists, "Vault daemon already running")
        }
        fs::TryLockError::Error(error) => error,
    })?;
    Ok(file)
}

/// Programmatic daemon server for embedded and CLI lifecycles.
pub struct DaemonServer {
    state: Arc<DaemonState>,
    socket_path: Option<PathBuf>,
}

impl DaemonServer {
    /// Create a new daemon server for the given state.
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self {
            state,
            socket_path: None,
        }
    }

    /// Override the socket path (useful for testing or isolated environments).
    pub fn with_socket_path(mut self, path: PathBuf) -> Self {
        self.socket_path = Some(path);
        self
    }

    /// Mark whether this daemon server is hosted in-process inside an external application.
    pub fn in_process(self, in_process: bool) -> Self {
        self.state.set_in_process(in_process);
        self
    }

    /// Access the cooperative shutdown signal.
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.state.shutdown.clone()
    }

    /// Run the server loop synchronously on the current thread until shutdown is triggered.
    pub fn serve(self) -> std::io::Result<()> {
        let socket_path = self.socket_path.unwrap_or_else(get_socket_path);
        serve_daemon(self.state, &socket_path)
    }

    /// Spawn the server loop on a dedicated background thread, waiting until the socket
    /// is bound and ready to accept connections before returning the handle.
    pub fn spawn(self) -> std::io::Result<DaemonHandle> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let shutdown = self.shutdown_signal();
        let socket_path = self.socket_path.unwrap_or_else(get_socket_path);
        let state = self.state;
        let thread = std::thread::Builder::new()
            .name("omawarden-daemon".to_string())
            .spawn(move || serve_daemon_with_ready(state, &socket_path, Some(ready_tx)))?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(DaemonHandle { thread, shutdown }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "daemon worker thread exited prematurely",
                ))
            }
        }
    }
}

/// Handle to a background daemon server thread.
pub struct DaemonHandle {
    pub thread: std::thread::JoinHandle<std::io::Result<()>>,
    pub shutdown: ShutdownSignal,
}

impl DaemonHandle {
    /// Signal the server to shut down cooperatively.
    pub fn stop(&self) {
        self.shutdown.trigger();
    }

    /// Check if the server has been requested to shut down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.is_shutting_down()
    }

    /// Wait for the server thread to finish and return its result.
    pub fn join(self) -> std::thread::Result<std::io::Result<()>> {
        self.thread.join()
    }
}

pub fn run_daemon_server(state: Arc<DaemonState>) -> std::io::Result<()> {
    DaemonServer::new(state).serve()
}

pub(crate) fn serve_daemon(state: Arc<DaemonState>, socket_path: &Path) -> std::io::Result<()> {
    serve_daemon_with_ready(state, socket_path, None)
}

pub(crate) fn serve_daemon_with_ready(
    state: Arc<DaemonState>,
    socket_path: &Path,
    ready_tx: Option<std::sync::mpsc::Sender<std::io::Result<()>>>,
) -> std::io::Result<()> {
    let setup = || -> std::io::Result<(UnixListener, fs::File, fs::File)> {
        use std::io::{Error, ErrorKind};
        if let Some(parent) = socket_path.parent() {
            crate::fs_util::create_secure_dir_all(parent, 0o700)?;
        }
        if let Ok(mut sp_guard) = state.socket_path.lock() {
            *sp_guard = Some(socket_path.to_path_buf());
        }

        // One owner for the socket and one for the encrypted cache, even when a
        // second process starts with a different runtime or configuration path.
        let socket_owner = lock_daemon_instance(&socket_path.with_extension("instance.lock"))?;
        let cache_owner = lock_daemon_instance(
            &state
                .vault_mgr
                .storage_mgr
                .file_path
                .with_extension("daemon.lock"),
        )?;
        if socket_path.exists() {
            validate_socket_path(socket_path)?;
            match UnixStream::connect(socket_path) {
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::AlreadyExists,
                        "Vault daemon already running",
                    ))
                }
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    let _ = fs::remove_file(socket_path);
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        let listener = UnixListener::bind(socket_path)?;
        let mut perms = fs::metadata(socket_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(socket_path, perms)?;
        listener.set_nonblocking(true)?;

        if let Err(e) = crate::ssh_agent::apply(&state) {
            crate::log_error!("omawarden:daemon", "SSH agent failed to start: {}", e);
        }

        Ok((listener, socket_owner, cache_owner))
    };

    let (listener, _socket_owner, _cache_owner) = match setup() {
        Ok(res) => {
            if let Some(tx) = ready_tx {
                let _ = tx.send(Ok(()));
            }
            res
        }
        Err(e) => {
            if let Some(tx) = ready_tx {
                let _ = tx.send(Err(std::io::Error::new(e.kind(), e.to_string())));
            }
            return Err(e);
        }
    };

    let state_clone = state.clone();
    let shutdown_clone = state.shutdown.clone();
    let watchdog = std::thread::spawn(move || {
        while !shutdown_clone.is_shutting_down() {
            let is_unlocked = state_clone.vault_mgr.is_unlocked();
            let sleep_duration = if is_unlocked {
                Duration::from_secs(2)
            } else {
                Duration::from_secs(5)
            };
            let start = Instant::now();
            while start.elapsed() < sleep_duration {
                if shutdown_clone.is_shutting_down() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if shutdown_clone.is_shutting_down() {
                return;
            }
            // Resume-edge suspend detection must run regardless of lock state:
            // the dominant quick-unlock state (soft-locked) is exactly when the
            // screen detector above would otherwise never fire.
            state_clone.check_suspend_drift();
            state_clone.check_auto_lock();
            state_clone.check_screen_lock();
        }
    });

    use std::os::unix::io::AsRawFd;
    let fd = listener.as_raw_fd();
    let mut loop_err = None;

    while !state.shutdown.is_shutting_down() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            loop_err = Some(err);
            break;
        }
        if ret == 0 {
            continue;
        }
        if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0
            && (pfd.revents & libc::POLLIN) == 0
        {
            break;
        }
        if (pfd.revents & libc::POLLIN) != 0 {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let st = state.clone();
                    std::thread::spawn(move || {
                        let _ = handle_client(stream, st);
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    crate::log_error!("omawarden:daemon", "Socket accept error: {}", e);
                }
            }
        }
    }

    // Ensure shutdown is marked
    state.shutdown.trigger();

    // Clean up watchdog thread
    let _ = watchdog.join();

    // Final clean-up: lock vault, stop SSH agent, unlink socket
    state.lock();
    crate::ssh_agent::stop(&state);
    let _ = fs::remove_file(socket_path);

    if let Some(err) = loop_err {
        Err(err)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn verify_peer_credentials(stream: &UnixStream) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut ucred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut ucred_len,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let current_uid = unsafe { libc::getuid() };
    if ucred.uid != current_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Peer UID mismatch: expected {}, got {}",
                current_uid, ucred.uid
            ),
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn get_peer_pid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut ucred_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut ucred_len,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    if ucred.pid <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid peer PID",
        ));
    }

    Ok(ucred.pid as u32)
}

#[cfg(not(target_os = "linux"))]
pub fn get_peer_pid(_stream: &UnixStream) -> std::io::Result<u32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Peer PID inspection unsupported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn verify_peer_credentials(_stream: &UnixStream) -> std::io::Result<()> {
    Ok(())
}
