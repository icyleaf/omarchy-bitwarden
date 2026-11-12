use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use super::protocol::{
    check_protocol_version, get_socket_path, validate_socket_path, ProtocolCheck,
};
use super::server::{lock_daemon_instance, verify_peer_credentials};

pub(crate) struct DaemonOwnerGuard {
    _socket: fs::File,
    _cache: fs::File,
}

// Ping carries metadata only. Bound it separately from vault-data responses.
const MAX_EPOCH_PING_BYTES: u64 = 16 * 1024;

fn acquire_daemon_ownership(cache: &Path) -> io::Result<DaemonOwnerGuard> {
    Ok(DaemonOwnerGuard {
        _socket: lock_daemon_instance(&get_socket_path().with_extension("instance.lock"))?,
        _cache: lock_daemon_instance(&cache.with_extension("daemon.lock"))?,
    })
}

// Keep connection failures distinct from confirmed owner absence.
fn existing_daemon_stream() -> io::Result<Option<UnixStream>> {
    let path = get_socket_path();
    validate_socket_path(&path)?;
    let stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    verify_peer_credentials(&stream)?;
    Ok(Some(stream))
}

/// Keep both owner leases while performing a local transition without a daemon.
pub(crate) fn guard_absent_daemon(cache: &Path) -> io::Result<DaemonOwnerGuard> {
    let owner = acquire_daemon_ownership(cache)?;
    if existing_daemon_stream()?.is_some() {
        return Err(io::Error::other(
            "A live daemon must confirm the vault lock",
        ));
    }
    Ok(owner)
}

/// Confirm shared-epoch support, or hold the leases proving the daemon absent.
/// Call again under the output gate before publishing an offline value.
pub(crate) fn guard_cache_daemon(cache: &Path) -> io::Result<Option<DaemonOwnerGuard>> {
    let owner = match acquire_daemon_ownership(cache) {
        Ok(owner) => Some(owner),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
        Err(error) => return Err(error),
    };
    let Some(mut stream) = existing_daemon_stream()? else {
        return owner
            .map(Some)
            .ok_or_else(|| io::Error::other("Cannot confirm the daemon owner. Retry the copy."));
    };
    let timeout = Some(crate::clipboard::CLIPBOARD_SETUP_TIMEOUT);
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    // Publishers hold the output gate here. Ping must remain independent of
    // both that gate and restore_guard, as output_generation is.
    writeln!(stream, "{}", json!({"action": "ping"}))?;
    let mut response = String::new();
    BufReader::new(stream)
        .take(MAX_EPOCH_PING_BYTES)
        .read_line(&mut response)?;
    let reply: Value = serde_json::from_str(&response)?;
    if reply["ok"] != true
        || reply["pong"] != true
        || reply["shared_lock_epoch"] != true
        || check_protocol_version(&reply) != ProtocolCheck::Compatible
    {
        return Err(io::Error::other(
            "The running daemon cannot authorize offline copies. Restart it with shared lock epoch support.",
        ));
    }
    Ok(owner)
}

/// Execution strategy for resolving and launching the standalone daemon binary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DaemonLaunchStrategy {
    /// Automatic resolution:
    /// 1. `OMA_DAEMON_BIN` environment variable (if set and pointing to an existing file).
    /// 2. `env::current_exe()` if its file stem is "omawarden".
    /// 3. Lookup "omawarden" in system PATH via `which::which("omawarden")`.
    #[default]
    Auto,
    /// Explicit executable path to the standalone omawarden binary.
    Explicit(PathBuf),
    /// In-process daemon host: external process spawning is disabled because
    /// the host application manages the daemon server lifecycle directly in-process.
    InProcess,
    /// Daemon launching is disabled. If no daemon is already active, callers fail closed.
    Disabled,
}

static LAUNCH_STRATEGY: Mutex<Option<DaemonLaunchStrategy>> = Mutex::new(None);

/// Sets the process-global daemon launch strategy.
pub fn set_daemon_launch_strategy(strategy: DaemonLaunchStrategy) {
    let mut lock = LAUNCH_STRATEGY.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(strategy);
}

/// Clears any configured process-global daemon launch strategy, reverting to default (`Auto`).
pub fn reset_daemon_launch_strategy() {
    let mut lock = LAUNCH_STRATEGY.lock().unwrap_or_else(|e| e.into_inner());
    *lock = None;
}

/// Resolves the effective daemon launch strategy from process configuration or environment.
pub fn daemon_launch_strategy() -> DaemonLaunchStrategy {
    let lock = LAUNCH_STRATEGY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref strategy) = *lock {
        return strategy.clone();
    }
    drop(lock);

    if let Ok(bin) = env::var("OMA_DAEMON_BIN") {
        let trimmed = bin.trim();
        if !trimmed.is_empty() {
            return DaemonLaunchStrategy::Explicit(PathBuf::from(trimmed));
        }
    }

    if let Ok(strat) = env::var("OMA_DAEMON_LAUNCH_STRATEGY") {
        let trimmed = strat.trim();
        match trimmed.to_lowercase().as_str() {
            "disabled" | "none" | "off" | "false" => return DaemonLaunchStrategy::Disabled,
            "in-process" | "inprocess" | "host" => return DaemonLaunchStrategy::InProcess,
            "auto" | "system" | "system-cli" | "system_cli" | "cli" => {
                return DaemonLaunchStrategy::Auto;
            }
            _ if !trimmed.is_empty() => {
                return DaemonLaunchStrategy::Explicit(PathBuf::from(trimmed));
            }
            _ => {}
        }
    }

    DaemonLaunchStrategy::Auto
}

/// Verifies whether the path represents the canonical `omawarden` CLI binary by file stem.
pub fn is_omawarden_binary(path: &Path) -> bool {
    path.file_stem().is_some_and(|stem| stem == "omawarden")
}

/// Resolves the path to the standalone `omawarden` binary using the active launch strategy.
pub fn resolve_daemon_binary() -> io::Result<PathBuf> {
    resolve_daemon_binary_with_strategy(&daemon_launch_strategy())
}

/// Resolves the path to the standalone `omawarden` binary using a specific strategy.
pub fn resolve_daemon_binary_with_strategy(strategy: &DaemonLaunchStrategy) -> io::Result<PathBuf> {
    resolve_daemon_binary_custom(strategy, env::current_exe().ok().as_deref(), |name| {
        if cfg!(test) {
            // Tests never launch system binaries from PATH to avoid polluting the host
            // or interfering with isolated test environments.
            Err(which::Error::CannotFindBinaryPath)
        } else {
            which::which(name)
        }
    })
}

pub(crate) fn resolve_daemon_binary_custom<F>(
    strategy: &DaemonLaunchStrategy,
    current_exe: Option<&Path>,
    which_lookup: F,
) -> io::Result<PathBuf>
where
    F: Fn(&str) -> Result<PathBuf, which::Error>,
{
    match strategy {
        DaemonLaunchStrategy::Explicit(path) => {
            if path.is_file() {
                Ok(path.clone())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Configured daemon binary '{}' does not exist or is not a file",
                        path.display()
                    ),
                ))
            }
        }
        DaemonLaunchStrategy::Disabled => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Daemon launching is disabled",
        )),
        DaemonLaunchStrategy::InProcess => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "External daemon launching is disabled for in-process host",
        )),
        DaemonLaunchStrategy::Auto => {
            if let Ok(bin) = env::var("OMA_DAEMON_BIN") {
                let trimmed = bin.trim();
                if !trimmed.is_empty() {
                    let path = PathBuf::from(trimmed);
                    if path.is_file() {
                        return Ok(path);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!(
                                "OMA_DAEMON_BIN '{}' does not exist or is not a file",
                                path.display()
                            ),
                        ));
                    }
                }
            }

            if let Some(exe) = current_exe {
                if is_omawarden_binary(exe) {
                    return Ok(exe.to_path_buf());
                }
            }

            match which_lookup("omawarden") {
                Ok(path) => Ok(path),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Could not locate 'omawarden' standalone executable in current binary or PATH",
                )),
            }
        }
    }
}

/// Unified client interface for communicating with the `omawarden` daemon.
///
/// Encapsulates Unix Domain Socket connection, peer UID security verification (`SO_PEERCRED`),
/// framed JSON protocol message transmission, and automatic lifecycle/protocol management.
#[derive(Debug, Clone)]
pub struct DaemonClient {
    socket_path: PathBuf,
    launch_strategy: DaemonLaunchStrategy,
    timeout: Option<Duration>,
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonClient {
    /// Creates a new `DaemonClient` using the default runtime socket path and active launch strategy.
    pub fn new() -> Self {
        Self {
            socket_path: get_socket_path(),
            launch_strategy: daemon_launch_strategy(),
            timeout: Some(Duration::from_secs(60)),
        }
    }

    /// Configures an explicit socket path for the client.
    pub fn with_socket_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket_path = path.into();
        self
    }

    /// Configures an explicit launch strategy for the client.
    pub fn with_launch_strategy(mut self, strategy: DaemonLaunchStrategy) -> Self {
        self.launch_strategy = strategy;
        self
    }

    /// Configures an explicit communication timeout for client socket read/write operations.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the target socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the active launch strategy.
    pub fn launch_strategy(&self) -> &DaemonLaunchStrategy {
        &self.launch_strategy
    }

    /// Returns the configured socket read/write timeout.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Connects to the daemon socket, enforcing security checks and mutual `SO_PEERCRED` validation.
    pub fn connect(&self) -> Result<UnixStream, DispatchError> {
        if !self.socket_path.exists() {
            return Err(DispatchError::NotSent);
        }

        if let Err(e) = validate_socket_path(&self.socket_path) {
            crate::log_error!(
                "omawarden:daemon",
                "Refusing to connect to socket {}: {}",
                self.socket_path.display(),
                e
            );
            return Err(DispatchError::NotSent);
        }

        let stream = UnixStream::connect(&self.socket_path).map_err(|_| DispatchError::NotSent)?;

        if let Some(timeout) = self.timeout {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
        }

        // Mutual SO_PEERCRED verification: client verifies that server process UID matches current UID
        if let Err(e) = verify_peer_credentials(&stream) {
            crate::log_error!(
                "omawarden:daemon",
                "Refusing to send request: server peer UID verification failed: {}",
                e
            );
            return Err(DispatchError::NotSent);
        }

        Ok(stream)
    }

    /// Sends a raw JSON request to the daemon without automatic client context or protocol checks.
    pub fn send_raw(&self, req: &Value) -> Result<Value, DispatchError> {
        let mut stream = self.connect()?;
        let payload = format!("{}\n", req);
        stream
            .write_all(payload.as_bytes())
            .map_err(|_| DispatchError::Unconfirmed)?;
        stream.flush().map_err(|_| DispatchError::Unconfirmed)?;

        let mut reader = BufReader::new(stream);
        let mut response_line = zeroize::Zeroizing::new(String::new());
        reader
            .read_line(&mut response_line)
            .map_err(|_| DispatchError::Unconfirmed)?;

        serde_json::from_str(&response_line).map_err(|_| DispatchError::Unconfirmed)
    }

    /// Sends a request with automatic client context attachment and data-plane protocol validation.
    pub fn send(&self, req: &Value) -> Result<Value, DispatchError> {
        let is_ping = req.get("action").and_then(|a| a.as_str()) == Some("ping");
        let mut payload_val = req.clone();
        if let Value::Object(ref mut map) = payload_val {
            if !map.contains_key("client") {
                if let Some(ctx) = crate::api::resolve_effective_client_context(None) {
                    map.insert("client".to_string(), json!(ctx));
                }
            }
        }
        let resp = self.send_raw(&payload_val)?;
        if is_ping || resp.get("protocol_version").is_some() {
            match check_protocol_version(&resp) {
                ProtocolCheck::Compatible => Ok(resp),
                ProtocolCheck::Incompatible {
                    running,
                    min_supported,
                    current,
                } => Err(DispatchError::IncompatibleProtocol {
                    running,
                    min_supported,
                    current,
                }),
            }
        } else {
            Ok(resp)
        }
    }

    /// Pings the daemon and validates protocol compatibility.
    pub fn ping(&self) -> Result<Value, DispatchError> {
        let resp = self.send_raw(&json!({ "action": "ping" }))?;
        match check_protocol_version(&resp) {
            ProtocolCheck::Compatible => Ok(resp),
            ProtocolCheck::Incompatible {
                running,
                min_supported,
                current,
            } => Err(DispatchError::IncompatibleProtocol {
                running,
                min_supported,
                current,
            }),
        }
    }

    /// Ensures the daemon is running, spawning it via the configured strategy if necessary.
    pub fn ensure_running(&self) -> Result<(), DispatchError> {
        match self.ping() {
            Ok(_) => return Ok(()),
            Err(e @ DispatchError::IncompatibleProtocol { .. }) => {
                crate::log_error!(
                    "omawarden:daemon",
                    "Running daemon protocol version is incompatible with client. Restart daemon explicitly."
                );
                return Err(e);
            }
            Err(_) => {}
        }

        let exe_path = match resolve_daemon_binary_with_strategy(&self.launch_strategy) {
            Ok(path) => path,
            Err(e) => {
                crate::log_error!("omawarden:daemon", "Refusing to spawn daemon: {}", e);
                return Err(DispatchError::LaunchFailed(e.to_string()));
            }
        };

        let cfg = crate::config::ConfigManager::default().load();
        let auto_lock_mins = if cfg.auto_lock_minutes >= 0 {
            cfg.auto_lock_minutes as u64
        } else {
            15
        };

        let mut cmd = Command::new(&exe_path);
        cmd.arg("daemon")
            .arg("--auto-lock")
            .arg(auto_lock_mins.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }

        if let Err(e) = cmd.spawn() {
            crate::log_error!(
                "omawarden:daemon",
                "Failed to spawn daemon process '{}': {}",
                exe_path.display(),
                e
            );
            return Err(DispatchError::LaunchFailed(e.to_string()));
        }

        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(20));
            match self.ping() {
                Ok(_) => return Ok(()),
                Err(e @ DispatchError::IncompatibleProtocol { .. }) => return Err(e),
                Err(_) => {}
            }
        }

        Err(DispatchError::LaunchFailed(
            "Daemon process spawned but did not respond to ping within 600ms".to_string(),
        ))
    }
}

pub fn ensure_daemon_running() -> Result<(), DispatchError> {
    DaemonClient::new().ensure_running()
}

pub fn ensure_daemon_running_with_strategy(
    strategy: &DaemonLaunchStrategy,
) -> Result<(), DispatchError> {
    DaemonClient::new()
        .with_launch_strategy(strategy.clone())
        .ensure_running()
}

pub fn send_daemon_request(req: &Value) -> Option<Value> {
    DaemonClient::new().send(req).ok()
}

pub(crate) fn send_daemon_request_raw(req: &Value) -> Option<Value> {
    DaemonClient::new().send_raw(req).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    NotSent,
    Unconfirmed,
    IncompatibleProtocol {
        running: u32,
        min_supported: u32,
        current: u32,
    },
    LaunchFailed(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSent => write!(f, "Could not send the request to the daemon."),
            Self::Unconfirmed => write!(f, "Daemon request unconfirmed."),
            Self::IncompatibleProtocol {
                running,
                min_supported,
                current,
            } => write!(
                f,
                "Incompatible daemon protocol version {running} (supported: {min_supported}..={current}). Please restart the daemon."
            ),
            Self::LaunchFailed(msg) => write!(f, "Failed to launch daemon: {msg}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Dispatches request to the daemon.
pub fn dispatch_daemon_request(req: &Value) -> Result<Value, DispatchError> {
    DaemonClient::new().send(req)
}

/// Preserve the dispatch boundary for callers performing a non-idempotent write.
pub fn dispatch_daemon_request_raw(req: &Value) -> Result<Value, DispatchError> {
    DaemonClient::new().send_raw(req)
}

pub(crate) fn connect_daemon() -> Result<UnixStream, DispatchError> {
    DaemonClient::new().connect()
}
