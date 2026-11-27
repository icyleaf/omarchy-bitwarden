use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use super::protocol::{
    check_protocol_version, get_socket_path, validate_socket_path, ProtocolCheck,
};
use super::server::verify_peer_credentials;

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

/// Computes the minimum daemon `schema_version` required to process a Cipher or Folder mutation request.
pub fn cipher_mutation_required_schema_version(request: &Value) -> u32 {
    let action = request.get("action").and_then(Value::as_str);
    if matches!(
        action,
        Some(
            "folder_list" | "folder_resolve" | "folder_create" | "folder_update" | "folder_delete"
        )
    ) {
        return 3;
    }
    let is_card_or_identity_type = match request.get("type") {
        Some(Value::Number(n)) => matches!(n.as_u64(), Some(3 | 4)),
        Some(Value::String(s)) => {
            s == "3"
                || s == "4"
                || s.eq_ignore_ascii_case("card")
                || s.eq_ignore_ascii_case("identity")
        }
        _ => request
            .get("cipher_type")
            .and_then(Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("card") || t.eq_ignore_ascii_case("identity")),
    };
    let has_uri_match_rule = [
        request.get("uris"),
        request.get("add_uris"),
        request.get("login").and_then(|l| l.get("uris")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_array)
    .flatten()
    .any(|u| u.as_object().is_some_and(|o| o.contains_key("match")));
    let has_login_totp = request.get("totp").is_some()
        || (action == Some("cipher_create")
            && request.get("login").and_then(|l| l.get("totp")).is_some());
    if request.get("card").is_some()
        || request.get("identity").is_some()
        || (action == Some("cipher_create") && is_card_or_identity_type)
        || has_login_totp
        || has_uri_match_rule
    {
        return 3;
    }

    let has_fields = request
        .get("fields")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
        || request
            .get("remove_fields")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
    let has_edit_uris = request
        .get("add_uris")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
        || request
            .get("clear_uris")
            .is_some_and(|v| v.as_bool().unwrap_or(false))
        || (action == Some("cipher_update") && request.get("uris").is_some());
    let has_unconverted_create_uris = action == Some("cipher_create")
        && request
            .get("uris")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        && request.get("login").and_then(|l| l.get("uris")).is_none();

    if has_fields || has_edit_uris || has_unconverted_create_uris {
        2
    } else {
        1
    }
}

/// Ensures the running daemon advertises `capability` in `ping.capabilities`,
/// attempting an on-demand restart of a stale standalone daemon when absent (ADR-0037).
pub fn ensure_daemon_capability(capability: &str) -> Result<Value, String> {
    use super::protocol::ping_has_capability;

    if let Err(e @ DispatchError::IncompatibleProtocol { .. }) = ensure_daemon_running() {
        return Err(e.to_string());
    }

    let mut ping = match dispatch_daemon_request(&json!({ "action": "ping" })) {
        Ok(p) => p,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            return Err("Daemon protocol version is incompatible with this client.".to_string());
        }
        Err(_) => return Err("Daemon unavailable.".to_string()),
    };

    if ping_has_capability(&ping, capability) {
        return Ok(ping);
    }

    // Attempt on-demand auto-restart of stale standalone daemon (ADR-0037)
    let stop_req = json!({ "action": "stop", "admin": true });
    match dispatch_daemon_request(&stop_req) {
        Ok(stop_res) if stop_res["ok"] == true => {
            std::thread::sleep(Duration::from_millis(50));
            if let Err(e) = ensure_daemon_running() {
                return Err(format!("Could not restart the daemon: {e}"));
            }
            ping = match dispatch_daemon_request(&json!({ "action": "ping" })) {
                Ok(p) => p,
                Err(_) => return Err("Daemon unavailable after restart.".to_string()),
            };
            if ping_has_capability(&ping, capability) {
                return Ok(ping);
            }
            Err(format!(
                "The running daemon was restarted, but still does not advertise required capability '{capability}'. Check OMA_DAEMON_BIN or update your installation."
            ))
        }
        _ => Err(format!(
            "The running daemon does not support required capability '{capability}' and could not be restarted (it may be hosted in-process). Restart the daemon or its host application to apply the update."
        )),
    }
}

/// Submits a Cipher or Folder mutation request to the daemon with `schema_version`
/// negotiation, standalone daemon auto-restart, and caller-injected unlock password retrieval.
pub fn submit_cipher_mutation<F>(request: &Value, read_unlock_password: F) -> Result<Value, Value>
where
    F: FnOnce() -> Option<zeroize::Zeroizing<String>>,
{
    use super::protocol::CURRENT_SCHEMA_VERSION;

    let reject = |reason: &str| json!({"ok":false, "outcome":"rejected", "error":reason});
    if let Err(e @ DispatchError::IncompatibleProtocol { .. }) = ensure_daemon_running() {
        return Err(reject(&e.to_string()));
    }
    let mut ping = match dispatch_daemon_request(&json!({"action":"ping"})) {
        Ok(p) => p,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            return Err(reject(
                "Daemon protocol version is incompatible with this client.",
            ));
        }
        Err(_) => return Err(reject("Daemon unavailable.")),
    };

    let running_schema = ping
        .get("schema_version")
        .and_then(Value::as_u64)
        .unwrap_or(1) as u32;
    let required_schema = cipher_mutation_required_schema_version(request);
    let is_folder_action = matches!(
        request.get("action").and_then(Value::as_str),
        Some(
            "folder_list" | "folder_resolve" | "folder_create" | "folder_update" | "folder_delete"
        )
    );
    let schema_feature_label = if is_folder_action {
        "folder operations"
    } else if required_schema >= 3 {
        "card or identity cipher mutations"
    } else {
        "custom fields or advanced URI mutations"
    };

    if required_schema > 1 && running_schema < required_schema {
        // Attempt on-demand auto-restart of stale standalone daemon
        let stop_req = json!({ "action": "stop", "admin": true });
        match dispatch_daemon_request(&stop_req) {
            Ok(stop_res) if stop_res["ok"] == true => {
                std::thread::sleep(Duration::from_millis(50));
                if let Err(e) = ensure_daemon_running() {
                    return Err(reject(&format!("Could not restart the daemon: {e}")));
                }
                ping = match dispatch_daemon_request(&json!({"action":"ping"})) {
                    Ok(p) => p,
                    Err(_) => return Err(reject("Daemon unavailable after restart.")),
                };
                let restarted_schema = ping
                    .get("schema_version")
                    .and_then(Value::as_u64)
                    .unwrap_or(1) as u32;
                if restarted_schema < required_schema {
                    return Err(reject(&format!(
                        "The running daemon was restarted, but the active executable does not support {schema_feature_label}. Check OMA_DAEMON_BIN or update your installation."
                    )));
                }
            }
            _ => {
                return Err(reject(&format!(
                    "The running daemon does not support {schema_feature_label}. Restart the daemon or its host application to apply the update."
                )));
            }
        }
    }

    if ping["unlocked"] != true {
        let password =
            read_unlock_password().unwrap_or_else(|| zeroize::Zeroizing::new(String::new()));
        if password.is_empty()
            || !send_daemon_request(&json!({"action":"unlock","password":password.as_str()}))
                .is_some_and(|r| r["ok"] == true)
        {
            let verb = match request.get("action").and_then(|a| a.as_str()) {
                Some("cipher_delete") => "deleting",
                Some("cipher_delete_trash") => "permanently deleting from trash",
                Some("cipher_restore") => "restoring",
                Some("cipher_update") => "editing",
                Some("cipher_resolve") => match request.get("purpose").and_then(Value::as_str) {
                    Some("edit") | Some("editing") => "editing",
                    Some("restore") | Some("restoring") => "restoring",
                    Some("delete") | Some("deleting") => "deleting",
                    _ => "deleting",
                },
                Some("folder_list") => "listing folders",
                Some("folder_create") => "creating a folder",
                Some("folder_update") => "renaming a folder",
                Some("folder_delete") | Some("folder_resolve") => "deleting a folder",
                _ => "creating a cipher",
            };
            let err_text = if verb.contains("folder") || verb.contains("cipher") {
                format!("Unlock the vault before {verb}.")
            } else {
                format!("Unlock the vault before {verb} a cipher.")
            };
            return Err(reject(&err_text));
        }
    }
    let unknown = || json!({"ok":false, "outcome":"unknown", "error":"Could not confirm the mutation. Sync the vault before trying again."});
    let (mutation_req, uses_envelope) = if required_schema > 1 {
        let mut env = json!({
            "action": request.get("action").cloned().unwrap_or_else(|| json!("cipher_update")),
            "mutation": request,
        });
        if let Some(client) = request.get("client") {
            env["client"] = client.clone();
        }
        (env, true)
    } else {
        (request.clone(), false)
    };

    let reply = dispatch_daemon_request(&mutation_req).map_err(|e| match e {
        DispatchError::NotSent => reject("Could not send the request to the daemon."),
        DispatchError::Unconfirmed => unknown(),
        DispatchError::IncompatibleProtocol { .. } => {
            reject("Daemon protocol version is incompatible with this client.")
        }
        DispatchError::LaunchFailed(msg) => reject(&format!("Could not start the daemon: {msg}")),
    })?;
    if reply["ok"] == false {
        let err_str = reply.get("error").and_then(Value::as_str).unwrap_or("");
        if ((err_str.contains("Invalid cipher fields")
            || err_str.contains("Invalid cipher update fields"))
            && running_schema < CURRENT_SCHEMA_VERSION)
            || (uses_envelope
                && (err_str.contains("Target cipher ID or name is required")
                    || err_str.contains("Missing cipher target")
                    || err_str.contains("Cipher name is required")
                    || err_str.contains("Invalid cipher fields")
                    || err_str.contains("Invalid cipher update fields")))
        {
            return Err(reject(&format!(
                "The running daemon does not support {schema_feature_label}. Restart the daemon or its host application to apply the update."
            )));
        }
        return Err(reply);
    }
    let action = request.get("action").and_then(Value::as_str);
    let receipt_valid = match action {
        Some("folder_list") => reply["folders"].is_array(),
        Some("folder_resolve" | "folder_create" | "folder_update" | "folder_delete") => reply
            ["folder"]["id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        _ => reply["item"]["id"].as_str().is_some_and(|s| !s.is_empty()),
    };
    if reply["ok"] != true || !receipt_valid {
        return Err(unknown());
    }
    Ok(reply)
}

/// Submits an SSH Key cipher creation request after verifying `ssh_write_receipt` support.
/// Once dispatched, a missing reply cannot justify another create.
pub fn submit_ssh_cipher<F>(request: &Value, read_unlock_password: F) -> Result<Value, Value>
where
    F: FnOnce() -> Option<zeroize::Zeroizing<String>>,
{
    let reject = |reason: &str| json!({"ok":false, "outcome":"rejected", "error":reason});
    let ping = match dispatch_daemon_request(&json!({"action":"ping"})) {
        Ok(p) => p,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            return Err(reject(
                "Daemon protocol version is incompatible with this client.",
            ));
        }
        Err(_) => return Err(reject("Daemon unavailable.")),
    };
    if ping["ssh_write_receipt"] != true {
        return Err(reject(
            "Lock the vault and restart the daemon to enable safe cipher writes.",
        ));
    }
    submit_cipher_mutation(request, read_unlock_password)
}

/// Non-interactive resolution outcome for a Cipher target query sent to the daemon.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedCipherTarget {
    Resolved(Value),
    Ambiguous {
        error: String,
        candidates: Vec<Value>,
    },
}

/// Resolves a Cipher target through the daemon without performing any terminal I/O.
/// Callers decide how to present ambiguous candidates or error messages.
pub fn resolve_target_cipher<F>(
    target: &str,
    purpose: &str,
    client_ctx: Option<&crate::api::ClientContext>,
    trash: bool,
    read_unlock_password: F,
) -> Result<ResolvedCipherTarget, String>
where
    F: FnOnce() -> Option<zeroize::Zeroizing<String>>,
{
    let mut resolve_req = json!({
        "action": "cipher_resolve",
        "target": target,
        "purpose": purpose,
        "trash": trash,
    });
    if let Some(ctx) = client_ctx {
        resolve_req["client"] = json!(ctx);
    }

    match submit_cipher_mutation(&resolve_req, read_unlock_password) {
        Ok(res) => Ok(ResolvedCipherTarget::Resolved(res["item"].clone())),
        Err(err_obj) => {
            if err_obj.get("ambiguous") == Some(&Value::Bool(true)) {
                let error = err_obj
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("Multiple ciphers matched query.")
                    .to_string();
                let candidates = err_obj
                    .get("candidates")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                return Ok(ResolvedCipherTarget::Ambiguous { error, candidates });
            }

            let err_msg = err_obj
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Failed to resolve cipher")
                .to_string();
            Err(err_msg)
        }
    }
}

#[cfg(test)]
mod client_mutation_tests {
    use super::*;

    #[test]
    fn test_schema_version_requirements_for_card_mutations() {
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "type": 3,
                "name": "Card"
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "cipher_type": "card",
                "name": "Card"
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_update",
                "card": { "brand": "Visa" }
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "type": 1,
                "name": "Login",
                "login": { "username": "alice" }
            })),
            1
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "type": 1,
                "name": "Login",
                "login": { "totp": "JBSWY3DPEHPK3PXP" }
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_update",
                "totp": "JBSWY3DPEHPK3PXP"
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "type": 1,
                "name": "Login",
                "login": {
                    "uris": [{ "uri": "https://example.com", "match": 3 }]
                }
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_update",
                "fields": [{ "name": "k", "value": "v", "type": 0 }]
            })),
            2
        );
    }

    #[test]
    fn test_schema_version_requirements_for_identity_mutations() {
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "type": 4,
                "name": "Work ID"
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_create",
                "cipher_type": "identity",
                "name": "Work ID"
            })),
            3
        );
        assert_eq!(
            cipher_mutation_required_schema_version(&json!({
                "action": "cipher_update",
                "identity": { "email": "alice@example.com" }
            })),
            3
        );
    }
}
