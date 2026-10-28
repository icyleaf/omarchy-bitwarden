use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::{Engine, BASE64};
use crate::storage::StorageManager;
use crate::vault::VaultManager;

use std::os::unix::process::CommandExt;

/// Resolves the secure runtime directory for daemon sockets and IPC.
///
/// Precedence:
/// 1. `XDG_RUNTIME_DIR`: Verified to exist, owned by current UID, and not a symlink.
/// 2. Fallback: Creates an isolated `/tmp/omawarden-runtime-{uid}/` directory with mode `0700`.
///
/// Tests never resolve to the login session's `/run/user/{uid}`: some send `stop`
/// or start a daemon, which would lock the user's real vault and drop their SSH agent.
pub fn get_runtime_dir() -> PathBuf {
    let current_uid = unsafe { libc::getuid() };

    if let Ok(runtime_dir) = env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime_dir);
        let is_session_dir = p == Path::new(&format!("/run/user/{}", current_uid));
        if let Ok(meta) = fs::symlink_metadata(&p) {
            if !meta.file_type().is_symlink()
                && meta.uid() == current_uid
                && !(cfg!(test) && is_session_dir)
            {
                return p;
            }
        }
    }

    let fallback = env::temp_dir().join(format!("omawarden-runtime-{}", current_uid));
    let _ = crate::fs_util::create_secure_dir_all(&fallback, 0o700);
    fallback
}

pub fn get_socket_path() -> PathBuf {
    get_runtime_dir().join("omawarden.sock")
}

/// Validates that a socket file (and its parent directory) is owned by the current UID
/// and is not a symlink to prevent cross-user socket hijacking or TOCTOU attacks.
pub fn validate_socket_path(path: &Path) -> std::io::Result<()> {
    let current_uid = unsafe { libc::getuid() };

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Socket path '{}' is a symlink (potential hijacking attempt)",
                    path.display()
                ),
            ));
        }

        if meta.uid() != current_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Socket path '{}' is owned by foreign UID {} (expected current UID {})",
                    path.display(),
                    meta.uid(),
                    current_uid
                ),
            ));
        }
    }

    if let Some(parent) = path.parent() {
        if let Ok(parent_meta) = fs::symlink_metadata(parent) {
            if parent_meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Socket parent directory '{}' is a symlink (potential hijacking attempt)",
                        parent.display()
                    ),
                ));
            }

            if parent_meta.uid() != current_uid
                && parent != Path::new("/tmp")
                && parent != Path::new("/var/tmp")
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "Socket parent directory '{}' is owned by foreign UID {} (expected current UID {})",
                        parent.display(),
                        parent_meta.uid(),
                        current_uid
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// What to do about a running daemon built from a different commit.
#[derive(Debug, PartialEq)]
enum DaemonCheck {
    UpToDate,
    /// Mismatched but unlocked: replacing it would lock the vault and drop
    /// the SSH agent socket mid-use, so leave it until it locks.
    Defer,
    Replace,
}

fn check_running_daemon(ping: &Value, our_commit: &str) -> DaemonCheck {
    let running_commit = ping.get("commit").and_then(|v| v.as_str()).unwrap_or("");
    if running_commit == our_commit {
        DaemonCheck::UpToDate
    } else if ping.get("unlocked").and_then(|v| v.as_bool()) == Some(true) {
        DaemonCheck::Defer
    } else {
        DaemonCheck::Replace
    }
}

pub fn ensure_daemon_running() {
    if let Some(resp) = send_daemon_request(&json!({ "action": "ping" })) {
        let check = check_running_daemon(&resp, env!("GIT_HASH"));
        if check == DaemonCheck::Defer {
            crate::log_info!(
                "omawarden:daemon",
                "Running daemon is from another build but the vault is unlocked; keeping it until it locks"
            );
        }
        if check != DaemonCheck::Replace {
            return;
        }
        // Outdated daemon running: gracefully stop it so we can spawn the latest binary version
        let _ = send_daemon_request(&json!({ "action": "stop" }));
        std::thread::sleep(Duration::from_millis(50));
    }

    if let Ok(exe_path) = env::current_exe() {
        let cfg = crate::config::ConfigManager::default().load();
        let auto_lock_mins = if cfg.auto_lock_minutes >= 0 {
            cfg.auto_lock_minutes as u64
        } else {
            15
        };

        let mut cmd = Command::new(exe_path);
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

        let _ = cmd.spawn();

        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(20));
            if send_daemon_request(&json!({ "action": "ping" })).is_some() {
                break;
            }
        }
    }
}

pub fn send_daemon_request(req: &Value) -> Option<Value> {
    let socket_path = get_socket_path();
    if !socket_path.exists() {
        return None;
    }

    if let Err(e) = validate_socket_path(&socket_path) {
        crate::log_error!(
            "omawarden:daemon",
            "Refusing to connect to socket {}: {}",
            socket_path.display(),
            e
        );
        return None;
    }

    let mut stream = UnixStream::connect(&socket_path).ok()?;

    // Mutual SO_PEERCRED verification: client verifies that server process UID matches current UID
    if let Err(e) = verify_peer_credentials(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Refusing to send request: server peer UID verification failed: {}",
            e
        );
        return None;
    }

    let mut payload_val = req.clone();
    if let Value::Object(ref mut map) = payload_val {
        if !map.contains_key("client") {
            if let Some(ctx) = crate::api::resolve_effective_client_context(None) {
                map.insert("client".to_string(), json!(ctx));
            }
        }
    }

    let payload = format!("{}\n", payload_val);
    stream.write_all(payload.as_bytes()).ok()?;
    stream.flush().ok()?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).ok()?;

    serde_json::from_str(&response_line).ok()
}

pub struct DaemonState {
    pub vault_mgr: Arc<VaultManager>,
    pub last_activity: Mutex<Instant>,
    pub auto_lock_duration: Mutex<Duration>,
    pub unlocked_at: Mutex<Option<Instant>>,
    pub max_session_lifetime: Mutex<Duration>,
    pub ssh_agent: Arc<crate::ssh_agent::SshAgent>,
    /// Failed polkit checks since the last successful quick unlock. Three in
    /// a row wipe the retained key (ADR-0025).
    pub quick_unlock_failures: Mutex<u32>,
    /// Held for the duration of an interactive polkit prompt so concurrent
    /// requests don't stack dialogs.
    pub quick_unlock_busy: Mutex<()>,
    /// Injectable for tests; defaults to `pkcheck` resolved from PATH.
    pub polkit_binary: PathBuf,
    /// Rule 9 / ADR-0025: when the current session's last master-password
    /// unlock happened. Survives soft locks so the 12h ceiling bounds the
    /// retained key too; cleared by every hard lock.
    pub session_anchor: Mutex<Option<Instant>>,
    /// CLOCK_BOOTTIME minus CLOCK_MONOTONIC, in whole seconds, as of the last
    /// watchdog tick. Suspend time accumulates in BOOTTIME only, so a growing
    /// delta is a deterministic resume-edge detector (no D-Bus needed).
    pub last_boot_delta_secs: Mutex<Option<u64>>,
}

/// What locked the session. Sleep is treated harder than a screen lock
/// everywhere: a soft lock never survives a suspend (ADR-0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSignal {
    None,
    Screen,
    Sleep,
}

/// Hard limit of consecutive denied quick-unlock prompts before the retained
/// key is wiped and the master password is required again.
pub const MAX_QUICK_UNLOCK_FAILURES: u32 = 3;

impl DaemonState {
    pub fn new(storage_mgr: StorageManager, auto_lock_minutes: u64) -> Self {
        let vault_mgr = Arc::new(VaultManager::new("", Some(storage_mgr), None));
        let polkit_binary =
            which::which("pkcheck").unwrap_or_else(|_| std::path::PathBuf::from("pkcheck"));
        Self {
            vault_mgr,
            last_activity: Mutex::new(Instant::now()),
            auto_lock_duration: Mutex::new(Duration::from_secs(auto_lock_minutes * 60)),
            unlocked_at: Mutex::new(None),
            max_session_lifetime: Mutex::new(Duration::from_secs(12 * 3600)),
            ssh_agent: Arc::new(crate::ssh_agent::SshAgent::default()),
            quick_unlock_failures: Mutex::new(0),
            quick_unlock_busy: Mutex::new(()),
            polkit_binary,
            session_anchor: Mutex::new(None),
            last_boot_delta_secs: Mutex::new(None),
        }
    }

    /// CLOCK_BOOTTIME minus CLOCK_MONOTONIC in whole seconds. The two clocks
    /// run together while awake; suspend time accrues only to BOOTTIME.
    pub fn boot_delta_secs() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let mut boot = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut mono = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let ok = unsafe {
                libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) == 0
                    && libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) == 0
            };
            if !ok {
                return None;
            }
            let delta = boot.tv_sec - mono.tv_sec;
            Some(delta.unsigned_abs())
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    /// Pure resume-edge predicate: the delta only grows by whole suspend
    /// periods, so a jump over one second means at least one suspend since
    /// the previous sample. Shrinkage (clock skew between the two reads) is
    /// ignored rather than treated as an event.
    pub fn suspend_happened(prev: Option<u64>, current: Option<u64>) -> bool {
        match (prev, current) {
            (Some(prev), Some(cur)) => cur > prev + 1,
            // First sample after start: if the machine already suspended since
            // boot the cached value is None, but nothing was retained before
            // the daemon started either, so treat it as no event.
            _ => false,
        }
    }

    /// Watchdog step: wipe/hard-lock on suspend regardless of vault state.
    /// Runs every tick, cheap (two clock reads), and is the guarantee behind
    /// ADR decision 4 — the polled PreparingForSleep property alone can be
    /// missed while the daemon is frozen.
    pub fn check_suspend_drift_with(&self, current_delta: Option<u64>) -> bool {
        let prev = self.last_boot_delta_secs.lock().ok().and_then(|g| *g);
        if let Ok(mut cache) = self.last_boot_delta_secs.lock() {
            *cache = current_delta;
        }
        if !Self::suspend_happened(prev, current_delta) {
            return false;
        }
        crate::log_info!(
            "omawarden:daemon",
            "Suspend detected (boottime drift); wiping quick unlock retention"
        );
        // lock() is the hard path: wipes the retained key AND locks.
        self.lock();
        true
    }

    pub fn check_suspend_drift(&self) -> bool {
        self.check_suspend_drift_with(Self::boot_delta_secs())
    }

    fn quick_unlock_enabled(&self) -> bool {
        crate::config::ConfigManager::default().load().quick_unlock
    }

    /// Quick unlock availability as advertised over IPC: enabled in settings
    /// AND a key currently retained by a soft lock.
    pub fn quick_unlock_ready(&self) -> bool {
        self.quick_unlock_enabled() && self.vault_mgr.quick_unlock_available()
    }

    /// ADR-0025: re-unlock the vault behind a polkit system-authentication
    /// check instead of the master password. Fail-closed on every rejection;
    /// three consecutive denials wipe the retained key.
    pub fn perform_quick_unlock(&self) -> Result<usize, &'static str> {
        if !self.quick_unlock_enabled() {
            return Err("Quick unlock is disabled in settings.");
        }
        if !self.vault_mgr.quick_unlock_available() {
            return Err("Quick unlock is unavailable: the vault was hard-locked.");
        }
        // One interactive prompt at a time; concurrent callers fail fast and
        // the overlay falls back to the master password field.
        let _guard = match self.quick_unlock_busy.try_lock() {
            Ok(g) => g,
            Err(_) => return Err("Quick unlock is already in progress."),
        };
        // Re-check: a wipe may have raced with acquiring the busy lock.
        if !self.vault_mgr.quick_unlock_available() {
            return Err("Quick unlock is unavailable: the vault was hard-locked.");
        }

        match crate::polkit::check(
            crate::polkit::POLKIT_ACTION_ID,
            &self.polkit_binary,
            crate::polkit::DEFAULT_CHECK_TIMEOUT,
        ) {
            crate::polkit::PolkitOutcome::Authorized => {}
            crate::polkit::PolkitOutcome::Denied => {
                let strike = {
                    match self.quick_unlock_failures.lock() {
                        Ok(mut n) => {
                            *n += 1;
                            *n
                        }
                        Err(_) => MAX_QUICK_UNLOCK_FAILURES,
                    }
                };
                if strike >= MAX_QUICK_UNLOCK_FAILURES {
                    crate::log_warn!(
                        "omawarden:daemon",
                        "Quick unlock denied {} times; wiping retained key",
                        strike
                    );
                    self.vault_mgr.wipe_quick_unlock();
                    if let Ok(mut n) = self.quick_unlock_failures.lock() {
                        *n = 0;
                    }
                }
                return Err("System authentication was denied.");
            }
            crate::polkit::PolkitOutcome::Unavailable(reason) => {
                crate::log_warn!("omawarden:daemon", "polkit unavailable: {}", reason);
                return Err("System authentication is unavailable right now.");
            }
        }

        match self.vault_mgr.quick_unlock_restore() {
            Ok(count) => {
                if let Ok(mut n) = self.quick_unlock_failures.lock() {
                    *n = 0;
                }
                // Rule 9: re-arm the per-unlock anchor so the idle/lifetime
                // watchdogs keep running after a quick unlock. The session
                // anchor is deliberately NOT touched: quick unlocks extend
                // nothing; the 12h ceiling is measured from the master
                // password unlock (ADR-0025 decision 4).
                if let Ok(mut ua) = self.unlocked_at.lock() {
                    *ua = Some(Instant::now());
                }
                self.touch_activity();
                Ok(count)
            }
            Err(e) => {
                crate::log_error!("omawarden:daemon", "Quick unlock restore failed: {}", e);
                Err("Quick unlock failed to restore the vault.")
            }
        }
    }
}

impl DaemonState {
    pub fn set_auto_lock_duration(&self, duration: Duration) {
        if let Ok(mut dur) = self.auto_lock_duration.lock() {
            *dur = duration;
        }
    }

    pub fn set_auto_lock_minutes(&self, minutes: u64) {
        self.set_auto_lock_duration(Duration::from_secs(minutes * 60));
    }

    pub fn check_auto_lock(&self) -> bool {
        // Rule 9 / ADR-0025: the 12h ceiling is anchored to the last
        // master-password unlock and bounds the retained key as well: a vault
        // that stays soft-locked (key retained) past the ceiling is wiped.
        // Quick unlocks re-arm only the per-unlock anchor (idle watchdogs);
        // they never extend the session anchor.
        let session_expired = {
            let anchor = self.session_anchor.lock().ok().and_then(|g| *g);
            let max = self.max_session_lifetime.lock().ok().map(|g| *g);
            matches!(
                (anchor, max),
                (Some(a), Some(max)) if !max.is_zero() && a.elapsed() > max
            )
        };
        if session_expired
            && (self.vault_mgr.is_unlocked() || self.vault_mgr.quick_unlock_available())
        {
            crate::log_info!(
                "omawarden:daemon",
                "Maximum session lifetime reached; locking vault and wiping retention"
            );
            self.lock();
            return true;
        }

        if self.vault_mgr.is_unlocked() {
            // 1. Per-unlock absolute lifetime (unchanged behavior when quick
            // unlock is off: identical to the session anchor in that case).
            let max_lifetime_expired = {
                if let Ok(ua_guard) = self.unlocked_at.lock() {
                    if let Some(unlocked_time) = *ua_guard {
                        if let Ok(max_dur) = self.max_session_lifetime.lock() {
                            !max_dur.is_zero() && unlocked_time.elapsed() > *max_dur
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if max_lifetime_expired {
                crate::log_info!(
                    "omawarden:daemon",
                    "Maximum session lifetime reached; locking vault"
                );
                self.lock();
                crate::attachment::clear_preview_attachments(None);
                return true;
            }

            // 2. Check idle inactivity timeout
            let idle_expired = {
                if let Ok(dur) = self.auto_lock_duration.lock() {
                    if !dur.is_zero() {
                        if let Ok(last) = self.last_activity.lock() {
                            last.elapsed() > *dur
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            };

            if idle_expired {
                // Idle timeout is a soft lock: with quick unlock enabled the
                // key is retained for a later polkit check (ADR-0025).
                crate::log_info!("omawarden:daemon", "Idle timeout elapsed; locking vault");
                self.soft_lock();
                return true;
            }
        }
        false
    }

    pub fn check_screen_lock(&self) -> bool {
        self.check_screen_lock_with(system_lock_signal)
    }

    pub fn check_screen_lock_with<F>(&self, detector: F) -> bool
    where
        F: FnOnce() -> LockSignal,
    {
        // The detector must also run while soft-locked: a Sleep signal while
        // a key is retained must wipe it (ADR decision 4). The suspend-drift
        // watchdog covers the resume edge this poll can miss.
        if self.vault_mgr.is_unlocked() || self.vault_mgr.quick_unlock_available() {
            match detector() {
                LockSignal::None => {}
                LockSignal::Sleep => {
                    // A suspend must never leave the key retained.
                    crate::log_info!(
                        "omawarden:daemon",
                        "System is going to sleep; hard-locking vault"
                    );
                    self.lock();
                    return true;
                }
                LockSignal::Screen => {
                    if self.vault_mgr.is_unlocked() {
                        // soft_lock() itself hard-locks when quick unlock is off.
                        self.soft_lock();
                        return true;
                    }
                    // Already soft-locked: the screen signal changes nothing.
                }
            }
        }
        false
    }

    pub fn touch_activity(&self) {
        if let Ok(mut act) = self.last_activity.lock() {
            *act = Instant::now();
        }
    }

    /// Hard lock (ADR-0025): wipes the retained key. Used by explicit lock,
    /// logout, stop, sleep and every other non-soft path.
    pub fn lock(&self) {
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        if let Ok(mut anchor) = self.session_anchor.lock() {
            *anchor = None;
        }
        if let Ok(mut n) = self.quick_unlock_failures.lock() {
            *n = 0;
        }
        self.vault_mgr.hard_lock();
        let _ = crate::clipboard::ClipboardManager::default()
            .without_detached_worker()
            .clear();
    }

    /// Soft lock (ADR-0025): purges decrypted state but retains the user key
    /// in locked memory when quick unlock is enabled in settings.
    pub fn soft_lock(&self) {
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        if self.quick_unlock_enabled() {
            self.vault_mgr.soft_lock();
        } else {
            self.vault_mgr.hard_lock();
        }
        let _ = crate::clipboard::ClipboardManager::default()
            .without_detached_worker()
            .clear();
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        let count = self.vault_mgr.unlock(password)?;
        if let Ok(mut ua_guard) = self.unlocked_at.lock() {
            *ua_guard = Some(Instant::now());
        }
        // A master-password unlock (re)anchors the hard 12h session ceiling.
        if let Ok(mut anchor) = self.session_anchor.lock() {
            *anchor = Some(Instant::now());
        }
        // A successful master unlock supersedes any earlier denials.
        if let Ok(mut n) = self.quick_unlock_failures.lock() {
            *n = 0;
        }
        self.touch_activity();
        Ok(count)
    }

    pub fn sync(&self) -> Result<usize, String> {
        self.sync_with_client(None)
    }

    pub fn sync_with_client(
        &self,
        client_context: Option<&crate::api::ClientContext>,
    ) -> Result<usize, String> {
        let res = self.vault_mgr.sync_with_client(client_context);
        if res.is_ok() {
            self.touch_activity();
        }
        res
    }
}

pub fn should_touch_activity(action: &str, req: &Value) -> bool {
    if let Some(touch) = req.get("touch").and_then(|v| v.as_bool()) {
        return touch;
    }
    matches!(
        action,
        "sync"
            | "list"
            | "search"
            | "ssh_key_create"
            | "get_item"
            | "get_ssh_key"
            | "get_attachment_key"
            | "copy"
            | "generate_password"
    )
}

pub fn run_daemon_server(state: Arc<DaemonState>) -> std::io::Result<()> {
    let socket_path = get_socket_path();
    if socket_path.exists() {
        validate_socket_path(&socket_path)?;
        let _ = fs::remove_file(&socket_path);
    }

    if let Some(parent) = socket_path.parent() {
        crate::fs_util::create_secure_dir_all(parent, 0o700)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    let mut perms = fs::metadata(&socket_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&socket_path, perms)?;

    if let Err(e) = crate::ssh_agent::apply(&state) {
        crate::log_error!("omawarden:daemon", "SSH agent failed to start: {}", e);
    }

    let state_clone = state.clone();
    std::thread::spawn(move || loop {
        let is_unlocked = state_clone.vault_mgr.is_unlocked();
        let sleep_duration = if is_unlocked {
            Duration::from_secs(2)
        } else {
            Duration::from_secs(5)
        };
        std::thread::sleep(sleep_duration);
        // Resume-edge suspend detection must run regardless of lock state:
        // the dominant quick-unlock state (soft-locked) is exactly when the
        // screen detector above would otherwise never fire.
        state_clone.check_suspend_drift();
        state_clone.check_auto_lock();
        state_clone.check_screen_lock();
    });

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let st = state.clone();
                std::thread::spawn(move || {
                    let _ = handle_client(stream, st);
                });
            }
            Err(e) => {
                eprintln!("Socket accept error: {}", e);
            }
        }
    }

    Ok(())
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

#[cfg(not(target_os = "linux"))]
pub fn verify_peer_credentials(_stream: &UnixStream) -> std::io::Result<()> {
    Ok(())
}

pub const SCREEN_LOCKER_PROCESS_NAMES: &[&str] = &["hyprlock", "swaylock", "waylock", "gtklock"];

pub fn get_omarchy_shell_cmd() -> Option<PathBuf> {
    if which::which("omarchy-shell").is_ok() {
        return Some(PathBuf::from("omarchy-shell"));
    }
    if let Ok(home) = env::var("HOME") {
        let candidate = PathBuf::from(home).join(".local/share/omarchy/bin/omarchy-shell");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn is_omarchy_locked() -> bool {
    let cmd_name = match get_omarchy_shell_cmd() {
        Some(cmd) => cmd,
        None => return false,
    };

    if let Ok(output) = Command::new(cmd_name).args(["lock", "isLocked"]).output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "true" {
                return true;
            }
        }
    }
    false
}

pub fn is_screen_locker_running() -> bool {
    let locker_regex = SCREEN_LOCKER_PROCESS_NAMES.join("|");
    if let Ok(output) = Command::new("pgrep").args(["-x", &locker_regex]).output() {
        if output.status.success() && !output.stdout.is_empty() {
            return true;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                if let Some(name_str) = file_name.to_str() {
                    if name_str.chars().all(|c| c.is_ascii_digit()) {
                        let comm_path = entry.path().join("comm");
                        if let Ok(comm) = fs::read_to_string(comm_path) {
                            let comm = comm.trim();
                            if SCREEN_LOCKER_PROCESS_NAMES.contains(&comm) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    false
}

pub fn is_logind_locked_or_sleeping() -> bool {
    matches!(logind_lock_signal(), LockSignal::Screen | LockSignal::Sleep)
}

/// logind session state as a lock signal. Sleep wins over a locked hint:
/// both together must produce the hard lock.
pub fn logind_lock_signal() -> LockSignal {
    // 1. Check Manager PreparingForSleep
    if let Ok(output) = Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
            "PreparingForSleep",
        ])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "b true" {
                return LockSignal::Sleep;
            }
        }
    }

    // 2. Check session LockedHint
    if let Ok(output) = Command::new("busctl")
        .args([
            "get-property",
            "org.freedesktop.login1",
            "/org/freedesktop/login1/session/auto",
            "org.freedesktop.login1.Session",
            "LockedHint",
        ])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            if s.trim() == "b true" {
                return LockSignal::Screen;
            }
        }
    }

    LockSignal::None
}

/// Combine every desktop signal into the strongest applicable lock kind.
pub fn system_lock_signal() -> LockSignal {
    // Sleep dominates: it must hard-lock even if a screen lock is also up.
    let logind = logind_lock_signal();
    if logind == LockSignal::Sleep {
        return LockSignal::Sleep;
    }
    if is_omarchy_locked() || is_screen_locker_running() || logind == LockSignal::Screen {
        return LockSignal::Screen;
    }
    LockSignal::None
}

pub fn is_system_or_screen_locked() -> bool {
    system_lock_signal() != LockSignal::None
}

fn handle_client(mut stream: UnixStream, state: Arc<DaemonState>) -> std::io::Result<()> {
    if let Err(e) = verify_peer_credentials(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Client connection rejected: peer credential check failed: {}",
            e
        );
        let err = json!({ "ok": false, "error": "Access denied: client UID mismatch" });
        let _ = writeln!(stream, "{}", err);
        return Ok(());
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    if line.trim().is_empty() {
        return Ok(());
    }

    let req: Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(_) => {
            let err = json!({ "ok": false, "error": "Malformed JSON request" });
            let _ = writeln!(stream, "{}", err);
            return Ok(());
        }
    };

    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let is_unlocked = state.vault_mgr.is_unlocked();

    let is_privileged = matches!(
        action,
        "list"
            | "search"
            | "get_item"
            | "get_ssh_key"
            | "get_attachment_key"
            | "ssh_key_create"
            | "sync"
    ) || (action == "totp"
        && (req.get("query").is_some() || req.get("id").is_some()))
        || ((action == "stop" || action == "set_auto_lock") && is_unlocked);

    if is_privileged && !is_unlocked {
        let _ = writeln!(
            stream,
            "{}",
            json!({ "ok": false, "error": "Vault is locked. Please unlock the vault first." })
        );
        return Ok(());
    }

    if should_touch_activity(action, &req) {
        state.touch_activity();
    }

    let client_context: Option<crate::api::ClientContext> = req
        .get("client")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .filter(|c: &crate::api::ClientContext| c.is_valid());

    let response = match action {
        "ping" => json!({
            "ok": true,
            "pong": true,
            "version": env!("CARGO_PKG_VERSION"),
            "commit": env!("GIT_HASH"),
            "unlocked": is_unlocked,
            "quick_unlock": state.quick_unlock_ready(),
        }),
        "stop" => {
            state.lock();
            crate::ssh_agent::remove_socket();
            crate::attachment::clear_preview_attachments(None);
            let _ = writeln!(stream, "{}", json!({ "ok": true }));
            let _ = stream.flush();
            std::process::exit(0);
        }
        "status" => state.vault_mgr.get_status(),
        // SSH agent confirmations: the overlay lists pending prompts and answers them.
        "ssh_agent_apply" => match crate::ssh_agent::apply(&state) {
            Ok(_) => json!({ "ok": true, "running": crate::ssh_agent::is_running(&state) }),
            Err(e) => json!({ "ok": false, "error": format!("SSH agent: {e}") }),
        },
        "ssh_agent_status" => json!({
            "ok": true,
            "running": crate::ssh_agent::is_running(&state),
            "socket": crate::ssh_agent::socket_path(),
        }),
        "ssh_agent_pending" => json!({ "ok": true, "prompts": state.ssh_agent.pending() }),
        "ssh_agent_reply" => {
            let id = req.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let decision = crate::ssh_agent::Decision {
                approve: req
                    .get("approve")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };
            json!({ "ok": true, "delivered": state.ssh_agent.reply(id, decision) })
        }
        "unlock" => {
            let pwd = req.get("password").and_then(|v| v.as_str()).unwrap_or("");
            match state.unlock(pwd) {
                Ok(count) => json!({
                    "ok": true,
                    "status": "unlocked",
                    "items_count": count,
                }),
                Err(e) => json!({ "ok": false, "status": "locked", "error": e }),
            }
        }
        // ADR-0025: system-authentication re-unlock from the retained key.
        "quick_unlock" => match state.perform_quick_unlock() {
            Ok(count) => json!({
                "ok": true,
                "status": "unlocked",
                "items_count": count,
            }),
            Err(reason) => json!({ "ok": false, "status": "locked", "error": reason }),
        },
        // Config side-effect: drop the retained key without locking.
        "wipe_quick_unlock" => {
            state.vault_mgr.wipe_quick_unlock();
            json!({ "ok": true })
        }
        "lock" => {
            state.lock();
            crate::attachment::clear_preview_attachments(None);
            json!({ "ok": true, "status": "locked" })
        }
        "sync" => match state.sync_with_client(client_context.as_ref()) {
            Ok(count) => json!({ "ok": true, "ciphers_count": count }),
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "list" => json!(state.vault_mgr.get_items()),
        "search" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let category = req.get("category").and_then(|v| v.as_str());
            json!(state.vault_mgr.search_items(query, category))
        }
        "ssh_key_create" => {
            if let Some(user_key) = state.vault_mgr.get_user_key() {
                let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let priv_k = req
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let pub_k = req.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
                let fp = req
                    .get("fingerprint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let notes = req.get("notes").and_then(|v| v.as_str());
                let folder_id = req.get("folder_id").and_then(|v| v.as_str());

                let ssh_data = crate::ssh::GeneratedSshKey {
                    algorithm_name: String::new(),
                    private_key: priv_k.to_string(),
                    public_key: pub_k.to_string(),
                    fingerprint: fp.to_string(),
                };

                match state.vault_mgr.create_ssh_key_with_client(
                    name,
                    &ssh_data,
                    notes,
                    folder_id,
                    &user_key,
                    client_context.as_ref(),
                ) {
                    Ok(item) => json!({ "ok": true, "item": item }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            } else {
                json!({ "ok": false, "error": "Vault is locked. Please unlock the vault first." })
            }
        }
        "get_item" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let category = req.get("category").and_then(|v| v.as_str());
            if let Some(item) = state.vault_mgr.find_item(query, category) {
                json!({ "ok": true, "item": item })
            } else {
                json!({ "ok": false, "error": format!("Item '{}' not found in vault", query) })
            }
        }
        "get_ssh_key" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(item) = state.vault_mgr.find_ssh_key(query) {
                json!({ "ok": true, "item": item })
            } else {
                json!({ "ok": false, "error": format!("SSH key item '{}' not found", query) })
            }
        }
        "get_attachment_key" => {
            let item_id = req.get("item_id").and_then(|v| v.as_str()).unwrap_or("");
            let attachment_id = req
                .get("attachment_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(key) = state
                .vault_mgr
                .resolve_attachment_key(item_id, attachment_id)
            {
                let mut raw = Vec::new();
                raw.extend_from_slice(&key.enc_key);
                if let Some(mac_k) = key.mac_key {
                    raw.extend_from_slice(&mac_k);
                }
                json!({
                    "ok": true,
                    "key_b64": BASE64.encode(&raw)
                })
            } else {
                json!({ "ok": false, "error": "Unable to resolve attachment key (vault locked or missing item)" })
            }
        }
        "totp" => {
            let secret = req.get("secret").and_then(|v| v.as_str());
            let query = req
                .get("query")
                .or_else(|| req.get("id"))
                .and_then(|v| v.as_str());

            if let Some(q) = query {
                if let Some(item) = state.vault_mgr.find_item(q, None) {
                    let totp_seed = item
                        .login
                        .as_ref()
                        .and_then(|l| l.get("totp"))
                        .and_then(|v| v.as_str());
                    if let Some(seed) = totp_seed {
                        if let Some(res) = crate::totp::generate_totp(seed, None, 6, 30) {
                            json!({
                                "ok": true,
                                "code": res.code,
                                "ttl": res.ttl,
                                "period": res.period,
                                "id": item.id,
                                "name": item.name
                            })
                        } else {
                            json!({ "ok": false, "error": "Item has invalid TOTP configuration" })
                        }
                    } else {
                        json!({ "ok": false, "error": format!("Item '{}' has no TOTP configured", item.name) })
                    }
                } else {
                    json!({ "ok": false, "error": format!("Item '{}' not found in vault", q) })
                }
            } else if let Some(sec) = secret {
                if let Some(res) = crate::totp::generate_totp(sec, None, 6, 30) {
                    json!({ "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period })
                } else {
                    json!({ "ok": false, "error": "Invalid TOTP secret" })
                }
            } else {
                json!({ "ok": false, "error": "Missing TOTP secret or item query" })
            }
        }
        "copy" => {
            let text = req.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let sensitive = req
                .get("sensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let timeout = req.get("timeout").and_then(|v| v.as_i64()).unwrap_or(30);
            let clip_mgr = crate::clipboard::ClipboardManager::default().without_detached_worker();
            if clip_mgr.copy(text, sensitive, timeout) {
                json!({ "ok": true })
            } else {
                json!({ "ok": false, "error": "Failed to copy to clipboard" })
            }
        }
        "generate_password" => {
            let is_passphrase = req
                .get("passphrase")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_passphrase {
                let options = crate::generator::PassphraseOptions {
                    words: req
                        .get("words")
                        .and_then(|v| v.as_u64())
                        .map(|w| w as usize)
                        .unwrap_or(crate::generator::DEFAULT_PASSPHRASE_WORDS),
                    separator: req
                        .get("separator")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    capitalize: req
                        .get("capitalize")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                };
                match crate::generator::generate_passphrase(&options) {
                    Ok(secret) => json!({
                        "ok": true,
                        "password": secret.value,
                        "entropy": secret.entropy,
                        "type": secret.secret_type,
                    }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            } else {
                let options = crate::generator::PasswordOptions {
                    length: req
                        .get("length")
                        .and_then(|v| v.as_u64())
                        .map(|l| l as usize)
                        .unwrap_or(crate::generator::DEFAULT_PASSWORD_LENGTH),
                    uppercase: req
                        .get("uppercase")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    lowercase: req
                        .get("lowercase")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    numbers: req.get("numbers").and_then(|v| v.as_bool()).unwrap_or(true),
                    special: req.get("special").and_then(|v| v.as_bool()).unwrap_or(true),
                    avoid_ambiguous: req
                        .get("avoid_ambiguous")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    min_numbers: req
                        .get("min_numbers")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as usize)
                        .unwrap_or(1),
                    min_special: req
                        .get("min_special")
                        .and_then(|v| v.as_u64())
                        .map(|s| s as usize)
                        .unwrap_or(1),
                };
                match crate::generator::generate_password(&options) {
                    Ok(secret) => json!({
                        "ok": true,
                        "password": secret.value,
                        "entropy": secret.entropy,
                        "type": secret.secret_type,
                    }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
        }
        "set_auto_lock" => {
            if let Some(secs) = req.get("auto_lock_seconds").and_then(|v| v.as_u64()) {
                state.set_auto_lock_duration(Duration::from_secs(secs));
                json!({ "ok": true, "auto_lock_seconds": secs })
            } else {
                let mins = req
                    .get("auto_lock")
                    .or_else(|| req.get("auto_lock_minutes"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(15);
                state.set_auto_lock_minutes(mins);
                json!({ "ok": true, "auto_lock_minutes": mins })
            }
        }
        other => json!({ "ok": false, "error": format!("Unknown action: {}", other) }),
    };

    let _ = writeln!(stream, "{}", response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_daemon_state_lifecycle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);

        let state = DaemonState::new(storage_mgr, 15);
        assert!(!state.vault_mgr.is_unlocked());

        // Lock
        state.lock();
        assert!(!state.vault_mgr.is_unlocked());
        assert_eq!(state.vault_mgr.decrypted_items.read().unwrap().len(), 0);
    }

    #[test]
    fn test_daemon_totp_action() {
        let res = crate::totp::generate_totp("JBSWY3DPEHPK3PXP", None, 6, 30);
        assert!(res.is_some());
        let totp_res = res.unwrap();
        assert_eq!(totp_res.code.len(), 6);
    }

    #[test]
    fn test_daemon_totp_action_with_item_query() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);

        let state = DaemonState::new(storage_mgr, 15);
        let test_item = crate::vault::VaultItem {
            id: "item-totp-123".to_string(),
            name: "Github 2FA".to_string(),
            item_type: 1,
            type_name: "login".to_string(),
            sub_title: "user@github.com".to_string(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: Some(serde_json::json!({
                "username": "user",
                "totp": "JBSWY3DPEHPK3PXP"
            })),
            card: None,
            identity: None,
            ssh_key: None,
            fields: vec![],
            attachments: vec![],
            search_text: "github 2fa user".to_string(),
        };

        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        state
            .vault_mgr
            .decrypted_items
            .write()
            .unwrap()
            .push(test_item);

        // Find by ID
        let found = state.vault_mgr.find_item("item-totp-123", None);
        assert!(found.is_some());
        let seed = found
            .unwrap()
            .login
            .unwrap()
            .get("totp")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let res = crate::totp::generate_totp(&seed, None, 6, 30);
        assert!(res.is_some());
        assert_eq!(res.unwrap().code.len(), 6);

        // Find by Name
        let found_name = state.vault_mgr.find_item("Github", None);
        assert!(found_name.is_some());
    }

    #[test]
    fn test_should_touch_activity_classification() {
        // Passive actions must not touch activity
        for action in &[
            "ping",
            "status",
            "stop",
            "lock",
            "totp",
            "set_auto_lock",
            "unknown_action",
            "",
        ] {
            assert!(
                !should_touch_activity(action, &json!({ "action": action })),
                "Action '{}' should not touch activity",
                action
            );
        }

        // Active user actions must touch activity
        for action in &[
            "sync",
            "list",
            "search",
            "ssh_key_create",
            "get_item",
            "get_ssh_key",
            "get_attachment_key",
            "copy",
        ] {
            assert!(
                should_touch_activity(action, &json!({ "action": action })),
                "Action '{}' should touch activity",
                action
            );
        }

        // Explicit touch: false must override active actions
        let req_touch_false = json!({ "action": "list", "touch": false });
        assert!(!should_touch_activity("list", &req_touch_false));

        // Explicit touch: true must override passive actions
        let req_touch_true = json!({ "action": "ping", "touch": true });
        assert!(should_touch_activity("ping", &req_touch_true));
    }

    #[test]
    fn test_handle_client_selective_activity_touch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        // Set initial activity to a known point in the past
        let past = Instant::now() - Duration::from_secs(10);
        *state.last_activity.lock().unwrap() = past;

        // Helper to send a request via UnixStream pair and receive response
        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. "ping" without touch should not touch activity
        let res = send_req(json!({ "action": "ping" }));
        assert_eq!(res.get("pong").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 2. "status" without touch should not touch activity
        let _ = send_req(json!({ "action": "status" }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 3. "totp" with raw secret should not touch activity
        let _ = send_req(json!({ "action": "totp", "secret": "JBSWY3DPEHPK3PXP" }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 4. "get_item" with explicit touch: false should not touch activity
        let _ = send_req(json!({ "action": "get_item", "query": "none", "touch": false }));
        assert_eq!(*state.last_activity.lock().unwrap(), past);

        // 5. "ping" with explicit touch: true DOES touch activity
        let ping_touch_res = send_req(json!({ "action": "ping", "touch": true }));
        assert_eq!(
            ping_touch_res.get("pong").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(*state.last_activity.lock().unwrap() > past);

        // Reset past activity for subsequent test
        *state.last_activity.lock().unwrap() = past;

        // 6. Active action (e.g. "search") should touch activity
        let search_res = send_req(json!({ "action": "search", "query": "test" }));
        assert!(search_res.is_array());
        assert!(*state.last_activity.lock().unwrap() > past);
    }

    #[test]
    fn test_ssh_agent_ipc_actions() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let runtime = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));
        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // Disabled by default: applying starts nothing.
        let res = send_req(json!({ "action": "ssh_agent_apply" }));
        assert_eq!(res["ok"], true);
        assert_eq!(res["running"], false);
        let res = send_req(json!({ "action": "ssh_agent_status" }));
        assert_eq!(res["running"], false);
        assert_eq!(
            res["socket"],
            json!(runtime.path().join("omawarden-ssh-agent.sock"))
        );

        // Enabled: applying binds the socket.
        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.ssh_agent_enabled = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let res = send_req(json!({ "action": "ssh_agent_apply" }));
        assert_eq!(
            (res["ok"].clone(), res["running"].clone()),
            (json!(true), json!(true))
        );
        assert_eq!(
            send_req(json!({ "action": "ssh_agent_status" }))["running"],
            true
        );

        // Nothing is waiting for an answer.
        let res = send_req(json!({ "action": "ssh_agent_pending" }));
        assert_eq!(res["prompts"], json!([]));
        let res = send_req(json!({ "action": "ssh_agent_reply", "id": 42, "approve": true }));
        assert_eq!(res["ok"], true);
        assert_eq!(res["delivered"], false);
        let res = send_req(json!({ "action": "ssh_agent_reply" }));
        assert_eq!(
            res["delivered"], false,
            "missing id and approve are tolerated"
        );

        // Disabled again: applying stops it and removes the socket.
        let write_enabled = |on: bool| {
            let mut cfg = crate::config::ConfigManager::default().load();
            cfg.ssh_agent_enabled = on;
            fs::write(
                dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
                serde_json::to_string(&cfg).unwrap(),
            )
            .unwrap();
        };
        write_enabled(false);
        let res = send_req(json!({ "action": "ssh_agent_apply" }));
        assert_eq!(res["running"], false);
        assert!(!crate::ssh_agent::socket_path().exists());

        // A path that can't be bound is reported.
        std::os::unix::fs::symlink("/tmp/elsewhere", crate::ssh_agent::socket_path()).unwrap();
        write_enabled(true);
        let res = send_req(json!({ "action": "ssh_agent_apply" }));
        assert_eq!(res["ok"], false);
        assert!(res["error"].as_str().unwrap().starts_with("SSH agent: "));

        for (k, v) in [
            ("XDG_RUNTIME_DIR", old_runtime),
            ("OMAWARDEN_CONFIG_DIR", old_config),
        ] {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn test_ensure_daemon_running_keeps_a_running_daemon_it_should_not_replace() {
        let _lock = crate::env_lock();
        let runtime = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());

        // A daemon that answers every ping the same way; if it were replaced,
        // a second daemon would be spawned and the connection count would
        // show it.
        let listener = std::os::unix::net::UnixListener::bind(get_socket_path()).unwrap();
        for reply in [
            json!({ "ok": true, "commit": env!("GIT_HASH"), "unlocked": false }),
            json!({ "ok": true, "commit": "another-build", "unlocked": true }),
        ] {
            let server = {
                let listener = listener.try_clone().unwrap();
                let reply = reply.clone();
                std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut line = String::new();
                    BufReader::new(stream.try_clone().unwrap())
                        .read_line(&mut line)
                        .unwrap();
                    assert_eq!(
                        serde_json::from_str::<Value>(&line).unwrap()["action"],
                        "ping"
                    );
                    writeln!(stream, "{reply}").unwrap();
                })
            };
            ensure_daemon_running();
            server.join().unwrap();
        }

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
    }

    #[test]
    fn test_outdated_daemon_is_only_replaced_while_locked() {
        let ping = |commit: &str, unlocked: Option<bool>| {
            let mut v = json!({ "ok": true, "commit": commit });
            if let Some(u) = unlocked {
                v["unlocked"] = json!(u);
            }
            v
        };
        assert_eq!(
            check_running_daemon(&ping("abc", Some(true)), "abc"),
            DaemonCheck::UpToDate
        );
        assert_eq!(
            check_running_daemon(&ping("old", Some(true)), "abc"),
            DaemonCheck::Defer
        );
        assert_eq!(
            check_running_daemon(&ping("old", Some(false)), "abc"),
            DaemonCheck::Replace
        );
        // Daemons predating the field are replaced as before.
        assert_eq!(
            check_running_daemon(&ping("old", None), "abc"),
            DaemonCheck::Replace
        );
    }

    #[test]
    fn test_background_pings_do_not_prevent_idle_auto_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        // Configure a short timeout (100ms) for testing
        state.set_auto_lock_duration(Duration::from_millis(100));

        // Unlock the vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.vault_mgr.is_unlocked());

        // Send repeated pings over 150ms (crossing the 100ms threshold)
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(150) {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", json!({ "action": "ping" }));
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();
            handle.join().unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }

        // Auto-lock check must lock the vault despite the continuous background pings
        assert!(state.check_auto_lock());
        assert!(!state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_set_auto_lock_action() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // Update with minutes
        let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_minutes": 5 }));
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            *state.auto_lock_duration.lock().unwrap(),
            Duration::from_secs(300)
        );

        // Update with seconds
        let res = send_req(json!({ "action": "set_auto_lock", "auto_lock_seconds": 45 }));
        assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            *state.auto_lock_duration.lock().unwrap(),
            Duration::from_secs(45)
        );
    }

    #[test]
    fn test_verify_peer_credentials() {
        let (client, server) = UnixStream::pair().unwrap();
        assert!(verify_peer_credentials(&client).is_ok());
        assert!(verify_peer_credentials(&server).is_ok());
    }

    #[test]
    fn test_suspend_happened_predicate() {
        fn f(prev: Option<u64>, current: Option<u64>) -> bool {
            DaemonState::suspend_happened(prev, current)
        }
        assert!(!f(None, Some(100)), "first sample is never an event");
        assert!(
            !f(Some(100), Some(100)),
            "equal deltas: awake the whole time"
        );
        assert!(
            !f(Some(100), Some(101)),
            "one second of clock skew is not suspend"
        );
        assert!(f(Some(100), Some(103)), "grew by 3s: suspend happened");
        assert!(!f(Some(100), Some(99)), "shrinkage ignored");
        assert!(!f(Some(100), None), "clock unavailable is not an event");
    }

    #[test]
    fn test_suspend_drift_wipes_retained_key_while_soft_locked() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);

        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        // Soft-locked with a retained key: the dominant quick-unlock state.
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());
        assert!(state.vault_mgr.quick_unlock_available());

        // First tick primes the cache; second tick observes the drift.
        assert!(!state.check_suspend_drift_with(Some(1_000)));
        assert!(
            state.check_suspend_drift_with(Some(1_900)),
            "900s of accumulated suspend time must be detected"
        );
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "suspend must wipe the retained key even while soft-locked"
        );
        assert!(!state.vault_mgr.is_unlocked());

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_suspend_drift_hard_locks_unlocked_vault() {
        let dir = tempdir().unwrap();
        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(!state.check_suspend_drift_with(Some(10)));
        assert!(state.check_suspend_drift_with(Some(600)));
        assert!(!state.vault_mgr.is_unlocked());
    }

    #[test]
    fn test_session_anchor_ceiling_wipes_retained_key_while_soft_locked() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = DaemonState::new(StorageManager::new(dir.path().join("daemon_data.json")), 15);

        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        // Unlocked 13h ago (session anchor), then soft-locked with retention.
        *state.session_anchor.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(13 * 3600));
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());

        assert!(
            state.check_auto_lock(),
            "the 12h ceiling must fire for a retained key past the session anchor"
        );
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "ceiling must wipe the retained key"
        );
        assert!(
            state.session_anchor.lock().unwrap().is_none(),
            "hard lock clears the anchor"
        );

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_quick_unlock_re_arms_unlocked_at_but_not_session_anchor() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let runtime = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

        let pk = dir.path().join("mock-pkcheck");
        crate::write_test_executable(&pk, "#!/bin/sh\nexit 0\n");
        daemon_state.polkit_binary = pk;
        let state = Arc::new(daemon_state);

        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        // Session anchored 13h ago by the master-password unlock.
        *state.session_anchor.lock().unwrap() =
            Some(Instant::now() - Duration::from_secs(13 * 3600));
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());

        assert!(state.perform_quick_unlock().is_ok());
        assert!(
            state.unlocked_at.lock().unwrap().is_some(),
            "quick unlock must re-arm the per-unlock anchor (Rule 9 while unlocked)"
        );

        // The session anchor is untouched, so the ceiling still fires even
        // though the vault was just quick-unlocked.
        assert!(
            state.check_auto_lock(),
            "quick unlock must not extend the 12h session ceiling"
        );
        assert!(!state.vault_mgr.is_unlocked());

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_check_screen_lock_custom_detector() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = DaemonState::new(storage_mgr, 15);

        // Vault is initially locked: detector should not be invoked or return false
        let mut called = false;
        assert!(!state.check_screen_lock_with(|| {
            called = true;
            LockSignal::Screen
        }));
        assert!(!called);
        assert!(!state.vault_mgr.is_unlocked());

        // Unlock the vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.vault_mgr.is_unlocked());

        // No lock signal -> vault remains unlocked
        assert!(!state.check_screen_lock_with(|| LockSignal::None));
        assert!(state.vault_mgr.is_unlocked());

        // Screen signal -> locks
        assert!(state.check_screen_lock_with(|| LockSignal::Screen));
        assert!(!state.vault_mgr.is_unlocked());

        // Subsequent call returns false because already locked
        assert!(!state.check_screen_lock_with(|| LockSignal::Screen));
    }

    #[test]
    fn test_sleep_signal_hard_locks_and_screen_signal_soft_locks() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));
        let key = crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap();

        // Screen lock with quick unlock enabled: key must survive in the slot.
        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        *state.vault_mgr.user_key.write().unwrap() = Some(key.clone());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.check_screen_lock_with(|| LockSignal::Screen));
        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            state.vault_mgr.quick_unlock_available(),
            "screen lock must retain the key when quick unlock is on"
        );

        // Sleep signal: retention must be wiped even while quick unlock is on.
        *state.vault_mgr.user_key.write().unwrap() = Some(key);
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(state.check_screen_lock_with(|| LockSignal::Sleep));
        assert!(!state.vault_mgr.is_unlocked());
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "sleep must hard-lock: no key may survive a suspend"
        );

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_quick_unlock_ipc_disabled_and_unavailable() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", dir.path().join("runtime"));
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(
            res["error"].as_str().unwrap().contains("disabled"),
            "got: {res}"
        );

        // Enabled but nothing retained (hard-locked vault) must fail closed.
        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(
            res["error"].as_str().unwrap().contains("unavailable"),
            "got: {res}"
        );

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_quick_unlock_ipc_authorized_and_three_denies_wipe() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let runtime = tempdir().unwrap();
        let old_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());

        // A real login on disk so a successful polkit check can restore.
        let _vault = crate::vault::tests::seeded_vault(dir.path(), "master-pw");
        let mut daemon_state =
            DaemonState::new(StorageManager::new(dir.path().join("data.json")), 15);

        // Mock pkcheck whose exit code is driven by a file the test flips.
        let pk = dir.path().join("mock-pkcheck");
        crate::write_test_executable(
            &pk,
            format!(
                r#"#!/bin/sh
exit $(cat {})
"#,
                dir.path().join("pk_code").display()
            ),
        );
        daemon_state.polkit_binary = pk.clone();
        let state = Arc::new(daemon_state);

        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();

        // Prime retention the way a soft lock would.
        *state.vault_mgr.user_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[7u8; 64]).unwrap());
        assert!(state.vault_mgr.soft_lock());
        assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            client.write_all(format!("{}\n", req).as_bytes()).unwrap();
            client.flush().unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. polkit authorizes: IPC reports an unlocked vault.
        fs::write(dir.path().join("pk_code"), "0").unwrap();
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], true, "got: {res}");
        assert_eq!(res["status"], "unlocked");
        assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

        // 2. Three denials in a row wipe the retained key.
        fs::write(dir.path().join("pk_code"), "1").unwrap();
        for i in 1..=3 {
            let res = send_req(json!({ "action": "quick_unlock" }));
            assert_eq!(res["ok"], false, "attempt {i}: {res}");
            assert!(
                res["error"].as_str().unwrap().contains("denied"),
                "attempt {i}: {res}"
            );
        }
        assert!(
            !state.vault_mgr.quick_unlock_available(),
            "three denials must wipe the retained key"
        );
        assert_eq!(*state.quick_unlock_failures.lock().unwrap(), 0);

        // 3. After the wipe the action fails closed without calling polkit.
        fs::write(dir.path().join("pk_code"), "0").unwrap();
        let res = send_req(json!({ "action": "quick_unlock" }));
        assert_eq!(res["ok"], false);
        assert!(res["error"].as_str().unwrap().contains("unavailable"));

        // 4. wipe_quick_unlock action is a harmless explicit no-op.
        let res = send_req(json!({ "action": "wipe_quick_unlock" }));
        assert_eq!(res["ok"], true);

        old_runtime.map_or_else(
            || std::env::remove_var("XDG_RUNTIME_DIR"),
            |v| std::env::set_var("XDG_RUNTIME_DIR", v),
        );
        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_ping_advertises_quick_unlock_only_when_ready() {
        let _lock = crate::env_lock();
        let dir = tempdir().unwrap();
        let old_config = std::env::var_os("OMAWARDEN_CONFIG_DIR");
        std::env::set_var("OMAWARDEN_CONFIG_DIR", dir.path());
        let state = Arc::new(DaemonState::new(
            StorageManager::new(dir.path().join("daemon_data.json")),
            15,
        ));
        // Disabled by default and nothing retained.
        assert!(!state.quick_unlock_ready());
        let mut cfg = crate::config::ConfigManager::default().load();
        cfg.quick_unlock = true;
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
        // Enabled but no retained key: still not ready.
        assert!(!state.quick_unlock_ready());
        *state.vault_mgr.quick_unlock_key.write().unwrap() =
            Some(crate::crypto::SymmetricCryptoKey::from_raw_bytes(&[9u8; 64]).unwrap());
        assert!(state.quick_unlock_ready());

        old_config.map_or_else(
            || std::env::remove_var("OMAWARDEN_CONFIG_DIR"),
            |v| std::env::set_var("OMAWARDEN_CONFIG_DIR", v),
        );
    }

    #[test]
    fn test_screen_lock_detection_functions_safe() {
        // Ensure detection functions execute safely without panicking
        let _ = is_omarchy_locked();
        let _ = is_screen_locker_running();
        let _ = is_logind_locked_or_sleeping();
        let _ = is_system_or_screen_locked();
    }

    #[test]
    fn test_validate_socket_path_valid_and_symlink_rejection() {
        let dir = tempdir().unwrap();
        let real_socket = dir.path().join("real.sock");
        fs::write(&real_socket, b"").unwrap();

        // Valid socket file owned by current user
        assert!(validate_socket_path(&real_socket).is_ok());

        // Symlink pointing to the real socket must be rejected
        let symlink_socket = dir.path().join("symlink.sock");
        std::os::unix::fs::symlink(&real_socket, &symlink_socket).unwrap();
        let err = validate_socket_path(&symlink_socket);
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_validate_socket_path_parent_symlink_rejection() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_runtime");
        fs::create_dir_all(&real_dir).unwrap();

        let symlink_dir = dir.path().join("symlink_runtime");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let socket_in_symlink_parent = symlink_dir.join("omawarden.sock");
        let err = validate_socket_path(&socket_in_symlink_parent);
        assert!(err.is_err());
        assert_eq!(
            err.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn test_get_runtime_dir_permissions_and_ownership() {
        let runtime_dir = get_runtime_dir();
        assert!(runtime_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&runtime_dir).unwrap();
            assert_eq!(meta.uid(), unsafe { libc::getuid() });
        }
    }

    #[test]
    fn test_privileged_actions_require_unlocked_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let privileged_actions = vec![
            json!({ "action": "list" }),
            json!({ "action": "search", "query": "test" }),
            json!({ "action": "get_item", "query": "test" }),
            json!({ "action": "get_ssh_key", "query": "test" }),
            json!({ "action": "get_attachment_key", "item_id": "i", "attachment_id": "a" }),
            json!({ "action": "sync" }),
            json!({ "action": "totp", "query": "test" }),
        ];

        // 1. While locked, all privileged actions fail with locked error
        for req in &privileged_actions {
            let res = send_req(req.clone());
            assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(false));
            assert!(
                res.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .contains("locked"),
                "Action '{}' should fail when vault is locked",
                req.get("action").unwrap()
            );
        }

        // 2. Unlock vault
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        // 3. When unlocked, privileged actions proceed without needing any session token
        let list_res = send_req(json!({ "action": "list" }));
        assert!(list_res.is_array(), "List should succeed when unlocked");

        let search_res = send_req(json!({ "action": "search", "query": "test" }));
        assert!(search_res.is_array(), "Search should succeed when unlocked");
    }

    #[test]
    fn test_max_session_lifetime_auto_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = DaemonState::new(storage_mgr, 15);

        // Vault unlocked 2 hours ago with max lifetime of 1 hour
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        *state.unlocked_at.lock().unwrap() = Some(Instant::now() - Duration::from_secs(7200));
        *state.max_session_lifetime.lock().unwrap() = Duration::from_secs(3600);

        // Keep last_activity brand new (just now) so idle timeout would NOT trigger
        *state.last_activity.lock().unwrap() = Instant::now();

        // check_auto_lock must trigger because max_session_lifetime has elapsed!
        assert!(state.check_auto_lock());
        assert!(!state.vault_mgr.is_unlocked());
        assert!(state.unlocked_at.lock().unwrap().is_none());
    }

    #[test]
    fn test_handle_client_client_context_parsing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));
        *state.vault_mgr.is_unlocked.write().unwrap() = true;

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = Arc::clone(&state);
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. Valid client context in sync request (fails with missing session token error, proving sync_with_client was called)
        let res_valid = send_req(json!({
            "action": "sync",
            "client": {
                "name": "Omarchy_Bitwarden",
                "version": "0.11.2"
            }
        }));
        assert_eq!(res_valid.get("ok").and_then(|v| v.as_bool()), Some(false));
        assert!(res_valid.get("error").is_some());

        // 2. Invalid client context with CRLF injection is rejected/filtered
        let res_injection = send_req(json!({
            "action": "sync",
            "client": {
                "name": "evil\r\nHeader: foo",
                "version": "0.11.2"
            }
        }));
        assert_eq!(
            res_injection.get("ok").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert!(res_injection.get("error").is_some());
    }

    #[test]
    fn test_daemon_generate_password_action() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("daemon_data.json");
        let storage_mgr = StorageManager::new(path);
        let state = Arc::new(DaemonState::new(storage_mgr, 15));

        let send_req = |req: Value| -> Value {
            let (mut client, server) = UnixStream::pair().unwrap();
            let st = state.clone();
            let handle = std::thread::spawn(move || {
                let _ = handle_client(server, st);
            });
            let payload = format!("{}\n", req);
            client.write_all(payload.as_bytes()).unwrap();
            client.flush().unwrap();

            let mut reader = BufReader::new(client);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            handle.join().unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // 1. Password generation while locked
        let res_pwd = send_req(json!({
            "action": "generate_password",
            "length": 25,
            "uppercase": true,
            "lowercase": true,
            "numbers": true,
            "special": true
        }));
        assert_eq!(res_pwd.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            res_pwd.get("type").and_then(|v| v.as_str()),
            Some("password")
        );
        let pwd_str = res_pwd
            .get("password")
            .and_then(|v| v.as_str())
            .expect("missing password");
        assert_eq!(pwd_str.len(), 25);
        assert!(res_pwd.get("entropy").and_then(|v| v.as_f64()).unwrap() > 100.0);

        // 2. Passphrase generation while locked
        let res_phrase = send_req(json!({
            "action": "generate_password",
            "passphrase": true,
            "words": 5,
            "separator": ".",
            "capitalize": true
        }));
        assert_eq!(res_phrase.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            res_phrase.get("type").and_then(|v| v.as_str()),
            Some("passphrase")
        );
        let phrase_str = res_phrase
            .get("password")
            .and_then(|v| v.as_str())
            .expect("missing passphrase");
        assert_eq!(phrase_str.split('.').count(), 5);
        assert!(res_phrase.get("entropy").and_then(|v| v.as_f64()).unwrap() > 60.0);
    }
}
