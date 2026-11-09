use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::storage::StorageManager;
use crate::vault::VaultManager;

use super::client::is_omawarden_binary;
use super::lock_detect::system_lock_signal;

/// Cooperative cancellation signal for the daemon server.
#[derive(Clone, Debug, Default)]
pub struct ShutdownSignal {
    flag: Arc<AtomicBool>,
}

pub type ShutdownHandle = ShutdownSignal;

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
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
    /// Cached `quick_unlock` setting, read once at startup and refreshed via
    /// the `set_quick_unlock` IPC that `config set --quick-unlock` sends.
    /// Reading the file per call put a disk read + parse on the ping path
    /// (the overlay polls every 3s), on every watchdog tick and inside
    /// check_auto_lock, and a transient read failure silently meant
    /// "disabled", turning a soft lock into a hard lock mid-session.
    pub quick_unlock_setting: Mutex<bool>,
    /// Whether the packaged policy file for POLKIT_ACTION_ID exists in the
    /// polkit action directories, resolved once at startup. Without the
    /// policy, pkcheck exits 127 and quick unlock can only ever fail, so
    /// readiness must not advertise it.
    pub polkit_policy_registered: bool,
    /// Rule 9 / ADR-0025: when the current session's last master-password
    /// unlock happened. Survives soft locks so the 12h ceiling bounds the
    /// retained key too; cleared by every hard lock.
    pub session_anchor: Mutex<Option<Instant>>,
    /// CLOCK_BOOTTIME minus CLOCK_MONOTONIC, in whole seconds, as of the last
    /// watchdog tick. Suspend time accumulates in BOOTTIME only, so a growing
    /// delta is a deterministic resume-edge detector (no D-Bus needed).
    pub last_boot_delta_secs: Mutex<Option<u64>>,
    pub shutdown: ShutdownSignal,
    pub socket_path: Mutex<Option<PathBuf>>,
    /// Whether this daemon is hosted in-process inside an external application.
    pub in_process: AtomicBool,
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

/// Resolve pkcheck from trusted system locations only, requiring a
/// root-owned regular file that group/other cannot write. A plain PATH
/// lookup would let any same-UID process plant a fake `pkcheck` in
/// ~/.local/bin that authorizes every quick unlock without a dialog
/// (full-review security finding).
fn resolve_pkcheck() -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for candidate in ["/usr/bin/pkcheck", "/usr/sbin/pkcheck"] {
        let path = Path::new(candidate);
        let Ok(meta) = fs::metadata(path) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        if meta.uid() != 0 {
            continue;
        }
        if meta.permissions().mode() & 0o022 != 0 {
            continue;
        }
        return Some(path.to_path_buf());
    }
    None
}

impl DaemonState {
    pub fn new(storage_mgr: StorageManager, auto_lock_minutes: u64) -> Self {
        let vault_mgr = Arc::new(VaultManager::new("", Some(storage_mgr), None));
        let polkit_binary = resolve_pkcheck().unwrap_or_default();
        let quick_unlock_setting = crate::config::ConfigManager::default().load().quick_unlock;
        let polkit_policy_registered =
            crate::polkit::policy_registered(crate::polkit::POLKIT_ACTION_ID);
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
            quick_unlock_setting: Mutex::new(quick_unlock_setting),
            polkit_policy_registered,
            session_anchor: Mutex::new(None),
            last_boot_delta_secs: Mutex::new(None),
            shutdown: ShutdownSignal::new(),
            socket_path: Mutex::new(None),
            in_process: AtomicBool::new(
                !env::current_exe()
                    .ok()
                    .as_deref()
                    .is_some_and(is_omawarden_binary),
            ),
        }
    }

    /// Returns true if this daemon is running in-process inside a host application.
    pub fn is_in_process(&self) -> bool {
        self.in_process.load(Ordering::SeqCst)
    }

    /// Sets whether this daemon is running in-process inside a host application.
    pub fn set_in_process(&self, in_process: bool) {
        self.in_process.store(in_process, Ordering::SeqCst);
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

    pub(crate) fn quick_unlock_enabled(&self) -> bool {
        // A poisoned mutex resolves to false: that is the fail-closed
        // default (unlike quick_unlock_busy, whose guard state is re-derived
        // and therefore safe to recover with into_inner).
        self.quick_unlock_setting
            .lock()
            .ok()
            .map(|g| *g)
            .unwrap_or(false)
    }

    /// `config set --quick-unlock` refreshes the cached setting through this
    /// IPC so the daemon never re-reads config.json on its hot paths.
    /// Editing the file by hand while the daemon runs still needs a restart
    /// (or a `config set`) to be picked up.
    pub fn set_quick_unlock_enabled(&self, enabled: bool) {
        if let Ok(mut setting) = self.quick_unlock_setting.lock() {
            *setting = enabled;
        }
    }

    /// Whether the feature can work at all right now: enabled in settings, a
    /// polkit binary resolved at daemon startup, and the packaged policy
    /// registered. Retention is gated on this too (see `soft_lock`): holding
    /// the key for a prompt that can only fail would be pure exposure with no
    /// way to spend it. (Resolution is cached at startup; installing polkit
    /// or the policy later is picked up at the next daemon start.)
    pub fn quick_unlock_usable(&self) -> bool {
        self.quick_unlock_enabled()
            && !self.polkit_binary.as_os_str().is_empty()
            && self.polkit_policy_registered
    }

    /// Quick unlock availability as advertised over IPC: usable AND a key
    /// currently retained by a soft lock. Including the binary and the policy
    /// keeps the button honest on systems without polkit or with the policy
    /// missing (older package, dev tarball predating this feature): it stays
    /// hidden instead of erroring on click.
    pub fn quick_unlock_ready(&self) -> bool {
        self.quick_unlock_usable() && self.vault_mgr.quick_unlock_available()
    }

    /// ADR-0025: re-unlock the vault behind a polkit system-authentication
    /// check instead of the master password. Fail-closed on every rejection;
    /// three consecutive denials wipe the retained key.
    pub fn perform_quick_unlock(&self) -> Result<usize, String> {
        self.perform_quick_unlock_with_timeout(crate::polkit::DEFAULT_CHECK_TIMEOUT)
    }

    /// Same check with a caller-chosen prompt timeout. The SSH agent path
    /// uses a shorter one: an unattended `git fetch` must not sit silent for
    /// the full two minutes the overlay can afford (the user is looking at
    /// its dialog).
    pub fn perform_quick_unlock_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<usize, String> {
        if !self.quick_unlock_enabled() {
            return Err("Quick unlock is disabled in settings.".into());
        }
        if self.vault_mgr.is_unlocked() {
            // Already unlocked: never re-prompt or re-arm timers.
            return Err("Vault is already unlocked.".into());
        }
        if self.polkit_binary.as_os_str().is_empty() {
            return Err("System authentication is unavailable right now.".into());
        }
        // Same gate quick_unlock_ready() advertises: without the policy the
        // pkcheck call can only fail (exit 127, action not registered), so
        // the SSH path must not even attempt it.
        if !self.polkit_policy_registered {
            return Err("System authentication is unavailable right now.".into());
        }
        if !self.vault_mgr.quick_unlock_available() {
            return Err("Quick unlock is unavailable: the vault was hard-locked.".into());
        }
        // One interactive prompt at a time; concurrent callers fail fast and
        // the overlay falls back to the master password field. A panic in an
        // earlier prompt poisons the mutex; recovering the guard (instead of
        // propagating the poison) keeps quick unlock usable — the state this
        // guard protected is re-checked right below.
        let _guard = match self.quick_unlock_busy.try_lock() {
            Ok(g) => g,
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err("Quick unlock is already in progress.".into());
            }
        };
        // Re-check: a wipe may have raced with acquiring the busy lock.
        if !self.vault_mgr.quick_unlock_available() {
            return Err("Quick unlock is unavailable: the vault was hard-locked.".into());
        }

        let context = self.vault_mgr.unlock_context();
        match crate::polkit::check(
            crate::polkit::POLKIT_ACTION_ID,
            &self.polkit_binary,
            timeout,
        ) {
            crate::polkit::PolkitOutcome::Authorized => {}
            crate::polkit::PolkitOutcome::Denied => {
                let _restore = self
                    .vault_mgr
                    .restore_guard
                    .lock()
                    .map_err(|_| "Vault state unavailable")?;
                if self.vault_mgr.unlock_context() != context {
                    return Err("Vault session changed during quick unlock.".into());
                }
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
                    self.vault_mgr.wipe_quick_unlock_inner();
                    if let Ok(mut n) = self.quick_unlock_failures.lock() {
                        *n = 0;
                    }
                }
                return Err("System authentication was denied.".into());
            }
            crate::polkit::PolkitOutcome::Unavailable(reason) => {
                crate::log_warn!("omawarden:daemon", "polkit unavailable: {}", reason);
                return Err("System authentication is unavailable right now.".into());
            }
        }

        match self.vault_mgr.quick_unlock_restore_in_context(&context) {
            Ok(count) => {
                let _restore = self
                    .vault_mgr
                    .restore_guard
                    .lock()
                    .map_err(|_| "Vault state unavailable")?;
                if self.vault_mgr.unlock_context() != context {
                    return Err("Vault was locked during quick unlock.".into());
                }
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
                Err(e)
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

    pub(crate) fn reset_session_timers(&self) {
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        if let Ok(mut anchor) = self.session_anchor.lock() {
            *anchor = None;
        }
        if let Ok(mut n) = self.quick_unlock_failures.lock() {
            *n = 0;
        }
    }

    /// Hard lock (ADR-0025). Returns whether output cleanup also succeeded.
    pub fn lock(&self) -> bool {
        let _restore = self
            .vault_mgr
            .restore_guard
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let outputs_cleared = self.vault_mgr.hard_lock_inner();
        self.reset_session_timers();
        outputs_cleared
    }

    /// Soft lock (ADR-0025): purges decrypted state but retains the user key
    /// in locked memory when quick unlock is enabled in settings.
    pub fn soft_lock(&self) {
        if let Ok(mut ua) = self.unlocked_at.lock() {
            *ua = None;
        }
        // Retention requires the feature to actually be usable: with the
        // policy missing or no polkit binary the polkit check can only fail,
        // so keeping the key would add exposure without a way to spend it.
        if self.quick_unlock_usable() {
            self.vault_mgr.soft_lock();
        } else {
            self.vault_mgr.hard_lock();
        }
    }

    pub fn unlock(&self, password: &str) -> Result<usize, String> {
        self.unlock_in_context(password, &self.vault_mgr.unlock_context(), None)
    }

    pub(crate) fn unlock_in_context(
        &self,
        password: &str,
        expected: &str,
        credential_id: Option<&str>,
    ) -> Result<usize, String> {
        let count = self
            .vault_mgr
            .unlock_in_context(password, expected, credential_id)?;
        let _restore = self
            .vault_mgr
            .restore_guard
            .lock()
            .map_err(|_| "Vault state unavailable")?;
        if self.vault_mgr.unlock_context() != expected {
            return Err("Vault was locked during unlock.".into());
        }
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
            | "ssh_key_create_v2"
            | "get_item"
            | "get_ssh_key"
            | "get_attachment_key"
            | "copy"
            | "generate_password"
    )
}
