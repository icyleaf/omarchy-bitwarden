use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use super::state::LockSignal;

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
