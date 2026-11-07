use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::client::connect_daemon;
use super::server::open_daemon_lock;

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

// The gate belongs to the runtime (clipboard and previews), not to a cache
// inode. Only final output and its revocation take it.
pub(crate) fn lock_session_outputs() -> io::Result<fs::File> {
    let gate = open_daemon_lock(&get_socket_path().with_extension("outputs.lock"))?;
    gate.lock()?;
    Ok(gate)
}

#[derive(serde::Deserialize, serde::Serialize)]
pub(crate) struct OutputSession {
    pub(crate) lock_generation: u64,
    pub(crate) credential_id: String,
}

pub(crate) fn output_session() -> io::Result<OutputSession> {
    let changed = || io::Error::other("Vault session changed. Unlock the vault and try again.");
    let mut stream = connect_daemon().map_err(|_| changed())?;
    let timeout = Some(Duration::from_secs(2));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    writeln!(stream, "{}", json!({"action":"output_generation"}))?;
    let mut reply = String::new();
    BufReader::new(stream).take(256).read_line(&mut reply)?;
    serde_json::from_str::<Option<OutputSession>>(&reply)?
        .filter(|session| crate::credential_slots::valid_id(&session.credential_id))
        .ok_or_else(changed)
}

/// Hold the output gate while publishing data from the named unlocked session.
#[doc(hidden)]
pub fn guard_session_output(expected: u64) -> io::Result<fs::File> {
    let gate = lock_session_outputs()?;
    // The generation query takes neither the output gate nor the restore
    // guard. It must remain safe to answer while a revocation waits for us.
    if output_session()?.lock_generation != expected {
        return Err(io::Error::other(
            "Vault session changed. Unlock the vault and try again.",
        ));
    }
    Ok(gate)
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

/// The monotonically increasing integer version of the Daemon Protocol wire format.
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// The minimum protocol version this client/server understands.
/// Version 0 represents legacy unversioned daemons.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 0;

/// The result of checking protocol version compatibility against the wire handshake.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolCheck {
    Compatible,
    Incompatible {
        running: u32,
        min_supported: u32,
        current: u32,
    },
}

/// Evaluates daemon protocol version from a ping response.
///
/// Missing or malformed `protocol_version` fields are treated as legacy version 0.
pub fn check_protocol_version(ping: &Value) -> ProtocolCheck {
    let running = ping
        .get("protocol_version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    if (MIN_SUPPORTED_PROTOCOL_VERSION..=CURRENT_PROTOCOL_VERSION).contains(&running) {
        ProtocolCheck::Compatible
    } else {
        ProtocolCheck::Incompatible {
            running,
            min_supported: MIN_SUPPORTED_PROTOCOL_VERSION,
            current: CURRENT_PROTOCOL_VERSION,
        }
    }
}
