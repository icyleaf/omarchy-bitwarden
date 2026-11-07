//! Durable cross-process epoch for lock transitions.
//!
//! Copies served from the encrypted cache capture their authorization before
//! reading or decrypting the cache. Every lock transition advances
//! a shared epoch: a process captures the value before reading the cache, and
//! the detached holder re-reads it before publishing. Keeping the counter in
//! the runtime directory instead of in a process means a daemon restart cannot
//! revive an authorization, and the `flock` guard means two processes cannot
//! mint the same transition value.
//!
//! The file holds a non-secret ASCII decimal `u64`. Readers fail closed on
//! corrupt data. Transitions never reuse an aged epoch: a valid value is
//! incremented, a missing file starts a random 63-bit value, and a corrupt
//! file rotates to a fresh random value. All files are opened with
//! `O_NOFOLLOW`, validated as regular files owned by the current UID, and the
//! data file is replaced atomically with mode 0600 and fsynced together with
//! its parent directory. Transitions invalidate the previous record first so
//! failed publication cannot leave the old authorization usable.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

use crate::fs_util;

const DATA_FILE: &str = "omawarden.lock-epoch";
const GUARD_FILE: &str = "omawarden.lock-epoch.lock";
// The stable guard is empty during a transition and one byte after publication.
const PUBLISHED_GUARD_LEN: u64 = 1;
/// Longest decimal representation of a `u64`; longer files are corrupt.
const MAX_EPOCH_LEN: u64 = 20;
const PRIVATE_MODE: u32 = 0o600;

/// A lock transition counter that never repeats within a runtime directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LockEpoch(u64);

impl LockEpoch {
    pub(crate) fn value(self) -> u64 {
        self.0
    }
}

/// A handle to the epoch file in a runtime directory.
pub(crate) struct LockEpochStore {
    runtime_dir: PathBuf,
    #[cfg(test)]
    before_rename: Option<fn(&Path)>,
}

impl LockEpochStore {
    pub(crate) fn new(runtime_dir: &Path) -> Self {
        Self {
            runtime_dir: runtime_dir.to_path_buf(),
            #[cfg(test)]
            before_rename: None,
        }
    }

    /// Returns the current epoch, initializing and persisting a fresh random
    /// one when the file does not exist yet.
    ///
    /// Corrupt data is an error: the caller must not act on an epoch it could
    /// not read.
    pub(crate) fn current(&self) -> io::Result<LockEpoch> {
        let guard = self.lock_guard()?;
        let epoch = match self.read_locked()? {
            Stored::Epoch(epoch) => match guard.metadata()?.len() {
                PUBLISHED_GUARD_LEN => return Ok(LockEpoch(epoch)),
                // Finish an interrupted transition or migrate an older guard
                // by revoking its old value before authorizing another copy.
                0 => next_epoch(epoch),
                _ => return Err(corrupt_error("unexpected guard length")),
            },
            Stored::Missing => random_epoch(),
            Stored::Corrupt(reason) => return Err(corrupt_error(reason)),
        };
        self.persist(epoch, &guard)?;
        Ok(epoch)
    }

    /// Issues a new epoch that differs from every previously issued value.
    ///
    /// A valid value is incremented (rotating instead of wrapping at
    /// `u64::MAX`), a missing file starts a random epoch, and a corrupt file is
    /// rotated to a random epoch.
    pub(crate) fn advance(&self) -> io::Result<LockEpoch> {
        let guard = self.lock_guard()?;
        let previous = self.read_locked();
        // Try both revocations even if one fails. The stable guard also marks
        // an unfinished transition when the data file itself is inaccessible.
        let guard_revoked = guard.set_len(0).and_then(|()| guard.sync_all());
        let record_revoked = self.invalidate_current();
        guard_revoked?;
        record_revoked?;
        let next = match previous? {
            Stored::Epoch(epoch) => next_epoch(epoch),
            Stored::Missing => random_epoch(),
            Stored::Corrupt(reason) => {
                crate::log_warn!(
                    "omawarden:lock-epoch",
                    "Corrupt shared lock epoch ({}). Rotating to a fresh epoch.",
                    reason
                );
                random_epoch()
            }
        };
        self.persist(next, &guard)?;
        Ok(next)
    }

    fn invalidate_current(&self) -> io::Result<()> {
        let invalidate = || {
            let file = fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.data_path())?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.uid() != current_uid() {
                return Err(corrupt_error("not an owned regular file"));
            }
            file.set_len(0)?;
            file.sync_all()
        };
        match invalidate() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            // A read-only file or symlink can still be revoked by removing
            // its name from the private runtime directory.
            Err(_) => {
                fs::remove_file(self.data_path())?;
                File::open(&self.runtime_dir)?.sync_all()
            }
        }
    }

    fn data_path(&self) -> PathBuf {
        self.runtime_dir.join(DATA_FILE)
    }

    fn guard_path(&self) -> PathBuf {
        self.runtime_dir.join(GUARD_FILE)
    }

    /// Takes the exclusive cross-process guard.
    ///
    /// The guard inode is stable, unlike the data file which is replaced on
    /// every write, so all processes serialize on the same lock.
    fn lock_guard(&self) -> io::Result<File> {
        fs_util::create_secure_dir_all(&self.runtime_dir, 0o700)?;
        let guard = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(PRIVATE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.guard_path())?;
        let metadata = guard.metadata()?;
        if !metadata.is_file() || metadata.uid() != current_uid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid lock epoch guard",
            ));
        }
        guard.lock()?;
        Ok(guard)
    }

    /// Reads the epoch file while the caller holds the guard.
    fn read_locked(&self) -> io::Result<Stored> {
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.data_path())
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Stored::Missing),
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Ok(Stored::Corrupt("not a regular file"))
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != current_uid() {
            return Ok(Stored::Corrupt("not a regular file"));
        }
        if metadata.len() > MAX_EPOCH_LEN {
            return Ok(Stored::Corrupt("unexpected length"));
        }
        let mut bytes = Vec::with_capacity(MAX_EPOCH_LEN as usize + 1);
        file.take(MAX_EPOCH_LEN + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_EPOCH_LEN {
            return Ok(Stored::Corrupt("unexpected length"));
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Ok(Stored::Corrupt("not decimal"));
        };
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(Stored::Corrupt("not decimal"));
        }
        match text.parse::<u64>() {
            Ok(epoch) => Ok(Stored::Epoch(epoch)),
            Err(_) => Ok(Stored::Corrupt("out of range")),
        }
    }

    /// Atomically replaces the data file and makes the replacement durable.
    ///
    /// The staged file is fsynced *before* the rename, so a crash cannot leave
    /// the previous epoch in place after this transition returned.
    fn persist(&self, epoch: LockEpoch, guard: &File) -> io::Result<()> {
        let path = self.data_path();
        let mut staged = tempfile::NamedTempFile::new_in(&self.runtime_dir)?;
        staged
            .as_file_mut()
            .write_all(epoch.0.to_string().as_bytes())?;
        staged.as_file().sync_all()?;
        #[cfg(test)]
        if let Some(before_rename) = self.before_rename {
            before_rename(&self.runtime_dir);
        }
        staged.persist(&path).map_err(|error| error.error)?;
        File::open(&self.runtime_dir)?.sync_all()?;
        guard.set_len(PUBLISHED_GUARD_LEN)?;
        guard.sync_all()
    }
}

/// Resolves the store for the daemon's runtime directory.
pub(crate) fn store() -> LockEpochStore {
    LockEpochStore::new(&crate::daemon::get_runtime_dir())
}

/// The on-disk state of the epoch file, as seen under the guard.
enum Stored {
    Epoch(u64),
    Missing,
    Corrupt(&'static str),
}

/// Draws a non-zero 63-bit epoch so a rotation can never reproduce a saturated
/// `u64::MAX` and an initialized store never starts at zero.
fn random_epoch() -> LockEpoch {
    loop {
        let candidate = OsRng.next_u64() & (u64::MAX >> 1);
        if candidate != 0 {
            return LockEpoch(candidate);
        }
    }
}

fn next_epoch(epoch: u64) -> LockEpoch {
    match epoch.checked_add(1) {
        Some(next) => LockEpoch(next),
        // Rotation draws below u64::MAX, so saturation cannot reuse its value.
        None => random_epoch(),
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no pointer arguments and cannot fail.
    unsafe { libc::geteuid() }
}

fn corrupt_error(reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Invalid lock epoch: {reason}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn store_in(dir: &tempfile::TempDir) -> LockEpochStore {
        LockEpochStore::new(dir.path())
    }

    fn read_raw(dir: &tempfile::TempDir) -> String {
        fs::read_to_string(dir.path().join(DATA_FILE)).unwrap()
    }

    #[test]
    fn current_initialises_and_persists_a_random_epoch() {
        let dir = tempdir().unwrap();
        let epoch = store_in(&dir).current().unwrap();

        assert_ne!(epoch.value(), 0);
        assert!(epoch.value() < 1 << 63);
        assert_eq!(read_raw(&dir), epoch.value().to_string());

        for name in [DATA_FILE, GUARD_FILE] {
            let metadata = fs::metadata(dir.path().join(name)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "{name}");
        }
    }

    #[test]
    fn current_is_stable_across_calls_and_stores() {
        let dir = tempdir().unwrap();
        let first = store_in(&dir).current().unwrap();
        let second = store_in(&dir).current().unwrap();

        assert_eq!(first, second);
        assert_eq!(store_in(&dir).current().unwrap(), first);
        assert_eq!(read_raw(&dir), first.value().to_string());
    }

    #[test]
    fn advance_increments_and_is_visible_to_another_store() {
        let dir = tempdir().unwrap();
        let store = store_in(&dir);
        let initial = store.current().unwrap();
        let advanced = store.advance().unwrap();

        assert_eq!(advanced.value(), initial.value() + 1);
        assert_eq!(store_in(&dir).current().unwrap(), advanced);
        assert_eq!(read_raw(&dir), advanced.value().to_string());
    }

    #[test]
    fn advance_initialises_from_missing() {
        let dir = tempdir().unwrap();
        let store = store_in(&dir);
        let epoch = store.advance().unwrap();

        assert_ne!(epoch.value(), 0);
        assert!(epoch.value() < 1 << 63);
        assert_eq!(read_raw(&dir), epoch.value().to_string());
        assert_eq!(store.current().unwrap(), epoch);
    }

    #[test]
    fn concurrent_advances_are_unique() {
        let dir = tempdir().unwrap();
        let store = Arc::new(store_in(&dir));
        let initial = store.current().unwrap();

        let workers: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    (0..4)
                        .map(|_| store.advance().unwrap().value())
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let mut seen = HashSet::new();
        for worker in workers {
            for epoch in worker.join().unwrap() {
                assert!(seen.insert(epoch), "epoch {epoch} was issued twice");
                assert!(epoch > initial.value());
            }
        }
        assert_eq!(seen.len(), 32);
        assert_eq!(store.current().unwrap().value(), initial.value() + 32);
    }

    #[test]
    fn corrupt_current_errors_and_advance_rotates() {
        let dir = tempdir().unwrap();
        let store = store_in(&dir);
        let initial = store.current().unwrap();

        for corrupt in [
            "",
            "not-a-number",
            " 42",
            "42\n",
            "0x2a",
            "18446744073709551616",
        ] {
            fs::write(dir.path().join(DATA_FILE), corrupt).unwrap();
            let error = store.current().unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "content {corrupt:?}"
            );

            let rotated = store.advance().unwrap();
            assert_ne!(rotated.value(), 0);
            assert!(rotated.value() < 1 << 63);
            assert_eq!(store.current().unwrap(), rotated);
            assert_eq!(read_raw(&dir), rotated.value().to_string());
        }

        // The corrupt contents must never have been accepted as an epoch.
        assert_ne!(initial.value(), 0);
    }

    #[test]
    fn advance_rotates_instead_of_wrapping_at_max() {
        let dir = tempdir().unwrap();
        let store = store_in(&dir);
        fs::write(dir.path().join(DATA_FILE), u64::MAX.to_string()).unwrap();

        let rotated = store.advance().unwrap();

        assert_ne!(rotated.value(), u64::MAX);
        assert_ne!(rotated.value(), 0);
        assert_eq!(store.current().unwrap(), rotated);
    }

    #[test]
    fn failed_rename_cannot_restore_the_previous_authorization() {
        let dir = tempdir().unwrap();
        let mut store = store_in(&dir);
        let previous = store.current().unwrap();
        store.before_rename = Some(|parent| {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        });

        let failed = store.advance();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        assert!(failed.is_err(), "the read-only parent must reject rename");
        assert!(
            store.current().is_err(),
            "a failed publication must revoke {previous:?}"
        );
        store.before_rename = None;
        let recovered = store.advance().unwrap();
        assert_ne!(recovered, previous);
        assert_eq!(store.current().unwrap(), recovered);
    }

    #[test]
    fn an_interrupted_transition_revokes_a_still_readable_old_record() {
        let dir = tempdir().unwrap();
        let store = store_in(&dir);
        let previous = store.current().unwrap();
        // Model a transition interrupted before it can alter the data file.
        let guard = fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join(GUARD_FILE))
            .unwrap();
        guard.set_len(0).unwrap();
        guard.sync_all().unwrap();
        assert_eq!(read_raw(&dir), previous.value().to_string());

        let recovered = store.current().unwrap();

        assert_ne!(
            recovered, previous,
            "an unfinished transition reused its old authorization"
        );
        assert_eq!(store.current().unwrap(), recovered);
    }

    #[test]
    fn guard_symlink_is_rejected() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("attacker-target");
        fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(GUARD_FILE)).unwrap();

        let store = store_in(&dir);
        assert!(store.current().is_err());
        assert!(store.advance().is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    }

    #[test]
    fn data_symlink_fails_current_and_rotates_on_advance() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("attacker-target");
        fs::write(&target, "123").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join(DATA_FILE)).unwrap();

        let store = store_in(&dir);
        assert_eq!(
            store.current().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let rotated = store.advance().unwrap();
        assert!(!dir.path().join(DATA_FILE).is_symlink());
        assert_eq!(store.current().unwrap(), rotated);
        assert_eq!(fs::read_to_string(&target).unwrap(), "123");
    }
}
