//! Durable, nonsecret markers for keyring slots and unpublished login attempts.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::keyring::KeyringManager;
use crate::storage::{StorageManager, VaultStorage};

const LEGACY: &str = "legacy";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CANDIDATE_SIZE: u64 = crate::api::MAX_SYNC_BODY_SIZE + crate::api::MAX_API_BODY_SIZE;

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) struct CredentialSlot {
    marker: PathBuf,
    name: String,
    _lease: File,
}

impl CredentialSlot {
    pub(crate) fn write_candidate(&self, storage: &VaultStorage) -> io::Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.marker.with_extension("candidate"))?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, storage)?;
        writer.flush()
    }

    /// Keep the slot leased if the writer outlives the parent process.
    /// The keyring writer must keep inherited descriptors open until it exits.
    pub(crate) fn inherit_in(&self, command: &mut Command) -> io::Result<()> {
        let lease = self._lease.try_clone()?;
        if lease.as_raw_fd() < 3 {
            return Err(io::Error::other(
                "Credential lease conflicts with child stdio",
            ));
        }
        // SAFETY: The closure owns the descriptor through spawn and calls
        // async-signal-safe fcntl on the child's copy of its flags.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(lease.as_raw_fd(), libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }

    fn erase(self, keyring: &KeyringManager, deadline: Instant) -> io::Result<()> {
        remove_if_exists(&self.marker.with_extension("candidate"))?;
        keyring.erase_credential_slot((self.name != LEGACY).then_some(&self.name), deadline)?;
        remove_if_exists(&self.marker)
    }
}

pub(crate) fn erase_retired(
    slots: impl IntoIterator<Item = CredentialSlot>,
    keyring: &KeyringManager,
) -> io::Result<()> {
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    let mut result = Ok(());
    for slot in slots {
        if let Err(error) = slot.erase(keyring, deadline) {
            if error.kind() == io::ErrorKind::TimedOut {
                return Err(error);
            }
            result = Err(error);
        }
    }
    result
}

fn remove_if_exists(path: &std::path::Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn open_private_file(dir: &File, name: &str) -> io::Result<File> {
    let name = CString::new(name)?;
    // SAFETY: dir and name are live for openat. A successful return owns a new fd.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new fd, now owned by File.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != dir.metadata()?.uid()
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid login file",
        ));
    }
    Ok(file)
}

#[derive(serde::Deserialize)]
struct CandidateSnapshot {
    ciphers: Vec<serde_json::Value>,
    folders: Vec<serde_json::Value>,
    collections: Vec<serde_json::Value>,
    #[serde(flatten)]
    storage: VaultStorage,
}

fn parse_candidate(file: File, id: &str) -> io::Result<VaultStorage> {
    let mut reader = BufReader::new(file.take(MAX_CANDIDATE_SIZE + 1));
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Invalid login snapshot");
    if reader.fill_buf()?.first() != Some(&b'{') {
        return Err(invalid());
    }
    let CandidateSnapshot {
        ciphers,
        folders,
        collections,
        mut storage,
    } = serde_json::from_reader(&mut reader)?;
    if reader.into_inner().limit() == 0
        || storage.scoped_credential_id() != Some(id)
        || storage.server_url.trim().is_empty()
        || storage.user_email.trim().is_empty()
        || storage.access_token.is_some()
        || storage.refresh_token.is_some()
        || storage.last_sync.is_none()
    {
        return Err(invalid());
    }
    storage.ciphers = ciphers;
    storage.folders = folders;
    storage.collections = collections;
    Ok(storage)
}

impl StorageManager {
    fn credential_slots_dir(&self) -> PathBuf {
        self.file_path.with_extension("credentials")
    }

    fn credential_marker(&self, name: &str, new: bool) -> io::Result<File> {
        if (new || name != LEGACY) && !valid_id(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid credential slot ID",
            ));
        }
        let dir = self.credential_slots_dir();
        crate::fs_util::create_secure_dir_all(&dir, 0o700)?;
        let file = OpenOptions::new()
            .write(true)
            .create(!new)
            .create_new(new)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join(name))?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid credential marker",
            ));
        }
        if new {
            file.lock_shared()?;
        }
        file.sync_all()?;
        File::open(dir)?.sync_all()?;
        self.sync_parent()?;
        Ok(file)
    }

    pub(crate) fn lease_candidate(&self, id: &str) -> io::Result<CredentialSlot> {
        let _account = self.account_guard()?;
        let lease = self.credential_marker(id, true)?;
        Ok(CredentialSlot {
            marker: self.credential_slots_dir().join(id),
            name: id.into(),
            _lease: lease,
        })
    }

    /// Pin the candidate slot while the daemon reads and publishes its snapshot.
    pub(crate) fn open_login_candidate(&self, id: &str) -> io::Result<(File, VaultStorage)> {
        if !valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid login attempt ID",
            ));
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(self.credential_slots_dir())?;
        let meta = dir.metadata()?;
        // SAFETY: geteuid has no pointer arguments.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unsafe login directory",
            ));
        }
        let lease = open_private_file(&dir, id)?;
        lease.try_lock_shared().map_err(io::Error::from)?;
        let file = open_private_file(&dir, &format!("{id}.candidate"))?;
        if file.metadata()?.len() > MAX_CANDIDATE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Login snapshot too large",
            ));
        }
        let storage = parse_candidate(file, id)?;
        Ok((lease, storage))
    }

    /// Reclaim an attempt known to have been rejected, after dropping the writer lease.
    pub(crate) fn rejected_candidate(&self, id: &str) -> io::Result<Option<CredentialSlot>> {
        let _account = self.account_guard()?;
        if self.cache_snapshot()?.storage.scoped_credential_id() == Some(id) {
            return Ok(None);
        }
        self.try_retired_slot(id)
    }

    pub(crate) fn remove_candidate_snapshot(&self, id: &str) -> io::Result<()> {
        remove_if_exists(
            &self
                .credential_slots_dir()
                .join(id)
                .with_extension("candidate"),
        )
    }

    fn try_retired_slot(&self, name: &str) -> io::Result<Option<CredentialSlot>> {
        let marker = self.credential_slots_dir().join(name);
        let lease = match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&marker)
        {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !lease.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid credential marker",
            ));
        }
        match lease.try_lock() {
            Ok(()) => Ok(Some(CredentialSlot {
                marker,
                name: name.into(),
                _lease: lease,
            })),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(error)) => Err(error),
        }
    }

    /// Record the outgoing reference before changing the cache under account_guard.
    pub(crate) fn remember_credentials(
        &self,
        storage: &VaultStorage,
        erase_legacy: bool,
    ) -> io::Result<()> {
        if let Some(id) = storage.scoped_credential_id() {
            self.credential_marker(id, false)?;
        }
        if erase_legacy
            && (storage.has_login_metadata() || self.credential_slots_dir().try_exists()?)
        {
            self.credential_marker(LEGACY, false)?;
        }
        Ok(())
    }

    /// Call under account_guard after replacing the cache with a synced file
    /// or removing it. Hold each inactive slot's lease through keyring cleanup.
    pub(crate) fn retired_credentials(
        &self,
        active_id: Option<&str>,
    ) -> io::Result<Vec<CredentialSlot>> {
        #[cfg(test)]
        if self.fail_credential_cleanup_sync {
            return Err(io::Error::other("Injected directory sync failure"));
        }
        self.sync_parent()?;
        let entries = match fs::read_dir(self.credential_slots_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut slots = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            if Some(name.as_str()) == active_id || (name != LEGACY && !valid_id(&name)) {
                continue;
            }
            if let Some(slot) = self.try_retired_slot(&name)? {
                slots.push(slot);
            }
        }
        Ok(slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_reads_only_a_complete_private_candidate_bound_to_the_attempt() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let manager = StorageManager::new(dir.path().join("data.json"));
        let id = crate::test_support::CREDENTIAL_ID;
        let lease = manager.lease_candidate(id).unwrap();
        let storage = VaultStorage {
            server_url: "https://fixture.invalid".into(),
            user_email: "account@fixture.invalid".into(),
            credential_id: Some(id.into()),
            last_sync: Some("fixture".into()),
            ..Default::default()
        };
        lease.write_candidate(&storage).unwrap();
        assert_eq!(
            manager.open_login_candidate(id).unwrap().1.credential_id,
            storage.credential_id
        );
        let path = lease.marker.with_extension("candidate");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(manager.open_login_candidate(id).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut incomplete = serde_json::to_value(&storage).unwrap();
        incomplete.as_object_mut().unwrap().remove("ciphers");
        fs::write(&path, incomplete.to_string()).unwrap();
        assert!(manager.open_login_candidate(id).is_err());
        let mut wrong = serde_json::to_value(&storage).unwrap();
        wrong["credential_id"] = serde_json::json!("22222222222222222222222222222222");
        fs::write(&path, wrong.to_string()).unwrap();
        assert!(manager.open_login_candidate(id).is_err());

        let other_file = dir.path().join("other-file");
        fs::rename(&path, &other_file).unwrap();
        fs::write(&other_file, serde_json::to_vec(&storage).unwrap()).unwrap();
        symlink(&other_file, &path).unwrap();
        assert!(manager.open_login_candidate(id).is_err());
    }

    #[test]
    fn cleanup_skips_the_active_reference_and_leased_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let manager = StorageManager::new(dir.path().join("data.json"));
        let active = "11111111111111111111111111111111";
        let running = "22222222222222222222222222222222";
        let abandoned = "33333333333333333333333333333333";
        drop(manager.lease_candidate(active).unwrap());
        let lease = manager.lease_candidate(running).unwrap();
        drop(manager.lease_candidate(abandoned).unwrap());

        let _account = manager.account_guard().unwrap();
        let slots = manager.retired_credentials(Some(active)).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].name, abandoned);

        drop(lease);
        let slots = manager.retired_credentials(Some(active)).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].name, running);
    }

    #[test]
    fn cleanup_continues_after_a_slot_cannot_be_erased() {
        let dir = tempfile::tempdir().unwrap();
        let manager = StorageManager::new(dir.path().join("data.json"));
        let locked_id = crate::test_support::CREDENTIAL_ID;
        let absent_id = "22222222222222222222222222222222";
        drop(manager.lease_candidate(locked_id).unwrap());
        drop(manager.lease_candidate(absent_id).unwrap());
        let locked = manager.rejected_candidate(locked_id).unwrap().unwrap();
        let absent = manager.rejected_candidate(absent_id).unwrap().unwrap();
        let locked_marker = locked.marker.clone();
        let absent_marker = absent.marker.clone();
        let secret_tool = dir.path().join("secret-tool");
        crate::write_test_executable(
            &secret_tool,
            format!(
                "#!/bin/sh\ncase \"$*\" in\nclear*) exit 1;;\nsearch*{}) echo present;;\nesac\n",
                locked.name
            ),
        );
        let keyring = KeyringManager::new(secret_tool.to_str().unwrap());
        assert!(erase_retired([locked, absent], &keyring).is_err());
        assert!(locked_marker.is_file());
        assert!(!absent_marker.exists());
    }

    #[test]
    fn cleanup_waits_for_a_keyring_child_after_the_parent_releases_its_lease() {
        use std::process::Stdio;

        let dir = tempfile::tempdir().unwrap();
        let manager = StorageManager::new(dir.path().join("data.json"));
        let id = crate::test_support::CREDENTIAL_ID;
        let lease = manager.lease_candidate(id).unwrap();
        let mut command = Command::new("/bin/cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        lease.inherit_in(&mut command).unwrap();
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(lease);

        let _account = manager.account_guard().unwrap();
        let while_running = manager.retired_credentials(None);
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        assert!(while_running.unwrap().is_empty());
        let slots = manager.retired_credentials(None).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].name, id);
    }
}
