//! Durable, nonsecret markers for keyring slots and unpublished login attempts.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::keyring::KeyringManager;
use crate::storage::{StorageManager, VaultStorage};

const LEGACY: &str = "legacy";

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) struct CredentialSlot {
    marker: PathBuf,
    name: String,
    _lease: File,
}

impl CredentialSlot {
    pub(crate) fn erase(self, keyring: &KeyringManager) -> io::Result<()> {
        keyring.erase_credential_slot((self.name != LEGACY).then_some(&self.name))?;
        match fs::remove_file(&self.marker) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}

pub(crate) fn erase_retired(
    slots: Vec<CredentialSlot>,
    keyring: &KeyringManager,
) -> io::Result<()> {
    let mut result = Ok(());
    for slot in slots {
        if let Err(error) = slot.erase(keyring) {
            result = Err(error);
        }
    }
    result
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
            file.lock()?;
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

    /// Record the outgoing reference before changing the cache under account_guard.
    pub(crate) fn remember_credentials(
        &self,
        storage: &VaultStorage,
        erase_legacy: bool,
    ) -> io::Result<()> {
        if let Some(id) = &storage.credential_id {
            self.credential_marker(id, false)?;
        }
        if erase_legacy
            && (!storage.user_email.is_empty()
                || storage.client_id.is_some()
                || storage.enc_user_key.is_some()
                || storage.access_token.is_some()
                || storage.refresh_token.is_some()
                || self.credential_slots_dir().try_exists()?)
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
            let marker = entry.path();
            let lease = match OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&marker)
            {
                Ok(lease) => lease,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if !lease.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid credential marker",
                ));
            }
            match lease.try_lock() {
                Ok(()) => slots.push(CredentialSlot {
                    marker,
                    name,
                    _lease: lease,
                }),
                Err(fs::TryLockError::WouldBlock) => {}
                Err(fs::TryLockError::Error(error)) => return Err(error),
            }
        }
        Ok(slots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
