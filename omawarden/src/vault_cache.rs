//! Conditional publication of encrypted storage and the matching plaintext index.
use crate::storage::{CacheSnapshot, VaultStorage};
use crate::vault::{VaultItem, VaultManager};
use std::fmt;

#[derive(Clone, Copy)]
pub(crate) struct CacheSession {
    pub(crate) generation: u64,
    pub(crate) unlocked: bool,
}

pub(crate) enum IndexUpdate {
    Replace(Vec<VaultItem>),
    Upsert(Box<VaultItem>),
    CiphertextOnly,
}

#[derive(Debug)]
pub(crate) enum CacheCommitError {
    Conflict,
    SessionChanged,
    Unavailable,
    Io(std::io::Error),
}

impl fmt::Display for CacheCommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict => {
                f.write_str("Vault changed during sync. Please retry synchronization.")
            }
            Self::SessionChanged => {
                f.write_str("Vault session changed. Synchronization cancelled.")
            }
            Self::Unavailable => f.write_str("Vault state unavailable. Please restart the daemon."),
            Self::Io(e) => write!(f, "Cannot commit the vault cache: {e}"),
        }
    }
}

impl From<std::io::Error> for CacheCommitError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl VaultManager {
    pub(crate) fn cache_session(&self) -> Result<CacheSession, CacheCommitError> {
        let unlocked = self
            .is_unlocked
            .read()
            .map_err(|_| CacheCommitError::Unavailable)?;
        Ok(CacheSession {
            generation: self.lock_generation(),
            unlocked: *unlocked,
        })
    }

    pub(crate) fn commit_cache(
        &self,
        base: &CacheSnapshot,
        updated: VaultStorage,
        index: IndexUpdate,
        session: CacheSession,
    ) -> Result<(), CacheCommitError> {
        let staged = self.storage_mgr.stage(&updated)?;
        // Serializes publication with password/quick unlock and hard/soft lock.
        // No key, HTTP, or keyring work belongs in this critical section.
        let _account = self.storage_mgr.account_guard()?;
        let _restore = self
            .restore_guard
            .lock()
            .map_err(|_| CacheCommitError::Unavailable)?;
        let unlocked = self
            .is_unlocked
            .read()
            .map_err(|_| CacheCommitError::Unavailable)?;
        if *unlocked != session.unlocked || self.lock_generation() != session.generation {
            return Err(CacheCommitError::SessionChanged);
        }
        let mut current = self
            .storage
            .write()
            .map_err(|_| CacheCommitError::Unavailable)?;
        if !current.same_account(&base.storage) {
            return Err(CacheCommitError::SessionChanged);
        }
        if !base.is_current(&self.storage_mgr)? {
            return Err(CacheCommitError::Conflict);
        }
        #[cfg(test)]
        self.cache_validated.reach();
        let mut items = self
            .decrypted_items
            .write()
            .map_err(|_| CacheCommitError::Unavailable)?;
        staged
            .persist(&self.storage_mgr.file_path)
            .map_err(|e| e.error)?;
        match index {
            IndexUpdate::Replace(replacement) => *items = replacement,
            IndexUpdate::Upsert(item) => {
                items.retain(|cached| cached.id != item.id);
                items.push(*item);
            }
            IndexUpdate::CiphertextOnly => {}
        }
        *current = updated;
        Ok(())
    }
}
