//! Pause after decryption or validation, rather than relying on KDF timing.
use crate::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use crate::storage::{StorageManager, VaultStorage};
use crate::vault::VaultManager;
use crate::vault_cache::IndexUpdate;
use serde_json::json;
use std::sync::{Arc, TryLockError};
use std::thread;
use std::time::Duration;

fn fixture(dir: &std::path::Path) -> VaultManager {
    let email = "publication@example.invalid";
    let master =
        derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None).unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let manager = StorageManager::new(dir.join("data.json"));
    manager
        .save(&VaultStorage {
            server_url: "https://fixture.invalid".into(),
            user_email: email.into(),
            credential_id: Some(crate::test_support::CREDENTIAL_ID.into()),
            enc_user_key: Some(wrap),
            kdf_iterations: Some(100_000),
            ..Default::default()
        })
        .unwrap();
    VaultManager::new("", Some(manager), None)
}

fn publish_new_snapshot(vault: &VaultManager) {
    let base = vault.storage_mgr.snapshot().unwrap();
    let mut updated = base.storage.clone();
    let key = SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap();
    updated.ciphers = vec![json!({
        "id":"newer", "type":1, "name":key.encrypt_string("newer snapshot").unwrap()
    })];
    let index = if vault.is_unlocked() {
        IndexUpdate::Replace(crate::api::decrypt_sync_ciphers(&updated.ciphers, &key))
    } else {
        IndexUpdate::CiphertextOnly
    };
    vault
        .commit_cache(&base, updated, index, vault.cache_session().unwrap())
        .unwrap();
}

#[test]
fn password_unlock_cannot_replace_a_newer_published_snapshot() {
    let _environment = crate::env_lock();
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(fixture(dir.path()));
    vault.unlock("fixture").unwrap();
    let (entered, release) = vault.before_unlock_publication.arm();
    let unlocker = Arc::clone(&vault);
    let pending = thread::spawn(move || unlocker.unlock("fixture"));
    entered.recv_timeout(Duration::from_secs(30)).unwrap();
    publish_new_snapshot(&vault);
    release.send(()).unwrap();
    let result = pending.join().unwrap();
    assert!(
        result.is_err(),
        "an old unlock must not supersede a committed snapshot"
    );
    assert_eq!(vault.storage_mgr.load().ciphers[0]["id"], "newer");
    assert_eq!(vault.storage.read().unwrap().ciphers[0]["id"], "newer");
    assert_eq!(vault.decrypted_items.read().unwrap()[0].id, "newer");
}

#[test]
fn quick_unlock_cannot_replace_a_newer_ciphertext_snapshot() {
    let _environment = crate::env_lock();
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(fixture(dir.path()));
    vault.unlock("fixture").unwrap();
    assert!(vault.soft_lock());
    let (entered, release) = vault.before_unlock_publication.arm();
    let unlocker = Arc::clone(&vault);
    let pending = thread::spawn(move || unlocker.quick_unlock_restore());
    entered.recv_timeout(Duration::from_secs(30)).unwrap();
    publish_new_snapshot(&vault);
    release.send(()).unwrap();
    let result = pending.join().unwrap();
    assert!(
        result.is_err(),
        "an old quick unlock must not supersede a committed snapshot"
    );
    assert!(!vault.is_unlocked());
    assert!(vault.user_key.read().unwrap().is_none());
    assert!(vault.decrypted_items.read().unwrap().is_empty());
    assert_eq!(vault.storage.read().unwrap().ciphers[0]["id"], "newer");
    assert_eq!(vault.quick_unlock_restore().unwrap(), 1);
    assert_eq!(vault.decrypted_items.read().unwrap()[0].id, "newer");
}

#[test]
fn account_replacement_during_password_unlock_cannot_restore_the_old_account() {
    let _environment = crate::env_lock();
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(fixture(dir.path()));
    let (entered, release) = vault.before_unlock_publication.arm();
    let unlocker = Arc::clone(&vault);
    let pending = thread::spawn(move || unlocker.unlock("fixture"));
    entered.recv_timeout(Duration::from_secs(30)).unwrap();
    let mut other = vault.storage_mgr.load();
    other.user_email = "other@example.invalid".into();
    other.server_url = "https://other.invalid".into();
    {
        let _account = vault.storage_mgr.account_guard().unwrap();
        vault.storage_mgr.save(&other).unwrap();
    }
    release.send(()).unwrap();
    let result = pending.join().unwrap();
    assert!(
        result.is_err(),
        "an unlock prepared for another account must be discarded"
    );
    assert!(!vault.is_unlocked());
    assert!(vault.user_key.read().unwrap().is_none());
    assert!(vault.decrypted_items.read().unwrap().is_empty());
    assert_eq!(vault.storage_mgr.load().user_email, "other@example.invalid");
}

#[test]
fn cache_publication_serializes_with_hard_and_soft_lock() {
    let _environment = crate::env_lock();
    for soft in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(fixture(dir.path()));
        vault.unlock("fixture").unwrap();
        let (entered, release) = vault.cache_validated.arm();
        let publisher = Arc::clone(&vault);
        let pending = thread::spawn(move || publish_new_snapshot(&publisher));
        entered.recv_timeout(Duration::from_secs(30)).unwrap();
        // The read guard already excluded is_unlocked=false before this fix.
        let state_held = matches!(vault.is_unlocked.try_write(), Err(TryLockError::WouldBlock));
        let transition_held = matches!(
            vault.restore_guard.try_lock(),
            Err(TryLockError::WouldBlock)
        );
        let locker = Arc::clone(&vault);
        let locking = thread::spawn(move || {
            if soft {
                locker.soft_lock();
            } else {
                locker.lock();
            }
        });
        release.send(()).unwrap();
        pending.join().unwrap();
        locking.join().unwrap();
        assert!(state_held, "publication must retain its session read guard");
        assert!(
            transition_held,
            "publication and lock transitions must share the restore guard"
        );
        assert!(!vault.is_unlocked());
        assert!(vault.user_key.read().unwrap().is_none());
        assert!(vault.decrypted_items.read().unwrap().is_empty());
        assert_eq!(vault.storage_mgr.load().ciphers[0]["id"], "newer");
    }
}
