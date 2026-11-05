//! Fetch full snapshots without holding session locks, then conditionally publish.
use crate::api::{decrypt_sync_ciphers_with_context, ApiError, BitwardenApiClient, ClientContext};
use crate::vault::VaultManager;
use crate::vault_cache::{CacheCommitError, IndexUpdate};

fn snapshot_error(error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        "A cipher write is in progress. Please retry synchronization after it finishes.".into()
    } else {
        format!("Cannot read the vault cache: {error}")
    }
}

impl VaultManager {
    pub fn sync(&self) -> Result<usize, String> {
        self.sync_with_client(None)
    }

    pub fn sync_with_client(&self, context: Option<&ClientContext>) -> Result<usize, String> {
        let session = self.cache_session().map_err(|e| e.to_string())?;
        // An outstanding write may be waiting on the network. Fail promptly
        // here; the bounded refetch below handles completed cache changes.
        let account = self.storage_mgr.snapshot().map_err(snapshot_error)?.storage;
        let server = if account.server_url.is_empty() {
            &self.server_url
        } else {
            &account.server_url
        };
        let identity = account.credential_identity_url(self.identity_url.as_deref());
        let client = BitwardenApiClient::with_options(server, identity, context);
        let token = self
            .keyring_mgr
            .for_storage(&account, server)
            .access_token();
        let mut token = match token {
            Some(token) if !crate::auth::is_jwt_expired(&token) => token,
            _ => self.renew_for_account(&account, context, session.generation)?,
        };
        let mut renewed_after_rejection = false;
        // A stale snapshot is safe to discard, but repeated conflicts should
        // ask the caller to retry rather than creating an unbounded GET loop.
        for attempt in 0..2 {
            let (base, response) = loop {
                let base = {
                    let unlocked = self
                        .is_unlocked
                        .read()
                        .map_err(|_| CacheCommitError::Unavailable.to_string())?;
                    if *unlocked != session.unlocked || self.lock_generation() != session.generation
                    {
                        return Err(CacheCommitError::SessionChanged.to_string());
                    }
                    let base = self.storage_mgr.snapshot().map_err(snapshot_error)?;
                    if !base.storage.same_account(&account) {
                        return Err(CacheCommitError::SessionChanged.to_string());
                    }
                    base
                };
                match client.sync_vault(&token) {
                    Ok(response) => break (base, response),
                    Err(ApiError::HttpStatus(status, _))
                        if !renewed_after_rejection
                            && (status == reqwest::StatusCode::UNAUTHORIZED
                                || status == reqwest::StatusCode::FORBIDDEN) =>
                    {
                        renewed_after_rejection = true;
                        token = self.renew_for_account(&account, context, session.generation)?;
                        // Renewal may scrub legacy tokens and replace data.json:
                        // capture a new base *before* issuing the next GET.
                    }
                    Err(error) => return Err(format!("Sync failed: {error:?}")),
                }
            };
            let mut updated = base.storage.clone();
            updated.ciphers = response.ciphers;
            updated.folders = response.folders;
            updated.collections = response.collections;
            if let Some(orgs) = response
                .profile
                .as_ref()
                .and_then(|p| p.get("organizations"))
                .and_then(|v| v.as_array())
            {
                updated.organizations = orgs.clone();
            }
            updated.last_sync = Some(chrono::Utc::now().to_rfc3339());
            let count = updated.ciphers.len();
            let index = if session.unlocked {
                let key = self
                    .user_key
                    .read()
                    .map_err(|_| CacheCommitError::Unavailable.to_string())?;
                let key = key
                    .as_ref()
                    .ok_or_else(|| CacheCommitError::SessionChanged.to_string())?;
                IndexUpdate::Replace(decrypt_sync_ciphers_with_context(
                    &updated.ciphers,
                    &updated.folders,
                    &updated.organizations,
                    key,
                    updated.enc_private_key.as_deref(),
                ))
            } else {
                // Low-level callers may refresh ciphertext while locked. They
                // must never populate a plaintext index or unlock the vault.
                IndexUpdate::CiphertextOnly
            };
            match self.commit_cache(&base, updated, index, session) {
                Ok(()) => return Ok(count),
                Err(CacheCommitError::Conflict) if attempt == 0 => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Err(CacheCommitError::Conflict.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::SymmetricCryptoKey;
    use crate::keyring::KeyringManager;
    use crate::storage::{StorageManager, VaultStorage};
    use crate::vault::VaultManager;
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    struct RuntimeEnv(Option<std::ffi::OsString>);
    impl RuntimeEnv {
        fn new(dir: &std::path::Path) -> Self {
            let old = std::env::var_os("XDG_RUNTIME_DIR");
            std::env::set_var("XDG_RUNTIME_DIR", dir);
            Self(old)
        }
    }
    impl Drop for RuntimeEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }
    }

    fn fixture(dir: &std::path::Path) -> (Arc<VaultManager>, TcpListener) {
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        api.set_nonblocking(true).unwrap();
        let url = format!("http://{}", api.local_addr().unwrap());
        let keyring = dir.join("secret-tool");
        crate::write_test_executable(&keyring, "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\n*) exit 1;;\nesac\n");
        let storage_mgr = StorageManager::new(dir.join("data.json"));
        let master = crate::crypto::derive_master_key(
            "fixture@example.invalid",
            "fixture",
            crate::crypto::KdfType::Pbkdf2Sha256,
            100_000,
            None,
            None,
        )
        .unwrap();
        let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
            .encrypt(&[42; 64])
            .unwrap();
        storage_mgr
            .save(&VaultStorage {
                server_url: url.clone(),
                user_email: "fixture@example.invalid".into(),
                user_id: Some("user-id".into()),
                enc_user_key: Some(wrap),
                kdf_iterations: Some(100_000),
                ..Default::default()
            })
            .unwrap();
        let mgr = VaultManager::new(
            &url,
            Some(storage_mgr),
            Some(KeyringManager::new(keyring.to_str().unwrap())),
        );
        *mgr.is_unlocked.write().unwrap() = true;
        *mgr.user_key.write().unwrap() =
            Some(SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap());
        (Arc::new(mgr), api)
    }

    fn accept(api: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match api.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    return stream;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "missing API request");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    fn request(stream: &mut TcpStream) -> (String, Value) {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_owned();
        let mut size = 0;
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                size = value.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; size];
        reader.read_exact(&mut body).unwrap();
        (path, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn reply(stream: &mut TcpStream, body: Value) {
        let body = body.to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    }

    fn sync(
        mgr: &Arc<VaultManager>,
        api: &TcpListener,
    ) -> (JoinHandle<Result<usize, String>>, TcpStream) {
        let mgr = Arc::clone(mgr);
        let task = thread::spawn(move || mgr.sync());
        let mut stream = accept(api);
        assert_eq!(request(&mut stream).0, "/api/sync");
        (task, stream)
    }

    fn stale_sync_after_create(cache_receipt: bool) {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        let (task, mut old_sync) = sync(&mgr, &api);
        let writer = Arc::clone(&mgr);
        let create = thread::spawn(move || {
            writer.write_ssh_key(json!({
            "name":"new key", "private_key":"private", "public_key":"public", "fingerprint":"fingerprint"
        }), None).map_err(|e| e.response())
        });
        let mut post = accept(&api);
        let (path, mut cipher) = request(&mut post);
        assert_eq!(path, "/api/ciphers");
        cipher["id"] = json!("created");
        let mut receipt = cipher.clone();
        if !cache_receipt {
            receipt["name"] = Value::Null;
        }
        reply(&mut post, receipt);
        assert_eq!(
            create.join().unwrap().unwrap()["outcome"],
            if cache_receipt {
                "saved"
            } else {
                "saved_needs_sync"
            }
        );
        reply(&mut old_sync, json!({"ciphers":[]}));
        // The fixed implementation refetches once. The old one completes
        // immediately, allowing the data-loss assertion below to report it.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut refetched = false;
        while !task.is_finished() {
            match api.accept() {
                Ok((mut fresh, _)) => {
                    assert_eq!(request(&mut fresh).0, "/api/sync");
                    reply(&mut fresh, json!({"ciphers":[cipher]}));
                    assert!(!refetched, "sync must not refetch indefinitely");
                    refetched = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "sync did not finish");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        }
        assert!(task.join().unwrap().is_ok());
        assert_eq!(
            mgr.storage_mgr.load().ciphers.len(),
            1,
            "confirmed create lost from disk"
        );
        assert_eq!(mgr.decrypted_items.read().unwrap()[0].id, "created");
        assert!(refetched);
    }

    #[test]
    fn stale_sync_does_not_erase_a_confirmed_create() {
        stale_sync_after_create(true);
    }

    #[test]
    fn an_uncached_write_invalidates_sync_even_without_a_disk_change() {
        stale_sync_after_create(false);
    }

    fn cipher(id: &str) -> Value {
        let key = SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap();
        json!({"id": id, "type": 1, "name": key.encrypt_string(id).unwrap(), "login": {"password": key.encrypt_string("secret").unwrap()}})
    }

    fn seed(mgr: &VaultManager, ciphers: Vec<Value>) {
        let _account = mgr.storage_mgr.account_guard().unwrap();
        let mut storage = mgr.storage_mgr.load();
        storage.ciphers = ciphers;
        mgr.storage_mgr.save(&storage).unwrap();
        *mgr.decrypted_items.write().unwrap() = crate::api::decrypt_sync_ciphers(
            &storage.ciphers,
            mgr.user_key.read().unwrap().as_ref().unwrap(),
        );
        *mgr.storage.write().unwrap() = storage;
    }

    #[test]
    fn out_of_order_sync_refetches_without_rolling_back_the_newer_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        let (old, mut old_stream) = sync(&mgr, &api);
        let (new, mut new_stream) = sync(&mgr, &api);
        let latest = cipher("latest");
        reply(&mut new_stream, json!({"ciphers":[latest]}));
        assert_eq!(new.join().unwrap().unwrap(), 1);
        let stamp = mgr.storage_mgr.load().last_sync;
        reply(&mut old_stream, json!({"ciphers":[]}));
        let mut retry = accept(&api);
        assert_eq!(request(&mut retry).0, "/api/sync");
        assert_eq!(mgr.storage_mgr.load().ciphers[0]["id"], "latest");
        assert_eq!(mgr.decrypted_items.read().unwrap()[0].id, "latest");
        assert_eq!(mgr.storage_mgr.load().last_sync, stamp);
        reply(&mut retry, json!({"ciphers":[latest]}));
        assert_eq!(old.join().unwrap().unwrap(), 1);
    }

    #[test]
    fn two_conflicts_stop_without_advancing_last_sync() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        let (task, mut stream) = sync(&mgr, &api);
        seed(&mgr, vec![cipher("first")]);
        reply(&mut stream, json!({"ciphers":[]}));
        let mut retry = accept(&api);
        assert_eq!(request(&mut retry).0, "/api/sync");
        seed(&mgr, vec![cipher("second")]);
        reply(&mut retry, json!({"ciphers":[]}));
        let error = task.join().unwrap().unwrap_err();
        assert!(error.contains("retry"), "{error}");
        assert_eq!(mgr.storage_mgr.load().ciphers[0]["id"], "second");
        assert_eq!(mgr.decrypted_items.read().unwrap()[0].id, "second");
        assert!(mgr.storage_mgr.load().last_sync.is_none());
        assert_eq!(
            api.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn lock_cycles_and_account_changes_cancel_late_syncs() {
        for action in [
            "lock",
            "lock-cycle",
            "logout",
            "server",
            "account",
            "remove",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (mgr, api) = fixture(dir.path());
            let (task, mut stream) = sync(&mgr, &api);
            match action {
                "lock" => mgr.lock(),
                "lock-cycle" => {
                    mgr.lock();
                    mgr.unlock("fixture").unwrap();
                }
                "logout" => {
                    mgr.lock();
                    let _account = mgr.storage_mgr.account_guard().unwrap();
                    mgr.storage_mgr.save(&VaultStorage::default()).unwrap();
                }
                "server" | "account" => {
                    let _account = mgr.storage_mgr.account_guard().unwrap();
                    let mut other = mgr.storage_mgr.load();
                    if action == "server" {
                        other.server_url = "https://other.invalid".into();
                    } else {
                        other.user_id = Some("other".into());
                    }
                    mgr.storage_mgr.save(&other).unwrap();
                }
                "remove" => {
                    let _account = mgr.storage_mgr.account_guard().unwrap();
                    std::fs::remove_file(&mgr.storage_mgr.file_path).unwrap();
                }
                _ => unreachable!(),
            }
            let before = std::fs::read(&mgr.storage_mgr.file_path).ok();
            reply(&mut stream, json!({"ciphers":[cipher("stale")]}));
            assert!(task.join().unwrap().is_err(), "{action}");
            assert_eq!(
                std::fs::read(&mgr.storage_mgr.file_path).ok(),
                before,
                "{action}"
            );
            assert!(mgr.decrypted_items.read().unwrap().is_empty(), "{action}");
            assert_eq!(
                api.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "{action}"
            );
        }
    }

    #[test]
    fn a_fresh_snapshot_applies_remote_deletions() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        seed(&mgr, vec![cipher("deleted-remotely")]);
        let (task, mut stream) = sync(&mgr, &api);
        reply(&mut stream, json!({"ciphers":[]}));
        assert_eq!(task.join().unwrap().unwrap(), 0);
        assert!(mgr.storage_mgr.load().ciphers.is_empty());
        assert!(mgr.decrypted_items.read().unwrap().is_empty());
        assert!(mgr.storage_mgr.load().last_sync.is_some());
    }

    #[test]
    fn incomplete_sync_response_preserves_cache_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        let (task, mut stream) = sync(&mgr, &api);
        reply(&mut stream, json!({"ciphers":[cipher("retained")]}));
        assert_eq!(task.join().unwrap().unwrap(), 1);
        let before = std::fs::read(&mgr.storage_mgr.file_path).unwrap();
        let last_sync = mgr.storage.read().unwrap().last_sync.clone();
        assert!(last_sync.is_some());

        for body in [
            json!({"error":"snapshot unavailable"}),
            json!([null, [], [], []]),
        ] {
            let (task, mut stream) = sync(&mgr, &api);
            reply(&mut stream, body);
            assert!(task.join().unwrap().is_err());
            assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
            assert_eq!(mgr.storage.read().unwrap().last_sync, last_sync);
            let items = mgr.decrypted_items.read().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].id, "retained");
        }
    }

    #[test]
    fn a_locked_sync_only_updates_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        mgr.lock();
        let (task, mut stream) = sync(&mgr, &api);
        reply(&mut stream, json!({"ciphers":[cipher("encrypted")]}));
        assert_eq!(task.join().unwrap().unwrap(), 1);
        assert_eq!(mgr.storage_mgr.load().ciphers.len(), 1);
        assert!(mgr.decrypted_items.read().unwrap().is_empty());
        assert!(!mgr.is_unlocked());
        assert!(mgr.user_key.read().unwrap().is_none());
    }

    #[test]
    fn corrupted_cache_is_not_replaced_or_treated_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        seed(&mgr, vec![cipher("retained")]);
        let (task, mut stream) = sync(&mgr, &api);
        std::fs::write(&mgr.storage_mgr.file_path, "broken").unwrap();
        reply(&mut stream, json!({"ciphers":[]}));
        assert!(task.join().unwrap().unwrap_err().contains("cache"));
        assert_eq!(
            std::fs::read_to_string(&mgr.storage_mgr.file_path).unwrap(),
            "broken"
        );
        assert_eq!(mgr.decrypted_items.read().unwrap()[0].id, "retained");
        assert!(mgr.sync().unwrap_err().contains("cache"));
        assert_eq!(
            api.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn failed_rename_preserves_disk_index_and_last_sync() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        seed(&mgr, vec![cipher("retained")]);
        let before = std::fs::read(&mgr.storage_mgr.file_path).unwrap();
        let (task, mut stream) = sync(&mgr, &api);
        let guard = mgr.storage_mgr.account_guard().unwrap();
        reply(&mut stream, json!({"ciphers":[]}));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let staged = std::fs::read_dir(dir.path())
                .unwrap()
                .map(Result::unwrap)
                .find(|e| e.file_name().to_string_lossy().starts_with(".tmp"));
            if let Some(staged) = staged {
                std::fs::remove_file(staged.path()).unwrap();
                break;
            }
            assert!(Instant::now() < deadline, "cache was not staged");
            thread::sleep(Duration::from_millis(5));
        }
        drop(guard);
        assert!(task.join().unwrap().unwrap_err().contains("commit"));
        assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
        assert_eq!(mgr.decrypted_items.read().unwrap()[0].id, "retained");
        assert!(mgr.storage.read().unwrap().last_sync.is_none());
    }

    #[test]
    fn login_initial_sync_cannot_overwrite_a_newer_cache() {
        let _environment = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _runtime = RuntimeEnv::new(dir.path());
        let (mgr, api) = fixture(dir.path());
        let auth = crate::auth::AuthManager::new(
            &mgr.server_url,
            Some(mgr.storage_mgr.clone()),
            Some(mgr.keyring_mgr.clone()),
        );
        let task = thread::spawn(move || auth.login_apikey("user.fixture", "secret"));
        let mut grant = accept(&api);
        assert_eq!(request(&mut grant).0, "/identity/connect/token");
        reply(&mut grant, json!({"access_token":"new", "expires_in":3600}));
        let mut initial = accept(&api);
        assert_eq!(request(&mut initial).0, "/api/sync");
        seed(&mgr, vec![cipher("newer")]);
        let before = std::fs::read(&mgr.storage_mgr.file_path).unwrap();
        reply(&mut initial, json!({"ciphers":[]}));
        let result = task.join().unwrap();
        assert!(!result.ok);
        assert!(result.error.unwrap().contains("changed during login"));
        assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
    }

    #[test]
    fn login_initial_sync_observes_an_uncached_write_from_another_manager() {
        let _environment = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _runtime = RuntimeEnv::new(dir.path());
        let (mgr, api) = fixture(dir.path());
        let auth = crate::auth::AuthManager::new(
            &mgr.server_url,
            Some(mgr.storage_mgr.clone()),
            Some(mgr.keyring_mgr.clone()),
        );
        let task = thread::spawn(move || auth.login_apikey("user.fixture", "secret"));
        let mut grant = accept(&api);
        assert_eq!(request(&mut grant).0, "/identity/connect/token");
        reply(&mut grant, json!({"access_token":"new", "expires_in":3600}));
        let mut initial = accept(&api);
        assert_eq!(request(&mut initial).0, "/api/sync");
        let before = std::fs::read(&mgr.storage_mgr.file_path).unwrap();
        let writer = Arc::clone(&mgr);
        let write = thread::spawn(move || {
            writer.write_ssh_key(json!({
            "name":"new key", "private_key":"private", "public_key":"public", "fingerprint":"fingerprint"
        }), None).map_err(|e| e.response())
        });
        let mut post = accept(&api);
        assert_eq!(request(&mut post).0, "/api/ciphers");
        reply(&mut post, json!({"id":"created"}));
        assert_eq!(
            write.join().unwrap().unwrap()["outcome"],
            "saved_needs_sync"
        );
        assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
        reply(&mut initial, json!({"ciphers":[]}));
        let result = task.join().unwrap();
        assert!(!result.ok);
        assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
    }

    #[test]
    fn outstanding_writes_block_sync_without_blocking_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, api) = fixture(dir.path());
        let pending = mgr.storage_mgr.begin_cipher_write().unwrap();
        let error = mgr.sync().unwrap_err();
        assert!(error.contains("retry"), "{error}");
        assert!(
            !error.contains("Cannot read"),
            "contention is not cache corruption: {error}"
        );
        mgr.lock();
        assert!(!mgr.is_unlocked());
        drop(pending);
        assert!(mgr.storage_mgr.snapshot().is_ok());
        assert_eq!(
            api.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn login_unlock_context_is_revoked_even_by_an_already_locked_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _) = fixture(dir.path());
        let before = mgr.unlock_context();
        mgr.lock();
        assert!(mgr.unlock_in_context("fixture", &before).is_err());
        let locked = mgr.unlock_context();
        mgr.lock();
        assert!(mgr.unlock_in_context("fixture", &locked).is_err());
        assert!(!mgr.is_unlocked());
        assert!(mgr.user_key.read().unwrap().is_none());
        assert!(mgr.decrypted_items.read().unwrap().is_empty());
        assert_eq!(mgr.unlock("fixture").unwrap(), 0);
    }

    fn failed_initial_sync_preserves_account(password_login: bool, status: &str, body: &str) {
        let _environment = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _runtime = RuntimeEnv::new(dir.path());
        let (mgr, api) = fixture(dir.path());
        seed(&mgr, vec![cipher("original-account-item")]);
        let before = std::fs::read(&mgr.storage_mgr.file_path).unwrap();
        let stores = dir.path().join("token-stores");
        crate::write_test_executable(
            &dir.path().join("secret-tool"),
            format!("#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\nstore*) /bin/cat >/dev/null; echo stored >> '{}'; exit 0;;\n*) exit 1;;\nesac\n", stores.display()),
        );
        let email = "other@example.invalid";
        let master = crate::crypto::derive_master_key(
            email,
            "fixture",
            crate::crypto::KdfType::Pbkdf2Sha256,
            100_000,
            None,
            None,
        )
        .unwrap();
        let other_wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
            .encrypt(&[43; 64])
            .unwrap();
        let auth = crate::auth::AuthManager::new(
            &mgr.server_url,
            Some(mgr.storage_mgr.clone()),
            Some(mgr.keyring_mgr.clone()),
        );
        let task = thread::spawn(move || {
            if password_login {
                auth.login_password(email, "fixture", None, None, None)
            } else {
                auth.login_apikey("user.other", "other-secret")
            }
        });
        if password_login {
            let mut prelogin = accept(&api);
            assert!(request(&mut prelogin).0.ends_with("/accounts/prelogin"));
            reply(&mut prelogin, json!({"kdf":0, "kdfIterations":100_000}));
        }
        let mut grant = accept(&api);
        assert_eq!(request(&mut grant).0, "/identity/connect/token");
        reply(
            &mut grant,
            json!({
                "access_token":"other-token", "refresh_token":"other-refresh", "expires_in":3600,
                "key":other_wrap, "kdf":0, "kdf_iterations":100_000
            }),
        );
        let mut initial = accept(&api);
        assert_eq!(request(&mut initial).0, "/api/sync");
        write!(initial, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let result = task.join().unwrap();
        assert!(
            !result.ok,
            "a failed initial sync cannot install another account"
        );
        assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
        assert!(
            !stores.exists(),
            "credentials must not change before initial sync succeeds"
        );
        assert_eq!(
            mgr.decrypted_items.read().unwrap()[0].id,
            "original-account-item"
        );
    }

    #[test]
    fn failed_password_login_initial_sync_preserves_the_previous_account() {
        failed_initial_sync_preserves_account(true, "500 Internal Server Error", "{}");
    }

    #[test]
    fn failed_apikey_login_initial_sync_preserves_the_previous_account() {
        failed_initial_sync_preserves_account(false, "500 Internal Server Error", "{}");
    }

    #[test]
    fn incomplete_sync_response_cannot_replace_account_during_password_login() {
        for body in ["{}", "[null, [], [], []]"] {
            failed_initial_sync_preserves_account(true, "200 OK", body);
        }
    }

    #[test]
    fn incomplete_sync_response_cannot_replace_account_during_apikey_login() {
        for body in ["{}", "[null, [], [], []]"] {
            failed_initial_sync_preserves_account(false, "200 OK", body);
        }
    }

    #[derive(PartialEq, Eq)]
    enum LoginPublication {
        KeyringFailure,
        RenameFailure,
        Committed,
    }

    fn login_candidate_slot(outcome: LoginPublication, replace_account: bool) {
        use crate::keyring::{KIND_ACCESS_TOKEN, KIND_API_SECRET, KIND_REFRESH_TOKEN};

        let _environment = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _runtime = RuntimeEnv::new(dir.path());
        let (mgr, api) = fixture(dir.path());
        let key_dir = dir.path().join("keys");
        std::fs::create_dir(&key_dir).unwrap();
        crate::write_test_executable(
            &dir.path().join("secret-tool"),
            format!(
                r#"#!/bin/sh
command=$1
shift
case "$1" in --label=*) shift;; esac
while [ "$#" -ge 2 ]; do
    case "$1" in
        service) service=$2;;
        account) account=$2;;
        credential_id) slot=$2;;
        kind) kind=$2;;
    esac
    shift 2
done
prefix="{}/$service.$account.$slot."
case "$command" in
    store)
        secret=$(/bin/cat)
        if [ "{}" = yes ] && [ "$secret" = other-refresh ]; then
            exit 1
        fi
        printf '%s' "$secret" > "$prefix$kind"
        ;;
    lookup) /bin/cat "$prefix$kind";;
    clear) if [ -n "$kind" ]; then /bin/rm -f "$prefix$kind"; else /bin/rm -f "$prefix"*; fi;;
    *) exit 1;;
esac
"#,
                key_dir.display(),
                if outcome == LoginPublication::KeyringFailure {
                    "yes"
                } else {
                    "no"
                },
            ),
        );
        let mut original = mgr.storage_mgr.load();
        original.credential_id = Some(format!("{:032x}", 1));
        original.client_id = Some("user.fixture".into());
        mgr.storage_mgr.save(&original).unwrap();
        seed(&mgr, vec![cipher("original")]);
        let before = std::fs::read(&mgr.storage_mgr.file_path).unwrap();
        let original_keys = mgr.keyring_mgr.for_storage(&original, &mgr.server_url);
        assert!(original_keys.store_token(KIND_ACCESS_TOKEN, "original-access"));
        assert!(original_keys.store_token(KIND_REFRESH_TOKEN, "original-refresh"));
        assert!(original_keys.store_token(KIND_API_SECRET, "original-secret"));
        assert!(mgr
            .keyring_mgr
            .store_token(&mgr.server_url, KIND_ACCESS_TOKEN, "legacy-access"));
        let unused = VaultStorage {
            credential_id: Some(format!("{:032x}", 2)),
            access_token: Some("legacy-disk-token".into()),
            ..original.clone()
        };
        assert!(mgr
            .keyring_mgr
            .for_storage(&unused, &mgr.server_url)
            .access_token()
            .is_none());

        let mut auth = crate::auth::AuthManager::new(
            &mgr.server_url,
            Some(mgr.storage_mgr.clone()),
            Some(mgr.keyring_mgr.clone()),
        );
        if outcome == LoginPublication::RenameFailure {
            auth.before_login_persist = Some(|file| std::fs::remove_file(file.path()).unwrap());
        }
        let (user_id, email, client_id) = if replace_account {
            ("other-id", "other@example.invalid", "user.other")
        } else {
            ("user-id", "fixture@example.invalid", "user.fixture")
        };
        let task = thread::spawn(move || auth.login_apikey(client_id, "other-secret"));
        let mut grant = accept(&api);
        assert_eq!(request(&mut grant).0, "/identity/connect/token");
        reply(
            &mut grant,
            json!({
                "access_token":"other-access", "refresh_token":"other-refresh", "expires_in":3600,
                "key":original.enc_user_key
            }),
        );
        let mut initial = accept(&api);
        assert_eq!(request(&mut initial).0, "/api/sync");
        reply(
            &mut initial,
            json!({"ciphers":[], "profile":{"id":user_id, "email":email}}),
        );
        let result = task.join().unwrap();
        if outcome == LoginPublication::Committed {
            assert!(result.ok, "{:?}", result.error);
            let active = mgr.storage_mgr.load_existing().unwrap();
            assert_ne!(active.credential_id, original.credential_id);
            assert_eq!(active.user_id.as_deref(), Some(user_id));
            assert!(original_keys.access_token().is_none());
            assert!(original_keys.refresh_token().is_none());
            assert!(original_keys.api_secret().is_none());
            assert!(mgr.keyring_mgr.clear_all());
            let active_keys = mgr.keyring_mgr.for_storage(&active, &mgr.server_url);
            assert_eq!(active_keys.access_token().as_deref(), Some("other-access"));
            assert_eq!(
                active_keys.refresh_token().as_deref(),
                Some("other-refresh")
            );
            assert_eq!(active_keys.api_secret().as_deref(), Some("other-secret"));
        } else {
            assert!(!result.ok);
            let expected = if outcome == LoginPublication::KeyringFailure {
                "Failed to store refresh token in system keyring."
            } else {
                "Cannot save the account cache"
            };
            assert_eq!(result.error.as_deref(), Some(expected));
            assert_eq!(std::fs::read(&mgr.storage_mgr.file_path).unwrap(), before);
            assert_eq!(mgr.decrypted_items.read().unwrap()[0].id, "original");
            assert_eq!(
                original_keys.access_token().as_deref(),
                Some("original-access")
            );
            assert_eq!(
                original_keys.refresh_token().as_deref(),
                Some("original-refresh")
            );
            assert_eq!(
                original_keys.api_secret().as_deref(),
                Some("original-secret")
            );
            assert_eq!(std::fs::read_dir(key_dir).unwrap().count(), 4);
        }
    }

    #[test]
    fn login_keyring_failure_preserves_active_credentials() {
        login_candidate_slot(LoginPublication::KeyringFailure, true);
    }

    #[test]
    fn login_rename_failure_preserves_active_credentials() {
        for replace_account in [true, false] {
            login_candidate_slot(LoginPublication::RenameFailure, replace_account);
        }
    }

    #[test]
    fn login_publishes_the_new_slot_and_retires_the_old_one() {
        login_candidate_slot(LoginPublication::Committed, true);
    }

    #[test]
    fn successful_login_does_not_inherit_the_previous_profile_metadata() {
        let _environment = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _runtime = RuntimeEnv::new(dir.path());
        let (mgr, api) = fixture(dir.path());
        let mut original = mgr.storage_mgr.load();
        original.user_id = Some("old-user".into());
        original.organizations = vec![json!({"id":"old-organization"})];
        original.client_id = Some("user.old".into());
        mgr.storage_mgr.save(&original).unwrap();
        crate::write_test_executable(&dir.path().join("secret-tool"), "#!/bin/sh\nexit 0\n");
        let auth = crate::auth::AuthManager::new(
            &mgr.server_url,
            Some(mgr.storage_mgr.clone()),
            Some(mgr.keyring_mgr.clone()),
        );
        let task = thread::spawn(move || auth.login_apikey("user.other", "other-secret"));
        let mut grant = accept(&api);
        assert_eq!(request(&mut grant).0, "/identity/connect/token");
        reply(
            &mut grant,
            json!({"access_token":"other-token", "expires_in":3600, "key":original.enc_user_key}),
        );
        let mut initial = accept(&api);
        assert_eq!(request(&mut initial).0, "/api/sync");
        reply(
            &mut initial,
            json!({"ciphers":[],"profile":{"email":"other@example.invalid"}}),
        );
        assert!(task.join().unwrap().ok);
        let current = mgr.storage_mgr.load();
        assert_eq!(current.client_id.as_deref(), Some("user.other"));
        assert_eq!(current.user_email, "other@example.invalid");
        assert!(current.user_id.is_none());
        assert!(current.organizations.is_empty());
        assert!(current.ciphers.is_empty());
    }
}
