//! Prepare a pinned cache version and publish an encrypted login snapshot over one connection.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::{json, Value};

use crate::daemon::{connect_daemon, DaemonState};
use crate::storage::StorageManager;

const REPLY_TIMEOUT: Duration = Duration::from_secs(15);
const PREPARATION_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_MESSAGE: u64 = 4096;
pub(crate) const SESSION_CHANGED: &str = "Vault session changed during login. Sign in again.";

pub(crate) struct LoginConnection {
    reader: BufReader<UnixStream>,
    pub(crate) attempt_id: String,
}

#[derive(Debug)]
pub(crate) enum ActivationError {
    Rejected(String),
    Unknown,
}

fn read_message(reader: &mut impl BufRead) -> io::Result<Value> {
    let mut line = String::new();
    let len = reader.take(MAX_MESSAGE + 1).read_line(&mut line)?;
    if len as u64 > MAX_MESSAGE || !line.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Incomplete login message",
        ));
    }
    Ok(serde_json::from_str(&line)?)
}

fn discard_published_candidate(storage: &StorageManager, id: &str) {
    if let Err(error) = storage.remove_candidate_snapshot(id) {
        crate::log_warn!(
            "omawarden:auth",
            "Cannot remove the published login snapshot. {error}"
        );
    }
}

impl LoginConnection {
    pub(crate) fn begin(expected_context: Option<&str>) -> Result<Self, String> {
        let unavailable = || "Cannot verify the daemon session before login.".to_string();
        let expected_context = expected_context.ok_or_else(unavailable)?;
        let mut stream = connect_daemon().map_err(|_| unavailable())?;
        stream
            .set_read_timeout(Some(REPLY_TIMEOUT))
            .map_err(|_| unavailable())?;
        stream
            .set_write_timeout(Some(REPLY_TIMEOUT))
            .map_err(|_| unavailable())?;
        writeln!(
            stream,
            "{}",
            json!({"action":"prepare_account_login","expected_unlock_context":expected_context})
        )
        .map_err(|_| unavailable())?;
        let mut reader = BufReader::new(stream);
        let response = read_message(&mut reader).map_err(|_| unavailable())?;
        if response["outcome"] == "rejected" {
            return Err(response["error"]
                .as_str()
                .map_or_else(unavailable, str::to_owned));
        }
        let attempt_id = response["attempt_id"]
            .as_str()
            .filter(|id| response["outcome"] == "ready" && crate::credential_slots::valid_id(id))
            .ok_or_else(unavailable)?
            .to_owned();
        Ok(Self { reader, attempt_id })
    }

    /// A reconciled receipt proves publication only. It cannot authorize a late unlock.
    pub(crate) fn activate(
        mut self,
        storage: &StorageManager,
    ) -> Result<Option<String>, ActivationError> {
        let request = json!({"action":"activate_account","attempt_id":self.attempt_id});
        let reply = writeln!(self.reader.get_mut(), "{request}")
            .and_then(|()| read_message(&mut self.reader));
        if let Ok(reply) = reply {
            if reply["attempt_id"] == self.attempt_id {
                match reply["outcome"].as_str() {
                    Some("committed") => {
                        return Ok(reply["unlock_context"].as_str().map(str::to_owned))
                    }
                    Some("rejected") => {
                        if let Some(error) = reply["error"].as_str() {
                            return Err(ActivationError::Rejected(error.to_owned()));
                        }
                    }
                    _ => {}
                }
            }
        }
        // data.json was atomically replaced. It is the receipt even across daemon restarts.
        if storage
            .load_existing()
            .is_ok_and(|current| current.scoped_credential_id() == Some(&self.attempt_id))
        {
            discard_published_candidate(storage, &self.attempt_id);
            return Ok(None);
        }
        Err(ActivationError::Unknown)
    }
}

pub(crate) fn serve(
    state: &DaemonState,
    stream: &mut UnixStream,
    reader: &mut impl BufRead,
    request: &Value,
) -> io::Result<()> {
    let vault = &state.vault_mgr;
    let expected = request["expected_unlock_context"].as_str().unwrap_or("");
    if vault.unlock_context() != expected {
        return writeln!(
            stream,
            "{}",
            json!({"outcome":"rejected","error":SESSION_CHANGED})
        );
    }
    let mut base = match vault.storage_mgr.snapshot() {
        Ok(base) => base,
        Err(error) => {
            return writeln!(
                stream,
                "{}",
                json!({"outcome":"rejected","error":format!("Cannot prepare account cache. {error}")})
            );
        }
    };
    if vault.unlock_context() != expected {
        return writeln!(
            stream,
            "{}",
            json!({"outcome":"rejected","error":SESSION_CHANGED})
        );
    }
    // Keep the inode, write revision and outgoing account metadata through
    // initial sync. The cached cipher payload is never used by the commit.
    base.storage.ciphers = Vec::new();
    base.storage.folders = Vec::new();
    base.storage.collections = Vec::new();
    base.storage.organizations = Vec::new();

    let id = format!("{:032x}", rand::random::<u128>());
    stream.set_read_timeout(Some(PREPARATION_TIMEOUT))?;
    stream.set_write_timeout(Some(REPLY_TIMEOUT))?;
    writeln!(stream, "{}", json!({"outcome":"ready","attempt_id":id}))?;
    let request = read_message(reader)?;
    let result = (|| {
        if request["action"] != "activate_account" || request["attempt_id"] != id {
            return Err("Invalid login attempt.".into());
        }
        if vault.unlock_context() != expected {
            return Err(SESSION_CHANGED.into());
        }
        let (_lease, candidate) = vault
            .storage_mgr
            .open_login_candidate(&id)
            .map_err(|_| "Cannot read the prepared login snapshot.")?;
        vault.activate_account(&base, candidate, expected, || {
            state.reset_session_timers();
            state.ssh_agent.cancel_pending();
        })
    })();
    let reply = match result {
        Ok(context) => {
            discard_published_candidate(&vault.storage_mgr, &id);
            json!({"outcome":"committed","attempt_id":id,"unlock_context":context})
        }
        Err(error) => json!({"outcome":"rejected","attempt_id":id,"error":error}),
    };
    writeln!(stream, "{reply}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::VaultStorage;
    use crate::test_support::TestDaemon;
    use crate::vault::VaultManager;
    use std::sync::Arc;

    #[test]
    fn concurrent_attempts_on_one_cache_can_activate_only_once() {
        let _environment = crate::env_lock();
        let root = tempfile::tempdir().unwrap();
        let storage = StorageManager::new(root.path().join("data.json"));
        let vault = Arc::new(VaultManager::new("", Some(storage.clone()), None));
        let _daemon = TestDaemon::start(Arc::clone(&vault));
        let context = vault.unlock_context();
        let first = LoginConnection::begin(Some(&context)).unwrap();
        let second = LoginConnection::begin(Some(&context)).unwrap();
        let first_id = first.attempt_id.clone();
        let second_id = second.attempt_id.clone();
        let leases: Vec<_> = [(&first_id, "first"), (&second_id, "second")]
            .into_iter()
            .map(|(id, account)| {
                let lease = storage.lease_candidate(id).unwrap();
                lease
                    .write_candidate(&VaultStorage {
                        server_url: "https://fixture.invalid".into(),
                        user_email: format!("{account}@fixture.invalid"),
                        credential_id: Some(id.clone()),
                        last_sync: Some("fixture".into()),
                        ..Default::default()
                    })
                    .unwrap();
                lease
            })
            .collect();
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| first.activate(&storage));
            let second = scope.spawn(|| second.activate(&storage));
            (first.join().unwrap(), second.join().unwrap())
        });
        let winner = match (first, second) {
            (Ok(Some(_)), Err(ActivationError::Rejected(_))) => first_id,
            (Err(ActivationError::Rejected(_)), Ok(Some(_))) => second_id,
            other => panic!("expected one activation, got {other:?}"),
        };
        assert_eq!(storage.load().credential_id, Some(winner));
        assert_eq!(
            vault.storage.read().unwrap().credential_id,
            storage.load().credential_id
        );
        assert!(!vault.is_unlocked());
        drop(leases);
    }
}
