use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::credential_slots::CredentialSlot;

use super::provider::KeyringProvider;
use super::{SCOPED_SERVICE_NAME, SERVICE_NAME};

type AttributeKey = BTreeMap<String, String>;

#[derive(Debug, Default, Clone)]
struct MockKeyringState {
    entries: BTreeMap<AttributeKey, String>,
    available: bool,
    fail_erase: bool,
}

/// Pure in-memory keyring provider for deterministic unit and integration tests.
#[derive(Debug, Clone)]
pub struct MockKeyringProvider {
    state: Arc<Mutex<MockKeyringState>>,
}

impl Default for MockKeyringProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockKeyringProvider {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockKeyringState {
                entries: BTreeMap::new(),
                available: true,
                fail_erase: false,
            })),
        }
    }

    pub fn set_available(&self, available: bool) {
        self.state.lock().unwrap().available = available;
    }

    pub fn set_fail_erase(&self, fail_erase: bool) {
        self.state.lock().unwrap().fail_erase = fail_erase;
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.lock().unwrap().entries.is_empty()
    }
}

fn parse_attributes(attributes: &[&str]) -> Option<AttributeKey> {
    if attributes.is_empty() {
        return None;
    }
    let (pairs, remainder) = attributes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut map = BTreeMap::new();
    for [k, v] in pairs {
        map.insert((*k).to_string(), (*v).to_string());
    }
    Some(map)
}

fn matches_filter(entry: &AttributeKey, filter: &AttributeKey) -> bool {
    filter
        .iter()
        .all(|(k, v)| entry.get(k).is_some_and(|ev| ev == v))
}

impl KeyringProvider for MockKeyringProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn is_available(&self) -> bool {
        self.state.lock().unwrap().available
    }

    fn store(
        &self,
        _label: &str,
        attributes: &[&str],
        secret: &str,
        _lease: Option<&CredentialSlot>,
    ) -> bool {
        if secret.is_empty() {
            return false;
        }
        let Some(key) = parse_attributes(attributes) else {
            return false;
        };
        let mut st = self.state.lock().unwrap();
        if !st.available {
            return false;
        }
        st.entries.insert(key, secret.to_string());
        true
    }

    fn lookup(&self, attributes: &[&str]) -> Option<String> {
        let key = parse_attributes(attributes)?;
        let st = self.state.lock().unwrap();
        if !st.available {
            return None;
        }
        st.entries.get(&key).filter(|v| !v.is_empty()).cloned()
    }

    fn clear(&self, attributes: &[&str]) -> bool {
        let Some(filter) = parse_attributes(attributes) else {
            return false;
        };
        let mut st = self.state.lock().unwrap();
        if !st.available {
            return false;
        }
        st.entries
            .retain(|entry_key, _| !matches_filter(entry_key, &filter));
        true
    }

    fn erase_credential_slot(
        &self,
        credential_id: Option<&str>,
        deadline: Instant,
    ) -> io::Result<()> {
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Keyring cleanup timed out",
            ));
        }
        let mut st = self.state.lock().unwrap();
        if !st.available || st.fail_erase {
            return Err(io::Error::other("Could not confirm keyring cleanup"));
        }
        let filter = if let Some(id) = credential_id {
            parse_attributes(&["service", SCOPED_SERVICE_NAME, "credential_id", id])
        } else {
            parse_attributes(&["service", SERVICE_NAME])
        }
        .expect("static attributes are even-length");
        st.entries
            .retain(|entry_key, _| !matches_filter(entry_key, &filter));
        Ok(())
    }
}
