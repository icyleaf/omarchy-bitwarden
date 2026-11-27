use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use crate::credential_slots::CredentialSlot;

use super::provider::KeyringProvider;
use super::{SCOPED_SERVICE_NAME, SERVICE_NAME};

/// Low-level Keychain operations abstraction allowing `MacOsKeychainProvider`
/// to use native `Security.framework` FFI on macOS while remaining deterministically
/// testable on non-macOS CI hosts.
pub(crate) trait KeychainBackend: Send + Sync {
    fn is_available(&self) -> bool;
    fn upsert(&self, service: &str, account: &str, label: &str, secret: &[u8]) -> Result<(), i32>;
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, i32>;
    fn delete(&self, service: &str, account: Option<&str>) -> Result<(), i32>;
    fn has_any(&self, service: &str) -> Result<bool, i32>;
}

#[cfg(target_os = "macos")]
mod security_ffi {
    use std::ffi::{c_char, c_void};
    use std::ptr;

    use super::KeychainBackend;

    type CFTypeRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFMutableDictionaryRef = *mut c_void;
    type CFBooleanRef = *const c_void;
    type CFIndex = isize;
    type OSStatus = i32;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        static kCFBooleanTrue: CFBooleanRef;
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;

        fn CFRelease(cf: CFTypeRef);
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFStringRef;
        fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
        fn CFDataGetLength(the_data: CFDataRef) -> CFIndex;
        fn CFDataGetBytePtr(the_data: CFDataRef) -> *const u8;
        fn CFDictionaryCreateMutable(
            allocator: CFAllocatorRef,
            capacity: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFMutableDictionaryRef;
        fn CFDictionarySetValue(
            the_dict: CFMutableDictionaryRef,
            key: *const c_void,
            value: *const c_void,
        );
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecAttrLabel: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;

        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemUpdate(query: CFDictionaryRef, attributes_to_update: CFDictionaryRef)
            -> OSStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    }

    struct CfGuard(CFTypeRef);

    impl Drop for CfGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    unsafe fn cf_string(s: &str) -> Option<CfGuard> {
        let ptr = CFStringCreateWithBytes(
            kCFAllocatorDefault,
            s.as_ptr(),
            s.len() as CFIndex,
            K_CF_STRING_ENCODING_UTF8,
            0,
        );
        (!ptr.is_null()).then_some(CfGuard(ptr))
    }

    unsafe fn cf_data(bytes: &[u8]) -> Option<CfGuard> {
        let ptr = CFDataCreate(kCFAllocatorDefault, bytes.as_ptr(), bytes.len() as CFIndex);
        (!ptr.is_null()).then_some(CfGuard(ptr))
    }

    unsafe fn cf_dict() -> Option<CfGuard> {
        let ptr = CFDictionaryCreateMutable(
            kCFAllocatorDefault,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        );
        (!ptr.is_null()).then_some(CfGuard(ptr as CFTypeRef))
    }

    unsafe fn dict_set(dict: &CfGuard, key: CFStringRef, value: CFTypeRef) {
        CFDictionarySetValue(dict.0 as CFMutableDictionaryRef, key, value);
    }

    pub struct NativeMacOsKeychainBackend;

    impl KeychainBackend for NativeMacOsKeychainBackend {
        fn is_available(&self) -> bool {
            true
        }

        fn upsert(
            &self,
            service: &str,
            account: &str,
            label: &str,
            secret: &[u8],
        ) -> Result<(), i32> {
            unsafe {
                let svc = cf_string(service).ok_or(-1)?;
                let acc = cf_string(account).ok_or(-1)?;
                let lbl = cf_string(label).ok_or(-1)?;
                let data = cf_data(secret).ok_or(-1)?;

                let add_query = cf_dict().ok_or(-1)?;
                dict_set(&add_query, kSecClass, kSecClassGenericPassword);
                dict_set(&add_query, kSecAttrService, svc.0);
                dict_set(&add_query, kSecAttrAccount, acc.0);
                dict_set(&add_query, kSecAttrLabel, lbl.0);
                dict_set(&add_query, kSecValueData, data.0);

                let status = SecItemAdd(add_query.0, ptr::null_mut());
                if status == ERR_SEC_SUCCESS {
                    return Ok(());
                }
                if status != ERR_SEC_DUPLICATE_ITEM {
                    return Err(status);
                }

                let match_query = cf_dict().ok_or(-1)?;
                dict_set(&match_query, kSecClass, kSecClassGenericPassword);
                dict_set(&match_query, kSecAttrService, svc.0);
                dict_set(&match_query, kSecAttrAccount, acc.0);

                let update_attrs = cf_dict().ok_or(-1)?;
                dict_set(&update_attrs, kSecAttrLabel, lbl.0);
                dict_set(&update_attrs, kSecValueData, data.0);

                let update_status = SecItemUpdate(match_query.0, update_attrs.0);
                if update_status == ERR_SEC_SUCCESS {
                    Ok(())
                } else {
                    Err(update_status)
                }
            }
        }

        fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, i32> {
            unsafe {
                let svc = cf_string(service).ok_or(-1)?;
                let acc = cf_string(account).ok_or(-1)?;

                let query = cf_dict().ok_or(-1)?;
                dict_set(&query, kSecClass, kSecClassGenericPassword);
                dict_set(&query, kSecAttrService, svc.0);
                dict_set(&query, kSecAttrAccount, acc.0);
                dict_set(&query, kSecReturnData, kCFBooleanTrue);
                dict_set(&query, kSecMatchLimit, kSecMatchLimitOne);

                let mut result: CFTypeRef = ptr::null();
                let status = SecItemCopyMatching(query.0, &mut result);
                if status == ERR_SEC_ITEM_NOT_FOUND {
                    return Ok(None);
                }
                if status != ERR_SEC_SUCCESS || result.is_null() {
                    return Err(status);
                }
                let _guard = CfGuard(result);
                let len = CFDataGetLength(result as CFDataRef);
                if len <= 0 {
                    return Ok(None);
                }
                let ptr = CFDataGetBytePtr(result as CFDataRef);
                if ptr.is_null() {
                    return Ok(None);
                }
                let slice = std::slice::from_raw_parts(ptr, len as usize);
                Ok(Some(slice.to_vec()))
            }
        }

        fn delete(&self, service: &str, account: Option<&str>) -> Result<(), i32> {
            unsafe {
                let svc = cf_string(service).ok_or(-1)?;
                let query = cf_dict().ok_or(-1)?;
                dict_set(&query, kSecClass, kSecClassGenericPassword);
                dict_set(&query, kSecAttrService, svc.0);
                let _acc_guard = if let Some(acc) = account {
                    let g = cf_string(acc).ok_or(-1)?;
                    dict_set(&query, kSecAttrAccount, g.0);
                    Some(g)
                } else {
                    None
                };

                // On macOS file-based keychains, `SecItemDelete` does not accept
                // `kSecMatchLimit` (returns errSecParam) and may remove one matching
                // item per call. Loop until `errSecItemNotFound` when erasing a slot.
                if account.is_some() {
                    let status = SecItemDelete(query.0);
                    if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
                        Ok(())
                    } else {
                        Err(status)
                    }
                } else {
                    loop {
                        let status = SecItemDelete(query.0);
                        match status {
                            ERR_SEC_SUCCESS => continue,
                            ERR_SEC_ITEM_NOT_FOUND => return Ok(()),
                            other => return Err(other),
                        }
                    }
                }
            }
        }

        fn has_any(&self, service: &str) -> Result<bool, i32> {
            unsafe {
                let svc = cf_string(service).ok_or(-1)?;
                let query = cf_dict().ok_or(-1)?;
                dict_set(&query, kSecClass, kSecClassGenericPassword);
                dict_set(&query, kSecAttrService, svc.0);
                dict_set(&query, kSecMatchLimit, kSecMatchLimitOne);

                let mut result: CFTypeRef = ptr::null();
                let status = SecItemCopyMatching(query.0, &mut result);
                let _guard = CfGuard(result);
                match status {
                    ERR_SEC_SUCCESS => Ok(true),
                    ERR_SEC_ITEM_NOT_FOUND => Ok(false),
                    other => Err(other),
                }
            }
        }
    }

    // Suppress unused import lint on non-FFI helpers.
    const _: *const c_char = ptr::null();
}

#[cfg(not(target_os = "macos"))]
mod security_ffi {
    use super::KeychainBackend;

    pub struct NativeMacOsKeychainBackend;

    impl KeychainBackend for NativeMacOsKeychainBackend {
        fn is_available(&self) -> bool {
            false
        }

        fn upsert(
            &self,
            _service: &str,
            _account: &str,
            _label: &str,
            _secret: &[u8],
        ) -> Result<(), i32> {
            Err(-1)
        }

        fn get(&self, _service: &str, _account: &str) -> Result<Option<Vec<u8>>, i32> {
            Err(-1)
        }

        fn delete(&self, _service: &str, _account: Option<&str>) -> Result<(), i32> {
            Err(-1)
        }

        fn has_any(&self, _service: &str) -> Result<bool, i32> {
            Err(-1)
        }
    }
}

/// macOS Keychain keyring provider backed by native `Security.framework` C FFI.
///
/// Maps multi-attribute credential keys deterministically onto `kSecClassGenericPassword`:
/// - `kSecAttrService`: `"omarchy-bitwarden-v2.<credential_id>"` for scoped v2 credentials,
///   or `"omarchy-bitwarden"` for legacy v1 entries.
/// - `kSecAttrAccount`: canonically sorted percent-encoded `key=value` pairs for all
///   remaining attributes, enabling O(1) lookup/upsert and atomic per-slot erasure.
#[derive(Clone)]
pub struct MacOsKeychainProvider {
    backend: Arc<dyn KeychainBackend>,
}

impl std::fmt::Debug for MacOsKeychainProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacOsKeychainProvider")
            .field("is_available", &self.backend.is_available())
            .finish()
    }
}

impl Default for MacOsKeychainProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsKeychainProvider {
    pub fn new() -> Self {
        Self {
            backend: Arc::new(security_ffi::NativeMacOsKeychainBackend),
        }
    }

    /// Constructs a `MacOsKeychainProvider` with an injected low-level Keychain backend
    /// (for deterministic cross-platform testing).
    #[cfg(test)]
    pub(crate) fn with_backend(backend: Arc<dyn KeychainBackend>) -> Self {
        Self { backend }
    }
}

/// Computes the deterministic `(kSecAttrService, Option<kSecAttrAccount>)` mapping for a
/// flat `[k1, v1, k2, v2, ...]` attribute slice.
///
/// Returns `None` if `attributes` is empty, has odd length, or lacks a non-empty `service`.
pub(crate) fn map_keychain_attributes(attributes: &[&str]) -> Option<(String, Option<String>)> {
    if attributes.is_empty() {
        return None;
    }
    let (pairs, remainder) = attributes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }

    let mut map: BTreeMap<&str, &str> = BTreeMap::new();
    for [k, v] in pairs {
        map.insert(*k, *v);
    }

    let raw_service = map.remove("service")?;
    if raw_service.is_empty() {
        return None;
    }

    let keychain_service = if let Some(cred_id) = map.remove("credential_id") {
        if cred_id.is_empty() {
            return None;
        }
        format!("{raw_service}.{cred_id}")
    } else {
        raw_service.to_string()
    };

    if map.is_empty() {
        return Some((keychain_service, None));
    }

    let account = map
        .into_iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    Some((keychain_service, Some(account)))
}

fn slot_service_name(credential_id: Option<&str>) -> String {
    match credential_id {
        Some(id) => format!("{SCOPED_SERVICE_NAME}.{id}"),
        None => SERVICE_NAME.to_string(),
    }
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{byte:02X}");
        }
    }
    out
}

impl KeyringProvider for MacOsKeychainProvider {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    fn unavailable_reason(&self) -> Option<String> {
        if self.is_available() {
            None
        } else {
            Some("macOS Keychain (Security.framework) is not available on this system.".to_string())
        }
    }

    fn store(
        &self,
        label: &str,
        attributes: &[&str],
        secret: &str,
        _lease: Option<&CredentialSlot>,
    ) -> bool {
        if secret.is_empty() || !self.backend.is_available() {
            return false;
        }
        let Some((service, Some(account))) = map_keychain_attributes(attributes) else {
            return false;
        };
        // Native Security.framework calls run synchronously in-process, so the caller's
        // stack frame holds the `CredentialSlot` file lock for the entire write duration.
        self.backend
            .upsert(&service, &account, label, secret.as_bytes())
            .is_ok()
    }

    fn lookup(&self, attributes: &[&str]) -> Option<String> {
        if !self.backend.is_available() {
            return None;
        }
        let (service, Some(account)) = map_keychain_attributes(attributes)? else {
            return None;
        };
        let bytes = self.backend.get(&service, &account).ok()??;
        let bytes = zeroize::Zeroizing::new(bytes);
        let secret = String::from_utf8_lossy(&bytes).trim().to_owned();
        (!secret.is_empty()).then_some(secret)
    }

    fn clear(&self, attributes: &[&str]) -> bool {
        if !self.backend.is_available() {
            return false;
        }
        let Some((service, account)) = map_keychain_attributes(attributes) else {
            return false;
        };
        self.backend.delete(&service, account.as_deref()).is_ok()
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
        if !self.backend.is_available() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                self.unavailable_reason().unwrap_or_default(),
            ));
        }
        let service = slot_service_name(credential_id);
        self.backend.delete(&service, None).map_err(|code| {
            io::Error::other(format!("Keychain delete failed (OSStatus {code})"))
        })?;
        let remaining = self.backend.has_any(&service).map_err(|code| {
            io::Error::other(format!("Keychain verification failed (OSStatus {code})"))
        })?;
        if remaining {
            return Err(io::Error::other("Could not confirm keyring cleanup"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::{KeyringManager, KIND_ACCESS_TOKEN, KIND_API_SECRET, KIND_REFRESH_TOKEN};
    use crate::storage::VaultStorage;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct InMemoryKeychainState {
        items: BTreeMap<(String, String), (String, Vec<u8>)>,
        available: bool,
        fail_delete: bool,
        simulate_residual_after_delete: bool,
    }

    struct InMemoryKeychainBackend {
        state: Mutex<InMemoryKeychainState>,
    }

    impl InMemoryKeychainBackend {
        fn new() -> Self {
            Self {
                state: Mutex::new(InMemoryKeychainState {
                    items: BTreeMap::new(),
                    available: true,
                    fail_delete: false,
                    simulate_residual_after_delete: false,
                }),
            }
        }

        fn set_fail_delete(&self, fail: bool) {
            self.state.lock().unwrap().fail_delete = fail;
        }

        fn set_simulate_residual_after_delete(&self, residual: bool) {
            self.state.lock().unwrap().simulate_residual_after_delete = residual;
        }

        fn services(&self) -> Vec<String> {
            self.state
                .lock()
                .unwrap()
                .items
                .keys()
                .map(|(svc, _)| svc.clone())
                .collect()
        }
    }

    impl KeychainBackend for InMemoryKeychainBackend {
        fn is_available(&self) -> bool {
            self.state.lock().unwrap().available
        }

        fn upsert(
            &self,
            service: &str,
            account: &str,
            label: &str,
            secret: &[u8],
        ) -> Result<(), i32> {
            let mut st = self.state.lock().unwrap();
            if !st.available {
                return Err(-25308);
            }
            st.items.insert(
                (service.to_string(), account.to_string()),
                (label.to_string(), secret.to_vec()),
            );
            Ok(())
        }

        fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, i32> {
            let st = self.state.lock().unwrap();
            if !st.available {
                return Err(-25308);
            }
            Ok(st
                .items
                .get(&(service.to_string(), account.to_string()))
                .map(|(_, secret)| secret.clone()))
        }

        fn delete(&self, service: &str, account: Option<&str>) -> Result<(), i32> {
            let mut st = self.state.lock().unwrap();
            if !st.available || st.fail_delete {
                return Err(-25308);
            }
            if let Some(acc) = account {
                st.items.remove(&(service.to_string(), acc.to_string()));
            } else {
                st.items.retain(|(svc, _), _| svc != service);
            }
            Ok(())
        }

        fn has_any(&self, service: &str) -> Result<bool, i32> {
            let st = self.state.lock().unwrap();
            if !st.available {
                return Err(-25308);
            }
            if st.simulate_residual_after_delete {
                return Ok(true);
            }
            Ok(st.items.keys().any(|(svc, _)| svc == service))
        }
    }

    #[test]
    fn test_keychain_attribute_mapping_bucketing_and_determinism() {
        let scoped = map_keychain_attributes(&[
            "service",
            SCOPED_SERVICE_NAME,
            "server_url",
            "https://vault.bitwarden.com",
            "account",
            "user-1",
            "credential_id",
            "11111111111111111111111111111111",
            "identity_url",
            "",
            "kind",
            KIND_ACCESS_TOKEN,
        ])
        .unwrap();
        assert_eq!(
            scoped.0,
            "omarchy-bitwarden-v2.11111111111111111111111111111111"
        );
        assert_eq!(
            scoped.1.as_deref(),
            Some("account=user-1&identity_url=&kind=access_token&server_url=https%3A%2F%2Fvault.bitwarden.com")
        );

        let legacy_all = map_keychain_attributes(&["service", SERVICE_NAME]).unwrap();
        assert_eq!(legacy_all, (SERVICE_NAME.to_string(), None));
    }

    #[test]
    fn test_macos_keychain_provider_lifecycle_upsert_and_isolation() {
        let backend = Arc::new(InMemoryKeychainBackend::new());
        let provider = Arc::new(MacOsKeychainProvider::with_backend(backend.clone()));
        let mgr = KeyringManager::with_provider(provider);

        assert!(mgr.is_available());
        assert_eq!(mgr.provider().name(), "macos");

        let server_a = "https://server-a.example";
        let server_b = "https://server-b.example";

        // Store and upsert (overwrite) token
        assert!(mgr.store_token(server_a, KIND_ACCESS_TOKEN, "tok_v1"));
        assert_eq!(
            mgr.get_token(server_a, KIND_ACCESS_TOKEN),
            Some("tok_v1".to_string())
        );
        assert!(mgr.store_token(server_a, KIND_ACCESS_TOKEN, "tok_v2"));
        assert_eq!(
            mgr.get_token(server_a, KIND_ACCESS_TOKEN),
            Some("tok_v2".to_string())
        );

        // Cross-server isolation
        assert!(mgr.store_token(server_b, KIND_ACCESS_TOKEN, "tok_b"));
        assert_eq!(
            mgr.get_token(server_a, KIND_ACCESS_TOKEN),
            Some("tok_v2".to_string())
        );
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("tok_b".to_string())
        );

        // Clear single token leaves other server intact
        assert!(mgr.clear_token(server_a, KIND_ACCESS_TOKEN));
        assert_eq!(mgr.get_token(server_a, KIND_ACCESS_TOKEN), None);
        assert_eq!(
            mgr.get_token(server_b, KIND_ACCESS_TOKEN),
            Some("tok_b".to_string())
        );

        // clear_all wipes legacy namespace
        assert!(mgr.clear_all());
        assert_eq!(mgr.get_token(server_b, KIND_ACCESS_TOKEN), None);
    }

    #[test]
    fn test_macos_keychain_provider_scoped_slot_atomic_erasure() {
        let backend = Arc::new(InMemoryKeychainBackend::new());
        let provider = Arc::new(MacOsKeychainProvider::with_backend(backend.clone()));
        let mgr = KeyringManager::with_provider(provider);

        let storage_a = VaultStorage {
            server_url: "https://vault.example.com".into(),
            user_email: "alice@example.com".into(),
            user_id: Some("uid-alice".into()),
            credential_id: Some("11111111111111111111111111111111".into()),
            client_id: Some("user.alice".into()),
            ..Default::default()
        };
        let storage_b = VaultStorage {
            server_url: "https://vault.example.com".into(),
            user_email: "bob@example.com".into(),
            user_id: Some("uid-bob".into()),
            credential_id: Some("22222222222222222222222222222222".into()),
            ..Default::default()
        };

        let slot_a = mgr.for_storage(&storage_a);
        let slot_b = mgr.for_storage(&storage_b);

        assert!(slot_a.store_token(KIND_ACCESS_TOKEN, "access_a"));
        assert!(slot_a.store_token(KIND_REFRESH_TOKEN, "refresh_a"));
        assert!(slot_a.store_token(KIND_API_SECRET, "secret_a"));
        assert!(slot_b.store_token(KIND_ACCESS_TOKEN, "access_b"));

        // Verify distinct Keychain service buckets
        let services = backend.services();
        assert!(services
            .iter()
            .any(|s| s == "omarchy-bitwarden-v2.11111111111111111111111111111111"));
        assert!(services
            .iter()
            .any(|s| s == "omarchy-bitwarden-v2.22222222222222222222222222222222"));

        // Failure during delete propagates error and retains slot
        backend.set_fail_delete(true);
        let err = mgr
            .erase_credential_slot(
                Some("11111111111111111111111111111111"),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
        assert!(err.to_string().contains("OSStatus"));
        assert_eq!(slot_a.access_token().as_deref(), Some("access_a"));

        // Successful erase removes all items in slot A while leaving slot B untouched
        backend.set_fail_delete(false);
        mgr.erase_credential_slot(
            Some("11111111111111111111111111111111"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(slot_a.access_token(), None);
        assert_eq!(slot_a.refresh_token(), None);
        // Residual item detected by follow-up has_any() fails closed
        backend.set_simulate_residual_after_delete(true);
        let residual_err = mgr
            .erase_credential_slot(
                Some("22222222222222222222222222222222"),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
        assert!(residual_err
            .to_string()
            .contains("Could not confirm keyring cleanup"));
        backend.set_simulate_residual_after_delete(false);

        // Legacy slot erasure (None) wipes only legacy SERVICE_NAME entries
        assert!(mgr.store_token("https://legacy.example", KIND_ACCESS_TOKEN, "legacy_tok"));
        assert!(slot_b.store_token(KIND_ACCESS_TOKEN, "access_b_2"));
        mgr.erase_credential_slot(None, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            mgr.get_token("https://legacy.example", KIND_ACCESS_TOKEN),
            None
        );
        assert_eq!(slot_b.access_token().as_deref(), Some("access_b_2"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_real_system_keychain_roundtrip() {
        let provider = Arc::new(MacOsKeychainProvider::new());
        let mgr = KeyringManager::with_provider(provider);
        assert!(mgr.is_available());

        let cred_id = format!(
            "{:032x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let storage = VaultStorage {
            server_url: "https://omawarden-test.invalid".into(),
            user_email: "test@omawarden-test.invalid".into(),
            user_id: Some("test-uid".into()),
            credential_id: Some(cred_id.clone()),
            ..Default::default()
        };

        let slot = mgr.for_storage(&storage);
        assert!(slot.store_token(KIND_ACCESS_TOKEN, "initial_mac_token"));
        assert_eq!(slot.access_token().as_deref(), Some("initial_mac_token"));

        // Upsert existing entry
        assert!(slot.store_token(KIND_ACCESS_TOKEN, "updated_mac_token"));
        assert_eq!(slot.access_token().as_deref(), Some("updated_mac_token"));

        // Erase slot and confirm zero residue
        mgr.erase_credential_slot(Some(&cred_id), Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(slot.access_token(), None);
    }
}
