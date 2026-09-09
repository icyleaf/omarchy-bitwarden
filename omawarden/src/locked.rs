use std::alloc::{alloc, dealloc, Layout};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const PAGE_SIZE: usize = 4096;

static MLOCK_WARNED: AtomicBool = AtomicBool::new(false);

/// Page-aligned, mlocked memory container for sensitive cryptographic secrets.
///
/// Ensures:
/// 1. Page-aligned allocation (4096 bytes) to eliminate mlock/munlock cross-key race conditions.
/// 2. Physical RAM locking via `libc::mlock` to prevent swapping to disk.
/// 3. Secure zeroization (`Zeroize`) of the entire allocated page prior to deallocation.
/// 4. Disables debug printing of raw secret bytes.
pub struct LockedMemory<const N: usize> {
    ptr: NonNull<u8>,
    layout: Layout,
    is_locked: bool,
}

unsafe impl<const N: usize> Send for LockedMemory<N> {}
unsafe impl<const N: usize> Sync for LockedMemory<N> {}

pub type LockedKey32 = LockedMemory<32>;
pub type LockedKey64 = LockedMemory<64>;

impl<const N: usize> LockedMemory<N> {
    pub fn new_zeroed() -> Self {
        assert!(
            N <= PAGE_SIZE,
            "LockedMemory payload must fit in PAGE_SIZE ({PAGE_SIZE} bytes)"
        );
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)
            .expect("Invalid page layout for LockedMemory");
        let raw_ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(raw_ptr).expect("Memory allocation failed for LockedMemory");

        // Zero out the freshly allocated page
        unsafe {
            std::slice::from_raw_parts_mut(ptr.as_ptr(), PAGE_SIZE).zeroize();
        }

        let mut is_locked = false;
        #[cfg(unix)]
        {
            let ret = unsafe { libc::mlock(ptr.as_ptr() as *const libc::c_void, PAGE_SIZE) };
            if ret == 0 {
                is_locked = true;
            } else if !MLOCK_WARNED.swap(true, Ordering::Relaxed) {
                let err = std::io::Error::last_os_error();
                crate::log_warn!(
                    "omawarden:locked",
                    "mlock failed ({}); operating in unlocked memory fallback mode",
                    err
                );
            }
        }

        Self {
            ptr,
            layout,
            is_locked,
        }
    }

    pub fn from_array(arr: [u8; N]) -> Self {
        let mut mem = Self::new_zeroed();
        mem.as_mut_slice().copy_from_slice(&arr);
        mem
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != N {
            return None;
        }
        let mut mem = Self::new_zeroed();
        mem.as_mut_slice().copy_from_slice(slice);
        Some(mem)
    }

    pub fn as_array(&self) -> &[u8; N] {
        unsafe { &*(self.ptr.as_ptr() as *const [u8; N]) }
    }

    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        unsafe { &mut *(self.ptr.as_ptr() as *mut [u8; N]) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), N) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), N) }
    }

    pub fn is_locked(&self) -> bool {
        self.is_locked
    }
}

impl<const N: usize> Clone for LockedMemory<N> {
    fn clone(&self) -> Self {
        let mut new_mem = Self::new_zeroed();
        new_mem.as_mut_slice().copy_from_slice(self.as_slice());
        new_mem
    }
}

impl<const N: usize> Drop for LockedMemory<N> {
    fn drop(&mut self) {
        unsafe {
            // 1. Zero out the entire 4KB page
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size());
            slice.zeroize();

            // 2. Unlock memory page if mlock was active
            #[cfg(unix)]
            if self.is_locked {
                libc::munlock(self.ptr.as_ptr() as *const libc::c_void, self.layout.size());
            }

            // 3. Deallocate the page-aligned memory
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

impl<const N: usize> Deref for LockedMemory<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<const N: usize> DerefMut for LockedMemory<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<const N: usize> AsRef<[u8; N]> for LockedMemory<N> {
    fn as_ref(&self) -> &[u8; N] {
        self.as_array()
    }
}

impl<const N: usize> AsRef<[u8]> for LockedMemory<N> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> AsMut<[u8]> for LockedMemory<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl<const N: usize> Zeroize for LockedMemory<N> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<const N: usize> PartialEq for LockedMemory<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}

impl<const N: usize> Eq for LockedMemory<N> {}

impl<const N: usize> fmt::Debug for LockedMemory<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[LOCKED_SECRET; {} bytes]", N)
    }
}

/// Disables ptrace debugging attachment and core dump generation on Linux.
#[cfg(target_os = "linux")]
pub fn disable_dumpable() -> Result<(), std::io::Error> {
    const PR_SET_DUMPABLE: libc::c_int = 4;
    let ret = unsafe { libc::prctl(PR_SET_DUMPABLE, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn disable_dumpable() -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_memory_allocation_and_alignment() {
        let key = LockedKey32::new_zeroed();
        let addr = key.ptr.as_ptr() as usize;
        assert_eq!(
            addr % PAGE_SIZE,
            0,
            "Memory buffer must be page-aligned to {PAGE_SIZE} bytes"
        );
        assert_eq!(key.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn test_locked_memory_read_write_and_deref() {
        let mut key = LockedKey32::new_zeroed();
        key[0] = 0x42;
        key[31] = 0x99;
        assert_eq!(key[0], 0x42);
        assert_eq!(key[31], 0x99);
        assert_eq!(key.len(), 32);

        let from_arr = LockedKey32::from_array(*key.as_array());
        assert_eq!(key, from_arr);
    }

    #[test]
    fn test_locked_memory_clone_isolation() {
        let mut k1 = LockedKey32::new_zeroed();
        k1[0] = 0xAA;
        let mut k2 = k1.clone();
        assert_eq!(k1, k2);

        // Modifying k2 should not alter k1
        k2[0] = 0xBB;
        assert_ne!(k1, k2);
        assert_ne!(
            k1.ptr.as_ptr(),
            k2.ptr.as_ptr(),
            "Cloned keys must occupy independent memory pages"
        );
    }

    #[test]
    fn test_locked_memory_debug_formatting_does_not_leak_bytes() {
        let mut key = LockedKey32::new_zeroed();
        key.as_mut_slice()
            .copy_from_slice(b"super_secret_master_key_12345678");
        let debug_str = format!("{:?}", key);
        assert_eq!(debug_str, "[LOCKED_SECRET; 32 bytes]");
        assert!(!debug_str.contains("super_secret"));
    }

    #[test]
    fn test_locked_memory_from_slice() {
        let bytes = [7u8; 32];
        let key = LockedKey32::from_slice(&bytes).unwrap();
        assert_eq!(key.as_slice(), &bytes);

        assert!(LockedKey32::from_slice(&bytes[..16]).is_none());
        assert!(LockedKey32::from_slice(&[0u8; 64]).is_none());
    }

    #[test]
    fn test_disable_dumpable() {
        let res = disable_dumpable();
        assert!(res.is_ok(), "disable_dumpable should succeed on Linux");
    }
}
