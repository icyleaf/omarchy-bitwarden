# ADR 0009: Physical Memory Locking (mlock) and Anti-Dumping Protection for Cryptographic Secrets

## Status
Proposed

## Context

In password management engines like `omawarden`, cryptographic keys—specifically the derived Master Key, User Symmetric Encryption/MAC Keys (`SymmetricCryptoKey`), and Master Password hashes—are resident in process memory while the vault is unlocked.

Currently, `omawarden` utilizes the `zeroize` crate to overwrite memory buffers with zeroes upon deallocation (`Drop`). While effective against residual memory leakage upon clean deallocation, this mechanism does not protect against two critical OS-level threat vectors:

1. **Linux Kernel Swap Paging to Disk**:
   Under memory pressure, the Linux kernel virtual memory subsystem periodically flushes anonymous heap pages to disk swap partitions or swap files (`/swapfile`). Sensitive cryptographic keys held in ordinary heap memory (`Vec<u8>`, `[u8; 32]`) may be silently persisted onto persistent disk sectors in unencrypted plaintext, leaving residual keys extractable via physical disk forensics or after system reboot.

2. **Process Memory Dumping & Inspection**:
   - **Crash Coredumps**: If the daemon or CLI terminates abnormally (e.g. panic or fatal signal), `systemd-coredump` or the kernel core dumper writes the full virtual address space of the process to `/var/lib/systemd/coredump/` or the current directory, exposing master keys in plaintext.
   - **PTRACE / Debugger Attachment**: Other processes running under the same user ID (e.g. compromised browser extensions, unvetted user scripts) can attach via `ptrace(PTRACE_ATTACH, ...)` or read `/proc/$pid/mem` to extract decrypted keys from a running daemon.

Prior art in the Linux ecosystem (notably `rbw`, the unofficial Bitwarden CLI) implements memory locking via `mlock` and disables process tracing via `prctl(PR_SET_DUMPABLE, 0)`. However, naive implementation of `mlock` on small heap buffers suffers from page-sharing race hazards: because Linux `mlock`/`munlock` operates on 4KB memory page boundaries, unlocking one key buffer can prematurely unlock another key buffer allocated by `malloc` on the same page.

---

## Decision

We will implement a dedicated physical memory locking architecture and anti-dumping protections in `omawarden`:

### 1. Page-Aligned Secure Memory Container (`omawarden/src/locked.rs`)

We introduce a dedicated `LockedMemory<const N: usize>` (and ergonomic aliases `LockedKey32 = LockedMemory<32>`, `LockedKey64 = LockedMemory<64>`) with the following invariants:

- **Isolated Page Allocation**:
  Memory is allocated using `std::alloc::alloc` with `Layout::from_size_align(PAGE_SIZE, PAGE_SIZE)` (where `PAGE_SIZE = 4096` on x86_64/aarch64 Linux). Each sensitive key resides in its own isolated memory page, eliminating any possibility of page-sharing race conditions during `munlock`.
- **Physical Memory Lock (`mlock`)**:
  Upon allocation, invoke `libc::mlock(ptr as *const libc::c_void, PAGE_SIZE)` to lock the physical page into RAM and prevent kernel swap out to disk.
- **Graceful Fallback on Resource Limits**:
  If `mlock` returns `EPERM` or `ENOMEM` (e.g., inside restricted container environments or when `RLIMIT_MEMLOCK` is zero), log a one-time diagnostic warning and fall back gracefully to unlocked page memory without crashing. Memory sanitization (`zeroize`) remains fully active.
- **Guaranteed Cleanup on Drop**:
  On `Drop`, the container:
  1. Overwrites the active buffer and the entire 4KB page with zeroes using `zeroize::Zeroize`.
  2. Calls `libc::munlock(ptr as *const libc::c_void, PAGE_SIZE)`.
  3. Deallocates the page via `std::alloc::dealloc`.

```rust
pub struct LockedMemory<const N: usize> {
    ptr: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
    is_locked: bool,
}
```

### 2. Cryptographic Key Hardening (`omawarden/src/crypto.rs`)

Refactor `SymmetricCryptoKey` and key derivation functions to be backed by `LockedKey32`:

- `SymmetricCryptoKey`:
  ```rust
  #[derive(Clone)]
  pub struct SymmetricCryptoKey {
      pub enc_key: LockedKey32,
      pub mac_key: Option<LockedKey32>,
  }
  ```
- `derive_master_key`: Returns `Result<LockedKey32, CryptoError>`, guaranteeing that the raw derived master key is locked into RAM immediately upon creation.

### 3. State & Vault Management Protection (`vault.rs`, `daemon.rs`)

- In `VaultManager`:
  `pub user_key: RwLock<Option<SymmetricCryptoKey>>` holds the locked keys. While the vault is unlocked, all encryption/decryption operations reference locked memory pages that cannot be paged to swap.
- Upon `vault_mgr.lock()`:
  Setting `user_key = None` triggers immediate `Drop`, which zeroes out the memory page, calls `munlock`, and frees the page.

### 4. Process Anti-Tracing and Coredump Suppression

In `omawarden daemon` initialization and CLI startup:
- On Linux, invoke:
  ```rust
  #[cfg(target_os = "linux")]
  pub fn disable_dumpable() -> Result<(), std::io::Error> {
      let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
      if ret == 0 {
          Ok(())
      } else {
          Err(std::io::Error::last_os_error())
      }
  }
  ```
  This single call:
  - Disables `ptrace` attachment from non-root same-UID processes.
  - Disables Linux kernel and `systemd-coredump` core dumps upon process crash.
  - Prevents `/proc/$pid/mem` snooping.

---

## Consequences

### Positive
- **Immunity to Swap Leakage**: Master keys and user decryption keys are pinned to physical RAM and will never be flushed to swap files or partitions.
- **Zero Page Collisions**: Dedicated page alignment (`align: 4096`) guarantees that dropping one key will never prematurely unlock adjacent keys.
- **Anti-Forensics & Anti-Dump**: `PR_SET_DUMPABLE = 0` eliminates core dump leakage and blocks user-space memory scrapers.
- **Fail-Safe Portability**: Gracefully degrades in resource-constrained environments (containers/CI) where `mlock` is restricted, without breaking functionality.

### Trade-offs & Mitigations
- **Memory Footprint**: Each locked key occupies one 4KB page. In a typical running instance (1 master key, 1 user key with enc/mac, 1-2 organization keys), total locked memory is 16–24 KB, well below standard Linux `ulimit -l` limits (typically 8,192 KB).
