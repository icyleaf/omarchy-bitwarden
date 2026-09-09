# Security Handbook & Agent Constraints

This document defines the **mandatory security invariants, anti-patterns, and verification rules** for all agents and developers contributing to `omarchy-bitwarden` and the `omawarden` core engine.

These rules were distilled from real-world vulnerabilities and architectural pitfalls identified across authentication, token persistence, IPC, file permissions, downloader verification, and desktop lifecycle integration.

---

## The 9 Mandatory Security Principles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CORE SECURITY INVARIANTS                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Zero Disk Fallback        │ Bearer tokens & credentials NEVER hit disk   │
│ 2. Fail-Closed Downloaders   │ Checksum & integrity checks MUST NOT skip    │
│ 3. Active Session Watchdog   │ Never rely on passive desktop hooks          │
│ 4. RFC 6454 Same-Origin      │ Exact scheme+host+port match; NO prefix match│
│ 5. Atomic 0600 Permissions   │ Restrictive mode set at creation time        │
│ 6. IPC SO_PEERCRED Auth      │ Verify caller UID on all socket requests     │
│ 7. Memory Locking (mlock)    │ Page-aligned physical RAM lock & no coredump │
│ 8. Authenticated Encryption  │ Encrypt-then-MAC mandatory; no unauth cipher │
│ 9. Ephemeral Session Token   │ Same-user socket authorization & max watchdog│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Rule 1: Zero Disk Fallback & Fail-Closed Keyring Policy

**Principle**: Bearer tokens (access/refresh tokens), API client secrets, and master passwords MUST NEVER enter disk files, local caches, or plaintext storage—under ANY condition.

- ❌ **Anti-Pattern**:
  Writing access or refresh tokens into `data.json` or local configuration when the system keyring (FreeDesktop Secret Service / KWallet / KeePassXC) fails, is locked, or is unavailable.
- ✅ **Required Pattern**:
  Keyring operations are **fail-closed**. If the keyring store fails, the login or token renewal operation MUST fail immediately with an explicit error. Only zero-knowledge encrypted vault ciphertext is permitted on disk (`data.json`).
- 🧪 **Mandatory Verification**:
  Include a unit test with a simulated failing keyring backend asserting that:
  1. The login/refresh call returns `Err`.
  2. The local storage file does NOT contain `access_token` or `refresh_token` keys.

---

### Rule 2: Fail-Closed Integrity & Cryptographic Checksum Verification

**Principle**: All installers, downloaders, and update bootstrap scripts (`scripts/download-engine.sh`, `check-update.sh`) MUST cryptographically verify release artifacts before extracting or executing them.

- ❌ **Anti-Pattern**:
  - Skipping verification if a checksum file fails to download (404/network error) or is empty.
  - Parsing HTML error pages as checksum strings.
  - Reporting synthetic success (`verified: true`) when no actual verification was performed.
- ✅ **Required Pattern**:
  - Checksum downloads are **mandatory and fail-closed**: if the checksum cannot be fetched, contains non-hex text, or does not match the archive's SHA-256 hash, the script MUST immediately delete the download and exit with a non-zero code.
  - Report `verified: true` ONLY after `sha256sum -c` (or equivalent cryptographic validation) succeeds.
  - Support pinned version arguments to bypass dynamic feed resolution during automated testing or reproducible builds.
- 🧪 **Mandatory Verification**:
  Maintain automated tests covering:
  1. Checksum mismatch aborts without extraction.
  2. 404 / missing checksum aborts without extraction.
  3. Malformed/HTML checksum aborts without extraction.

---

### Rule 3: Active Host & Desktop Lifecycle Watchdog (No Passive Hook Reliance)

**Principle**: Never assume third-party desktop environments, compositors, or shells will execute arbitrary external hook directories (e.g. `~/.config/omarchy/hooks/system-lock.d/`).

- ❌ **Anti-Pattern**:
  Relying solely on a shell script dropped into a hook directory to lock the vault when the screen locks or the laptop sleeps. Modern desktop shells (like Quickshell in Omarchy) often manage session locking internally via Wayland protocols (`WlSessionLock`) without running external scripts.
- ✅ **Required Pattern**:
  The background daemon (`omawarden daemon`) MUST actively monitor session lifecycle via multiple independent mechanisms:
  1. **Compositor / Shell IPC**: Query native shell lock state (e.g., `omarchy-shell lock isLocked`).
  2. **Screen Locker Processes**: Check for active locker binaries (`hyprlock`, `swaylock`, `waylock`, `gtklock`) via `pgrep` and Linux `/proc/*/comm` fallback.
  3. **systemd-logind D-Bus**: Query `org.freedesktop.login1` for session `LockedHint` and manager `PreparingForSleep`.
  4. **Watchdog Loop**: Poll with an adaptive timer (e.g. every 2s when unlocked, sleeping 5s when locked to maintain zero idle overhead).
- 🧪 **Mandatory Verification**:
  Provide mockable detector interfaces (`check_screen_lock_with`) and verify that detection immediately locks the vault and purges in-memory decrypted items and attachment previews.

---

### Rule 4: Strict URL Origin Validation (RFC 6454)

**Principle**: Never use substring or prefix matching (`starts_with`) when checking whether a target URL is authorized to receive bearer tokens or authenticated API calls.

- ❌ **Anti-Pattern**:
  ```rust
  // VULNERABLE: allows https://vault.bitwarden.com.evil.com to steal tokens!
  if target_url.starts_with(&server_url) { ... }
  ```
- ✅ **Required Pattern**:
  Parse both URLs with a standard-compliant URL parser (`url::Url`) and verify exact matching on scheme, host, and port:
  ```rust
  pub fn is_same_origin(base: &str, target: &str) -> bool {
      let Ok(u1) = Url::parse(base) else { return false };
      let Ok(u2) = Url::parse(target) else { return false };
      u1.scheme() == u2.scheme() && u1.host() == u2.host() && u1.port_or_known_default() == u2.port_or_known_default()
  }
  ```
- 🧪 **Mandatory Verification**:
  Unit test must assert rejection on subdomain spoofing (`target.domain.com.attacker.com`), scheme downgrades (`https` vs `http`), and mismatched ports.

---

### Rule 5: Atomic Least-Privilege File Permissions (`0600` / `0700`)

**Principle**: Any file written to disk that contains decrypted vault items, cached attachments, SSH private keys, or credentials MUST be protected with `0600` (directories `0700`).

- ❌ **Anti-Pattern**:
  - Creating a file with default umask (`0644`), writing sensitive content, and only then calling `set_permissions(0600)`. This leaves a race window where other users on the system can read the file.
  - Setting `0600` only on previews but leaving regular downloads at default system permissions.
- ✅ **Required Pattern**:
  - Apply `0o600` permissions **atomically upon creation** using `OpenOptionsExt::mode(0o600)`.
  - Check return values on all permission changes; do not silently ignore permission errors (`let _ = ...`).
  - Purge temporary decrypted files (such as attachment previews) immediately upon vault lock or daemon exit.
- 🧪 **Mandatory Verification**:
  Unit test must read file metadata on all download/cache paths and assert `metadata.permissions().mode() & 0o777 == 0o600`.

---

### Rule 6: Local IPC Socket Authentication (`SO_PEERCRED`) & Memory Hygiene

**Principle**: Local Unix domain sockets connect processes under the operating system; they do not automatically guarantee that only the owner process is communicating or listening.

- ❌ **Anti-Pattern**:
  - Trusting any connection that reaches the socket file simply because the socket file mode is `0600` (e.g. in containerized, shared runtime, or misconfigured permission scenarios).
  - Clients blindly connecting to `/tmp/omawarden-{uid}.sock` or `XDG_RUNTIME_DIR` sockets without verifying that the socket and its parent directory are owned by current UID, free of symlinks, and that the listening server UID matches caller UID before transmitting plaintext credentials (such as master password on unlock).
- ✅ **Required Pattern**:
  - **Mutual Peer Verification**: Both server AND client perform peer credential verification. On connection accept, the server queries caller process credentials using `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` on Linux and ensures `ucred.uid == libc::getuid()`. Similarly, the client verifies the server process credentials immediately upon `connect()` before transmitting any request payload.
  - **Path & Directory Hardening**: Socket paths and parent runtime directories are validated with `symlink_metadata()` to reject symlinks and foreign ownership. Fallback runtime directories in `/tmp` must be created atomically as dedicated `0700` directories (`/tmp/omawarden-runtime-{uid}/`).
  - **Cryptographic Memory Hygiene**: Master keys, derived cryptographic keys, and master passwords in memory MUST implement `zeroize::Zeroize` and be scrubbed on lock.
  - **Threat Boundary Clarity**: Document clearly that processes running as the *same OS user* share access under the same UID; defense against same-user memory scraping requires OS sandboxing.
- 🧪 **Mandatory Verification**:
  Unit test must assert that `verify_peer_credentials` succeeds for valid socket pairs, rejects foreign/mismatched connections, and `validate_socket_path` rejects symlinks and foreign socket files.

---

### Rule 7: Physical Memory Locking (`mlock`) and Anti-Dump Protection (`prctl`)

**Principle**: Master keys and derived cryptographic keys resident in memory while the vault is unlocked MUST be locked to physical RAM to prevent Linux kernel swap paging to disk, and protected against user-space memory dumping and crash coredumps.

- ❌ **Anti-Pattern**:
  - Allocating master keys and `SymmetricCryptoKey` in raw un-locked heap buffers without page-aligned `mlock`.
  - Allowing `systemd-coredump` or `ptrace` to dump process memory containing active decrypted keys.
  - Naive `mlock` on arbitrary heap memory where unlocking one key inadvertently unlocks other adjacent keys sharing the same 4KB page.
- ✅ **Required Pattern**:
  - Allocate sensitive cryptographic keys (`LockedKey32`, `LockedKey64`) in dedicated, 4096-byte page-aligned memory (`Layout::from_size_align(4096, 4096)`).
  - Pin memory pages to physical RAM using `libc::mlock` upon allocation, and gracefully degrade with diagnostic logging if resource limits (`RLIMIT_MEMLOCK`) prevent locking.
  - Overwrite entire 4KB page with zeroes (`zeroize`) and call `libc::munlock` upon `Drop`.
  - Invoke `libc::prctl(libc::PR_SET_DUMPABLE, 0)` at process startup on Linux to disable ptrace attachment and suppress crash coredumps.
- 🧪 **Mandatory Verification**:
  Unit test must assert that `LockedKey32` allocations are 4096-byte page-aligned, independent copies occupy distinct memory addresses, and `disable_dumpable` returns `Ok`.

---

### Rule 8: Mandatory Authenticated Encryption & Zero Unauthenticated Ciphertext Fallback

**Principle**: All symmetric cryptographic operations (vault items, fields, attachments) MUST follow strict Authenticated Encryption (Encrypt-then-MAC via HMAC-SHA256). Silent fallback to unauthenticated ciphertexts or bypass on HMAC mismatch is strictly forbidden.

- ❌ **Anti-Pattern**:
  - Silently falling back to bare AES-CBC decryption without MAC when HMAC fails or when MAC is absent.
  - Allowing unauthenticated attachment blob decryption (e.g. raw IV+ciphertext or encType 0) where a malicious or compromised server could alter ciphertext bytes undetected.
  - Swallowing `MacMismatch` errors or returning partial unverified plaintexts.
- ✅ **Required Pattern**:
  - `decrypt_attachment_blob` MUST require `key.mac_key` and enforce HMAC-SHA256 validation over `IV + Ciphertext` before any decryption.
  - Any attachment payload failing HMAC validation or omitting cryptographic authentication MUST immediately return `Err(CryptoError)`.
  - Constant-time comparison (`subtle::ConstantTimeEq`) is mandatory for all MAC verifications.
- 🧪 **Mandatory Verification**:
  Unit tests must assert that:
  1. Tampered ciphertext with valid MAC returns `Err`.
  2. Corrupted MAC byte returns `Err`.
  3. Unauthenticated blobs (bare IV + ciphertext) return `Err`.
  4. Keys lacking `mac_key` fail immediately with `Err`.

---

### Rule 9: Ephemeral Session Token Authorization & Max Lifetime Watchdog for Local IPC Daemon

**Principle**: `SO_PEERCRED` establishes caller user identity (preventing cross-user attacks on multi-user systems), but does NOT protect against unauthorized processes running under the *same UID* from connecting to `/run/user/<uid>/omawarden.sock` and dumping decrypted secrets or executing privileged commands without user consent.

- ❌ **Anti-Pattern**:
  - Exposing an unrestricted "same-user zero-auth vault API" where any process running as the current UID can execute `{"action": "list"}` or `{"action": "search"}` to dump all decrypted passwords, TOTP seeds, cards, notes, and SSH keys.
  - Allowing unauthenticated connections (e.g. rogue scripts polling `ping` or `status`) to touch daemon activity, preventing idle auto-lock indefinitely.
  - Allowing unauthenticated processes to terminate the unlocked daemon via `{"action": "stop"}`.
  - Allowing indefinite vault unlock without an absolute maximum session lifetime limit.
- ✅ **Required Pattern**:
  - **Cryptographic Ephemeral Session Token**: Upon `unlock`, the daemon generates a cryptographically random, high-entropy 256-bit ephemeral session token (`session_token`) using `rand_core::OsRng` encoded in URL-safe base64.
  - **Privileged Action Protection**: All privileged operations (`list`, `search`, `get_item`, `get_ssh_key`, `get_attachment_key`, `ssh_key_create`, `sync`, `totp` with query, and `stop` when unlocked) strictly require a valid `session_token`.
  - **Constant-Time Verification**: Session token validation MUST use constant-time byte comparison (`subtle::ConstantTimeEq`).
  - **No Keep-Alive Leakage**: Unauthenticated requests (or requests failing token verification) are rejected immediately and MUST NOT touch activity; they cannot bypass idle auto-lock.
  - **Absolute Maximum Lifetime Watchdog**: Implement a hard ceiling (`max_session_lifetime`, default 12 hours) from `unlocked_at`. The daemon locks the vault when this limit elapses, regardless of continuous user activity.
  - **Safe Environment Passing**: Pass the session token to child processes via process environment (`QProcessEnvironment` in QML / `OMAWARDEN_SESSION` in CLI), NEVER via command-line arguments (which are readable via `/proc/<pid>/cmdline`).
  - **Immediate Zeroization**: The session token resides in `Zeroizing<String>` memory and is scrubbed immediately upon `lock`, `stop`, or timeout.
- 🧪 **Mandatory Verification**:
  Unit tests must assert that:
  1. Privileged actions (`list`, `search`, `get_item`, `get_ssh_key`, `get_attachment_key`, `sync`, `totp` with query, `stop`) without a session token or with an invalid token return `Unauthorized`.
  2. Unauthenticated requests do NOT touch activity.
  3. `lock()` clears the session token and invalidates subsequent privileged calls.
  4. `check_auto_lock()` triggers when `max_session_lifetime` is exceeded even if `last_activity` is recent.

---

## Agent Checklist Before Opening a PR

Before submitting any code changes touching authentication, crypto, networking, IPC, or storage:

```markdown
- [ ] No tokens, secrets, or master passwords are written to disk or logs.
- [ ] Keyring failures fail-closed (no fallback to plaintext files).
- [ ] All file writes with sensitive data enforce 0600 permissions atomically.
- [ ] All URLs sending Auth headers use exact RFC 6454 same-origin checks.
- [ ] Sockets enforce mutual peer UID (SO_PEERCRED) verification and validate paths/symlinks.
- [ ] Daemon privileged actions require ephemeral session token verified in constant time.
- [ ] Master keys and cryptographic keys use page-aligned physical memory locks (LockedKey32 / mlock).
- [ ] Symmetric decryption strictly requires and verifies HMAC-SHA256 (no unauthenticated fallback).
- [ ] Process anti-dump protection (PR_SET_DUMPABLE = 0) is active.
- [ ] Installers / downloaders enforce fail-closed checksum checks.
- [ ] Vault locks cleanly upon screen-lock, sleep, idle timeout, or max session lifetime.
- [ ] Sensitive memory structures implement Zeroize.
- [ ] cargo fmt --check, cargo clippy -- -D warnings, and full cargo test pass.
```
