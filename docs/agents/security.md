# Security Handbook & Agent Constraints

This document defines the **mandatory security invariants, anti-patterns, and verification rules** for all agents and developers contributing to `omarchy-bitwarden` and the `omawarden` core engine.

These rules were distilled from real-world vulnerabilities and architectural pitfalls identified across authentication, token persistence, IPC, file permissions, downloader verification, and desktop lifecycle integration.

---

## The 6 Mandatory Security Principles

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

**Principle**: Local Unix domain sockets connect processes under the operating system; they do not automatically guarantee that only the owner process is communicating.

- ❌ **Anti-Pattern**:
  Trusting any connection that reaches the socket file simply because the socket file mode is `0600` (e.g. in containerized, shared runtime, or misconfigured permission scenarios).
- ✅ **Required Pattern**:
  - **Socket Peer Verification**: On connection accept, query the peer process credentials using `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` on Linux and ensure `ucred.uid == libc::getuid()`. Reject foreign UIDs immediately before reading any input.
  - **Cryptographic Memory Hygiene**: Master keys, derived cryptographic keys, and master passwords in memory MUST implement `zeroize::Zeroize` and be scrubbed on lock.
  - **Threat Boundary Clarity**: Document clearly that processes running as the *same OS user* share access under the same UID; defense against same-user memory scraping requires OS sandboxing.
- 🧪 **Mandatory Verification**:
  Unit test must assert that `verify_peer_credentials` succeeds for valid socket pairs and rejects mismatched client connections.

---

## Agent Checklist Before Opening a PR

Before submitting any code changes touching authentication, crypto, networking, IPC, or storage:

```markdown
- [ ] No tokens, secrets, or master passwords are written to disk or logs.
- [ ] Keyring failures fail-closed (no fallback to plaintext files).
- [ ] All file writes with sensitive data enforce 0600 permissions atomically.
- [ ] All URLs sending Auth headers use exact RFC 6454 same-origin checks.
- [ ] Socket handlers verify peer UID (SO_PEERCRED) on connection.
- [ ] Installers / downloaders enforce fail-closed checksum checks.
- [ ] Vault locks cleanly upon screen-lock, sleep, or idle timeout.
- [ ] Sensitive memory structures implement Zeroize.
- [ ] cargo fmt --check, cargo clippy -- -D warnings, and full cargo test pass.
```
