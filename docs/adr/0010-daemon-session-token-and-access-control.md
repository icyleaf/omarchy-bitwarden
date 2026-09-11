# ADR 0010: Daemon Ephemeral Session Token and Access Control Architecture

## Status
Accepted

## Context

In `omarchy-bitwarden`, the background daemon (`omawarden daemon`) maintains decrypted vault items in physical memory (`LockedKey32` / `LockedKey64`) to provide sub-millisecond response times for search, auto-fill, clipboard copying, and TOTP generation across desktop workflows.

Communication between the UI (Quickshell frontend) or CLI and the daemon occurs over a local Unix domain socket (`/run/user/<uid>/omawarden.sock`). While mutual `SO_PEERCRED` verification (enforced in ADR 0003 and Security Rule 6) successfully isolates cross-user access on multi-user systems, it creates an unrestricted "same-user zero-auth vault API":

1. **Unrestricted Same-UID Decrypted Vault Extraction**:
   Any process executing under the same UID (for example, compromised user scripts, third-party desktop tools, unvetted electron applications, or malicious curl/bash snippets) could connect to `/run/user/<uid>/omawarden.sock` and issue `{"action": "list"}` or `{"action": "search"}` to dump all decrypted credentials, TOTP secrets, credit cards, secure notes, and SSH private keys without authenticating.

2. **Auto-Lock Evasion via Unauthenticated Keep-Alives**:
   A rogue local background loop could periodically send unauthenticated `ping` or `status` requests to the socket to prevent idle auto-lock indefinitely.

3. **Denial of Service via Unauthenticated Daemon Termination**:
   Any local process under the same UID could issue `{"action": "stop"}` while the vault was unlocked, killing the user's password manager process without authorization.

4. **Missing Upper Ceiling on Unlock Duration**:
   While idle inactivity timeouts locked the vault after periods of disuse, there was no absolute upper ceiling (`max_session_lifetime`). A workstation with continuous activity could remain perpetually unlocked for days or weeks.

---

## Decision

We introduce an **Ephemeral Session Token Authorization** and **Max Session Lifetime Watchdog** model for the `omawarden` daemon:

### 1. High-Entropy Ephemeral Session Token
- Upon successful `unlock` (via master password or quick PIN), the daemon generates a cryptographically random, 256-bit (32 bytes) token using OS entropy (`rand_core::OsRng`) encoded as URL-safe base64 without padding.
- The session token is wrapped in `Zeroizing<String>` in physical memory and associated with the daemon state.
- Upon `lock` (manual lock, idle timeout, screen lock, sleep, or max lifetime expiration) or daemon exit, the session token is scrubbed with zeroes and reset to `None`.

### 2. Privileged Action Enforcement
- Privileged operations strictly require a valid `session_token` in the request payload (`session_token` or `session` field):
  - `list` (vault item export/dump)
  - `search` (vault item search)
  - `get_item` (decrypted item retrieval)
  - `get_ssh_key` (SSH private/public key retrieval)
  - `get_attachment_key` (decryption key for encrypted attachments)
  - `ssh_key_create` (vault item modification)
  - `sync` (vault synchronization)
  - `totp` with item query (`query` or `id`)
  - `stop` when the vault is unlocked
- Non-privileged actions (which do not require token) include:
  - `ping` (health check)
  - `status` (lock status and version check)
  - `unlock` (authentication handshake)
  - `lock` (defensive action; any local process can defensively lock the vault)
  - `totp` with raw secret (stateless cryptographic utility)
  - `copy` (clipboard utility)
  - `set_auto_lock` (timeout configuration)

### 3. Constant-Time Verification & Fail-Closed Policy
- Token comparison is performed in constant time using `subtle::ConstantTimeEq` to eliminate timing side-channels.
- Requests failing session verification are rejected immediately with `{"ok": false, "error": "Unauthorized: valid session token required"}`.
- Unauthenticated or rejected requests **NEVER touch activity**, guaranteeing that rogue polling cannot prevent idle auto-locking.

### 4. Absolute Maximum Session Lifetime (`max_session_lifetime`)
- Alongside the idle inactivity timeout, the daemon tracks `unlocked_at: Instant`.
- An absolute maximum session lifetime (default 12 hours) is enforced in `check_auto_lock()`.
- When elapsed, the daemon locks the vault and purges all decrypted keys and session tokens, even if continuous user activity has kept the idle timer fresh.

### 5. Secure Token Propagation (Zero Process Argv Leaks)
- In the Quickshell UI (`OmarchyBitwarden.qml`), the session token received from the `unlock` response is retained in the root component state.
- When launching child `Process` blocks (`vaultSyncProc`, `vaultListProc`, `clipCopyProc`, `totpGenProc`, `attachmentProc`, `sshKeyActionProc`), the token is injected into the child process environment via `environment: ({ "OMAWARDEN_SESSION": root.sessionToken })`.
- This ensures tokens are strictly in-memory and **never passed via CLI command-line arguments**, preventing leakage to `/proc/<pid>/cmdline`.
- In `omawarden` CLI, commands read `OMAWARDEN_SESSION` or `BW_SESSION` from the environment and automatically inject it into daemon requests. Passing `--session` on CLI is explicitly forbidden under the Zero-Argv security policy.

---

## Consequences

### Positive
- **Complete Same-UID Isolation**: Rogue or unvetted scripts running as the same user can no longer dump decrypted vault items or steal credentials from the daemon.
- **Auto-Lock Invariant Guaranteed**: Unauthenticated requests cannot refresh the idle watchdog.
- **Hard Ceiling on Unlocked State**: 12-hour max lifetime enforces periodic re-authentication even on unattended systems with simulated mouse/keyboard activity.
- **Zero Disk or Argv Leakage**: Ephemeral tokens stay in process RAM and environment variables, never entering `argv` or disk, and are zeroized upon lock.

### Trade-offs & Operational Impact
- External shell scripts interacting with the daemon must export `OMAWARDEN_SESSION` upon `omawarden auth unlock` (e.g. `export OMAWARDEN_SESSION="..."`). CLI flags like `--session` are not permitted.
- The CLI outputs a shell export snippet (`export OMAWARDEN_SESSION="..."`) when `omawarden auth unlock` is run in an interactive terminal.

