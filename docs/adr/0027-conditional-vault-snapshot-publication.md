# ADR 0027: Conditional Vault Snapshot Publication

## Status
Proposed

## Context
A full sync started before a cipher create can return an older snapshot after the
create succeeds. Publishing that response can erase the new item from both the
encrypted cache and the unlocked index. Password and quick unlock also prepare an
index from a cache snapshot; decryption may finish after a newer sync or login has
replaced that cache.

These invariants apply to all vault items and extend the daemon architecture in
[ADR 0003](0003-omawarden-rust-native-helper-and-daemon-architecture.md). SSH write
receipts and retry rules remain in
[ADR 0005](0005-ssh-key-management-lifecycle.md).

## Decision

1. **Capture before remote work or decryption.** Pin the open cache file and record
   its filesystem version. Holding the original inode open prevents inode reuse
   from making a stale snapshot look current. Malformed or unreadable caches are
   errors, not empty vaults.

2. **Coordinate writes across processes.** A cipher request holds a shared lock on
   `writes.lock` through HTTP and receipt processing. Before dispatch, it replaces
   a 16-byte random revision under the account guard. Remote snapshot capture and commit
   use a nonblocking exclusive lock and compare that revision. This invalidates
   older snapshots even when a confirmed receipt cannot update the cache. The
   marker contains no secrets and the OS releases its lock when a process exits.

3. **Validate and publish under a common lock order.** Prepare encrypted JSON and
   decrypted indexes outside the publication critical section. Final publication
   acquires `account_guard` before `restore_guard`, revalidates the cache version
   and session, then publishes. Cache commit retains its `is_unlocked` read guard
   through atomic file replacement and index publication. Password and quick
   unlock revalidate the pinned snapshot after decryption under both guards.
   Local unlock snapshots do not acquire the remote-write barrier: a pending
   request must not prevent a user from locking and re-unlocking the cache.
   Hard/soft lock hold `restore_guard` through the plaintext purge and need no
   account guard. HTTP and password derivation hold neither guard.

4. **Bound retries and preserve deletion semantics.** An outstanding cipher write
   can be waiting on the network, so sync fails promptly with a retry message,
   including before the first GET. A completed cache change invalidating a sync
   response allows one fresh GET; further conflicts fail without advancing
   `last_sync`. A fresh full snapshot remains authoritative, including remote
   deletions. Do not union local and remote item sets.

5. **Bind login to its starting session.** Both login modes start the daemon
   before capturing its unlock context. The CLI handles authentication and 2FA.
   Before the initial sync, the daemon pins the cache inode and write revision
   on a dedicated, time-limited login connection. The daemon returns a random
   attempt ID that also names the candidate credential slot. After a complete
   initial sync, the CLI stores credentials under that slot and writes a
   private encrypted snapshot. The activation request sends only the attempt ID.

   Runtime and cache instance locks serialize daemons that implement these
   locks. A live socket also prevents takeover in the same runtime directory.
   A legacy daemon in a different runtime directory must be stopped before
   upgrading a shared cache.

   The daemon opens the snapshot relative to its private directory and holds
   a lease while reading and publishing it. It validates the pinned cache and
   the original context under the account and restore guards. Rename publishes
   the new account. In the same session transition, the daemon advances the
   generation, wipes plaintext and quick-unlock retention, and installs the
   new account in the locked state. API Key login ends there. Password login
   may unlock using the context and credential reference from that activation.
   A later lock invalidates the context, even if the vault was already locked.

   The daemon confirms directory durability before retiring previous
   credentials. If durability cannot be confirmed, the new account stays
   locked and retirement stays pending. A missing activation reply is resolved
   by comparing the attempt ID with the active credential reference. A match
   confirms publication and permits removal of the encrypted candidate. It
   supplies no authorization to unlock. Other results remain unconfirmed,
   with the candidate retained for lease-based cleanup.

   On confirmed login, the overlay clears the previous account’s data and
   advances its vault revision. It stops the previous copy and attachment
   helpers and dismisses old SSH approvals. Replies from the previous revision
   cannot update the overlay. The daemon also denies pending SSH approvals
   when changing accounts.

   Overlay copies and attachment outputs carry the unlocked session's
   generation. The helper verifies it at publication under a runtime file
   lock shared with revocation. The detached clipboard holder retains the
   gate until the compositor confirms setup. Attachment HTTP and decryption
   run before acquiring the gate. Activation clears the clipboard and
   previews under the gate before renaming the new account, including on
   the path where the activation receipt is lost. A failed rename can leave
   the previous account active with these outputs cleared. Completed
   downloads are user-owned files.

6. **Keep command outcomes honest.** `vault sync` uses the daemon exclusively.
   Missing or malformed IPC replies report failure instead of starting a second
   CLI sync. Low-level callers may refresh ciphertext while locked, but cannot
   publish a plaintext index or unlock the vault.

7. **Require a scoped credential reference before unlocking.** Upgrade an existing cache
   with a fresh sign-in. Keep the legacy cache encrypted until the replacement
   is ready. Retire the legacy keyring entries after the new credential
   reference is durable. Retain cleanup records if the keyring cannot confirm
   deletion within the cleanup budget. A scoped cache can be unlocked offline
   with the master password. Remote operations resolve tokens independently.

## Consequences
- Long cipher requests can make sync ask the user to retry; they do not block
  hard/soft lock. A brief snapshot capture can similarly reject a concurrent
  create before dispatch.
- Cache replacement and plaintext publication share one validated commit point.
  A failed rename preserves the existing disk cache and index.
- Credential cleanup selects inactive slots under the account guard and erases
  them under their individual leases. Token renewal still uses the account
  guard during keyring updates. Revalidation after an in-place keyring write
  cannot undo an overwritten token.
- A fresh server response is authoritative. This is local ordering protection,
  not an offline merge protocol or a server consistency guarantee.

## Validation
[Publication tests](../../omawarden/src/vault_publication_tests.rs) pause between
preparation and publication to exercise newer syncs, account replacement, and
hard/soft lock. [Sync tests](../../omawarden/src/vault_sync.rs) cover out-of-order
responses, uncached receipts, bounded retries, remote deletion, and login failure.
[CLI tests](../../omawarden/tests/vault_sync_cli.rs) cover cold daemon login,
same-server and cross-server account changes, locks on both sides of
activation, and lost replies across daemon restart using isolated vaults.
