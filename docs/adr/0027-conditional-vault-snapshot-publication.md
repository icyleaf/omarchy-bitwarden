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

5. **Bind login to its starting session.** Password login starts the daemon at the
   authentication entry point before capturing its unlock context. Later checks
   only observe that context; they do not restart a stopped daemon or sample a
   replacement context. Auto-unlock validates the expected context after the KDF
   under `restore_guard`. Initial login sync must succeed before replacing
   credentials or account storage; a new storage value is built from the new
   response rather than inheriting the previous account's metadata.

6. **Keep command outcomes honest.** `vault sync` uses the daemon exclusively.
   Missing or malformed IPC replies report failure instead of starting a second
   CLI sync. Low-level callers may refresh ciphertext while locked, but cannot
   publish a plaintext index or unlock the vault.

7. **Require scoped credentials before unlocking.** Upgrade an existing cache
   with a fresh sign-in. Keep the legacy cache encrypted until the replacement
   is ready. Retire the legacy keyring entries after the new credential
   reference is durable. Retain cleanup records if the keyring cannot confirm
   deletion within the cleanup budget.

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
lock-during-login cancellation, and lost IPC replies using isolated vaults.
