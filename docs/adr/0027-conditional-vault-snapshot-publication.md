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

   Overlay copies, daemon-backed CLI copies and attachment outputs carry the
   generation that supplied the plaintext. An offline CLI copy captures the
   shared lock epoch before it reads the encrypted cache, then rechecks the
   credential slot and captured epoch under the account guard and output gate.
   The detached holder repeats those checks before it starts the clipboard
   provider and keeps the gate until clipboard setup completes, so a lock that
   lands during the master-password prompt or decryption cannot revive the
   copy. Attachment HTTP and decryption run outside the gate. Previews are
   stored by credential slot, item and attachment ID.

   The provider abstraction in ADR 0030 keeps these authorization checks in
   `ClipboardGuard`, before any provider writes. The holder accepts explicit
   provider/binary options and the legacy positional binary path, but a cache
   scope must include its captured epoch in either form. An explicit provider
   (including the mock provider) cannot bypass credential or epoch validation.

   Offline authorization and final publication separately verify the daemon's
   `shared_lock_epoch: true` ping capability. Clients require both wire
   compatibility and this capability. With no reachable daemon, both the
   runtime and cache owner leases must be available. The holder retains those
   leases through clipboard setup. A busy owner with an unreachable socket
   fails authorization. An epoch-unaware daemon requires an explicit upgrade
   before it can authorize offline copies.

   This cache-only clipboard path supports the default runtime socket paired
   with its configured cache. Embedded hosts using a custom socket require a
   client configured for that socket and remain outside this discovery path.
   A busy cache owner prevents absence fallback when the default socket is
   unreachable. Sampling releases its leases before password entry and
   decryption. The detached holder rechecks authority and retains newly
   acquired leases until clipboard
   setup is acknowledged.

   Hard and soft lock advance the persisted runtime lock epoch before output
   cleanup, so an expired copy is rejected even when clipboard or preview
   cleanup stays pending. `auth lock` and `auth logout` advance the epoch
   locally after a daemon confirms locking without a durable epoch, or after
   obtaining the owner leases and confirming the daemon is absent. An
   unconfirmed reply from a live or starting daemon reports failure. A daemon
   restart preserves a completed epoch. A graceful stop is a lock transition
   and advances it. Quick unlock preserves the epoch. The epoch file contains no
   secrets, is serialized across CLI and daemon processes, and readers fail
   closed on corrupt data; a lock transition with corrupt data rotates to a
   fresh epoch so an old authorization can never be reused.

   Lock transitions hold the output gate while advancing the epoch and
   clearing outputs when the gate is available. If acquiring the gate fails,
   the transition still attempts to advance the epoch under its independent
   guard and leaves output cleanup pending. Before staging a new epoch, the
   transition invalidates and syncs the previous record under the epoch guard.
   Failed writes and renames therefore leave readers with invalid state.
   A subsequent successful `omawarden auth lock` repairs that state. The guard
   inode remains stable and
   records publication completion in its length. An empty guard marks an
   unfinished transition. A readable old data record with that marker is
   advanced before another authorization is issued, including when migrating
   a guard from an older build.

   A daemon `lock` reply carries `lock_epoch` and `epoch_advanced` alongside
   `outputs_cleared`. A numeric epoch and `epoch_advanced: true` identify the
   durable transition. `null` and `epoch_advanced: false` report a locked vault
   whose new epoch could not be published. The CLI preserves confirmed lock
   success while exposing that independent outcome through `epoch_advanced`
   and an optional `warning`. `error` describes an unsuccessful operation.
   The overlay commits its locked state after a successful JSON receipt and
   normal process exit, and refreshes auth status after an unsuccessful lock.
   Direct IPC callers apply the same owner checks before a local fallback.
   The epoch associates a cleanup result with its transition for the
   pending-cleanup follow-up.

   The daemon and its helpers share the same validated runtime directory,
   configured clipboard provider and display session. A vault copy records a
   marker before setting the selection.
   The marker survives a daemon restart and is removed only after confirmed
   clipboard clearing. A headless runtime without a configured Wayland
   display, the default Wayland socket or a marker can sign in without a
   clipboard operation.

   Activation requires both preview deletion and applicable clipboard clearing
   to succeed under the gate before renaming the new cache. A cleanup failure
   rejects activation and preserves the previous account. A failed rename can
   leave the previous account active with outputs already cleared. Lock still
   revokes access when output cleanup fails. Logout can retry cleanup locally
   when the daemon is unavailable. Completed downloads are user-owned files.

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
[Clipboard tests](../../omawarden/tests/clipboard_cli.rs) cover stale offline
holders, lock fallback without a daemon, and the local logout transition.
