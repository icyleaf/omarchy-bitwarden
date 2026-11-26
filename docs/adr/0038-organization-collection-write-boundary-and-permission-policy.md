# ADR 0038: Organization & Collection Write Boundary and Fail-Closed Permission Policy

## Status

Accepted — supersedes ADR-0033 Section 3 (Organization Read-Only Guard) and ADR-0036 Section 4's blanket Organization read-only statement.

## Context

Under ADR-0033 and ADR-0036, Omawarden and the Quickshell **Overlay** blocked every mutation on **Organization**-owned **Ciphers** with a blanket `"Organization ciphers are read-only."` error. While safe as an initial guard, this prevented members of Bitwarden and Vaultwarden **Organizations** from pinning personal **Favorites** or **Folders** onto shared Ciphers, creating or editing shared credentials, transferring personal Ciphers into an Organization, reassigning **Collections**, or managing **Attachments** on writable Organization Ciphers.

Unlocking Organization writes introduces strict cryptographic and authorization boundaries audited against `bitwarden/server`, `bitwarden/clients`, `bitwarden/sdk-internal`, and `dani-garcia/vaultwarden` (Issues #420, #427):

1. **User-Scope vs Admin Console Boundary**: Standard vault clients operate exclusively on User-scope endpoints; Admin Console routes (`/ciphers/admin`, `/collections-admin`, Collection CRUD) carry distinct role semantics (`editAssignedCiphers`, `editAnyCollection`) and remain out of scope.
2. **Cryptographic Key Isolation**: Organization Ciphers must wrap and unwrap `cipher.key` strictly under the Organization's 64-byte symmetric key (`org_key`). Falling back to `user_key` on write corrupts shared Ciphers for all other Organization members. Furthermore, `encryptedFor` must always be the acting `userId` (never `organizationId`).
3. **Granular Permissions & Hidden Passwords**: Multi-Collection permissions (`readOnly`, `hidePasswords`, `manage`) aggregate to per-Cipher `edit`, `viewPassword`, `permissions.delete`, and `permissions.restore`. Allowing full content edits (`PUT /ciphers/{id}`) or Collection reassignment when `viewPassword == false` risks clobbering or leaking hidden secrets. Conversely, per-user Favorite and Folder updates (`PUT /ciphers/{id}/partial`) require read access only and succeed even when `edit == false`.

## Decision

### 1. User-Scope Organization Write Boundary
Unlock all six User-scope Organization mutations while keeping Admin Console routes strictly out of scope:
1. Per-user **Favorite** & **Folder** assignment on any readable Organization Cipher via `PUT /ciphers/{id}/partial`.
2. **Create** a Cipher directly in an Organization via `POST /ciphers/create` (requiring non-empty writable `collectionIds`; `omawarden ssh-key create|import` remains personal-only).
3. **Edit** writable Organization Ciphers (`edit && view_password`) via `PUT /ciphers/{id}` (metadata-only for Organization **SSH Keys**).
4. **Soft/Hard Delete & Restore** Organization Ciphers gated by `permissions.delete` (`can_delete`) and `permissions.restore` (`can_restore`), honoring Bitwarden's `LimitItemDeletion` policy alongside Vaultwarden.
5. **Share / Move** a personal Cipher into an Organization via `PUT /ciphers/{id}/share` (irreversible ownership transfer).
6. **Reassign Collections** on an Organization Cipher via `PUT /ciphers/{id}/collections_v2` (cross-compatible with Bitwarden and Vaultwarden, handling `unavailable: true` via atomic local cache eviction).

### 2. Fail-Closed Permission & Cryptographic Invariants
- **Fail-Closed Cache Defaults**: Persist `edit`, `view_password`, `can_delete`, and `can_restore` on `VaultItem` (default `true` for personal Ciphers; fail-closed `false` for Organization Ciphers whenever absent in cached JSON). Parse `readOnly` (default `true`), `hidePasswords` (default `true`), and `manage` (default `false`) on cached Collections.
- **`edit: true && view_password: false` Policy**: Fail closed and reject full content edits (`PUT /ciphers/{id}`), Attachment V2 mutations, and Collection reassignment with explicit permission errors, while continuing to permit per-user Favorite/Folder updates via `PUT /ciphers/{id}/partial`.
- **Strict Key Isolation**: Resolve Organization symmetric keys through a dedicated fail-closed `resolve_org_key` helper with zero `user_key` fallback. Always emit `encryptedFor = userId`, unwrap/wrap `cipher.key` strictly with `org_key` on Organization writes, and pass cached `organizations` and `enc_private_key` when re-decrypting cached Organization writes.
- **Attachment Safety on Share**: Permit sharing modern personal Ciphers carrying keyed Attachments (`attachment.key != null`) by re-wrapping `cipher.key` in place from `user_key` to `org_key`; fail closed on legacy unkeyed Attachments (`attachment.key == null`) and legacy no-`cipher.key` Ciphers carrying Attachments.

### 3. Daemon Protocol & Overlay UX (Superseding ADR-0033 Section 3)
- **Daemon Capabilities**: Remain on `CURRENT_SCHEMA_VERSION = 3` and advertise `"org_write"` in `ping.capabilities` (ADR-0037) with fail-closed client negotiation and standalone daemon auto-restart.
- **Permission-Aware Overlay Controls**: Replace ADR-0033 Section 3's blanket `"Organization ciphers are read-only."` guard with permission-aware controls:
  - Favorite (`Ctrl+B` / Inspector star) and Folder assignment work on all readable Organization Ciphers via `/partial` using Zero-Argv `--stdin --json`.
  - Edit (`Ctrl+E`), Delete (`Ctrl+D`), Attachments, and Collections remain visible in the **Inspector** for layout stability, render visually disabled when unauthorized, and surface specific actionable permission errors if invoked via shortcut or **Action Palette** (`Ctrl+K`).

## Consequences

### Positive
- Enables full User-scope Organization collaboration across Daemon, CLI, and Overlay without compromising zero-knowledge key isolation.
- Pre-upgrade local caches fail closed automatically until the next sync populates server permission flags.
- Per-user Favorite and Folder organization works seamlessly on read-only Organization Ciphers.

### Negative / Trade-offs
- Users with `"Can edit, except passwords"` (`edit: true, viewPassword: false`) cannot edit non-secret fields on those Ciphers from Omawarden until a dedicated hidden-field-preserving edit path is introduced.
