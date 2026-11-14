# ADR 0033: Overlay Cipher Mutation and Zero-Argv Edit Contract

## Status
Accepted

## Context
While `omawarden` already supports creating, editing, favoriting, and deleting **Login** and **Secure Note** ciphers from the terminal (ADR-0027, ADR-0032), and `omawarden-app` exposes cipher mutations through an in-process Rust bridge, the Quickshell QML **Overlay** (`OmarchyBitwarden.qml`) remained read-only for standard vault items.

Bringing cipher mutation to the **Overlay** introduced three architectural questions:
1. **Zero-Argv Secret Transport**: Unlike `omawarden-app`, the QML **Overlay** invokes `omawarden` as an external subprocess via `Quickshell.Io.Process`. While `omawarden vault create` already supported `--stdin` and `--from-json`, `omawarden vault edit <target>` only accepted CLI flags (`--password`, `--notes`, `--field`, `--hidden-field`) or interactive `$EDITOR` sessions. Passing secrets from QML via CLI flags would expose plaintext passwords, notes, and hidden custom fields in `/proc/<pid>/cmdline` (violating `docs/agents/security.md` Rule 11).
2. **Multi-URI and Custom Field Fidelity vs Partial Updates**: ADR-0032 added full daemon support for multiple **Login URIs** (`uris`, `clear_uris`) and typed **Custom Fields** (`fields`, `remove_fields`). An edit modal in the **Overlay** must preserve untouched attributes, preserve read-only `Linked (3)` fields, and avoid overwriting fields the user did not modify.
3. **Favorite & Delete Ergonomics in a Spotlight-Style Overlay**: Embedding `Favorite` inside the multi-field edit form forces a full form open/save cycle for a single boolean toggle, whereas destructive deletion requires a clear distinction between reversible soft-deletion (**Trash**) and permanent erasure.

## Decision

### 1. Symmetric Zero-Argv JSON Contract on `vault edit`
We extend `omawarden vault edit <target>` with `--stdin` and `--from-json <path>` (mutually exclusive with CLI field flags):
- The CLI reads a JSON object from `stdin` (or file), strips reserved envelope keys (`action`, `id`, `target`, `client`) and `null` entries, validates cipher-type constraints (rejecting login-only keys on **Secure Note** targets), and forwards a `cipher_update` request to the daemon.
- The QML **Overlay** executes all create, edit, and favorite mutations exclusively via `omawarden vault create --stdin --json` and `omawarden vault edit <id> --stdin --json` with `stdinEnabled: true`, ensuring zero plaintext secrets ever appear in `argv`.

### 2. Client-Side Dirty-Diff Calculation for Edits
`CipherFormModal.qml` computes a minimal dirty diff against the original `VaultItem` before submitting an edit:
- Only modified scalar fields (`name`, `username`, `password`, `notes`, `folder_id`) are included in the JSON payload.
- For **Login URIs**, if the edited URI list differs from the original list, the diff emits `uris: [...]` (when non-empty) or `clear_uris: true` (when all existing URIs were removed).
- For **Custom Fields**, `Linked (3)` fields are rendered read-only and excluded from mutation payloads so the daemon preserves them untouched. Editable fields (`Text = 0`, `Hidden = 1`, `Boolean = 2`) are diffed by name: deleted or renamed original field names are emitted in `remove_fields`, and added or modified fields are emitted in `fields`.
- If the resulting diff is empty, the modal closes without spawning a subprocess.

### 3. Direct Inspector Favorite Toggle & Two-Tier Delete Confirmation
- **Favorite Toggle**: Favoriting is decoupled from `CipherFormModal` and placed directly in the `ItemInspector.qml` header (and bound to `Ctrl+B` / **Action Palette**), using optimistic UI state updates backed by `omawarden vault edit <id> --stdin --json` with `{"favorite": <bool>}` and automatic rollback on failure.
- **Delete Confirmation (`CipherDeleteModal.qml`)**: Deletion defaults to soft-delete (`omawarden vault delete <id> --yes --json`, moving the cipher to **Trash**) and provides an explicit `"Delete permanently (skip Trash)"` toggle inside the modal that switches to danger styling and invokes `--permanent`.
- **Organization Read-Only Guard**: Edit, Delete, and Favorite controls remain visible on **Organization**-owned **Login** and **Secure Note** ciphers for layout consistency, but triggering them immediately surfaces `"Organization ciphers are read-only."` without opening a mutation modal.

## Consequences

### Positive
- **Strict Secret Locality**: Passwords, notes, and hidden custom fields never enter OS process arguments (`argv`) or temporary files during **Overlay** mutations.
- **Full ADR-0032 Parity**: Unlike earlier GUI specs that restricted edits to a single URI and read-only custom fields, the **Overlay** supports full multi-URI and typed custom field creation and editing.
- **Minimal Network & Daemon Traffic**: Unchanged edits become zero-cost no-ops, and partial edits transmit only modified fields while preserving `Linked` custom fields and unedited metadata.

### Negative / Trade-offs
- `CipherFormModal.qml` maintains client-side diffing logic for custom field renames/removals (`fields` + `remove_fields`) and URI clearing (`clear_uris`), requiring dedicated headless QML test coverage (`tests/tst_cipher_mutation.qml`).
