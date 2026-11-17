# ADR 0034: Inspector-Embedded Cipher Form and Type Picker

## Status
Accepted

## Context
The Quickshell QML **Overlay** (`OmarchyBitwarden.qml`) historically used a centered modal (`CipherFormModal.qml`) for both creating and editing personal **Login** and **Secure Note** ciphers. While ADR-0033 introduced the zero-argv JSON contract for `vault edit`, the modal still covered the vault list and forced the user into a blocking dialog.

Issue #386 migrated **creation** to an Inspector-embedded form (`CipherEditor.qml`), rendering the draft in the right-hand column so the vault list stays visible. Issue #387 completes the migration by moving **edit** into the same component and retiring `CipherFormModal` entirely.

The existing `CipherFormModal` duplicated ~1,400 lines of form logic (field models, validation, dirty tracking, keyboard shortcuts, URI and custom field management) that `CipherEditor` already implemented for creation. Keeping both components in sync was a maintenance burden and a source of divergence.

## Decision

### 1. Single Component for Create and Edit
Extend `CipherEditor.qml` (introduced in #386) to support both `mode: "create" | "edit"`:
- **Create mode** (`cipherEditorEditItem === null`): pristine draft, dirty tracking counts any user input.
- **Edit mode** (`cipherEditorEditItem !== null`): pre-populated from `originalItem`, dirty tracking computes a **minimal dirty diff** against the original cipher. Unchanged fields are omitted from the payload.

The component exposes:
- `property string mode: "create"` — `"create"` or `"edit"`.
- `property var originalItem: null` — the `VaultItem` being edited (only in edit mode).
- `property var linkedFields: []` — read-only display of `Linked (type 3)` custom fields.
- `function buildEditPayload(trimmedName)` — returns a minimal JSON diff for `omawarden vault edit <id> --stdin --json`.

### 2. Zero-Argv Edit Contract Reuse
The edit payload uses the same zero-argv stdin JSON contract established in ADR-0033:
```bash
omawarden vault edit <id> --stdin --json
```
No secrets ever appear in `argv`. The diff excludes:
- `cipher_type` (immutable after creation).
- Unchanged scalars (`name`, `username`, `password`, `notes`, `folder_id`).
- Unchanged URI lists (emits `uris: [...]` or `clear_uris: true` only when modified).
- Unchanged custom fields (emits `fields` for upserts, `remove_fields` for deletions; `Linked` fields are never touched).

If the diff is empty, the editor returns to view mode without spawning a subprocess.

### 3. Inspector Integration
- `Ctrl+E` and the **Inspector Edit button** both call `openCipherEditModal(item)`, which:
  1. Sets `cipherEditorEditItem = item`
  2. Sets `cipherEditorType` from the item's `type_name`
  3. Sets `showCipherEditor = true`
- The `CipherEditor` component binds:
  - `mode: root.cipherEditorEditItem ? "edit" : "create"`
  - `originalItem: root.cipherEditorEditItem`
  - `onSubmitRequested` routes to `submitCipherEdit` in edit mode, `submitCipherCreate` in create mode.
- On success, `handleCipherEditSuccess` / `handleCipherCreateSuccess` clear `cipherEditorEditItem`, hide the editor, and reload the vault list with `pendingSelectItemId` to re-select the edited cipher.

### 4. CipherFormModal Retirement
- Delete `components/CipherFormModal.qml`.
- Remove its declaration from `components/qmldir`.
- Remove `showCipherFormModal` property and all references from `OmarchyBitwarden.qml`.
- Update `hasActiveModal` focus guard to include `showCipherEditor` instead of `showCipherFormModal`.
- Update all test files (`tst_cipher_mutation.qml`, `tst_modal_cards_theming.qml`, `tst_inspector_action_controls.qml`, `tst_modal_focus.qml`) to exercise `CipherEditor` edit mode and remove `CipherFormModal` assertions.

### 5. Type Picker Remains
The **Type Picker** (`Ctrl+N` → choose Login / Secure Note) introduced in #386 continues to route into `openCipherCreateModal`, which uses `CipherEditor` in create mode. No change to this flow.

## Consequences

### Positive
- **Single Source of Truth**: One component (`CipherEditor`) handles all personal cipher mutations. No logic drift between create and edit paths.
- **Minimal Diff Discipline**: Edit payloads are strictly dirty diffs; the daemon receives only what changed.
- **Inspector Stays Visible**: The vault list remains visible during edits, preserving context and enabling quick multi-item workflows.
- **Reduced Code Surface**: ~1,400 lines of duplicated modal code removed. Test coverage consolidated into `tst_cipher_mutation.qml`.
- **Keyboard Seam Unification**: `handleKey(key, modifiers)` is the single source of truth for `Ctrl+S`, `Ctrl+G`, `Esc` in both modes. The Overlay's window-level shortcuts dispatch into it; no competing `Keys` handlers.

### Negative / Trade-offs
- **Edit State in Overlay**: `cipherEditorEditItem` lives on the root `OmarchyBitwarden` item. A future refactor could hoist this into a dedicated controller, but the current scope is manageable.
- **ScrollView vs Modal Sizing**: The embedded form uses a `ScrollView` with dynamic height; the old modal had a fixed card size. The new layout adapts to the Inspector column width, which is a UX improvement but requires care with long field lists.

## Migration Notes
- No data migration required. The contract with `omawarden` is unchanged (ADR-0033).
- Existing keyboard shortcuts (`Ctrl+E`, `Ctrl+S`, `Ctrl+G`, `Esc`) retain their behavior; they now target the embedded form.
- The **Action Palette** `Edit Item` entry and **Inspector** Edit button both route to the same `openCipherEditModal` handler.

## Related ADRs
- ADR-0033: Overlay Cipher Mutation and Zero-Argv Edit Contract
- ADR-0032: Cipher Custom Fields and Multi-URI Mutation
- ADR-0027: Conditional Vault Snapshot Publication