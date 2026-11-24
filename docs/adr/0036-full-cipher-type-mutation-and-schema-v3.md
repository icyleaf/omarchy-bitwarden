# ADR 0036: Full Cipher Type Mutation Contract and Daemon Schema v3

## Status
Accepted

## Context
Following ADR-0032, ADR-0033, and ADR-0034, Omawarden and the Quickshell Overlay supported Create, Update, Delete, and Favorite only for **Login** (Type 1) and **Secure Note** (Type 2) ciphers, alongside a dedicated Generate/Import/Export flow for **SSH Key** (Type 5) ciphers (ADR-0005). **Card** (Type 3) and **Identity** (Type 4) ciphers remained read-only across both CLI and Overlay, and **SSH Key** ciphers lacked metadata editing, Overlay deletion, and favorite toggles.

Extending mutation parity to all five Bitwarden cipher types required settling four architectural boundaries:
1. **Wire Compatibility**: Legacy Schema v2 daemons use `#[serde(deny_unknown_fields)]` on `CipherCreateDraft` and `CipherUpdateDraft` and reject `card` / `identity` payloads.
2. **Nested Partial-Merge Semantics**: **Card** (6 fields) and **Identity** (18 fields) carry structured nested objects in Bitwarden's API; partial updates must preserve unedited sub-fields without forcing clients to re-transmit untouched secrets.
3. **SSH Key Mutability & Shortcut Ergonomics**: Unlike Card or Identity, an **SSH Key** cipher contains cryptographic key material (`privateKey`, `publicKey`, `keyFingerprint`) that Bitwarden treats as immutable after generation/import, and `Ctrl+E` in the Overlay previously triggered Export on SSH Keys instead of Edit.
4. **Delete & Favorite Parity**: Backend `cipher_delete` and `favorite` mutations already operate on any personal cipher type, while the Overlay restricted them to Login and Secure Note.

## Decision

### 1. Daemon Schema v3 (`CURRENT_SCHEMA_VERSION = 3`)
- Increment `CURRENT_SCHEMA_VERSION` from `2` to `3` in `omawarden/src/daemon/protocol.rs`.
- Schema `3` adds `card` (Type 3) and `identity` (Type 4) create/update payloads and formalizes metadata updates on `ssh_key` (Type 5).
- Clients continue using the fail-closed `mutation` envelope established in ADR-0032 whenever a mutation requires `schema_version >= 2`, and enforce `running_schema >= required_schema` (with on-demand standalone daemon restart and post-restart re-validation).

### 2. Native Nested `card` and `identity` Payloads with Partial Merge
- `cipher_create` and `cipher_update` accept nested `card` and `identity` objects matching Bitwarden's wire schema:
  - `card`: `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code`.
  - `identity`: `title`, `firstName`, `middleName`, `lastName`, `username`, `company`, `ssn`, `passportNumber`, `licenseNumber`, `email`, `phone`, `address1`, `address2`, `address3`, `city`, `state`, `postalCode`, `country`.
- `omawarden/src/api.rs` decrypts all 18 Identity fields including `address3` so round-trip edits never drop data.
- On `cipher_update`, omitted sub-fields within `card` or `identity` preserve their existing encrypted values; an explicit empty string (`""`) clears the sub-field to `null`.
- Mismatched type-specific payloads (e.g., `card` fields on a non-Card cipher, `identity` fields on a non-Identity cipher, or `login` fields on a non-Login cipher) are rejected fail-closed.

### 3. SSH Key Metadata-Only Edit & `Ctrl+E` Unification
- **Create**: SSH Key generation and import remain in `omawarden ssh-key create|import` and `SshKeyModal.qml`, surfaced in the `Ctrl+N` **Type Picker** (`S` shortcut) alongside `Login [L]`, `Secure Note [N]`, `Card [C]`, and `Identity [I]`.
- **Edit**: Editing an **SSH Key** (via `vault edit` or **Inspector Form**) modifies metadata only (`name`, `notes`, `folder_id`, `favorite`, **Custom Fields**). Cryptographic key material remains immutable after creation/import.
- **Shortcut**: `Ctrl+E` in the **Overlay** uniformly opens **Edit** (**Inspector Form**) across all five cipher types. SSH Key Export remains accessible via the Inspector header action and **Action Palette**.

### 4. Uniform Delete & Favorite Across All Personal Ciphers
- Soft-delete (**Trash**), permanent delete, and Favorite (`Ctrl+B` / Inspector header toggle) are enabled for all five personal cipher types (**Login**, **Secure Note**, **Card**, **Identity**, **SSH Key**).
- **Organization** ciphers remain strictly read-only across all mutation paths (ADR-0033).

### 5. CLI Interface Division & Zero-Argv Enforcement
- `omawarden vault create` exposes `card` and `identity` subcommands with non-sensitive metadata flags alongside `--stdin` and `--from-json`.
- Per Security Rule 11 (Zero-Argv), sensitive item secrets (Card `number` and `code`, Identity `ssn`, `passportNumber`, and `licenseNumber`) are **never** accepted as CLI `argv` flags; they are supplied via interactive non-echoing terminal prompts or via `--stdin` / `--from-json` JSON payloads.
- `omawarden vault edit <target>` supports interactive `$EDITOR` templates and zero-argv `--stdin` / `--from-json` payloads for all five cipher types, while keeping top-level CLI flags focused on common metadata (`--name`, `--notes`, `--folder`, `--favorite`, `--field*`) to avoid flag bloat.

## Consequences

### Positive
- Full Bitwarden cipher-type parity across Daemon, CLI, and Overlay without leaving the native workflow.
- Zero-argv secret transport (ADR-0033) and fail-closed mixed-version safety (ADR-0032) apply uniformly to Card, Identity, and SSH Key mutations.
- Immutable SSH Key material prevents accidental corruption of OpenSSH PEM envelopes during metadata edits.

### Trade-offs
- Users accustomed to pressing `Ctrl+E` on an SSH Key to open Export now use the Inspector Export button or **Action Palette** (`Ctrl+K`), in exchange for consistent `Ctrl+E` -> Edit behavior across the entire Overlay.
