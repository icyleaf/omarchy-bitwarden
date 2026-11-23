# ADR 0035: Pluggable Keyring Provider Architecture

## Status
Accepted

## Context
Previously, `KeyringManager` was tightly coupled to the Linux-specific `secret-tool` utility (FreeDesktop Secret Service D-Bus API), hardcoding subprocess execution, command flags, and health diagnostics across `keyring.rs` and `health.rs`.

This coupling presented three challenges:
1. **Platform Lock-In**: Running Omawarden on macOS could not persist OAuth2 tokens or API secrets in the native macOS Keychain unless `secret-tool` was installed externally.
2. **Security Invariant Conflict on macOS CLI**: Unlike `pbcopy` (which accepts clipboard secrets via standard input in [ADR 0030](0030-pluggable-clipboard-provider-architecture.md)), the macOS `/usr/bin/security` CLI (`security add-generic-password -w <secret>`) requires passing secrets via command-line arguments or an interactive TTY prompt, directly violating Security Handbook Rule 11 (Zero-Argv & Zero-Environ).
3. **Subprocess vs. In-Process Slot Erasure**: [ADR 0027](0027-conditional-vault-snapshot-publication.md) introduced scoped credential slots (`credential_id`), file-descriptor lease inheritance (`CredentialSlot::inherit_in`) to guard against outliving `secret-tool` writer processes, and bounded `clear` + `search --all` confirmation to verify slot erasure.

## Decision

We decouple the keyring subsystem into a two-tier architecture analogous to [ADR 0030](0030-pluggable-clipboard-provider-architecture.md):

### 1. Separation of Concerns
- **Core Orchestration (`KeyringManager` & `AccountKeyring`)**:
  - Enforces server-URL normalization and attribute scoping (Rule 10) and fail-closed zero-disk fallback (Rule 1).
  - Manages scoped v2 credential slot attributes (`service=omarchy-bitwarden-v2`, `credential_id`, `server_url`, `account`, `identity_url`, `kind`, `client_id`) and legacy v1 fallback lookups.
  - Holds the active `Keyring Provider` via dynamic polymorphism (`Arc<dyn KeyringProvider>`).
- **Low-Level Adapters (`KeyringProvider`)**:
  - Defines platform operations:
    - `name(&self) -> &'static str`
    - `is_available(&self) -> bool`
    - `unavailable_reason(&self) -> Option<String>`
    - `store(&self, label: &str, attributes: &[&str], secret: &str, lease: Option<&CredentialSlot>) -> bool`
    - `lookup(&self, attributes: &[&str]) -> Option<String>`
    - `clear(&self, attributes: &[&str]) -> bool`
    - `erase_credential_slot(&self, credential_id: Option<&str>, deadline: Instant) -> io::Result<()>`

### 2. Platform Providers
- **Linux FreeDesktop Secret Service (`SecretToolKeyringProvider`)**:
  - Backed by `secret-tool`, covering standard Linux desktop environments and window managers (GNOME Keyring, KDE KWallet Secret Service integration, KeePassXC, Hyprland/Omarchy).
  - Preserves stdin secret piping (Rule 11), `CredentialSlot` file-descriptor lease inheritance across child processes, and bounded `clear` + `search --all` verification on slot retirement.
- **macOS Keychain (`MacOsKeychainProvider`)**:
  - Backed by in-process C FFI bindings to Apple's `Security.framework` and `CoreFoundation.framework` (`SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`) using `kSecClassGenericPassword`.
  - Avoids spawning `/usr/bin/security`, keeping secrets strictly in process memory and satisfying Rule 11 (Zero-Argv & Zero-Environ).
  - **Deterministic Keychain Attribute Mapping**:
    - Maps `kSecAttrService` to the slot namespace: `"omarchy-bitwarden-v2.<credential_id>"` for scoped v2 credentials, or `"omarchy-bitwarden"` for legacy v1 entries.
    - Encodes all remaining key-value attribute pairs in sorted canonical order into `kSecAttrAccount`, enabling $O(1)$ exact lookup, upsert (`errSecDuplicateItem` -> `SecItemUpdate`), and atomic slot erasure (`SecItemDelete` by `kSecAttrService`) followed by zero-residue verification.
  - Because `Security.framework` calls execute synchronously in-process, the caller's stack frame holds the `CredentialSlot` file lock directly without needing child fd inheritance.
- **Test Double (`MockKeyringProvider`) & Fallback (`UnavailableKeyringProvider`)**:
  - `MockKeyringProvider` provides a pure in-memory, thread-safe attribute store for deterministic unit tests without spawning shell scripts.
  - Unsupported platforms (such as Windows, pending a future Windows Credential Manager `wincred` provider) resolve to `UnavailableKeyringProvider`, failing closed in accordance with Rule 1.

### 3. Resolution Chain & Backward Compatibility
- Resolves providers in the following precedence order:
  1. Explicit provider name or binary path passed programmatically (`KeyringManager::new`, `resolve_provider`).
  2. Environment override (`OMA_KEYRING_PROVIDER`, `OMA_SECRET_TOOL_PATH`).
  3. Compile-time target OS dispatch (`#[cfg(target_os = "macos")]` -> `MacOsKeychainProvider`; `#[cfg(target_os = "linux")]` -> `SecretToolKeyringProvider`; other targets -> `UnavailableKeyringProvider`).
- Passing a filesystem path or a string containing `"secret-tool"` to `KeyringManager::new` automatically constructs `SecretToolKeyringProvider` with that binary path, preserving 100% compatibility with existing integration test fixtures.
