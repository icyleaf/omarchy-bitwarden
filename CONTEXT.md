# Omarchy Bitwarden Plugin Domain Model

## Core Concepts & Glossary

### Backend & Execution Engine (`omawarden`)
- **Native Backend (`omawarden`)**: Standalone pure Rust helper binary and resident Unix Domain Socket daemon providing sub-millisecond in-memory vault indexing, zero external runtime dependencies (no Python or Node.js runtime needed), memory-hardened secret scrubbing (`zeroize`), and Wayland desktop integration (see `docs/adr/0003-omawarden-rust-native-helper-and-daemon-architecture.md`).
- **Toolchain & Versioning**: Managed via `mise` (`.mise.toml`) and standard Cargo workspaces. Built-in `GIT_HASH` and `BUILD_DATE` embedded at compile-time with automated version checking (`omawarden -V`).
- **Daemon Lifecycle & Auto-Upgrade**: Resident daemon listening on `/run/user/<UID>/omawarden.sock`. The CLI verifies the daemon's running Git commit hash on every command invocation; outdated daemons are gracefully terminated via `{"action": "stop"}` and smoothly re-spawned with the latest binary version.
- **System Package Distribution & Path Resolution**: Distributed natively as an Arch User Repository (AUR) package (`omawarden-bin`) declaring mandatory runtime dependencies on `libsecret` and `wl-clipboard`. On overlay initialization, the frontend dynamically probes for system-wide `omawarden` in `$PATH` (`which omawarden`) with graceful fallback to local `bin/omawarden` for backward-compatible transitions. If runtime prerequisites are missing, the overlay gates entry and presents an onboarding view (`components/DependencyCheckView.qml`) with one-click terminal package installation (see `docs/adr/0012-transition-engine-distribution-to-aur.md`).
- **Development Versioning & Pre-release Delivery**: Explicit next-version identifiers (e.g., `0.8.0-dev`) configured in `omawarden/Cargo.toml`. Pushes to `develop` automatically trigger dual-architecture builds (`x86_64`, `aarch64`) published to GitHub Pre-releases via a rolling, floating `omawarden-dev` tag without publishing pre-releases to AUR. The desktop frontend suppresses regular stable update notifications when running an unreleased `-dev` engine (see `docs/adr/0013-engine-dev-versioning-and-pre-release-delivery.md`).
- **Local Development Packaging**: Developer workflows supporting dual testing modalities: in-tree binary deployment via `mise run dev-deploy` (rendered with `[ builtin ]` badge) and offline local Arch package creation and installation via `mise run pkg-dev [--install]` (rendered with `[ AUR ]` badge), featuring automatic `-dev` to `.dev` pkgver normalization conforming to pacman packaging standards.

### Vault & Session Lifecycle
- **Vault**: The encrypted collection of user credentials, folders, organization collections, and attachments synced from a Bitwarden / Vaultwarden server.
- **Server Address (`server_url`) & Instance Isolation**: The base endpoint of the Bitwarden instance (e.g., official cloud `https://vault.bitwarden.com` or custom self-hosted Vaultwarden instance). Updating the configuration to a different `server_url` automatically triggers instance-isolation cleanup, atomically wiping stale credentials (email, API key `client_id`, API `client_secret`), destroying active sessions (tokens and daemon memory), and purging local cache files (`data.json`, `/tmp` attachments) to prevent cross-server credential or data contamination (see `docs/adr/0008-server-switching-credential-and-cache-invalidation.md`).
- **Authentication Modes**:
  - **Master Password Login**: Email + Master Password with PBKDF2/Argon2id client-side key derivation and 2FA challenge support.
  - **API Key Login**: Standard OAuth2 `client_credentials` flow using `client_id` and `client_secret`.
- **Vault Status**:
  - `unauthenticated`: Logged out; requires server URL configuration, auth credentials (Email + Master Password or API Key `client_id`/`client_secret`).
  - `locked`: Logged in, but vault encrypted; requires Master Password to unlock and load in-memory decrypted cache.
  - `unlocked`: Decryption session active, stored in System Keyring, in-memory search index populated.

### Keyring & Security Policies
- **System Keyring & Credential Persistence**: Secret storage backend (via FreeDesktop Secret Service / `secret-tool` / D-Bus) used to securely persist `access_token`, `refresh_token`, and API `client_secret` across app invocations, ensuring `data.json` on disk remains a pure zero-knowledge ciphertext store (see `docs/adr/0007-keyring-credential-persistence-and-silent-reauth.md`).
- **Silent Background Re-authentication**: Seamless re-authentication via API `client_secret` or OAuth2 `refresh_token` when tokens expire (~2h TTL) or return 401/403, preventing disruption during background sync.
- **Atomic Credential Erasure**: Calling `auth logout` or updating to a different `server_url` triggers `clear_all()` across all `service=omarchy-bitwarden` entries in the OS keyring and purges local storage (see `docs/adr/0008-server-switching-credential-and-cache-invalidation.md`).
- **Zero-Leakage Memory Policy**: Sensitive cryptographic keys (`SymmetricCryptoKey`) and intermediate hashes derive `Zeroize` and `#[zeroize(drop)]` to enforce volatile memory destruction on drop.
- **Zero-Argv / Zero-Environ Security Seam**: To prevent credential leakage across Linux processes (`/proc/<pid>/cmdline` and `/proc/<pid>/environ`), secrets (Master Passwords, API Secrets, TOTP seeds, Clipboard text) are delivered exclusively through protected `stdin` streams or `0600` Unix Domain Sockets.
- **Strict File & Socket Permissions**: Disk storage (`data.json`) and the daemon Unix socket (`omawarden.sock`) enforce `0600` owner-only permissions.
- **Daemon In-Memory Cache & Scrubbing**: Decrypted vault items and keys are held exclusively in daemon memory while unlocked. Manual `auth lock`, `auth logout`, idle timeouts, or screen-lock events immediately trigger `{"action": "lock"}` IPC to purge all decrypted items and keys from memory.
- **Clipboard Guard**: Ephemeral clipboard management using Wayland native `wl-copy` with automatic 30-second TTL cleanup for copied passwords, PINs, and TOTPs.
- **Website Icon Privacy & Endpoint Isolation**: Resolution policy governing website favicon retrieval. Official Bitwarden cloud instances query `https://icons.bitwarden.net/{domain}/icon.png`. Self-hosted instances (e.g. Vaultwarden or self-hosted Bitwarden) strictly query the user's configured server endpoint (`${server_root}/icons/{domain}/icon.png`), preventing leakage of intranet or private domain names to public third-party services. If self-hosted icon retrieval fails (such as on air-gapped networks or when server icon proxying is disabled), the UI fails closed to default category icons (`\uf084`) and never falls back to public servers (see `docs/adr/0014-self-hosted-icon-service-endpoint-and-privacy-isolation.md`).

### Cryptographic Hierarchy & Organization Domain
- **User Master Key**: Derived via PBKDF2-HMAC-SHA256 or Argon2id, used to decrypt the User Symmetric Key (`enc_user_key`).
- **User RSA Private Key**: Decrypted from `enc_private_key` (supporting PKCS#8 DER, PKCS#1 DER, Base64-encoded strings, and PEM formats).
- **Organizations & Collections**:
  - Organization Symmetric Keys (`organizations[].key`) are decrypted via RSA-OAEP-SHA1 (`Rsa2048_OaepSha1_B64`, Type 4) using the user's RSA private key.
  - Organization items link to `organization_id`, `organization_name`, and `collection_ids`, displayed with `[🏢 Org Name]` badges in list and inspector views.
- **Folders**: Decrypted folder names (`folder_id`, `folder_name`) associated with vault items, displayed with `[📁 Folder Name]` badges.
- **Soft-Delete Filtering**: Items flagged with `deletedDate` (Trash / Recycle Bin) are filtered out automatically during sync and search.

### Vault Item Domain & Type Isolation
- **Vault Item**: A single entity stored in the vault, categorized by type with strict type-specific JSON serialization (omitting empty structures for unrelated types):
  - **Login**: Website/app credentials (Username, Password, URIs, live TOTP countdown, Custom Fields, Password History with `Ctrl+H` modal).
  - **Card**: Payment card details (Brand, Cardholder, Number with reveal toggle, Expiration, CVV/Security Code).
  - **Identity**: Personal identification records (Title, Full Name, Username, Email, Phone, Company, Address, SSN, Passport, License).
  - **Secure Note**: Encrypted text notes or documentation with dedicated category classification.
  - **SSH Key**: Private and public key pairs (official Bitwarden Cipher Type 5 with `privateKey`, `publicKey`, and `keyFingerprint`). Supports automated on-the-fly key generation (Ed25519, RSA, ECDSA), file/STDIN import with auto-derived public keys/fingerprints, and export with hardened Unix file permissions (`0600`/`0644`) via `omawarden ssh-key` (see `docs/adr/0005-ssh-key-management-lifecycle.md`).
  - **Attachments**: Encrypted binary or text files associated with an item. Downloads resolve signed URLs, decrypt Bitwarden `EncArrayBuffer` binary blobs (`[encType][IV][MAC][Ciphertext]`) via AES-256-CBC using resolved `attachment.key` or `cipher_key`, and support both in-overlay popup previews (images and text) and external default app viewing via `xdg-open` (see `docs/adr/0002-vault-item-attachments-lifecycle.md`).
- **Vault Index**: An in-memory, fast-searchable structured cache of vault items updated upon `sync` or vault unlock.

### Interaction & UI Paradigms
- **Overlay Window**: Main search launcher modal summoned by global shortcut (`Super+/` or user-defined).
- **Multi-Dimensional Filtering & Scope**:
  - **Vault Scope (`vault_scope`)**: Filters items by vault ownership domain: `All Vaults` (default), `Personal Vault` (personal credentials where `organization_id == null`), or a specific Organization (`[🏢 Org Name]`). Triggered via the search bar dropdown selector or `Ctrl+K`.
  - **Folder Scope (`folder_scope`)**: Filters items assigned to a specific folder: `All Folders` (default) or a specific Folder (`[📁 Folder Name]`).
  - **Category Tabs (`category_scope`)**: Filter bar allowing quick switching across item kinds (All, Login, Card, Identity, Note, SSH).
  - **Conjunctive Filter Pipeline**: Orthogonal multi-layer query evaluation (`Query ∧ Category ∧ VaultScope ∧ FolderScope`), enabling precise credential narrowing.
- **Inspector Pane**: Side panel rendering details, masked secrets, live TOTP countdown, custom fields, organization/folder tags, attachments, and password history entry.
- **Action Palette (`Ctrl+K`)**: Modal listing all contextual operations (Copy Password `↵`, Copy TOTP `Ctrl+↵`, Copy Username `Ctrl+U`, Toggle Field Visibility `Ctrl+T`, View Password History `Ctrl+H`, Open Website `Ctrl+O`, Filter by Vault/Org, Filter by Folder, Copy Organization Name, Copy Folder Name, Copy Card/Identity attributes, Copy Public/Private Key, View/Download Attachments, Lock Vault `Ctrl+L`, Sync `Ctrl+R`).
- **Config & Settings View**: Allows user configuration of `server_url`, `download_dir`, `auto_lock_minutes`, `clipboard_clear_seconds`, and `log_level`, with real-time CLI readiness indicators and an embedded Logs Viewer.
- **Observability & Diagnostics**: Dual-channel structured logging across `omawarden` (`stderr`) and Quickshell (`console.error`), featuring module prefixes (`[omawarden:cli]`, `[omarchy:ui]`), configurable log levels (`error` by default), zero-knowledge credential and custom server URL redaction, and one-click "Copy Diagnostics" for privacy-safe GitHub issue reporting (see `docs/adr/0004-structured-logging-and-diagnostics.md`).
- **Prerequisite Onboarding View**: If core system packages (`omawarden`, `libsecret`, `wl-clipboard`) are not detected via `pacman -Q`, the overlay gates normal vault views and displays `DependencyCheckView`, allowing users to install missing dependencies with one click via their preferred AUR helper (`paru`, `yay`, `pacman`) in an Omarchy floating terminal window.

## Boundaries & Non-Goals
- **Non-Goals**: Full vault item creation/editing/management (e.g. creating complex cryptographic policies or modifying organization memberships is handled via official Bitwarden web/apps). Focus is on lightning-fast retrieval, search, copying, and secure autofill in the Omarchy desktop.
