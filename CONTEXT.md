# Omarchy Bitwarden Plugin Domain Model

## Core Concepts & Glossary

### Backend & Execution Engine (`omawarden`)
- **Native Backend (`omawarden`)**: Standalone pure Rust helper binary and resident Unix Domain Socket daemon providing sub-millisecond in-memory vault indexing, zero external runtime dependencies (no Python or Node.js runtime needed), memory-hardened secret scrubbing (`zeroize`), and Wayland desktop integration (see `docs/adr/0003-omawarden-rust-native-helper-and-daemon-architecture.md`).
- **Toolchain & Versioning**: Managed via `mise` (`.mise.toml`) and standard Cargo workspaces. Built-in `GIT_HASH` and `BUILD_DATE` embedded at compile-time with automated version checking (`omawarden -V`).
- **Daemon Lifecycle & Auto-Upgrade**: Resident daemon listening on `/run/user/<UID>/omawarden.sock`. The CLI verifies the daemon's running Git commit hash on every command invocation; outdated daemons are gracefully terminated via `{"action": "stop"}` and smoothly re-spawned with the latest binary version.
- **Binary Bootstrap & Auto-Download**: On overlay initialization, if `bin/omawarden` is missing, the frontend automatically triggers architecture detection (`x86_64` / `aarch64`), downloads the latest prebuilt binary archive and `.sha256` checksum file (`omawarden-<target>.tar.gz`) from GitHub Releases, cryptographically verifies the SHA-256 hash before extraction, and unpacks directly into `bin/omawarden`.

### Vault & Session Lifecycle
- **Vault**: The encrypted collection of user credentials, folders, organization collections, and attachments synced from a Bitwarden / Vaultwarden server.
- **Server Address (`server_url`)**: The base endpoint of the Bitwarden instance (e.g., official cloud `https://vault.bitwarden.com` or custom self-hosted Vaultwarden instance).
- **Authentication Modes**:
  - **Master Password Login**: Email + Master Password with PBKDF2/Argon2id client-side key derivation and 2FA challenge support.
  - **API Key Login**: Standard OAuth2 `client_credentials` flow using `client_id` and `client_secret`.
- **Vault Status**:
  - `unauthenticated`: Logged out; requires server URL configuration, auth credentials (Email + Master Password or API Key `client_id`/`client_secret`).
  - `locked`: Logged in, but vault encrypted; requires Master Password to unlock and load in-memory decrypted cache.
  - `unlocked`: Decryption session active, stored in System Keyring, in-memory search index populated.

### Keyring & Security Policies
- **System Keyring**: Secret storage backend (via FreeDesktop Secret Service / `secret-tool` / D-Bus) used to securely persist access tokens across app invocations during the unlocked lifecycle (see `docs/adr/0001-keyring-session-and-helper-architecture.md`).
- **Zero-Leakage Memory Policy**: Sensitive cryptographic keys (`SymmetricCryptoKey`) and intermediate hashes derive `Zeroize` and `#[zeroize(drop)]` to enforce volatile memory destruction on drop.
- **Zero-Argv / Zero-Environ Security Seam**: To prevent credential leakage across Linux processes (`/proc/<pid>/cmdline` and `/proc/<pid>/environ`), secrets (Master Passwords, API Secrets, TOTP seeds, Clipboard text) are delivered exclusively through protected `stdin` streams or `0600` Unix Domain Sockets.
- **Strict File & Socket Permissions**: Disk storage (`data.json`) and the daemon Unix socket (`omawarden.sock`) enforce `0600` owner-only permissions.
- **Daemon In-Memory Cache & Scrubbing**: Decrypted vault items and keys are held exclusively in daemon memory while unlocked. Manual `auth lock`, `auth logout`, idle timeouts, or screen-lock events immediately trigger `{"action": "lock"}` IPC to purge all decrypted items and keys from memory.
- **Clipboard Guard**: Ephemeral clipboard management using Wayland native `wl-copy` with automatic 30-second TTL cleanup for copied passwords, PINs, and TOTPs.

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
  - **Login**: Website/app credentials (Username, Password, URIs, live TOTP countdown, Custom Fields).
  - **Card**: Payment card details (Brand, Cardholder, Number with reveal toggle, Expiration, CVV/Security Code).
  - **Identity**: Personal identification records (Title, Full Name, Username, Email, Phone, Company, Address, SSN, Passport, License).
  - **Secure Note**: Encrypted text notes or documentation with dedicated category classification.
  - **SSH Key**: Private and public key pairs (heuristically identified by PEM headers or custom fields `private_key`/`public_key`/`passphrase`).
  - **Attachments**: Encrypted binary or text files associated with an item. Downloads resolve signed URLs, decrypt Bitwarden `EncArrayBuffer` binary blobs (`[encType][IV][MAC][Ciphertext]`) via AES-256-CBC using resolved `attachment.key` or `cipher_key`, and support both in-overlay popup previews (images and text) and external default app viewing via `xdg-open` (see `docs/adr/0002-vault-item-attachments-lifecycle.md`).
- **Vault Index**: An in-memory, fast-searchable structured cache of vault items updated upon `sync` or vault unlock.

### Interaction & UI Paradigms
- **Overlay Window**: Main search launcher modal summoned by global shortcut (`Super+/` or user-defined).
- **Category Tabs**: Filter bar allowing quick switching across item kinds (All, Login, Card, Identity, Note, SSH).
- **Inspector Pane**: Side panel rendering details, masked secrets, live TOTP countdown, custom fields, organization/folder tags, and attachments.
- **Action Palette (`Ctrl+K`)**: Modal listing all contextual operations (Copy Password, Copy Username, Copy TOTP, Copy Organization Name, Copy Folder Name, Copy Card/Identity attributes, Copy Public/Private Key, View/Download Attachments, Lock Vault, Sync).
- **Config & Settings View**: Allows user configuration of `server_url`, `download_dir`, `auto_lock_minutes`, `clipboard_clear_seconds`, and `max_output_mb`, with real-time CLI readiness indicators.

## Boundaries & Non-Goals
- **Non-Goals**: Full vault item creation/editing/management (e.g. creating complex cryptographic policies or modifying organization memberships is handled via official Bitwarden web/apps). Focus is on lightning-fast retrieval, search, copying, and secure autofill in the Omarchy desktop.
