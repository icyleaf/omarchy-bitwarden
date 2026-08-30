# Omarchy Bitwarden Plugin Domain Model

## Core Concepts & Glossary

### Backend & Execution Engine (`omawarden`)
- **Native Backend (`omawarden`)**: Standalone pure Rust helper binary and resident Unix Domain Socket daemon providing sub-millisecond in-memory vault indexing, zero external runtime dependencies (no Node.js or `bw` CLI needed), memory-hardened secret scrubbing, and Wayland desktop integration (see `docs/adr/0003-omawarden-rust-native-helper-and-daemon-architecture.md`).
- **Toolchain & Versioning**: Managed via `mise` (`.mise.toml`) and standard Cargo workspaces.

### Vault & Session Lifecycle
- **Vault**: The encrypted collection of user credentials and items synced from a Bitwarden / Vaultwarden server.
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
- **Zero-Leakage Memory Policy**: Sensitive cryptographic keys and credentials use `zeroize` volatile memory destruction on drop.
- **Protected Descriptor Seam**: All secret-bearing paths (Master Passwords, API Secrets, TOTP seeds, Clipboard plaintext) travel exclusively through standard input streams or secure Unix Domain Sockets.
- **Daemon In-Memory Cache & Scrubbing**: Decrypted vault items are held exclusively in daemon memory while unlocked. Manual `auth lock`, `auth logout`, idle timeouts, or screen-lock events immediately trigger `{"action": "lock"}` IPC to purge all decrypted items and keys from memory.
- **Clipboard Guard**: Ephemeral clipboard management using Wayland native `wl-copy` with automatic 30-second TTL cleanup for copied passwords, PINs, and TOTPs.

### Vault Item Domain
- **Vault Item**: A single entity stored in the vault, categorized by type:
  - **Login**: Website/app credentials (Username, Password, URIs, live TOTP countdown, Custom Fields).
  - **Card**: Payment card details (Brand, Cardholder, Number with reveal toggle, Expiration, CVV/Security Code).
  - **Identity**: Personal identification records (Title, Full Name, Username, Email, Phone, Company, Address, SSN, Passport, License).
  - **Secure Note**: Encrypted text notes or documentation with dedicated category classification.
  - **SSH Key**: Private and public key pairs (heuristically identified by PEM headers or custom fields `private_key`/`public_key`/`passphrase`).
  - **Attachments**: Encrypted binary or text files associated with an item. Downloads resolve signed URLs, decrypt payload bytes using symmetric cipher keys, and support both in-overlay popup previews (images and text) and external default app viewing via `xdg-open` (see `docs/adr/0002-vault-item-attachments-lifecycle.md`).
- **Vault Index**: An in-memory, fast-searchable structured cache of vault items updated upon `sync` or vault unlock.

### Interaction & UI Paradigms
- **Overlay Window**: Main search launcher modal summoned by global shortcut (`Super+/` or user-defined).
- **Category Tabs**: Filter bar allowing quick switching across item kinds (All, Login, Card, Identity, Note, SSH).
- **Inspector Pane**: Side panel rendering details, masked secrets, live TOTP countdown, custom fields, and attachments.
- **Action Palette (`Ctrl+K`)**: Modal listing all contextual operations (Copy Password, Copy Username, Copy TOTP, Copy Card/Identity attributes, Copy Public/Private Key, View/Download Attachments, Lock Vault, Sync).
- **Config & Settings View**: Allows user configuration of `server_url`, `download_dir`, `auto_lock_minutes`, `clipboard_clear_seconds`, and `max_output_mb`.

## Boundaries & Non-Goals
- **Non-Goals**: Full vault creation/editing/management (e.g. creating folders, generating complex cryptographic policies is handled via official Bitwarden apps/CLI). Focus is on lightning-fast retrieval, search, copying, and secure autofill in the Omarchy desktop.
