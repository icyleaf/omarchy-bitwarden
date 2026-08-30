# Omarchy Bitwarden Plugin Domain Model

## Core Concepts & Glossary

### Backend & Execution Engine (`omawarden`)
- **Native Backend (`omawarden`)**: Native Rust helper binary and resident daemon providing sub-millisecond vault indexing, zero-dependency execution, memory-hardened secret scrubbing, and D-Bus/Wayland desktop integration (see `docs/adr/0003-omawarden-rust-native-helper-and-daemon-architecture.md`).
- **Toolchain & Versioning**: Managed via `mise` (`.mise.toml`).

### Vault & Session Lifecycle
- **Vault**: The encrypted collection of user credentials and items synced from a Bitwarden / Vaultwarden server.
- **Server Address (`server_url`)**: The base endpoint of the Bitwarden instance (e.g., official cloud `https://vault.bitwarden.com` or custom self-hosted Vaultwarden instance).
- **Session Token (`BW_SESSION`)**: The ephemeral decryption key generated upon unlocking the vault. Required for reading and manipulating vault items.
- **Vault Status**:
  - `unauthenticated`: Logged out; requires server URL configuration, auth credentials (Email + Master Password or API Key `client_id`/`client_secret`).
  - `locked`: Logged in, but vault encrypted; requires Master Password or PIN to unlock.
  - `unlocked`: Decryption session active, stored in System Keyring, memory search index populated.

### Keyring & Security Policies
- **System Keyring**: Secret storage backend (via FreeDesktop Secret Service / `secret-tool` / D-Bus) used to securely persist `BW_SESSION` across app invocations during the unlocked lifecycle (see `docs/adr/0001-keyring-session-and-helper-architecture.md`).
- **Zero-Leakage Memory Policy**: Sensitive cryptographic keys and credentials use `zeroize` volatile memory destruction on drop, memory page locking (`mlock`), and disabled core dumps (`PR_SET_DUMPABLE`).
- **Protected Descriptor Seam**: All secret-bearing paths (Master Passwords, API Secrets, TOTP seeds, Clipboard plaintext) travel exclusively through standard input streams (`/proc/self/fd/0` descriptor pipes) or secure Unix Domain Sockets. No secrets ever appear in `argv`, global `os.environ`, logs, or error strings.
- **Bounded Stream Ingestion**: Vault item JSON ingestion and CLI output buffers are bounded by user-configurable memory limits (`max_output_mb`, default 10MB) to guard against memory exhaustion.
- **Opaque Error Mapping**: CLI and subprocess error outputs are stripped and sanitized to prevent credential reflection in UI toasts or logs.
- **Auto-lock Policy**: Security mechanism that invalidates the session token and purges memory cache on idle timeout, system sleep, or Hyprland screen lock events.
- **Clipboard Guard**: Ephemeral clipboard management using Wayland native `wl-copy` with automatic 30-second TTL cleanup for copied passwords, PINs, and TOTPs.

### Vault Item Domain
- **Vault Item**: A single entity stored in the vault, categorized by type:
  - **Login**: Website/app credentials (Username, Password, URIs, TOTP, Custom Fields).
  - **Card**: Payment card details (Cardholder, Number, Expiration, CVV/Security Code).
  - **Identity**: Personal identification records (Name, Address, Phone, Email, SSN).
  - **Secure Note**: Encrypted text notes or documentation.
  - **SSH Key**: Private and public key pairs (identified by PEM headers or custom fields `private_key`/`public_key`/`passphrase`).
  - **Attachments**: Encrypted binary or text files associated with an item, supporting in-app discovery, quick preview via `xdg-open`, and direct download with desktop notification routing (see `docs/adr/0002-vault-item-attachments-lifecycle.md`).
- **Vault Index**: An in-memory, fast-searchable structured cache of vault items updated upon `bw sync` or vault unlock.

### Interaction & UI Paradigms
- **Overlay Window**: Main search launcher modal summoned by global shortcut (`Super+Shift+B` or user-defined).
- **Category Tabs**: Filter bar allowing quick switching across item kinds (All, Login, Card, Identity, Note, SSH).
- **Inspector Pane**: Side panel rendering details, masked secrets, live TOTP countdown, custom fields, and attachments.
- **Action Palette (`Ctrl+K`)**: Modal listing all contextual operations (Copy Password, Copy Username, Copy TOTP, Copy Public/Private Key, View/Download Attachments, Lock Vault, Sync).
- **Config & Settings View**: Allows user configuration of `server_url`, `bw_path`, `download_dir`, `auto_lock_minutes`, `clipboard_clear_seconds`, and `max_output_mb`.

## Boundaries & Non-Goals
- **Non-Goals**: Full vault creation/editing/management (e.g. creating folders, generating complex cryptographic policies is handled via official Bitwarden apps/CLI). Focus is on lightning-fast retrieval, search, copying, and secure autofill in the Omarchy desktop.
