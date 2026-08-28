# Omarchy Bitwarden Plugin Domain Model

## Core Concepts & Glossary

### Vault & Session Lifecycle
- **Vault**: The encrypted collection of user credentials and items synced from a Bitwarden / Vaultwarden server.
- **Server Address (`server_url`)**: The base endpoint of the Bitwarden instance (e.g., official cloud `https://vault.bitwarden.com` or custom self-hosted Vaultwarden instance).
- **Session Token (`BW_SESSION`)**: The ephemeral decryption key generated upon unlocking the vault. Required for reading and manipulating vault items.
- **Vault Status**:
  - `unauthenticated`: Logged out; requires server URL configuration, auth credentials (Email + Master Password or API Key `client_id`/`client_secret`).
  - `locked`: Logged in, but vault encrypted; requires Master Password or PIN to unlock.
  - `unlocked`: Decryption session active, stored in System Keyring, memory search index populated.

### Keyring & Security Policies
- **System Keyring**: Secret storage backend (via FreeDesktop Secret Service / `secret-tool` / D-Bus) used to securely persist `BW_SESSION` across app invocations during the unlocked lifecycle.
- **Auto-lock Policy**: Security mechanism that invalidates the session token and purges memory cache on idle timeout, system sleep, or Hyprland screen lock events.
- **Clipboard Guard**: Ephemeral clipboard management using Wayland native `wl-copy` with automatic 30-second TTL cleanup for copied passwords, PINs, and TOTPs.

### Vault Item Domain
- **Vault Item**: A single entity stored in the vault, categorized by type:
  - **Login**: Website/app credentials (Username, Password, URIs, TOTP, Custom Fields).
  - **Card**: Payment card details (Cardholder, Number, Expiration, CVV/Security Code).
  - **Identity**: Personal identification records (Name, Address, Phone, Email, SSN).
  - **Secure Note**: Encrypted text notes or documentation.
  - **SSH Key**: Private and public key pairs (identified by PEM headers or custom fields `private_key`/`public_key`/`passphrase`).
- **Vault Index**: An in-memory, fast-searchable structured cache of vault items updated upon `bw sync` or vault unlock.

### Interaction & UI Paradigms
- **Overlay Window**: Main search launcher modal summoned by global shortcut (`Super+Shift+B` or user-defined).
- **Category Tabs**: Filter bar allowing quick switching across item kinds (All, Login, Card, Identity, Note, SSH).
- **Inspector Pane**: Side panel rendering details, masked secrets, live TOTP countdown, and custom fields.
- **Action Palette (`Ctrl+K`)**: Modal listing all contextual operations (Copy Password, Copy Username, Copy TOTP, Copy Public/Private Key, Lock Vault, Sync).

## Boundaries & Non-Goals
- **Non-Goals**: Full vault creation/editing/management (e.g. creating folders, generating complex cryptographic policies is handled via official Bitwarden apps/CLI). Focus is on lightning-fast retrieval, search, copying, and secure autofill in the Omarchy desktop.
