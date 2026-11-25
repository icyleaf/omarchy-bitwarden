# Omarchy Bitwarden

A native, zero-knowledge Bitwarden and Vaultwarden desktop overlay and daemon for the Omarchy Linux desktop.

## Language

### Core & Execution

**Omawarden**:
The resident pure-Rust background daemon and CLI engine that executes cryptographic derivation, in-memory vault indexing, and secret isolation.
_Avoid_: Backend service, runner daemon, helper process

**Overlay**:
The Spotlight-style floating QML desktop window that provides keyboard-driven search, credential inspection, and actions.
_Avoid_: Modal window, popup, main window, app window

**Keyring**:
The system-backed credential store subsystem (such as FreeDesktop Secret Service on Linux or macOS Keychain) used to persist tokens and API secrets without writing plaintext to disk.
_Avoid_: Token cache, plaintext credential file, local secret cache

**Keyring Provider**:
A platform-specific keyring backend adapter responsible for low-level credential storage, attribute-scoped lookup, slot erasure, and availability checks.
_Avoid_: Keyring backend, keystore wrapper, secret helper

**Clipboard Guard**:
The ephemeral clipboard subsystem that enforces automatic time-to-live clearing and secure revocation of copied secrets across supported display and OS clipboard providers.
_Avoid_: Clipboard manager, clipboard watcher

**Clipboard Provider**:
A platform-specific clipboard backend adapter responsible for low-level clipboard copy, clear, and availability checks.
_Avoid_: Clipboard backend, clipboard wrapper, clipboard helper

**Daemon Protocol**:
The framed JSON wire interface exposed over the local Unix domain socket by Omawarden, evolved across three layers: a monotonically increasing integer (`protocol_version`) for breaking wire-framing or transport changes, a per-release-cycle `schema_version` baseline for coarse-grained IPC contract changes, and **Daemon Capabilities** (`ping.capabilities`) for fine-grained additive feature negotiation.
_Avoid_: Socket API, daemon version, API version

**Daemon Capabilities**:
The authoritative list of fine-grained local Omawarden Daemon Protocol feature identifiers advertised in the `ping` response (`ping.capabilities`, e.g., `"cipher_mutation_v3"`, `"folder_crud"`, `"login_totp_uri_match"`, `"vault_get"`). Clients use Daemon Capabilities for fail-closed runtime feature gating and standalone daemon auto-restart. Distinct from **Capability Discovery** and the **Server Capability Matrix**, which govern upstream Bitwarden/Vaultwarden server features.
_Avoid_: Daemon feature flags, ping booleans, server capabilities

**Capability Discovery**:
The background interrogation of the upstream server's `/api/config` and `/api/version` endpoints during sync and initialization to detect server versions, active feature flags, and API deprecations without blocking core vault operations.
_Avoid_: Feature probing, version sniffing, server polling

**Server Capability Matrix**:
The declarative specification in Omawarden mapping upstream Bitwarden and Vaultwarden feature flags (`featureStates`) and API versions to local engine capabilities, feature gates, and deprecation statuses.
_Avoid_: Feature checklist, server flag list, compat table

### Vault & Cryptography

**Vault**:
The local zero-knowledge encrypted database containing synced user credentials, collections, and metadata.
_Avoid_: Database, password store, credentials file

**Master Password**:
The user-supplied secret used to derive the user master encryption key and authenticate against the identity server.
_Avoid_: Account password, master code

**Master Key**:
The primary symmetric cryptographic key derived from the master password using PBKDF2 or Argon2id.
_Avoid_: Encryption key, secret key

**Cipher**:
A single encrypted credential item stored in the vault, categorized by type.
_Avoid_: Record, password entry, credential item

**Login**:
A vault cipher containing website or application credentials, live TOTP seeds, and password history.
_Avoid_: Account, password entry

**Card**:
A payment card cipher containing brand, cardholder, expiration, CVV, and formatted number.
_Avoid_: Credit card, payment method

**Identity**:
A personal identification cipher containing names, addresses, emails, and passport or social numbers.
_Avoid_: Profile, personal info

**Secure Note**:
An encrypted arbitrary text note cipher.
_Avoid_: Note, text file, memo

**Custom Field**:
An arbitrary user-defined key-value attribute attached to a vault cipher, categorized as Text, Hidden (masked secret), Boolean (toggle), or Linked.
_Avoid_: Extra property, custom property, metadata field, user attribute

**Login URI**:
A website or service uniform resource identifier associated with a Login cipher, evaluated against target application domains or hosts using configured match detection rules.
_Avoid_: Website URL, login URL, web link, target address

**SSH Key**:
An OpenSSH cryptographic keypair cipher (Type 5) containing private key, public key, and SHA256 fingerprint.
_Avoid_: Keyfile, SSH credential

**Attachment**:
The encrypted binary or text file associated with a vault cipher.
_Avoid_: File, upload, asset

**Icon Cache**:
The local offline store of website and service favicons, namespaced by origin and domain to preserve network privacy and enable offline UI rendering.
_Avoid_: Favicon folder, icon directory, image cache

**Organization**:
A shared administrative entity containing enterprise or team credentials.
_Avoid_: Company, team, tenant

**Collection**:
A logical grouping of ciphers within an Organization.
_Avoid_: Shared folder, group

**Folder**:
A user-defined organizational container for grouping personal or organization ciphers.
_Avoid_: Category, directory

**Trash**:
The holding state for soft-deleted ciphers awaiting restoration to the active vault or permanent destruction.
_Avoid_: Recycle bin, trash folder, deleted items

**Password Generator**:
The cryptographic engine within Omawarden that generates random passwords and passphrases using OS entropy.
_Avoid_: Secret generator, randomizer

**Passphrase**:
A sequence of random words derived from the EFF wordlist used as an easily memorable yet high-entropy credential.
_Avoid_: Mnemonic password, word sequence, passphrase sentence

### UI & Interaction

**Action Palette**:
The keyboard-invoked command palette (`Ctrl+K`) for executing contextual operations on the active cipher.
_Avoid_: Command menu, quick actions

**Inspector**:
The side panel within the overlay that reveals details, masked secrets, and metadata for the selected cipher.
_Avoid_: Details pane, info view, sidebar

**Inspector Form**:
The inline editable state within the Inspector panel for drafting or modifying personal and writable Organization ciphers (Login, Secure Note, Card, Identity, and SSH Key metadata) without opening a blocking modal dialog.
_Avoid_: Create window, edit popup, modal form

**Type Picker**:
The lightweight keyboard-driven selector (`Ctrl+N`) for choosing a cipher type to create (Login, Secure Note, Card, Identity, or SSH Key).
_Avoid_: Creation modal, type dialog, prompt window

**Theme Tokens**:
The reactive, system-wide color primitives provided by the Omarchy shell (`qs.Commons.Color`) that dynamically adapt to the active desktop theme (dark or light).
_Avoid_: Hardcoded hex codes, custom color schemes, fixed color palettes

**Surface Roles**:
Semantic UI layer classifications (`popups`, `menu`, `tooltip`, `controls`) defining background, border, text, and selection colors for distinct interface contexts.
_Avoid_: Component-level color configs, local background overrides

**Muted Color**:
The theme-provided secondary color token (`Color.muted`) used for subdued labels, captions, and placeholders across both dark and light modes.
_Avoid_: Darkened foreground, lighter black, gray tint

