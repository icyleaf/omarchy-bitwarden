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
The system FreeDesktop Secret Service store used to persist tokens and credentials without writing plaintext to disk.
_Avoid_: Keychain, token cache, credential store

**Clipboard Guard**:
The ephemeral Wayland clipboard manager that enforces automatic time-to-live clearing of copied secrets.
_Avoid_: Clipboard manager, clipboard watcher

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

**SSH Key**:
An OpenSSH cryptographic keypair cipher (Type 5) containing private key, public key, and SHA256 fingerprint.
_Avoid_: Keyfile, SSH credential

**Attachment**:
An encrypted binary or text file associated with a vault cipher.
_Avoid_: File, upload, asset

**Organization**:
A shared administrative entity containing enterprise or team credentials.
_Avoid_: Company, team, tenant

**Collection**:
A logical grouping of ciphers within an Organization.
_Avoid_: Shared folder, group

**Folder**:
A user-defined organizational container for grouping personal or organization ciphers.
_Avoid_: Category, directory

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

### VaultBroker & Secret Execution

**VaultBroker**:
The execution, policy enforcement, and secret isolation subsystem within Omawarden that brokers vault ciphers into child process environments and tools without exposing plaintext credentials to users or AI agents.
_Avoid_: Secret broker, proxy runner, credential injector, secret wrapper

**Destination Binding**:
A security policy constraint that strictly restricts a brokered cipher or token to authorized executable binary paths and argument prefixes.
_Avoid_: Command whitelist, path allowlist, execution rule

**Redaction**:
The real-time streaming filter that scrubs secret values and sensitive substrings from child process standard output and standard error streams.
_Avoid_: Masking, string replacement, log censoring

**Project Manifest**:
A zero-plaintext configuration file (`.omawarden.toml`) in a project workspace root declaring cipher references and destination policies.
_Avoid_: Config file, env file, secret definition

**Agent Skills**:
The structured, machine-readable instructions and usage contract exposed by Omawarden for AI agents to discover safe credential execution without requesting plaintext secrets.
_Avoid_: Agent prompt, LLM guide, agent instructions
