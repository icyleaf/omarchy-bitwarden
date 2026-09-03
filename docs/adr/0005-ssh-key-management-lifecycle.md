# ADR 0005: Omawarden SSH Key Automated Lifecycle, Generation, Import, and Export

## Status
Accepted

## Context
Bitwarden officially supports SSH Key items (Cipher Type 5) with fields for `privateKey`, `publicKey`, and `keyFingerprint`. While `omawarden` supports decrypting and viewing SSH keys in the UI, users previously had to manually generate keys using external tools (`ssh-keygen`), paste them into the Bitwarden web or desktop vault, and sync.

To streamline developer workflows on Linux (especially in Omarchy desktop environments), `omawarden` needs native CLI capabilities to:
1. **Automatically generate** standard SSH key pairs (Ed25519, RSA, ECDSA) on the fly and immediately encrypt and store them in Bitwarden.
2. **Import existing SSH key files** (or standard input streams) into Bitwarden, automatically deriving public keys and SHA256 fingerprints if only the private key is provided.
3. **Export stored SSH keys** to local files with strict Unix file permissions (`0600` for private keys, `0644` for public keys) or to standard output for piping directly into `ssh-add` or agent sockets.

## Decision

1. **Subcommand Hierarchy**:
   - Establish a dedicated top-level subcommand: `omawarden ssh-key <create|import|export>`.
   - `create`: Generates a cryptographic key pair locally, encrypts it using the user's master symmetric key, posts it to `/api/ciphers`, and updates the local storage cache.
   - `import`: Reads private/public keys from files or STDIN, auto-derives missing public keys and fingerprints, encrypts them, and uploads them to the vault.
   - `export`: Decrypts the target SSH Key cipher and writes files with hardened permissions (`0600` / `0644`) or outputs directly to STDOUT.

2. **Cryptographic Generation and Parsing Standards**:
   - Use the Rust `ssh-key` crate with OpenSSH PEM formatting (`-----BEGIN OPENSSH PRIVATE KEY-----` and `ssh-ed25519 AAA...`).
   - Supported Algorithms:
     - `Ed25519` (Default, recommended)
     - `RSA` (2048-bit, 4096-bit)
     - `ECDSA` (NIST P-256, NIST P-384)
   - Auto-calculate standard OpenSSH SHA256 fingerprints (`SHA256:Base64...`).
   - Support optional passphrases for encrypting private keys at rest within OpenSSH envelopes.

3. **Bitwarden Vault Integration & Sync Lifecycle**:
   - Encrypt `name`, `notes`, and `sshKey` container fields using `SymmetricCryptoKey::encrypt` (Type 2 EncString `2.IV|Cipher|Mac`).
   - Send `POST /api/ciphers` with modern `Bitwarden-Client-Version` and `Bitwarden-Client-Name` headers.
   - On successful server response, immediately insert the new decrypted item into the local `data.json` storage and notify the resident daemon to update its in-memory item cache.

4. **Security & Permission Hardening**:
   - **File Permissions**: All exported private key files are strictly created with Unix `0600` (read/write by owner only); public keys are written with `0644`.
   - **Zeroize Memory Protection**: Private keys in memory use `zeroize` wiping upon drop.
   - **Zero-Argv Seam**: Passphrases and private keys can be supplied via standard input or interactive prompts rather than CLI argument strings.

## Consequences
- **Positive**:
  - Full developer productivity workflow for managing SSH keys directly from the terminal.
  - Zero manual copy-pasting of long PEM blocks into browser forms.
  - Automated public key and fingerprint derivation eliminates human error during import.
  - Hardened file permissions (`0600`) prevent OpenSSH `UNPROTECTED PRIVATE KEY FILE!` errors.
- **Trade-off**:
  - Introduces `ssh-key` crate dependency in `omawarden/Cargo.toml`.
