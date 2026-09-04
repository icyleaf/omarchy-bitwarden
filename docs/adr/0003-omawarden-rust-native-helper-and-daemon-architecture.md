# ADR 0003: Omawarden Rust Native Helper and Resident Daemon Architecture

## Status
Accepted (Supersedes [ADR 0001](0001-keyring-session-and-helper-architecture.md))

## Context
The previous helper backend (`bitwarden-helper`) was implemented in Python, wrapping external CLI binaries (`secret-tool`, `wl-copy`, official Node.js `bw` CLI). While functional, this architecture introduces subprocess cold-start latency (~60-80ms), multiple IPC hops across process pipes, and reliance on system Python environments and external utilities.

To achieve sub-millisecond query responses (<1ms), deterministic memory zeroization (`zeroize::ZeroizeOnDrop`), robust Linux security hardening (`0600` permissions, protected `stdin` descriptors), native Bitwarden cryptographic capabilities (Argon2id, PBKDF2, RSA-OAEP-SHA1 Organization Key unwrapping, AES-256-CBC attachment decryption), and self-contained zero-dependency distribution across Omarchy environments, a native Rust helper and daemon backend (`omawarden`) is established.

## Decision
1. **Name, Identity & Versioning**:
   - The native Rust backend executable is named `omawarden`.
   - Toolchain and environment versions are pinned and managed via `mise` (`.mise.toml`).
   - Embed compile-time Git Commit SHA (`GIT_HASH`) and Build Date (`BUILD_DATE`) into the binary.

2. **Dual-Mode Execution Architecture & Seamless Daemon Auto-Upgrade**:
   - **CLI Mode**: Standalone subcommands for `config`, `health`, `auth`, `hook`, `vault`, `copy`, `totp`, `attachment`, `ssh-key`.
   - **Resident Daemon Mode**: Stateful background daemon listening on `/run/user/<UID>/omawarden.sock` with `0600` permissions. Holds decrypted vault items in RAM while unlocked, enabling instantaneous sub-millisecond fuzzy search.
   - **Version Handshake & Auto-Upgrade**: The CLI queries the daemon version on every command; if the daemon's commit SHA does not match the active binary, the CLI gracefully requests the outdated daemon to exit via `{"action": "stop"}` and spawns the new version automatically.

3. **Zero-Leakage Memory & Linux Security Hardening**:
   - Master passwords, session tokens, and cryptographic keys utilize `zeroize::ZeroizeOnDrop` volatile byte overwriting on drop.
   - **Zero-Argv / Zero-Environ Seam**: Passwords, 2FA codes, API secrets, and sensitive clipboard text travel exclusively through standard input streams or `0600` Unix Domain Sockets to prevent leakage via `/proc/<pid>/cmdline` and `/proc/<pid>/environ`.
   - Storage file `data.json` and Unix socket enforce `0600` permissions (owner read/write only).

4. **Comprehensive Bitwarden Cryptographic Hierarchy**:
   - **User Keys**: PBKDF2-HMAC-SHA256 and Argon2id Master Key derivation with HKDF expansion.
   - **User RSA Key**: Decrypts user private key supporting PKCS#8 DER, PKCS#1 DER, Base64 strings, and PEM text.
   - **Organization Keys**: Decrypts Organization Symmetric Keys (`organizations[].key`) via RSA-OAEP-SHA1 (`Rsa2048_OaepSha1_B64`, Type 4).
   - **Folders & Soft-Delete**: Resolves decrypted folder names and automatically skips soft-deleted items (Recycle Bin).
   - **Binary Attachment Decryption**: Downloads encrypted blobs and decrypts binary AES-256-CBC payloads using resolved attachment/cipher keys for seamless in-overlay previews.

5. **Multi-Arch CI & In-App Dynamic Release Delivery**:
   - GitHub Actions automated matrix builds for target architectures (`x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`).
   - Plugin distribution mechanism supporting dynamic retrieval of architecture-specific `omawarden` binaries.

## Consequences
- **Positive**:
  - Sub-millisecond latency for vault search and cryptographic operations.
  - Zero external runtime dependencies (no Python interpreter or Node.js runtime required).
  - Hardened memory and process isolation with zero credential leakage in `/proc`.
  - Full support for multi-organization vaults, folders, live TOTP, and attachment previews.
  - Clean, type-safe codebase with comprehensive unit and regression test coverage (100% passing).
- **Trade-off**:
  - Requires maintaining Rust build pipelines and release artifacts.
