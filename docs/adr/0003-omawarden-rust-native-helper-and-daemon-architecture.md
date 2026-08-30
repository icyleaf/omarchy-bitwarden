# ADR 0003: Omawarden Rust Native Helper and Resident Daemon Architecture

## Status
Accepted

## Context
The previous helper backend (`bitwarden-helper`) was implemented in Python, wrapping external CLI binaries (`secret-tool`, `wl-copy`, official Node.js `bw` CLI). While functional, this architecture introduces subprocess cold-start latency (~60-80ms), multiple IPC hops across process pipes, and reliance on system Python environments and external utilities.

To achieve sub-millisecond query responses (<1ms), deterministic memory zeroization (`zeroize::ZeroizeOnDrop`), robust Linux security hardening (`mlock`, `PR_SET_DUMPABLE`, socket `SO_PEERCRED` validation), and self-contained zero-dependency distribution across Omarchy environments, a native Rust helper and daemon backend (`omawarden`) is established.

## Decision
1. **Name & Identity**:
   - The native Rust backend executable is named `omawarden`.
   - Toolchain and environment versions are pinned and managed via `mise` (`.mise.toml`).

2. **Dual-Mode Execution Architecture**:
   - **CLI Mode**: Provides 100% backward-compatible subcommands, argument flags, and JSON payloads matching existing specifications (`config`, `health`, `auth`, `hook`, `vault`, `clipboard`, `totp`, `attachment`).
   - **Daemon Mode**: Optional background stateful daemon listening on `$XDG_RUNTIME_DIR/omawarden/daemon.sock` providing in-memory pre-decrypted index queries, instant clipboard lifecycle management, and D-Bus sleep/lock signal listeners.

3. **Zero-Leakage Memory & Security Policy**:
   - Master passwords, session tokens, and cryptographic keys must utilize `zeroize::ZeroizeOnDrop` or volatile byte overwriting on drop.
   - Sensitive memory regions are locked via `mlock` to eliminate the risk of swapping plaintext secrets to disk.
   - Process dumpability is disabled via `PR_SET_DUMPABLE(0)`.
   - Unix Domain Sockets enforce `0600` permissions and caller UID verification via `SO_PEERCRED`.

4. **Multi-Arch CI & In-App Dynamic Release Delivery**:
   - GitHub Actions automated matrix builds for target architectures (`x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`).
   - Plugin distribution mechanism supporting dynamic retrieval of architecture-specific `omawarden` binaries.

## Consequences
- **Positive**:
  - Sub-millisecond latency for vault search and cryptographic operations.
  - Zero external runtime dependencies (no Python interpreter or Node.js runtime required).
  - Hardened memory security with deterministic secret destruction.
  - Clean, type-safe codebase with comprehensive test coverage.
- **Trade-off**:
  - Requires maintaining Rust build pipelines and release artifacts.
