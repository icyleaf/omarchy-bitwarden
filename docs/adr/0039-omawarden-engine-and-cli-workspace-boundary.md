# ADR 0039: Omawarden Engine and Omawarden CLI Cargo Workspace Boundary

## Status

Accepted

## Context

**Omawarden** originally shipped as a single Rust package (`omawarden`) containing both the library target and the `omawarden` binary entrypoint. Over time, the binary entrypoint (`src/main.rs`) grew to nearly 9,000 lines, tangling three distinct concerns:

1. **Terminal command parsing and presentation**: `clap` subcommand definitions, Rule 11 Zero-Argv `stdin` readers, interactive prompts, Dual-Mode human/JSON output envelopes, and the `$EDITOR` interactive editing workflow.
2. **Shared Omawarden Engine orchestration**: **Daemon Protocol** capability/schema negotiation (`ping.capabilities`, `schema_version`), standalone daemon auto-restart, **Cipher** mutation submission, unlocked **Vault** lookup with offline cache fallback, **Cipher** field resolution across all 5 Cipher types and **Custom Fields**, `Copy` field extraction, interactive two-factor authentication state transitions, configuration key lookup, and Organization/Collection identifier normalization.
3. **Inline command handlers**: 17 top-level commands sharing one monolithic source file and one monolithic inline test block.

This monolithic package created three concrete architectural issues:

- **Non-CLI frontends could not cleanly reuse core Omawarden behavior**: Native frontends such as `omawarden-app` embed the Rust library directly, yet key **Daemon Protocol** and **Vault** workflows lived only in the CLI binary target. Depending on the single package also forced non-CLI consumers to pull in terminal-only dependencies (`clap`, `rpassword`), and `clap::ValueEnum` had even leaked into library types (`SshAlgorithm`).
- **No enforced no-terminal-I/O boundary**: Without a crate-level dependency boundary, terminal prompts, `stdin` reads, or `stdout`/`stderr` formatting could silently enter reusable engine logic.
- **High change friction**: Adding upcoming Phase 6 features (Collection reassignment, Attachment V2 upload/delete, Vault export/import) in a single-package monolith increased merge conflicts and slowed review.

## Decision

### 1. Two-Crate Virtual Cargo Workspace with Shared Versioning

Convert `omawarden/` into a virtual Cargo Workspace with two member crates sharing `[workspace.package]` metadata (including the single-source `version`):

- **`omawarden-engine`** (`omawarden/omawarden-engine`): Pure Rust library crate implementing the **Omawarden Engine** (cryptography, zero-knowledge **Vault** storage and cache, Bitwarden/Vaultwarden API client, **Keyring Provider**, **Clipboard Guard** provider abstraction, **SSH Key** & SSH agent, **Password Generator**, **Server Capability Matrix**, resident daemon server, and **Daemon Protocol** client).
- **`omawarden-cli`** (`omawarden/omawarden-cli`): Thin binary crate implementing the **Omawarden CLI** and declaring the `omawarden` executable (`[[bin]] name = "omawarden"`).

Single-source build assets and metadata belong to `omawarden-engine`:
- A single `build.rs` inside `omawarden-engine` captures `GIT_HASH` and `BUILD_DATE` and exposes build-metadata constants (`ENGINE_VERSION`, `GIT_HASH`, `BUILD_DATE`, `VERSION_WITH_BUILD_INFO`) consumed by both engine diagnostics (`health`, `daemon` `ping`) and `omawarden-cli --version`.
- The **Passphrase** EFF wordlist asset (`resources/eff_large_wordlist.txt`) lives inside `omawarden-engine` alongside **Password Generator**.
- Keeping `[workspace.package] version` in `omawarden/Cargo.toml` and producing `omawarden/target/release/omawarden` preserves compatibility with existing CI, macOS CI, AUR (`omawarden-bin`, `omawarden-git`), release, and `mise` version-bump workflows.

### 2. Strict No-Terminal-I/O Boundary for `omawarden-engine`

`omawarden-engine` MUST obey a strict, compiler-enforced boundary:

- **Zero CLI dependencies**: `omawarden-engine/Cargo.toml` MUST NOT depend on `clap`, `rpassword`, or any terminal UI/prompt crate. CLI-only `clap::ValueEnum` adapters live exclusively in `omawarden-cli`.
- **Zero terminal I/O**: `omawarden-engine` MUST NOT read from `std::io::stdin()` or write user-facing output to `std::io::stdout()` / `std::io::stderr()`. Diagnostic logging goes exclusively through the structured logging subsystem.
- **Caller-injected I/O callbacks**: Engine workflows that may require user input (such as unlock-password retrieval during Cipher mutations or offline Vault lookup, or interactive 2FA email/code steps) accept caller-injected closures or return structured outcomes (e.g. `ResolvedCipherTarget::Ambiguous { error, candidates }`) so every frontend (**Omawarden CLI**, **Overlay**, `omawarden-app`) controls its own presentation and interaction model.

### 3. Explicit Division of Responsibilities

- **Owned by `omawarden-engine`**:
  - **Daemon Protocol** client & mutation negotiation (`ensure_daemon_capability`, `cipher_mutation_required_schema_version`, `submit_cipher_mutation`, `submit_ssh_cipher`, `resolve_target_cipher`).
  - Unlocked **Vault** lookup with offline cache fallback (`vault_output_item`, `ensure_unlocked_user_key`), non-stdin TOTP resolution (`resolve_totp_for_query`, `resolve_totp_from_daemon`), `vault get` field selector resolution (`resolve_vault_get_field`) across all 5 **Cipher** types plus **Custom Field** fallback and sensitivity classification, and `Copy` field extraction (`resolve_copy_field`).
  - Interactive two-factor authentication state orchestration (`complete_interactive_two_factor`).
  - Configuration key lookup/mapping (`Config::get_value`) and Organization/Collection identifier normalization and validation (`normalize_organization_id`, `normalize_collection_ids`, `validate_org_create_scope`, `validate_org_share_scope`).
- **Owned by `omawarden-cli`**:
  - `clap` command/subcommand/flag definitions, CLI value parsers (`parse_cli_bool`, `CliSshAlgorithm`), custom-field flag parsing, and JSON update payload cleaning for stdin/file input.
  - Rule 11 Zero-Argv `stdin` readers and interactive terminal prompts (master password prompts, numbered candidate selection for ambiguous Cipher targets, irreversible-action `y/N` confirmations).
  - Dual-Mode output envelopes (`--json` vs. human text), session-redacting JSON output, `vault get` summary card rendering and TTY `--reveal` redaction guard, `org list` tree rendering, and the `$EDITOR` interactive template workflow with secure zeroizing temp-file wipe.
  - The detached **Clipboard Guard** holder dispatch and its isolated `clipboard_holder` module.

## Consequences

### Positive

- Downstream native frontends (`omawarden-app`) can depend directly on `omawarden-engine` without pulling in `clap` or `rpassword`, while sharing one fail-closed **Daemon Protocol**, **Vault**, and **Cipher** field resolution implementation.
- `cargo test -p omawarden-engine` verifies all engine domain logic independently with zero terminal dependencies, while the 18 subprocess/E2E integration test suites run inside `omawarden-cli` against the `omawarden` binary.
- Prepares the workspace cleanly for vertical modularization of `omawarden-cli` (Issue #464) and future multi-repository extraction (RFC #393) with zero external CLI behavior changes.

### Negative / Trade-offs

- Workspace manifests require updating two crate `Cargo.toml` files when adding a dependency used by both engine and CLI.
- CLI-specific `clap` derives (such as `CliSshAlgorithm`) require thin wrapper enums around pure engine domain enums (`SshAlgorithm`) to keep `clap` out of `omawarden-engine`.
