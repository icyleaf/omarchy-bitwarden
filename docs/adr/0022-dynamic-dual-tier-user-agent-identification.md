# ADR 0022: Dynamic Dual-Tier User-Agent Identification for CLI and Desktop UI

## Status
Accepted

## Context
`omawarden` serves as both an interactive command-line interface (CLI) for terminal users and the background helper engine for the Omarchy Bitwarden desktop UI overlay (`OmarchyBitwarden.qml`).

Previously, outbound HTTP requests emitted a generic, static User-Agent header:
`Bitwarden_Desktop/2026.7.0 (Linux)`

This static header created several observability and telemetry limitations:
1. Bitwarden server operators and telemetry metrics could not differentiate between terminal CLI calls and Omarchy desktop overlay usage.
2. The installed version of the Omarchy Bitwarden desktop plugin was not communicated to upstream servers, complicating debugging, compatibility tracking, and telemetry for user issues reported across different UI releases.
3. Passing plugin version metadata from the QML frontend via process command-line arguments (`--client-version`) or environment variables (`OMA_CLIENT_VERSION`) posed data exposure risks under Rule 11 of the Security Handbook (Zero-Argv / Zero-Environ for sensitive process boundaries) and would require intrusive manual plumbing across QML `Process` invocation points.

## Decision
1. **Dynamic Dual-Tier User-Agent Format**:
   - Outbound HTTP requests format the `User-Agent` header according to the execution context while preserving standard Bitwarden compatibility headers:
     - **Pure CLI Mode**:
       `Omawarden/<engine_version> (Bitwarden/2026.7.0; Linux)`
     - **UI Overlay Mode**:
       `Omarchy_Bitwarden/<plugin_version> (Omawarden/<engine_version>; Bitwarden/2026.7.0; Linux)`
   - Supporting Bitwarden compatibility headers remain standardized:
     - `bitwarden-client-name`: `desktop`
     - `bitwarden-client-version`: `2026.7.0`
     - `device-type`: `8`

2. **Automated Non-Interactive TTY Detection & Plugin Manifest Probing**:
   - The CLI identifies interactive terminal usage via standard output terminal detection (`std::io::stdout().is_terminal()`).
   - When stdout is not attached to a terminal (such as when spawned by Quickshell / QML via non-interactive sub-process pipes), the CLI activates plugin context probing.
   - It reads the local user plugin manifest at `$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/manifest.json` (falling back to `~/.config/omarchy/plugins/icyleaf.bitwarden/manifest.json`).
   - The probe is non-blocking, capped at 64 KiB, and fails safe: if the file is missing, unreadable, or invalid, `omawarden` falls back to pure CLI User-Agent format with zero warnings or errors.

3. **IPC Protocol Context Transmission**:
   - The Unix Domain Socket IPC schema supports an optional client metadata object:
     ```json
     {
       "action": "sync",
       "client": {
         "name": "Omarchy_Bitwarden",
         "version": "0.11.2"
       }
     }
     ```
   - Client metadata is transmitted exclusively in-memory across the local `0600` socket, keeping process argument lists (`/proc/<pid>/cmdline`) and environment tables (`/proc/<pid>/environ`) completely clean.
   - The background daemon parses client metadata on a per-request basis, constructing the appropriate HTTP client User-Agent for that specific operation without mutating global daemon state.

4. **Strict Header Sanitization & Injection Prevention**:
   - Client names and version strings are validated against a strict character whitelist: length 1..=32 characters containing only `[0-9a-zA-Z._-]`.
   - Any string containing control characters, carriage returns, newlines (`\r`, `\n`), spaces, or semicolons is rejected immediately, safely falling back to the standard engine User-Agent.

## Consequences
- **Zero Frontend Changes**: The QML frontend requires zero manual parameter plumbing or configuration changes; plugin context is detected automatically.
- **Accurate Server Telemetry & Observability**: Upstream servers and self-hosted instances can reliably distinguish desktop UI interactions from interactive terminal scripts while maintaining compatibility with Bitwarden WAFs and API gateways.
- **Fail-Safe & Headless Server Friendly**: Terminal users, automated headless scripts, and environments without the Omarchy desktop plugin seamlessly default to the pure CLI format.
- **Header Injection Immunity**: Strict character whitelisting guarantees immunity against HTTP header manipulation (CRLF injection).
