# ADR 0004: Structured Logging and Diagnostics Across CLI and Quickshell

## Status
Accepted

## Context
As `omarchy-bitwarden` evolves, diagnosing transient network failures, Bitwarden API edge-cases, authentication discrepancies, daemon lifecycle events, and desktop environment issues requires observability. Previously, error output was ad-hoc, with CLI errors output to stderr or buried inside JSON payloads, while QML errors were occasionally printed to `console.error`.

To provide a unified debugging mechanism that helps both users and maintainers troubleshoot unexpected issues without compromising zero-knowledge privacy, a structured logging and diagnostics subsystem is required.

## Decision
1. **Dual-Channel Observability & Prefixes**:
   - **CLI (`omawarden`)**: All logs are written to `stderr` with timestamp, severity level, and module origin (e.g. `[omawarden:core]`, `[omawarden:daemon]`, `[omawarden:crypto]`), preserving `stdout` exclusively for clean JSON IPC responses.
   - **Frontend (`omarchy-bitwarden`)**: Quickshell `Process` subprocesses capture `stderr` streams via `StdioCollector` and route them through a central QML logging pipeline with `[omawarden:cli]` prefix. Internal UI/lifecycle events use `[omarchy:ui]`, `[omarchy:auth]`, and `[omarchy:vault]`.

2. **Log Level Configuration & Hierarchy**:
   - **Default Level**: `error` (silent in normal daily operation, logging only critical failures and unhandled exceptions).
   - **Supported Levels**: `error`, `warn`, `info`, `debug`, `trace`.
   - **Configuration Hierarchy**:
     1. Environment variable override (`OMA_LOG_LEVEL` or `RUST_LOG`).
     2. CLI config parameter (`omawarden config set --log-level <level>`).
     3. GUI Settings dropdown in the Settings modal (persisted to `config.json`).

3. **Zero-Knowledge Redaction & Privacy Seam**:
   - Both CLI and QML logging pipelines enforce sanitization regexes prior to output:
     - Bearer tokens: `Bearer [A-Za-z0-9-_.]+` $\to$ `Bearer <REDACTED_TOKEN>`
     - Passwords, 2FA codes, API client secrets, encryption keys, and master keys are scrubbed with `<REDACTED>`.

4. **In-App Logs Viewer & Issue Diagnostics Export**:
   - A dedicated Logs section within Settings displays the in-memory ring buffer (up to 500 recent entries) with level filtering (All, Error, Warn).
   - A "Copy Diagnostics" action aggregates anonymized environment metadata (OS, Quickshell, omawarden Git commit SHA, server host domain, log level) and recent logs into a preformatted Markdown report for GitHub Issue submissions.

## Consequences
- **Positive**:
  - Consistent and readable log stream across CLI and UI.
  - Complete zero-knowledge data protection ensuring credentials never leak into terminal logs or diagnostics reports.
  - Easy self-service debugging and simplified issue reporting for end-users.
- **Negative**:
  - Minor in-memory overhead (~100KB for 500 log lines).
