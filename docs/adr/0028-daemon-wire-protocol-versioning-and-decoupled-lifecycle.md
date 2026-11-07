# ADR 0028: Daemon Wire Protocol Versioning and Decoupled Process Lifecycle

## Status
Accepted (Supersedes [ADR 0003](0003-omawarden-rust-native-helper-and-daemon-architecture.md) Section 2 & [ADR 0013](0013-engine-dev-versioning-and-pre-release-delivery.md) Section 3)

## Context
Under [ADR 0003](0003-omawarden-rust-native-helper-and-daemon-architecture.md) and [ADR 0013](0013-engine-dev-versioning-and-pre-release-delivery.md), the `omawarden` CLI queried the running resident daemon on every command and compared compile-time Git Commit SHA (`GIT_HASH`) equality. If the commit hash differed and the vault was locked, the client automatically issued `{"action": "stop"}` to kill the running daemon and re-spawned `current_exe() daemon`.

This design rested on the assumption that the CLI and the daemon are always built from the same binary checkout and run as a single executable pair. When introducing additional consumers—such as `omawarden-app` (an NSH GUI desktop application linking the `omawarden` engine as a Rust library crate) alongside the desktop Quickshell `Overlay`—this assumption collapses:

1. **Fragile Commit-Hash Mismatches**: Git commit hashes differ across development builds, package releases, and dependent crates even when the wire communication protocol is 100% identical.
2. **Host Termination via `exit(0)`**: The daemon's `stop` action executed `std::process::exit(0)`. When `omawarden-app` hosted an in-process daemon worker thread, any external CLI invocation (or configuration change like `Save & Apply` under [ADR 0008](0008-server-switching-credential-and-cache-invalidation.md)) killed the entire GUI application process.
3. **Executable Confusion in Library Mode**: `ensure_daemon_running()` invoked `env::current_exe().arg("daemon")`. In a third-party host binary, this spawned an unexpected second instance of the GUI window rather than a background daemon.

## Decision

1. **Explicit Integer Protocol Version (`protocol_version`)**:
   - The framed JSON Unix Domain Socket interface introduces a monotonic integer `protocol_version: 1` (`u32`) starting at 1.
   - The daemon's `ping` response returns `protocol_version` alongside informational `version` and `commit`.
   - Older daemon instances omitting this field are unambiguously classified as legacy protocol `0`.
   - Clients evaluate compatibility against a window (`daemon_protocol >= MIN_SUPPORTED_PROTOCOL_VERSION && daemon_protocol <= CURRENT_PROTOCOL_VERSION`). Commit hash differences with matching protocol versions are treated as completely benign and fully supported.

2. **Fail-Closed Rejection Without Implicit Process Termination**:
   - When a client encounters an unsupported protocol version, it fails closed with an explicit typed error (`ProtocolMismatch`) and reports the incompatibility to the caller.
   - Clients **MUST NEVER** issue an automatic, uncoordinated `{"action": "stop"}` to kill a mismatched daemon.
   - Daemon recycling across breaking protocol upgrades must be performed explicitly via user or administrative commands (`omawarden daemon restart` or package manager service triggers).

3. **Graceful Listener Loop Shutdown (Eliminating `process::exit(0)`)**:
   - In `omawarden::daemon::run_daemon_server`, receiving `stop` initiates a structured shutdown: locks the vault, wipes quick-unlock keys, removes the socket path, and signals the listener loop to break.
   - The function returns `Ok(())` naturally.
   - For standalone CLI executions, `main()` returns code 0 normally.
   - For library embeddings (e.g. worker threads in `omawarden-app`), the background thread terminates cleanly without terminating the host process.

4. **Decoupled Executable Resolution in Daemon Spawning**:
   - `ensure_daemon_running()` validates whether `current_exe()` is indeed named `omawarden`.
   - If invoked from within a non-omawarden host process, it resolves the canonical `omawarden` binary through system `PATH` (or explicit environment configuration), and refuses to spawn the current executable as a daemon.

## Consequences

### Positive
- **Multi-Client Coexistence**: `omawarden-app` and the desktop `Overlay` safely share the same daemon socket without triggering spurious restarts.
- **Host Stability**: In-process threads and server URL changes ([ADR 0008](0008-server-switching-credential-and-cache-invalidation.md)) no longer terminate the calling application.
- **Stable Seam**: Protocol compatibility is decoupled from git commit activity and packaging pipelines.
- **Testability**: Protocol mismatch and shutdown scenarios can be tested deterministically in unit tests without process aborts.

### Trade-off
- Breaking protocol changes will require an explicit restart (`omawarden daemon restart` or service restart) rather than silent opportunistic in-place replacement.
