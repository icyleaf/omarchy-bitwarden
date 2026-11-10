# ADR 0031: Server Capability Discovery and Upstream Feature Matrix

## Status
Accepted

## Context
Bitwarden identity and vault servers (including compatible implementations like Vaultwarden) expose unauthenticated configuration metadata through `/api/config` and `/api/version`. This payload includes the server's semantic version, Git commit hash, and a dictionary of active feature flags (`featureStates`).

The official Bitwarden ecosystem leverages `featureStates` to dynamically toggle experimental or evolving capabilities across clients—notably `ssh-key-vault-item` (Cipher Type 5), `ssh-agent` (v1 agent prototype), and `ssh-agent-v2` (modern SSH Agent protocol overhaul with robust signature negotiation and caller process inspection). Self-hosted Vaultwarden instances configure these flags via `EXPERIMENTAL_CLIENT_FEATURE_FLAGS`.

Previously, Omawarden relied solely on a static compile-time constant (`BITWARDEN_COMPAT_VERSION = "2026.7.0"`). It possessed no runtime introspection into the connected server's feature flags or API deprecations. Consequently:
1. Users and self-hosters had no straightforward way to diagnose whether their upstream server advertises modern capabilities (such as `ssh-agent-v2`).
2. Omawarden could not warn administrators about deprecated endpoints or missing server-side flags without triggering disruptive sync failures.
3. Offline inspection tools (`omawarden doctor`) had no cached knowledge of the connected server's capability posture.

## Decision

We establish an end-to-end subsystem for server capability discovery, declarative feature evaluation, and diagnostic reporting:

### 1. Capability Discovery Lifecycle
- **Discovery Endpoint**: Interrogate `GET /api/config` and fallback to `GET /api/version` on the configured server base URL.
- **Trigger Points**:
  - Automatically during full vault synchronization (`omawarden sync`), updating cached capabilities without failing the core sync if `/api/config` is unavailable or returns non-200.
  - Explicitly upon demand via CLI (`omawarden server capabilities --refresh`) or daemon IPC.
- **Persistence & Offline Access**:
  - Store discovered non-sensitive server metadata in `$XDG_DATA_HOME/omawarden/server_capabilities.json` (`0600` permissions).
  - This enables offline inspection by `omawarden doctor` and CLI queries without blocking on network I/O or requiring unlocked vault state.

### 2. Declarative Server Capability Matrix & Cascading Feature Gating
Omawarden maintains a structured capability matrix registering known upstream feature flags, version thresholds, and **cascading feature dependencies**:
- **Flag Classifications**:
  - `Mandatory`: Fundamental protocol invariants required for basic vault interaction.
  - `Optional`: Ecosystem enhancements (e.g., `ssh-agent-v2`, `ssh-key-vault-item`, `passkeys`, `bitwarden-send`).
- **Cascading Gating Rules**:
  - If `ssh-key-vault-item` is disabled/unsupported on the server:
    - `omawarden ssh-key create` and `import` are blocked with an actionable error.
    - `omawarden ssh-agent` refuses to start (or reports 0 keys available), since a vault-backed agent cannot operate without vault-backed key storage.
  - If a feature is gated by a missing server capability, interactive and CLI commands report the exact server configuration needed (e.g., Vaultwarden `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent`).
  - An escape hatch (`--ignore-server-capabilities` / `--force`) is provided for developers and air-gapped test rigs.
- **Evaluation Statuses**:
  - `Supported`: Active upstream and fully supported in Omawarden.
  - `Disabled`: Inactive or absent on upstream (e.g. self-hosted Vaultwarden without experimental flags).
  - `Unsupported`: Active upstream but not yet implemented in Omawarden (tracked for future releases).
  - `Deprecated`: Flagged by upstream for removal or superseded by a newer standard.

### 3. Graceful Diagnostic & Health Strategy
- **Non-Blocking Invariant**: Missing optional upstream features (such as `ssh-agent-v2`) MUST NEVER fail core synchronization, cipher editing, or unlock operations.
- **Graduated Health Reporting in `omawarden doctor`**:
  - Enabled optional feature: `[OK] Upstream ssh-agent-v2 is enabled`.
  - Missing optional feature: `[INFO] Upstream ssh-agent-v2 is not enabled (optional; self-hosters can enable it via EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent,ssh-agent-v2)`.
  - Deprecated or critically outdated server version: `[WARN]` or `[FAIL]` with actionable upgrade advice.

### 4. Daemon Protocol & CLI Interface
- **Daemon IPC**:
  - Action: `{ "action": "server_capabilities", "refresh": false }`
  - Response:
    ```json
    {
      "ok": true,
      "server_url": "https://vault.example.com",
      "server_version": "2026.10.1",
      "cached_at": "2026-11-10T07:20:00Z",
      "feature_states": {
        "ssh-agent-v2": true,
        "ssh-key-vault-item": true
      },
      "matrix": [
        {
          "name": "ssh-agent-v2",
          "category": "optional",
          "status": "supported",
          "description": "Modern SSH Agent v2 signature negotiation and process binding"
        }
      ]
    }
    ```
- **CLI Subcommand**:
  - `omawarden server capabilities [--refresh] [--json]`
  - Interactive mode prints a clean summary table of server version, active features, and recommendations.
  - Machine mode (`--json`) emits the standard JSON envelope specified above.

## Consequences

- **Positive**:
  - Transparent visibility into upstream server version, feature flags, and Git commit hashes.
  - Clear, non-intimidating guidance for self-hosters to enable modern features like `ssh-agent-v2`.
  - Zero disruption to core vault operations and zero plain secret exposure (only public server metadata is probed and cached).
- **Trade-off**:
  - Adds one lightweight, non-blocking HTTP GET to the sync lifecycle.
  - Requires maintaining the known capability matrix in Omawarden as upstream Bitwarden evolves new flags.
