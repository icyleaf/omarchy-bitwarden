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
- **Nested Server Metadata Extraction**: Alongside the top-level Bitwarden compatibility version (`version` -> `server_version`) and `gitHash`, discovery captures the optional nested `server` object (`server.name` -> `server_name`, `server.version` -> `server_vendor_version`) so Vaultwarden instances can be distinguished from official Bitwarden deployments and their real release version identified.
- **Persistence & Offline Access**:
  - Store discovered non-sensitive server metadata in `$XDG_DATA_HOME/omawarden/server_capabilities.json` (`0600` permissions).
  - `server_name` and `server_vendor_version` are optional and default to `None`; caches written by older builds without these keys deserialize cleanly via `#[serde(default)]`.
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

#### 2.1 Server Flavor Classification & Version-Aware Evaluation

A lightweight, zero-regex version parser extracts `(major, minor, patch)` from release strings such as `1.37.4`, `v1.37.4-testing`, `1.37.4-2a3b4c`, and calendar versions like `2026.7.0`. Unparseable or missing versions degrade to `None`. The upstream server is classified into one of three flavors:

1. **Bitwarden Official**: `EnvironmentUrls::resolve` reports `is_cloud == true`, or `server.name` case-insensitively matches `"Bitwarden"`, or metadata is absent while the compatibility version is a valid `>= 2024.12.0` calendar version.
2. **Vaultwarden**: `server.name` case-insensitively matches `"Vaultwarden"`, or `server_vendor_version` / compatibility version has major version `1`.
3. **Unknown Self-Hosted**: Neither a cloud origin nor recognizable server metadata.

For `ssh-key-vault-item`, explicit booleans in `featureStates` always take precedence (`true` -> `supported`, `false` -> `disabled`). When the flag is absent, the matrix defaults by flavor and version:

| Server flavor | Version | Default status |
| --- | --- | --- |
| Vaultwarden | `>= 1.37.4` | `supported` (GA; experimental flag removed upstream) |
| Vaultwarden | `1.33.0 ..= 1.37.3` | `disabled` (requires `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item`) |
| Vaultwarden | `< 1.33.0` | `unsupported` (predates Cipher Type 5 support) |
| Vaultwarden | unparseable / missing vendor version | `disabled` (conservative fallback) |
| Bitwarden Official | compatibility `< 2024.12.0` | `unsupported` |
| Bitwarden Official | otherwise | `supported` |
| Unknown Self-Hosted | any | `disabled` (conservative fallback) |

Cascading feature gating and `doctor` diagnostics are flavor/version aware: pre-1.33.0 Vaultwarden servers receive an upgrade recommendation instead of flag guidance, and Vaultwarden `>= 1.37.4` instances are never told to re-add the removed `ssh-key-vault-item` / `ssh-agent` flags. Vaultwarden `< 1.28.0` triggers an explicit minimum-baseline warning (Argon2id KDF and modern identity prelogin).

##### 2.1.1 Vaultwarden version support tiers

| Vaultwarden version | Support tier |
| --- | --- |
| `>= 1.37.4` | Recommended: native SSH Key (Cipher Type 5) support without experimental flags |
| `>= 1.33.0` | SSH Key support behind `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item,ssh-agent` |
| `>= 1.32.0` | WebAuthn / OTP support |
| `>= 1.28.0` | Minimum baseline: Argon2id KDF and modern identity prelogin |
| `< 1.28.0` | Unsupported: `doctor` warns the server is below the minimum baseline |

Official Bitwarden Cloud (`vault.bitwarden.com` / `vault.bitwarden.eu`) and self-hosted official Bitwarden (`server.name == "Bitwarden"`, compatibility version `>= 2024.12.0`) support `ssh-key-vault-item` natively without flags.

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
      "server_name": "Vaultwarden",
      "server_vendor_version": "1.37.4",
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
    `server_name` and `server_vendor_version` are optional and omitted when the upstream server does not report a nested `server` object.
- **CLI Subcommand**:
  - `omawarden server capabilities [--refresh] [--json]`
  - Interactive mode prints a clean summary of server identity, compatibility version, vendor version, active features, and recommendations.
  - Machine mode (`--json`) emits the standard JSON envelope specified above.

## Consequences

- **Positive**:
  - Transparent visibility into upstream server version, feature flags, and Git commit hashes.
  - Clear, non-intimidating guidance for self-hosters to enable modern features like `ssh-agent-v2`.
  - Zero disruption to core vault operations and zero plain secret exposure (only public server metadata is probed and cached).
- **Trade-off**:
  - Adds one lightweight, non-blocking HTTP GET to the sync lifecycle.
  - Requires maintaining the known capability matrix in Omawarden as upstream Bitwarden evolves new flags.
