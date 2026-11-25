# ADR 0037: Daemon Capabilities and Three-Tier Protocol Evolution

## Status
Accepted

## Context
Under [ADR 0028](0028-daemon-wire-protocol-versioning-and-decoupled-lifecycle.md), [ADR 0032](0032-cipher-custom-fields-and-multi-uri-mutation.md), and [ADR 0036](0036-full-cipher-type-mutation-and-schema-v3.md), the local **Daemon Protocol** evolved through two integer fields in `ping` (`protocol_version` and `schema_version`) plus ad-hoc top-level booleans (`ssh_write_receipt`, `account_activation_v1`).

As multiple additive capabilities land within a single release cycle (for example, `vault get`, Attachment V2 upload/delete, Vault export/import, and Organization write operations), relying exclusively on monotonic `schema_version` bumps or additional top-level booleans creates two problems:
1. **Schema Version Churn**: Incrementing `schema_version` for every PR within one release cycle forces unnecessary version inflation while still failing to distinguish which specific additive capability a running daemon supports.
2. **Ad-hoc Boolean Proliferation**: Adding top-level boolean flags to `ping` fragments feature discovery and encourages inconsistent client checks.

## Decision

### 1. Three-Tier Daemon Protocol `ping` Contract
The local **Daemon Protocol** `ping` response maintains three distinct layers:

1. **`protocol_version`** (ADR-0028): Monotonic integer reserved strictly for breaking wire-framing or transport changes.
2. **`schema_version`** (ADR-0032 / ADR-0036): Coarse-grained baseline incremented at most once per release cycle that introduces new or modified Daemon IPC actions or payloads.
   - Additive capabilities landing before the next release tag (e.g. `0.13.0`) remain on `CURRENT_SCHEMA_VERSION = 3`.
   - After a release is tagged, the first PR in the next development cycle that adds or modifies a Daemon IPC contract increments `CURRENT_SCHEMA_VERSION`, and subsequent PRs in that cycle remain on that baseline.
3. **`capabilities: Vec<String>` (**Daemon Capabilities**, new)**: Authoritative list of fine-grained local Daemon Protocol feature identifiers advertised by the running daemon (seeded with `"cipher_mutation_v3"`, `"folder_crud"`, `"login_totp_uri_match"`, and `"vault_get"`).
   - Existing top-level booleans (`ssh_write_receipt`, `account_activation_v1`) remain for backward compatibility.
   - All new local daemon features MUST be advertised via `ping.capabilities`; no new ad-hoc top-level capability booleans may be added to `ping`.

### 2. Fail-Closed Runtime Capability Gating & Auto-Restart
Clients invoking a capability-gated Daemon Protocol action MUST verify `ping["capabilities"]` contains the required capability identifier before sending the request:
1. If `ping["capabilities"]` contains the target capability, proceed normally.
2. If the capability is absent (or `capabilities` is missing on an older daemon), attempt the existing standalone on-demand auto-restart (`{"action": "stop", "admin": true}` -> restart daemon -> re-`ping`) and re-verify `ping["capabilities"]`.
3. If the capability is still absent after restart, or if `stop` is rejected because the daemon is hosted in-process (ADR-0028), fail closed with an actionable error naming the missing capability. Clients MUST NEVER silently downgrade or dispatch unsupported payloads.

### 3. Terminology Boundary
**Daemon Capabilities** (`ping.capabilities`) strictly describe local Omawarden Daemon Protocol IPC features and are distinct from **Capability Discovery** and the **Server Capability Matrix** (ADR-0031), which track upstream Bitwarden/Vaultwarden server feature flags and API versions.

## Consequences

### Positive
- Eliminates per-PR `schema_version` churn within a release cycle while preserving coarse-grained release baselines.
- Gives CLI and desktop clients a single, uniform, fail-closed mechanism to gate new IPC actions and recycle stale standalone daemons cleanly.
- Prevents proliferation of ad-hoc boolean flags on `ping`.

### Trade-off
- Clients and daemons must keep capability identifier strings consistent across the protocol boundary (mitigated by centralizing `DAEMON_CAPABILITIES` in the protocol module).
