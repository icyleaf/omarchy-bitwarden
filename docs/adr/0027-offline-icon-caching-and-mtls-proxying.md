# ADR 0027: Offline-First Icon Caching and Engine-Managed mTLS Delivery

## Status
On Hold (Proposed)

## Context
ADR 0014 resolved self-hosted Bitwarden/Vaultwarden icon privacy by directing website icon requests away from public Bitwarden CDNs to the self-hosted icon proxy (`${server_url}/icons/{domain}/icon.png`). Subsequently, ADR 0023 introduced mTLS client certificate authentication into `omawarden`'s `reqwest` HTTP client for enterprise and homelab gateways enforcing mutual TLS.

However, real-world deployment on mTLS-protected self-hosted instances revealed a fundamental architectural gap (GitHub Issue #267):
1. **Frontend Network Isolation from mTLS**: The desktop overlay is implemented in pure QML running within the host desktop shell runtime. QML's native `Image` element issues standard HTTPS requests via `QNetworkAccessManager` without client certificate credentials. When communicating with an mTLS-protected gateway, these requests fail closed with HTTP 403 Forbidden.
2. **Absence of Persistent Disk Caching in Qt Quick**: Qt Quick's `Image { cache: true }` retains decoded textures strictly in RAM/VRAM. Without a custom C++ application injecting `QNetworkDiskCache`, the frontend issues repeated network calls across sessions.
3. **Domain Privacy & Memory Safety**: Plaintext domain filenames in user cache directories leak internal network topology, while unbounded concurrent icon downloads during vault synchronization risk causing severe daemon memory spikes.

---

## Decision

We establish an engine-managed, offline-first icon caching architecture where `omawarden` acts as the trusted network proxy and local storage manager for website icons.

### 1. Engine-Managed Network Delivery & XDG Storage
- `omawarden` utilizes its centralized HTTP client factory (`build_http_client_with_context`) to download icons, inheriting mTLS client certificate authentication, origin gating, and system CA trust.
- Downloaded icons are persisted under the standard Linux XDG Cache directory:
  ```
  $XDG_CACHE_HOME/omawarden/icons/
  ```
  (defaulting to `~/.cache/omawarden/icons/`).
- **Cryptographic Filename Hashing**: Filenames are strictly hashed as:
  ```
  sha256(server_origin + "/" + domain).png
  ```
  This prevents local plaintext inspection of intranet service hostnames on disk and enforces origin isolation across server switches.

### 2. Decoupled Asynchronous Synchronization & Bounded Memory
- **Non-Blocking Vault Sync**: `omawarden vault sync` decrypts ciphers, updates the local database, and returns immediately to unfreeze the UI. It never blocks on icon network latency.
- **Daemon-Managed Concurrency**: In the background, `omawarden daemon` inspects synced login items for missing or expired icons. Concurrency is strictly bounded (maximum 3–4 concurrent HTTP streams) with direct disk streaming to prevent heap and RSS memory spikes.
- **Tombstone Failure Backoff**: If the vault server returns HTTP 404, empty data, or persistent network errors, a 0-byte tombstone cache file is recorded with a 7-day backoff to prevent continuous retry loops for sites lacking favicons.

### 3. Precomputed Data Contract with QML Overlay
- To eliminate expensive pure-JavaScript SHA-256 computations in QML, `omawarden vault list` and `omawarden vault search` calculate and attach the target local filesystem path in the item JSON payload:
  ```json
  "icon_path": "/home/user/.cache/omawarden/icons/<hash>.png"
  ```
- `VaultItemList.qml` and `ItemInspector.qml` load the local file via `file://`. If the file does not yet exist or is invalid, the UI fails closed immediately to the default category glyph (`\uf084`) without delay or jitter.

### 4. Cache Lifecycle, Purge Semantics, and Privacy Isolation
- **Freshness Window**: Icons carry a 30-day freshness window based on file `mtime`. Expired icons are lazily refreshed during subsequent background sync passes.
- **Granular Purge CLI**:
  - `omawarden vault purge --icons`: Selectively purges the `$XDG_CACHE_HOME/omawarden/icons/` directory without affecting encrypted vault data or tokens.
  - `omawarden vault purge`: Atomically purges both local encrypted vault storage (`data.json`) and the icon cache directory.
- **Fail-Closed Global Privacy**: When `show_website_icons` is set to `false`, `omawarden` completely suppresses background icon network activity, and the overlay suppresses all local icon rendering.

---

## Consequences

### Positive
- **Resolves mTLS Gateway Blockage (#267)**: All icon fetching routes through `omawarden`'s authenticated HTTP client, seamlessly supporting client certificates.
- **Offline-First & 60fps Scrolling**: Local `file://` reading eliminates network latency and flickering during fast list scrolling.
- **Zero Plaintext Domain Leakage on Disk**: Hashed filenames prevent local snooping of private domains.
- **Bounded Resource Consumption**: Background downloading throttles memory footprint and avoids spiking daemon RAM.

### Trade-offs
- Modest local disk usage in `$XDG_CACHE_HOME/omawarden/icons/`, easily reclaimable via `omawarden vault purge --icons`.
