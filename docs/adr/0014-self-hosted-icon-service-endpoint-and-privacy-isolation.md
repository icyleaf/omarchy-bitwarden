# ADR 0014: Self-Hosted Icon Service Endpoint Resolution and Privacy Isolation

## Status
Accepted

## Context

The `omarchy-bitwarden` desktop overlay provides optional website icon (favicon) rendering for login items (`show_website_icons`). Previously, icon URLs were statically constructed using the official Bitwarden cloud icon CDN:

```javascript
return "https://icons.bitwarden.net/" + domain + "/icon.png"
```

While functional for users connecting to the official Bitwarden cloud service (`https://vault.bitwarden.com`), this design suffered from critical security and operational deficiencies when interacting with self-hosted Bitwarden and Vaultwarden instances:

1. **Intranet Domain Leakage to External Services**:
   Self-hosted vaults frequently contain credentials for internal enterprise or homelab services (e.g., `jira.corp.internal`, `gitlab.mycompany.net`, `router.local`, or private IP ranges). Routing icon requests for these items to `icons.bitwarden.net` leaked private domain names and internal infrastructure topology to public Bitwarden servers.

2. **Failure to Leverage Self-Hosted Icon Capabilities**:
   Both Vaultwarden and official self-hosted Bitwarden deployments feature built-in icon caching and proxying services hosted at `${server_url}/icons/{domain}/icon.png`. Bypassing this endpoint prevented self-hosted users from retrieving icons cached within their private networks.

3. **Misleading Settings Disclosure**:
   The settings interface hardcoded a warning stating that icons are fetched from `icons.bitwarden.net`, which was inaccurate for self-hosted configurations.

---

## Decision

We introduce an automated endpoint resolution policy and privacy barrier for website icons:

### 1. Centralized Endpoint Resolution (`components/iconpolicy.js`)
- **Official Cloud Classification (`isOfficialServer`)**:
  Identifies whether the configured server URL targets official Bitwarden cloud domains (`bitwarden.com`, `bitwarden.eu`, or subdomains).
- **Endpoint Derivation (`resolveIconUrl`)**:
  - **Official Cloud**: Resolves to `https://icons.bitwarden.net/{domain}/icon.png`.
  - **Self-Hosted**: Normalizes `server_url` (stripping `/api`, `/identity`, and trailing slashes) and constructs the self-hosted icon proxy path:
    ```
    ${normalized_server_url}/icons/${domain}/icon.png
    ```

### 2. Strict Privacy Isolation (Fail-Closed)
- When using self-hosted instances, if the self-hosted icon service fails to load an icon (e.g. HTTP 404, network timeout, air-gapped network, or server-side `ENABLE_ICON_SERVICE=false`), the client **strictly fails closed** by displaying the default FontAwesome category icon (`\uf084`).
- Under no circumstances does the client fall back to querying public services (`icons.bitwarden.net`) for self-hosted items.

### 3. Reactive UI & Settings Integration
- `OmarchyBitwarden.qml` derives `effectiveServerUrl` from active authentication state or configuration and passes `serverUrl` down to `VaultItemList.qml` and `ItemInspector.qml`.
- `SettingsModal.qml` dynamically tailors its privacy disclosure notice:
  - Official cloud: `"Fetches icons from icons.bitwarden.net, revealing your saved sites to Bitwarden."`
  - Self-hosted: `"Fetches icons directly from your vault server (<host>)."`

---

## Consequences

### Positive
- **Zero Third-Party Leakage**: Self-hosted vaults never transmit internal domains or metadata to public Bitwarden infrastructure.
- **Support for Air-Gapped & Offline Deployments**: Works seamlessly within intranet environments hosting local icon proxies.
- **Accurate Privacy Transparence**: Users are clearly informed about the exact origin of network requests made on their behalf.

### Trade-offs
- If a self-hosted instance disables its built-in icon service or lacks external internet access, icons for public sites will not display, falling back to category icons. This trade-off is accepted as mandatory for security and domain privacy.
