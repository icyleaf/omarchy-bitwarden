# ADR 0008: Server Switching Credential and Cache Invalidation Lifecycle

## Status
Accepted

## Context
When managing Bitwarden credentials across multiple environments (such as switching between official Bitwarden cloud `https://vault.bitwarden.com` and a self-hosted Vaultwarden instance), changing the configured server URL previously only updated the `server_url` field in `config.json`.

This created critical security, data integrity, and user experience issues:
1. **Cross-Server Data Contamination**: The local ciphertext cache (`data.json`), in-memory daemon index, and temporary decrypted attachment previews (`/tmp/omarchy-bitwarden/attachments/`) retained the vault items, ciphers, folders, and organization keys belonging to the previous server.
2. **Stale Session & Authentication Mismatches**: OAuth2 access tokens, refresh tokens, and API key secrets persisted in the OS Keyring (`service=omarchy-bitwarden`) and `data.json` were issued by the old server. Attempting to synchronize or check status against the new server with old tokens triggered HTTP 401/404 errors, broken silent re-auth loops, or silent failure modes.
3. **Stale Credential Pre-filling**: Stored user email and API client ID from the old server remained in `config.json` and were displayed on the login screen, risking credential submission against the wrong server instance.

## Decision
1. **Normalized Server URL Comparison**:
   - In `ConfigManager::update_config`, normalize both existing and incoming server URLs by stripping whitespace and trailing slashes (`trim().trim_end_matches('/')`).
   - If the normalized server URL has not changed (e.g. updating unrelated settings like `auto_lock_minutes`, or saving `https://vault.bitwarden.com/` when `https://vault.bitwarden.com` is configured), the update proceeds without purging data.

2. **Atomic Multi-tier Cascade Purge on Server Change**:
   When a genuine server URL change is detected (`!new_server.is_empty() && old_server != new_server`):
   - **Configuration (`config.json`)**: Reset `identity_url` to `None` (preventing an old server's identity endpoint from contaminating the new server unless explicitly provided). The remembered login email (`email`) in `config.json` is preserved for user convenience across server changes, whereas session-associated credentials in the vault storage and keyring are purged.
   - **Local Ciphertext Cache (`data.json`)**: Atomically delete `data.json` (`fs::remove_file`) so no ciphers, user keys, or authenticated user session records (`storage.user_email`) from the previous server remain on disk.
   - **System Keyring**: Execute `keyring_mgr.clear_all()` and `keyring_mgr.clear_session()`, purging all bearer tokens (`access_token`, `refresh_token`), API secrets (`api_secret`), and legacy session entries matching `service=omarchy-bitwarden`.
   - **Daemon In-Memory Scrubbing**: Send `{"action": "stop"}` IPC to the running `omawarden` daemon process. The daemon exits immediately, destroying all decrypted in-memory vault items, cryptographic keys, and active search indices. The CLI will automatically respawn a clean daemon upon the next request.
   - **Decrypted Temporary Files**: Call `attachment::clear_preview_attachments(None)` to recursively delete any ephemeral decrypted attachment files cached in `/tmp/omarchy-bitwarden/attachments/`.

3. **Frontend UI Reactive Synchronization**:
   - In `OmarchyBitwarden.qml`, upon completion of `configSetProc`, immediately invoke `root.refreshAuthStatus()`.
   - The CLI responds with `status: "unauthenticated"`, `has_session: false`, and `user_email: ""`.
   - The UI resets `rawVaultItems = []` and `filteredItems = []`, clearing any stale items from the view, and transitions directly to a clean login screen for the new server.

## Consequences
- **Positive**:
  - **Zero Cross-Server Contamination**: Eliminates any possibility of mixing vault items, organization keys, or attachments across different Bitwarden instances.
  - **Security & Privacy Guarantee**: Complete erasure of bearer tokens, API secrets, and cached credentials upon switching instances.
  - **Predictable UX**: Users are presented with a clean login form targeted at the new server without confusing authentication failures caused by mismatched tokens.
- **Trade-off**:
  - Switching servers forces a full re-authentication and fresh vault synchronization on the newly configured instance (which is the intended and secure behavior).
