# ADR 0007: Keyring Credential Persistence and Silent Re-authentication Architecture

## Status
Accepted

## Context
In previous releases, `omawarden` persisted OAuth2 `access_token` and `refresh_token` in plaintext inside `~/.config/omarchy/plugins/icyleaf.bitwarden/data.json`. Although protected with `0600` file permissions, writing bearer tokens to disk exposes credentials to filesystem inspection, backups, or sync utilities, violating pure zero-knowledge local storage principles.

Furthermore, when authenticating via Bitwarden API Key (`client_credentials` grant), the Bitwarden server issues an `access_token` with an expiration window of ~2 hours without providing an OAuth2 `refresh_token`. Consequently, users were forced to re-enter their API Key (`client_id` and `client_secret`) every 2 hours, disrupting the desktop launcher workflow.

While `KeyringManager` integrated with the FreeDesktop Secret Service via `secret-tool`, it was previously restricted to a single monolithic `account=session` slot and was not utilized for token lifecycle management, API secrets, or automated re-authentication.

## Decision
1. **Multi-Slot Structured Secret Service Store (`KeyringManager`)**:
   - Deepen `KeyringManager` to store credentials with specific attribute pairs:
     - **Access Token**: `service=omarchy-bitwarden kind=access_token`
     - **Refresh Token**: `service=omarchy-bitwarden kind=refresh_token`
     - **API Secret**: `service=omarchy-bitwarden kind=api_secret server_url=<url> client_id=<client_id>`
   - Maintain backward compatibility with legacy `account=session` lookups.
   - Implement `clear_all()` using `secret-tool clear service omarchy-bitwarden` to atomically purge all service credentials from the OS keyring upon `auth logout`.
   - Preserve protected standard input (`stdin`) streaming for all `secret-tool store` invocations to prevent secret leakage in process arguments (`argv`).

2. **Zero Plaintext Tokens in Local Disk Storage (`data.json`)**:
   - Remove plaintext `access_token` and `refresh_token` from `data.json` when the system keyring is available.
   - `data.json` functions strictly as an encrypted zero-knowledge cache containing encrypted keys (`enc_user_key`, `enc_private_key`), encrypted ciphers, organizations, folders, and non-sensitive identifiers (`server_url`, `user_email`, `client_id`).
   - Introduce automated migration: on status check or login, if plaintext tokens exist in `data.json` and the keyring is available, transfer them to the keyring and scrub them from disk.
   - If the system keyring is absent (e.g. headless environment without D-Bus Secret Service), gracefully fall back to local encrypted file storage with explicit security warnings.

3. **Silent Background Re-authentication Flow**:
   - During vault synchronization (`sync`) and status evaluations (`get_status`):
     1. Retrieve the active `access_token` from Keyring (falling back to storage if needed).
     2. If the token is expired (detected via JWT `exp` claims) or an API request returns HTTP 401/403:
        - First, attempt OAuth2 renewal using the keyring-stored `refresh_token`.
        - If no refresh token exists (standard for API Key `client_credentials` grant) or refresh fails, retrieve the stored API `client_secret` from Keyring for the recorded `client_id` and `server_url`.
        - Silently re-authenticate against the server (`login_apikey`), obtain new tokens, save them into Keyring, and seamlessly resume vault synchronization without user interruption.
     3. If all renewal strategies fail, invalidate expired tokens, lock the in-memory cache, and transition the session to `unauthenticated`.

4. **Complete Credential Lifecycle Cleanup**:
   - Invoking `auth logout` triggers `keyring_mgr.clear_all()`, completely erasing access tokens, refresh tokens, API secrets, and legacy session slots from the OS keyring, while resetting `data.json`.

## Consequences
- **Positive**:
  - **Zero Bearer Tokens on Disk**: Eliminates plaintext tokens from `data.json`, ensuring local disk storage contains only zero-knowledge ciphertexts.
  - **Frictionless API Key Experience**: API Key users no longer suffer from 2-hour session expiration prompts; background re-authentication keeps the vault synchronized seamlessly.
  - **Hardened Cleanup**: Complete and atomic wiping of credentials on logout via FreeDesktop Secret Service.
- **Trade-off**:
  - Requires a running Secret Service daemon (`gnome-keyring`, `keepassxc`, etc.) for keyring persistence. Fallback to local storage is retained for environments without Secret Service.
