# ADR 0017: Support Email and Pluggable Two-Factor Authentication (2FA) Providers

## Status

Accepted

## Context

Bitwarden accounts can be configured with multiple two-factor authentication (2FA) providers, including Authenticator Apps (TOTP, provider 0), Email (provider 1), Duo (provider 2), YubiKey OTP (provider 3), and WebAuthn/FIDO2 (provider 7).

When a Bitwarden identity server requires 2FA:

1. The server returns HTTP 400 with `"error": "invalid_grant"`, `"TwoFactorProviders": [...]`, and optional `"TwoFactorProviders2": {...}`.
2. For accounts with Email 2FA (provider 1):
   - The Bitwarden server automatically sends an email containing a 6-digit verification code to the registered email address upon the initial login attempt.
   - To complete the login, the client must resubmit credentials with `twoFactorProvider=1` and `twoFactorToken=<code>` (or optionally trigger resending the email via `/identity/connect/token` with `twoFactorEmailToken=true`).
3. Previously, `omawarden` hardcoded `twoFactorProvider=0` (Authenticator) whenever 2FA was triggered. If a user only had Email 2FA enabled, or preferred Email 2FA, the login failed because provider 0 was rejected by the server (see issue #165).

## Decision

1. **Pluggable Provider Architecture (`TwoFactorProviderType`)**:
   - Introduce `TwoFactorProviderType` in `omawarden::api`:
     - `Authenticator = 0`
     - `Email = 1`
     - `Duo = 2`
     - `Yubikey = 3`
     - `WebAuthn = 7`
   - Extend `BitwardenApiClient::login_password` and `AuthManager::login_password` with `two_factor_provider: Option<i32>`.
   - Propagate `two_factor_provider` in `AuthResult`. When the server reports active providers, `omawarden` determines the primary/effective provider (e.g. defaulting to provider 1 when only email is enabled, or provider 0 when authenticator is enabled).

2. **Automatic Retry with Server-Demanded Provider**:
   - If a caller submits a 2FA token without specifying the provider (defaulting to provider 0), and the server rejects it indicating only Email 2FA is configured (`TwoFactorProviders: [1]`), `BitwardenApiClient::login_password` automatically retries once with `twoFactorProvider=1`. This eliminates friction for users who enter their email code directly without needing to configure options.

3. **Email 2FA Resend Capability**:
   - Add `BitwardenApiClient::send_two_factor_email` and `AuthManager::send_two_factor_email` to allow re-triggering the email verification dispatch if the initial email expired or was not received.

4. **CLI Interactive and Non-Interactive Support**:
   - Update `parse_auth_payload` to parse `two_factor_provider`, `twoFactorProvider`, or `provider` from JSON payloads.
   - In interactive login mode (`omawarden auth login`), inspect the active providers from the 2FA challenge:
     - If provider 1 is active, prompt: `Enter Email Two-Factor Verification Code (check your email): `.
     - If provider 3 is active, prompt: `Touch your YubiKey or enter OTP: `.
     - Otherwise, prompt: `Enter Two-Factor (2FA) Code: `.

5. **QML UI Support**:
   - In `components/AuthView.qml` and `OmarchyBitwarden.qml`, expose `twoFactorProvider` and `availableTwoFactorProviders`.
   - When Email 2FA (provider 1) is active, dynamically update the input label to `"Email 2FA Verification Code:"`.
   - Ensure the selected provider is forwarded in the authentication payload upon form submission and cleared on logout/reset.

## Consequences

- **Email 2FA Fully Functional**: Users with Bitwarden Email 2FA can smoothly log in via both the GUI overlay and the CLI.
- **Extensibility**: The codebase now has clean, structured support for Bitwarden's provider enum, laying the foundation for additional providers (e.g., YubiKey OTP, Duo).
- **Zero Regression**: Accounts using standard Authenticator TOTP (provider 0) or New Device Verification (ADR 0016) remain unaffected.
