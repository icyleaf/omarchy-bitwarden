# ADR 0018: Support WebAuthn / FIDO2 Security Key Two-Factor Authentication (Provider 7)

## Status

Accepted

## Context

Bitwarden and Vaultwarden identity servers support WebAuthn / FIDO2 hardware security keys (such as YubiKey, Nitrokey, SoloKey, and Feitian keys) as two-factor authentication provider type 7 (`TwoFactorProviderType::WebAuthn`).

When an account requires WebAuthn 2FA:

1. The identity server returns an HTTP 400 Bad Request challenge containing:
   - `"error": "invalid_grant"`
   - `"TwoFactorProviders": [..., 7, ...]`
   - `"TwoFactorProviders2": { "7": { "publicKey": { "challenge": "...", "rpId": "...", "allowCredentials": [...] } } }`
2. The client must perform a WebAuthn CTAP2 assertion using the connected FIDO2 security key, requiring physical user presence (touching the key).
3. The resulting W3C `PublicKeyCredential` response (containing `id`, `rawId`, `type: "public-key"`, and `response: { authenticatorData, clientDataJSON, signature, userHandle }`) is serialized as a JSON string and submitted in the `twoFactorToken` parameter with `twoFactorProvider=7`.

As part of resolving [Issue #165](https://github.com/icyleaf/omarchy-bitwarden/issues/165) ("Support multiple 2FA providers instead of hardcoding Authenticator 0"), after implementing Email 2FA (provider 1 in [ADR 0017](0017-email-and-pluggable-2fa-providers.md)), WebAuthn / Security Key authentication was required to support phishing-resistant hardware authenticators. Previously, `omawarden` lacked WebAuthn challenge parsing and CTAP2 assertion capabilities, failing completely on accounts where security keys were configured.

## Decision

1. **WebAuthn Challenge Parsing (`parse_webauthn_challenge`)**:
   - Implement robust parsing for `TwoFactorProviders2["7"]` compatible with both official Bitwarden cloud servers and Vaultwarden self-hosted instances.
   - Extract `challenge`, `rp_id` (with fallback to server domain), normalized RFC 6454 origin (`url.origin().ascii_serialization()`), and allowed credential IDs (`allowCredentials`, supporting both array of string IDs and array of `{ "id": "...", "type": "public-key" }` objects).

2. **CTAP2 Assertion Execution via `libfido2` Tools**:
   - Integrate with standard `libfido2` utilities (`fido2-token` and `fido2-assert`) natively available across Linux distributions.
   - Device Discovery: `fido2-token -L` enumerates connected security keys matching `/dev/hidraw*`.
   - Hardware Assertion: Execute `fido2-assert -G -t pin=false <device_path>` to initiate user presence verification without requesting PIN prompts (matching Bitwarden's 2FA assertion specification).
   - Zero-Argv Principle (Rule 11): Hash of `clientDataJSON`, `rp_id`, and Base64-decoded `credentialId` are delivered exclusively over standard input (`child.stdin`), preventing sensitive cryptographic material from leaking into `/proc/<pid>/cmdline`.
   - CBOR Byte-String Unwrapping: `fido2-assert -G` outputs CBOR-encoded (major type 2) `authenticatorData`. `omawarden` unwraps the CBOR byte-string header before Base64URL encoding to produce the exact raw byte structure required by W3C WebAuthn and Bitwarden servers.

3. **Smart Provider Selection & Seamless Fallback**:
   - In `AuthManager::login_password`, if provider 7 is among the server's demanded 2FA methods and a physical security key is detected (`Fido2Status::Available`), the system defaults to WebAuthn (provider 7) and initiates hardware assertion.
   - If no security key is detected or `libfido2` is absent, the system automatically falls back to Authenticator TOTP (0) or Email (1) if enabled on the account.

4. **Desktop UI & Continuous Bidirectional Hotplug Detection**:
   - `components/AuthView.qml` introduces a dedicated Security Key verification card displaying live status badges (`fido2Status`: `available`, `no_device`, `tool_not_found`).
   - A bidirectional 1.5s hotplug timer runs while the WebAuthn tab is active, detecting both when a key is newly plugged in and when an inserted key is suddenly unplugged, updating the submit button state in real-time.
   - The submit button is disabled when `no_device` (`"Insert Security Key to Verify"`) and enabled when `available` (`"Verify with Security Key"`). During assertion, the polling timer pauses to prevent device contention, and the button shows `"Waiting for key touch..."`.

5. **Optional Dependency Packaging & One-Click Terminal Installation**:
   - Keep `libfido2` as an optional dependency (`optdepends` in Arch Linux PKGBUILD) so users without hardware keys are not forced to install extra packages.
   - If `libfido2` tools are not detected (`tool_not_found`), the UI provides a **⚡ Install libfido2** button that invokes `omarchy-launch-floating-terminal-with-presentation` running `paru / yay / pacman -S --needed libfido2`.
   - Upon terminal exit, `installDependenciesProc.onExited` automatically invokes `root.doCheckFido2Status()` to refresh the environment and transition the view without requiring an app reload or restart.

6. **Log Redaction & Process Hygiene**:
   - Structured logging (`crate::log_info!`) formats touch prompts and verification notices cleanly for QML consumption without generating spurious error logs.
   - Both Rust and QML log sanitizers (`sanitize_log_message`, `sanitizeLog`) redact 2FA codes, OTPs, and authentication tokens (`"code"`, `"twoFactorToken"`, `"newDeviceOtp"`).

## Consequences

- **Phishing-Resistant Hardware Security Key Support**: Users with YubiKey, Nitrokey, SoloKey, or other FIDO2 authenticators can authenticate seamlessly via GUI and CLI.
- **Zero Friction Onboarding**: Users needing `libfido2` can install it with one click directly from the login screen in an Omarchy floating terminal.
- **Zero Regression**: Standard password logins, TOTP (provider 0), Email 2FA (provider 1), and New Device Verification (ADR 0016) remain completely unaffected.

## References

- [Issue #165: Support multiple 2FA providers instead of hardcoding Authenticator (0)](https://github.com/icyleaf/omarchy-bitwarden/issues/165)
- [PR #168: feat(auth): support WebAuthn security key 2FA (provider 7)](https://github.com/icyleaf/omarchy-bitwarden/pull/168)
- [ADR 0017: Support Email and Pluggable Two-Factor Authentication (2FA) Providers](0017-email-and-pluggable-2fa-providers.md)
- [W3C Web Authentication (WebAuthn) Specification](https://www.w3.org/TR/webauthn-2/)
