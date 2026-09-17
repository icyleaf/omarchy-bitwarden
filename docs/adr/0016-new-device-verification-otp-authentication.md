# ADR 0016: Support New Device Verification OTP Challenge During Master Password Authentication

## Status
Accepted

## Context
Bitwarden identity servers enforce email verification for logins originating from unrecognized devices or client installations when standard two-factor authentication (2FA) is not explicitly enabled on the account.

When a login request (`/identity/connect/token`) encounters an unrecognized device or client:
1. The server returns an HTTP 400 Bad Request response containing:
   - `"error": "device_error"`
   - `"error_description": "New device verification required"`
   - `"ErrorModel": { "Message": "new device verification required" }`
2. Bitwarden dispatches an email containing a temporary verification code (OTP) to the account's registered email address.
3. To complete the login, the client must resubmit the master password credentials with the code provided in the `newDeviceOtp` form parameter.

Previously, `omawarden` only supported the `twoFactorToken` and `twoFactorProvider` parameters. When users without account-level 2FA logged in on a new device or fresh install, `omawarden` failed with a generic error or failed authentication, leaving users unable to complete the login flow via the overlay UI or CLI (see issue #164).

## Decision
1. **Challenge Detection (`ApiError::NewDeviceVerificationRequired`)**:
   - In `BitwardenApiClient::login_password`, parse HTTP 400 error payloads for `"device_error"` or `"new device verification required"`.
   - Distinguish this challenge from standard 2FA provider challenges (`ApiError::TwoFactorRequired`) by returning `ApiError::NewDeviceVerificationRequired`.
   - Surface `new_device_verification_required: Some(true)` in `AuthResult`.

2. **`newDeviceOtp` Parameter Support**:
   - Extend `BitwardenApiClient::login_password` and `AuthManager::login_password` to accept `new_device_otp: Option<&str>`.
   - When present, append `newDeviceOtp` to the form body sent to `/identity/connect/token`.

3. **Automatic Fallback Retry**:
   - If a caller (such as a generic script, CLI flag `--code`, or standard 2FA input field) submits a code as `two_factor_token` without specifying `new_device_otp`, and the server returns `New device verification required`, `BitwardenApiClient::login_password` automatically retries the request once with `newDeviceOtp` set to the provided token. This prevents unnecessary roundtrips and user friction.

4. **Interactive CLI Guidance**:
   - In interactive mode (`omawarden auth login`), if master password authentication returns `new_device_verification_required`, prompt specifically:
     `Enter New Device Verification Code (check your email): `
   - In JSON payload parsing (`parse_auth_payload`), extract `new_device_otp` and `newDeviceOtp`.

5. **QML & Desktop Overlay Integration**:
   - In `OmarchyBitwarden.qml` and `components/AuthView.qml`, track `isNewDeviceVerification`.
   - When the backend signals `new_device_verification_required`, dynamically update the code input label to `"New Device Verification Code (check email):"` and ensure the entered code is submitted as `new_device_otp` in the JSON auth payload.

## Consequences
- **Seamless New Device Login**: Users logging in from new installations or IP addresses can successfully verify their device using the code emailed by Bitwarden.
- **Clear User Experience**: Both the desktop UI and CLI clearly communicate that an email verification code is expected, rather than confusing it with an authenticator TOTP app code.
- **Backward Compatibility**: Accounts with standard 2FA (TOTP, YubiKey, Duo, email 2FA) continue using the existing `twoFactorToken` flow without regression.
