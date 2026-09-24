# ADR 0021: Adopt Operating System Native Trust Store for TLS and Reject Insecure Bypass

## Status
Accepted

## Context
When connecting to Bitwarden or self-hosted Vaultwarden instances, `omawarden` relies on HTTPS for confidential transport of derived master password hashes, two-factor authentication tokens, and OAuth2 bearer access/refresh tokens.

Previously, `omawarden` compiled `reqwest` with default `rustls-tls` features:
`reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "blocking"] }`

In this configuration, `rustls` exclusively loaded compile-time static `webpki-roots` (a snapshot of public Mozilla root certificate authorities). It did not query the host operating system certificate trust store (such as `/etc/ca-certificates/extracted/tls-ca-bundle.pem` or `/etc/ssl/certs/` on Arch Linux / Omarchy).

This caused severe usability issues for self-hosted instances on private local area networks (LANs) and enterprise environments (Issue #203):
1. Users who deploy Vaultwarden with certificates issued by private, internal, or homelab Certificate Authorities (CAs) and install those CAs system-wide into Arch Linux / Omarchy found that while `curl`, web browsers, and other native tools like `rbw` connected seamlessly, `omawarden` rejected connections with unknown issuer errors.
2. A naive proposal suggested adding an `insecure_tls` boolean switch or `danger_accept_invalid_certs(true)` configuration option to bypass TLS verification. However, this is an anti-pattern that violates project security invariants (Rule 4 of the Security Handbook) and creates dangerous exposure to Man-in-the-Middle (MITM) credential theft on local networks.

## Decision
1. **Switch to OS Native Trust Store (`rustls-tls-native-roots`)**:
   - Update `omawarden/Cargo.toml` to use `rustls-tls-native-roots`:
     `reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls-native-roots", "blocking"] }`
   - At runtime, `omawarden` automatically queries the platform-native certificate store (via `rustls-native-certs` and `openssl-probe`), allowing any CA trusted by the host OS to be trusted by `omawarden` with zero user configuration.

2. **Categorically Reject `insecure_tls` / `danger_accept_invalid_certs`**:
   - In accordance with our security audit standards and the project Security Handbook (Rule 4), no configuration option, CLI flag, or runtime switch will be provided to disable TLS verification.
   - Any untrusted certificate, hostname mismatch, or expired certificate fails closed immediately.

3. **Consolidate HTTP Client Construction**:
   - Abstract a central `build_http_client(timeout)` factory function in `omawarden::api` shared by API requests, attachment downloads, and server reachability health checks, guaranteeing consistent security headers, timeout policies, and TLS trust roots across all outbound traffic.

## Consequences
- **Seamless Self-Hosted Vaultwarden Compatibility**: Users with internal or enterprise CAs installed system-wide in Arch Linux / Omarchy can immediately log in, sync, download attachments, and check health without extra configuration.
- **Dynamic Security Updates**: Operating system certificate updates and CA revocations (e.g. via `pacman -Syu ca-certificates`) take effect immediately at runtime without requiring an engine recompile or release.
- **Uncompromised Transport Security**: Full TLS verification (SAN matching, certificate chaining, validity periods) remains 100% enforced, completely preventing LAN-based MITM attacks on password hashes and bearer tokens.
- **Architectural Parity with Industry Standard**: Adopts the same proven, secure trust model as `rbw` (`doy/rbw`).
