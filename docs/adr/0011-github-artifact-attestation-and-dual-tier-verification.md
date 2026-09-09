# ADR 0011: GitHub Artifact Attestation and Dual-Tier Release Verification

## Status
Accepted

## Context

The `omarchy-bitwarden` desktop plugin downloads pre-compiled native engine binaries (`omawarden`) from GitHub Releases via `scripts/download-engine.sh`.

Previously, download verification relied solely on comparing the downloaded archive against a `.sha256` checksum file published alongside the archive in the same GitHub Release. While this protects against incomplete downloads, proxy caching errors, and network corruption, it has a significant architectural limitation in the supply chain threat model:

1. **Vulnerability to Release Asset Tampering**:
   Because the `.sha256` checksum file is co-located with the release archive, any attacker who gains write access to the GitHub repository or release assets can simultaneously overwrite both the binary archive and the checksum file. A client verifying only `sha256sum` would compute a valid hash matching the attacker's forged file and execute untrusted code.

2. **Absence of Cryptographic Provenance Verification**:
   Users and the desktop UI had no mechanism to prove that an archive actually originated from a clean, automated build in GitHub Actions from the official source repository, as opposed to a third-party upload.

3. **Key Management Trade-Offs**:
   While traditional signing methods (Minisign / GPG) provide cryptographic guarantees, managing static signing private keys across an automated GitHub Actions release pipeline presents security challenges (key exposure in repository secrets) and requires distributing/maintaining trusted public keys across client environments.

---

## Decision

We adopt a **Dual-Tier Release Verification Architecture** leveraging GitHub Artifact Attestations (Sigstore OIDC) combined with universal SHA-256 checksums:

### 1. Build Provenance Attestations (GitHub Actions Release Workflow)
- In `.github/workflows/release-omawarden.yml`, we configure `id-token: write` and `attestations: write` permissions.
- After producing the release archives (`dist/*.tar.gz`), the workflow invokes `actions/attest-build-provenance@v2`.
- GitHub's Sigstore integration signs cryptographic assertions binding each archive's SHA-256 digest to the repository, workflow, commit SHA, and OIDC identity. The attestation is recorded immutably in the public transparency log (Rekor).
- No long-lived cryptographic private keys are stored in CI secrets.

### 2. Dual-Tier Verification in Downloader Bootstrap (`scripts/download-engine.sh`)
- **Tier 1 (Universal Checksum Verification)**:
  - Continues to download and verify `.sha256` using local `sha256sum` / `shasum`.
  - Ensures universal compatibility and fail-closed corruption detection even on systems lacking the GitHub CLI.
- **Tier 2 (Provenance Attestation Verification)**:
  - If the GitHub CLI (`gh`) is available, the script executes `gh attestation verify "$TMP_DIR/omawarden.tar.gz" --repo "$REPO"`.
  - If verified, `attestation_verified: true` is reported.
  - If unverified in default mode, the script falls back gracefully to Tier 1 integrity and reports `attestation_verified: false`.
  - In strict mode (`REQUIRE_ATTESTATION=1`), missing `gh` or failed provenance verification triggers an immediate fail-closed abort with a clear security alert.

### 3. Structured Verification Reporting & Frontend Transparency
- The downloader script returns structured JSON containing verification metadata:
  ```json
  {
    "ok": true,
    "version": "0.6.1",
    "path": "/path/to/omawarden",
    "verified": true,
    "sha256": "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    "attestation_verified": true
  }
  ```
- In `OmarchyBitwarden.qml`:
  - `root.engineAttestationVerified` stores the provenance verification outcome in memory.
  - User-facing status messages reflect the verification tier (`✓ GitHub Attestation verified` vs `SHA-256 verified`).
  - The System Diagnostics report displays the engine attestation trust state.

---

## Consequences

### Positive
- **Supply-Chain Hardening**: Release archives can be mathematically proven to have been compiled by GitHub Actions from the authentic `icyleaf/omarchy-bitwarden` repository.
- **Zero Key Management Overhead**: Uses short-lived OIDC certificates from GitHub's Sigstore CA, eliminating the risk of compromised or leaked static private keys.
- **Graceful Compatibility**: Existing environments without `gh` continue to work with Tier 1 SHA-256 integrity verification, while environments with `gh` gain automated provenance verification.
- **Package Manager Friendly**: Standard `.sha256` files remain available for AUR / package managers.

### Trade-offs
- Verification of Tier 2 provenance depends on the GitHub CLI (`gh`) and access to the Sigstore API.
