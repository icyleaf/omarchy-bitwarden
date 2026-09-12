# ADR 0013: Engine Dev Versioning, Rolling Pre-Release Delivery, and Local Packaging

## Status
Accepted

## Context

Following the migration to AUR package distribution (`omawarden-bin`, ADR 0012) and dual-source UI indicators (`[ AUR ]` vs `[ builtin ]`), developers and testers require clear mechanisms to build, package, test, and continuously deliver development versions of the `omawarden` engine:

1. **Explicit Next-Version Identification**:
   Between official releases (e.g. following `0.7.0`), development iterations on the `develop` branch must clearly indicate their unreleased status to avoid ambiguity in bug reports, crash dumps, and diagnostics.

2. **Continuous Integration & Pre-Release Delivery**:
   Testers on the `develop` branch need access to compiled binaries without waiting for official tagged releases. However:
   - Pushing intermediate development commits to the official Arch User Repository (`omawarden-bin`) would violate AUR packaging guidelines, spam AUR commit histories, and disrupt stable package installations.
   - Creating distinct Git tags on every commit to `develop` would pollute the repository's tag space and changelogs.

3. **Packaging Specification Constraints**:
   Standard Cargo / SemVer specifications use hyphens for pre-releases (e.g., `0.8.0-dev`). Arch Linux `pacman` and `makepkg` prohibit hyphens in `pkgver`, requiring dot or underscore separation (e.g., `0.8.0.dev`).

4. **Local Development Workflow & Feedback Loops**:
   Developers testing UI changes need to rapidly switch between and verify both execution modes:
   - In-tree binary deployment (`bin/omawarden`, presenting `[ builtin ]`).
   - System Arch package installation (`/usr/bin/omawarden`, presenting `[ AUR ]`).
   Generating a local Arch package previously required mock PKGBUILDs or manual network fetches.

---

## Decision

We establish an end-to-end development versioning and delivery lifecycle encompassing explicit SemVer identifiers, automated rolling GitHub pre-releases, update notification suppression, and offline local packaging:

### 1. Explicit SemVer Dev Identifier in Cargo
- During active integration on `develop`, `omawarden/Cargo.toml` explicitly declares the next target version with a `-dev` suffix (e.g., `version = "0.8.0-dev"`).
- `omawarden -V` prints the full version string including compile-time Git hash and build date (`0.8.0-dev (<hash> <date>)`).
- The resident daemon lifecycle (ADR 0003) continues using `GIT_HASH` equality to automatically recycle running instances across development builds.

### 2. Rolling GitHub Pre-Release on Push to `develop`
- Introduced `.github/workflows/release-dev-omawarden.yml` triggered on pushes to `develop` affecting `omawarden/**` or the workflow itself.
- Cross-compiles release binaries for both supported architectures (`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`), generates SHA-256 checksums, and attests build provenance.
- Updates a floating Git tag named `omawarden-dev` using `git push origin omawarden-dev --force`.
- Publishes or refreshes a single rolling GitHub Pre-Release (`prerelease: true`, `make_latest: false`) titled `Omawarden (dev)`, providing stable download endpoints without polluting the repository with hundreds of incremental tags.
- Development builds are strictly excluded from AUR publication. Official AUR releases remain triggered exclusively on versioned release tags (`omawarden-[0-9]*`).

### 3. Client Update Notification Suppression
- In `OmarchyBitwarden.qml`, `updateAvailable` suppresses regular release update prompts if the running engine version contains `-dev` or `.dev`.
- This prevents misleading update banners that would prompt users running bleeding-edge development builds to "downgrade" to the latest stable release.

### 4. Local Development Packaging (`mise run pkg-dev`)
- Added `scripts/package-dev.sh` and task `pkg-dev` in `.mise.toml`.
- Workflow:
  1. Compiles release binary via `cargo build --release`.
  2. Extracts Cargo version and converts `-dev` to `.dev` (e.g., `0.8.0-dev` -> `0.8.0.dev`) conforming to `pacman` `pkgver` grammar.
  3. Generates a local `PKGBUILD` in `dist/pkg-dev/` referencing the local binary and license.
  4. Invokes `makepkg -f --nodeps` to build `omawarden-bin-<pkgver>-1-<carch>.pkg.tar.zst` offline in seconds.
  5. If invoked with `-i` or `--install`, automatically executes `sudo pacman -U --noconfirm` to install `/usr/bin/omawarden`, allowing immediate validation of `[ AUR ]` mode.

---

## Consequences

### Positive
- **Deterministic Traceability**: Binary outputs, diagnostics, and issue reports unambiguously identify unreleased development builds.
- **Automated Rolling Delivery**: Testers can pull the latest pre-compiled `develop` binaries from GitHub without developer intervention.
- **Clean Tag & AUR History**: No tag proliferation in Git or AUR update spam for unstable commits.
- **Rapid Local Verification**: One command (`mise run pkg-dev --install`) builds and installs a valid Arch package locally without external network access.

### Trade-offs & Mitigations
- **Non-Immutable Rolling Pre-Release**: Binaries under `omawarden-dev` are overwritten on every `develop` push. Historical builds can still be retrieved via GitHub Actions workflow run artifacts or Git commit checkouts.
