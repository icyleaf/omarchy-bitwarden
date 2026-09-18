# ADR 0019: Engine AUR Git Package Distribution (omawarden-git)

## Status
Accepted

## Context

Following the migration to AUR package distribution for stable releases (`omawarden-bin`, ADR 0012) and the establishment of rolling pre-releases and local development packaging (ADR 0013), community testers and developers tracking the active integration branch (`develop`) needed a standard, native Arch package distribution channel:

1. **Arch User Repository VCS Packaging Standards**:
   In the Arch Linux ecosystem, packages tracking upstream source repositories use the `-git` suffix. Arch User Repository (AUR) packaging guidelines strictly mandate that VCS packages must build from source (`makedepends=('cargo' 'git')`) rather than downloading pre-compiled binaries.

2. **Commit Noise & Release Decoupling in AUR**:
   As outlined in ADR 0013, pushing intermediate commits to AUR on every single git push pollutes AUR history and disrupts users. Standard Arch VCS packages solve this by providing a dynamic `pkgver()` function evaluated locally by AUR helpers (`paru`, `yay`), meaning the PKGBUILD in AUR only needs updating when build flags, dependencies, or package metadata change.

3. **Package Replacement & Frontend Compatibility**:
   Users alternating between stable binaries (`omawarden-bin`) and bleeding-edge source builds (`omawarden-git`) need smooth package replacement without file collisions. Furthermore, the desktop overlay's prerequisite checker (`DependencyCheckView.qml`) must recognize `omawarden-git` as satisfying the native engine dependency.

---

## Decision

We establish an official AUR VCS distribution lifecycle for `omawarden-git` alongside `omawarden-bin`:

### 1. AUR VCS Package Specification (`dist/aur-git/PKGBUILD`)
- The package is named `omawarden-git` on AUR, targeting `x86_64` and `aarch64`.
- Clones the active development branch: `source=("omarchy-bitwarden::git+https://github.com/icyleaf/omarchy-bitwarden.git#branch=develop")`.
- Declares `provides=('omawarden' 'omawarden-bin')` and `conflicts=('omawarden' 'omawarden-bin')`, allowing seamless mutual substitution between binary and source package variants.
- Declares mandatory runtime dependencies `depends=('libsecret' 'wl-clipboard')` and build dependencies `makedepends=('cargo' 'git')`.
- Compiles exclusively the native backend in `omawarden/` via `cargo build --frozen --release --bin omawarden`.
- Installs `/usr/bin/omawarden` and `/usr/share/licenses/omawarden-git/LICENSE`.

### 2. Monotonic Dynamic Versioning (`pkgver()`)
- Extracts the active SemVer development baseline from `omawarden/Cargo.toml` (e.g. `0.8.0-dev` -> `0.8.0`).
- Appends git commit count and abbreviated hash: `printf "%s.r%s.g%s" "$_ver" "$_rev" "$_hash"` (e.g. `0.8.0.r145.ga1b2c3d`).
- Ensures versions strictly increase monotonically as commits are integrated into `develop`, satisfying pacman version comparison rules.

### 3. Dedicated AUR Continuous Deployment Workflow
- Added `.github/workflows/release-aur-git.yml` triggered on manual dispatch (`workflow_dispatch`) and on pushes to `develop` modifying `dist/aur-git/PKGBUILD`.
- Deploys via `KSXGitHub/github-actions-deploy-aur@v4.1.1` to the AUR `omawarden-git` repository using established `AUR_KEY`, `AUR_USERNAME`, and `AUR_EMAIL` secrets.

### 4. Local Packaging Task (`mise run pkg-git`)
- Added `scripts/package-git.sh` and task `pkg-git` in `.mise.toml`.
- Enables developers to test the full `makepkg` VCS build process locally in `dist/pkg-git/`, with optional `--install` (`-i`) to install directly via `pacman -U` and `--local` (`-l`) to test against the local git repository.

### 5. Frontend Dependency Recognition
- Updated `components/DependencyCheckView.qml` to recognize `omawarden-git` in `parsePacmanStdout`, marking the engine status as ready and unblocking vault access.
- One-click dependency installation continues to target `omawarden-bin` by default, providing instant pre-compiled binaries for regular users who lack a Rust compilation toolchain.

---

## Consequences

### Positive
- **Arch VCS Compliance**: Follows official Arch Linux packaging standards by compiling from source with system toolchains.
- **Clean AUR History**: AUR repository updates occur only when packaging recipes change, while users get automatic updates via `paru -Syu --devel`.
- **Frictionless Transition**: `provides`/`conflicts` allow seamless swapping between `omawarden-bin` and `omawarden-git`.
- **Unified UI Verification**: `DependencyCheckView.qml` correctly recognizes both package variants.

### Trade-offs & Mitigations
- **Compilation Overhead**: Installing `omawarden-git` requires compiling Rust code on the user's system (~1-2 minutes). Users seeking instant zero-compile installation remain served by `omawarden-bin`.
