# ADR 0012: Transition Engine Distribution to AUR and Native System Packages

## Status
Accepted

## Context

The `omarchy-bitwarden` desktop plugin previously relied on an in-tree binary bootstrap download mechanism (`scripts/download-engine.sh`), fetching pre-compiled native engine archives (`omawarden-<target>.tar.gz`) from GitHub Releases directly into the plugin's local `bin/` directory.

While this facilitated initial zero-configuration prototyping, several architectural and operational drawbacks emerged:

1. **Mismatch with Arch Linux System Package Philosophy**:
   In the Omarchy / Arch Linux ecosystem, system executables and shared libraries are properly managed through `pacman` and AUR helpers (`paru`, `yay`). In-app binary downloading bypassed system package management, preventing system-wide package updates, dependency tracking, and file ownership accounting.

2. **Undeclared Runtime Dependencies**:
   `omawarden` requires native system utilities to operate securely:
   - `libsecret` (`secret-tool`) for FreeDesktop Secret Service system keyring credential persistence (ADR 0007).
   - `wl-clipboard` (`wl-copy` / `wl-paste`) for Wayland ephemeral clipboard scrubbing and TOTP generation (ADR 0003).
   Under the bootstrap downloader model, these system dependencies had to be installed manually by the user, leading to runtime failures if absent.

3. **Binary Duplication Across Worktrees & Plugins**:
   Users managing multiple developer checkouts, worktrees, or plugin clones accumulated duplicate ~10–20MB binary copies in each checkout directory.

4. **Environment Variable Injection Risks**:
   The frontend supported `OMARCHY_BITWARDEN_HELPER` to override the helper binary path. This created potential environment injection seams and made troubleshooting difficult across different execution contexts.

---

## Decision

We transition the distribution of the `omawarden` engine to the Arch User Repository (AUR) and implement a native system dependency lifecycle:

### 1. AUR Package Specification (`omawarden-bin`)
- The package is named `omawarden-bin` on AUR, targeting `x86_64` and `aarch64`.
- Defines `provides=('omawarden')` and `conflicts=('omawarden')`.
- Explicitly declares mandatory runtime dependencies: `depends=('libsecret' 'wl-clipboard')`.
- Installs `/usr/bin/omawarden` and `/usr/share/licenses/omawarden-bin/LICENSE`.

### 2. Automated AUR CI/CD Pipeline
- Extended `.github/workflows/release-omawarden.yml` with a dedicated `publish-aur` job running upon publication of `omawarden-v*` release tags.
- The workflow generates the `PKGBUILD` dynamically in the runner using `pkgver`, `x86_64` and `aarch64` SHA-256 archive digests, avoiding checked-in static PKGBUILD drifts.
- Deploys via `KSXGitHub/github-actions-deploy-aur@v4.1.1` reusing established repository secrets (`AUR_KEY`, `AUR_USERNAME`, `AUR_EMAIL`).

### 3. Dynamic Path Resolution & Environment Clean-up
- Completely removed `OMARCHY_BITWARDEN_HELPER` from frontend path resolution.
- On initialization, `OmarchyBitwarden.qml` dynamically queries the host `$PATH` via `which omawarden`.
- If found in system `$PATH`, `/usr/bin/omawarden` is used directly.
- If not present in `$PATH`, the frontend falls back gracefully to in-tree `bin/omawarden` to ensure existing installations do not break during the migration phase.

### 4. Gated Dependency Onboarding View (`DependencyCheckView.qml`)
- On overlay startup and activation, the frontend queries package installation states via `pacman -Q omawarden libsecret wl-clipboard`.
- If any required package is missing from pacman:
  - Normal vault search, unlock, and login views are gated.
  - The UI routes `effectiveView` to `dependency_check`, rendering `components/DependencyCheckView.qml`.
  - Manual access to Settings (`currentView === "settings"`) remains accessible for configuration and diagnostics.
- The view displays each dependency's status (installed version vs missing) and provides a **One-Click Install Missing Dependencies** button.
- Clicking the button launches `omarchy-launch-floating-terminal-with-presentation` running `paru -S --needed` (with automatic fallback to `yay` or `sudo pacman`), mapping `omawarden` to `omawarden-bin`.
- When the installation terminal window is dismissed, an automatic recheck executes, transitioning seamlessly into normal vault operations as soon as prerequisites are satisfied.

---

## Consequences & Trade-offs

### Positive
- **Native OS Integration**: `omawarden` is managed like any other Arch / Omarchy package with standard system upgrades (`paru -Syu`).
- **Guaranteed Runtime Dependencies**: `libsecret` and `wl-clipboard` are declared as pacman dependencies and installed automatically.
- **Single System-Wide Binary**: Eliminates duplicate binary copies across repositories and worktrees.
- **Frictionless Onboarding**: New users without prerequisites are guided by a unified, styled GUI view with one-click terminal installation.
- **Zero Static PKGBUILD Maintenance**: Release CI automatically derives package versions and hashes directly from GitHub Release tarballs.

### Negative / Trade-offs
- **AUR Helper Dependency for One-Click Install**: One-click installation in the terminal relies on an installed AUR helper (`paru` or `yay`) to build/install `omawarden-bin` from AUR. If neither is found, it falls back to `sudo pacman`, which will prompt if packages are only in AUR.
- **Temporary Retention of Downloader Script**: `scripts/download-engine.sh` is preserved temporarily during the transition phase to support legacy development workflows before complete deprecation.
