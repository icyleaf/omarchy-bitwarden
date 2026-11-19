# ADR 0029: Dual-Track Development Lifecycle, Hotfix Channel, and UI Dev Badges

## Status
Accepted

## Context

Following ADR 0013 (Engine Dev Versioning and Pre-Release Delivery), the repository adopted `-dev` suffixes for backend development builds. However, several operational and UX challenges remained across the full-stack repository (Rust `omawarden` backend + QML `Overlay` plugin):

1. **Frontend-Backend Dev Asymmetry**:
   While `omawarden/Cargo.toml` used `-dev` during active development, the frontend `manifest.json` remained on the last release version until release day, making it unclear whether the installed plugin was running stable release code or unreleased development code.

2. **UI Visual Ambiguity in Local Builds**:
   When testing local builds (`mise run dev-deploy-full` or `scripts/package-dev.sh --install`), neither the `FooterBar` nor `SettingsModal` offered an immediate, high-visibility indicator distinguishing a development build from a stable production install, hindering issue triage and user bug reports.

3. **Release PR Trigger Ambiguity**:
   The Auto Release PR workflow (`.github/workflows/auto-release-pr.yml`) automatically generated a Release PR to `main` upon detecting any commit prefixed with `bump:`. If developers bumped versions to `-dev` at the beginning of a cycle, the workflow mistakenly treated it as a production release candidate.

4. **Hotfix Decoupling Under Active Development**:
   When `develop` is in active development with unreleased features and breaking refactors (targeting the next minor/major release, e.g., `0.15.0-dev`), an emergency hotfix for the current production release (e.g., `0.14.0` -> `0.14.1`) cannot be cut from `develop` without prematurely shipping incomplete features.

---

## Decision

We establish a dual-track development and hotfix lifecycle with explicit development versioning, dedicated tooling, CI guards, and UI visual indicators:

### 1. Dual-Track Branch & Hotfix Strategy
- **Active Development (`develop`)**:
  - Immediately following an official release, `develop` is bumped to the next development cycle using `mise run bump-dev` (e.g., `omawarden 0.12.0-dev`, `omarchy-bitwarden 0.15.0-dev`).
  - Feature branches (`feat/*`) branch off and merge into `develop`.
- **Emergency Hotfix Channel (`main`)**:
  - When a critical issue is discovered in the production release, a hotfix branch is cut directly from `main`: `git checkout main && git checkout -b fix/<description>`.
  - The patch version is bumped on the hotfix branch using standard `mise run bump` (e.g., `0.14.1`).
  - The PR targets `main` (`base: main`).
  - Upon merging into `main`, GitHub Actions automatically tags the patch release, publishes release artifacts, and syncs `main` back into `develop`.
  - Development on `develop` continues uninterrupted at `-dev`.

### 2. Dedicated `bump-dev` Tooling & CI Guards
- Introduced `mise run bump-dev` in `.mise.toml` to bump components with `-dev` suffixes and create commits formatted as `bump(dev): ...`.
- Updated `mise run bump` to reject versions containing `-dev`, ensuring formal releases only accept clean SemVer.
- Updated `.github/workflows/auto-release-pr.yml` to filter out commits matching `(-dev|\.dev)`, guaranteeing that only clean production bumps trigger Release PRs to `main`.

### 3. Visual UI DEV Badges in Overlay
- **FooterBar**: Whenever `overlayVersion` or `backendVersion` contains `-dev` or `.dev`, a compact, theme-adaptive `DEV` pill badge is displayed directly beside the version string.
- **SettingsModal**:
  - A `DEV` badge appears in the Header title row when `overlayVersion` is a dev build.
  - A `DEV` badge appears inside the Engine Status card when `cliHealth.version` is a dev build.
- **SemVer Compatibility**: Core SemVer parsers (`parseSemVer`) continue parsing the numeric major/minor/patch, while update check logic suppresses update notifications for dev builds.

---

## Consequences

### Positive
- **Zero Coupling Between Development & Hotfixes**: High-velocity feature iteration on `develop` no longer blocks immediate, single-commit hotfixes from being released to `main`.
- **High-Visibility Development Status**: Users and developers immediately recognise development builds from UI badges and CLI outputs.
- **Safe CI Pipeline**: Accidental `-dev` bumps will never trigger automated Release PRs or tag creation.
- **Documented & Predictable Workflow**: Standardized commands (`mise run bump-dev` vs `mise run bump`) eliminate guesswork.

### Trade-offs & Mitigations
- **Merge Conflicts During Sync Back**: When `main` hotfixes are synced back into `develop`, conflicting version numbers or overlapping bugfix lines may need manual resolution on `develop`. Mitigated by having `develop` maintain clear `-dev` version declarations.
