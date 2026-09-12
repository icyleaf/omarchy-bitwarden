# Contributing to omarchy-bitwarden

Thank you for your interest in contributing to `omarchy-bitwarden`! We appreciate contributions of all kinds, including bug reports, feature suggestions, documentation improvements, and pull requests.

To ensure smooth collaboration, code quality, and automated changelog generation via `git-cliff`, please follow the workflow outlined below.

---

## Branching Strategy

Our repository adopts a strict branch lifecycle:

- **`main` (Production / Stable Release)**: The default branch on GitHub. Users install plugins and download releases from `main`. Direct commits are strictly prohibited.
- **`develop` (Active Integration)**: The staging branch for all ongoing development. All new features, bug fixes, refactors, and chores must branch off `develop` and target `develop` for pull requests.

### Branch Naming Conventions

Always branch off `develop`:

```bash
git checkout develop && git pull
git checkout -b <type>/<short-description-or-issue>
```

Recommended branch prefixes:
- `feat/`: New features (e.g., `feat/password-generator` or `feat/123-item-creation`)
- `fix/`: Bug fixes (e.g., `fix/socket-timeout`)
- `sec/`: Security fixes or enhancements (e.g., `sec/peercred-hardening`)
- `refactor/`: Code restructuring without behavioral changes
- `chore/` or `docs/`: Maintenance tasks or documentation updates

---

## Development & Verification

The core daemon and CLI (`omawarden`) is written in pure Rust located in the `omawarden/` directory.

### 1. Standard Cargo Workflow

You can build and test using standard Rust tools:

```bash
cd omawarden

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets --all-features -- -D warnings

# Run tests (set XDG_RUNTIME_DIR to ensure a safe test environment)
XDG_RUNTIME_DIR=/tmp cargo test
```

### 2. Convenient Development via `mise` (Optional)

If you have [`mise`](https://mise.jdx.dev/) installed, you can leverage predefined tasks:

```bash
# Build omawarden binary
mise run build

# Build release binary and copy to bin/
mise run build-release

# Deploy to local Omarchy plugins directory and restart shell
mise run dev-deploy
```

---

## Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification so that release notes and changelogs are generated automatically:

```text
<type>(<scope>): <summary>
```

- **Types**:
  - `feat`: New features
  - `fix`: Bug fixes
  - `sec` / `fix(security)`: Security fixes
  - `refactor`: Code refactoring
  - `docs`: Documentation changes
  - `style`: Code style / formatting
  - `chore`: Maintenance / tooling updates
- **Scopes**: Optional but recommended (e.g., `daemon`, `ui`, `crypto`, `auth`, `clipboard`, `vault`).
- **Breaking Changes**: Append a `!` before the colon (e.g., `feat(daemon)!: switch to binary protocol`) or include `BREAKING CHANGE:` in the footer.

---

## Submitting a Pull Request

1. Push your branch to GitHub:
   ```bash
   git push -u origin HEAD
   ```
2. Open a Pull Request targeting the **`develop`** branch (not `main`):
   ```bash
   gh pr create --base develop --title "feat(scope): short description"
   ```
3. Describe your changes clearly in the PR description and reference any related issues (e.g., `Closes #123`).
4. Ensure all CI checks pass. Maintainers will review your PR and merge it into `develop`.
