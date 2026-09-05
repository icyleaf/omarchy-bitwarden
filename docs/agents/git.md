# Git & Pull Request Workflow

All implementation and bugfix tasks must follow a strict branch-and-PR workflow so that GitHub Release notes and changelogs are populated automatically by `git-cliff` from commit history and merged Pull Requests.

## Rules

1. **Never commit directly to `main`**:
   - Always branch off `main` before starting any implementation, bugfix, or chore:
     ```bash
     git checkout main && git pull
     git checkout -b <type>/<short-description-or-issue>
     ```
   - Standard branch naming conventions:
     - Features: `feat/<issue-number>-<description>` (e.g., `feat/38-structured-logging`)
     - Fixes: `fix/<description>` (e.g., `fix/upgrade-text-file-busy`)
     - Chores / Refactors: `chore/<description>` or `refactor/<description>`

2. **Verify before pushing**:
   - Run quality checks before opening a PR:
     ```bash
     cargo fmt --check
     cargo clippy --all-targets --all-features -- -D warnings
     XDG_RUNTIME_DIR=/tmp cargo test
     ```

3. **Commit with Conventional Commits**:
   - Format: `<type>(<scope>): <summary>` or `<type>(<scope>)!: <summary>` for breaking changes.
   - **Allowed Types & Release Notes Category Mapping**:
     - `feat`: Features
     - `fix`: Bug Fixes
     - `perf`: Features
     - `refactor`: Features
     - `style`: Styling
     - `docs`: Documentation
     - `chore(deps)`: Dependencies
     - `chore` / `ci`: Miscellaneous Tasks
     - `sec` / `fix(security)` / `feat(security)`: Security
     - `test`: Skipped (internal only)
   - **Scopes**: Always specify a concise scope when applicable (e.g., `ui`, `qml`, `daemon`, `clipboard`, `vault`, `crypto`, `auth`, `attachment`, `logging`, `cli`, `install`).
   - **Breaking Changes**:
     - Mark breaking changes with a `!` before the colon (e.g., `feat(daemon)!: switch to binary protocol`).
     - Alternatively, include `BREAKING CHANGE:` in the commit message footer explaining the migration requirements.
     - Breaking changes are automatically rendered with `[BREAKING]` in release notes.

4. **Create Pull Request via `gh` CLI**:
   - Push branch to remote:
     ```bash
     git push -u origin HEAD
     ```
   - Create PR linking the issue:
     ```bash
     gh pr create --title "<type>(<scope>): <summary>" --body "Closes #<issue_number>

     ## Summary of Changes
     - ..."
     ```

5. **Merge PR & Clean Up**:
   - Merge the pull request (squash or merge):
     ```bash
     gh pr merge --squash --delete-branch
     ```
   - Sync local `main`:
     ```bash
     git checkout main && git pull
     ```

