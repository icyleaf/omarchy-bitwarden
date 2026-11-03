# Git & Pull Request Workflow

All implementation and bugfix tasks must follow a strict branch-and-PR workflow so that GitHub Release notes and changelogs are populated automatically by `git-cliff` from commit history and merged Pull Requests.

## Rules

1. **Branch Strategy (`main` vs `develop`)**:
   - `main`: **Production / Stable Release Branch** and the default GitHub branch. End-users install plugins and download releases from `main`. Direct commits are strictly forbidden. Only Release PRs (from `develop`) or emergency hotfixes merge into `main`.
   - `develop`: **Active Integration Branch**. All feature branches, bugfixes, refactors, and chores must branch off `develop` and target `develop` for PRs.
   - Always branch off `develop` before starting any work:
     ```bash
     git checkout develop && git pull
     git checkout -b <type>/<short-description-or-issue>
     ```
   - Standard branch naming conventions:
     - Features: `feat/<issue-number>-<description>` (e.g., `feat/38-structured-logging`)
     - Fixes: `fix/<description>` (e.g., `fix/upgrade-text-file-busy`)
     - Chores / Refactors: `chore/<description>` or `refactor/<description>`

2. **Verify before pushing**:
   - Run the complete project test suite (Rust checks, Python workflow validation, `qmllint`, and QML unit test runner) before opening a PR:
     ```bash
     ./scripts/test-all.sh
     ```
   - Or run individual backend checks:
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
     - `chore`: Miscellaneous Tasks
     - `sec` / `fix(security)` / `feat(security)`: Security
     - `ci` / `test`: Skipped (internal only)
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
   - **Crucial Rule**: Every new feature, bugfix, or UI change **MUST** be placed on its own dedicated branch off `develop`. Do not combine unrelated tasks or reuse old merged branches.
   - **Wait for Developer Verification**: Agents must **NEVER** proactively open a Pull Request without explicit confirmation or verification from the developer/user. Wait until the developer completes local verification and gives explicit instruction to submit the PR.
   - Create PR targeting `develop` (linking the issue if applicable):
     ```bash
     gh pr create --base develop --title "<type>(<scope>): <summary>" --body "Closes #<issue_number>

     ## Summary of Changes
     - ..."
     ```
   - **Stacked PRs**: when a slice builds on work that is not merged yet, branch off that parent branch and set the PR base to it instead of `develop`. Targeting `develop` from a child branch makes the PR diff repeat every parent commit. Once the parent merges, drop its commits and retarget:
     ```bash
     git fetch origin develop
     git rebase --onto origin/develop <parent-branch-tip> <your-branch>
     git push --force-with-lease origin HEAD
     gh api -X PATCH "repos/<owner>/<repo>/pulls/<number>" -F base=develop
     ```
     Use the REST call above for retargeting: `gh pr edit --base` needs the `read:org` token scope and fails on this repo's token.

5. **Merge PR & Clean Up**:
   - **Crucial Rule**: Agents must **NEVER** proactively merge a Pull Request (`gh pr merge` or `git merge`) without explicit user permission and instruction. PR reviews, approvals, and merges are strictly controlled by the developer/owner.
   - If the developer explicitly instructs to merge via CLI:
     ```bash
     gh pr merge --squash --delete-branch
     ```
   - Sync local `develop`:
     ```bash
     git checkout develop && git pull
     ```

6. **Release Lifecycle (Promoting `develop` to `main`)**:
   - Releases are automated via GitHub Actions when a version bump commit is merged from `develop` into `main`.
   - To prepare a release on `develop`:
     ```bash
     # Single component bump:
     mise run bump cli <version>        # e.g., 0.5.2
     mise run bump plugin <version>     # e.g., 0.7.2

     # Both components:
     mise run bump all <cli_version> <plugin_version>  # e.g., 0.5.2 0.7.2

     git push origin develop
     ```
   - Pushing a `bump:` commit to `develop` automatically triggers the **Auto Release PR** workflow (`.github/workflows/auto-release-pr.yml`), which opens or updates a Release PR from `develop` to `main` with changelog previews.
   - Review and merge the Release PR on GitHub using **Merge commit** (to preserve full Git commit history between `develop` and `main`).
     > **Warning**: **Never use Squash merge on Release PRs targeting `main`!** Squash merging squashes all conventional commits into a single commit, causing `git-cliff` on `main` to lose individual `feat`, `fix`, `sec` commits when generating release notes.
   - Upon merging to `main`, the **Auto Tag on Release** workflow (`.github/workflows/auto-tag.yml`) automatically detects version changes, tags the release (`omawarden-<version>` and/or `omarchy-bitwarden-<version>`), dispatches the build and package workflows (`release-omawarden.yml` / `release-plugin.yml`), and automatically syncs `main` back into `develop` to keep branch histories aligned.
