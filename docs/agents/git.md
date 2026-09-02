# Git & Pull Request Workflow

All implementation and bugfix tasks must follow a strict branch-and-PR workflow so that GitHub Release notes and changelogs are populated automatically from merged Pull Requests.

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
   - Format: `<type>(<scope>): <summary>`

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
