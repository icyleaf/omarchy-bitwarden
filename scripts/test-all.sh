#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Running Cargo Format Check ==="
(cd "${ROOT_DIR}/omawarden" && cargo fmt --check)

echo "=== Running Cargo Clippy ==="
(cd "${ROOT_DIR}/omawarden" && cargo clippy --all-targets --all-features -- -D warnings)

echo "=== Running Cargo Test Suite ==="
(cd "${ROOT_DIR}/omawarden" && XDG_RUNTIME_DIR=/tmp cargo test --all-targets)

echo "=== Running Python Workflow Tests ==="
python3 "${ROOT_DIR}/tests/test_workflow_action_pinning.py"

if command -v qmllint >/dev/null 2>&1; then
  echo "=== Running QML Lint ==="
  (cd "${ROOT_DIR}" && qmllint OmarchyBitwarden.qml components/*.qml)
fi

echo "=== Running Standalone QML Test Suites ==="
cd "${ROOT_DIR}"
STANDALONE_TESTS=(
  "tests/tst_password_generator_modal.qml"
  "tests/tst_modal_focus.qml"
  "tests/tst_card_formatting.qml"
  "tests/tst_dev_version_update_suppression.qml"
  "tests/tst_diagnostics_report.qml"
  "tests/tst_engine_minimum_version.qml"
  "tests/tst_helper_resolution.qml"
  "tests/tst_lock_cleanup.qml"
  "tests/tst_scope_filtering.qml"
  "tests/tst_sync_error_formatting.qml"
)

for test_file in "${STANDALONE_TESTS[@]}"; do
  if [ -f "$test_file" ]; then
    echo "Running $test_file..."
    qml6 "$test_file"
  fi
done

echo "=== All Tests Passed Successfully ==="
