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

echo "=== Running QML Lint, Gate & Test Suites ==="
"${ROOT_DIR}/scripts/test-qml.sh"

echo "=== All Tests Passed Successfully ==="
