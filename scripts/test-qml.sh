#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=== 1. Checking Static Hardcoded Colors Gate ==="
python3 "${ROOT_DIR}/scripts/check-hardcoded-colors.py"
python3 "${ROOT_DIR}/scripts/check-hardcoded-colors.py" --self-test

if command -v qmllint >/dev/null 2>&1; then
  echo "=== 2. Running QML Lint ==="
  qmllint -I components OmarchyBitwarden.qml components/*.qml > qmllint_output.log 2>&1 || true
  cat qmllint_output.log
  if grep -i -E "(\bError:|\berror:|\bfatal:)" qmllint_output.log; then
    echo "qmllint detected syntax or parser errors!"
    rm -f qmllint_output.log
    exit 1
  fi
  rm -f qmllint_output.log
else
  echo "=== 2. QML Lint (skipped, qmllint not found) ==="
fi

echo "=== 3. Running Standalone QML Test Suites ==="
export QML_IMPORT_PATH="${ROOT_DIR}/tests/stubs${QML_IMPORT_PATH:+:${QML_IMPORT_PATH}}"
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"

if command -v qml6 >/dev/null 2>&1; then
  for test_file in tests/tst_*.qml; do
    if [ -f "$test_file" ]; then
      echo "Running $test_file..."
      qml6 "$test_file"
    fi
  done
else
  echo "qml6 not found, skipping standalone QML tests."
fi

echo "=== QML Test Suite Passed Successfully ==="
