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
  if ! qmllint -I components OmarchyBitwarden.qml components/*.qml > qmllint_output.log 2>&1; then
    cat qmllint_output.log
    echo "qmllint reported errors or warnings!"
    rm -f qmllint_output.log
    exit 1
  fi
  cat qmllint_output.log
  rm -f qmllint_output.log
else
  echo "=== 2. QML Lint (skipped, qmllint not found) ==="
fi

echo "=== 3. Running Standalone QML Test Suites ==="
export QML_IMPORT_PATH="${ROOT_DIR}/tests/stubs${QML_IMPORT_PATH:+:${QML_IMPORT_PATH}}"
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
# Qt drops QML console output when stderr is not a TTY (pipes, CI logs, agent
# tooling), leaving a failing suite with an exit code and no diagnostic.
export QT_ASSUME_STDERR_HAS_CONSOLE=1

QML_EXEC=""
if command -v qml6 >/dev/null 2>&1; then
  QML_EXEC="qml6"
elif command -v qml >/dev/null 2>&1; then
  QML_EXEC="qml"
fi

if [ -n "$QML_EXEC" ]; then
  for test_file in tests/tst_*.qml; do
    if [ -f "$test_file" ]; then
      echo "Running $test_file..."
      "$QML_EXEC" "$test_file"
    fi
  done
else
  echo "Neither qml6 nor qml runner found, skipping standalone QML tests."
fi

echo "=== QML Test Suite Passed Successfully ==="
