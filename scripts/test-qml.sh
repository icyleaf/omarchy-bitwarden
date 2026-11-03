#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=== 1. Checking Static Gates (colors, module manifest) ==="
python3 "${ROOT_DIR}/scripts/check-hardcoded-colors.py"
python3 "${ROOT_DIR}/scripts/check-hardcoded-colors.py" --self-test
python3 "${ROOT_DIR}/scripts/check-qml-module.py"
python3 "${ROOT_DIR}/scripts/check-qml-module.py" --self-test

if command -v qmllint >/dev/null 2>&1; then
  echo "=== 2. Running QML Lint ==="
  # A non-zero exit is not by itself a failure: the Qt 6.4 qmllint on CI exits
  # non-zero for pre-existing Warning and Info diagnostics. Lint one file at a
  # time so a parse failure stays attributable: legacy qmllint exits non-zero
  # and prints nothing for a file it cannot parse, and linting the whole tree
  # in one call hides that silence behind the warnings of every other file.
  lint_failures=0
  for qml_file in OmarchyBitwarden.qml components/*.qml; do
    file_status=0
    file_output=$(qmllint -I components "${qml_file}" 2>&1) || file_status=$?
    if [ -n "${file_output}" ]; then
      printf '%s\n' "${file_output}"
    fi
    if [ "${file_status}" -ne 0 ]; then
      if [ -z "${file_output}" ]; then
        echo "qmllint could not parse ${qml_file} (exit ${file_status}, no diagnostic)!"
        lint_failures=$((lint_failures + 1))
      elif printf '%s' "${file_output}" | grep -qiE "(^|[[:space:]])error:"; then
        echo "qmllint reported errors in ${qml_file} (exit ${file_status})!"
        lint_failures=$((lint_failures + 1))
      fi
    fi
  done
  if [ "${lint_failures}" -ne 0 ]; then
    echo "qmllint failed on ${lint_failures} file(s)."
    exit 1
  fi
  echo "qmllint passed (warnings and Info diagnostics are reported, not fatal)."
else
  echo "=== 2. QML Lint (skipped, qmllint not found) ==="
fi

echo "=== 3. Running Standalone QML Test Suites ==="
export QML_IMPORT_PATH="${ROOT_DIR}/tests/stubs${QML_IMPORT_PATH:+:${QML_IMPORT_PATH}}"
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
# Qt drops QML console output when stderr is not a TTY (pipes, CI logs, agent
# tooling), leaving a failing suite with an exit code and no diagnostic.
export QT_ASSUME_STDERR_HAS_CONSOLE=1
# Suites that grep component sources (root wiring checks) read the repo files
# through XHR; without this Qt refuses file:// reads from QML.
export QML_XHR_ALLOW_FILE_READ=1

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
