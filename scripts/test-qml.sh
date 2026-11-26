#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-qml.sh [OPTIONS]

Run static QML gates, qmllint, and standalone Overlay QML test suites.

By default, QML test suites run headlessly with QT_QPA_PLATFORM=offscreen
(overriding any inherited desktop QT_QPA_PLATFORM such as wayland;xcb) so zero
test windows pop up or steal focus on the active workspace.

Options:
  -w, --workspace <WS>   Route real Wayland QML test windows silently to the
                         given Hyprland workspace (e.g. 9 or special:qml-test)
                         without stealing focus. Falls back to offscreen with a
                         warning when Hyprland is unavailable.
  -h, --help             Show this help message and exit.

Environment Variables:
  QML_HYPRLAND_WORKSPACE=<WS>
                         Default Hyprland workspace when --workspace is not
                         passed on the command line (--workspace takes precedence).
  QML_TEST_TIMEOUT=<DUR> Per-suite timeout passed to `timeout` (default: 30s).
EOF
}

CLI_WORKSPACE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -w|--workspace)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        echo "ERROR: --workspace requires a non-empty workspace argument." >&2
        exit 2
      fi
      CLI_WORKSPACE="$2"
      shift 2
      ;;
    --workspace=*)
      CLI_WORKSPACE="${1#*=}"
      if [[ -z "${CLI_WORKSPACE}" ]]; then
        echo "ERROR: --workspace requires a non-empty workspace argument." >&2
        exit 2
      fi
      shift
      ;;
    *)
      echo "ERROR: Unknown option '$1'. Run './scripts/test-qml.sh --help' for usage." >&2
      exit 2
      ;;
  esac
done

REQUESTED_WORKSPACE="${CLI_WORKSPACE:-${QML_HYPRLAND_WORKSPACE:-}}"
if [[ -n "${REQUESTED_WORKSPACE}" ]] && [[ ! "${REQUESTED_WORKSPACE}" =~ ^[A-Za-z0-9_:+-]+$ ]]; then
  echo "ERROR: Invalid workspace '${REQUESTED_WORKSPACE}'. Expected characters in [A-Za-z0-9_:+-]." >&2
  exit 2
fi

HYPR_RULE_ACTIVE=0
HYPR_RULE_MODE=""
HYPR_RULE_VAR="omarchy_bitwarden_qml_test_$$"
HYPR_RULE_NAME="omarchy-bitwarden-qml-test-$$"

cleanup_hyprland_rule() {
  if [[ "${HYPR_RULE_ACTIVE}" -eq 1 ]]; then
    HYPR_RULE_ACTIVE=0
    if [[ "${HYPR_RULE_MODE}" == "eval" ]]; then
      local eval_disable_out eval_disable_status=0
      eval_disable_out="$(hyprctl eval "if ${HYPR_RULE_VAR} then ${HYPR_RULE_VAR}:set_enabled(false); ${HYPR_RULE_VAR} = nil end" 2>&1)" || eval_disable_status=$?
      if [[ "${eval_disable_status}" -ne 0 ]] || printf '%s' "${eval_disable_out}" | grep -qiE '(^unknown request|^invalid|^error)'; then
        echo "WARNING: Failed to disable temporary Hyprland eval window rule '${HYPR_RULE_VAR}': ${eval_disable_out}" >&2
      fi
    elif [[ "${HYPR_RULE_MODE}" == "keyword" ]]; then
      local kw_disable_out kw_disable_status=0
      kw_disable_out="$(hyprctl keyword "windowrule[${HYPR_RULE_NAME}]:enable" false 2>&1)" || kw_disable_status=$?
      if [[ "${kw_disable_status}" -ne 0 ]] || printf '%s' "${kw_disable_out}" | grep -qiE '(^unknown request|^invalid|^error|can'\''t work)'; then
        echo "WARNING: Failed to disable temporary Hyprland keyword window rule '${HYPR_RULE_NAME}': ${kw_disable_out}" >&2
      fi
    fi
  fi
}

setup_qml_platform() {
  if [[ -z "${REQUESTED_WORKSPACE}" ]]; then
    export QT_QPA_PLATFORM="offscreen"
    return 0
  fi

  if [[ -z "${HYPRLAND_INSTANCE_SIGNATURE:-}" ]] || ! command -v hyprctl >/dev/null 2>&1; then
    echo "WARNING: Hyprland workspace '${REQUESTED_WORKSPACE}' requested, but Hyprland is unavailable (missing HYPRLAND_INSTANCE_SIGNATURE or hyprctl); falling back to QT_QPA_PLATFORM=offscreen." >&2
    export QT_QPA_PLATFORM="offscreen"
    return 0
  fi

  trap 'cleanup_hyprland_rule' EXIT
  trap 'cleanup_hyprland_rule; exit 130' INT
  trap 'cleanup_hyprland_rule; exit 143' TERM

  local eval_expr eval_out eval_status=0
  eval_expr="if ${HYPR_RULE_VAR} then ${HYPR_RULE_VAR}:set_enabled(false) end; ${HYPR_RULE_VAR} = hl.window_rule({ match = { class = \"(org.qt-project.qml6|org.qt-project.qml|qml6|qml)\" }, workspace = \"${REQUESTED_WORKSPACE} silent\", no_initial_focus = true })"
  eval_out="$(hyprctl eval "${eval_expr}" 2>&1)" || eval_status=$?

  if [[ "${eval_status}" -eq 0 ]] && ! printf '%s' "${eval_out}" | grep -qiE '(^unknown request|^invalid|^error)'; then
    HYPR_RULE_MODE="eval"
    HYPR_RULE_ACTIVE=1
    export QT_QPA_PLATFORM="wayland"
    echo "Routing QML test windows silently to Hyprland workspace '${REQUESTED_WORKSPACE}'."
    return 0
  fi

  local kw_out kw_status=0
  kw_out="$(hyprctl keyword windowrule "name ${HYPR_RULE_NAME}, match:class ^(org\\.qt-project\\.qml6?|qml6?)$, workspace ${REQUESTED_WORKSPACE} silent, no_initial_focus on" 2>&1)" || kw_status=$?
  if [[ "${kw_status}" -eq 0 ]] && ! printf '%s' "${kw_out}" | grep -qiE '(^unknown request|^invalid|^error|can'\''t work)'; then
    HYPR_RULE_MODE="keyword"
    HYPR_RULE_ACTIVE=1
    export QT_QPA_PLATFORM="wayland"
    echo "Routing QML test windows silently to Hyprland workspace '${REQUESTED_WORKSPACE}'."
    return 0
  fi

  echo "WARNING: Failed to register Hyprland window rule for workspace '${REQUESTED_WORKSPACE}'; falling back to QT_QPA_PLATFORM=offscreen." >&2
  export QT_QPA_PLATFORM="offscreen"
}

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
setup_qml_platform
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
  QML_TEST_TIMEOUT="${QML_TEST_TIMEOUT:-30s}"
  for test_file in tests/tst_*.qml; do
    if [ -f "$test_file" ]; then
      echo "Running $test_file..."
      suite_status=0
      if command -v timeout >/dev/null 2>&1; then
        timeout --foreground --kill-after=5s "$QML_TEST_TIMEOUT" "$QML_EXEC" "$test_file" || suite_status=$?
      else
        "$QML_EXEC" "$test_file" || suite_status=$?
      fi
      if [ "${suite_status}" -ne 0 ]; then
        exit "${suite_status}"
      fi
    fi
  done
else
  echo "Neither qml6 nor qml runner found, skipping standalone QML tests."
fi

echo "=== QML Test Suite Passed Successfully ==="
