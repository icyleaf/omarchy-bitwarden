#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-all.sh [OPTIONS]

Run the complete Omarchy Bitwarden test suite:
  1. Cargo format check (`cargo fmt --check`)
  2. Cargo clippy (`cargo clippy --all-targets --all-features -- -D warnings`)
  3. Parallel Omawarden test suite (`cargo test --all-targets`) under a bounded
     timeout guardrail (`CARGO_TEST_TIMEOUT`, default: 300s)
  4. Python workflow & runner contract tests
  5. QML static gates, `qmllint`, and standalone Overlay QML test suites
     (headless `QT_QPA_PLATFORM=offscreen` by default)

Options:
  -w, --workspace <WS>   Forward `--workspace <WS>` to `./scripts/test-qml.sh`
                         so Overlay QML test windows render silently on the
                         specified Hyprland workspace (e.g. 9 or special:qml-test)
                         without stealing focus.
  -h, --help             Show this help message and exit.

Environment Variables:
  CARGO_TEST_TIMEOUT=<DUR>
                         Timeout guardrail for the parallel `cargo test` run
                         (default: 300s).
  QML_HYPRLAND_WORKSPACE=<WS>
                         Default Hyprland workspace forwarded to `./scripts/test-qml.sh`
                         when `--workspace` is not passed on the command line.
  QML_TEST_TIMEOUT=<DUR> Per-suite QML timeout forwarded to `./scripts/test-qml.sh`
                         (default: 30s).
EOF
}

QML_ARGS=()
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
      QML_ARGS+=("--workspace" "$2")
      shift 2
      ;;
    --workspace=*)
      ws_val="${1#*=}"
      if [[ -z "${ws_val}" ]]; then
        echo "ERROR: --workspace requires a non-empty workspace argument." >&2
        exit 2
      fi
      QML_ARGS+=("--workspace" "${ws_val}")
      shift
      ;;
    *)
      echo "ERROR: Unknown option '$1'. Run './scripts/test-all.sh --help' for usage." >&2
      exit 2
      ;;
  esac
done

echo "=== Running Cargo Format Check ==="
(cd "${ROOT_DIR}/omawarden" && cargo fmt --check)

echo "=== Running Cargo Clippy ==="
(cd "${ROOT_DIR}/omawarden" && cargo clippy --all-targets --all-features -- -D warnings)

echo "=== Running Cargo Test Suite ==="
CARGO_TEST_TIMEOUT="${CARGO_TEST_TIMEOUT:-300s}"
TMP_TEST_ROOT="$(mktemp -d)"
TMP_RUNTIME_DIR="${TMP_TEST_ROOT}/runtime"
TMP_CONFIG_DIR="${TMP_TEST_ROOT}/config"
TMP_DATA_DIR="${TMP_TEST_ROOT}/data"
mkdir -m 0700 -p "${TMP_RUNTIME_DIR}" "${TMP_CONFIG_DIR}" "${TMP_DATA_DIR}"
trap 'rm -rf "${TMP_TEST_ROOT}"' EXIT

cargo_status=0
if command -v timeout >/dev/null 2>&1; then
  (
    cd "${ROOT_DIR}/omawarden" && \
    env -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u DISPLAY \
      -u OMAWARDEN_CONFIG_DIR -u OMAWARDEN_DATA_DIR \
      XDG_RUNTIME_DIR="${TMP_RUNTIME_DIR}" \
      XDG_CONFIG_HOME="${TMP_CONFIG_DIR}" \
      XDG_DATA_HOME="${TMP_DATA_DIR}" \
      timeout --kill-after=10s "${CARGO_TEST_TIMEOUT}" cargo test --all-targets
  ) || cargo_status=$?
else
  (
    cd "${ROOT_DIR}/omawarden" && \
    env -u WAYLAND_DISPLAY -u WAYLAND_SOCKET -u DISPLAY \
      -u OMAWARDEN_CONFIG_DIR -u OMAWARDEN_DATA_DIR \
      XDG_RUNTIME_DIR="${TMP_RUNTIME_DIR}" \
      XDG_CONFIG_HOME="${TMP_CONFIG_DIR}" \
      XDG_DATA_HOME="${TMP_DATA_DIR}" \
      cargo test --all-targets
  ) || cargo_status=$?
fi

if [[ "${cargo_status}" -eq 124 || "${cargo_status}" -eq 137 ]]; then
  echo "ERROR: Omawarden cargo test suite timed out after ${CARGO_TEST_TIMEOUT} (possible parallel hang or environment-lock deadlock)." >&2
  exit "${cargo_status}"
elif [[ "${cargo_status}" -ne 0 ]]; then
  exit "${cargo_status}"
fi

echo "=== Running Python Workflow Tests ==="
python3 "${ROOT_DIR}/tests/test_workflow_action_pinning.py"
python3 "${ROOT_DIR}/tests/test_runner_scripts.py"

echo "=== Running QML Lint, Gate & Test Suites ==="
"${ROOT_DIR}/scripts/test-qml.sh" ${QML_ARGS[@]+"${QML_ARGS[@]}"}

echo "=== All Tests Passed Successfully ==="
