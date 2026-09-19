#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-$HOME/.config/omarchy/plugins/icyleaf.bitwarden/bin}"
REPO="${2:-icyleaf/omarchy-bitwarden}"
TAG="${3:-${OMAWARDEN_TAG:-}}"
ARG_EXPECTED_SHA="${4:-}"

# Validate repository format to prevent path or URL injection
if [[ ! "$REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
  echo "{\"ok\":false,\"error\":\"Invalid repository format: $REPO\"}"
  exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) TRIPLE="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) TRIPLE="aarch64-unknown-linux-gnu" ;;
  *) echo "{\"ok\":false,\"error\":\"Unsupported architecture: $ARCH\"}"; exit 1 ;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

download_file() {
  local url="$1"
  local dest="$2"
  rm -f "$dest"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 60 "$url" -o "$dest" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=60 -O "$dest" "$url" 2>/dev/null
  else
    return 1
  fi
  [ -s "$dest" ]
}

GH_HOST="${GITHUB_SERVER_URL:-https://github.com}"

# Pinned omawarden release and expected SHA-256 digests in validated plugin source
DEFAULT_PINNED_VERSION="0.8.0"
DEFAULT_PINNED_TAG="omawarden-${DEFAULT_PINNED_VERSION}"

PINNED_SHA_X86_64="cf122e2ff08c30857a5c298929b16a50c58ca513b3cf200946d5859149f35eb5"
PINNED_SHA_AARCH64="821e2e008e9cf19ce7b759c5693aa9205b072032023549a8bcc3d19558064edd"

# 1. Resolve release tag: default to immutable pinned release from validated plugin source
if [ -z "$TAG" ]; then
  TAG="$DEFAULT_PINNED_TAG"
fi

# Normalize tag name: accept 0.8.0, v0.8.0, omawarden-0.8.0, omawarden-v0.8.0
if [[ "$TAG" =~ ^omawarden-v?([0-9]+\.[0-9]+\.[0-9]+.*)$ ]]; then
  CLEAN_VER="${BASH_REMATCH[1]}"
  TAG="omawarden-${CLEAN_VER}"
elif [[ "$TAG" =~ ^v?([0-9]+\.[0-9]+\.[0-9]+.*)$ ]]; then
  CLEAN_VER="${BASH_REMATCH[1]}"
  TAG="omawarden-${CLEAN_VER}"
fi

# Sanitize release tag to prevent directory traversal or malformed injection
if ! [[ "$TAG" =~ ^omawarden-[a-zA-Z0-9._-]+$ ]]; then
  echo "{\"ok\":false,\"error\":\"Invalid release tag format: $TAG\"}"
  exit 1
fi

VERSION="${TAG#omawarden-}"
VERSION="${VERSION#v}"

# Resolve expected SHA-256 from validated plugin source
EXPECTED_SHA=""
IS_PINNED=false

if [ -n "$ARG_EXPECTED_SHA" ]; then
  EXPECTED_SHA="$ARG_EXPECTED_SHA"
  IS_PINNED=true
else
  # Check companion checksums.txt in validated plugin source
  ARCHIVE_FILE_NAME="omawarden-${VERSION}-${TRIPLE}.tar.gz"
  if [ -f "$SCRIPT_DIR/checksums.txt" ]; then
    LOOKUP_SHA=$(grep -E "[[:space:]]${ARCHIVE_FILE_NAME}\$" "$SCRIPT_DIR/checksums.txt" | head -n 1 | awk '{print $1}' | tr -d ' \r\n' | tr '[:upper:]' '[:lower:]')
    if [ -n "$LOOKUP_SHA" ]; then
      EXPECTED_SHA="$LOOKUP_SHA"
      IS_PINNED=true
    fi
  fi

  # Fallback to in-script pinned digests
  if [ -z "$EXPECTED_SHA" ] && [ "$VERSION" = "$DEFAULT_PINNED_VERSION" ]; then
    case "$TRIPLE" in
      x86_64-unknown-linux-gnu) EXPECTED_SHA="$PINNED_SHA_X86_64"; IS_PINNED=true ;;
      aarch64-unknown-linux-gnu) EXPECTED_SHA="$PINNED_SHA_AARCH64"; IS_PINNED=true ;;
    esac
  fi
fi

# 2. Try candidate URLs in order of preference
CANDIDATE_URLS=(
  "${GH_HOST}/${REPO}/releases/download/${TAG}/omawarden-${VERSION}-${TRIPLE}.tar.gz"
  "${GH_HOST}/${REPO}/releases/download/${TAG}/omawarden-${TRIPLE}.tar.gz"
  "${GH_HOST}/${REPO}/releases/download/omawarden-v${VERSION}/omawarden-${VERSION}-${TRIPLE}.tar.gz"
  "${GH_HOST}/${REPO}/releases/download/omawarden-v${VERSION}/omawarden-${TRIPLE}.tar.gz"
)

DOWNLOADED=false
DOWNLOADED_URL=""
for URL in "${CANDIDATE_URLS[@]}"; do
  if download_file "$URL" "$TMP_DIR/omawarden.tar.gz"; then
    DOWNLOADED=true
    DOWNLOADED_URL="$URL"
    break
  fi
done

if [ "$DOWNLOADED" != "true" ]; then
  echo "{\"ok\":false,\"error\":\"Failed to download omawarden archive from release $TAG\"}"
  exit 1
fi

# Ensure SHA-256 utility is available
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA=$(sha256sum "$TMP_DIR/omawarden.tar.gz" | awk '{print $1}' | tr -d ' \r\n' | tr '[:upper:]' '[:lower:]')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA=$(shasum -a 256 "$TMP_DIR/omawarden.tar.gz" | awk '{print $1}' | tr -d ' \r\n' | tr '[:upper:]' '[:lower:]')
else
  echo "{\"ok\":false,\"error\":\"No SHA-256 utility found (requires sha256sum or shasum)\"}"
  exit 1
fi

if ! [[ "$ACTUAL_SHA" =~ ^[a-f0-9]{64}$ ]]; then
  echo "{\"ok\":false,\"error\":\"Failed to compute SHA-256 checksum of downloaded archive\"}"
  exit 1
fi

# 3. Integrity and Provenance Verification (Dual-tier & Fail-closed)
VERIFIED=false
ATTESTATION_VERIFIED=false

if [ "$IS_PINNED" = "true" ]; then
  # Expected SHA-256 is pinned in the validated plugin source: verify immutably
  if ! [[ "$EXPECTED_SHA" =~ ^[a-f0-9]{64}$ ]]; then
    echo "{\"ok\":false,\"error\":\"Malformed pinned SHA-256 checksum in plugin source: $EXPECTED_SHA\"}"
    exit 1
  fi

  if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "{\"ok\":false,\"error\":\"SHA-256 checksum mismatch: expected $EXPECTED_SHA, got $ACTUAL_SHA\"}"
    exit 1
  fi
  VERIFIED=true

  # Tier 2 Provenance Verification: If gh is available, verify attestation
  if command -v gh >/dev/null 2>&1; then
    if gh attestation verify "$TMP_DIR/omawarden.tar.gz" --repo "$REPO" >/dev/null 2>&1; then
      ATTESTATION_VERIFIED=true
    else
      if [ "${REQUIRE_ATTESTATION:-0}" = "1" ]; then
        echo "{\"ok\":false,\"error\":\"Security Alert: GitHub Artifact Attestation verification failed for $REPO\"}"
        exit 1
      fi
    fi
  elif [ "${REQUIRE_ATTESTATION:-0}" = "1" ]; then
    echo "{\"ok\":false,\"error\":\"Security Alert: GitHub CLI (gh) required for strict attestation verification but not found\"}"
    exit 1
  fi
else
  # UNPINNED release: require fail-closed immutable provenance check
  # Step 3a: Verify download against release .sha256 for transport integrity
  CHECKSUM_FILE="$TMP_DIR/omawarden.tar.gz.sha256"
  if ! download_file "${DOWNLOADED_URL}.sha256" "$CHECKSUM_FILE"; then
    echo "{\"ok\":false,\"error\":\"Failed to download SHA-256 checksum file from release $TAG\"}"
    exit 1
  fi

  DOWNLOADED_SHA=$(awk '{print $1}' "$CHECKSUM_FILE" | tr -d ' \r\n' | tr '[:upper:]' '[:lower:]')
  if ! [[ "$DOWNLOADED_SHA" =~ ^[a-f0-9]{64}$ ]]; then
    echo "{\"ok\":false,\"error\":\"Malformed or invalid SHA-256 checksum in release metadata\"}"
    exit 1
  fi

  if [ "$DOWNLOADED_SHA" != "$ACTUAL_SHA" ]; then
    echo "{\"ok\":false,\"error\":\"SHA-256 checksum mismatch: expected $DOWNLOADED_SHA, got $ACTUAL_SHA\"}"
    exit 1
  fi

  # Step 3b: Fail-closed immutable provenance check is mandatory for unpinned releases
  if ! command -v gh >/dev/null 2>&1; then
    echo "{\"ok\":false,\"error\":\"Security Alert: GitHub CLI (gh) required for fail-closed provenance verification of unpinned release $TAG, but not found\"}"
    exit 1
  fi

  if ! gh attestation verify "$TMP_DIR/omawarden.tar.gz" --repo "$REPO" >/dev/null 2>&1; then
    echo "{\"ok\":false,\"error\":\"Security Alert: GitHub Artifact Attestation verification failed for unpinned release $TAG\"}"
    exit 1
  fi

  ATTESTATION_VERIFIED=true
  VERIFIED=true
fi

# 4. Extract and install (fail-closed: only if VERIFIED is true)
if [ "$VERIFIED" != "true" ]; then
  echo "{\"ok\":false,\"error\":\"Installation blocked: archive failed integrity verification\"}"
  exit 1
fi

EXTRACT_DIR=$(mktemp -d)
tar -xzf "$TMP_DIR/omawarden.tar.gz" -C "$EXTRACT_DIR"
FOUND_BIN=$(find "$EXTRACT_DIR" -type f -name "omawarden" | head -n 1)
if [ -z "$FOUND_BIN" ]; then
  rm -rf "$EXTRACT_DIR"
  echo "{\"ok\":false,\"error\":\"Binary omawarden not found in archive\"}"
  exit 1
fi

mkdir -p "$TARGET_DIR"
chmod 0755 "$FOUND_BIN"

# Terminate running daemon processes to free active sockets and file locks
if command -v pkill >/dev/null 2>&1; then
  pkill -f "$TARGET_DIR/omawarden" 2>/dev/null || true
  sleep 0.1
fi

# Use atomic unlink and copy/move to avoid Linux ETXTBSY ("Text file busy") error
rm -f "$TARGET_DIR/omawarden" 2>/dev/null || true
cp -f "$FOUND_BIN" "$TARGET_DIR/omawarden" 2>/dev/null || mv -f "$FOUND_BIN" "$TARGET_DIR/omawarden"
chmod 0755 "$TARGET_DIR/omawarden"
rm -rf "$EXTRACT_DIR"

INSTALLED_VER=$("$TARGET_DIR/omawarden" --version 2>/dev/null || echo "ok")
echo "{\"ok\":true,\"version\":\"$INSTALLED_VER\",\"path\":\"$TARGET_DIR/omawarden\",\"verified\":true,\"sha256\":\"$ACTUAL_SHA\",\"attestation_verified\":$ATTESTATION_VERIFIED}"
