#!/usr/bin/env bash
set -e

TARGET_DIR="${1:-$HOME/.config/omarchy/plugins/icyleaf.bitwarden/bin}"
REPO="${2:-icyleaf/omarchy-bitwarden}"
TAG="${3:-${OMAWARDEN_TAG:-}}"

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

# 1. Resolve release tag: use pinned tag if provided, otherwise fetch latest release
if [ -n "$TAG" ]; then
  # Normalize tag name if only version number was supplied
  if [[ "$TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+.*$ ]]; then
    CLEAN_VER="${TAG#v}"
    TAG="omawarden-v${CLEAN_VER}"
  fi
else
  # Fetch latest omawarden release tag via Atom feed (immune to API rate limits)
  if command -v curl >/dev/null 2>&1; then
    TAG=$(curl -fsSL --max-time 6 "${GH_HOST}/${REPO}/releases.atom" 2>/dev/null | grep -o 'releases/tag/omawarden-[^"/]*' | head -n 1 | cut -d'/' -f3 || true)
  elif command -v wget >/dev/null 2>&1; then
    TAG=$(wget -qO- --timeout=6 "${GH_HOST}/${REPO}/releases.atom" 2>/dev/null | grep -o 'releases/tag/omawarden-[^"/]*' | head -n 1 | cut -d'/' -f3 || true)
  fi

  # Fallback to GitHub Releases API if Atom feed was not resolved
  if [ -z "$TAG" ]; then
    if [ "$GH_HOST" = "https://github.com" ]; then
      API_URL="https://api.github.com/repos/${REPO}/releases?per_page=10"
    else
      API_URL="${GH_HOST}/api/v3/repos/${REPO}/releases?per_page=10"
    fi
    if command -v curl >/dev/null 2>&1; then
      RELEASE_JSON=$(curl -fsSL -H "User-Agent: OmarchyBitwarden" --max-time 10 "$API_URL" 2>/dev/null || true)
    elif command -v wget >/dev/null 2>&1; then
      RELEASE_JSON=$(wget -qO- --user-agent="OmarchyBitwarden" --timeout=10 "$API_URL" 2>/dev/null || true)
    else
      RELEASE_JSON=""
    fi
    TAG=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"omawarden-[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  fi
fi

if [ -z "$TAG" ]; then
  echo "{\"ok\":false,\"error\":\"Failed to resolve release tag\"}"
  exit 1
fi

# Sanitize release tag to prevent directory traversal or malformed injection
if ! [[ "$TAG" =~ ^omawarden-[a-zA-Z0-9._-]+$ ]]; then
  echo "{\"ok\":false,\"error\":\"Invalid release tag format: $TAG\"}"
  exit 1
fi

VERSION="${TAG#omawarden-}"
VERSION="${VERSION#v}"

# 2. Try candidate URLs in order of preference
CANDIDATE_URLS=(
  "${GH_HOST}/${REPO}/releases/download/${TAG}/omawarden-${VERSION}-${TRIPLE}.tar.gz"
  "${GH_HOST}/${REPO}/releases/download/${TAG}/omawarden-${TRIPLE}.tar.gz"
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

# 3. Download checksum and verify (fail-closed)
CHECKSUM_FILE="$TMP_DIR/omawarden.tar.gz.sha256"
if ! download_file "${DOWNLOADED_URL}.sha256" "$CHECKSUM_FILE"; then
  echo "{\"ok\":false,\"error\":\"Failed to download SHA-256 checksum file from release $TAG\"}"
  exit 1
fi

EXPECTED_SHA=$(awk '{print $1}' "$CHECKSUM_FILE" | tr -d ' \r\n' | tr '[:upper:]' '[:lower:]')

# Validate that expected checksum is a valid 64-character hexadecimal SHA-256 string
if ! [[ "$EXPECTED_SHA" =~ ^[a-f0-9]{64}$ ]]; then
  echo "{\"ok\":false,\"error\":\"Malformed or invalid SHA-256 checksum in release metadata\"}"
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

if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  echo "{\"ok\":false,\"error\":\"SHA-256 checksum mismatch: expected $EXPECTED_SHA, got $ACTUAL_SHA\"}"
  exit 1
fi

VERIFIED=true

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
echo "{\"ok\":true,\"version\":\"$INSTALLED_VER\",\"path\":\"$TARGET_DIR/omawarden\",\"verified\":true}"
