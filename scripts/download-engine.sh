#!/usr/bin/env bash
set -e

TARGET_DIR="${1:-$HOME/.config/omarchy/plugins/icyleaf.bitwarden/bin}"
REPO="${2:-icyleaf/omarchy-bitwarden}"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) TRIPLE="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) TRIPLE="aarch64-unknown-linux-gnu" ;;
  *) echo "{\"ok\":false,\"error\":\"Unsupported architecture: $ARCH\"}"; exit 1 ;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

download_file() {
  if command -v curl >/dev/null 2>&1; then
    curl -sSL --max-time 60 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=60 -O "$2" "$1"
  else
    return 1
  fi
}

# 1. Fetch latest release tag via web redirect (immune to API rate limits)
if command -v curl >/dev/null 2>&1; then
  TAG=$(curl -sIL --max-time 6 "https://github.com/${REPO}/releases/latest" 2>/dev/null | grep -i "^location:" | awk -F'/tag/' '{print $2}' | tr -d ' \r\n' || true)
elif command -v wget >/dev/null 2>&1; then
  TAG=$(wget --spider -S --max-redirect=0 "https://github.com/${REPO}/releases/latest" 2>&1 | grep -i "^  Location:" | awk -F'/tag/' '{print $2}' | tr -d ' \r\n' || true)
else
  TAG=""
fi

# Fallback to API if web redirect was not found
if [ -z "$TAG" ]; then
  if command -v curl >/dev/null 2>&1; then
    RELEASE_JSON=$(curl -sSL -H "User-Agent: OmarchyBitwarden" --max-time 10 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)
  elif command -v wget >/dev/null 2>&1; then
    RELEASE_JSON=$(wget -qO- --user-agent="OmarchyBitwarden" --timeout=10 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)
  else
    RELEASE_JSON=""
  fi
  TAG=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
fi

if [ -z "$TAG" ]; then
  echo "{\"ok\":false,\"error\":\"Failed to resolve latest release tag\"}"
  exit 1
fi

VERSION="${TAG#omawarden-}"
VERSION="${VERSION#v}"

# 2. Try candidate URLs in order of preference
CANDIDATE_URLS=(
  "https://github.com/${REPO}/releases/download/${TAG}/omawarden-${VERSION}-${TRIPLE}.tar.gz"
  "https://github.com/${REPO}/releases/download/${TAG}/omawarden-${TRIPLE}.tar.gz"
)

DOWNLOADED=false
DOWNLOADED_URL=""
for URL in "${CANDIDATE_URLS[@]}"; do
  if download_file "$URL" "$TMP_DIR/omawarden.tar.gz" && [ -s "$TMP_DIR/omawarden.tar.gz" ]; then
    DOWNLOADED=true
    DOWNLOADED_URL="$URL"
    break
  fi
done

if [ "$DOWNLOADED" != "true" ]; then
  echo "{\"ok\":false,\"error\":\"Failed to download omawarden archive from release $TAG\"}"
  exit 1
fi

# 3. Download checksum and verify
download_file "${DOWNLOADED_URL}.sha256" "$TMP_DIR/omawarden.tar.gz.sha256" || true

if [ -s "$TMP_DIR/omawarden.tar.gz.sha256" ]; then
  EXPECTED_SHA=$(awk '{print $1}' "$TMP_DIR/omawarden.tar.gz.sha256" | tr -d ' \r\n')
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA=$(sha256sum "$TMP_DIR/omawarden.tar.gz" | awk '{print $1}' | tr -d ' \r\n')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA=$(shasum -a 256 "$TMP_DIR/omawarden.tar.gz" | awk '{print $1}' | tr -d ' \r\n')
  fi
  if [ -n "$EXPECTED_SHA" ] && [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    echo "{\"ok\":false,\"error\":\"SHA-256 checksum verification failed\"}"
    exit 1
  fi
fi

# 4. Extract and install
EXTRACT_DIR=$(mktemp -d)
tar -xzf "$TMP_DIR/omawarden.tar.gz" -C "$EXTRACT_DIR"
FOUND_BIN=$(find "$EXTRACT_DIR" -type f -name "omawarden" | head -n 1)
if [ -z "$FOUND_BIN" ]; then
  rm -rf "$EXTRACT_DIR"
  echo "{\"ok\":false,\"error\":\"Binary omawarden not found in archive\"}"
  exit 1
fi

mkdir -p "$TARGET_DIR"
cp "$FOUND_BIN" "$TARGET_DIR/omawarden"
chmod +x "$TARGET_DIR/omawarden"
rm -rf "$EXTRACT_DIR"

INSTALLED_VER=$("$TARGET_DIR/omawarden" --version 2>/dev/null || echo "ok")
echo "{\"ok\":true,\"version\":\"$INSTALLED_VER\",\"path\":\"$TARGET_DIR/omawarden\",\"verified\":true}"
