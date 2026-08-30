#!/usr/bin/env bash
set -e

REPO="${1:-icyleaf/omarchy-bitwarden}"

# 1. Try web redirect first (not subject to GitHub REST API rate limits)
if command -v curl >/dev/null 2>&1; then
  TAG=$(curl -sIL --max-time 6 "https://github.com/${REPO}/releases/latest" 2>/dev/null | grep -i "^location:" | awk -F'/tag/' '{print $2}' | tr -d ' \r\n' || true)
elif command -v wget >/dev/null 2>&1; then
  TAG=$(wget --spider -S --max-redirect=0 "https://github.com/${REPO}/releases/latest" 2>&1 | grep -i "^  Location:" | awk -F'/tag/' '{print $2}' | tr -d ' \r\n' || true)
else
  TAG=""
fi

# 2. Fallback to GitHub REST API if redirect was empty
if [ -z "$TAG" ]; then
  if command -v curl >/dev/null 2>&1; then
    TAG=$(curl -sSL -H "User-Agent: OmarchyBitwarden" --max-time 6 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  elif command -v wget >/dev/null 2>&1; then
    TAG=$(wget -qO- --user-agent="OmarchyBitwarden" --timeout=6 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  fi
fi

if [ -n "$TAG" ]; then
  echo "{\"ok\":true,\"tag\":\"$TAG\"}"
else
  echo "{\"ok\":false,\"error\":\"Failed to fetch latest release metadata\"}"
fi
