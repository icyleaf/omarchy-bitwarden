#!/usr/bin/env bash
set -e

REPO="${1:-icyleaf/omarchy-bitwarden}"

# 1. Try using python3 for full JSON fetching and safe parsing (releases API)
if command -v python3 >/dev/null 2>&1; then
  python3 - <<EOF
import json, sys, urllib.request

repo = "${REPO}"
headers = {"User-Agent": "OmarchyBitwarden"}
req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
try:
    with urllib.request.urlopen(req, timeout=6) as response:
        data = json.loads(response.read().decode())
        tag = data.get("tag_name", "")
        name = data.get("name", "")
        body = data.get("body", "")
        url = data.get("html_url", "")
        pub = data.get("published_at", "")
        if tag:
            print(json.dumps({
                "ok": True,
                "tag": tag,
                "name": name,
                "body": body,
                "url": url,
                "published_at": pub
            }))
            sys.exit(0)
except Exception:
    pass
sys.exit(1)
EOF
  if [ $? -eq 0 ]; then
    exit 0
  fi
fi

# 2. Fallback: Try web redirect (not subject to GitHub REST API rate limits)
if command -v curl >/dev/null 2>&1; then
  TAG=$(curl -sIL --max-time 6 "https://github.com/${REPO}/releases/latest" 2>/dev/null | grep -i "^location:" | awk -F'/tag/' '{print $2}' | tr -d ' \r\n' || true)
elif command -v wget >/dev/null 2>&1; then
  TAG=$(wget --spider -S --max-redirect=0 "https://github.com/${REPO}/releases/latest" 2>&1 | grep -i "^  Location:" | awk -F'/tag/' '{print $2}' | tr -d ' \r\n' || true)
else
  TAG=""
fi

# 3. Fallback: GitHub REST API via curl/wget
if [ -z "$TAG" ]; then
  if command -v curl >/dev/null 2>&1; then
    TAG=$(curl -sSL -H "User-Agent: OmarchyBitwarden" --max-time 6 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  elif command -v wget >/dev/null 2>&1; then
    TAG=$(wget -qO- --user-agent="OmarchyBitwarden" --timeout=6 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  fi
fi

if [ -n "$TAG" ]; then
  echo "{\"ok\":true,\"tag\":\"$TAG\",\"url\":\"https://github.com/${REPO}/releases/tag/${TAG}\"}"
else
  echo "{\"ok\":false,\"error\":\"Failed to fetch latest release metadata\"}"
fi
