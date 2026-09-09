#!/usr/bin/env bash
set -e

REPO="${1:-icyleaf/omarchy-bitwarden}"

# Validate repository format to prevent script and URL injection
if [[ ! "$REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]]; then
  echo '{"ok":false,"error":"Invalid repository format"}'
  exit 1
fi

# 1. Try using python3 for full JSON fetching and safe parsing (releases API)
if command -v python3 >/dev/null 2>&1; then
  python3 - "$REPO" << 'EOF'
import json, sys, urllib.request

repo = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else "icyleaf/omarchy-bitwarden"
headers = {"User-Agent": "OmarchyBitwarden"}
req = urllib.request.Request(f"https://api.github.com/repos/{repo}/releases?per_page=10", headers=headers)
try:
    with urllib.request.urlopen(req, timeout=6) as response:
        releases = json.loads(response.read().decode())
        for r in releases:
            tag = r.get("tag_name", "")
            if tag.startswith("omawarden-") and not r.get("draft") and not r.get("prerelease"):
                name = r.get("name", "")
                body = r.get("body", "")
                url = r.get("html_url", "")
                pub = r.get("published_at", "")
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

# 2. Fallback: Try Atom feed (not subject to GitHub REST API rate limits)
if command -v curl >/dev/null 2>&1; then
  TAG=$(curl -sSL --max-time 6 "https://github.com/${REPO}/releases.atom" 2>/dev/null | grep -o 'releases/tag/omawarden-[^"/]*' | head -n 1 | cut -d'/' -f3 || true)
elif command -v wget >/dev/null 2>&1; then
  TAG=$(wget -qO- --timeout=6 "https://github.com/${REPO}/releases.atom" 2>/dev/null | grep -o 'releases/tag/omawarden-[^"/]*' | head -n 1 | cut -d'/' -f3 || true)
else
  TAG=""
fi

# 3. Fallback: GitHub REST API via curl/wget
if [ -z "$TAG" ]; then
  if command -v curl >/dev/null 2>&1; then
    TAG=$(curl -sSL -H "User-Agent: OmarchyBitwarden" --max-time 6 "https://api.github.com/repos/${REPO}/releases?per_page=10" 2>/dev/null | grep -o '"tag_name": *"omawarden-[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  elif command -v wget >/dev/null 2>&1; then
    TAG=$(wget -qO- --user-agent="OmarchyBitwarden" --timeout=6 "https://api.github.com/repos/${REPO}/releases?per_page=10" 2>/dev/null | grep -o '"tag_name": *"omawarden-[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
  fi
fi

if [ -n "$TAG" ]; then
  echo "{\"ok\":true,\"tag\":\"$TAG\",\"url\":\"https://github.com/${REPO}/releases/tag/${TAG}\"}"
else
  echo "{\"ok\":false,\"error\":\"Failed to fetch latest release metadata\"}"
fi
