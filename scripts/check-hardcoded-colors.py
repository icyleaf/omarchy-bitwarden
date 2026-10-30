#!/usr/bin/env python3
"""
Static Zero-Hardcode CI Gate (Issue #276 / ADR 0026 / docs/agents/ui.md)

Scans components/*.qml and OmarchyBitwarden.qml to enforce:
1. Strict ban on `Qt.darker(foreground, ...)` or any derivation of secondary/muted
   text by darkening foreground.
2. Ban on unapproved bare hex colors (#[0-9a-fA-F]{3,8}), ensuring surfaces and text
   derive dynamically from Commons.Color tokens.

Approved hex colors are strictly limited to semantic status indicators,
diagnostic log level badges, and password complexity rating meters.
"""

import glob
import os
import re
import sys

# Approved semantic status, diagnostic badge, and contrast hex codes (case-insensitive)
APPROVED_HEX_COLORS = {
    # Text-on-accent / saturated status contrast
    "#ffffff",
    # Health dot / online status indicators
    "#4ade80",  # online (green)
    "#f87171",  # offline / destructive (red)
    # Diagnostic log levels & badge pills
    "#ef4444",  # fatal / error (red)
    "#f59e0b",  # warn (amber)
    "#3b82f6",  # info (blue)
    "#a855f7",  # debug (purple)
    "#6b7280",  # trace (gray)
    # AUR & packaging badges
    "#89b4fa",  # AUR badge sapphire
    "#f9e2af",  # AUR badge yellow / checking
    "#a6e3a1",  # installed package green
    "#f38ba8",  # missing package red
    "#22c55e",  # update action green
    # Password strength ratings
    "#34d399",  # strong (emerald)
    "#60a5fa",  # fair (blue)
    "#fbbf24",  # weak (amber)
    "#fca5a5",  # invalid / weak key (light red)
    # Copy / confirmation feedback
    "#10b981",  # copied success (green)
}

HEX_PATTERN = re.compile(r"#[0-9a-fA-F]{3,8}\b")
QT_DARKER_FOREGROUND_PATTERN = re.compile(r"Qt\.darker\([^)]*foreground", re.IGNORECASE)


def strip_comments(text: str) -> list[tuple[int, str]]:
    """
    Strips single-line and multi-line comments while preserving 1-based line numbers.
    Returns a list of (line_number, line_code).
    """
    lines = text.split("\n")
    in_multiline = False
    result = []

    for idx, line in enumerate(lines, start=1):
        clean = ""
        i = 0
        n = len(line)
        while i < n:
            if in_multiline:
                if i + 1 < n and line[i : i + 2] == "*/":
                    in_multiline = False
                    i += 2
                else:
                    i += 1
            else:
                if i + 1 < n and line[i : i + 2] == "/*":
                    in_multiline = True
                    i += 2
                elif i + 1 < n and line[i : i + 2] == "//":
                    # Rest of line is comment
                    break
                else:
                    clean += line[i]
                    i += 1
        result.append((idx, clean))

    return result


def scan_file(path: str) -> list[str]:
    violations = []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    stripped_lines = strip_comments(content)

    for line_num, line in stripped_lines:
        # Check 1: Qt.darker with foreground
        if QT_DARKER_FOREGROUND_PATTERN.search(line):
            violations.append(
                f"{path}:{line_num}: Banned Qt.darker(foreground) call: '{line.strip()}'\n"
                f"  Rule: Secondary and muted text MUST bind to Color.muted instead of darkening foreground."
            )

        # Check 2: Unapproved bare hex colors
        for match in HEX_PATTERN.finditer(line):
            hex_code = match.group(0).lower()
            if hex_code not in APPROVED_HEX_COLORS:
                violations.append(
                    f"{path}:{line_num}: Unapproved bare hex color '{match.group(0)}': '{line.strip()}'\n"
                    f"  Rule: Surfaces and text MUST derive dynamically from Commons.Color tokens."
                )

    return violations


def main() -> int:
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_files = [os.path.join(root_dir, "OmarchyBitwarden.qml")]
    target_files.extend(sorted(glob.glob(os.path.join(root_dir, "components", "*.qml"))))

    total_violations = []
    scanned_count = 0

    print("=== Checking QML Static Theme Compliance (Zero-Hardcode Gate) ===")
    for file_path in target_files:
        if not os.path.isfile(file_path):
            continue
        rel_path = os.path.relpath(file_path, root_dir)
        scanned_count += 1
        violations = scan_file(file_path)
        if violations:
            total_violations.extend(violations)

    if total_violations:
        print(f"FAILED: Found {len(total_violations)} theme compliance violation(s):\n")
        for v in total_violations:
            print(f"  ✗ {v}\n")
        return 1

    print(f"PASSED: {scanned_count} QML files scanned cleanly. Zero theme violations found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
