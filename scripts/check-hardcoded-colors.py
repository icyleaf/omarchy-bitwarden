#!/usr/bin/env python3
"""
Static Zero-Hardcode CI Gate (Spec #291 / ADR 0026 / docs/agents/ui.md)

Enforces zero-hardcoded palettes across components/*.qml and OmarchyBitwarden.qml:
1. File-location rule: Bare hex colors (#[0-9a-fA-F]{3,8}) and numeric Qt.rgba(...)
   fills are STRICTLY prohibited outside components/StatusPalette.qml.
2. Ban on `Qt.darker(foreground, ...)`: Secondary and muted text must bind to Color.muted.

Exit codes:
- Strict is the default: any violation returns 1 so CI blocks new hardcoded colors.
- In report-only mode (--report-only, or STRICT_COLOR_GATE=0): prints violations
  and returns 0. Use it for local triage only.
"""

import argparse
import glob
import os
import re
import sys

HEX_PATTERN = re.compile(r"#[0-9a-fA-F]{3,8}\b")
NUMERIC_RGBA_PATTERN = re.compile(r"Qt\.rgba\(\s*[\d\.]+\s*,\s*[\d\.]+\s*,\s*[\d\.]+\s*,", re.IGNORECASE)
QT_DARKER_FOREGROUND_PATTERN = re.compile(r"Qt\.darker\([^)]*foreground", re.IGNORECASE)


def strip_comments(text: str) -> list[tuple[int, str]]:
    """
    Strips single-line (//) and multi-line (/* */) comments while preserving
    1-based line numbers. Returns list of (line_number, line_code).
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
                    break
                else:
                    clean += line[i]
                    i += 1
        result.append((idx, clean))

    return result


def scan_file(path: str, is_palette_exempt: bool = False) -> list[str]:
    """
    Scans a single QML file for theme compliance violations.
    If is_palette_exempt is True, bare hex and numeric values are allowed.
    """
    if is_palette_exempt:
        return []

    violations = []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    stripped_lines = strip_comments(content)

    for line_num, line in stripped_lines:
        # Check 1: Qt.darker with foreground
        if QT_DARKER_FOREGROUND_PATTERN.search(line):
            violations.append(
                f"{path}:{line_num}: Banned Qt.darker(foreground) call: '{line.strip()}'\n"
                f"  Remediation: Bind secondary/caption text to Color.muted (ADR 0026 Rule 3)."
            )

        # Check 2: Banned numeric Qt.rgba(r, g, b, a)
        if NUMERIC_RGBA_PATTERN.search(line):
            violations.append(
                f"{path}:{line_num}: Banned numeric-RGB Qt.rgba literal: '{line.strip()}'\n"
                f"  Remediation: Derive translucent wash from StatusPalette.tint(role, alpha) or Qt.rgba(color.r, color.g, color.b, alpha)."
            )

        # Check 3: Bare hex colors outside StatusPalette.qml
        for match in HEX_PATTERN.finditer(line):
            violations.append(
                f"{path}:{line_num}: Banned bare hex color '{match.group(0)}': '{line.strip()}'\n"
                f"  Remediation: Move status color to components/StatusPalette.qml or use an existing palette role."
            )

    return violations


def run_self_tests() -> bool:
    """
    Self-tests for the static color gate covering all acceptance criteria:
    - hex outside palette fails
    - hex inside palette passes
    - numeric Qt.rgba fails
    - role-derived Qt.rgba passes
    - comments ignored
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        # Fixture 1: Hex outside palette fails
        bad_hex = os.path.join(tmpdir, "BadHex.qml")
        with open(bad_hex, "w") as f:
            f.write("Item { property color c: \"#123456\" }\n")
        v_bad_hex = scan_file(bad_hex, is_palette_exempt=False)
        assert len(v_bad_hex) == 1, f"Expected 1 violation for bad hex, got {len(v_bad_hex)}"

        # Fixture 2: Hex inside palette passes
        palette_file = os.path.join(tmpdir, "StatusPalette.qml")
        with open(palette_file, "w") as f:
            f.write("QtObject { readonly property color ok: \"#4ade80\" }\n")
        v_palette = scan_file(palette_file, is_palette_exempt=True)
        assert len(v_palette) == 0, f"Expected 0 violations for palette, got {len(v_palette)}"

        # Fixture 3: Numeric Qt.rgba fails
        bad_rgba = os.path.join(tmpdir, "BadRgba.qml")
        with open(bad_rgba, "w") as f:
            f.write("Rectangle { color: Qt.rgba(0.2, 0.8, 0.4, 0.15) }\n")
            f.write("Rectangle { color: Qt.rgba(1, 1, 1, 0.2) }\n")
            f.write("Rectangle { color: Qt.rgba(255, 255, 255, 0.08) }\n")
        v_bad_rgba = scan_file(bad_rgba, is_palette_exempt=False)
        assert len(v_bad_rgba) == 3, f"Expected 3 violations for bad rgba, got {len(v_bad_rgba)}"

        # Fixture 4: Role-derived Qt.rgba passes
        good_rgba = os.path.join(tmpdir, "GoodRgba.qml")
        with open(good_rgba, "w") as f:
            f.write("Rectangle { color: Qt.rgba(fg.r, fg.g, fg.b, 0.08) }\n")
            f.write("Rectangle { color: StatusPalette.tint(StatusPalette.error, 0.15) }\n")
        v_good_rgba = scan_file(good_rgba, is_palette_exempt=False)
        assert len(v_good_rgba) == 0, f"Expected 0 violations for good rgba, got {len(v_good_rgba)}"

        # Fixture 5: Comments ignored
        comments_file = os.path.join(tmpdir, "Comments.qml")
        with open(comments_file, "w") as f:
            f.write("// #123456 in single line comment\n")
            f.write("/* #abcdef in multi-line\n   Qt.rgba(1, 1, 1, 0.5)\n   Qt.darker(foreground, 1.2) */\n")
        v_comments = scan_file(comments_file, is_palette_exempt=False)
        assert len(v_comments) == 0, f"Expected 0 violations for comments, got {len(v_comments)}"

    print("PASS: check-hardcoded-colors self-tests (all 5 fixture checks succeeded).")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Static Zero-Hardcode CI Gate")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on violations (default; kept for compatibility)")
    parser.add_argument("--report-only", action="store_true", help="Print violations but exit 0 (local triage only)")
    parser.add_argument("--summary", action="store_true", help="Print per-file violation counts instead of every hit")
    parser.add_argument("--self-test", action="store_true", help="Run fixture test suite")
    args = parser.parse_args()

    if args.self_test:
        return 0 if run_self_tests() else 1

    strict_mode = not args.report_only and os.environ.get("STRICT_COLOR_GATE", "1") != "0"

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_files = [os.path.join(root_dir, "OmarchyBitwarden.qml")]
    target_files.extend(sorted(glob.glob(os.path.join(root_dir, "components", "*.qml"))))

    total_violations = []
    scanned_count = 0

    print("=== Checking QML Static Theme Compliance (Spec #291 / ADR 0026) ===")
    for file_path in target_files:
        if not os.path.isfile(file_path):
            continue
        rel_path = os.path.relpath(file_path, root_dir)
        scanned_count += 1
        is_palette = (os.path.basename(file_path) == "StatusPalette.qml")
        violations = scan_file(file_path, is_palette_exempt=is_palette)
        if violations:
            total_violations.extend(violations)

    if total_violations:
        print(f"Found {len(total_violations)} theme compliance violation(s):\n")
        if not args.summary:
            for v in total_violations:
                print(f"  ✗ {v}\n")

        counts = {}
        for v in total_violations:
            path = v.split(":", 1)[0]
            counts[path] = counts.get(path, 0) + 1
        print("Violations per file:")
        for path, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {os.path.relpath(path, root_dir)}: {count}")
        print()

        if strict_mode:
            print(f"FAILED (Strict Mode): {len(total_violations)} violation(s) must be resolved.")
            return 1
        else:
            print(f"[REPORT-ONLY] {len(total_violations)} violation(s) reported.")
            print("Note: report-only mode never fails; it exists for local triage, not for CI.")
            return 0

    print(f"PASSED: {scanned_count} QML files scanned cleanly. Zero theme violations found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
