#!/usr/bin/env python3
"""
QML Module Manifest Gate

components/qmldir turns components/ into an explicit QML module. Quickshell
resolves that module through the manifest alone, so a component missing from
it is "not a type" at runtime, while qmllint and the qml6 test suites still
resolve it from the directory because they never read the manifest. A plugin
that refused to open (SearchHeader could not build CategoryTabBar) shipped
exactly that way, so the manifest is gated here.

Checks:
1. Every components/*.qml is declared, and declared against its own file name.
2. Every declaration points at a file that exists.
3. A file containing `pragma Singleton` is declared with the `singleton` flag.

Exit codes:
- 0 when the manifest matches the directory.
- 1 when it does not, so CI blocks a component that would only break at runtime.
"""

import argparse
import os
import re
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPONENTS_DIR = os.path.join(ROOT_DIR, "components")
MANIFEST_PATH = os.path.join(COMPONENTS_DIR, "qmldir")

DECLARATION_PATTERN = re.compile(
    r"^(singleton\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+(\d+\.\d+)\s+([A-Za-z0-9_.\-]+\.qml)$"
)


def parse_manifest(manifest_path: str) -> tuple[dict, list[str]]:
    """Returns (declarations keyed by type name, parse errors)."""
    declarations = {}
    errors = []

    with open(manifest_path, encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            match = DECLARATION_PATTERN.match(line)
            if not match:
                errors.append(f"qmldir:{line_number}: unparsable declaration: {line}")
                continue

            singleton, name, _version, file_name = match.groups()
            declarations[name] = {
                "file": file_name,
                "singleton": singleton is not None,
                "line": line_number,
            }

    return declarations, errors


def check_module(components_dir: str, manifest_path: str) -> list[str]:
    """Returns every mismatch between the manifest and the directory."""
    if not os.path.isfile(manifest_path):
        return [f"missing manifest: {os.path.relpath(manifest_path, ROOT_DIR)}"]

    declarations, failures = parse_manifest(manifest_path)
    qml_files = sorted(
        name for name in os.listdir(components_dir) if name.endswith(".qml")
    )

    for file_name in qml_files:
        type_name = file_name[: -len(".qml")]
        declaration = declarations.get(type_name)

        if declaration is None:
            failures.append(
                f"components/{file_name}: not declared in components/qmldir "
                f"(add `{type_name} 1.0 {file_name}`)"
            )
            continue

        if declaration["file"] != file_name:
            failures.append(
                f"components/{file_name}: declared as {declaration['file']} on line "
                f"{declaration['line']}"
            )

        with open(os.path.join(components_dir, file_name), encoding="utf-8") as handle:
            is_singleton = "pragma Singleton" in handle.read()

        if is_singleton and not declaration["singleton"]:
            failures.append(
                f"components/{file_name}: has `pragma Singleton` but is declared without "
                f"the `singleton` flag on line {declaration['line']}"
            )
        elif declaration["singleton"] and not is_singleton:
            failures.append(
                f"components/{file_name}: declared as a singleton on line "
                f"{declaration['line']} but has no `pragma Singleton`"
            )

    for type_name, declaration in declarations.items():
        if not os.path.isfile(os.path.join(components_dir, declaration["file"])):
            failures.append(
                f"qmldir:{declaration['line']}: {type_name} points at missing "
                f"{declaration['file']}"
            )

    return failures


def run_self_tests() -> bool:
    """Fixtures covering the three ways a manifest can drift from the directory."""
    import tempfile

    def build(tmpdir: str, manifest: str, files: dict) -> str:
        components = os.path.join(tmpdir, "components")
        os.makedirs(components, exist_ok=True)
        for name, content in files.items():
            with open(os.path.join(components, name), "w", encoding="utf-8") as handle:
                handle.write(content)
        path = os.path.join(components, "qmldir")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(manifest)
        return components, path

    with tempfile.TemporaryDirectory() as tmpdir:
        # Fixture 1: complete manifest passes
        components, manifest = build(
            tmpdir,
            "singleton Palette 1.0 Palette.qml\nCard 1.0 Card.qml\n",
            {"Palette.qml": "pragma Singleton\nQtObject {}\n", "Card.qml": "Item {}\n"},
        )
        assert check_module(components, manifest) == [], "complete manifest should pass"

        # Fixture 2: undeclared component fails
        components, manifest = build(
            os.path.join(tmpdir, "undeclared"),
            "singleton Palette 1.0 Palette.qml\n",
            {"Palette.qml": "pragma Singleton\nQtObject {}\n", "Card.qml": "Item {}\n"},
        )
        assert any("Card.qml" in f for f in check_module(components, manifest)), (
            "undeclared component should fail"
        )

        # Fixture 3: singleton flag missing fails
        components, manifest = build(
            os.path.join(tmpdir, "singleton-flag"),
            "Palette 1.0 Palette.qml\n",
            {"Palette.qml": "pragma Singleton\nQtObject {}\n"},
        )
        assert any("pragma Singleton" in f for f in check_module(components, manifest)), (
            "missing singleton flag should fail"
        )

        # Fixture 4: declaration pointing at a missing file fails
        components, manifest = build(
            os.path.join(tmpdir, "missing-file"),
            "Ghost 1.0 Ghost.qml\n",
            {},
        )
        assert any("missing" in f for f in check_module(components, manifest)), (
            "declaration to a missing file should fail"
        )

    print("PASS: check-qml-module self-tests (all 4 fixture checks succeeded).")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="QML Module Manifest Gate")
    parser.add_argument("--self-test", action="store_true", help="Run fixture test suite")
    args = parser.parse_args()

    if args.self_test:
        return 0 if run_self_tests() else 1

    print("=== Checking QML Module Manifest (components/qmldir) ===")
    failures = check_module(COMPONENTS_DIR, MANIFEST_PATH)

    if failures:
        print(f"Found {len(failures)} manifest problem(s):\n")
        for failure in failures:
            print(f"  ✗ {failure}\n")
        print("FAILED: components/qmldir must declare every component exactly once.")
        return 1

    declared = len(parse_manifest(MANIFEST_PATH)[0])
    print(f"PASSED: components/qmldir declares all {declared} components.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
