# ADR 0026: Theme Color Tokens and Zero-Hardcoded Palettes

## Status
Accepted

## Context
When switching Omarchy to light themes such as `catppuccin-latte` or `flexoki-light`, the desktop environment transitions to light surfaces (`background = "#eff1f5"`, `foreground = "#4c4f69"`), but the `omarchy-bitwarden` overlay suffered severe visual breakage (tracked in GitHub Issue #265):
1. **Unreadable Modals (Dark on Dark)**: Floating modal dialog cards (`ActionPaletteModal`, `PasswordGeneratorModal`, `SshApprovalModal`, etc.) hardcoded their background fill to dark slate (`Qt.rgba(0.12, 0.14, 0.18, 0.98)`). However, they received the light-theme dark text (`#4c4f69`), resulting in dark text on dark surfaces.
2. **Invisible Selection (White on Light)**: Item lists and palettes hardcoded selected text to `#ffffff`. In light themes, `selectedBackground` is a subtle 8% tint of foreground, making white text completely invisible.
3. **Contrast Inversion via `Qt.darker()`**: The UI repeatedly used `Qt.darker(foreground, ...)` to derive secondary or muted text. In a light theme where `foreground` is already dark, `Qt.darker()` produces near-pitch-black text, inverting the visual hierarchy instead of softening it.
4. **Undefined Muted Reference**: `AuthView.qml` referenced `authRoot.muted` without declaring the property, producing `Unable to assign [undefined] to QColor` runtime errors.
5. **No Test Verification**: The test stubs under `tests/stubs/qs/Commons/` only provided `Style.qml` without `Color.qml`, leaving CI blind to color regressions.

## Decision
1. **Mandatory Surface Role Mapping**:
   - The main overlay window binds to `Color.menu.background` and `Color.menu.border`.
   - All floating modal dialogs, cards, and dropdown popups MUST bind their card background to `Color.popups.background` and border to `Color.popups.border`.
   - Interactive item selection MUST bind text to `Color.menu.selectedText` and background to `Color.menu.selectedBackground`.
2. **Strict Ban on Bare Hex and Fixed Dark Alphas**:
   - Hardcoding bare hex color codes (such as `#ffffff` or `#1f242e`) for UI surfaces and text is strictly prohibited in `components/` and `OmarchyBitwarden.qml`.
   - Fixed dark alpha fills (such as `Qt.rgba(0, 0, 0, 0.25)` or `Qt.rgba(0.12, 0.14, 0.18, 0.98)`) are banned; controls must use `Style.controlFill` or alpha blends computed from `foreground`.
3. **Strict Ban on `Qt.darker(foreground, ...)` for Muted Text**:
   - Secondary labels, captions, and placeholders must bind to `Color.muted`.
   - Child components requiring secondary text must declare `property color muted: Color.muted` and inherit it from the root overlay.
4. **Dual-Mode Testing & CI Guardrails**:
   - Add `Color.qml` to `tests/stubs/qs/Commons/` providing both Dark (Tokyo Night) and Light (Catppuccin Latte) presets for headless `qml6` execution.
   - Enforce static color checks in `scripts/test-all.sh` to fail CI if unapproved bare hex colors are introduced in `components/`.

## Alternatives Considered
- **Keep Dark Identity Exclusively**: Preserving a fixed dark look regardless of desktop theme. Rejected because Omarchy is an integrated desktop environment where cohesive theming across bar, menus, and plugins is a foundational design principle.
- **Manual Light/Dark Mode Detection via `colors.toml` Parsing**: Detecting `mode == "light"` inside the plugin and maintaining two separate local palettes. Rejected because `qs.Commons.Color` already handles live hot-reloading and token abstraction natively; introducing custom parsing creates duplicate maintenance overhead and misses theme-specific accents.

## Consequences
- **Positive**: The overlay seamlessly and instantly adapts to all stock and custom Omarchy themes (dark and light) without restarts or manual toggling; eliminates runtime binding errors; resolves Issue #265.
- **Trade-off**: Requires `tests/stubs/qs/Commons/Color.qml` to be maintained alongside `Style.qml` so headless component tests continue to run without a live `omarchy-shell` process.
