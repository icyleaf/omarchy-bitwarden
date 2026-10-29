# Frontend (QML) UI Design & Architecture Specifications

This document defines the mandatory design specifications, container behaviors, visual conventions, and process lifecycle standards for developing and extending the Quickshell / QML frontend in `omarchy-bitwarden`.

---

## 1. Dynamic Secret & Token Containers

### Unbounded Content Wrapping & Dynamic Height
Any container, modal, or input presenting unbounded or long credentials (5–128 character passwords, multi-word Diceware passphrases, SSH public/private keys, certificates, or tokens) **MUST NOT** rely on single-line inputs or fixed-height bounding boxes.

- **Wrapping**: Apply `wrapMode: TextEdit.WrapAnywhere` (or `Text.WrapAnywhere`) to prevent text from clipping or overflowing past horizontal component bounds.
- **Dynamic Adaptive Height**: Bind container height to text content metrics:
  ```qml
  Layout.preferredHeight: Math.max(52, secretTextEdit.contentHeight + 20)
  Behavior on Layout.preferredHeight {
    NumberAnimation { duration: 120; easing.type: Easing.OutQuad }
  }
  ```
- **Readability & Character Class Styling**:
  Where visual clarity aids credential transcription (such as differentiating digits `0-9` from letters), use rich text formatting (`textFormat: TextEdit.RichText`):
  - Highlight digits using the theme `accent` color.
  - Always sanitize HTML entities (`&`, `<`, `>`, `"`) before rendering rich text.

---

## 2. Interactive Control Lifecycle & Debouncing

### Rapid Input Throttle & In-Flight Cancellation
Interactive controls (sliders, continuous spinboxes, search inputs) that trigger background process executions (`Process { ... }` executing `omawarden` CLI or Daemon IPC) **MUST** prevent socket flooding, thread pool starvation, and UI flickering.

- **Debounce Timer**: High-frequency value changes (e.g. `Slider.onMoved`) must defer process dispatching through a debounced `Timer` (typically `150ms` – `250ms`).
- **In-Flight Cancellation**: Before starting a new process invocation, verify and terminate any active execution:
  ```qml
  if (workerProcess.running) {
    workerProcess.kill()
  }
  workerProcess.command = [...]
  workerProcess.running = true
  ```
- **Error Guarding**: Prevent transient error displays while controls are actively in transit. Only surface failure states once the final settled invocation terminates with an error.

---

## 3. Human-Centric Metric Presentation

### User-Friendly Translation of Machine Entropy
Technical entropy metrics (such as Shannon entropy bits, raw bitmasks, or algorithm numbers) must be converted into user-actionable visual indicators:
- **Strength Ratings**: Map bits to qualitative states:
  - `< 36 bits`: Very Weak (Red)
  - `36..52 bits`: Weak (Orange)
  - `52..68 bits`: Fair / Medium (Yellow)
  - `68..80 bits`: Strong (Green)
  - `>= 80 bits`: Very Strong (Accent / Blue)
- **Visual Meters**: Render segmented progress bars alongside qualitative labels, avoiding raw bits display in primary glance areas.

---

## 4. Modal Header & Dismissal Ergonomics

### Header Cleanliness & Non-Redundant Close Actions
- Modal headers must remain focused on titles and primary mode selectors.
- If a modal provides bottom action buttons (e.g. a dedicated "Close" button in the footer) and supports standard `Escape` key dismissal or overlay backdrop clicking, **avoid redundant top-right 'X' close buttons** that clutter the header layout.
- Maintain consistent keyboard escape semantics across all modals via `root.hasActiveModal` focus restoration traps.

---

## 5. Omarchy Theme & Surface Color Contract

To maintain visual harmony and full dynamic accessibility across all official and user-defined Omarchy themes (both dark themes like `tokyo-night` and light themes like `catppuccin-latte`), all frontend QML components **MUST strictly comply** with the following theming invariants:

### Rule 1: Zero Hardcoded Palettes (Strict Ban on Bare Hex and Fixed Dark Alphas)
Components **MUST NOT** define hardcoded hex colors (`#ffffff`, `#1f242e`, `#111827`, etc.) or static dark fills (e.g. `Qt.rgba(0.12, 0.14, 0.18, 0.98)` or `Qt.rgba(0, 0, 0, 0.25)`) for surfaces, text, or interactive borders:
- **Main Overlay**: Window background and chrome MUST derive from `Color.menu.background` and `Color.menu.border`.
- **Modal Dialog Cards & Dropdowns**: Floating modal cards (Action Palette, Password Generator, SSH Approval, Settings, Release Notes, etc.) and dropdown popups MUST bind card background to `Color.popups.background` and borders to `Color.popups.border`.
- **Component Inputs**: Text fields and input boxes MUST use `Style.controlFill` or alpha-blended `foreground` values rather than fixed black/white tints.

### Rule 2: Strict Ban on `Qt.darker(foreground, ...)` for Secondary / Muted Text
Never derive secondary or muted text colors via `Qt.darker(foreground, <factor>)`. In light themes (such as `catppuccin-latte`), `foreground` is already dark (`#4c4f69`), causing `Qt.darker()` to produce high-contrast, near-pitch-black text, inverting the visual hierarchy.
- **Muted Text & Captions**: Always bind to `Color.muted` (or pass `muted: root.muted`).
- **Child Component Declarations**: Any component rendering secondary labels, placeholders, or disabled buttons MUST declare `property color muted: Color.muted` and inherit it from the root overlay.

### Rule 3: Dynamic Selection State Contract
When styling selected or highlighted items in item lists, tab bars, or action palettes:
- **Selection Background**: MUST bind to `Color.menu.selectedBackground` (or `Color.controls.selectedFill`).
- **Selection Text**: MUST bind to `Color.menu.selectedText` (or theme `accent`).
- **White-Text Prohibition**: NEVER hardcode `itemDelegate.isSelected ? "#ffffff" : foreground`. In light themes where selection background is an 8% light gray wash, `#ffffff` text becomes completely invisible.

### Rule 4: Component Palette Inheritance & Transparency Fallbacks
When decomposing UI into separate QML component files:
- All child components that render text, borders, or fills MUST expose standard color properties:
  ```qml
  property color foreground: Color.menu.text
  property color accent: Color.menu.selectedText
  property color muted: Color.muted
  property color borderColor: Color.menu.border
  property color background: Color.popups.background
  ```
- Use `Qt.rgba(foreground.r, foreground.g, foreground.b, <alpha>)` for subtle hover washes and divider fills, preserving visual proportion across light and dark backgrounds alike.

### Rule 5: Testing & Automated CI Guardrails
- **Dual-Mode Testing**: Component tests under `tests/` MUST verify rendering against both a dark preset (`#1a1b26` bg / `#a9b1d6` fg) and a light preset (`#eff1f5` bg / `#4c4f69` fg) using `tests/stubs/qs/Commons/Color.qml`.
- **Static Linting**: `scripts/test-all.sh` executes automated scans on `components/*.qml` and `OmarchyBitwarden.qml` to reject unapproved raw hex codes and prevent color regressions.

