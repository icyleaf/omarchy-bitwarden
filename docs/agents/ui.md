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

All surface, text, selection, and status color rules live in one place: [ADR 0026: Theme Color Tokens and Zero-Hardcoded Palettes](../adr/0026-theme-color-tokens-and-zero-hardcoded-palettes.md). Read that decision before touching colors.

- Semantic status colors exist only in `components/StatusPalette.qml`; labels on colored fills come from `StatusPalette.textOn` / `textOnTint` / `labelOnTint` instead of hand-picked white or black.
- `scripts/check-hardcoded-colors.py` enforces the zero-hardcode rule and fails CI on any hex literal or numeric-RGB `Qt.rgba` outside that file.
- `tests/tst_theme_color_adaptation.qml` covers both presets and asserts WCAG contrast for colored badges, chips, toasts and confirmation buttons.
