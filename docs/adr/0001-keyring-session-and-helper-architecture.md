# ADR 0001: Keyring-backed Session and Helper Architecture

## Status
Accepted

## Context
The Omarchy Bitwarden plugin needs to provide instantaneous, secure, and keyboard-driven credential search similar to the Raycast Bitwarden extension on Wayland / Hyprland. Calling the `bw` CLI directly on every keystroke in QML causes high latency and UI stuttering. Furthermore, sensitive `BW_SESSION` tokens must never be written to plaintext config files, and clipboard operations containing sensitive secrets must be cleared after a short window.

## Decision
1. **Helper Backend Architecture**:
   - Provide a dedicated Python/CLI helper backend (`bitwarden-helper`) that wraps Bitwarden CLI execution, handles FreeDesktop Secret Service D-Bus interactions, manages the local in-memory search index, and oversees `wl-copy` clipboard timeouts.
   - The QML UI communicates with the helper via standard structured JSON IPC over `Quickshell.Process`.

2. **Session Persistence via Secret Service Keyring**:
   - Store active `BW_SESSION` tokens in the Linux system keyring (`secret-tool` / Secret Service API).
   - Hook into Omarchy lock events (`system-lock`) and D-Bus screen saver/lock signals to flush Keyring session tokens and wipe memory indexes upon lock.

3. **SSH Key Detection Heuristics**:
   - Automatically detect SSH keys by inspecting PEM headers (`-----BEGIN ... PRIVATE KEY-----`) and dedicated custom fields (`private_key`, `public_key`), elevating them to top-level SSH Key search items with dedicated copy actions.

## Consequences
- **Positive**: Blazing fast search response times (0ms UI latency), robust security with zero plaintext disk leakage of session tokens, clean separation of UI and cryptographic operations.
- **Trade-off**: Requires `bw` CLI and a FreeDesktop Secret Service daemon (standard on Omarchy/Arch desktops via `gnome-keyring` or `keepassxc`).
