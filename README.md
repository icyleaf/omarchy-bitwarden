# omarchy-bitwarden

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Omarchy](https://img.shields.io/badge/Omarchy-Plugin-8b5cf6.svg)](https://github.com/omarchy)

Native, high-performance Bitwarden and Vaultwarden credential manager overlay for the **Omarchy Shell** on Linux / Wayland.

Inspired by macOS Spotlight and Raycast, `omarchy-bitwarden` provides instantaneous keyboard-driven vault access, secure Keyring session persistence, live TOTP generation, heuristic SSH key detection, and ephemeral clipboard protection.

![Preview](preview.png)

---

## ✨ Features

- **⚡ Instant Overlay & Zero Latency**: In-memory caching and non-blocking background sync allow opening and searching your entire vault in milliseconds.
- **🔐 Secure Keyring Session Lifecycle**: Decrypted session tokens (`BW_SESSION`) are stored securely in FreeDesktop Secret Service (`secret-tool` / D-Bus). Auto-locks upon screen lock hooks or idle timeouts without storing cleartext master passwords.
- **🔍 Multi-Tier High-Precision Fuzzy Search**: Sub-millisecond ranking algorithm prioritizing exact matches, prefixes, substrings, and acronym subsequences across item names, usernames, notes, and custom fields.
- **🪄 Action Palette (<kbd>Ctrl</kbd>+<kbd>K</kbd>)**: Fast keyboard palette to copy usernames, passwords, TOTP codes, card CVVs, SSH keys, PINs, or launch website URLs.
- **⏱️ Live Real-time TOTP Token Engine**: Automatic TOTP countdown timer and live 6-digit one-time password generation.
- **🌐 Website Favicons & Card Brands**: Asynchronously fetches crisp website favicons for login entries and automatically recognizes payment card brands (Visa, Mastercard, Amex, JCB, UnionPay, Discover).
- **🗝️ Heuristic SSH Key Management**: Automatically detects SSH private/public key pairs and passphrases in notes or custom fields, exposing them under a dedicated SSH category filter.
- **📋 Ephemeral Wayland Clipboard**: Auto-purges sensitive passwords and tokens from the clipboard after 30 seconds using `wl-copy`.
- **☁️ Self-Hosted Vaultwarden Support**: Seamlessly switch between official Bitwarden and custom self-hosted Vaultwarden server instances.

---

## ⌨️ Keyboard Shortcuts

| Shortcut                       | Description                                                               |
| :----------------------------- | :------------------------------------------------------------------------ |
| <kbd>Enter</kbd>               | Copy primary credential (Password / Card Number / Public Key)             |
| <kbd>Ctrl</kbd> + <kbd>K</kbd> | Open Action Palette (Copy username, TOTP, PIN, etc.)                      |
| <kbd>Ctrl</kbd> + <kbd>,</kbd> | Open / Toggle Settings configuration view                                 |
| <kbd>Ctrl</kbd> + <kbd>L</kbd> | Manually lock the vault immediately                                       |
| <kbd>Ctrl</kbd> + <kbd>R</kbd> | Trigger manual vault sync with Bitwarden server                           |
| <kbd>↓</kbd> / <kbd>↑</kbd>    | Navigate item list or action options (stops at boundaries)                |
| <kbd>Tab</kbd>                 | Switch category filters (All, Logins, Cards, Identities, Notes, SSH Keys) |
| <kbd>Esc</kbd>                 | Dismiss Action Palette, Settings, or hide the overlay                     |

---

## 🛠️ Prerequisites

Ensure the following tools are available on your system:

- **Bitwarden CLI**: `bw` ([Bitwarden CLI Docs](https://bitwarden.com/help/cli/))
- **Keyring / Secret Service**: `secret-tool` (`libsecret` package on Arch/Debian/Fedora)
- **Wayland Clipboard**: `wl-clipboard` (`wl-copy` / `wl-paste`)
- **Python**: `>= 3.10`

---

## 🚀 Installation & Setup

1. **Clone or Link to Omarchy Plugins Directory**:

   ```bash
   git clone https://github.com/icyleaf/omarchy-bitwarden.git ~/.config/omarchy/plugins/icyleaf.bitwarden
   ```

2. **Reload Omarchy Shell Plugins**:

   ```bash
   omarchy-shell shell rescanPlugins
   ```

3. **Toggle Overlay**:

   ```bash
   omarchy-shell shell toggle icyleaf.bitwarden
   ```

4. **Bind a Global Hotkey** (in `~/.config/hypr/bindings.lua`):

   ```lua
   -- ~/.config/hypr/bindings.lua
   o.bind("SUPER + slash", "Bitwarden Vault", "omarchy-shell shell toggle icyleaf.bitwarden")
   ```

---

## 🏗️ Architecture

```
omarchy-bitwarden/
├── OmarchyBitwarden.qml         # Quickshell QML overlay UI & Action Palette
├── manifest.json                # Omarchy plugin manifest metadata
├── bin/
│   └── bitwarden-helper         # Fast Python CLI bridge for QML Process calls
├── bitwarden_helper/
│   ├── auth.py                  # Authentication, login & unlock logic
│   ├── keyring.py               # FreeDesktop Secret Service Keyring integration
│   ├── vault.py                 # Vault parsing, scoring & heuristic classification
│   ├── ssh.py                   # SSH key header pattern analysis
│   ├── totp.py                  # RFC 6238 TOTP computation
│   ├── clipboard.py             # Wayland ephemeral clipboard timer
│   ├── config.py                # User configuration persistence
│   ├── health.py                # CLI dependencies health checker
│   └── hook.py                  # Omarchy screen-lock auto-lock hook
└── tests/                       # Automated pytest test suites (59 test cases)
```

---

## 🧪 Running Tests

Run all unit and integration tests with `pytest`:

```bash
python3 -m pytest tests/
```

---

## 📄 License

This project is open-sourced under the [MIT License](LICENSE).
