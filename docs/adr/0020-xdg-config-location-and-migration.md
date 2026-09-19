# ADR 0020: Relocate Configuration File to XDG Config Directory to Prevent Shell Reload Loops

## Status
Accepted

## Context
In ADR 0015, the encrypted vault storage `data.json` was relocated from `$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/data.json` to `$XDG_DATA_HOME/omawarden/data.json` to eliminate hot-reload loops triggered by the host Omarchy desktop shell (`services/PluginRegistry.qml`), which actively monitors `$XDG_CONFIG_HOME/omarchy/plugins/` with `inotifywait -m -r -q -e close_write,create,delete,move`.

However, `config.json` remained located inside the watched plugin directory:
`$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/config.json`

Whenever a user modified preferences in the GUI Settings modal (such as changing the server URL, auto-lock timeout, clipboard TTL, or max attachment size) and clicked Save, `omawarden config set` performed an atomic file write (`fs_util::atomic_write_str`) over `config.json`. Because this atomic write creates a temporary file and renames it inside the plugin directory, `inotifywait` immediately detected the modification, causing `omarchy-shell` to misinterpret the event as a plugin code update and trigger `shell.reloadPlugins()`. This tore down panels, widgets, and services, causing visual UI restarts and desktop panel flickering.

In addition, storing application configuration inside a third-party desktop plugin repository violates the Freedesktop XDG Base Directory Specification, which specifies `$XDG_CONFIG_HOME` for application-specific configuration files.

## Decision
1. **Relocate Default Configuration to `$XDG_CONFIG_HOME/omawarden/config.json`**:
   - `ConfigManager::default()` now resolves `config.json` to `$XDG_CONFIG_HOME/omawarden/config.json` (defaulting to `$HOME/.config/omawarden/config.json`).
   - This location resides completely outside the inotify-monitored Omarchy plugin hierarchy.

2. **Environment Variable Override (`OMAWARDEN_CONFIG_DIR`)**:
   - `ConfigManager` checks the `OMAWARDEN_CONFIG_DIR` environment variable before falling back to `XDG_CONFIG_HOME`, allowing integration tests, containerized environments, and custom setups to override the configuration path.

3. **Transparent Legacy Migration**:
   - Upon initialization, `ConfigManager` checks whether a legacy file exists at `$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/config.json`.
   - If the legacy file exists and the new target does not, `omawarden` atomically moves the file, ensures the parent directory has `0700` permissions, enforces `0600` permissions on the target, and removes the legacy file.
   - If the target already exists, stale legacy files in the plugin directory are purged to avoid residual inotify events.

## Consequences
- **Elimination of Reload Loops on Settings Save**: Saving settings in the UI never touches the watched `omarchy/plugins` directory and no longer triggers Omarchy Shell plugin reloads or panel flickering.
- **XDG Specification Compliance**: Clean separation between plugin source code (`$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/`) and application configuration (`$XDG_CONFIG_HOME/omawarden/config.json`).
- **Zero Disruption for Existing Users**: Automatic migration preserves existing user configurations (custom server URLs, remember email settings, timeout intervals, etc.) seamlessly.
