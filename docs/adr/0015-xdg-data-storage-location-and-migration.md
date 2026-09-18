# ADR 0015: Relocate Local Vault Storage to XDG Data Directory to Eliminate Hot-Reload Loops

## Status
Accepted

## Context
In previous releases, `omawarden` placed its encrypted vault database `data.json` inside the plugin's source directory:
`$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/data.json`

The host Omarchy desktop shell (`services/PluginRegistry.qml`) actively monitors `$XDG_CONFIG_HOME/omarchy/plugins/` with `inotifywait -m -r -q -e close_write,create,delete,move` to trigger automatic hot-reloading (`reloadPlugins()`) when plugin code changes.

Because `omawarden` executes atomic file writes (`fs_util::atomic_write_str` which generates a temporary file and renames it over `data.json`) on every vault synchronization, this write activity was misinterpreted by Omarchy as a plugin code modification. Consequently, the shell triggered immediate plugin teardown and rebuild loops (up to hundreds of times in minutes), causing the floating overlay to prematurely collapse and crashing unrelated desktop plugins (see issue #161).

Furthermore, placing dynamic multi-megabyte ciphertext caches inside `$XDG_CONFIG_HOME/omarchy/plugins/` violates the Freedesktop XDG Base Directory specification, which prescribes `$XDG_DATA_HOME` for persistent application data and caches.

## Decision
1. **Relocate Default Storage to `$XDG_DATA_HOME`**:
   - `StorageManager::default()` now resolves `data.json` to `$XDG_DATA_HOME/omawarden/data.json` (falling back to `$HOME/.local/share/omawarden/data.json` if `$XDG_DATA_HOME` is unset).
   - This location resides entirely outside the inotify-monitored Omarchy plugin directory hierarchy.

2. **Environment Variable Override (`OMAWARDEN_DATA_DIR`)**:
   - `StorageManager` inspects `OMAWARDEN_DATA_DIR` before falling back to `XDG_DATA_HOME`, allowing containerized environments, testing harnesses, or custom setups to redirect the database directory.
   - CLI subcommands (including `omawarden daemon` and `omawarden config set`) derive sibling `data.json` paths if `--config <path>` specifies a custom parent directory.

3. **Transparent Legacy Migration**:
   - Upon initialization, `StorageManager` checks whether a legacy file exists at `$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/data.json`.
   - If the legacy file exists and the new destination does not, `omawarden` atomically moves the file, ensures the parent directory has `0700` permissions, enforces `0600` file permissions on the target, and removes the legacy file.
   - If the new destination already exists, stale legacy files in the plugin directory are purged to avoid residual inotify events.

## Consequences
- **Elimination of Reload Loops**: Background vault synchronization and local cache writes never trigger Omarchy plugin reloads.
- **XDG Compliance**: Clean separation between plugin source code (`$XDG_CONFIG_HOME/omarchy/plugins/icyleaf.bitwarden/`) and encrypted user data (`$XDG_DATA_HOME/omawarden/data.json`).
- **Zero Disruption for Existing Users**: Automatic migration preserves existing credentials, encrypted ciphers, and active unlock states without requiring re-authentication.
