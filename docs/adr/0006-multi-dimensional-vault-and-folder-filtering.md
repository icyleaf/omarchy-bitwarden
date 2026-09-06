# ADR 0006: Multi-Dimensional Vault and Folder Filtering Architecture

## Status
Accepted

## Context
As users accumulate credentials across personal vaults and multiple organization collections (workplaces, teams, shared families), filtering exclusively by item type (`All`, `Logins`, `Cards`, `Identities`, `Notes`, `SSH Keys`) becomes insufficient. Users require an ergonomic, zero-friction mechanism to isolate personal credentials from enterprise vaults and focus searches within specific folders without disrupting the keyboard-first Spotlight workflow.

## Decision
1. **Search Header Dropdown Integration**:
   - Transform the static magnifying glass icon on the left of the search bar into an interactive **Vault/Organization Scope Dropdown Capsule** (`[🔐 All Vaults ▾]`, `[👤 Personal ▾]`, `[🏢 <Org> ▾]`).
   - Add a dedicated **Folder Scope Dropdown Capsule** (`[📁 All Folders ▾]`, `[📁 <Folder> ▾]`) on the right side of the search bar before utility actions.
   - Visually elevate active filtered states with accent borders and subtle tinted backgrounds.

2. **Orthogonal Conjunctive Filtering Pipeline**:
   - Filter queries evaluate as a logical conjunction:
     $$\text{Match}(item) = \text{Query}(item) \land \text{Category}(item) \land \text{VaultScope}(item) \land \text{FolderScope}(item)$$
   - `VaultScope` supports:
     - `all`: All items.
     - `personal`: Only credentials where `organization_id == null`.
     - `<organization_id>` / `<organization_name>`: Credentials matching the selected organization.
   - `FolderScope` supports:
     - `all`: All items regardless of folder.
     - `<folder_id>` / `<folder_name>`: Credentials assigned to the specified folder.

3. **Dual-Track Clear & Keyboard Flow**:
   - Visual clear: Active scopes render an inline `×` button allowing one-click reset to `all`.
   - Keyboard reset: Pressing `Esc` in the search field when the query string is empty will first reset active `VaultScope` and `FolderScope` back to `all` before dismissing the overlay on subsequent `Esc`.
   - Action Palette integration (`Ctrl+K`): Inject commands to quickly filter by any available Vault or Folder directly via fuzzy typing.
   - Dedicated global hotkeys: `Alt+V` to open Vault Scope dropdown, `Alt+F` to open Folder Scope dropdown.

4. **In-Memory Dynamic Scope Aggregation**:
   - Aggregate unique Organizations and Folders dynamically from loaded, decrypted `rawVaultItems` in QML, ensuring zero additional IPC or backend overhead while automatically syncing with vault updates.

## Consequences
- **Positive**:
  - Sub-millisecond instant filtering across organizational and hierarchical dimensions.
  - Zero latency impact (pure client-side evaluation against in-memory decrypted items).
  - Clear, unambiguous visual feedback in the primary search bar.
  - Full keyboard accessibility without requiring mouse interaction.
- **Trade-off**:
  - Folders that contain zero items are not listed when dynamically aggregating from populated items (which keeps menus clutter-free).
