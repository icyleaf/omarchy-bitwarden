# ADR 0002: Vault Item Attachments Lifecycle and Desktop Integration

## Status
Accepted

## Context
Bitwarden vault items can contain encrypted file attachments (documents, images, certificates, tokens). Users need to discover, preview, and download these attachments directly from the Omarchy Bitwarden plugin overlay without leaving their desktop workflow.

Key requirements:
1. Identify vault items containing attachments with a dedicated `📎` badge in the search list.
2. Display attachments in the item details inspector pane with file type icons, filenames, and formatted sizes.
3. Provide in-overlay preview in the right inspector pane for images and text/code files (with "Copy Content" action), along with quick external viewer fallback.
4. Provide localized "Loading..." feedback directly on the View button without triggering global overlay messages.
5. Provide keyboard and mouse actions to "View" or "Download" (save to configured download folder) in both the Inspector and Action Palette (`Ctrl+K`).
6. Allow user-configurable default download destination in settings (default: `~/Downloads`).
7. Emit desktop notifications on successful download with actionable open file/folder buttons (`notify-send -A`).
8. Prevent secret and credential leakage when invoking `bw get attachment`.

## Decision
1. **Attachment Discovery & Presentation**:
   - Parse `item.attachments` list containing `id`, `fileName`, and `sizeName` / `size`.
   - Render an "Attachments" section in the Inspector pane with file type icons, localized Loading buttons, and quick "View" / "Download" actions.
   - Mark list items containing attachments with an inline `📎` badge.
   - Expose "View Attachment: <name>" and "Download Attachment: <name>" actions in the Action Palette (`Ctrl+K`).

2. **In-Overlay Preview & Download Execution Flow**:
   - Add an `attachment` module in `bitwarden_helper` and a CLI subcommand `bitwarden-helper attachment download`.
   - **Preview Mode (`--preview`)**: Downloads the attachment into a temporary cache (`/tmp/omarchy-bitwarden/attachments/<item_id>/<filename>`), inspects MIME/file types, extracts UTF-8 text if applicable, and renders directly inside the right-hand overlay pane (images via smooth QML Image viewer, code/text via monospace ScrollView with one-click copy, and binary cards with external open options).
   - **Download Mode**: Downloads the attachment into the configured `download_dir` (default `~/Downloads`), handling filename conflicts safely.
   - Session authentication is passed securely using the active `BW_SESSION` retrieved from the system keyring.

3. **Desktop Notifications**:
   - Upon download completion, invoke `notify-send` with actions (`Open File`, `Open Folder`) allowing immediate access to the downloaded file.

4. **Configuration**:
   - Add `download_dir: str = "~/Downloads"` to `Config` with GUI persistence in the Settings view.

## Consequences
- **Positive**: Clean, fast, and native workflow for vault attachments with in-overlay visual preview and zero browser context switching.
- **Security**: Temporary files in `/tmp` are scoped per item and session. Credentials and session tokens remain protected.
