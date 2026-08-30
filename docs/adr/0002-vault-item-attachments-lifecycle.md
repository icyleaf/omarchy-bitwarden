# ADR 0002: Vault Item Attachments Lifecycle and Native Decryption Architecture

## Status
Accepted

## Context
Bitwarden vault items can contain encrypted file attachments (documents, images, certificates, tokens). Users need to discover, preview, and download these attachments directly from the Omarchy Bitwarden plugin overlay without leaving their desktop workflow and without relying on external Node.js `bw` CLI tools.

Key requirements:
1. Identify vault items containing attachments with a dedicated `📎` badge in the search list.
2. Display attachments in the item details inspector pane with file type icons, filenames, and formatted sizes.
3. Provide in-overlay preview in the right inspector pane for images and text/code files (with "Copy Content" action), along with quick external viewer fallback via `xdg-open`.
4. Provide localized "Loading..." feedback directly on the View button without triggering global overlay messages.
5. Provide keyboard and mouse actions to "View" or "Download" (save to configured download folder) in both the Inspector and Action Palette (`Ctrl+K`).
6. Allow user-configurable default download destination in settings (default: `~/Downloads`).
7. Emit desktop notifications on successful download with actionable open file/folder buttons (`notify-send -A`).
8. Implement 100% native Rust streaming download and local symmetric decryption of Bitwarden `EncArrayBuffer` binary payloads without credential leaks.

## Decision
1. **Attachment Discovery & Presentation**:
   - Parse `item.attachments` list containing `id`, `fileName`, `key`, and `sizeName` / `size`.
   - Render an "Attachments" section in the Inspector pane with file type icons, localized Loading buttons, and quick "View" / "Download" actions.
   - Mark list items containing attachments with an inline `📎` badge.
   - Expose "View Attachment: <name>" and "Download Attachment: <name>" actions in the Action Palette (`Ctrl+K`).

2. **Native Cryptographic Decryption & `EncArrayBuffer` Layout**:
   - Direct REST API client downloads binary blobs using active session tokens or signed direct URLs (S3/storage).
   - Resolve `attachment.key` (or `cipher.key` / `organization.key` / `user.key`) through resident daemon IPC (`get_attachment_key`).
   - Binary payloads adhere to Bitwarden's `EncArrayBuffer` specification:
     - **Format 2 (Standard Binary)**: `[1 byte EncType (0x02)][16 bytes IV][32 bytes HMAC-SHA256 MAC][AES-256-CBC Ciphertext]`.
     - HMAC is verified over `IV + Ciphertext`.
     - Plaintext payload is extracted via AES-256-CBC with PKCS#7 unpadding.
   - If the vault is locked or key resolution fails, the download halts with an explicit error response (`ok: false`), preventing raw ciphertext from being written to disk as a corrupted file.

3. **In-Overlay Preview & Download Execution Flow**:
   - **CLI Subcommand**: `omawarden attachment download --item-id <id> --attachment-id <aid> --filename <name> [--preview] [--output-dir <dir>]`.
   - **Preview Mode (`--preview`)**: Saves decrypted bytes to temporary cache (`/tmp/omarchy-bitwarden/attachments/<item_id>/<filename>`), inspects MIME/file types, extracts UTF-8 text if applicable, and renders directly inside the right-hand overlay pane (images via smooth QML Image viewer, code/text via monospace ScrollView with one-click copy, and binary cards with external open options).
   - **Download Mode**: Saves decrypted bytes into the configured `download_dir` (default `~/Downloads`), handling filename conflicts safely.

4. **Desktop Notifications**:
   - Upon download completion, invoke `notify-send` with actions (`Open File`, `Open Folder`) allowing immediate access to the downloaded file.

5. **Configuration**:
   - Add `download_dir: String = "~/Downloads"` to `Config` with GUI persistence in the Settings view.

## Consequences
- **Positive**:
  - Clean, fast, and native workflow for vault attachments with in-overlay visual preview and zero browser context switching.
  - 100% native Rust execution without external Node.js `bw` CLI dependencies.
  - Exact adherence to Bitwarden `EncArrayBuffer` format guarantees error-free image and document rendering.
- **Security**: Temporary files in `/tmp` are scoped per item and session with `0600` permissions. Raw ciphertext is never saved as unreadable files.
