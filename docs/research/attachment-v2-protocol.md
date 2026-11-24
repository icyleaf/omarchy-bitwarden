# Bitwarden & Vaultwarden Attachment V2 Upload and Delete Protocol

> **Research Ticket**: [#418](https://github.com/icyleaf/omarchy-bitwarden/issues/418) (Map [#417](https://github.com/icyleaf/omarchy-bitwarden/issues/417), blocking [#425](https://github.com/icyleaf/omarchy-bitwarden/issues/425))  
> **Primary Sources Inspected**:
> - `bitwarden/server` @ [`9c109b6b`](https://github.com/bitwarden/server/tree/9c109b6b4addad5eb821e263e5cdc25657dc6563)
> - `bitwarden/clients` @ [`0e54e98a`](https://github.com/bitwarden/clients/tree/0e54e98aa3396b833405c11cd96cd0d1807187e6)
> - `bitwarden/sdk-internal` @ [`727954ac`](https://github.com/bitwarden/sdk-internal/tree/727954aca1399556f2f1c5b1a4f0fa31c28bf70a)
> - `dani-garcia/vaultwarden` @ [`b12874bd`](https://github.com/dani-garcia/vaultwarden/tree/b12874bd83b7fc4c96611bfb8f6976313904a598)
> - Local `omawarden` codebase: `omawarden/src/attachment.rs`, `omawarden/src/api.rs`, `omawarden/src/crypto.rs`, `omawarden/src/config.rs`, `omawarden/src/vault.rs`, `docs/adr/0002-vault-item-attachments-lifecycle.md`

---

## 1. Executive Summary

Bitwarden's Attachment V2 protocol is a **two-phase delayed-upload flow** with **no client-initiated confirmation step** and **client-side rollback on upload failure**:

1. **Create attachment slot (JSON)**: `POST /api/ciphers/{cipherId}/attachment/v2` registers the encrypted attachment key, encrypted filename, and **encrypted byte size**, returning `{ attachmentId, url, fileUploadType, cipherResponse }`.
2. **Upload encrypted binary blob**:
   - **`FileUploadType::Direct` (`0`)** — Bitwarden Self-Hosted and Vaultwarden: `POST /api/ciphers/{cipherId}/attachment/{attachmentId}` as `multipart/form-data` (field `"data"`) with `Authorization: Bearer <token>`. Server validates size synchronously (`±1 MiB` leeway).
   - **`FileUploadType::Azure` (`1`)** — Bitwarden Cloud: Direct `PUT` to the returned Azure Blob Storage SAS URL (single `BlockBlob` PUT for `≤ 256 MiB`, or Azure Block + BlockList PUT for `> 256 MiB`) with **no `Authorization` header**. Bitwarden Cloud validates asynchronously via Azure Event Grid. **There is no S3 `FileUploadType`** in Bitwarden Server or Vaultwarden.
3. **Rollback on upload failure**: If Step 2 fails, the client must call `DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}` to remove the unvalidated metadata slot.
4. **Delete attachment**: `DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}` (or `/admin` for org admins) deletes both the metadata and blob and returns the updated cipher envelope.

---

## 2. Endpoints & Request/Response Envelopes

### 2.1 Step 1 — Create Attachment Metadata Slot

- **Endpoint**: `POST {api_url}/ciphers/{id}/attachment/v2`
- **Auth**: `Authorization: Bearer <access_token>`
- **Content-Type**: `application/json`
- **Sources**:
  - `bitwarden/server`: [`CiphersController.cs#L1579-L1614`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1579-L1614), [`AttachmentRequestModel.cs`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Models/Request/AttachmentRequestModel.cs), [`AttachmentUploadDataResponseModel.cs`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Models/Response/AttachmentUploadDataResponseModel.cs)
  - `dani-garcia/vaultwarden`: [`src/api/core/ciphers.rs#L1618-L1720`](https://github.com/dani-garcia/vaultwarden/blob/b12874bd83b7fc4c96611bfb8f6976313904a598/src/api/core/ciphers.rs#L1618-L1720)
  - `bitwarden/sdk-internal`: [`crates/bitwarden-vault/src/cipher/attachment_client/create.rs`](https://github.com/bitwarden/sdk-internal/blob/727954aca1399556f2f1c5b1a4f0fa31c28bf70a/crates/bitwarden-vault/src/cipher/attachment_client/create.rs)

#### Request Body (`AttachmentRequestModel`)

```json
{
  "key": "2.<iv_b64>|<ct_b64>|<mac_b64>",
  "fileName": "2.<iv_b64>|<ct_b64>|<mac_b64>",
  "fileSize": 1048625,
  "adminRequest": false,
  "lastKnownRevisionDate": "2026-11-24T04:00:00.000Z"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `key` | `string` (`EncString`) | Yes | Per-attachment 64-byte symmetric key encrypted with the cipher's key (or org/user key). |
| `fileName` | `string` (`EncString`) | Yes | UTF-8 file basename encrypted with the cipher's key (or org/user key). |
| `fileSize` | `int64` (Vaultwarden also accepts numeric string) | Yes | **Encrypted** blob size in bytes (`encData.buffer.byteLength`), not plaintext file size. Must be `>= 1` on Bitwarden Server (`>= 0` on Vaultwarden). |
| `adminRequest` | `bool` (default `false`) | No | `true` when editing an organization cipher via admin permissions. |
| `lastKnownRevisionDate` | `string?` (ISO-8601 UTC) | Optional | Checked by Bitwarden Server for optimistic concurrency; ignored by Vaultwarden. |

#### Response Body (`AttachmentUploadDataResponseModel`, HTTP `200 OK`)

```json
{
  "object": "attachment-fileUpload",
  "attachmentId": "a1b2c3d4e5f6...",
  "url": "https://<account>.blob.core.windows.net/attachments-v2/<cipherId>/<attachmentId>?sv=...",
  "fileUploadType": 1,
  "cipherResponse": { "...": "full CipherResponseModel (when adminRequest=false)" },
  "cipherMiniResponse": null
}
```

- `fileUploadType` (`FileUploadType` enum in [`bitwarden/server/src/Core/Enums/FileUploadType.cs`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Core/Enums/FileUploadType.cs) and [`bitwarden/clients/libs/common/src/platform/enums/file-upload-type.enum.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/platform/enums/file-upload-type.enum.ts)):
  - `0` = `Direct` (Bitwarden Self-Hosted `LocalAttachmentStorageService`, Vaultwarden)
  - `1` = `Azure` (Bitwarden Cloud `AzureAttachmentStorageService`)
  - **Note**: Neither Bitwarden Server nor Vaultwarden defines an S3 `FileUploadType`. Any unknown value must fail closed.
- When `adminRequest == true`, `cipherResponse` is `null` and `cipherMiniResponse` is populated instead.

---

### 2.2 Step 2a — Direct Upload (`fileUploadType == 0`)

- **Endpoint**: `POST {api_url}/ciphers/{id}/attachment/{attachmentId}`
- **Auth**: `Authorization: Bearer <access_token>` (same-origin verified via RFC 6454)
- **Content-Type**: `multipart/form-data; boundary=...`
- **Form Part**:
  - Field name: `data`
  - Filename: encrypted `fileName` (`EncString`, e.g. `2.<iv>|<ct>|<mac>`)
  - Part Content-Type: `application/octet-stream`
  - Body: raw encrypted binary `EncArrayBuffer` bytes
- **Response**: HTTP `200 OK` with empty body (`Task` in `bitwarden/server`, `EmptyResult` in Vaultwarden).
- **URL Quirk**:
  - `bitwarden/server` `LocalAttachmentStorageService::GetAttachmentUploadUrlAsync` returns `"{cipherId}/attachment/{attachmentId}"` (missing `/ciphers/` prefix).
  - Vaultwarden `post_attachment_v2` returns `"/ciphers/{cipherId}/attachment/{attachmentId}"`.
  - Official `bitwarden/clients` **ignores `uploadData.url` for `Direct`** and always posts to `${apiUrl}/ciphers/${cipherId}/attachment/${attachmentId}` ([`bitwarden-file-upload.service.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/platform/services/file-upload/bitwarden-file-upload.service.ts), [`api.service.ts#L408-L433`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/services/api.service.ts#L408-L433)). `omawarden` should do the same to avoid path mismatch bugs across Bitwarden Self-Hosted and Vaultwarden.
- **Sources**:
  - `bitwarden/server`: [`CiphersController.cs#L1645-L1676`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1645-L1676), [`LocalAttachmentStorageService.cs#L171-L172`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Core/Vault/Services/Implementations/LocalAttachmentStorageService.cs#L171-L172)
  - `dani-garcia/vaultwarden`: [`src/api/core/ciphers.rs#L1722-L1895`](https://github.com/dani-garcia/vaultwarden/blob/b12874bd83b7fc4c96611bfb8f6976313904a598/src/api/core/ciphers.rs#L1722-L1895)

---

### 2.3 Step 2b — Azure Blob Storage Upload (`fileUploadType == 1`)

- **Target URL**: Full SAS URL returned in `url` from Step 1 (container `attachments-v2`, blob `{cipherId}/{attachmentId}`, SAS permissions `Create | Write`, lifetime **1 minute**).
- **Auth**: SAS query parameters only — **NEVER send `Authorization: Bearer` header** to Azure Blob Storage.
- **Sources**:
  - `bitwarden/clients`: [`azure-file-upload.service.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/platform/services/file-upload/azure-file-upload.service.ts)
  - `bitwarden/server`: [`AzureAttachmentStorageService.cs#L68-L75`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Core/Vault/Services/Implementations/AzureAttachmentStorageService.cs#L68-L75)

#### Case A: Encrypted blob size `<= 256 MiB` (`268,435,456` bytes) — Single BlockBlob PUT

```http
PUT <sas_url> HTTP/1.1
x-ms-date: <RFC 1123 UTC timestamp, e.g. Tue, 24 Nov 2026 04:00:00 GMT>
x-ms-version: <value of `sv` query parameter from sas_url>
x-ms-blob-type: BlockBlob
Content-Length: <encrypted_byte_len>

<raw EncArrayBuffer bytes>
```

- **Expected Response**: HTTP `201 Created`.

#### Case B: Encrypted blob size `> 256 MiB` (up to `501 MiB`) — Put Block + Put Block List

1. Check SAS expiry (`se` query param; renew if `< now + 1s`).
2. **Put Block**: `PUT <sas_url>&comp=block&blockid=<blockId>`
   - `blockId`: Base64 of 48-char zero-padded block index (`"0000...0000"` for block 0; Bitwarden sends a single block because Azure's max single block size in modern API versions exceeds 501 MiB).
   - Headers: `x-ms-date`, `x-ms-version` (`sv`), `Content-Length`.
   - Body: raw `EncArrayBuffer` bytes.
   - Expected: HTTP `201 Created`.
3. Check SAS expiry again (renew if needed).
4. **Put Block List**: `PUT <sas_url>&comp=blocklist`
   - Headers: `x-ms-date`, `x-ms-version` (`sv`), `Content-Length`.
   - Body: `<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>{blockId}</Latest></BlockList>`
   - Expected: HTTP `201 Created`.

#### SAS URL Renewal Endpoint (Bitwarden Server only)

- **Endpoint**: `GET {api_url}/ciphers/{id}/attachment/{attachmentId}/renew`
- **Auth**: `Authorization: Bearer <access_token>`
- **Response** (`200 OK`): `{ "object": "attachment-fileUpload", "url": "<new_sas_url>", "fileUploadType": 1 }`
- **Condition**: Only valid while the attachment record has `Validated == false` (returns `404 Not Found` once validated). Not implemented on Vaultwarden.
- **Source**: [`bitwarden/server/src/Api/Vault/Controllers/CiphersController.cs#L1616-L1643`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1616-L1643)

---

### 2.4 Confirmation & Rollback Semantics

- **No client confirmation call**:
  - For `Direct`, `bitwarden/server` (`UploadFileForExistingAttachmentAsync`) and Vaultwarden (`save_attachment`) validate the uploaded file size synchronously against the `fileSize` declared in Step 1 (`±1 MiB` leeway = `1,048,576` bytes), update the stored size if within leeway, mark `Validated = true` (Bitwarden), and delete the attachment record + return an error if out of bounds.
  - For `Azure`, Bitwarden Cloud receives an asynchronous Azure Event Grid `BlobCreated` webhook at `POST /api/ciphers/attachment/validate/azure` ([`CiphersController.cs#L1884-L1915`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Controllers/CiphersController.cs#L1884-L1915)), which sets blob metadata/headers, validates size (`±1 MiB`), and marks `Validated = true` (or deletes the attachment on mismatch).
- **Client-side rollback**: In [`file-upload.service.ts#L31-L55`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/platform/services/file-upload/file-upload.service.ts#L31-L55) and [`cipher-file-upload.service.ts#L47-L53`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/vault/services/file-upload/cipher-file-upload.service.ts#L47-L53), if Step 2 throws for any reason (network failure, non-201/200 status, timeout), the client immediately calls `DELETE /api/ciphers/{id}/attachment/{attachmentId}` (or `/admin`) before propagating the error.

---

### 2.5 Attachment Deletion

- **Endpoints**:
  - User scope: `DELETE {api_url}/ciphers/{id}/attachment/{attachmentId}`
  - Org admin scope: `DELETE {api_url}/ciphers/{id}/attachment/{attachmentId}/admin`
  - *(Legacy deprecated aliases: `POST .../delete` and `POST .../delete-admin` — do not use for new clients.)*
- **Auth**: `Authorization: Bearer <access_token>`
- **Response (`200 OK`)**:
  - **Bitwarden Server** ([`DeleteAttachmentResponseModel.cs`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Vault/Models/Response/DeleteAttachmentResponseModel.cs)):
    ```json
    {
      "object": "deleteAttachment",
      "cipher": { "...": "CipherMiniResponseModel" }
    }
    ```
  - **Vaultwarden** ([`src/api/core/ciphers.rs#L2609-L2610`](https://github.com/dani-garcia/vaultwarden/blob/b12874bd83b7fc4c96611bfb8f6976313904a598/src/api/core/ciphers.rs#L2609-L2610)):
    ```json
    {
      "cipher": { "...": "full cipher JSON for scope" }
    }
    ```
- Both servers remove the attachment metadata from the cipher, delete the underlying file/blob, bump `revisionDate`, log `CipherAttachmentDeleted` for org ciphers, and emit a `SyncCipherUpdate` push notification.

---

## 3. Cryptographic Format & Key Hierarchy

Sources: [`bitwarden/clients/libs/common/src/vault/services/cipher.service.ts#L1023-L1060`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/vault/services/cipher.service.ts#L1023-L1060), [`bitwarden/clients/libs/legacy-crypto/src/models/enc-array-buffer.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/models/enc-array-buffer.ts), [`bitwarden/sdk-internal/crates/bitwarden-crypto/src/stream/streaming_attachment_cipher.rs`](https://github.com/bitwarden/sdk-internal/blob/727954aca1399556f2f1c5b1a4f0fa31c28bf70a/crates/bitwarden-crypto/src/stream/streaming_attachment_cipher.rs).

### 3.1 Wrapping Key Selection (`targetKey`)

```text
vaultKey  = if cipher.organizationId != null { orgKey[cipher.organizationId] } else { userKey }
targetKey = if cipher.key != null { decrypt(cipher.key, vaultKey) } else { vaultKey }
```

- `targetKey` is a 64-byte `SymmetricCryptoKey` (`32-byte enc_key || 32-byte mac_key`).
- Individual per-cipher keys (`cipher.key`) are respected automatically: when present, both `fileName` and the per-attachment `key` are encrypted with `cipher.key`, not directly with `userKey`/`orgKey`.

### 3.2 Per-Attachment Symmetric Key Generation & Wrapping

1. Generate **64 cryptographically random bytes** (`OsRng`):
   - `att_enc_key = raw[0..32]` (AES-256 key)
   - `att_mac_key = raw[32..64]` (HMAC-SHA256 key)
2. Encrypt the raw 64-byte slice with `targetKey` as a standard **`EncString` type 2 (`AesCbc256_HmacSha256_B64`)**:
   ```text
   key = "2." + base64(iv_16) + "|" + base64(aes256_cbc_pkcs7(targetKey.enc_key, iv_16, raw_64)) + "|" + base64(hmac_sha256(targetKey.mac_key, iv_16 || ct))
   ```

### 3.3 Filename Encryption

- Extract the safe UTF-8 basename (no directory path components) and encrypt with `targetKey` as **`EncString` type 2**:
  ```text
  fileName = "2." + base64(iv_16) + "|" + base64(ct) + "|" + base64(mac)
  ```

### 3.4 File Payload Binary Format (`EncArrayBuffer`)

Unlike JSON string fields (`EncString`), attachment file payloads are **raw binary** (no Base64 encoding, no `.` or `|` delimiters):

```text
+-------------------+------------------+------------------------+----------------------------------+
| EncType (1 byte)  | IV (16 bytes)    | HMAC-SHA256 (32 bytes) | AES-256-CBC Ciphertext (16*N B)  |
| 0x02              | random OsRng     | HMAC(att_mac, IV||CT)  | PKCS#7 padded with att_enc_key   |
+-------------------+------------------+------------------------+----------------------------------+
```

- **EncType byte**: `0x02` (`EncryptionType::AesCbc256_HmacSha256_B64 = 2`).
- **Encrypt-then-MAC**: `HMAC-SHA256` is computed over `IV || Ciphertext` (the leading `0x02` discriminator byte is **not** included in the HMAC input — matching both `bitwarden/clients` and `omawarden/src/crypto.rs::decrypt_attachment_blob`).
- **Exact encrypted length**:
  $$\text{encrypted\_len} = 1 + 16 + 32 + \text{plaintext\_len} + \left(16 - (\text{plaintext\_len} \bmod 16)\right) = 49 + \text{padded\_len}$$
  *(Note: PKCS#7 always adds 1..=16 padding bytes, so even a 0-byte file produces `49 + 16 = 65` encrypted bytes, satisfying Bitwarden Server's `fileSize >= 1` check.)*
- **Important**: Pass `encrypted_len` (not `plaintext_len`) as `fileSize` in `POST /api/ciphers/{id}/attachment/v2`.

---

## 4. Bitwarden (Cloud & Self-Hosted) vs. Vaultwarden Differences

| Dimension | Bitwarden Cloud | Bitwarden Self-Hosted | Vaultwarden |
|---|---|---|---|
| **`FileUploadType`** | `1` (`Azure`) | `0` (`Direct`) | `0` (`Direct`) |
| **Max single file size (encrypted)** | `501 MiB` (`525,336,576` B; UI `"500 MB"`) | `501 MiB` (`Constants.FileSize501mb`) | `525 MB` (`550,502,400` B; Rocket `file`/`data-form` limit `525 MiB`) |
| **Size validation leeway** | `±1 MiB` (`1,048,576` B), async via Azure Event Grid | `±1 MiB`, sync in `POST .../attachment/{aid}` | `±1 MiB`, sync in `POST .../attachment/{aid}` |
| **Premium / quota enforcement** | Personal requires Premium; org requires `MaxStorageGb`; checks `StorageBytesRemaining` | Same logic (`SelfHostedMaxStorageGb = 10240` for org-granted premium) | Optional `USER_ATTACHMENT_LIMIT` / `ORG_ATTACHMENT_LIMIT` (KiB); unlimited if unset, disabled if `0` |
| **Step 1 `url` format** | Full `https://*.blob.core.windows.net/...` SAS URL (1 min TTL) | `"{cipherId}/attachment/{attachmentId}"` (no `/ciphers/` prefix) | `"/ciphers/{cipherId}/attachment/{attachmentId}"` |
| **`GET .../renew`** | Supported while `Validated == false` | Supported while `Validated == false` | **Not implemented** (not needed for `Direct`) |
| **`lastKnownRevisionDate`** | Validated (rejects stale cipher edits) | Validated | Ignored |
| **Empty file (`0` B plaintext)** | Allowed (encrypted size = `65` B `>= 1`) | Allowed (encrypted size = `65` B `>= 1`) | Allowed |
| **Delete response body** | `{ "object": "deleteAttachment", "cipher": CipherMiniResponseModel }` | Same as Cloud | `{ "cipher": <full cipher JSON> }` (no `"object"` field) |
| **Common error responses** | `400` (`"Max file size is 500 MB."`, `"Not enough storage available."`, `"You must have premium status to use attachments."`, `"File received does not match expected file length."`), `404` (`NotFoundException`) | Same as Cloud | `400` (`"Max file size is 525 MB."`, `"Attachments are disabled"`, `"Attachment storage limit reached! ..."`, `"Attachment storage limit exceeded with this file"`, `"Attachment size mismatch ..."`, `"Cipher is not write accessible"`) |

---

## 5. Integration with Existing `omawarden` Architecture

### 5.1 `max_attachment_size_mb` Configuration (`omawarden/src/config.rs`, `omawarden/src/attachment.rs`)

- `Config.max_attachment_size_mb` defaults to `DEFAULT_MAX_ATTACHMENT_SIZE_MB = 500` (500 MiB) and is currently enforced as a download response byte cap in `omawarden/src/attachment.rs:222-226`.
- **Upload interaction**:
  - Pre-check the source file's metadata length (`fs::metadata(path)?.len()`) **before** reading the file into RAM or encrypting it.
  - Because `EncArrayBuffer` adds `50..=65` bytes of header + PKCS#7 padding, a `500 MiB` plaintext file encrypts to `524,288,065` bytes, which fits cleanly within both Bitwarden's `501 MiB` (`525,336,576` B) and Vaultwarden's `525 MB` (`550,502,400` B) server limits.
  - Reject files whose encrypted size exceeds `min(cfg.max_attachment_size_mb * 1024 * 1024 + 65, 501 * 1024 * 1024)` (or enforce `cfg.max_attachment_size_mb` strictly as the plaintext cap, and warn/reject if `> 500 MiB` on Bitwarden Cloud).
  - For Azure uploads exceeding `256 MiB`, the client **must** implement the Azure Put Block + Put Block List flow (Section 2.3 Case B); otherwise uploads between `256 MiB` and `500 MiB` will fail on Bitwarden Cloud.

### 5.2 Cryptographic Primitives (`omawarden/src/crypto.rs`)

- **Already present**:
  - `SymmetricCryptoKey::encrypt(&self, plaintext: &[u8]) -> Result<String, CryptoError>` (type 2 `EncString`, Encrypt-then-MAC) — directly usable for encrypting both the raw 64-byte attachment key and the UTF-8 `fileName`.
  - `decrypt_attachment_blob(&[u8], &SymmetricCryptoKey)` — already validates and decrypts `[0x02][IV:16][MAC:32][CT]`.
- **Needed additions**:
  - `SymmetricCryptoKey::generate() -> Self`: fill two `LockedKey32` buffers (`enc_key`, `mac_key`) from `rand_core::OsRng` (satisfies Security Rule 7 `mlock` + `Zeroize`).
  - `encrypt_attachment_blob(plaintext: &[u8], key: &SymmetricCryptoKey) -> Result<Vec<u8>, CryptoError>`: emit `[0x02][IV:16][HMAC-SHA256(mac_key, IV || CT):32][AES-256-CBC-PKCS7(enc_key, IV, plaintext)]` (satisfies Security Rule 8 mandatory Encrypt-then-MAC).

### 5.3 Daemon Key Resolution, Security Guardrails & Cache Coherence (`omawarden/src/vault.rs`, `omawarden/src/daemon/handlers.rs`, `omawarden/src/attachment.rs`)

- **Key resolution**: `VaultManager::resolve_attachment_key` (`omawarden/src/vault.rs:1298-1395`) already implements the exact `user_key -> org_key -> cipher.key -> attachment.key` chain for reads. Upload needs the parent `targetKey` (`cipher.key` unwrapped, or `org_key`/`user_key`) — ideally kept **inside the daemon** (performing attachment key generation, `fileName` encryption, and blob encryption or returning only the per-cipher upload context over the `SO_PEERCRED`-authenticated socket, matching `cipher_create`/`cipher_update`).
- **Origin & Bearer Token Safety (Security Rule 4)**:
  - `attachment.rs` already has `is_same_origin(u1, u2)` (RFC 6454).
  - For `Direct`, always POST to `{env_urls.api_url}/ciphers/{id}/attachment/{attachmentId}` with `Authorization: Bearer <token>`.
  - For `Azure`, validate `url` is `https://` (no remote plaintext HTTP) and **never** attach `Authorization` header.
- **401/403 token refresh**: Reuse `attempt_attachment_token_refresh` (or `ApiClient` auth retry) for Step 1 (`POST /attachment/v2`), Step 2a (`Direct`), `GET .../renew`, and `DELETE`.
- **Local state & preview cache**:
  - After upload or delete succeeds, update the local cipher cache (`storage.ciphers` + daemon in-memory index) from the returned `cipherResponse` / `cipher` (or trigger a cipher refresh/sync, noting Bitwarden's `DELETE` returns `CipherMiniResponseModel` which omits some full-cipher fields, so merge carefully or re-fetch/sync).
  - On attachment deletion, purge any cached local preview under `preview_root()/<slot>/<item_id>/<attachment_id>` (via `omawarden/src/attachment.rs::clean_previews` / `remove_preview_dir`) so deleted attachments do not linger in `$XDG_RUNTIME_DIR`.
