# Organization & Collection Write Protocol and Permission Semantics

**Ticket:** [#420](https://github.com/icyleaf/omarchy-bitwarden/issues/420) (Parent: Map [#417](https://github.com/icyleaf/omarchy-bitwarden/issues/417), Blocks: Decision [#427](https://github.com/icyleaf/omarchy-bitwarden/issues/427))
**Primary Sources Audited:**
- `bitwarden/server` @ `9c109b6b4addad5eb821e263e5cdc25657dc6563`
- `bitwarden/clients` @ `0e54e98aa3396b833405c11cd96cd0d1807187e6`
- `bitwarden/sdk-internal` @ `727954aca1399556f2f1c5b1a4f0fa31c28bf70a`
- `dani-garcia/vaultwarden` @ `b12874bd83b7fc4c96611bfb8f6976313904a598`
- Local repository: `omawarden/src/api.rs`, `omawarden/src/cipher_write.rs`, `omawarden/src/vault.rs`, `omawarden/src/storage.rs`, `docs/adr/0033-overlay-cipher-mutation-and-zero-argv-edit-contract.md`

---

## 1. API Endpoints and Wire Payloads

All endpoints below are relative to `urls.api_url` (`https://api.bitwarden.com` / `https://api.bitwarden.eu` or `<self-hosted>/api`) and require `Authorization: Bearer <access_token>`. Standard vault clients (`omawarden`, Bitwarden Desktop/CLI) use the **User-scope** routes; Admin Console routes (`/admin`, `/collections-admin`) are documented only to clarify the boundary.

### 1.1 Create a Cipher Directly in an Organization

| Attribute | Specification |
| :--- | :--- |
| **Endpoint** | `POST /ciphers/create` (User scope) |
| **Admin-only variant** | `POST /ciphers/admin` (requires `CanEditAllCiphersAsync` / `can_edit_any_collection`) |
| **Request Wrapper** | `CipherCreateRequestModel` (Bitwarden) / `ShareCipherData` (Vaultwarden) |
| **Response** | `CipherResponseModel` (Bitwarden) / `cipherDetails` JSON (Vaultwarden) |

**Payload schema:**
```json
{
  "cipher": {
    "type": 1,
    "organizationId": "<org-uuid>",
    "folderId": "<optional-user-folder-uuid-or-null>",
    "favorite": false,
    "reprompt": 0,
    "key": "<2.iv|ct|mac wrapped under org_key>",
    "name": "<2.iv|ct|mac encrypted under cipher_key>",
    "notes": null,
    "login": { "...": "..." },
    "fields": [],
    "encryptedFor": "<acting-user-uuid>"
  },
  "collectionIds": ["<collection-uuid-1>"]
}
```

**Validation invariants:**
- `collectionIds` **must be non-empty** whenever `cipher.organizationId` is set (`CipherCreateRequestModel.Validate` returns `"You must select at least one collection."`; Vaultwarden validates every collection belongs to `organizationId` and is writable by the acting user).
- Note: `POST /ciphers` (without `/create`) does **not** accept `collectionIds` and is used for personal ciphers only (`bitwarden/sdk-internal` switches to `POST /ciphers/create` whenever `!collection_ids.is_empty()`).
- **Primary sources:**
  - `bitwarden/server`: `src/Api/Vault/Controllers/CiphersController.cs` (`PostCreate` L359-384), `src/Api/Vault/Models/Request/CipherRequestModel.cs` (`CipherCreateRequestModel` L535-549).
  - `dani-garcia/vaultwarden`: `src/api/core/ciphers.rs` (`post_ciphers_create` L473-523, `share_cipher_by_uuid` L1448-1551).
  - `bitwarden/sdk-internal`: `crates/bitwarden-vault/src/cipher/cipher_client/create.rs` (L139-157).

### 1.2 Edit an Existing Organization Cipher

| Attribute | Specification |
| :--- | :--- |
| **Endpoint** | `PUT /ciphers/{id}` (User scope; `POST /ciphers/{id}` is obsolete alias) |
| **Partial (folder/favorite only)** | `PUT /ciphers/{id}/partial` (User scope; requires **read access only**, works on read-only org ciphers) |
| **Admin-only variant** | `PUT /ciphers/{id}/admin` |
| **Request Body** | `CipherRequestModel` (flat cipher object, **not** wrapped in `{ cipher, collectionIds }`) |
| **Response** | `CipherResponseModel` (Bitwarden) / `cipherDetails` JSON (Vaultwarden) |

**Validation invariants:**
- `organizationId` in the request **must match** the server's stored `cipher.organizationId`. Both Bitwarden (`CiphersController.cs` L425-431) and Vaultwarden (`ciphers.rs` L1049-1051) reject mismatches with HTTP `400` (`"Organization mismatch..."`). Moving a personal cipher into an organization via `PUT /ciphers/{id}` is forbidden; use `/share`.
- Optimistic concurrency: include `lastKnownRevisionDate` set to the cached `revisionDate` (HTTP `400`/`409` on stale revision).
- **`PUT /ciphers/{id}/partial` payload:**
  ```json
  { "folderId": "<folder-uuid-or-null>", "favorite": true }
  ```
  Both Bitwarden (`CiphersController.cs` L905-920) and Vaultwarden (`ciphers.rs` L1070-1099) allow `folderId` and `favorite` updates on **read-only** organization ciphers through `/partial`, because folder placement and favorite state are per-user metadata rather than shared org cipher content. Using `PUT /ciphers/{id}` for a favorite toggle on a read-only org cipher fails with a write-permission error.
- **Primary sources:**
  - `bitwarden/server`: `src/Api/Vault/Controllers/CiphersController.cs` (`Put` L408-436, `PutPartial` L905-920).
  - `dani-garcia/vaultwarden`: `src/api/core/ciphers.rs` (`put_cipher_impl` L1022-1057, `put_cipher_partial` L1070-1099).

### 1.3 Share / Move a Personal Cipher to an Organization

| Attribute | Specification |
| :--- | :--- |
| **Endpoint (Single)** | `PUT /ciphers/{id}/share` (`POST /ciphers/{id}/share` is an obsolete alias in Bitwarden server) |
| **Endpoint (Bulk)** | `PUT /ciphers/share` (`{ "ciphers": [CipherWithIdRequestModel...], "collectionIds": [...] }`) |
| **Request Body (Single)** | `CipherShareRequestModel` (`{ "cipher": CipherRequestModel, "collectionIds": ["<uuid>", ...] }`) |
| **Response (Single)** | `CipherResponseModel` (Bitwarden) / `cipherDetails` JSON (Vaultwarden) |
| **Response (Bulk)** | `ListResponseModel<CipherMiniResponseModel>` (`{ "object": "list", "data": [...] }`); ciphers the user can no longer access after sharing may be omitted |

**Validation invariants:**
- The existing cipher **must be personal** (`cipher.UserId == acting_user.Id` and `cipher.OrganizationId == null`). Re-sharing an already-org-owned cipher is rejected (`"One or more ciphers already belong to an organization."`).
- `cipher.organizationId` **must be non-empty** and `collectionIds` **must be non-empty**.
- The acting user must be a confirmed member of `organizationId` and have write permission on every collection in `collectionIds`.
- **Irreversible ownership transfer:** On success, the server clears `userId` (moving ownership to `organizationId`), links `collectionIds`, and counts any attachments against the organization's storage quota (`CipherService.cs` L1172-1193; Vaultwarden `ciphers.rs` L1523-1528).
- **Primary sources:**
  - `bitwarden/server`: `src/Api/Vault/Controllers/CiphersController.cs` (`PutShare` L929-952, `PostShare` L954-959, `PutShareMany` L1491-1536), `src/Core/Vault/Services/Implementations/CipherService.cs` (`ShareAsync` L621-721, `ValidateCipherCanBeShared` L1151-1196), `src/Api/Vault/Models/Request/CipherRequestModel.cs` (`CipherShareRequestModel` L551-572).
  - `dani-garcia/vaultwarden`: `src/api/core/ciphers.rs` (`put_cipher_share` L1290-1316, `put_cipher_share_selected` L1364-1445, `share_cipher_by_uuid` L1448-1551).
  - `bitwarden/sdk-internal`: `crates/bitwarden-vault/src/cipher/cipher_client/share_cipher.rs` (L18-152).

### 1.4 Reassign Collections on an Organization Cipher

| Attribute | Specification |
| :--- | :--- |
| **Endpoints (User scope)** | `PUT /ciphers/{id}/collections` (legacy, returns `CipherDetailsResponseModel`)<br>`PUT /ciphers/{id}/collections_v2` (preferred, returns `OptionalCipherDetailsResponseModel`) |
| **Upstream terminology note** | `bitwarden/server` added `/shared-folders` and `/shared-folders_v2` aliases (marking `/collections` `[Obsolete]` for backwards compatibility), but **Vaultwarden only implements `/collections` and `/collections_v2`** (not `/shared-folders`). **Use `PUT /ciphers/{id}/collections_v2` (or `/collections`) for cross-server compatibility.** |
| **Request Body** | `CipherCollectionsRequestModel`: `{ "collectionIds": ["<collection-uuid-1>", ...] }` |
| **Response (`_v2`)** | `{ "object": "optionalCipherDetails", "unavailable": false, "cipher": { ... } }` — if removing collections revokes the user's own access to the cipher, Bitwarden returns `"unavailable": true, "cipher": null` |

**Validation invariants:**
- The cipher must belong to an organization (`organizationId != null`).
- `collectionIds` represents the **complete target set** (symmetric difference against current collections determines additions and removals).
- Both Bitwarden and Vaultwarden verify that the acting user can edit the cipher **and view its passwords** (`!read_only && !hide_passwords` or `manage`) before permitting collection changes, and that every added or removed collection belongs to the same organization and is writable by the user.
- **Primary sources:**
  - `bitwarden/server`: `src/Api/Vault/Controllers/CiphersController.cs` (`PutCollections` L983-990, `PutCollections_vNext` L1030-1037, `PutSharedFolders_vNext` L1001-1028), `src/Core/Vault/Services/Implementations/CipherService.cs` (`SaveCollectionsAsync` L753-803).
  - `dani-garcia/vaultwarden`: `src/api/core/ciphers.rs` (`put_collections2_update` L1108-1133, `put_collections_update` L1135-1155, `update_collections_by_scope` L1180-1268).

---

## 2. Cryptographic Key Rules

### 2.1 Organization Symmetric Key Unwrapping (Existing Pipeline)

`omawarden/src/api.rs` (L1627-1673) already unwraps each organization's 64-byte `SymmetricCryptoKey` (`Aes256Cbc_HmacSha256`) during sync decryption:
1. Decrypt `storage.enc_private_key` with `user_key` to obtain the user's PKCS#8 DER `RsaPrivateKey`.
2. For each `org` in `storage.organizations`, parse `org["key"]` as `EncString`:
   - `enc_type` `3..=6` (RSA-OAEP SHA-256 / SHA-1, with or without HMAC): decrypt with `rsa_priv_key`.
   - `enc_type` `0..=2` (symmetric): decrypt with `user_key`.
3. Parse the decrypted 64 bytes into `SymmetricCryptoKey` (`org_keys[org_id]`).

> **Current gap in `omawarden`:** `org_keys` are only computed transiently inside `decrypt_sync_ciphers_with_context` (`omawarden/src/api.rs:1643`) and are not exposed to `cipher_write.rs`. Furthermore, `api.rs:1737` currently falls back to `org_keys.get(oid).unwrap_or(user_key)` for *reading*; **write paths MUST NEVER fall back to `user_key` when `org_key` is missing**, because encrypting an org cipher with `user_key` corrupts it for all other organization members.

### 2.2 Per-Cipher Item Key (`cipher.key`) & Field Encryption

Modern Bitwarden clients (`bitwarden/sdk-internal`: `crates/bitwarden-vault/src/cipher/cipher.rs` L699-710, L936-949) enforce a two-level hierarchy:
- **Owning base key (`base_key`):** `user_key` for personal ciphers (`organizationId == null`), or `org_key` for organization ciphers (`organizationId != null`).
- **Per-cipher key (`cipher_key`):** a random 64-byte `SymmetricCryptoKey` wrapped as `EncString` (`type 2`) under `base_key` and stored in `cipher.key`. All sensitive cipher fields (`name`, `notes`, `login.*`, `card.*`, `identity.*`, `sshKey.*`, `fields[].name/value`, `passwordHistory[].password`, `attachments[].fileName`, `attachments2[].key`) are encrypted under `cipher_key`.

**Rules per operation:**

| Operation | Wrapping / Encryption Rule |
| :--- | :--- |
| **Create in Org (`POST /ciphers/create`)** | Generate a fresh 64-byte `cipher_key`, encrypt all sensitive fields with `cipher_key`, and wrap `cipher_key` under `org_key` into `payload["key"]`. (Legacy servers also accept `key: null` with fields encrypted directly under `org_key`, but emitting a per-cipher `key` matches `bitwarden/sdk-internal` L709 & L944.) |
| **Edit in Org (`PUT /ciphers/{id}`)** | Look up `org_key` for `cipher.organizationId` (**fail closed if missing**). If `cipher.key` is present, unwrap it using `org_key` (**do not** fall back to `user_key`); if `cipher.key` is `null` (legacy org cipher), use `org_key` directly. Encrypt modified fields with `cipher_key` and preserve `payload["key"]`. |
| **Share Personal → Org (`PUT /ciphers/{id}/share`)** | **Case 1 — Cipher already has `cipher.key`:** Either re-wrap `cipher.key` from `user_key` to `org_key` (`Cipher::rewrap_cipher_key`, `bw_sdk_cipher.rs` L381-401) — leaving all field ciphertexts and `attachments2` keys valid because `cipher_key` itself is unchanged — **or** decrypt the full cipher and re-encrypt all fields under `cipher_key` with `key` wrapped under `org_key` (what `share_cipher.rs` L118-140 does).<br>**Case 2 — Legacy personal cipher (`cipher.key == null`):** Fields were encrypted directly under `user_key`. You **MUST** decrypt *every* encrypted field (`name`, `notes`, type-specific fields, `fields`, `passwordHistory`, `login.uris`, `fido2Credentials`, etc.) under `user_key`, generate a new `cipher_key` (or use `org_key`), and re-encrypt every field under it with `key` wrapped under `org_key`. |
| **Share with Attachments (Fail-Closed Gate)** | Modern attachments carry `attachment.key` (wrapped under `cipher_key` or `user_key`). If `cipher.key` is preserved and re-wrapped, `attachments2[id].key` stays valid; if `cipher_key` changes, each `attachment.key` must be re-wrapped under the new `cipher_key` and submitted in `attachments2`. **Legacy attachments where `attachment.key == null`** were encrypted directly with `user_key` and **cannot** be shared without downloading, re-encrypting, and re-uploading the binary blob (`bitwarden/sdk-internal` `validate_attachment_keys` L992-997 explicitly returns `CipherError::AttachmentsWithoutKeys`). `omawarden` must **reject** sharing any cipher with `attachments` lacking a `key` (or any attachments at all if attachment re-wrapping is out of scope). |
| **Reassign Collections (`PUT /ciphers/{id}/collections_v2`)** | Metadata-only operation (`{ "collectionIds": [...] }`). No re-encryption is performed because the cipher remains in the same organization under the same `org_key`. |

### 2.3 `encryptedFor` and `encryptedByKeyId`

- **`encryptedFor` MUST ALWAYS be the acting `UserId` (UUID)** — even when creating, editing, or sharing an **Organization** cipher!
  - `bitwarden/server` (`CipherRequestModel.cs` L16-20): *"The Id of the user that encrypted the cipher. It should always represent a UserId."*
  - `bitwarden/server` (`CiphersController.cs` L1965-1978, `ValidateCipherEncryptedForUser`): rejects `model.EncryptedFor != userId` with HTTP `400` on `Post`, `PostCreate`, `Put`, `PutShare`, and `PutShareMany`.
  - `dani-garcia/vaultwarden` (`src/api/core/ciphers.rs` L372-377, `validate_encrypted_for_user`): identically rejects `data.encrypted_for != user_id`.
- **`encryptedByKeyId` (optional):** Introduced in `web-v2025.8.1` to identify the key that encrypted the cipher. Both Bitwarden (`CiphersController.cs` L1999-2002) and Vaultwarden (`ciphers.rs` L385-391) explicitly **skip** validating `encryptedByKeyId` when `isOrganizationCipher == true` (*"organizations carry no key id yet"*), and skip it when absent for backwards compatibility. `omawarden` should continue sending `encryptedFor: <user_id>` on all cipher create/update/share requests.

---

## 3. Permission Semantics: Bitwarden vs. Vaultwarden

### 3.1 Flags Returned in `/sync`

1. **On each Cipher (`sync.ciphers[]`, `CipherDetailsResponseModel`):**
   - `edit: bool` — whether the user can modify cipher content (`PUT /ciphers/{id}`).
   - `viewPassword: bool` — whether the user is permitted to view passwords / hidden fields / TOTP (inverse of `hidePasswords`).
   - `permissions: { "delete": bool, "restore": bool }` — added in `2025.6.0` (`CipherPermissionsResponseModel.cs` L11-28; Vaultwarden `src/db/models/cipher.rs` L437-440).
2. **On each Collection (`sync.collections[]`, `CollectionDetailsResponseModel`):**
   - `readOnly: bool` — `true` restricts the user to read-only access in this collection.
   - `hidePasswords: bool` — `true` hides passwords/hidden custom fields for items in this collection.
   - `manage: bool` — `true` grants collection management privileges (implies write + delete/restore even under `limitItemDeletion`).
3. **On each Organization (`sync.profile.organizations[]`):**
   - `type`: `0` (Owner), `1` (Admin), `2` (User), `3` (Manager), `4` (Custom).
   - `permissions` (Custom role): granular booleans including `editAnyCollection`, `deleteAnyCollection`, `createNewCollections`, `editAssignedCollections`, etc. (Note: `editAssignedCiphers` / `canEditUnassignedCiphers` / `canEditAllCiphers` govern **Admin Console** `/admin` routes, not standard User-scope vault routes; see `bitwarden/clients` `cipher-authorization.service.ts` L125-206).
   - `limitItemDeletion: bool` (Bitwarden org policy): when `true`, only users with `manage` (not merely `edit`) may delete/restore org ciphers.

### 3.2 Multi-Collection & User-vs-Group Aggregation Rules

When an organization cipher belongs to multiple collections (or a user has both direct user-collection and group-collection grants):
- **Precedence:** Direct user-collection permissions override group-collection permissions (`dani-garcia/vaultwarden` `src/db/models/cipher.rs` L753-779).
- **Combination across collections** (`vaultwarden` `src/db/models/cipher.rs` L791-800; mirrors Bitwarden SQL `MIN`/`MAX` aggregation):
  - `read_only = AND(collection.read_only)` → writable if **any** assigned collection allows write (`!read_only`).
  - `hide_passwords = AND(collection.hide_passwords)` → passwords visible if **any** assigned collection allows viewing passwords (`!hide_passwords`).
  - `manage = OR(collection.manage)` → manageable if **any** assigned collection grants `manage`.
- **Derived cipher flags:**
  - `edit = !read_only || manage` (Vaultwarden `is_write_accessible_to_user` L866-875; `to_json` emits `edit: !read_only`).
  - `viewPassword = !hide_passwords`.

### 3.3 Operation-by-Operation Permission Matrix

| Operation | Official Bitwarden (`bitwarden/server`) | Vaultwarden (`dani-garcia/vaultwarden`) | Notes / Edge Cases |
| :--- | :--- | :--- | :--- |
| **Create in Org** (`POST /ciphers/create`) | Confirmed org member + `CanEditItemsInCollections(orgId, collectionIds)` | Confirmed org member + every `col` in `collectionIds` belongs to `orgId` and `collection.is_writable_by_user` (`!read_only` or `manage`) | `collectionIds` must be non-empty. |
| **Edit Org Cipher** (`PUT /ciphers/{id}`) | `cipher.Edit == true` (`UserCanEditAsync`) | `is_write_accessible_to_user` (`!read_only \|\| manage`) | **Watch out for `viewPassword == false`:** a user can have `edit: true, viewPassword: false` ("Can edit, except passwords"). Clients must block/avoid overwriting hidden fields or reject edits if the client cannot preserve hidden values safely. |
| **Favorite / Folder on Org Cipher** (`PUT /ciphers/{id}/partial`) | Any read access to cipher (`GetByIdAsync(id, user.Id) != null`) | `is_accessible_to_user` (read access) | Works even when `edit == false` (`readOnly == true`). |
| **Soft/Hard Delete & Restore** (`PUT/DELETE /ciphers/{id}...`) | `NormalCipherPermissions.CanDelete`: if `org.LimitItemDeletion` then `cipher.Manage`, else `cipher.Manage \|\| cipher.Edit` → surfaced in `cipher.permissions.delete` / `restore` | `is_write_accessible_to_user` (`!read_only \|\| manage`) → surfaced in `cipher.permissions.delete` / `restore` | **Difference:** Vaultwarden does not implement `LimitItemDeletion` yet and sets `delete = restore = !read_only`. Relying on `cipher.permissions.delete` / `restore` automatically respects both servers. |
| **Share Personal → Org** (`PUT /ciphers/{id}/share`) | Personal cipher owned by user + confirmed org member + write access to all `collectionIds` + org attachment storage limit check | Same (`user_uuid == user`, `organization_uuid == None`, every `col` in `collectionIds` belongs to `orgId` and `is_writable_by_user`) | Fails if cipher has legacy attachments without `attachment.key`. |
| **Reassign Collections** (`PUT /ciphers/{id}/collections[_v2]`) | `UserCanEditAsync(cipher)` **AND** `cipher.ViewPassword == true` (`PutSharedFolders_vNext` L1007) + write access on all added/removed collections | `is_in_editable_collection_by_user` (`(!read_only && !hide_passwords) \|\| manage`) + `is_writable_by_user` on every collection in symmetric difference (`ciphers.rs` L1193, L1218-1226) | **Privilege-escalation guard:** forbidding collection reassignment when `viewPassword == false` prevents moving a password-hidden cipher into a collection where the user can view passwords. |

---

## 4. Fail-Closed Write Guard Design for `omawarden`

Today `omawarden` blocks all organization cipher mutations unconditionally (`"Organization ciphers are read-only."` in `omawarden/src/cipher_write.rs` L213-217, L398-422, L872-880, L1032-1040, and ADR-0033). To safely lift that guard in a future slice (Decision [#427](https://github.com/icyleaf/omarchy-bitwarden/issues/427)):

1. **Extend Local Cache & `VaultItem` Model (Fail-Closed Defaults):**
   - Persist `edit: bool`, `view_password: bool`, `can_delete: bool`, `can_restore: bool` on `VaultItem` (from raw cipher JSON `edit`, `viewPassword`, `permissions.delete`, `permissions.restore`).
   - **Fail-closed default for org ciphers:** if `organizationId.is_some()` and a permission field is absent in cached JSON (e.g., pre-upgrade cache or older server), default `edit`, `view_password`, `can_delete`, `can_restore` to **`false`** (for personal ciphers, default to `true`).
   - Parse `readOnly` (default `true`), `hidePasswords` (default `true`), and `manage` (default `false`) from `storage.collections[]` so collection pickers and write guards fail closed when metadata is missing.

2. **Strict Cryptographic Key Guards:**
   - Extract a dedicated `resolve_org_key(storage, user_key, org_id) -> Result<SymmetricCryptoKey, WriteError>` helper that **fails closed** if `enc_private_key` or `org_keys[org_id]` is missing or undecryptable — **never** fall back to `user_key`.
   - When updating an org cipher with `cipher.key`, unwrap `cipher.key` strictly with `org_key` (no `or_else(|_| decrypt(user_key))` fallback).
   - Always set `payload["encryptedFor"] = user_id` (acting user UUID) on `POST /ciphers/create`, `PUT /ciphers/{id}`, and `PUT /ciphers/{id}/share`.
   - On `share`, reject any cipher containing attachments with `key == null` (or reject ciphers with attachments outright until attachment key re-wrapping is implemented).

3. **Operation-Specific Pre-Flight Guards (Before Any HTTP Call):**
   - **Create in Org:** require non-empty `collection_ids`; verify every collection exists in `storage.collections`, matches `organization_id`, and has `!read_only || manage`.
   - **Edit Org Cipher:**
     - If **only** `folder_id` and/or `favorite` changed → route to `PUT /api/ciphers/{id}/partial` (allowed even when `edit == false`, matching ADR-0033 Inspector favorite UX!).
     - Otherwise → require `item.edit == true`. If `item.view_password == false`, reject edits to `password`, `totp`, and `Hidden (1)` custom fields (or fail closed and reject full edits until hidden-field preservation is verified).
   - **Delete / Restore Org Cipher:** require `item.can_delete == true` (for soft/hard delete) or `item.can_restore == true` (for restore), honoring Bitwarden's `LimitItemDeletion` policy automatically.
   - **Reassign Collections:** require `item.edit == true && item.view_password == true`; compute symmetric difference against `item.collection_ids` and verify every added or removed collection belongs to `item.organization_id` and has `!read_only || manage`; handle `collections_v2` `unavailable: true` by evicting the cipher from local cache.
   - **Cache Refresh on Org Writes:** `cache_created_cipher` (`omawarden/src/cipher_write.rs:331`) currently passes `&[]` for `organizations` and `None` for `enc_private_key` to `decrypt_sync_ciphers_with_context`. It **must** pass `&updated.organizations` and `updated.enc_private_key.as_deref()` so newly created/updated/shared org ciphers decrypt immediately in the local cache instead of falling back to `"Untitled"`.
