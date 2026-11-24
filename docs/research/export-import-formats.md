# Research: Bitwarden Encrypted Export and Import File Formats

- **Ticket**: [#419](https://github.com/icyleaf/omarchy-bitwarden/issues/419) (Parent Map: [#417](https://github.com/icyleaf/omarchy-bitwarden/issues/417), Unblocks: [#426](https://github.com/icyleaf/omarchy-bitwarden/issues/426))
- **Primary Sources**:
  - `bitwarden/clients` @ [`0e54e98a`](https://github.com/bitwarden/clients/tree/0e54e98aa3396b833405c11cd96cd0d1807187e6)
  - `bitwarden/sdk-internal` @ [`727954ac`](https://github.com/bitwarden/sdk-internal/tree/727954aca1399556f2f1c5b1a4f0fa31c28bf70a)
  - `bitwarden/server` @ [`9c109b6b`](https://github.com/bitwarden/server/tree/9c109b6b4addad5eb821e263e5cdc25657dc6563)
  - `dani-garcia/vaultwarden` @ [`b12874bd`](https://github.com/dani-garcia/vaultwarden/tree/b12874bd83b7fc4c96611bfb8f6976313904a598)
  - Local codebase: `omawarden/src/crypto.rs`, `omawarden/src/api.rs`, `omawarden/src/vault.rs`

---

## Executive Summary

Bitwarden defines **four** vault export/import file formats:

| Format | `encrypted` | `passwordProtected` | Portable Across Accounts? | Preserves All Cipher Types? | Attachments |
| --- | --- | --- | --- | --- | --- |
| **Account-Restricted Encrypted JSON** | `true` | *(absent)* | No (bound to account `userKey` / `orgKey`) | Yes (all types) | No |
| **Password-Protected Encrypted JSON** | `true` | `true` | Yes (self-contained KDF + salt) | Yes (all types) | No |
| **Plaintext JSON** | `false` | *(absent)* | Yes | Yes (all types) | No (`.zip` only) |
| **Bitwarden CSV** | *(N/A)* | *(N/A)* | Yes | **No** (Login & Secure Note only) | No |

### Critical Findings for `omawarden` Implementation

1. **HKDF-Expand-Only Key Stretching (`omawarden/src/crypto.rs` incompatibility)**: Official Bitwarden clients stretch the 32-byte KDF output for password-protected exports using **RFC 5869 Section 2.3 HKDF-Expand only** (`Hkdf::<Sha256>::from_prk(kdf_key)`), NOT HKDF-Extract+Expand (`Hkdf::<Sha256>::new(Some(&[]), kdf_key)`). Currently `omawarden/src/crypto.rs::SymmetricCryptoKey::from_master_key()` uses `Hkdf::new(Some(&[]), master_key)` (lines 126–140). Reusing `from_master_key()` for exports would produce keys **incompatible with official Bitwarden clients**.
2. **Base64 Salt Is UTF-8 Encoded, Not Base64-Decoded**: Password-protected exports generate 16 random bytes, Base64-encode them to a 24-character ASCII string, and pass that ASCII string's **raw UTF-8 bytes** (case-sensitive, never lowercased/trimmed, never Base64-decoded) directly to PBKDF2 or SHA-256+Argon2id.
3. **Mandatory KDF Bounds Before Derivation (DoS Protection)**: Untrusted password-protected import files carry attacker-controlled KDF parameters. Official clients strictly enforce bounds (`PBKDF2: 5,000–2,000,000`; `Argon2id: iterations 2–10, memory 16–1024 MiB, parallelism 1–16`) **before** prompting for the password or allocating memory. `omawarden/src/crypto.rs::derive_master_key()` currently clamps low iterations and has no upper bounds, so a dedicated export/import KDF helper is required.
4. **V2 Account-Restricted Exports (`enc_type = 7` COSE + Blob `data`)**: Newer Bitwarden clients can emit V2 account-restricted exports using `enc_type = 7` and sealed `data` blobs (`{"format_version":1,...}`). `omawarden` currently supports V1 (`enc_type` 0/2) only and must detect and reject V2 exports with a clear error.

---

## 1. Account-Restricted Encrypted JSON

Source: [`bitwarden-json-export-types.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts#L30-L42), [`individual-vault-export.service.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts#L237-L302), [`bitwarden-encrypted-json-importer.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/bitwarden-encrypted-json-importer.ts#L71-L200).

### 1.1 Schema

Individual vault export (`BitwardenEncryptedIndividualJsonExport`):

```json
{
  "encrypted": true,
  "encKeyValidation_DO_NOT_EDIT": "2.<iv_b64>|<ct_b64>|<mac_b64>",
  "folders": [
    {
      "id": "<uuid>",
      "name": "2.<iv_b64>|<ct_b64>|<mac_b64>"
    }
  ],
  "items": [
    {
      "id": "<uuid>",
      "organizationId": null,
      "folderId": "<uuid-or-null>",
      "type": 1,
      "reprompt": 0,
      "name": "2.<iv_b64>|<ct_b64>|<mac_b64>",
      "notes": "2.<iv_b64>|<ct_b64>|<mac_b64>",
      "key": "2.<iv_b64>|<ct_b64>|<mac_b64>",
      "favorite": false,
      "fields": [],
      "login": { "...": "EncString values" },
      "passwordHistory": [],
      "creationDate": "2024-01-30T11:23:54.416Z",
      "revisionDate": "2024-01-30T14:09:33.753Z",
      "collectionIds": null
    }
  ]
}
```

Organization vault export (`BitwardenEncryptedOrgJsonExport`) replaces `folders` with `collections` (`CollectionWithIdExport[]`), encrypts `encKeyValidation_DO_NOT_EDIT` with the organization's `OrgKey`, and populates `collectionIds` on each item.

### 1.2 Cryptographic Mechanics (V1)

- **Key validation (`encKeyValidation_DO_NOT_EDIT`)**: The exporter generates a random UUIDv4 (`Utils.newGuid()`) and encrypts it with the account's 64-byte symmetric `userKey` (or `orgKey` for org exports) using `AesCbc256_HmacSha256_B64` (`enc_type = 2`, format `2.<iv_b64>|<ct_b64>|<mac_b64>`).
- **Import verification**: `BitwardenEncryptedJsonImporter.parseEncrypted()` decrypts `encKeyValidation_DO_NOT_EDIT` with the active account's `userKey` (or target `orgKey`). Because `enc_type = 2` is authenticated (Encrypt-then-MAC HMAC-SHA256 over `iv || ct`), decryption fails immediately if the file belongs to another account or if the account's encryption key was rotated. The decrypted GUID content itself is discarded after authenticated decryption succeeds ([`bitwarden-encrypted-json-importer.vectors.spec.ts` L50-L52](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/bitwarden-encrypted-json-importer.vectors.spec.ts#L50-L52)).
- **Folders**: Each folder's `name` is the encrypted `EncString` wrapped with `userKey`.
- **Ciphers**: Each cipher is exported in its encrypted domain representation:
  - If the cipher uses a per-item key (`item.key`), `item.key` is an `EncString` wrapping the 64-byte cipher key under `userKey` (or `orgKey`), and all encrypted string fields of that item are encrypted under that per-item key.
  - If `item.key` is absent/null (legacy ciphers), all encrypted string fields are encrypted directly under `userKey` (or `orgKey`).
  - Unencrypted metadata fields (`id`, `organizationId`, `folderId`, `type`, `reprompt`, `favorite`, `creationDate`, `revisionDate`, `deletedDate`, `archivedDate`, `collectionIds`, `secureNote.type`, `fields[].type`, `fields[].linkedId`, `login.uris[].match`, `login.httpAuthenticationEnabled`, `fido2Credentials[].creationDate`, `passwordHistory[].lastUsedDate`) remain plaintext.
- **Exclusions on export**: Trashed items (`deletedDate != null`), partial/gated items (`isPartial == true`), organization items (when exporting a personal vault), and attachments are excluded ([`individual-vault-export.service.ts` L256-L295](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts#L256-L295)).
- **Import re-encryption**: On import, official clients decrypt every folder and cipher into plaintext `View` models, reset `id`/`organizationId`/`collectionIds`, re-encrypt everything fresh with the target account's key, and submit via `POST /ciphers/import`.

### 1.3 Emerging V2 Account-Restricted Format (COSE / Blob Ciphers)

Source: [`cipher.export.ts` L21-L22, L137-L142, L231-L257](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/models/export/cipher.export.ts#L21-L22), [`account-encrypted-v2.json.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/spec-data/bitwarden-json/account-encrypted-v2.json.ts#L35-L57).

Newer Bitwarden V2 accounts produce account-restricted exports where:
- `encKeyValidation_DO_NOT_EDIT`, folder `name`, and cipher `key` use `enc_type = 7` (COSE-encoded symmetric encryption).
- Cipher content is sealed inside a single `data` JSON string containing `{"format_version":1,"wrapped_cek":"2....","envelope":"..."}` and legacy per-field properties (`name`, `notes`, `login`, etc.) are omitted.
- **Impact on `omawarden`**: `omawarden/src/crypto.rs` supports `enc_type` 0 and 2 (symmetric) and 3–6 (RSA). Importing a V2 account-restricted export must detect `enc_type = 7` or blob `data` (`"format_version"`) and fail cleanly with an explicit unsupported-format message rather than a cryptic parse error.

---

## 2. Password-Protected Encrypted JSON

Source: [`base-vault-export.service.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/base-vault-export.service.ts#L21-L52), [`bitwarden-password-protected-importer.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/bitwarden-password-protected-importer.ts#L47-L120), [`password-protected-kdf-config.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/password-protected-kdf-config.ts#L1-L101), [`default-key-generation.service.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/services/default-key-generation.service.ts#L49-L103), [`bitwarden-crypto/src/keys/kdf.rs`](https://github.com/bitwarden/sdk-internal/blob/727954aca1399556f2f1c5b1a4f0fa31c28bf70a/crates/bitwarden-crypto/src/keys/kdf.rs#L34-L89).

### 2.1 Schema (`BitwardenPasswordProtectedFileFormat`)

```json
{
  "encrypted": true,
  "passwordProtected": true,
  "salt": "Oy0xcgVRzxQ+9NpB5GLehw==",
  "kdfType": 0,
  "kdfIterations": 600000,
  "encKeyValidation_DO_NOT_EDIT": "2.<iv_b64>|<ct_b64>|<mac_b64>",
  "data": "2.<iv_b64>|<ct_b64>|<mac_b64>"
}
```

When `kdfType` is `1` (Argon2id), two additional integer fields are required:

```json
{
  "encrypted": true,
  "passwordProtected": true,
  "salt": "<base64-of-16-random-bytes>",
  "kdfType": 1,
  "kdfIterations": 3,
  "kdfMemory": 64,
  "kdfParallelism": 4,
  "encKeyValidation_DO_NOT_EDIT": "2.<iv_b64>|<ct_b64>|<mac_b64>",
  "data": "2.<iv_b64>|<ct_b64>|<mac_b64>"
}
```

### 2.2 Exact Cryptographic Construction

1. **Salt generation (export)**:
   - Generate 16 random bytes from OS CSPRNG.
   - Base64-encode (standard alphabet with `=` padding) to a 24-character ASCII string and store in `salt` ([`base-vault-export.service.ts` L29](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/base-vault-export.service.ts#L29)).
2. **KDF key material derivation (32 bytes)**:
   - Input `password_bytes = password.as_bytes()` (UTF-8).
   - Input `salt_bytes = salt.as_bytes()` (UTF-8 bytes of the Base64 string — **NOT** Base64-decoded, **NOT** lowercased or trimmed; [`default-key-generation.service.ts` L54-L59](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/services/default-key-generation.service.ts#L54-L59)).
   - If `kdfType == 0` (`PBKDF2_SHA256`):
     ```text
     kdf_key = PBKDF2-HMAC-SHA256(password_bytes, salt_bytes, kdfIterations, dkLen=32)
     ```
   - If `kdfType == 1` (`Argon2id`, version `0x13`):
     ```text
     salt_sha = SHA-256(salt_bytes)   // 32-byte digest
     kdf_key  = Argon2id(password=password_bytes, salt=salt_sha,
                         m=kdfMemory * 1024 KiB, t=kdfIterations, p=kdfParallelism, outLen=32)
     ```
     ([`kdf.rs` L59-L79](https://github.com/bitwarden/sdk-internal/blob/727954aca1399556f2f1c5b1a4f0fa31c28bf70a/crates/bitwarden-crypto/src/keys/kdf.rs#L59-L79)).
3. **Key stretching (`stretchKey`) → 64-byte `SymmetricCryptoKey`**:
   - Uses **RFC 5869 Section 2.3 HKDF-Expand ONLY** (treating `kdf_key` directly as `PRK`, skipping HKDF-Extract) with HMAC-SHA256 ([`default-key-generation.service.ts` L68-L94](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/services/default-key-generation.service.ts#L68-L94), [`web-crypto-function.service.ts` L86-L119](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/services/web-crypto-function.service.ts#L86-L119), [`node-crypto-function.service.ts` L43-L76](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/node/node-crypto-function.service.ts#L43-L76)):
     ```text
     enc_key = HKDF-Expand-SHA256(PRK=kdf_key, info="enc", L=32)  // = HMAC-SHA256(kdf_key, "enc" || 0x01)
     mac_key = HKDF-Expand-SHA256(PRK=kdf_key, info="mac", L=32)  // = HMAC-SHA256(kdf_key, "mac" || 0x01)
     ```
   - In Rust (`hkdf` crate): `Hkdf::<Sha256>::from_prk(&kdf_key)`.
4. **Payload & validation encryption**:
   - `encKeyValidation_DO_NOT_EDIT`: `encrypt_string(uuid_v4, stretched_key)` → `2.<iv_b64>|<ct_b64>|<mac_b64>`.
   - `data`: `encrypt_string(plaintext_json_export_string, stretched_key)` → `2.<iv_b64>|<ct_b64>|<mac_b64>`.
   - Ciphertext format (`enc_type = 2`): 16-byte random IV, AES-256-CBC with PKCS#7 padding using `enc_key`, followed by `HMAC-SHA256(mac_key, iv || ciphertext)`.
5. **Import decryption**:
   - Validate required fields (`encrypted === true`, `passwordProtected === true`, non-empty `salt`, `encKeyValidation_DO_NOT_EDIT`, `data`) and KDF parameter bounds **before** prompting for password or running KDF.
   - Derive `stretched_key` from user-supplied password + `salt` + KDF params.
   - Authenticate and decrypt `encKeyValidation_DO_NOT_EDIT`; on MAC/decryption error, return "invalid file password" immediately.
   - Authenticate and decrypt `data` → yields a standard **Plaintext JSON** export document (`encrypted: false`), which is then parsed by the plaintext JSON importer.

### 2.3 KDF Parameter Bounds (Import DoS Defense & Export Defaults)

Source: [`password-protected-kdf-config.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/password-protected-kdf-config.ts#L13-L97), [`kdf-config.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/legacy-crypto/src/models/kdf-config.ts#L17-L78).

| KDF Type | Parameter | Import Min | Import Max | Export Default (if no account KDF) | Notes |
| --- | --- | --- | --- | --- | --- |
| `0` (PBKDF2-SHA256) | `kdfIterations` | `5,000` | `2,000,000` | Account KDF (or `600,000`) | Must be integer. Low floor preserves legacy exports. |
| `1` (Argon2id) | `kdfIterations` | `2` | `10` | Account KDF (or `6`) | Must be integer. |
| `1` (Argon2id) | `kdfMemory` | `16` MiB | `1,024` MiB | Account KDF (or `32`–`64` MiB) | Must be integer. Unbounded `kdfMemory` causes OOM DoS. |
| `1` (Argon2id) | `kdfParallelism` | `1` | `16` | Account KDF (or `4`) | Must be integer. |

On export, official clients inherit the active user's account `KdfConfig` (`kdfConfigService.getKdfConfig(userId)`).

### 2.4 Required Changes in `omawarden/src/crypto.rs`

Inspecting `omawarden/src/crypto.rs`:
- `SymmetricCryptoKey::from_master_key()` (lines 126–140) calls `Hkdf::<Sha256>::new(Some(&[]), master_key)` (Extract+Expand) instead of `Hkdf::<Sha256>::from_prk(master_key)` (Expand-only). **Do not call `from_master_key()` for export encryption/decryption.** Add a dedicated `SymmetricCryptoKey::stretch_prk(prk: &[u8]) -> Result<Self, CryptoError>` using `Hkdf::<Sha256>::from_prk(prk)`.
- `derive_master_key()` (lines 60–102) trims/lowercases its salt parameter, silently clamps `iterations < 100_000` to `600_000` and Argon2 `iterations < 3` to `3`, and enforces no upper bounds. Add a dedicated `derive_export_key(password: &str, salt: &str, kdf: ExportKdfParams)` that:
  1. Validates integer bounds against the table above before allocating.
  2. Preserves exact `salt.as_bytes()` without trimming or lowercasing.
  3. Runs PBKDF2-HMAC-SHA256 or SHA-256 + Argon2id v0x13.
  4. Stretches with `Hkdf::<Sha256>::from_prk`.
- `SymmetricCryptoKey::encrypt_string()` (lines 223–260) and `EncString::parse()` / `EncString::decrypt_string()` (lines 272–422) already implement Bitwarden `enc_type = 2` (AES-256-CBC + PKCS#7 + Encrypt-then-MAC HMAC-SHA256) and are directly compatible.

---

## 3. Plaintext JSON

Source: [`bitwarden-json-export-types.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts#L14-L24), [`individual-vault-export.service.ts` L333-L361](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts#L333-L361), [`cipher.export.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/models/export/cipher.export.ts), [`cipher-type.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/vault/enums/cipher-type.ts).

### 3.1 Top-Level Envelope

- **Individual Vault**: `{ "encrypted": false, "folders": FolderWithIdExport[], "items": CipherWithIdExport[] }`
- **Organization Vault**: `{ "encrypted": false, "collections": CollectionWithIdExport[], "items": CipherWithIdExport[] }`
- Pretty-printed with 2-space indentation (`JSON.stringify(jsonDoc, null, "  ")`).
- On plaintext export, `cipher.key` is explicitly deleted (`delete cipher.key`) and `cipher.collectionIds` is `null` for personal vaults.

### 3.2 Common Item & Folder Fields

- **`FolderWithIdExport`**: `{ "id": "<uuid>", "name": "<string>" }`
- **`CipherWithIdExport` common fields**:
  - `id`: string (UUID; reset to `null` on import)
  - `organizationId`: string | null (reset on import)
  - `folderId`: string | null (matched against `folders[].id` during import to build `folderRelationships`)
  - `type`: integer (`1`=Login, `2`=SecureNote, `3`=Card, `4`=Identity, `5`=SshKey; Bitwarden also recently added `6`=BankAccount, `7`=DriversLicense, `8`=Passport)
  - `reprompt`: integer (`0`=None, `1`=Password)
  - `name`: string
  - `notes`: string | null
  - `favorite`: boolean
  - `fields`: `FieldExport[]` — each `{ "name": string, "value": string | null, "type": 0|1|2|3, "linkedId": number | null }` (`0`=Text, `1`=Hidden, `2`=Boolean, `3`=Linked)
  - `passwordHistory`: `PasswordHistoryExport[]` — each `{ "password": string, "lastUsedDate": ISO8601 }`. **Truncated to first 5 entries on import** ([`bitwarden-json-importer.ts` L57-L59](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/bitwarden-json-importer.ts#L57-L59)).
  - `creationDate`, `revisionDate`, `deletedDate`, `archivedDate`: optional ISO 8601 strings
  - `collectionIds`: `string[] | null`

### 3.3 Type-Specific Sub-Objects (Types 1–5)

| `type` | Property | Schema |
| --- | --- | --- |
| `1` (Login) | `login` | `{ "uris": [{ "uri": string, "match": 0\|1\|2\|3\|4\|5\|null }], "username": string\|null, "password": string\|null, "totp": string\|null, "httpAuthenticationEnabled"?: boolean, "fido2Credentials"?: Fido2CredentialExport[] }` (`match`: `0`=Domain, `1`=Host, `2`=StartsWith, `3`=Exact, `4`=RegEx, `5`=Never, `null`=Default). Note: `fido2Credentials` has `credentialId`, `keyType`, `keyAlgorithm`, `keyCurve`, `keyValue`, `rpId`, `userHandle`, `userName`, `counter` (string), `rpName`, `userDisplayName`, `discoverable` (`"true"`/`"false"`), `creationDate` (ISO 8601). |
| `2` (SecureNote) | `secureNote` | `{ "type": 0 }` (`0` = Generic) |
| `3` (Card) | `card` | `{ "cardholderName", "brand", "number", "expMonth", "expYear", "code" }` (all `string \| null`) |
| `4` (Identity) | `identity` | `{ "title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state", "postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber" }` (all `string \| null`) |
| `5` (SshKey) | `sshKey` | `{ "privateKey": string, "publicKey": string, "keyFingerprint": string }` ([`ssh-key.export.ts` L40-L42](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/common/src/models/export/ssh-key.export.ts#L40-L42)). `SshKeyExport.toView()` throws if `privateKey` is empty. |

*(Bitwarden `clients` and Vaultwarden also define types `6` `bankAccount`, `7` `driversLicense`, and `8` `passport`; `omawarden` currently implements types 1–5.)*

---

## 4. Bitwarden CSV Format and Limitations

Source: [`bitwarden-csv-export-type.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/types/bitwarden-csv-export-type.ts), [`base-vault-export.service.ts` L54-L104](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/base-vault-export.service.ts#L54-L104), [`individual-vault-export.service.ts` L304-L331](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/tools/export-vault-core/src/services/individual-vault-export.service.ts#L304-L331), [`bitwarden-csv-importer.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts).

### 4.1 Column Schema

Headers are **case-sensitive** (RFC 4180 CSV via PapaParse):

- **Individual Vault**:
  ```csv
  folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp
  ```
  *(Older exports omit `archivedDate`; `BitwardenCsvImporter` treats it as optional.)*
- **Organization Vault**:
  ```csv
  collections,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp
  ```

### 4.2 Field Encoding Rules

- `type`: `"login"` (`CipherType.Login`) or `"note"` (`CipherType.SecureNote`). Any other/missing value defaults to Login on import.
- `favorite`: `1` for true, empty/null for false (on import, any non-empty value other than `"0"` is true).
- `reprompt`: `"0"` (None) or `"1"` (Password).
- `fields`: Newline-separated `Name: Value` lines (`(f.name || "") + ": " + (f.value ?? "")`). On import, split on newlines and parsed via `lastIndexOf(": ")` (so colons in names work, but `: ` in values mis-splits, and multi-line values are corrupted).
- `login_uri`: Comma-separated list of URIs serialized as a single CSV cell (parsed via `parseSingleRowCsv`).
- `collections` (org only): Comma-separated collection names.

### 4.3 Data Permanently Lost in CSV

1. **Entire cipher types dropped**: Cards (`type: 3`), Identities (`type: 4`), SSH Keys (`type: 5`), and newer types (`6`–`8`) are **silently skipped** on CSV export (`individual-vault-export.service.ts` L315).
2. **Custom field types & links**: Hidden (`1`), Boolean (`2`), and Linked (`3`) fields are all flattened to `FieldType.Text` (`0`), losing masking and `linkedId`.
3. **URI match rules**: Per-URI `match` strategy (`0`–`5`) is discarded; all imported URIs revert to `null` (default).
4. **Passkeys (`fido2Credentials`)**: Completely dropped.
5. **Password history (`passwordHistory`)**: Completely dropped.
6. **HTTP auth flag (`httpAuthenticationEnabled`)**: Dropped.
7. **Timestamps**: `creationDate` and `revisionDate` are dropped (only `archivedDate` is kept).
8. **Attachments**: Never included.
9. **Empty folders**: Folders containing no exported items are omitted.

---

## 5. Import API Protocol & Bitwarden vs. Vaultwarden Compatibility Quirks

Source: [`import-api.service.ts`](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/services/import-api.service.ts), [`import.service.ts` L593-L662](https://github.com/bitwarden/clients/blob/0e54e98aa3396b833405c11cd96cd0d1807187e6/libs/importer/src/services/import.service.ts#L593-L662), [`ImportCiphersController.cs`](https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Api/Tools/Controllers/ImportCiphersController.cs#L46-L89), Vaultwarden [`src/api/core/ciphers.rs` L131-L138, L900-L970](https://github.com/dani-garcia/vaultwarden/blob/b12874bd83b7fc4c96611bfb8f6976313904a598/src/api/core/ciphers.rs#L900-L970) & [`src/db/models/cipher.rs` L154-L207, L517-L528](https://github.com/dani-garcia/vaultwarden/blob/b12874bd83b7fc4c96611bfb8f6976313904a598/src/db/models/cipher.rs#L154-L207).

### 5.1 Bulk Import Endpoint (`POST /api/ciphers/import`)

Personal vault imports send a single atomic JSON payload containing **already client-encrypted** folders and ciphers:

```json
{
  "folders": [
    { "id": "<optional-existing-folder-uuid>", "name": "2.<enc>" }
  ],
  "ciphers": [
    { "type": 1, "name": "2.<enc>", "login": { "...": "2.<enc>" }, "...": "..." }
  ],
  "folderRelationships": [
    { "key": 0, "value": 0 }
  ]
}
```

- `folderRelationships[].key` is the 0-based index into `ciphers[]`; `folderRelationships[].value` is the 0-based index into `folders[]`.
- Organization imports use `POST /api/ciphers/import-organization?organizationId=<uuid>` with additional `collections` and `collectionRelationships` arrays.

### 5.2 Compatibility Quirks Matrix

| Area | Official Bitwarden Cloud / Clients | Vaultwarden (`main`) | Recommendation for `omawarden` |
| --- | --- | --- | --- |
| **SSH Key (Type 5) on `/sync`** | Returned to all modern clients. | Filters out `type == 5` unless `bitwarden-client-version >= 2024.12.0` (`ciphers.rs` L132-L138). | `omawarden` sends `2026.7.0` (`api.rs` L403), so Type 5 syncs cleanly. |
| **SSH Key field names & validation** | `SshKeyExport` uses `privateKey`, `publicKey`, `keyFingerprint` (`ssh-key.export.ts` L40-L42); `toView()` throws if `privateKey` is empty. Note: Bitwarden's `account-encrypted-v1.json.ts` SDK test vector uses `"fingerprint"` instead of `"keyFingerprint"`. | `legacy_type_data_json` sets `sshKey = null` if **any** of `privateKey`, `publicKey`, or `keyFingerprint` is missing/empty (`db/models/cipher.rs` L521-L528). | **Export**: Always emit `keyFingerprint`, `privateKey`, `publicKey` (all non-empty). **Import**: Accept `keyFingerprint` with fallback to `fingerprint`; validate all 3 are non-empty for Vaultwarden compatibility. |
| **Import batch limits** | Cloud rejects `> 7,000` ciphers, `> 7,000` folderRelationships, or `> 2,000` folders (`ImportCiphersController.cs` L49-L54). Self-hosted has no hard limit. | No hard item-count limit. | Warn or chunk/reject cleanly above 7,000 ciphers / 2,000 folders when targeting Cloud. |
| **Encrypted note length** | Server enforces max encrypted field lengths; rejects entire import on any invalid item. | Pre-validates `cipher.notes.len() <= _max_note_size()` (default 10,000 chars) and rejects the entire import atomically (`db/models/cipher.rs` L154-L166). | Surface server `validationErrors` with item index & name (matching `import.service.ts` L673-L714). |
| **Password history `null` entries** | Truncates `passwordHistory` to max 5 entries on import (`bitwarden-json-importer.ts` L57-L59). | Rejects entire import if any `passwordHistory[].password` is `null`/non-string (`db/models/cipher.rs` L179-L194). | Filter out entries with null/empty `password` and cap at 5 entries before encrypting. |
| **Duplicate / re-import behavior** | Always creates new ciphers; reuses a folder only if `folder.id` matches an existing user folder UUID. | Identical (`ciphers.rs` L930-L943). | Document clearly that import is additive (does not deduplicate existing ciphers). |
| **Personal import `organizationId`** | Ignored / cleared on `POST /ciphers/import`. | Ignored / cleared (`ciphers.rs` L958). | Always set `organizationId: null` for personal imports. |
| **Default filename convention** | `bitwarden[_encrypted][_org]_export_YYYYMMDDHHMMSS.<ext>` (`export-helper.ts` L1-L33). | N/A (client-side). | Follow the same convention when `--output` is a directory or omitted. |
| **CLI password passing** | Official `bw export --password <pw>` accepts passwords in argv (`cli-export.command.ts` L65, L130). | N/A. | **MUST NOT** replicate `--password <pw>` in `omawarden` — violates **Zero-Argv Rule 11** (`docs/agents/security.md`). Use stdin / `--password-file` / interactive TTY prompt (resolved in Decision #426). |
| **Attachments in exports** | Only in unencrypted `.zip` (`data.json` + `attachments/<cipherName>/<fileName>`); never in JSON/encrypted JSON/CSV, and `.zip` is not re-importable with attachments. | N/A. | Scope JSON/encrypted JSON/CSV without attachments; document explicitly. |
