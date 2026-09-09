use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
pub use base64::engine::general_purpose::STANDARD as BASE64;
pub use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKdfParams,
    InvalidEncString(String),
    UnsupportedCipherType(u32),
    MacMismatch,
    DecryptionFailed(String),
    InvalidKeyLength,
    Utf8Error,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKdfParams => write!(f, "Invalid KDF parameters"),
            CryptoError::InvalidEncString(s) => write!(f, "Invalid EncString format: {}", s),
            CryptoError::UnsupportedCipherType(t) => write!(f, "Unsupported cipher type: {}", t),
            CryptoError::MacMismatch => write!(f, "MAC verification failed"),
            CryptoError::DecryptionFailed(s) => write!(f, "Decryption failed: {}", s),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::Utf8Error => write!(f, "UTF-8 decoding error"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2Sha256 = 0,
    Argon2id = 1,
}

impl From<u32> for KdfType {
    fn from(val: u32) -> Self {
        match val {
            1 => KdfType::Argon2id,
            _ => KdfType::Pbkdf2Sha256,
        }
    }
}

pub fn derive_master_key(
    email: &str,
    password: &str,
    kdf_type: KdfType,
    iterations: u32,
    memory_mb: Option<u32>,
    parallelism: Option<u32>,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let email_normalized = email.trim().to_lowercase();
    let mut master_key = Zeroizing::new([0u8; 32]);

    match kdf_type {
        KdfType::Pbkdf2Sha256 => {
            let iter = if iterations < 100_000 {
                600_000
            } else {
                iterations
            };
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                email_normalized.as_bytes(),
                iter,
                master_key.as_mut(),
            );
        }
        KdfType::Argon2id => {
            let memory = memory_mb.unwrap_or(64) * 1024; // KB
            let passes = if iterations < 3 { 3 } else { iterations };
            let lanes = parallelism.unwrap_or(4);

            let params = Params::new(memory, passes, lanes, Some(32))
                .map_err(|_| CryptoError::InvalidKdfParams)?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let email_hash = Sha256::digest(email_normalized.as_bytes());
            argon2
                .hash_password_into(password.as_bytes(), &email_hash, master_key.as_mut())
                .map_err(|_| CryptoError::InvalidKdfParams)?;
        }
    }

    Ok(master_key)
}

pub fn derive_master_password_hash(master_key: &[u8; 32], password: &str) -> String {
    let mut hash = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(master_key.as_ref(), password.as_bytes(), 1, hash.as_mut());
    BASE64.encode(hash.as_ref())
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SymmetricCryptoKey {
    pub enc_key: [u8; 32],
    pub mac_key: Option<[u8; 32]>,
}

impl SymmetricCryptoKey {
    pub fn from_master_key(master_key: &[u8; 32]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(&[]), master_key);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        hkdf.expand(b"enc", &mut enc_key)
            .expect("HKDF expand enc failed");
        hkdf.expand(b"mac", &mut mac_key)
            .expect("HKDF expand mac failed");

        Self {
            enc_key,
            mac_key: Some(mac_key),
        }
    }

    pub fn decrypt_with_master_key(
        enc: &EncString,
        master_key: &[u8; 32],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut candidate_keys = Vec::new();

        // 1. HKDF from_prk (RFC 5869 Section 2.3 directly on master key)
        if let Ok(hkdf) = Hkdf::<Sha256>::from_prk(master_key) {
            let mut enc_key = [0u8; 32];
            let mut mac_key = [0u8; 32];
            if hkdf.expand(b"enc", &mut enc_key).is_ok()
                && hkdf.expand(b"mac", &mut mac_key).is_ok()
            {
                candidate_keys.push(SymmetricCryptoKey {
                    enc_key,
                    mac_key: Some(mac_key),
                });
            }
        }

        // 2. HKDF with empty salt (Node.js/WebCrypto extract+expand)
        {
            let hkdf = Hkdf::<Sha256>::new(Some(&[]), master_key);
            let mut enc_key = [0u8; 32];
            let mut mac_key = [0u8; 32];
            if hkdf.expand(b"enc", &mut enc_key).is_ok()
                && hkdf.expand(b"mac", &mut mac_key).is_ok()
            {
                candidate_keys.push(SymmetricCryptoKey {
                    enc_key,
                    mac_key: Some(mac_key),
                });
            }
        }

        // 3. Direct master key as encryption key (only for legacy unauthenticated enc_type == 0)
        if enc.enc_type == 0 {
            candidate_keys.push(SymmetricCryptoKey {
                enc_key: *master_key,
                mac_key: None,
            });
        }

        let mut last_err =
            CryptoError::DecryptionFailed("No matching candidate key found".to_string());
        for key in &candidate_keys {
            match enc.decrypt(key) {
                Ok(bytes) => return Ok(bytes),
                Err(e) => last_err = e,
            }
        }

        Err(last_err)
    }

    pub fn from_raw_bytes(key_bytes: &[u8]) -> Result<Self, CryptoError> {
        if key_bytes.len() == 32 {
            let mut enc = [0u8; 32];
            enc.copy_from_slice(key_bytes);
            Ok(Self {
                enc_key: enc,
                mac_key: None,
            })
        } else if key_bytes.len() == 64 {
            let mut enc = [0u8; 32];
            let mut mac = [0u8; 32];
            enc.copy_from_slice(&key_bytes[..32]);
            mac.copy_from_slice(&key_bytes[32..64]);
            Ok(Self {
                enc_key: enc,
                mac_key: Some(mac),
            })
        } else {
            Err(CryptoError::InvalidKeyLength)
        }
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, CryptoError> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use rand_core::RngCore;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        let mut iv = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut iv);

        let enc = Aes256CbcEnc::new_from_slices(&self.enc_key, &iv)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid key/iv: {}", e)))?;
        let mut buf = vec![0u8; plaintext.len() + 32];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext.as_bytes(), &mut buf)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Encryption failed: {}", e)))?
            .len();
        let ct = &buf[..ct_len];

        let mac_k = self.mac_key.as_ref().ok_or(CryptoError::MacMismatch)?;
        let mut hmac = HmacSha256::new_from_slice(mac_k)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid mac key: {}", e)))?;
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        Ok(format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncString {
    pub enc_type: u32,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl EncString {
    pub fn parse(raw: &str) -> Result<Self, CryptoError> {
        let raw = raw.trim();
        let (type_str, rest) = raw
            .split_once('.')
            .ok_or_else(|| CryptoError::InvalidEncString(raw.to_string()))?;

        let enc_type = type_str
            .parse::<u32>()
            .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;

        let parts: Vec<&str> = rest.split('|').collect();
        if enc_type == 3 || enc_type == 4 || enc_type == 5 || enc_type == 6 || parts.len() == 1 {
            // RSA ciphertext format: <cipher_text_b64> or <cipher_text_b64>|<hmac>
            let ciphertext = BASE64
                .decode(parts[0])
                .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;
            return Ok(Self {
                enc_type,
                iv: Vec::new(),
                ciphertext,
                mac: None,
            });
        }

        let iv = BASE64
            .decode(parts[0])
            .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;
        let ciphertext = BASE64
            .decode(parts[1])
            .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?;

        let mac = if parts.len() >= 3 {
            Some(
                BASE64
                    .decode(parts[2])
                    .map_err(|_| CryptoError::InvalidEncString(raw.to_string()))?,
            )
        } else {
            None
        };

        Ok(Self {
            enc_type,
            iv,
            ciphertext,
            mac,
        })
    }

    pub fn decrypt_rsa(&self, rsa_key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, CryptoError> {
        match self.enc_type {
            4 | 6 => {
                // Bitwarden type 4 (Rsa2048_OaepSha1_B64) & 6 (Rsa2048_OaepSha1_HmacSha256_B64) use SHA-1
                let padding = rsa::Oaep::new::<sha1::Sha1>();
                rsa_key
                    .decrypt(padding, &self.ciphertext)
                    .or_else(|_| {
                        let padding256 = rsa::Oaep::new::<Sha256>();
                        rsa_key.decrypt(padding256, &self.ciphertext)
                    })
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            3 | 5 => {
                // Bitwarden type 3 (Rsa2048_OaepSha256_B64) & 5 (Rsa2048_OaepSha256_HmacSha256_B64) use SHA-256
                let padding256 = rsa::Oaep::new::<Sha256>();
                rsa_key
                    .decrypt(padding256, &self.ciphertext)
                    .or_else(|_| {
                        let padding = rsa::Oaep::new::<sha1::Sha1>();
                        rsa_key.decrypt(padding, &self.ciphertext)
                    })
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
            }
            _ => Err(CryptoError::UnsupportedCipherType(self.enc_type)),
        }
    }

    pub fn decrypt(&self, key: &SymmetricCryptoKey) -> Result<Vec<u8>, CryptoError> {
        match self.enc_type {
            0 => {
                if self.iv.len() != 16 {
                    return Err(CryptoError::DecryptionFailed(
                        "Invalid IV length".to_string(),
                    ));
                }

                // enc_type 0: AesCbc256_B64 (legacy unauthenticated CBC)
                if let (Some(expected_mac), Some(mac_key)) = (&self.mac, &key.mac_key) {
                    let mut hmac = HmacSha256::new_from_slice(mac_key).map_err(|e| {
                        CryptoError::DecryptionFailed(format!("Invalid MAC key: {}", e))
                    })?;
                    hmac.update(&self.iv);
                    hmac.update(&self.ciphertext);
                    let calculated_mac = hmac.finalize().into_bytes();
                    if expected_mac.ct_eq(&calculated_mac).unwrap_u8() != 1 {
                        return Err(CryptoError::MacMismatch);
                    }
                }

                let mut buf = self.ciphertext.clone();
                let dec = Aes256CbcDec::new_from_slices(&key.enc_key, &self.iv)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

                let decrypted_slice = dec
                    .decrypt_padded_mut::<Pkcs7>(&mut buf)
                    .map_err(|e| CryptoError::DecryptionFailed(format!("{:?}", e)))?;

                Ok(decrypted_slice.to_vec())
            }
            2 => {
                if self.iv.len() != 16 {
                    return Err(CryptoError::DecryptionFailed(
                        "Invalid IV length".to_string(),
                    ));
                }

                // enc_type 2: AesCbc256_HmacSha256_B64 (MAC is mandatory)
                let expected_mac = self.mac.as_deref().ok_or(CryptoError::MacMismatch)?;
                let mac_key = key.mac_key.as_ref().ok_or(CryptoError::MacMismatch)?;

                let mut hmac = HmacSha256::new_from_slice(mac_key).map_err(|e| {
                    CryptoError::DecryptionFailed(format!("Invalid MAC key: {}", e))
                })?;
                hmac.update(&self.iv);
                hmac.update(&self.ciphertext);
                let calculated_mac = hmac.finalize().into_bytes();

                if expected_mac.ct_eq(&calculated_mac).unwrap_u8() != 1 {
                    return Err(CryptoError::MacMismatch);
                }

                // Decrypt ONLY after HMAC verification passes (Encrypt-then-MAC)
                let mut buf = self.ciphertext.clone();
                let dec = Aes256CbcDec::new_from_slices(&key.enc_key, &self.iv)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

                let decrypted_slice = dec
                    .decrypt_padded_mut::<Pkcs7>(&mut buf)
                    .map_err(|e| CryptoError::DecryptionFailed(format!("{:?}", e)))?;

                Ok(decrypted_slice.to_vec())
            }
            other => Err(CryptoError::UnsupportedCipherType(other)),
        }
    }

    pub fn decrypt_string(&self, key: &SymmetricCryptoKey) -> Result<String, CryptoError> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes).map_err(|_| CryptoError::Utf8Error)
    }
}

pub fn decrypt_aes_cbc_bytes(
    ciphertext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if iv.len() != 16 {
        return Err(CryptoError::DecryptionFailed(
            "Invalid IV length".to_string(),
        ));
    }
    let mut buf = ciphertext.to_vec();
    let dec = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
    let slice = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| CryptoError::DecryptionFailed(format!("{:?}", e)))?;
    Ok(slice.to_vec())
}

pub fn parse_rsa_private_key_der(der_bytes: &[u8]) -> Result<rsa::RsaPrivateKey, CryptoError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der_bytes) {
        return Ok(key);
    }
    if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(der_bytes) {
        return Ok(key);
    }

    // Try decoding if der_bytes is UTF-8 text (Base64 string or PEM formatted)
    if let Ok(text) = std::str::from_utf8(der_bytes) {
        let text_clean = text.trim();
        // 1. Try raw Base64 decode
        if let Ok(decoded_b64) = BASE64.decode(text_clean) {
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(&decoded_b64) {
                return Ok(key);
            }
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(&decoded_b64) {
                return Ok(key);
            }
        }
        // 2. Try PEM decode
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(text_clean) {
            return Ok(key);
        }
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_pem(text_clean) {
            return Ok(key);
        }
    }

    Err(CryptoError::DecryptionFailed(
        "Invalid RSA private key (failed PKCS#8/PKCS#1 DER/Base64/PEM parsing)".to_string(),
    ))
}

pub fn parse_symmetric_key_from_decrypted_bytes(bytes: &[u8]) -> Option<SymmetricCryptoKey> {
    if bytes.len() == 32 || bytes.len() == 64 {
        if let Ok(k) = SymmetricCryptoKey::from_raw_bytes(bytes) {
            return Some(k);
        }
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let text_clean = text.trim();
        if let Ok(decoded) = BASE64.decode(text_clean) {
            if decoded.len() == 32 || decoded.len() == 64 {
                if let Ok(k) = SymmetricCryptoKey::from_raw_bytes(&decoded) {
                    return Some(k);
                }
            }
        }
    }
    None
}

pub fn decrypt_attachment_blob(
    blob: &[u8],
    key: &SymmetricCryptoKey,
) -> Result<Vec<u8>, CryptoError> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }

    // Standard Bitwarden EncArrayBuffer format:
    // Format 1: [1 byte encType == 2][16 bytes IV][32 bytes MAC][Ciphertext]
    if blob.len() >= 49 && blob[0] == 2 {
        let iv = &blob[1..17];
        let mac = &blob[17..49];
        let ct = &blob[49..];

        if !ct.len().is_multiple_of(16) {
            return Err(CryptoError::DecryptionFailed(
                "Attachment ciphertext length is not a multiple of 16 (incomplete or truncated download)".to_string(),
            ));
        }

        let mac_key = key.mac_key.as_ref().ok_or(CryptoError::MacMismatch)?;
        let mut hmac = HmacSha256::new_from_slice(mac_key)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid MAC key".to_string()))?;
        hmac.update(iv);
        hmac.update(ct);
        let calculated_mac = hmac.finalize().into_bytes();
        if mac.ct_eq(&calculated_mac).unwrap_u8() != 1 {
            return Err(CryptoError::DecryptionFailed(
                "Attachment HMAC integrity verification failed (corrupted or incomplete download)"
                    .to_string(),
            ));
        }

        return decrypt_aes_cbc_bytes(ct, iv, &key.enc_key);
    }

    // Format 2: [1 byte encType == 0][16 bytes IV][Ciphertext]
    if blob.len() >= 17 && blob[0] == 0 {
        let iv = &blob[1..17];
        let ct = &blob[17..];
        if !ct.len().is_multiple_of(16) {
            return Err(CryptoError::DecryptionFailed(
                "Attachment ciphertext length is not a multiple of 16 (incomplete download)"
                    .to_string(),
            ));
        }
        return decrypt_aes_cbc_bytes(ct, iv, &key.enc_key);
    }

    // Format 3: [16 bytes IV][32 bytes MAC][Ciphertext] (no leading encType byte)
    if blob.len() >= 48 {
        let iv = &blob[0..16];
        let mac = &blob[16..48];
        let ct = &blob[48..];
        if ct.len().is_multiple_of(16) {
            if let Some(mac_key) = key.mac_key.as_ref() {
                if let Ok(mut hmac) = HmacSha256::new_from_slice(mac_key) {
                    hmac.update(iv);
                    hmac.update(ct);
                    let calculated_mac = hmac.finalize().into_bytes();
                    if mac.ct_eq(&calculated_mac).unwrap_u8() == 1 {
                        if let Ok(decrypted) = decrypt_aes_cbc_bytes(ct, iv, &key.enc_key) {
                            return Ok(decrypted);
                        }
                    }
                }
            }
        }
    }

    // Format 4: [16 bytes IV][Ciphertext][32 bytes MAC] (trailing MAC)
    if blob.len() >= 48 {
        let iv = &blob[0..16];
        let ct_len = blob.len() - 48;
        if ct_len.is_multiple_of(16) {
            let ct = &blob[16..16 + ct_len];
            let mac = &blob[16 + ct_len..];
            if let Some(mac_key) = key.mac_key.as_ref() {
                if let Ok(mut hmac) = HmacSha256::new_from_slice(mac_key) {
                    hmac.update(iv);
                    hmac.update(ct);
                    let calculated_mac = hmac.finalize().into_bytes();
                    if mac.ct_eq(&calculated_mac).unwrap_u8() == 1 {
                        if let Ok(decrypted) = decrypt_aes_cbc_bytes(ct, iv, &key.enc_key) {
                            return Ok(decrypted);
                        }
                    }
                }
            }
        }
    }

    // Format 5: [16 bytes IV][Ciphertext]
    if blob.len() >= 16 {
        let iv = &blob[0..16];
        let ct = &blob[16..];
        if ct.len().is_multiple_of(16) {
            if let Ok(decrypted) = decrypt_aes_cbc_bytes(ct, iv, &key.enc_key) {
                return Ok(decrypted);
            }
        }
    }

    Err(CryptoError::DecryptionFailed(
        "Attachment blob does not match any valid encrypted format or decryption failed"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_master_key_derivation() {
        let master_key = derive_master_key(
            "user@example.com",
            "password123",
            KdfType::Pbkdf2Sha256,
            100_000,
            None,
            None,
        )
        .unwrap();

        assert_eq!(master_key.len(), 32);

        let auth_hash = derive_master_password_hash(&master_key, "password123");
        assert!(!auth_hash.is_empty());
    }

    #[test]
    fn test_symmetric_key_and_encstring_roundtrip() {
        let raw_key = [7u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        // Sample encrypted string: type 2 (AES-256-CBC with HMAC-SHA256)
        // Let's create an encstring and verify decrypt
        let iv = [1u8; 16];
        let plaintext = b"Hello, Bitwarden Native Rust!";

        use cbc::cipher::BlockEncryptMut;
        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let enc = Aes256CbcEnc::new_from_slices(&key.enc_key, &iv).unwrap();
        let mut buf = vec![0u8; 64];
        let ct_len = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let mut hmac = HmacSha256::new_from_slice(key.mac_key.as_ref().unwrap()).unwrap();
        hmac.update(&iv);
        hmac.update(ct);
        let mac = hmac.finalize().into_bytes();

        let enc_str_val = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );

        let parsed = EncString::parse(&enc_str_val).unwrap();
        assert_eq!(parsed.enc_type, 2);

        let decrypted = parsed.decrypt_string(&key).unwrap();
        assert_eq!(decrypted, "Hello, Bitwarden Native Rust!");
    }

    #[test]
    fn test_hmac_verification_rejects_tampered_mac() {
        let raw_key = [7u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("https://vault.bitwarden.com").unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();

        // Corrupt MAC byte
        if let Some(ref mut mac) = parsed.mac {
            mac[0] ^= 0xFF;
        }

        assert_eq!(
            parsed.decrypt(&key).unwrap_err(),
            CryptoError::MacMismatch,
            "Altered MAC must be strictly rejected with MacMismatch"
        );
        assert_eq!(
            parsed.decrypt_string(&key).unwrap_err(),
            CryptoError::MacMismatch,
            "decrypt_string must not fall back to unauthenticated CBC decryption"
        );
    }

    #[test]
    fn test_hmac_verification_rejects_altered_iv_cbc_bit_flipping() {
        let raw_key = [11u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        // Plaintext: "https://good.example/login"
        let plaintext = "https://good.example/login";
        let encrypted = key.encrypt_string(plaintext).unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();

        // CBC bit-flip: "https://" is 8 chars, 'g' is index 8 in plaintext block 0.
        // Changing IV[8] by ('g' ^ 'b') would flip 'g' to 'b' in CBC mode without MAC.
        parsed.iv[8] ^= b'g' ^ b'b';

        let res = parsed.decrypt_string(&key);
        assert!(
            res.is_err(),
            "CBC bit flipping attack on IV must be rejected by HMAC verification"
        );
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_hmac_verification_rejects_altered_ciphertext() {
        let raw_key = [13u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("SuperSecretPassword123!").unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();

        // Tamper ciphertext
        parsed.ciphertext[5] ^= 0xAA;

        let res = parsed.decrypt_string(&key);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_hmac_verification_rejects_missing_mac_on_type_2() {
        let raw_key = [17u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("Secret Data").unwrap();
        let mut parsed = EncString::parse(&encrypted).unwrap();
        parsed.mac = None; // Strip MAC

        let res = parsed.decrypt_string(&key);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_hmac_verification_rejects_key_missing_mac_key() {
        let raw_key = [19u8; 64];
        let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

        let encrypted = key.encrypt_string("Secret Data").unwrap();
        let parsed = EncString::parse(&encrypted).unwrap();

        let key_without_mac = SymmetricCryptoKey {
            enc_key: key.enc_key,
            mac_key: None,
        };

        let res = parsed.decrypt_string(&key_without_mac);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), CryptoError::MacMismatch);
    }

    #[test]
    fn test_decrypt_with_master_key_rejects_tampered_mac() {
        let master_key = [23u8; 32];
        let sym_key = SymmetricCryptoKey::from_master_key(&master_key);

        let user_key_raw = [42u8; 64];
        let encrypted_user_key = sym_key
            .encrypt_string(&BASE64.encode(user_key_raw))
            .unwrap();
        let mut parsed = EncString::parse(&encrypted_user_key).unwrap();

        // Tamper MAC
        if let Some(ref mut mac) = parsed.mac {
            mac[0] ^= 0xEE;
        }

        let res = SymmetricCryptoKey::decrypt_with_master_key(&parsed, &master_key);
        assert!(
            res.is_err(),
            "decrypt_with_master_key must reject tampered MAC without unauthenticated fallback"
        );
    }

    #[test]
    fn test_legacy_type_0_roundtrip() {
        let enc_key = [31u8; 32];
        let iv = [5u8; 16];
        let plaintext = b"Legacy Type 0 unauthenticated data";

        use cbc::cipher::BlockEncryptMut;
        let cipher = cbc::Encryptor::<Aes256>::new((&enc_key).into(), (&iv).into());
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .len();
        let ct = &buf[..ct_len];

        let enc_str_val = format!("0.{}|{}", BASE64.encode(iv), BASE64.encode(ct));
        let parsed = EncString::parse(&enc_str_val).unwrap();
        assert_eq!(parsed.enc_type, 0);
        assert!(parsed.mac.is_none());

        let key = SymmetricCryptoKey {
            enc_key,
            mac_key: None,
        };
        let decrypted = parsed.decrypt_string(&key).unwrap();
        assert_eq!(decrypted, "Legacy Type 0 unauthenticated data");
    }
}

#[test]
fn test_node_hkdf_match() {
    let ikm_arr = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    let hkdf_new = Hkdf::<Sha256>::new(Some(&[]), &ikm_arr);
    let mut enc1 = [0u8; 32];
    let mut mac1 = [0u8; 32];
    hkdf_new.expand(b"enc", &mut enc1).unwrap();
    hkdf_new.expand(b"mac", &mut mac1).unwrap();

    let hkdf_prk = Hkdf::<Sha256>::from_prk(&ikm_arr).unwrap();
    let mut enc2 = [0u8; 32];
    let mut mac2 = [0u8; 32];
    hkdf_prk.expand(b"enc", &mut enc2).unwrap();
    hkdf_prk.expand(b"mac", &mut mac2).unwrap();

    let node_enc_hex = "4f2f2b0e362ca4586b7a3e9914c5542aea3c70a1a79844839f87730cac1f709f";
    let node_mac_hex = "f6cfc3122278c43ca1dbee7cd9a7c05e32c086127d5afd8f758d99230fa37d4d";

    let hex_enc1: String = enc1.iter().map(|b| format!("{:02x}", b)).collect();
    let hex_mac1: String = mac1.iter().map(|b| format!("{:02x}", b)).collect();

    assert_eq!(hex_enc1, node_enc_hex);
    assert_eq!(hex_mac1, node_mac_hex);
}

#[test]
fn test_decrypt_attachment_blob() {
    use cbc::cipher::BlockEncryptMut;

    let raw_key = [42u8; 64];
    let key = SymmetricCryptoKey::from_raw_bytes(&raw_key).unwrap();

    let iv = [9u8; 16];
    let plaintext = b"JFIF JPEG Image Content Data";

    // Encrypt AES-256-CBC
    let cipher = cbc::Encryptor::<aes::Aes256>::new((&key.enc_key).into(), (&iv).into());
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);
    let ciphertext = cipher
        .encrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf, plaintext.len())
        .unwrap()
        .to_vec();

    // Test Standard Bitwarden EncArrayBuffer Format 1: [encType=2][IV][MAC][Ciphertext]
    let mut hmac = HmacSha256::new_from_slice(key.mac_key.as_ref().unwrap()).unwrap();
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    let mut bitwarden_blob = Vec::new();
    bitwarden_blob.push(2u8);
    bitwarden_blob.extend_from_slice(&iv);
    bitwarden_blob.extend_from_slice(&mac);
    bitwarden_blob.extend_from_slice(&ciphertext);

    let decrypted1 = decrypt_attachment_blob(&bitwarden_blob, &key).unwrap();
    assert_eq!(decrypted1, plaintext);

    // Test Format 5: [16 bytes IV][ciphertext]
    let mut blob = Vec::new();
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ciphertext);

    let decrypted2 = decrypt_attachment_blob(&blob, &key).unwrap();
    assert_eq!(decrypted2, plaintext);

    // Truncated blob (incomplete download) MUST fail decryption rather than returning raw ciphertext
    let truncated_blob = &bitwarden_blob[..bitwarden_blob.len() - 5];
    assert!(
        decrypt_attachment_blob(truncated_blob, &key).is_err(),
        "Truncated attachment blob must return Err, not Ok"
    );

    // Blob with corrupted HMAC (e.g. truncated block boundary) MUST fail decryption
    let mut bad_mac_blob = bitwarden_blob.clone();
    bad_mac_blob[20] ^= 0xFF;
    assert!(
        decrypt_attachment_blob(&bad_mac_blob, &key).is_err(),
        "Corrupted MAC attachment blob must return Err, not Ok"
    );
}
