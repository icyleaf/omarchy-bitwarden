use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
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
                .hash_password_into(
                    password.as_bytes(),
                    &email_hash,
                    master_key.as_mut(),
                )
                .map_err(|_| CryptoError::InvalidKdfParams)?;
        }
    }

    Ok(master_key)
}

pub fn derive_master_password_hash(
    master_key: &[u8; 32],
    password: &str,
) -> String {
    let mut hash = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(
        master_key.as_ref(),
        password.as_bytes(),
        1,
        hash.as_mut(),
    );
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
        let hkdf = Hkdf::<Sha256>::new(None, master_key);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];

        hkdf.expand(b"enc", &mut enc_key).expect("HKDF expand enc failed");
        hkdf.expand(b"mac", &mut mac_key).expect("HKDF expand mac failed");

        Self {
            enc_key,
            mac_key: Some(mac_key),
        }
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
        if parts.len() < 2 {
            return Err(CryptoError::InvalidEncString(raw.to_string()));
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

    pub fn decrypt(&self, key: &SymmetricCryptoKey) -> Result<Vec<u8>, CryptoError> {
        match self.enc_type {
            0 | 2 => {
                // If MAC is present, verify MAC
                if let (Some(expected_mac), Some(mac_key)) = (&self.mac, &key.mac_key) {
                    let mut hmac = HmacSha256::new_from_slice(mac_key)
                        .map_err(|_| CryptoError::MacMismatch)?;
                    hmac.update(&self.iv);
                    hmac.update(&self.ciphertext);
                    let calculated_mac = hmac.finalize().into_bytes();

                    if expected_mac.ct_eq(&calculated_mac).unwrap_u8() != 1 {
                        return Err(CryptoError::MacMismatch);
                    }
                }

                if self.iv.len() != 16 {
                    return Err(CryptoError::DecryptionFailed("Invalid IV length".to_string()));
                }

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
        let ct_len = enc.encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf).unwrap().len();
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
}
