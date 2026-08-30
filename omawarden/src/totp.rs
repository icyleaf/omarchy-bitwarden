use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpResult {
    pub code: String,
    pub ttl: u64,
    pub period: u64,
}

pub fn parse_totp_secret(secret_or_uri: &str) -> Option<String> {
    let raw = secret_or_uri.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("otpauth://") {
        if let Ok(parsed) = Url::parse(raw) {
            for (k, v) in parsed.query_pairs() {
                if k == "secret" && !v.trim().is_empty() {
                    let cleaned: String = v.chars().filter(|c| !c.is_whitespace()).collect();
                    return Some(cleaned.to_ascii_uppercase());
                }
            }
        }
        return None;
    }
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_ascii_uppercase())
    }
}

pub fn generate_totp(
    secret_or_uri: &str,
    timestamp: Option<u64>,
    digits: u32,
    period: u64,
) -> Option<TotpResult> {
    let secret = parse_totp_secret(secret_or_uri)?;

    let now = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let counter = now / period;
    let ttl = period - (now % period);

    // Normalize base32 padding
    let mut padded = secret;
    let missing_padding = padded.len() % 8;
    if missing_padding != 0 {
        padded.push_str(&"=".repeat(8 - missing_padding));
    }

    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &padded)?;

    // Counter to 8-byte big endian
    let msg = counter.to_be_bytes();

    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let mut mac = HmacSha1::new_from_slice(&key).ok()?;
    mac.update(&msg);
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0F) as usize;
    if offset + 4 > result.len() {
        return None;
    }

    let code_int = u32::from_be_bytes([
        result[offset] & 0x7F,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    let modulus = 10u32.pow(digits);
    let code_val = code_int % modulus;
    let code_str = format!("{:0width$}", code_val, width = digits as usize);

    Some(TotpResult {
        code: code_str,
        ttl,
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_totp_secret() {
        assert_eq!(
            parse_totp_secret("JBSWY3DPEHPK3PXP"),
            Some("JBSWY3DPEHPK3PXP".to_string())
        );
        assert_eq!(
            parse_totp_secret("jbsw y3dp ehpk 3pxp"),
            Some("JBSWY3DPEHPK3PXP".to_string())
        );
        assert_eq!(
            parse_totp_secret("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
            Some("JBSWY3DPEHPK3PXP".to_string())
        );
    }

    #[test]
    fn test_generate_totp_vector() {
        // RFC 6238 test vectors (HMAC-SHA1 with secret "12345678901234567890" in base32 is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let res = generate_totp(secret, Some(59), 6, 30).unwrap();
        assert_eq!(res.code, "287082");
        assert_eq!(res.ttl, 1);
        assert_eq!(res.period, 30);
    }
}
