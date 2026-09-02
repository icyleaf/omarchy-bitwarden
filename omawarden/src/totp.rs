use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpResult {
    pub code: String,
    pub ttl: u64,
    pub period: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpParams {
    pub secret: String,
    pub algorithm: String, // "SHA1", "SHA256", "SHA512"
    pub digits: u32,
    pub period: u64,
}

pub fn parse_totp_params(secret_or_uri: &str) -> Option<TotpParams> {
    let raw = secret_or_uri.trim();
    if raw.is_empty() {
        return None;
    }

    let mut secret = String::new();
    let mut algorithm = "SHA1".to_string();
    let mut digits = 6u32;
    let mut period = 30u64;

    if raw.starts_with("otpauth://") || raw.starts_with("otpauth-migration://") {
        if let Ok(parsed) = Url::parse(raw) {
            for (k, v) in parsed.query_pairs() {
                match k.as_ref() {
                    "secret" => {
                        secret = v.chars().filter(|c| !c.is_whitespace()).collect();
                    }
                    "algorithm" => {
                        algorithm = v.to_ascii_uppercase();
                    }
                    "digits" => {
                        if let Ok(d) = v.parse::<u32>() {
                            digits = d;
                        }
                    }
                    "period" => {
                        if let Ok(p) = v.parse::<u64>() {
                            period = p;
                        }
                    }
                    _ => {}
                }
            }
        }
    } else if let Some(q_idx) = raw.find('?') {
        let (sec_part, query_part) = raw.split_at(q_idx);
        secret = sec_part.chars().filter(|c| !c.is_whitespace()).collect();
        for pair in query_part.trim_start_matches('?').split('&') {
            let mut kv = pair.splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                match k {
                    "digits" => {
                        if let Ok(d) = v.parse::<u32>() {
                            digits = d;
                        }
                    }
                    "period" => {
                        if let Ok(p) = v.parse::<u64>() {
                            period = p;
                        }
                    }
                    "algorithm" => {
                        algorithm = v.to_ascii_uppercase();
                    }
                    _ => {}
                }
            }
        }
    } else {
        secret = raw.chars().filter(|c| !c.is_whitespace()).collect();
    }

    if secret.is_empty() {
        return None;
    }

    Some(TotpParams {
        secret: secret.to_ascii_uppercase(),
        algorithm,
        digits,
        period,
    })
}

pub fn parse_totp_secret(secret_or_uri: &str) -> Option<String> {
    parse_totp_params(secret_or_uri).map(|p| p.secret)
}

pub fn generate_totp(
    secret_or_uri: &str,
    timestamp: Option<u64>,
    default_digits: u32,
    default_period: u64,
) -> Option<TotpResult> {
    let params = parse_totp_params(secret_or_uri)?;
    let digits = if params.digits != 6 {
        params.digits
    } else {
        default_digits
    };
    let period = if params.period != 30 {
        params.period
    } else {
        default_period
    };

    let now = timestamp.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    let counter = now / period;
    let ttl = period - (now % period);

    // Normalize base32 padding
    let mut padded = params.secret.clone();
    let missing_padding = padded.len() % 8;
    if missing_padding != 0 {
        padded.push_str(&"=".repeat(8 - missing_padding));
    }

    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &padded)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &params.secret))
        .or_else(|| {
            base32::decode(
                base32::Alphabet::Rfc4648Lower { padding: false },
                &params.secret,
            )
        })?;

    let msg = counter.to_be_bytes();

    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    let result: Vec<u8> = match params.algorithm.as_str() {
        "SHA256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).ok()?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&key).ok()?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&key).ok()?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };

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

    crate::log_info!(
        "omawarden:totp",
        "Generated TOTP token (ttl: {}s, period: {}s).",
        ttl,
        period
    );

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
            parse_totp_secret(
                "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
            ),
            Some("JBSWY3DPEHPK3PXP".to_string())
        );
        assert_eq!(
            parse_totp_secret("JBSWY3DPEHPK3PXP?digits=6&period=30"),
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

    #[test]
    fn test_generate_totp_with_query_params() {
        let uri = "otpauth://totp/Test:user?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60&algorithm=SHA256";
        let res = generate_totp(uri, Some(59), 6, 30).unwrap();
        assert_eq!(res.code.len(), 8);
        assert_eq!(res.period, 60);
        assert_eq!(res.ttl, 1);
    }
}
