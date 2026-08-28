import base64
import hashlib
import hmac
import struct
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse, parse_qs

def parse_totp_secret(secret_or_uri: str) -> Optional[str]:
    if not secret_or_uri:
        return None
    raw = secret_or_uri.strip()
    if raw.startswith("otpauth://"):
        try:
            parsed = urlparse(raw)
            params = parse_qs(parsed.query)
            secret_list = params.get("secret")
            if secret_list and secret_list[0]:
                return secret_list[0].strip().replace(" ", "").upper()
        except Exception:
            return None
    cleaned = raw.replace(" ", "").upper()
    return cleaned if cleaned else None

def generate_totp(secret_or_uri: str, timestamp: Optional[float] = None, digits: int = 6, period: int = 30) -> Optional[Dict[str, Any]]:
    secret = parse_totp_secret(secret_or_uri)
    if not secret:
        return None

    now = timestamp if timestamp is not None else time.time()
    counter = int(now // period)
    ttl = period - int(now % period)

    # Pad base32 string to multiple of 8
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += "=" * (8 - missing_padding)

    try:
        key = base64.b32decode(secret, casefold=True)
    except Exception:
        return None

    # Counter to 8-byte big-endian int
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()

    # Dynamic truncation
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    code_str = str(code_int % (10 ** digits)).zfill(digits)

    return {
        "code": code_str,
        "ttl": ttl,
        "period": period,
    }
