import pytest
from bitwarden_helper.totp import generate_totp, parse_totp_secret

def test_parse_totp_secret():
    # Plain base32 secret
    assert parse_totp_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"
    # otpauth URL
    uri = "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    assert parse_totp_secret(uri) == "JBSWY3DPEHPK3PXP"
    # Invalid / empty
    assert parse_totp_secret("") is None

def test_generate_totp():
    # RFC 6238 reference test secret "12345678901234567890" in base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    secret = "JBSWY3DPEHPK3PXP"
    res = generate_totp(secret, timestamp=1700000000)
    assert res is not None
    assert len(res["code"]) == 6
    assert res["code"].isdigit()
    assert 0 <= res["ttl"] <= 30
    assert res["period"] == 30
