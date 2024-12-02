import pytest
import pyotp
from bluep.auth import TOTPAuth


def test_totp_verification(auth):
    totp = pyotp.TOTP(auth.secret_key)
    current_token = totp.now()
    assert auth.verify(current_token)
    assert not auth.verify("000000")


def test_rate_limiting(auth):
    ip = "127.0.0.1"
    for _ in range(auth.max_attempts):
        auth._record_failed_attempt(ip)
    assert not auth._check_rate_limit(ip)
