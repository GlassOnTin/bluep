import pytest
import pyotp
import time
from datetime import datetime, timedelta
from fastapi import HTTPException, Response
from starlette.requests import Request
from starlette.datastructures import Headers

def test_totp_verification(auth):
    """Test basic TOTP code verification"""
    totp = pyotp.TOTP(auth.secret_key)
    current_token = totp.now()
    assert auth.verify(current_token)
    assert not auth.verify("000000")
    assert not auth.verify("")

def test_rate_limiting(auth):
    """Test rate limiting for failed authentication attempts"""
    ip = "127.0.0.1"
    # Test successful rate limit check
    assert auth._check_rate_limit(ip)

    # Test rate limit exceeded
    for _ in range(auth.max_attempts):
        auth._record_failed_attempt(ip)
    assert not auth._check_rate_limit(ip)

    # Test rate limit reset after timeout
    auth._failed_attempts[ip] = (auth.max_attempts, time.time() - auth.lockout_time - 1)
    assert auth._check_rate_limit(ip)

def test_totp_qr_generation(auth):
    """Test TOTP QR code generation"""
    qr_data = auth._generate_qr()
    assert qr_data  # Should return base64 string
    assert isinstance(qr_data, str)
    assert len(qr_data) > 0

@pytest.mark.asyncio
async def test_verify_session_invalid(auth):
    """Test session verification with invalid session"""
    # Create a properly structured request with headers
    scope = {
        "type": "http",
        "headers": [(b"cookie", b"invalid=123")]
    }
    request = Request(scope)

    with pytest.raises(HTTPException) as exc:
        await auth.verify_session(request)
    assert exc.value.status_code == 401
    assert "No session found" in str(exc.value.detail)

@pytest.mark.asyncio
async def test_verify_session_expired(auth):
    """Test handling of expired sessions"""
    # Create mock request with proper structure
    class MockRequest:
        def __init__(self):
            self.client = type('Client', (), {'host': '127.0.0.1'})()
            self.scope = {
                "type": "http",
                "headers": [(b"cookie", b"bluep_session=test_session")]
            }
            self._cookies = {"bluep_session": "test_session"}

        @property
        def cookies(self):
            return self._cookies

    mock_request = MockRequest()
    response = Response()

    # Create a valid session first
    current_token = auth.totp.now()
    await auth.verify_and_create_session(current_token, mock_request, response)

    # Get the created session ID from the response cookie
    cookie_header = response.headers.get('set-cookie')
    session_id = cookie_header.split('=')[1].split(';')[0]

    # Update mock request with the real session ID
    mock_request._cookies["bluep_session"] = session_id

    # Manually expire the session
    auth.session_manager.sessions[session_id].expiry = datetime.now() - timedelta(hours=1)

    # Verify expired session raises exception
    with pytest.raises(HTTPException) as exc:
        await auth.verify_session(mock_request)
    assert exc.value.status_code == 401
    assert "Invalid or expired session" in str(exc.value.detail)

@pytest.mark.asyncio
async def test_verify_and_create_session_invalid_totp(auth):
    """Test handling of invalid TOTP codes"""
    class MockRequest:
        def __init__(self):
            self.client = type('Client', (), {'host': '127.0.0.1'})()

    response = Response()
    with pytest.raises(HTTPException) as exc:
        await auth.verify_and_create_session("000000", MockRequest(), response)
    assert exc.value.status_code == 403
    assert "Invalid TOTP key" in str(exc.value.detail)

def test_totp_reuse_prevention(auth, mock_request, mock_response):
    """Test prevention of TOTP code reuse"""
    totp = pyotp.TOTP(auth.secret_key)
    current_token = totp.now()

    # Should succeed first time
    session_id = auth.session_manager.create_session("test_user", mock_response)
    assert auth.session_manager.validate_totp_use(session_id, current_token)

    # Should fail on reuse
    assert not auth.session_manager.validate_totp_use(session_id, current_token)
