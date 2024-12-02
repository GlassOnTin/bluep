import pytest
from datetime import datetime, timedelta
from fastapi import Response
import time
from bluep.session_manager import SessionManager


def test_session_creation():
    """Test session creation and cookie setting"""
    manager = SessionManager()
    response = Response()
    session_id = manager.create_session("test_user", response)

    assert session_id in manager.sessions
    assert manager.sessions[session_id].username == "test_user"
    assert isinstance(manager.sessions[session_id].expiry, datetime)

    cookie_header = response.headers.get("set-cookie")
    assert cookie_header is not None
    assert session_id in cookie_header
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header


def test_session_expiry():
    """Test session expiration handling"""
    manager = SessionManager(cookie_max_age=1)
    response = Response()
    session_id = manager.create_session("test_user", response)

    # Test valid session
    assert manager.get_session(session_id) is not None

    # Test expired session
    time.sleep(2)
    assert manager.get_session(session_id) is None
    assert session_id not in manager.sessions


def test_session_totp_validation():
    """Test TOTP code reuse prevention"""
    manager = SessionManager()
    response = Response()
    session_id = manager.create_session("test_user", response)

    # Test first use of TOTP code
    assert manager.validate_totp_use(session_id, "123456")

    # Test reuse of same TOTP code
    assert not manager.validate_totp_use(session_id, "123456")

    # Test different TOTP code
    assert manager.validate_totp_use(session_id, "654321")
