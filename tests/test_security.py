"""Test security features of the bluep application.

This module contains tests for TLS certificates, cryptographic operations,
and security headers.
"""

import os
import tempfile
import pytest
import base64
import hashlib
import json
import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from bluep.cert_generator import generate_ssl_certs
from bluep.models import KeyExchangeRequest, KeyExchangeResponse, CertificateVerification, TamperingReport
from bluep.bluep import BlueApp
from fastapi.testclient import TestClient


def test_secure_config():
    """Test that secure configuration settings are enabled"""
    with patch("bluep.config.Settings") as mock_settings:
        # Configure mock
        mock_settings.return_value.ssl_certfile = "cert.pem"
        mock_settings.return_value.ssl_keyfile = "key.pem"
        mock_settings.return_value.port = 8500
        mock_settings.return_value.host_ip = "127.0.0.1"
        
        from bluep.bluep import settings
        
        # Verify SSL is enabled
        assert settings.ssl_certfile is not None
        assert settings.ssl_keyfile is not None


def test_ssl_cert_generation():
    """Test SSL certificate generation"""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "key.pem")
        cert_path = os.path.join(tmpdir, "cert.pem")
        
        # Generate certificates
        generate_ssl_certs(cert_path, key_path)
        
        # Verify files exist and have content
        assert os.path.exists(key_path)
        assert os.path.exists(cert_path)
        assert os.path.getsize(key_path) > 0
        assert os.path.getsize(cert_path) > 0


@pytest.mark.asyncio
async def test_certificate_verification():
    """Test certificate verification endpoint"""
    app = BlueApp()
    client = TestClient(app.app)
    
    # Mock certificate fingerprint
    app.cert_fingerprint = "mock_fingerprint_for_testing"
    
    # Send valid verification request with current time
    verification_data = CertificateVerification(
        clientTime=int(datetime.datetime.now().timestamp() * 1000),
        expectedFingerprint=app.cert_fingerprint
    )
    
    response = client.post(
        "/verify-cert",
        json=verification_data.model_dump()
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["fingerprint"] == app.cert_fingerprint
    
    # Test with incorrect fingerprint
    verification_data = CertificateVerification(
        clientTime=int(datetime.datetime.now().timestamp() * 1000),
        expectedFingerprint="incorrect_fingerprint"
    )
    
    response = client.post(
        "/verify-cert", 
        json=verification_data.model_dump()
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False


@pytest.mark.asyncio
async def test_key_exchange():
    """Test ECDH key exchange endpoint"""
    # Create app instance
    app = BlueApp()
    
    # Create a mock session manager
    mock_session_manager = MagicMock()
    mock_session_manager.validate_websocket_token.return_value = "test_session"
    mock_session_manager.get_session.return_value = MagicMock()
    
    # Replace the real session manager with the mock
    app.session_manager = mock_session_manager
    
    # Create a test client
    client = TestClient(app.app)
    
    # Generate client key pair for test
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    client_public_key = client_private_key.public_key()
    
    # Serialize public key for sending
    client_public_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Create key exchange request
    key_request = KeyExchangeRequest(
        token="test_token",
        clientKey=base64.b64encode(client_public_bytes).decode()
    )
    
    # Send request
    response = client.post(
        "/key-exchange",
        json=key_request.model_dump()
    )
    
    # Verify response
    assert response.status_code == 200
    data = response.json()
    assert "serverKey" in data
    assert "keyId" in data
    
    # Verify session was updated
    session = mock_session_manager.get_session.return_value
    assert hasattr(session, "key_exchange_data")


@pytest.mark.asyncio
async def test_tampering_report():
    """Test tampering report endpoint"""
    # Create app instance
    app = BlueApp()
    
    # Create a mock session manager
    mock_session_manager = MagicMock()
    mock_session_manager.validate_websocket_token.return_value = "test_session"
    mock_session_manager.websocket_tokens = {"test_token": "test_session"}
    mock_session_manager.sessions = {"test_session": MagicMock()}
    
    # Replace the real session manager with the mock
    app.session_manager = mock_session_manager
    
    # Create a test client
    client = TestClient(app.app)
    
    # Create tampering report
    report = TamperingReport(
        type="dom_modified",
        timestamp=1647123456789,
        token="test_token",
        details={"element": "script", "modification": "content"}
    )
    
    # Send report
    response = client.post(
        "/tampering-report",
        json=report.model_dump()
    )
    
    # Verify response
    assert response.status_code == 204
    
    # Verify session was invalidated
    assert "test_token" not in mock_session_manager.websocket_tokens
    assert "test_session" not in mock_session_manager.sessions


@pytest.mark.asyncio
async def test_security_headers():
    """Test that security headers are set correctly"""
    app = BlueApp()
    client = TestClient(app.app)
    
    # Mock authentication to access a protected route
    with patch("bluep.auth.TOTPAuth.verify_and_create_session", return_value=True):
        response = client.get("/?key=123456")
        
        # Check security headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
        assert "camera=()" in response.headers["Permissions-Policy"]
        assert "document-domain=()" in response.headers["Permissions-Policy"]
        
        # Check CSP headers
        csp = response.headers["Content-Security-Policy"] 
        assert "default-src 'self'" in csp
        assert "script-src" in csp
        assert "connect-src 'self' wss:" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        
        # Verify CSP reporting is configured
        assert "Report-To" in response.headers