import pytest
import pyotp
from fastapi.testclient import TestClient
from bluep.bluep import BlueApp
from PIL import Image
from io import BytesIO

def test_qr_raw_endpoint(client):
    """Test QR code generation endpoint"""
    response = client.get("/qr-raw")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"

    # Verify it's a valid PNG image
    img = Image.open(BytesIO(response.content))
    assert img.format == "PNG"

def test_setup_page(client):
    """Test TOTP setup page"""
    response = client.get("/setup")
    assert response.status_code == 200
    assert "Room Setup" in response.text
    assert "Secret key:" in response.text

def test_favicon_with_auth(client, auth):
    """Test favicon endpoint with authentication"""
    totp = pyotp.TOTP(auth.secret_key)
    current_token = totp.now()

    response = client.get(f"/favicon.png?key={current_token}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"

    # Test without auth
    response = client.get("/favicon.png")
    assert response.status_code == 403
