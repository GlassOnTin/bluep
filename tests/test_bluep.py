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


def test_encrypted_message_model():
    """Test that encrypted message models work correctly"""
    from bluep.models import WebSocketMessage

    # Create an encrypted message
    encrypted_msg = WebSocketMessage(
        type="content", data="encrypted_data_here", encrypted=True
    )

    # Verify the message has the encrypted flag
    assert encrypted_msg.encrypted is True

    # Test serialization and deserialization
    msg_json = encrypted_msg.model_dump_json()
    deserialized = WebSocketMessage.model_validate_json(msg_json)

    # Verify encryption flag is preserved
    assert deserialized.encrypted is True

    # Test default is False
    regular_msg = WebSocketMessage(type="content", data="regular data")
    assert regular_msg.encrypted is False

    # Test dumping to dict preserves encrypted flag
    msg_dict = encrypted_msg.model_dump(exclude_none=True)
    assert msg_dict.get("encrypted") is True
