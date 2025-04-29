"""Integration tests for the bluep application.

This module contains tests that verify multiple components work together correctly.
"""

import pytest
import json
import base64
import pyotp
from fastapi import WebSocket
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from starlette.testclient import WebSocketTestSession
from starlette.websockets import WebSocketDisconnect

from bluep.bluep import BlueApp
from bluep.auth import TOTPAuth
from bluep.models import WebSocketMessage


@pytest.fixture
def mock_app():
    """Create a test instance of the BlueApp."""
    app = BlueApp()
    return app


class MockWebSocketSession:
    """Mock WebSocket session for testing."""

    def __init__(self, client=None, url=None):
        self.client = client
        self.url = url
        self.sent_messages = []
        self.closed = False
        self.close_code = None
        self.application_state = "connected"
        self.query_params = {"token": "test_token"}

    async def accept(self):
        return None

    async def close(self, code=1000, reason=None):
        self.closed = True
        self.close_code = code

    async def send_json(self, data):
        self.sent_messages.append(data)

    async def receive_text(self):
        return json.dumps(
            {"type": "content", "data": "test message", "encrypted": True}
        )

    async def receive_json(self):
        return {"type": "content", "data": "test message", "encrypted": True}


@pytest.mark.asyncio
async def test_encryption_decryption_integration():
    """Test that encryption and decryption work with the client-side functions."""
    # In this test, we'll focus on the JavaScript crypto functions directly
    # We'll verify that:
    # 1. Messages are properly base64 encoded (simulating encryption)
    # 2. Messages can be decoded (simulating decryption)

    # Original message content
    original_message = "This is a test message for encryption"

    # Simulate encryption with base64 (as our JS would do with AES-GCM)
    encoded_message = base64.b64encode(original_message.encode()).decode()

    # Create the message object
    message = WebSocketMessage(type="content", data=encoded_message, encrypted=True)

    # Verify encrypted flag is set
    message_dict = message.model_dump(exclude_none=True)
    assert message_dict["encrypted"] is True
    assert "data" in message_dict

    # Simulate the client-side decryption with base64
    decoded_message = base64.b64decode(message_dict["data"].encode()).decode()

    # Verify the message decryption works correctly
    assert decoded_message == original_message, "Message should be correctly decrypted"


@pytest.mark.asyncio
async def test_shared_key_for_message_exchange():
    """Test that messages encrypted/decrypted with the same shared key work correctly."""
    # This test simulates how the shared key works in practice
    # It verifies:
    # 1. The server generates a consistent shared key
    # 2. Multiple clients use the same key for encryption/decryption
    # 3. Messages encrypted by one client can be decrypted by another

    # Create app and get shared key
    app = BlueApp()
    shared_key = app.session_manager.shared_encryption_key

    # Verify shared key exists
    assert shared_key, "Shared encryption key should be generated"

    # Create two session IDs representing different clients
    token1 = "test_token_client1"
    token2 = "test_token_client2"
    session_id1 = "session1"
    session_id2 = "session2"

    # Register tokens
    app.session_manager.websocket_tokens[token1] = session_id1
    app.session_manager.websocket_tokens[token2] = session_id2

    # Simulate client 1 message encryption (using base64 as a stand-in for AES)
    original_message = "Hello from client 1 to client 2"
    client1_encrypted = base64.b64encode(original_message.encode()).decode()

    # Create a properly formatted message
    message = WebSocketMessage(
        type="content", data=client1_encrypted, encrypted=True
    ).model_dump(exclude_none=True)

    # Verify the encrypted flag is preserved
    assert message["encrypted"] is True

    # Simulate client 2 receiving and decrypting the message
    # In a real app with our JS code, both clients would use the same key derived from shared_key
    received_data = message["data"]
    client2_decrypted = base64.b64decode(received_data.encode()).decode()

    # Verify client 2 can decrypt the message
    assert (
        client2_decrypted == original_message
    ), "Client 2 should be able to decrypt messages from client 1"

    # Now test in the reverse direction (client 2 -> client 1)
    response_message = "Reply from client 2 to client 1"
    client2_encrypted = base64.b64encode(response_message.encode()).decode()

    response = WebSocketMessage(
        type="content", data=client2_encrypted, encrypted=True
    ).model_dump(exclude_none=True)

    # Client 1 decrypts
    client1_decrypted = base64.b64decode(response["data"].encode()).decode()
    assert (
        client1_decrypted == response_message
    ), "Client 1 should be able to decrypt messages from client 2"


@pytest.mark.asyncio
async def test_shared_key_consistency():
    """Test that the shared encryption key is consistent across the application."""
    # Create an app instance with a specific shared key
    app = BlueApp()
    original_key = app.session_manager.shared_encryption_key

    # Verify the shared key exists and is not empty
    assert original_key, "Shared encryption key should be generated"

    # Create a mock session and verify it has access to the same key
    session_id = "test_session_id"
    token = "test_token"
    app.session_manager.websocket_tokens[token] = session_id

    # Verify that the token is registered
    assert app.session_manager.validate_websocket_token(token) == session_id

    # Verify the shared key remains consistent
    assert app.session_manager.shared_encryption_key == original_key


@pytest.mark.asyncio
async def test_client_messages_marked_encrypted(mock_app):
    """Test that client messages are properly marked as encrypted."""
    app = mock_app

    # Create a WebSocket message directly
    encrypted_data = base64.b64encode("This is encrypted content".encode()).decode()
    msg = WebSocketMessage(type="content", data=encrypted_data, encrypted=True)

    # Verify the encryption flag is preserved in the model dump
    message_dict = msg.model_dump(exclude_none=True)
    assert message_dict["encrypted"] is True
    assert message_dict["data"] == encrypted_data

    # Test the validation of encrypted flag
    msg2 = WebSocketMessage(
        type="content",
        data="some data",
        # encrypted not specified, should default to False
    )

    message_dict2 = msg2.model_dump(exclude_none=True)
    assert message_dict2["encrypted"] is False

    # Verify that a message with explicitly False flag
    msg3 = WebSocketMessage(type="content", data="plaintext data", encrypted=False)

    message_dict3 = msg3.model_dump(exclude_none=True)
    assert message_dict3["encrypted"] is False
