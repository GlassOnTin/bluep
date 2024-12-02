# tests/test_websocket.py
import pytest
import pyotp
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocket
from bluep.websocket_manager import WebSocketManager


class MockWebSocket:
    """Mock WebSocket for testing"""

    def __init__(self):
        self.sent_messages = []
        self.closed = False

    async def accept(self):
        pass

    async def send_json(self, data):
        self.sent_messages.append(data)

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_websocket_manager():
    """Test WebSocket manager functionality"""
    manager = WebSocketManager()
    ws1 = MockWebSocket()
    ws2 = MockWebSocket()

    # Test connection of first client
    await manager.connect(ws1)
    assert ws1 in manager.active_connections
    # Should receive client count and initial content
    assert len(ws1.sent_messages) == 2
    assert ws1.sent_messages[0] == {"type": "clients", "count": 1}
    assert ws1.sent_messages[1] == {"type": "content", "data": ""}

    # Test content broadcast with shared text update
    test_msg = {"type": "content", "data": "test"}
    manager.update_shared_text("test")  # Update the shared text state
    await manager.broadcast(test_msg)
    assert ws1.sent_messages[2] == test_msg

    # Test second client connection
    await manager.connect(ws2)
    # ws2 should receive client count and current content
    assert len(ws2.sent_messages) == 2
    assert ws2.sent_messages[0] == {"type": "clients", "count": 2}
    assert ws2.sent_messages[1] == {
        "type": "content",
        "data": "test",
    }  # Should receive updated content
    # ws1 should have received updated client count
    assert ws1.sent_messages[3] == {"type": "clients", "count": 2}

    # Test broadcast with exclusion and new content
    new_msg = {"type": "content", "data": "test2"}
    manager.update_shared_text("test2")  # Update shared text again
    await manager.broadcast(new_msg, exclude=ws1)
    # Only ws2 should receive the message
    assert new_msg in ws2.sent_messages
    assert new_msg not in ws1.sent_messages

    # Test disconnection
    await manager.disconnect(ws1)
    assert ws1 not in manager.active_connections
    assert ws2 in manager.active_connections
    # ws2 should receive updated client count
    assert ws2.sent_messages[-1] == {"type": "clients", "count": 1}

    # Verify final shared text state
    assert manager.shared_text == "test2"


@pytest.mark.asyncio
async def test_websocket_endpoint(client, auth):
    """Test WebSocket endpoint with authentication"""
    totp = pyotp.TOTP(auth.secret_key)
    token = totp.now()

    with client.websocket_connect(f"/ws?key={token}") as websocket:
        # First message should be client count
        data = websocket.receive_json()
        assert data["type"] == "clients"
        assert "count" in data

        # Second message should be current content
        data = websocket.receive_json()
        assert data["type"] == "content"
        assert "data" in data


def test_invalid_websocket_auth(client, auth):
    """Test WebSocket connection with invalid authentication"""
    with pytest.raises(Exception):
        with client.websocket_connect("/ws?key=invalid"):
            pass
