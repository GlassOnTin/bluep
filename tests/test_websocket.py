from fastapi.testclient import TestClient
import pytest
from bluep.websocket_manager import WebSocketManager


def test_websocket_connection(client, auth):
    totp = pyotp.TOTP(auth.secret_key)
    token = totp.now()
    with client.websocket_connect(f"/ws?key={token}") as websocket:
        data = websocket.receive_json()
        assert data["type"] == "content"


def test_websocket_broadcast(client, auth):
    manager = WebSocketManager()
    test_msg = {"type": "content", "data": "test"}

    async def test():
        await manager.broadcast(test_msg)
        for conn in manager.active_connections:
            assert manager.shared_text == "test"

    import asyncio

    asyncio.run(test())
