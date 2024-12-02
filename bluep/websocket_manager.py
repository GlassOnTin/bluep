from fastapi import WebSocket
from typing import Set, Dict, Any
import json

class WebSocketManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.shared_text: str = ""

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        await self.broadcast_client_count()
        await self.send_current_text(websocket)

    async def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        await self.broadcast_client_count()

    async def broadcast_client_count(self):
        count = len(self.active_connections)
        await self.broadcast({"type": "clients", "count": count})

    async def broadcast(self, message: Dict[str, Any], exclude: WebSocket = None):
        for connection in self.active_connections:
            if connection != exclude:
                await connection.send_json(message)

    async def send_current_text(self, websocket: WebSocket):
        await websocket.send_json({"type": "content", "data": self.shared_text})

    def update_shared_text(self, text: str):
        self.shared_text = text
