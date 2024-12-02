"""WebSocket management module for real-time collaboration.

This module handles WebSocket connections, broadcasts, and shared text state
for the collaborative text editor functionality.
"""

from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional
from fastapi import WebSocket


@dataclass
class ConnectionInfo:
    """Information about an active WebSocket connection.

    Attributes:
        last_active: Timestamp of last activity
        pending_pings: Count of unanswered ping messages
    """

    last_active: float
    pending_pings: int = 0


class WebSocketManager:
    """Manages active WebSocket connections and shared text state.

    Handles connection lifecycle, message broadcasting, and connection monitoring
    for the collaborative editing system.

    Attributes:
        active_connections: Dictionary of active WebSocket connections
        shared_text: Current shared text content
        timeout: Connection timeout in seconds
    """

    def __init__(self, timeout: int = 300):
        """Initialize the WebSocket manager.

        Args:
            timeout: Connection timeout in seconds (default: 300)
        """
        self.active_connections: Dict[WebSocket, ConnectionInfo] = {}
        self.shared_text: str = ""
        self.timeout = timeout

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and initialize it.

        Args:
            websocket: The WebSocket connection to initialize
        """
        await websocket.accept()
        self.active_connections[websocket] = ConnectionInfo(
            last_active=time.time(), pending_pings=0
        )
        asyncio.create_task(self._monitor_connection(websocket))
        await self.broadcast_client_count()
        await self.send_current_text(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection and clean up.

        Args:
            websocket: The WebSocket connection to disconnect
        """
        if websocket in self.active_connections:
            del self.active_connections[websocket]
        await self.broadcast_client_count()

    async def broadcast_client_count(self) -> None:
        """Broadcast the current number of connected clients."""
        count = len(self.active_connections)
        await self.broadcast({"type": "clients", "count": count})

    async def broadcast(
        self, message: Dict[str, Any], exclude: Optional[WebSocket] = None
    ) -> None:
        """Broadcast a message to all connected clients except excluded one.

        Args:
            message: The message to broadcast
            exclude: Optional WebSocket to exclude from broadcast
        """
        for connection in self.active_connections:
            if connection != exclude:
                await connection.send_json(message)

    async def send_current_text(self, websocket: WebSocket) -> None:
        """Send current shared text to a specific client.

        Args:
            websocket: The WebSocket connection to send text to
        """
        await websocket.send_json({"type": "content", "data": self.shared_text})

    def update_shared_text(self, text: str) -> None:
        """Update the shared text content.

        Args:
            text: New text content
        """
        self.shared_text = text

    async def _monitor_connection(self, websocket: WebSocket) -> None:
        """Monitor a connection for timeouts and disconnections.

        Args:
            websocket: The WebSocket connection to monitor
        """
        while websocket in self.active_connections:
            await asyncio.sleep(60)
            info = self.active_connections[websocket]

            if time.time() - info.last_active > self.timeout:
                await self.disconnect(websocket)
                break

            if info.pending_pings > 2:
                await self.disconnect(websocket)
                break

            try:
                await websocket.send_json({"type": "ping"})
                info.pending_pings += 1
            except Exception:
                await self.disconnect(websocket)
                break
