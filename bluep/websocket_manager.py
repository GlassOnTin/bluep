"""WebSocket management module for real-time collaboration.

This module handles WebSocket connections, broadcasts, and shared text state
for the collaborative text editor functionality.
"""

from __future__ import annotations
import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect

# Configure logging
logger = logging.getLogger(__name__)


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
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and initialize it.

        Args:
            websocket: The WebSocket connection to initialize
        """
        try:
            await websocket.accept()
            async with self._lock:
                self.active_connections[websocket] = ConnectionInfo(
                    last_active=time.time(), pending_pings=0
                )
            asyncio.create_task(self._monitor_connection(websocket))
            await self.broadcast_client_count()
            await self.send_current_text(websocket)
        except Exception as e:
            logger.error(f"Error connecting WebSocket: {e}")
            if websocket in self.active_connections:
                await self.disconnect(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection and clean up.

        Args:
            websocket: The WebSocket connection to disconnect
        """
        try:
            async with self._lock:
                if websocket in self.active_connections:
                    del self.active_connections[websocket]
            await websocket.close()
            await self.broadcast_client_count()
        except Exception as e:
            logger.error(f"Error disconnecting WebSocket: {e}")

    async def broadcast_client_count(self) -> None:
        """Broadcast the current number of connected clients."""
        try:
            count = len(self.active_connections)
            await self.broadcast({"type": "clients", "count": count})
        except Exception as e:
            logger.error(f"Error broadcasting client count: {e}")

    async def broadcast(
        self, message: Dict[str, Any], exclude: Optional[WebSocket] = None
    ) -> None:
        """Broadcast a message to all connected clients except excluded one.

        Args:
            message: The message to broadcast
            exclude: Optional WebSocket to exclude from broadcast
        """
        disconnected = []
        async with self._lock:
            for connection in self.active_connections:
                if connection != exclude:
                    try:
                        await connection.send_json(message)
                    except WebSocketDisconnect:
                        disconnected.append(connection)
                    except Exception as e:
                        logger.error(f"Error broadcasting message: {e}")
                        disconnected.append(connection)

        # Clean up disconnected clients
        for connection in disconnected:
            await self.disconnect(connection)

    async def send_current_text(self, websocket: WebSocket) -> None:
        """Send current shared text to a specific client.

        Args:
            websocket: The WebSocket connection to send text to
        """
        try:
            await websocket.send_json({"type": "content", "data": self.shared_text})
        except Exception as e:
            logger.error(f"Error sending current text: {e}")
            await self.disconnect(websocket)

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
        while True:
            await asyncio.sleep(60)
            try:
                async with self._lock:
                    if websocket not in self.active_connections:
                        break
                    info = self.active_connections[websocket]

                if time.time() - info.last_active > self.timeout:
                    logger.info(f"Connection timed out: {websocket}")
                    await self.disconnect(websocket)
                    break

                if info.pending_pings > 2:
                    logger.info(f"Connection unresponsive: {websocket}")
                    await self.disconnect(websocket)
                    break

                try:
                    await websocket.send_json({"type": "ping"})
                    info.pending_pings += 1
                except Exception as e:
                    logger.error(f"Error sending ping: {e}")
                    await self.disconnect(websocket)
                    break

            except Exception as e:
                logger.error(f"Error monitoring connection: {e}")
                await self.disconnect(websocket)
                break
