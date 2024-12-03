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
from starlette.websockets import WebSocketState

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
    def __init__(self, timeout: int = 3600):  # 1 hour timeout
        """Initialize the WebSocket manager."""
        self.active_connections: Dict[WebSocket, ConnectionInfo] = {}
        self.shared_text: str = ""
        self.timeout = timeout
        self._lock = asyncio.Lock()
        self.ping_interval = 30  # Send ping every 30 seconds

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and initialize it."""
        try:
            await websocket.accept()
            print(f"New WebSocket connection established")

            async with self._lock:
                self.active_connections[websocket] = ConnectionInfo(
                    last_active=time.time(),
                    pending_pings=0
                )
                print(f"Active connections: {len(self.active_connections)}")

            # Start keep-alive task
            asyncio.create_task(self._keep_alive(websocket))
            await self.broadcast_client_count()
            await self.send_current_text(websocket)

        except Exception as e:
            print(f"Error connecting WebSocket: {e}")
            if websocket in self.active_connections:
                await self.disconnect(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection and clean up."""
        try:
            async with self._lock:
                if websocket in self.active_connections:
                    del self.active_connections[websocket]

            # Only try to close if the connection is still open
            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close()
                except RuntimeError as e:
                    # Log but don't raise if we can't close an already closed connection
                    logger.debug(f"Could not close WebSocket (already closed): {e}")
                except Exception as e:
                    logger.error(f"Error closing WebSocket: {e}")

            await self.broadcast_client_count()
        except Exception as e:
            logger.error(f"Error in disconnect cleanup: {e}")

    async def broadcast_client_count(self) -> None:
        """Broadcast the current number of connected clients."""
        try:
            count = len(self.active_connections)
            await self.broadcast({"type": "clients", "count": count})
        except Exception as e:
            logger.error(f"Error broadcasting client count: {e}")

    async def broadcast(self, message: Dict[str, Any], exclude: Optional[WebSocket] = None) -> None:
        """Broadcast a message to all connected clients except excluded one."""
        disconnected = []

        async with self._lock:
            for connection in self.active_connections:
                if connection != exclude:
                    try:
                        if connection.application_state == WebSocketState.CONNECTED:
                            await connection.send_json(message)
                    except WebSocketDisconnect:
                        disconnected.append(connection)
                    except Exception as e:
                        print(f"Error during broadcast: {e}")
                        disconnected.append(connection)

        # Clean up disconnected clients
        for connection in disconnected:
            await self.disconnect(connection)

    async def send_current_text(self, websocket: WebSocket) -> None:
        """Send current shared text to a specific client."""
        try:
            if websocket.application_state == WebSocketState.CONNECTED:
                await websocket.send_json({"type": "content", "data": self.shared_text})
        except Exception as e:
            logger.error(f"Error sending current text: {e}")
            await self.disconnect(websocket)

    def update_shared_text(self, text: str) -> None:
        """Update the shared text content."""
        self.shared_text = text

    async def send_current_text(self, websocket: WebSocket) -> None:
        """Send current shared text to a specific client."""
        try:
            if websocket.application_state == WebSocketState.CONNECTED:
                print(f"Sending current text to {id(websocket)}")
                await websocket.send_json({"type": "content", "data": self.shared_text})
                print(f"Successfully sent current text to {id(websocket)}")
        except Exception as e:
            print(f"Error sending current text: {e}")
            await self.disconnect(websocket)

    async def _monitor_connection(self, websocket: WebSocket) -> None:
        """Monitor a connection for timeouts and disconnections."""
        while True:
            await asyncio.sleep(60)
            try:
                async with self._lock:
                    if websocket not in self.active_connections:
                        break
                    info = self.active_connections[websocket]

                    # Check connection state
                    if websocket.application_state != WebSocketState.CONNECTED:
                        logger.info(f"Connection no longer active: {websocket}")
                        await self.disconnect(websocket)
                        break

                    if time.time() - info.last_active > self.timeout:
                        logger.info(f"Connection timed out: {websocket}")
                        await self.disconnect(websocket)
                        break

                    if info.pending_pings > 2:
                        logger.info(f"Connection unresponsive: {websocket}")
                        await self.disconnect(websocket)
                        break

                    try:
                        if websocket.application_state == WebSocketState.CONNECTED:
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

    async def _keep_alive(self, websocket: WebSocket) -> None:
        """Keep connection alive with periodic pings."""
        while True:
            try:
                await asyncio.sleep(self.ping_interval)

                async with self._lock:
                    if websocket not in self.active_connections:
                        break

                    info = self.active_connections[websocket]

                    # Check connection state
                    if websocket.application_state != WebSocketState.CONNECTED:
                        await self.disconnect(websocket)
                        break

                    # Send ping and update last active time
                    try:
                        await websocket.send_json({"type": "ping"})
                        info.last_active = time.time()
                        info.pending_pings += 1

                        # If too many pending pings, disconnect
                        if info.pending_pings > 3:
                            logger.warning(f"Too many pending pings, disconnecting {websocket}")
                            await self.disconnect(websocket)
                            break

                    except Exception as e:
                        logger.error(f"Error in keep-alive ping: {e}")
                        await self.disconnect(websocket)
                        break

            except Exception as e:
                logger.error(f"Error in keep-alive loop: {e}")
                await self.disconnect(websocket)
                break

    async def handle_pong(self, websocket: WebSocket) -> None:
        """Reset pending pings when pong received."""
        if websocket in self.active_connections:
            self.active_connections[websocket].pending_pings = 0
            self.active_connections[websocket].last_active = time.time()
