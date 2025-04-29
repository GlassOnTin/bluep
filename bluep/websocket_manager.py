"""WebSocket management module for real-time collaboration."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, Set, List
from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from .models import ConnectionState, WebSocketMessage
from .session_manager import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Information about an active WebSocket connection."""

    session_id: str
    state: ConnectionState
    last_active: float
    pending_pings: int = 0


class WebSocketManager:
    def __init__(self, session_manager: SessionManager, timeout: int = 3600):
        self.active_connections: Dict[WebSocket, ConnectionInfo] = {}
        self.session_connections: Dict[str, WebSocket] = {}
        self.session_manager = session_manager
        self.shared_text: str = ""
        self.timeout = timeout
        self._lock = asyncio.Lock()
        self.ping_interval = 60
        self.available_files: Dict[str, Dict[str, Any]] = {}  # fileId -> file metadata

    async def transition_state(
        self,
        websocket: WebSocket,
        new_state: ConnectionState,
        session_id: Optional[str] = None,
    ) -> bool:
        async with self._lock:
            if (
                websocket not in self.active_connections
                and new_state != ConnectionState.INITIALIZING
            ):
                return False

            if websocket in self.active_connections:
                info = self.active_connections[websocket]
                current_state = info.state
                session_id = info.session_id
            else:
                if not session_id:
                    return False
                current_state = None

            if not self._is_valid_transition(current_state, new_state):
                return False

            if new_state == ConnectionState.INITIALIZING:
                self.active_connections[websocket] = ConnectionInfo(
                    session_id=session_id, state=new_state, last_active=time.time()
                )
            else:
                self.active_connections[websocket].state = new_state

            if session_id:
                session = self.session_manager.sessions.get(session_id)
                if session:
                    session.connection_state = new_state

            await self._broadcast_state_change(websocket, new_state)
            return True

    async def authenticate(self, websocket: WebSocket, token: str) -> Optional[str]:
        session_id = self.session_manager.validate_websocket_token(token)
        if not session_id:
            return None

        session = self.session_manager.get_session(session_id)
        if not session:
            return None

        return session_id

    async def connect(self, websocket: WebSocket, token: str) -> None:
        try:
            logger.debug(f"Checking token {token}")
            logger.debug(f"Available tokens: {self.session_manager.websocket_tokens}")

            if token not in self.session_manager.websocket_tokens:
                logger.error(f"Token {token} not found in valid tokens")
                return

            session_id = self.session_manager.websocket_tokens[token]
            logger.debug(f"Found session_id: {session_id}")

            await websocket.accept()

            self.active_connections[websocket] = ConnectionInfo(
                session_id=session_id,
                state=ConnectionState.CONNECTED,
                last_active=time.time(),
            )

            await self.broadcast_client_count()
            await self.send_current_text(websocket)

        except Exception as e:
            logger.error(f"Connection error: {e}")

    async def disconnect(self, websocket: WebSocket, reason: str = "unknown") -> None:
        try:
            async with self._lock:
                if websocket in self.active_connections:
                    info = self.active_connections.pop(websocket)
                    if info.session_id:
                        # Clean up token
                        tokens_to_remove = [
                            k
                            for k, v in self.session_manager.websocket_tokens.items()
                            if v == info.session_id
                        ]
                        for token in tokens_to_remove:
                            self.session_manager.websocket_tokens.pop(token)
                    await websocket.close()
                    await self.broadcast_client_count()

            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close(reason=reason)
                except Exception as e:
                    logger.debug(f"Could not close WebSocket: {e}")

            await self.broadcast_client_count()
        except Exception as e:
            logger.error(f"Error in disconnect cleanup: {e}")

    async def broadcast(
        self, message: Dict[str, Any], exclude: Optional[WebSocket] = None
    ) -> None:
        disconnected = []
        connections_to_broadcast = []

        # First collect all connections while holding the lock
        async with self._lock:
            for connection, info in self.active_connections.items():
                if connection != exclude and info.state == ConnectionState.CONNECTED:
                    connections_to_broadcast.append(connection)

        # Then send messages without holding the lock to prevent deadlocks
        for connection in connections_to_broadcast:
            try:
                if connection.application_state == WebSocketState.CONNECTED:
                    await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error(f"Error during broadcast: {e}")
                disconnected.append(connection)

        # Finally handle disconnections
        for connection in disconnected:
            await self.disconnect(connection, reason="broadcast_error")

    async def announce_file(
        self,
        file_id: str,
        file_name: str,
        file_size: int,
        file_type: str,
        source_websocket: WebSocket,
    ) -> None:
        """Announce a new file available for download to all clients"""
        # Store file metadata
        async with self._lock:
            # Find the source connection info
            for conn, info in self.active_connections.items():
                if conn == source_websocket:
                    source_id = info.session_id
                    break
            else:
                logger.error("Source connection not found")
                return

            # Store file metadata
            self.available_files[file_id] = {
                "fileName": file_name,
                "fileSize": file_size,
                "fileType": file_type,
                "sourceId": source_id,
                "timestamp": time.time(),
            }

        # Broadcast file announcement to all clients
        await self.broadcast(
            {
                "type": "file-announce",
                "fileId": file_id,
                "fileName": file_name,
                "fileSize": file_size,
                "fileType": file_type,
            },
            exclude=source_websocket,
        )

    async def handle_file_request(self, file_id: str, requester: WebSocket) -> None:
        """Handle a client requesting a file download"""
        # Check if the file exists
        if file_id not in self.available_files:
            await requester.send_json({"type": "error", "error": "File not found"})
            return

        # Find the source connection
        source_websocket = None
        source_id = self.available_files[file_id]["sourceId"]

        async with self._lock:
            for conn, info in self.active_connections.items():
                if info.session_id == source_id:
                    source_websocket = conn
                    break

        if not source_websocket:
            # Source client disconnected
            await requester.send_json(
                {"type": "error", "error": "File source disconnected"}
            )
            # Clean up this file
            self.available_files.pop(file_id, None)
            return

        # Forward the request to the source
        try:
            await source_websocket.send_json(
                {"type": "file-request", "fileId": file_id}
            )
        except Exception as e:
            logger.error(f"Error requesting file from source: {e}")
            await requester.send_json(
                {"type": "error", "error": "Failed to request file from source"}
            )

    async def broadcast_client_count(self) -> None:
        try:
            # Get count while holding lock
            async with self._lock:
                connected_count = sum(
                    1
                    for info in self.active_connections.values()
                    if info.state == ConnectionState.CONNECTED
                )
            # Broadcast without holding lock to prevent deadlocks
            await self.broadcast({"type": "clients", "count": connected_count})
        except Exception as e:
            logger.error(f"Error broadcasting client count: {e}")

    async def send_current_text(self, websocket: WebSocket) -> None:
        try:
            if websocket.application_state == WebSocketState.CONNECTED:
                # Get current text while holding the lock
                async with self._lock:
                    current_text = self.shared_text

                # Send without holding the lock to prevent deadlocks
                # Enable encryption for content messages
                await websocket.send_json(
                    {
                        "type": "content",
                        "data": current_text,
                        "encrypted": True,  # Mark as encrypted so clients will decrypt
                    }
                )
        except Exception as e:
            logger.error(f"Error sending current text: {e}")
            await self.disconnect(websocket, reason="send_error")

    async def update_shared_text(self, text: str) -> None:
        async with self._lock:
            self.shared_text = text

    async def handle_pong(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections[websocket].pending_pings = 0
                self.active_connections[websocket].last_active = time.time()

    def _is_valid_transition(
        self, current: Optional[ConnectionState], new: ConnectionState
    ) -> bool:
        if current is None:
            return new == ConnectionState.INITIALIZING

        valid_transitions = {
            ConnectionState.INITIALIZING: {ConnectionState.AUTHENTICATING},
            ConnectionState.AUTHENTICATING: {
                ConnectionState.CONNECTED,
                ConnectionState.DISCONNECTING,
            },
            ConnectionState.CONNECTED: {ConnectionState.DISCONNECTING},
            ConnectionState.DISCONNECTING: {ConnectionState.CLOSED},
            ConnectionState.CLOSED: {ConnectionState.INITIALIZING},
        }

        return new in valid_transitions.get(current, set())

    async def _broadcast_state_change(
        self, websocket: WebSocket, state: ConnectionState
    ) -> None:
        msg = WebSocketMessage(type="state", state=state.value)
        await self.broadcast(msg.model_dump(exclude_none=True))

    async def _keep_alive(self, websocket: WebSocket) -> None:
        while True:
            try:
                await asyncio.sleep(self.ping_interval)

                async with self._lock:
                    if websocket not in self.active_connections:
                        break

                    info = self.active_connections[websocket]

                    if websocket.application_state != WebSocketState.CONNECTED:
                        await self.disconnect(websocket, reason="disconnected")
                        break

                    if info.state != ConnectionState.CONNECTED:
                        break

                    try:
                        await websocket.send_json({"type": "ping"})
                        info.last_active = time.time()
                        info.pending_pings += 1

                        if info.pending_pings > 3:
                            logger.warning(f"Too many pending pings, disconnecting")
                            await self.disconnect(websocket, reason="ping_timeout")
                            break

                    except Exception as e:
                        logger.error(f"Error in keep-alive ping: {e}")
                        await self.disconnect(websocket, reason="ping_error")
                        break

            except Exception as e:
                logger.error(f"Error in keep-alive loop: {e}")
                await self.disconnect(websocket, reason="keepalive_error")
                break
