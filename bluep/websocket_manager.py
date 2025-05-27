"""WebSocket management module for real-time collaboration."""

import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from .models import ConnectionState, WebSocketMessage
from .process_manager import ProcessManager
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
        self.process_manager = ProcessManager()
        self._process_tasks: Dict[str, asyncio.Task] = {}  # processId -> output monitor task

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

    async def authenticate(self, _: WebSocket, token: str) -> Optional[str]:
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
            session_id = None
            async with self._lock:
                if websocket in self.active_connections:
                    info = self.active_connections.pop(websocket)
                    session_id = info.session_id
                    # Don't remove websocket tokens on disconnect - they should remain valid
                    # for the session lifetime to allow reconnections and page navigation
                    await websocket.close()
                    await self.broadcast_client_count()

            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close(reason=reason)
                except Exception as e:
                    logger.debug(f"Could not close WebSocket: {e}")

            await self.broadcast_client_count()
            
            # Clean up processes for this session
            if session_id:
                await self.process_manager.cleanup_session_processes(session_id)
                
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
        self, _: WebSocket, state: ConnectionState
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

    async def handle_process_spawn(self, websocket: WebSocket, command: str) -> None:
        """Handle request to spawn a new process."""
        if websocket not in self.active_connections:
            return
            
        info = self.active_connections[websocket]
        session_id = info.session_id
        
        # Spawn the process
        process_id = await self.process_manager.spawn_process(
            command=command,
            session_id=session_id
        )
        
        if process_id:
            # Start monitoring process output
            task = asyncio.create_task(self._monitor_process_output(process_id))
            self._process_tasks[process_id] = task
            
            # Send success response
            await websocket.send_json({
                "type": "process-status",
                "processId": process_id,
                "status": "spawned",
                "command": command
            })
        else:
            # Send error response
            await websocket.send_json({
                "type": "error",
                "error": "Failed to spawn process"
            })
            
    async def handle_process_input(self, websocket: WebSocket, process_id: str, data: str) -> None:
        """Handle input to a process."""
        if websocket not in self.active_connections:
            return
            
        info = self.active_connections[websocket]
        
        # Verify process belongs to session
        process_info = self.process_manager.get_process_info(process_id)
        if not process_info or process_info["session_id"] != info.session_id:
            await websocket.send_json({
                "type": "error",
                "error": "Process not found or access denied"
            })
            return
            
        # Write to process
        success = await self.process_manager.write_to_process(process_id, data)
        if not success:
            await websocket.send_json({
                "type": "error",
                "error": "Failed to write to process"
            })
            
    async def handle_process_resize(self, websocket: WebSocket, process_id: str, cols: int, rows: int) -> None:
        """Handle terminal resize for a process."""
        if websocket not in self.active_connections:
            return
            
        info = self.active_connections[websocket]
        
        # Verify process belongs to session
        process_info = self.process_manager.get_process_info(process_id)
        if not process_info or process_info["session_id"] != info.session_id:
            return
            
        await self.process_manager.resize_terminal(process_id, cols, rows)
        
    async def handle_process_terminate(self, websocket: WebSocket, process_id: str) -> None:
        """Handle request to terminate a process."""
        if websocket not in self.active_connections:
            return
            
        info = self.active_connections[websocket]
        
        # Verify process belongs to session
        process_info = self.process_manager.get_process_info(process_id)
        if not process_info or process_info["session_id"] != info.session_id:
            return
            
        # Cancel output monitoring task
        if process_id in self._process_tasks:
            self._process_tasks[process_id].cancel()
            del self._process_tasks[process_id]
            
        # Terminate process
        success = await self.process_manager.terminate_process(process_id)
        
        # Send status update
        await self.broadcast({
            "type": "process-status",
            "processId": process_id,
            "status": "terminated" if success else "error"
        })
        
    async def handle_process_list(self, websocket: WebSocket) -> None:
        """Handle request to list processes for a session."""
        if websocket not in self.active_connections:
            return
            
        info = self.active_connections[websocket]
        processes = self.process_manager.get_session_processes(info.session_id)
        
        await websocket.send_json({
            "type": "process-list",
            "processes": processes
        })
        
    async def _monitor_process_output(self, process_id: str) -> None:
        """Monitor and broadcast process output."""
        try:
            while True:
                # Read output from process
                output = await self.process_manager.read_from_process(process_id)
                
                if output:
                    # Encode output as base64 to handle binary data
                    encoded_output = base64.b64encode(output).decode('utf-8')
                    
                    # Broadcast to all connected clients
                    await self.broadcast({
                        "type": "process-output",
                        "processId": process_id,
                        "outputData": encoded_output
                    })
                    
                # Check if process is still alive
                process_info = self.process_manager.get_process_info(process_id)
                if not process_info or not process_info["is_alive"]:
                    # Send final status
                    await self.broadcast({
                        "type": "process-status",
                        "processId": process_id,
                        "status": "exited"
                    })
                    break
                    
                # Small delay to prevent busy loop
                await asyncio.sleep(0.01)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error monitoring process {process_id}: {e}")
