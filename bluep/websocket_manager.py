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
from .mcp_service_manager import MCPServiceManager
from .external_mcp_registry import ExternalMCPRegistry

logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Information about an active WebSocket connection."""

    session_id: str
    state: ConnectionState
    last_active: float
    pending_pings: int = 0
    message_count: int = 0
    last_message_time: float = 0


class WebSocketManager:
    def __init__(self, session_manager: SessionManager, timeout: int = 3600):
        self.active_connections: Dict[WebSocket, ConnectionInfo] = {}
        self.session_connections: Dict[str, WebSocket] = {}
        self.session_manager = session_manager
        self.shared_text: str = ""
        self.timeout = timeout
        self._lock = asyncio.Lock()
        self.ping_interval = 20  # Send ping every 20 seconds
        self.available_files: Dict[str, Dict[str, Any]] = {}  # fileId -> file metadata
        self.process_manager = ProcessManager()
        self._process_tasks: Dict[str, asyncio.Task] = {}  # processId -> output monitor task
        
        # Initialize MCP service manager
        from pathlib import Path
        mcp_services_dir = Path(__file__).parent.parent / "mcp-services"
        self.mcp_service_manager = MCPServiceManager(mcp_services_dir, self.process_manager)
        
        # Initialize external MCP registry
        self.external_mcp_registry = ExternalMCPRegistry()
        
        # MCP routing information
        self.mcp_service_clients: Dict[str, str] = {}  # service_name -> hosting_session_id
        self.mcp_client_proxies: Dict[str, Dict[str, Any]] = {}  # session_id -> proxy info
        self.mcp_external_connections: Dict[str, Any] = {}  # service_name -> aiohttp session/websocket

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
            logger.info(f"WebSocket connection attempt with token {token[:8]}...")
            logger.debug(f"Available tokens: {list(self.session_manager.websocket_tokens.keys())}")

            if token not in self.session_manager.websocket_tokens:
                logger.error(f"Token {token[:8]}... not found in valid tokens")
                return

            session_id = self.session_manager.websocket_tokens[token]
            logger.info(f"Found session_id: {session_id} for token {token[:8]}...")

            # Check if session is still valid
            session = self.session_manager.get_session(session_id)
            if not session:
                logger.error(f"Session {session_id} not found or expired")
                return

            await websocket.accept()
            logger.info(f"WebSocket accepted for session {session_id}")

            self.active_connections[websocket] = ConnectionInfo(
                session_id=session_id,
                state=ConnectionState.CONNECTED,
                last_active=time.time(),
            )

            # Start keep-alive task
            asyncio.create_task(self._keep_alive(websocket))
            logger.info(f"Started keep-alive task for session {session_id}")

            await self.broadcast_client_count()
            await self.send_current_text(websocket)

        except Exception as e:
            logger.error(f"Connection error: {e}", exc_info=True)

    async def disconnect(self, websocket: WebSocket, reason: str = "unknown") -> None:
        try:
            session_id = None
            async with self._lock:
                if websocket in self.active_connections:
                    info = self.active_connections.pop(websocket)
                    session_id = info.session_id
                    logger.info(f"Disconnecting WebSocket for session {session_id}, reason: {reason}")
                    # Don't remove websocket tokens on disconnect - they should remain valid
                    # for the session lifetime to allow reconnections and page navigation

            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close(reason=reason)
                except Exception as e:
                    logger.debug(f"Could not close WebSocket: {e}")

            await self.broadcast_client_count()
            
            # Don't clean up processes on disconnect - only on explicit termination
            # This allows reconnection to existing processes
            # Processes will be cleaned up by the process manager's monitor
            
            if session_id:
                logger.info(f"WebSocket disconnected for session {session_id}, active connections: {len(self.active_connections)}")
                
                # Check if this session was hosting any external MCP services
                services_to_remove = []
                for name, service in self.external_mcp_registry.list_services().items():
                    if service.session_id == session_id:
                        services_to_remove.append(name)
                
                # Remove external services registered by this session
                for service_name in services_to_remove:
                    logger.info(f"Removing external service '{service_name}' due to session disconnect")
                    self.external_mcp_registry.unregister_service(service_name)
                    
                    # Notify all clients about service removal
                    await self.broadcast({
                        "type": "mcp-service-status",
                        "serviceName": service_name,
                        "status": "stopped",
                        "serviceType": "external"
                    })
                
        except Exception as e:
            logger.error(f"Error in disconnect cleanup: {e}", exc_info=True)

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
    
    def _get_session_id_for_websocket(self, websocket: WebSocket) -> Optional[str]:
        """Get the session ID associated with a WebSocket connection."""
        info = self.active_connections.get(websocket)
        return info.session_id if info else None
    
    async def _broadcast_to_session(
        self, session_id: str, message: Dict[str, Any]
    ) -> None:
        """Broadcast a message only to connections in a specific session."""
        disconnected = []
        connections_to_broadcast = []
        
        # Collect connections for this session
        async with self._lock:
            for connection, info in self.active_connections.items():
                if info.session_id == session_id and info.state == ConnectionState.CONNECTED:
                    connections_to_broadcast.append(connection)
        
        # Send messages without holding the lock
        for connection in connections_to_broadcast:
            try:
                if connection.application_state == WebSocketState.CONNECTED:
                    await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error(f"Error during session broadcast: {e}")
                disconnected.append(connection)
        
        # Handle disconnections
        for connection in disconnected:
            await self.disconnect(connection, reason="session_broadcast_error")

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
            logger.info(f"Broadcasting client count: {connected_count} active connections")
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
        logger.info(f"Updating shared text, length: {len(text)}")
        async with self._lock:
            self.shared_text = text

    async def handle_pong(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self.active_connections:
                info = self.active_connections[websocket]
                info.pending_pings = 0
                info.last_active = time.time()
                logger.debug(f"Received pong from session {info.session_id}, resetting pending_pings")

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

                # Check connection state and get info while holding lock
                should_disconnect = False
                disconnect_reason = ""
                session_id = None
                
                async with self._lock:
                    if websocket not in self.active_connections:
                        break

                    info = self.active_connections[websocket]
                    session_id = info.session_id

                    if info.state != ConnectionState.CONNECTED:
                        break

                    # Check if we have too many pending pings BEFORE sending another
                    if info.pending_pings >= 3:
                        logger.warning(f"Too many pending pings ({info.pending_pings}) for session {session_id}, disconnecting")
                        should_disconnect = True
                        disconnect_reason = "ping_timeout"
                    else:
                        # Increment pending pings before sending
                        info.pending_pings += 1
                
                # Handle disconnection outside of lock
                if should_disconnect:
                    await self.disconnect(websocket, reason=disconnect_reason)
                    break
                
                # Check WebSocket state outside of lock
                if websocket.application_state != WebSocketState.CONNECTED:
                    logger.info(f"WebSocket not connected for session {session_id}, disconnecting")
                    await self.disconnect(websocket, reason="disconnected")
                    break
                
                # Send ping outside of lock to avoid blocking
                try:
                    await websocket.send_json({"type": "ping"})
                    logger.debug(f"Sent ping to session {session_id}")
                except Exception as e:
                    logger.error(f"Error sending ping to session {session_id}: {e}")
                    await self.disconnect(websocket, reason="ping_error")
                    break

            except Exception as e:
                logger.error(f"Error in keep-alive loop: {e}", exc_info=True)
                await self.disconnect(websocket, reason="keepalive_error")
                break
    
    def _check_rate_limit(self, websocket: WebSocket, message_type: str) -> bool:
        """Check if the connection is within rate limits."""
        if websocket not in self.active_connections:
            return False
            
        info = self.active_connections[websocket]
        current_time = time.time()
        
        # Reset counter every minute
        if current_time - info.last_message_time > 60:
            info.message_count = 0
            info.last_message_time = current_time
        
        # Different limits for different message types
        limits = {
            "process-spawn": 20,  # 20 process spawns per minute
            "process-input": 1000,  # 1000 inputs per minute
            "content": 100,  # 100 content updates per minute
            "file-announce": 10,  # 10 file announcements per minute
        }
        
        limit = limits.get(message_type, 50)  # Default 50 messages per minute
        
        if info.message_count >= limit:
            logger.warning(f"Rate limit exceeded for {message_type} from session {info.session_id}")
            return False
            
        info.message_count += 1
        return True

    async def handle_process_spawn(self, websocket: WebSocket, command: str) -> None:
        """Handle request to spawn a new process."""
        if websocket not in self.active_connections:
            return
            
        # Rate limiting
        if not self._check_rate_limit(websocket, "process-spawn"):
            await websocket.send_json({
                "type": "error",
                "error": "Rate limit exceeded: Maximum 20 terminals per minute. Please wait before creating more."
            })
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
            logger.info(f"Successfully spawned process {process_id} for command: {command}")
        else:
            # Get current process count for better error message
            current_processes = self.process_manager.get_session_processes(session_id)
            alive_count = sum(1 for p in current_processes if p.get("is_alive", False))
            
            error_msg = f"Failed to spawn process. You have {alive_count} active terminals."
            if alive_count >= 5:
                error_msg = f"Terminal limit reached: You have {alive_count} active terminals (max 5). Close some terminals before creating new ones."
            
            # Send error response
            await websocket.send_json({
                "type": "error",
                "error": error_msg
            })
            logger.warning(f"Failed to spawn process for session {session_id}: {error_msg}")
            
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
            
        # Debug: log all active monitors
        logger.info(f"Active output monitors: {list(self._process_tasks.keys())}")
        
        # Check if process has an active output monitor (critical for seeing responses)
        if process_id not in self._process_tasks:
            logger.warning(f"No output monitor for process {process_id} - starting one")
            # Start the monitor
            task = asyncio.create_task(self._monitor_process_output(process_id))
            self._process_tasks[process_id] = task
        else:
            # Check if the task is still running
            task = self._process_tasks[process_id]
            if task.done():
                logger.error(f"Output monitor for {process_id} is done! Exception: {task.exception() if not task.cancelled() else 'Cancelled'}")
                # Restart it
                logger.info(f"Restarting dead output monitor for {process_id}")
                task = asyncio.create_task(self._monitor_process_output(process_id))
                self._process_tasks[process_id] = task
            
        # Write to process
        logger.info(f"Writing to process {process_id}: {repr(data)}")
        success = await self.process_manager.write_to_process(process_id, data)
        if not success:
            logger.error(f"Write failed for process {process_id}")
            await websocket.send_json({
                "type": "error",
                "error": "Failed to write to process"
            })
        else:
            logger.info(f"Write successful for process {process_id}")
            
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
            logger.info(f"Cancelling output monitor for process {process_id}")
            task = self._process_tasks.pop(process_id, None)
            if task and not task.done():
                task.cancel()
                # Wait for task to complete cancellation with timeout
                try:
                    await asyncio.wait_for(asyncio.shield(task), timeout=0.5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    logger.debug(f"Output monitor cancellation completed for {process_id}")
                except Exception as e:
                    logger.error(f"Error during output monitor cancellation for {process_id}: {e}")
            logger.info(f"Output monitor cancelled for process {process_id}")
            
        # Terminate process
        success = await self.process_manager.terminate_process(process_id)
        
        # Send status update only to the session
        await self._broadcast_to_session(info.session_id, {
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
        """Monitor and broadcast process output to authorized sessions only."""
        logger.info(f"Starting output monitor for process {process_id}")
        try:
            # Get process info to determine session
            process_info = self.process_manager.get_process_info(process_id)
            if not process_info:
                logger.warning(f"Process {process_id} not found when starting monitor")
                return
                
            session_id = process_info.get("session_id")
            if not session_id:
                logger.error(f"Process {process_id} has no session_id")
                return
            
            loop_count = 0
            last_successful_read = time.time()
            
            while True:
                loop_count += 1
                if loop_count % 100 == 0:  # Log every 100 iterations
                    logger.debug(f"Output monitor for {process_id} still running (iteration {loop_count})")
                    # Check if we haven't read anything in a while
                    time_since_last_read = time.time() - last_successful_read
                    if time_since_last_read > 5:
                        logger.warning(f"No output from {process_id} for {time_since_last_read:.1f} seconds")
                        
                        # If we haven't read anything for 10 seconds, try to recover
                        if time_since_last_read > 10:
                            logger.error(f"Output monitor for {process_id} appears stuck, attempting recovery")
                            
                            # Check if the process is still alive
                            process_info = self.process_manager.get_process_info(process_id)
                            if process_info and process_info["is_alive"]:
                                # Try to write a null byte to wake up the PTY
                                try:
                                    await self.process_manager.write_to_process(process_id, "\x00")
                                    logger.info(f"Sent null byte to {process_id} to wake up PTY")
                                except Exception as e:
                                    logger.error(f"Failed to send wake-up byte: {e}")
                                    
                                # Reset the timer to avoid spamming
                                last_successful_read = time.time() - 8  # Will trigger again in 2 seconds
                    
                # Read output from process
                try:
                    output = await self.process_manager.read_from_process(process_id)
                except Exception as e:
                    logger.error(f"Exception reading from process {process_id}: {e}", exc_info=True)
                    output = None
                
                if output:
                    last_successful_read = time.time()
                    logger.debug(f"Got output from {process_id}: {len(output)} bytes")
                    # Encode output as base64 to handle binary data
                    encoded_output = base64.b64encode(output).decode('utf-8')
                    
                    # CRITICAL: Only broadcast to connections in the same session
                    await self._broadcast_to_session(session_id, {
                        "type": "process-output",
                        "processId": process_id,
                        "outputData": encoded_output
                    })
                    
                # Check if process is still alive
                process_info = self.process_manager.get_process_info(process_id)
                if not process_info or not process_info["is_alive"]:
                    # Send final status only to the session
                    await self._broadcast_to_session(session_id, {
                        "type": "process-status",
                        "processId": process_id,
                        "status": "exited"
                    })
                    # Clean up the task from our tracking
                    self._process_tasks.pop(process_id, None)
                    logger.info(f"Output monitor ending for process {process_id} - process exited")
                    break
                    
                # Small delay to prevent busy loop and ensure fair scheduling
                await asyncio.sleep(0.01)
                
                # Explicitly yield to other coroutines every few iterations
                if loop_count % 10 == 0:
                    await asyncio.sleep(0)
                
        except asyncio.CancelledError:
            # Clean up task from tracking on cancellation
            self._process_tasks.pop(process_id, None)
            logger.info(f"Output monitor cancelled for process {process_id}")
            raise
        except Exception as e:
            logger.error(f"Error monitoring process {process_id}: {e}", exc_info=True)
            # Clean up task from tracking on error
            self._process_tasks.pop(process_id, None)
    
    async def handle_mcp_service_list(self, websocket: WebSocket) -> None:
        """Handle request to list available MCP services."""
        logger.info("Handling MCP service list request")
        try:
            # Discover local services
            await self.mcp_service_manager.discover_services()
            
            services = []
            
            # Add local services
            for service in self.mcp_service_manager.list_services():
                services.append({
                    "name": service.name,
                    "status": service.status.value,
                    "port": service.port,
                    "hostingSession": self.mcp_service_clients.get(service.name),
                    "type": "local"
                })
            
            # Add external services
            for name, ext_service in self.external_mcp_registry.list_services().items():
                status = "running" if ext_service.active else "stopped"
                services.append({
                    "name": name,
                    "status": status,
                    "port": None,  # External services don't have local ports
                    "hostingSession": ext_service.session_id,
                    "type": "external",
                    "url": ext_service.url,
                    "description": ext_service.description
                })
            
            logger.info(f"Returning {len(services)} services (local + external)")
            
            await websocket.send_json({
                "type": "mcp-service-list",
                "mcpServices": services
            })
        except Exception as e:
            logger.error(f"Error listing MCP services: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to list MCP services: {str(e)}"
            })
    
    async def handle_mcp_service_start(self, websocket: WebSocket, service_name: str) -> None:
        """Handle request to start an MCP service."""
        try:
            session_id = self._get_session_id_for_websocket(websocket)
            if not session_id:
                raise ValueError("No session found")
            
            # Start the service
            process_info = await self.mcp_service_manager.start_service(service_name, session_id)
            
            # Track which session is hosting this service
            self.mcp_service_clients[service_name] = session_id
            
            # Get service info
            service = self.mcp_service_manager.get_service_info(service_name)
            
            # Notify all clients about service availability
            await self.broadcast({
                "type": "mcp-service-status",
                "serviceName": service_name,
                "status": "running",
                "port": service.port,
                "hostingSession": session_id
            })
            
            # Start monitoring the MCP service process
            task = asyncio.create_task(self._monitor_process_output(process_info.process_id, session_id))
            self._process_tasks[process_info.process_id] = task
            
        except Exception as e:
            logger.error(f"Error starting MCP service {service_name}: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to start MCP service: {str(e)}"
            })
    
    async def handle_mcp_service_stop(self, websocket: WebSocket, service_name: str) -> None:
        """Handle request to stop an MCP service."""
        try:
            session_id = self._get_session_id_for_websocket(websocket)
            if not session_id:
                raise ValueError("No session found")
            
            # Check if this session is hosting the service
            hosting_session = self.mcp_service_clients.get(service_name)
            if hosting_session != session_id:
                raise ValueError("Service is hosted by another session")
            
            # Stop the service
            await self.mcp_service_manager.stop_service(service_name)
            
            # Remove tracking
            self.mcp_service_clients.pop(service_name, None)
            
            # Notify all clients
            await self.broadcast({
                "type": "mcp-service-status",
                "serviceName": service_name,
                "status": "stopped"
            })
            
        except Exception as e:
            logger.error(f"Error stopping MCP service {service_name}: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to stop MCP service: {str(e)}"
            })
    
    async def handle_mcp_request(self, websocket: WebSocket, msg: WebSocketMessage) -> None:
        """Route MCP protocol requests between clients."""
        try:
            if not msg.serviceName or not msg.mcpPayload:
                raise ValueError("Missing service name or payload")
            
            session_id = self._get_session_id_for_websocket(websocket)
            if not session_id:
                raise ValueError("No session found")
            
            # Check if this is an external service
            ext_service = self.external_mcp_registry.get_service(msg.serviceName)
            if ext_service:
                # Route to external service via HTTP
                await self._route_to_external_mcp(websocket, msg, ext_service)
                return
            
            # Find which session is hosting this service
            hosting_session = self.mcp_service_clients.get(msg.serviceName)
            if not hosting_session:
                raise ValueError(f"Service {msg.serviceName} is not running")
            
            # Route the request to the hosting session
            message = {
                "type": "mcp-request",
                "serviceName": msg.serviceName,
                "mcpPayload": msg.mcpPayload,
                "targetClient": session_id  # So we know where to send response
            }
            
            await self._broadcast_to_session(hosting_session, message)
            
        except Exception as e:
            logger.error(f"Error routing MCP request: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to route MCP request: {str(e)}"
            })
    
    async def handle_mcp_response(self, websocket: WebSocket, msg: WebSocketMessage) -> None:
        """Route MCP protocol responses back to requesting clients."""
        try:
            if not msg.targetClient or not msg.mcpPayload:
                raise ValueError("Missing target client or payload")
            
            # Route the response to the requesting client
            message = {
                "type": "mcp-response",
                "serviceName": msg.serviceName,
                "mcpPayload": msg.mcpPayload
            }
            
            await self._broadcast_to_session(msg.targetClient, message)
            
        except Exception as e:
            logger.error(f"Error routing MCP response: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to route MCP response: {str(e)}"
            })
    
    async def _route_to_external_mcp(self, websocket: WebSocket, msg: WebSocketMessage, ext_service) -> None:
        """Route MCP request to an external service via HTTP."""
        try:
            import aiohttp
            
            # Create session if needed
            if msg.serviceName not in self.mcp_external_connections:
                self.mcp_external_connections[msg.serviceName] = aiohttp.ClientSession()
            
            session = self.mcp_external_connections[msg.serviceName]
            
            # Forward the request
            async with session.post(ext_service.url, json=msg.mcpPayload) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    # Send response back to client
                    await websocket.send_json({
                        "type": "mcp-response",
                        "serviceName": msg.serviceName,
                        "mcpPayload": result
                    })
                else:
                    error_text = await response.text()
                    raise Exception(f"External service error: {response.status} - {error_text}")
                    
        except Exception as e:
            logger.error(f"Error routing to external MCP service: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to reach external service: {str(e)}"
            })
    
    async def handle_mcp_service_register(self, websocket: WebSocket, msg: WebSocketMessage) -> None:
        """Handle registration of an external MCP service."""
        try:
            session_id = self._get_session_id_for_websocket(websocket)
            if not session_id:
                raise ValueError("No session found")
            
            # Extract registration details
            service_name = msg.serviceName
            service_url = msg.serviceUrl
            description = msg.description or ""
            
            if not service_name or not service_url:
                raise ValueError("Service name and URL are required")
            
            # Register the external service
            success = self.external_mcp_registry.register_service(
                name=service_name,
                url=service_url,
                session_id=session_id,
                description=description
            )
            
            if success:
                # Notify all clients about the new service
                await self.broadcast({
                    "type": "mcp-service-status",
                    "serviceName": service_name,
                    "status": "running",
                    "serviceType": "external",
                    "url": service_url,
                    "hostingSession": session_id,
                    "description": description
                })
                
                await websocket.send_json({
                    "type": "mcp-service-registered",
                    "serviceName": service_name,
                    "success": True
                })
            else:
                raise Exception("Failed to register service")
                
        except Exception as e:
            logger.error(f"Error registering external MCP service: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to register external service: {str(e)}"
            })
    
    async def handle_mcp_service_unregister(self, websocket: WebSocket, msg: WebSocketMessage) -> None:
        """Handle unregistration of an external MCP service."""
        try:
            session_id = self._get_session_id_for_websocket(websocket)
            if not session_id:
                raise ValueError("No session found")
            
            service_name = msg.serviceName
            if not service_name:
                raise ValueError("Service name is required")
            
            # Check if service exists and belongs to this session
            service = self.external_mcp_registry.get_service(service_name)
            if not service:
                raise ValueError(f"Service '{service_name}' not found")
            
            if service.session_id != session_id:
                raise ValueError("You can only unregister services you registered")
            
            # Unregister the service
            success = self.external_mcp_registry.unregister_service(service_name)
            
            if success:
                # Notify all clients about service removal
                await self.broadcast({
                    "type": "mcp-service-status",
                    "serviceName": service_name,
                    "status": "stopped",
                    "serviceType": "external"
                })
                
                await websocket.send_json({
                    "type": "mcp-service-unregistered",
                    "serviceName": service_name,
                    "success": True
                })
            else:
                raise Exception("Failed to unregister service")
                
        except Exception as e:
            logger.error(f"Error unregistering external MCP service: {e}")
            await websocket.send_json({
                "type": "error",
                "error": f"Failed to unregister service: {str(e)}"
            })
