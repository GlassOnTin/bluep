"""MCP Client Proxy for exposing remote MCP services locally."""

import asyncio
import json
import logging
from typing import Dict, Optional, Any
import websockets
from aiohttp import web
import aiohttp

logger = logging.getLogger(__name__)


class MCPClientProxy:
    """Proxy that exposes remote MCP services on local ports."""
    
    def __init__(self, bluep_ws_url: str, session_token: str):
        """Initialize MCP client proxy.
        
        Args:
            bluep_ws_url: WebSocket URL of the bluep server
            session_token: Session token for authentication
        """
        self.bluep_ws_url = bluep_ws_url
        self.session_token = session_token
        self.ws_connection: Optional[websockets.WebSocketClientProtocol] = None
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.request_counter = 0
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        
    async def connect(self) -> None:
        """Connect to bluep WebSocket server."""
        headers = {
            "Cookie": f"session={self.session_token}"
        }
        self.ws_connection = await websockets.connect(
            self.bluep_ws_url,
            extra_headers=headers
        )
        
        # Start message handler
        asyncio.create_task(self._handle_messages())
        
    async def _handle_messages(self) -> None:
        """Handle incoming WebSocket messages from bluep."""
        try:
            async for message in self.ws_connection:
                try:
                    data = json.loads(message)
                    if data.get("type") == "mcp-response":
                        # Route response to waiting request
                        request_id = data.get("mcpPayload", {}).get("id")
                        if request_id and request_id in self.pending_requests:
                            future = self.pending_requests.pop(request_id)
                            future.set_result(data["mcpPayload"])
                            
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection closed")
        except Exception as e:
            logger.error(f"Error in message handler: {e}")
            
    async def forward_mcp_request(self, service_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Forward an MCP request to the remote service.
        
        Args:
            service_name: Name of the MCP service
            payload: MCP protocol payload
            
        Returns:
            MCP response payload
        """
        if not self.ws_connection:
            raise RuntimeError("Not connected to bluep server")
            
        # Generate request ID if not present
        if "id" not in payload:
            self.request_counter += 1
            payload["id"] = f"req_{self.request_counter}"
            
        request_id = payload["id"]
        
        # Create future for response
        future = asyncio.Future()
        self.pending_requests[request_id] = future
        
        # Send request via WebSocket
        message = {
            "type": "mcp-request",
            "serviceName": service_name,
            "mcpPayload": payload
        }
        
        await self.ws_connection.send(json.dumps(message))
        
        # Wait for response with timeout
        try:
            response = await asyncio.wait_for(future, timeout=30.0)
            return response
        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise RuntimeError("MCP request timed out")
            
    async def start_http_proxy(self, service_name: str, local_port: int) -> None:
        """Start HTTP proxy server for an MCP service.
        
        Args:
            service_name: Name of the MCP service to proxy
            local_port: Local port to listen on
        """
        async def handle_request(request: web.Request) -> web.Response:
            """Handle HTTP requests and forward as MCP."""
            try:
                # Parse request body
                body = await request.text()
                payload = json.loads(body) if body else {}
                
                # Forward as MCP request
                response = await self.forward_mcp_request(service_name, payload)
                
                return web.json_response(response)
                
            except Exception as e:
                logger.error(f"Error handling request: {e}")
                return web.json_response(
                    {"error": str(e)},
                    status=500
                )
                
        # Add route
        self.app.router.add_route('*', '/{path:.*}', handle_request)
        
        # Start server
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, 'localhost', local_port)
        await site.start()
        
        logger.info(f"MCP proxy started on http://localhost:{local_port} for service {service_name}")
        
    async def start_websocket_proxy(self, service_name: str, local_port: int) -> None:
        """Start WebSocket proxy server for an MCP service.
        
        Args:
            service_name: Name of the MCP service to proxy
            local_port: Local port to listen on
        """
        async def handle_websocket(websocket, path):
            """Handle WebSocket connections and forward as MCP."""
            try:
                async for message in websocket:
                    try:
                        payload = json.loads(message)
                        response = await self.forward_mcp_request(service_name, payload)
                        await websocket.send(json.dumps(response))
                    except Exception as e:
                        logger.error(f"Error handling WebSocket message: {e}")
                        error_response = {"error": str(e)}
                        await websocket.send(json.dumps(error_response))
                        
            except websockets.exceptions.ConnectionClosed:
                logger.info("Client WebSocket closed")
                
        # Start WebSocket server
        await websockets.serve(handle_websocket, 'localhost', local_port)
        logger.info(f"MCP WebSocket proxy started on ws://localhost:{local_port} for service {service_name}")
        
    async def stop(self) -> None:
        """Stop the proxy and close connections."""
        if self.ws_connection:
            await self.ws_connection.close()
            
        if self.runner:
            await self.runner.cleanup()


async def main():
    """Example usage of MCP client proxy."""
    import argparse
    
    parser = argparse.ArgumentParser(description='MCP Client Proxy for bluep')
    parser.add_argument('--bluep-url', required=True, help='Bluep WebSocket URL (e.g., wss://localhost:8500/ws)')
    parser.add_argument('--session-token', required=True, help='Bluep session token')
    parser.add_argument('--service', required=True, help='MCP service name (e.g., azure-devops)')
    parser.add_argument('--local-port', type=int, default=4000, help='Local port to expose service on')
    parser.add_argument('--websocket', action='store_true', help='Use WebSocket proxy instead of HTTP')
    
    args = parser.parse_args()
    
    # Create and start proxy
    proxy = MCPClientProxy(args.bluep_url, args.session_token)
    await proxy.connect()
    
    if args.websocket:
        await proxy.start_websocket_proxy(args.service, args.local_port)
    else:
        await proxy.start_http_proxy(args.service, args.local_port)
        
    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy...")
        await proxy.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())