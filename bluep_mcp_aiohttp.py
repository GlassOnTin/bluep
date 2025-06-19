#!/usr/bin/env python3
"""
Bluep MCP Client using aiohttp - Alternative implementation for Windows compatibility

Usage:
    python bluep_mcp_aiohttp.py proxy SERVICE_NAME --server https://192.168.0.133:8500 --token YOUR_SESSION_COOKIE --port 4000
"""

import asyncio
import json
import logging
import ssl
import sys
from typing import Dict, Optional, Any

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    print("Error: aiohttp not found. Install with: pip install aiohttp")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MCPClientProxy:
    """Proxy that exposes remote MCP services on local ports using aiohttp."""
    
    def __init__(self, bluep_server_url: str, session_cookie: str, verify_ssl: bool = False):
        # Convert https:// to wss:// for WebSocket
        self.bluep_ws_url = bluep_server_url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
        self.bluep_server_url = bluep_server_url
        self.session_cookie = session_cookie
        self.verify_ssl = verify_ssl
        self.ws_connection = None
        self.session = None
        self.pending_requests = {}
        self.request_counter = 0
        
    async def connect(self):
        """Connect to bluep WebSocket server using aiohttp."""
        # Create SSL context for self-signed certificates
        ssl_context = None
        if not self.verify_ssl and self.bluep_ws_url.startswith("wss://"):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create session with cookies
        cookies = {"bluep_session": self.session_cookie}
        connector = aiohttp.TCPConnector(ssl=ssl_context) if ssl_context else None
        self.session = aiohttp.ClientSession(
            cookies=cookies,
            connector=connector
        )
        
        try:
            logger.info(f"Connecting to {self.bluep_ws_url}")
            self.ws_connection = await self.session.ws_connect(
                self.bluep_ws_url,
                headers={
                    "Origin": self.bluep_server_url
                }
            )
            logger.info("Connected to bluep server")
            
            # Start message handler
            asyncio.create_task(self._handle_messages())
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            if self.session:
                await self.session.close()
            raise
    
    async def _handle_messages(self):
        """Handle incoming WebSocket messages."""
        try:
            async for msg in self.ws_connection:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        msg_type = data.get("type")
                        
                        if msg_type == "ping":
                            # Respond to ping with pong
                            await self.ws_connection.send_json({"type": "pong"})
                            logger.debug("Received ping, sent pong")
                        elif msg_type == "clients":
                            logger.info(f"Active clients: {data.get('count', 0)}")
                        elif msg_type == "error":
                            logger.error(f"Server error: {data.get('error', 'Unknown error')}")
                        elif msg_type == "mcp-response":
                            request_id = data.get("mcpPayload", {}).get("id")
                            if request_id in self.pending_requests:
                                future = self.pending_requests.pop(request_id)
                                if not future.cancelled():
                                    future.set_result(data["mcpPayload"])
                    except Exception as e:
                        logger.error(f"Error handling message: {e}")
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {msg.data}")
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    logger.info("WebSocket connection closed")
                    break
        except Exception as e:
            logger.error(f"Message handler error: {e}")
    
    async def forward_mcp_request(self, service_name: str, payload: Dict[str, Any]):
        """Forward an MCP request to the remote service."""
        if not self.ws_connection or self.ws_connection.closed:
            raise RuntimeError("Not connected to bluep server")
        
        if "id" not in payload:
            self.request_counter += 1
            payload["id"] = f"req_{self.request_counter}"
        
        request_id = payload["id"]
        future = asyncio.Future()
        self.pending_requests[request_id] = future
        
        message = {
            "type": "mcp-request",
            "serviceName": service_name,
            "mcpPayload": payload
        }
        
        await self.ws_connection.send_json(message)
        
        try:
            return await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            self.pending_requests.pop(request_id, None)
            raise RuntimeError("MCP request timed out")
    
    async def start_http_proxy(self, service_name: str, local_port: int):
        """Start HTTP proxy server."""
        app = web.Application()
        
        async def handle_request(request):
            try:
                body = await request.text()
                payload = json.loads(body) if body else {}
                response = await self.forward_mcp_request(service_name, payload)
                return web.json_response(response)
            except Exception as e:
                logger.error(f"Error: {e}")
                return web.json_response(
                    {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}},
                    status=500
                )
        
        app.router.add_route('*', '/{path:.*}', handle_request)
        
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', local_port)
        await site.start()
        
        logger.info(f"MCP proxy started on http://localhost:{local_port}")
        return runner
    
    async def close(self):
        """Close connections."""
        if self.ws_connection:
            await self.ws_connection.close()
        if self.session:
            await self.session.close()


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Bluep MCP Client (aiohttp version)')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Proxy command
    proxy_parser = subparsers.add_parser('proxy', help='Start local proxy for MCP service')
    proxy_parser.add_argument('service', help='MCP service name')
    proxy_parser.add_argument('--server', '-s', default='https://localhost:8500',
                            help='Bluep server URL (use https://, not wss://)')
    proxy_parser.add_argument('--token', '-t', required=True,
                            help='Session cookie from bluep')
    proxy_parser.add_argument('--port', '-p', type=int, default=4000,
                            help='Local port')
    proxy_parser.add_argument('--verify-ssl', action='store_true',
                            help='Enable SSL verification (disabled by default for self-signed certs)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'proxy':
        proxy = MCPClientProxy(args.server, args.token, verify_ssl=args.verify_ssl)
        runner = None
        
        try:
            await proxy.connect()
            runner = await proxy.start_http_proxy(args.service, args.port)
            
            print(f"Proxying MCP service '{args.service}' on port {args.port}")
            print("Press Ctrl+C to stop")
            
            # Keep alive with automatic reconnection
            reconnect_delay = 5
            while True:
                try:
                    if proxy.ws_connection.closed:
                        print(f"Connection lost. Reconnecting in {reconnect_delay} seconds...")
                        await asyncio.sleep(reconnect_delay)
                        
                        # Clean up and reconnect
                        if runner:
                            await runner.cleanup()
                        await proxy.close()
                        
                        proxy = MCPClientProxy(args.server, args.token, verify_ssl=args.verify_ssl)
                        await proxy.connect()
                        runner = await proxy.start_http_proxy(args.service, args.port)
                        print(f"Reconnected and proxy restarted on port {args.port}")
                        reconnect_delay = 5  # Reset delay
                    else:
                        await asyncio.sleep(1)
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    reconnect_delay = min(reconnect_delay * 2, 60)  # Exponential backoff
                    print(f"Error occurred. Retrying in {reconnect_delay} seconds...")
                    await asyncio.sleep(reconnect_delay)
            
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)
        finally:
            if runner:
                await runner.cleanup()
            await proxy.close()


if __name__ == '__main__':
    # Handle Windows event loop
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())