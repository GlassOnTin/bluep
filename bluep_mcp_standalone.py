#!/usr/bin/env python3
"""
Bluep MCP Client - Standalone single-file version

Usage:
    python bluep_mcp_standalone.py --help
    python bluep_mcp_standalone.py proxy azure-devops --server wss://localhost:8500/ws --token YOUR_TOKEN

This is a single-file version of the bluep MCP client that can be easily copied and run anywhere.
"""

import asyncio
import json
import logging
import ssl
import sys
from typing import Dict, Optional, Any

# Check dependencies
try:
    import websockets
    import aiohttp
    from aiohttp import web
except ImportError:
    print("Error: Required dependencies not found. Please install:")
    print("  pip install websockets aiohttp")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MCPClientProxy:
    """Proxy that exposes remote MCP services on local ports."""
    
    def __init__(self, bluep_ws_url: str, session_token: str, verify_ssl: bool = False):
        self.bluep_ws_url = bluep_ws_url
        self.session_token = session_token
        self.verify_ssl = verify_ssl
        self.ws_connection = None
        self.pending_requests = {}
        self.request_counter = 0
        
    async def connect(self):
        """Connect to bluep WebSocket server."""
        headers = {
            "Cookie": f"bluep_session={self.session_token}",
            "Origin": self.bluep_ws_url.replace("wss://", "https://").replace("ws://", "http://").rsplit("/", 1)[0]
        }
        
        # Handle SSL for wss:// URLs
        if self.bluep_ws_url.startswith("wss://"):
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context = True  # Use default SSL verification
                
            self.ws_connection = await websockets.connect(
                self.bluep_ws_url,
                extra_headers=headers,
                ssl=ssl_context
            )
        else:
            # For ws:// URLs, don't use SSL
            self.ws_connection = await websockets.connect(
                self.bluep_ws_url,
                extra_headers=headers
            )
        
        logger.info(f"Connected to bluep server")
        asyncio.create_task(self._handle_messages())
        
    async def _handle_messages(self):
        """Handle incoming WebSocket messages."""
        try:
            async for message in self.ws_connection:
                try:
                    data = json.loads(message)
                    if data.get("type") == "mcp-response":
                        request_id = data.get("mcpPayload", {}).get("id")
                        if request_id in self.pending_requests:
                            future = self.pending_requests.pop(request_id)
                            if not future.cancelled():
                                future.set_result(data["mcpPayload"])
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection closed")
            
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
        
        await self.ws_connection.send(json.dumps(message))
        
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


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Bluep MCP Client - Access remote MCP services')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Proxy command
    proxy_parser = subparsers.add_parser('proxy', help='Start local proxy for MCP service')
    proxy_parser.add_argument('service', help='MCP service name')
    proxy_parser.add_argument('--server', '-s', default='wss://localhost:8500/ws',
                            help='Bluep WebSocket URL')
    proxy_parser.add_argument('--token', '-t', required=True,
                            help='Session token')
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
            
            await asyncio.Event().wait()
            
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            if runner:
                await runner.cleanup()
            if proxy.ws_connection:
                await proxy.ws_connection.close()


if __name__ == '__main__':
    asyncio.run(main())