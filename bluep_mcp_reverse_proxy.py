#!/usr/bin/env python3
"""
Bluep MCP Reverse Proxy Client

This client registers an external MCP service with bluep, allowing bluep to act as a
reverse proxy to reach MCP services running behind firewalls.

Usage:
    python bluep_mcp_reverse_proxy.py register azure-devops --server https://192.168.0.133:8500 --token YOUR_SESSION_COOKIE --local-port 4000
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


class MCPReverseProxy:
    """Registers a local MCP service with bluep for reverse proxy access."""
    
    def __init__(self, bluep_server_url: str, session_cookie: str, verify_ssl: bool = False):
        self.bluep_ws_url = bluep_server_url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
        self.bluep_server_url = bluep_server_url
        self.session_cookie = session_cookie
        self.verify_ssl = verify_ssl
        self.ws_connection = None
        self.session = None
        self.registered_services = {}
        
    async def connect(self):
        """Connect to bluep WebSocket server."""
        ssl_context = None
        if not self.verify_ssl and self.bluep_ws_url.startswith("wss://"):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
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
                            await self.ws_connection.send_json({"type": "pong"})
                            logger.debug("Received ping, sent pong")
                        
                        elif msg_type == "mcp-request":
                            # Handle incoming MCP request
                            service_name = data.get("serviceName")
                            if service_name in self.registered_services:
                                await self._handle_mcp_request(data)
                            else:
                                logger.warning(f"Received request for unregistered service: {service_name}")
                        
                        elif msg_type == "mcp-service-registered":
                            logger.info(f"Service registered successfully: {data.get('serviceName')}")
                        
                        elif msg_type == "error":
                            logger.error(f"Server error: {data.get('error', 'Unknown error')}")
                            
                    except Exception as e:
                        logger.error(f"Error handling message: {e}")
                        
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {msg.data}")
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    logger.info("WebSocket connection closed")
                    break
        except Exception as e:
            logger.error(f"Message handler error: {e}")
    
    async def _handle_mcp_request(self, data: Dict[str, Any]):
        """Forward MCP request to local service and send response back."""
        service_name = data.get("serviceName")
        service_info = self.registered_services.get(service_name)
        
        if not service_info:
            return
        
        try:
            # Forward to local MCP service
            async with aiohttp.ClientSession() as local_session:
                async with local_session.post(
                    service_info["url"],
                    json=data.get("mcpPayload", {})
                ) as response:
                    result = await response.json()
                    
                    # Send response back through WebSocket
                    await self.ws_connection.send_json({
                        "type": "mcp-response",
                        "targetClient": data.get("targetClient"),
                        "serviceName": service_name,
                        "mcpPayload": result
                    })
                    
        except Exception as e:
            logger.error(f"Error forwarding request to local service: {e}")
            # Send error response
            await self.ws_connection.send_json({
                "type": "mcp-response",
                "targetClient": data.get("targetClient"),
                "serviceName": service_name,
                "mcpPayload": {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": str(e)},
                    "id": data.get("mcpPayload", {}).get("id")
                }
            })
    
    async def register_service(self, service_name: str, local_port: int, description: str = ""):
        """Register a local MCP service with bluep."""
        local_url = f"http://localhost:{local_port}"
        
        # Store service info
        self.registered_services[service_name] = {
            "url": local_url,
            "port": local_port
        }
        
        # Send registration message
        await self.ws_connection.send_json({
            "type": "mcp-service-register",
            "serviceName": service_name,
            "serviceUrl": local_url,
            "description": description or f"External MCP service on port {local_port}"
        })
        
        logger.info(f"Registering service '{service_name}' at {local_url}")
    
    async def close(self):
        """Close connections."""
        if self.ws_connection:
            await self.ws_connection.close()
        if self.session:
            await self.session.close()


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Bluep MCP Reverse Proxy - Register external MCP services')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register and proxy a local MCP service')
    register_parser.add_argument('service', help='MCP service name')
    register_parser.add_argument('--server', '-s', default='https://localhost:8500',
                               help='Bluep server URL')
    register_parser.add_argument('--token', '-t', required=True,
                               help='Session cookie from bluep')
    register_parser.add_argument('--local-port', '-p', type=int, required=True,
                               help='Local port where MCP service is running')
    register_parser.add_argument('--description', '-d', default='',
                               help='Service description')
    register_parser.add_argument('--verify-ssl', action='store_true',
                               help='Enable SSL verification')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'register':
        proxy = MCPReverseProxy(args.server, args.token, verify_ssl=args.verify_ssl)
        
        try:
            await proxy.connect()
            await proxy.register_service(args.service, args.local_port, args.description)
            
            print(f"Registered '{args.service}' running on localhost:{args.local_port}")
            print("The service is now accessible through bluep")
            print("Press Ctrl+C to stop")
            
            # Keep running
            while not proxy.ws_connection.closed:
                await asyncio.sleep(1)
            
            print("Connection lost. Exiting...")
            
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)
        finally:
            await proxy.close()


if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())