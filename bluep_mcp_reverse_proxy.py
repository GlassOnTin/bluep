#!/usr/bin/env python3
"""
Bluep MCP Reverse Proxy Client

This client registers an external MCP service with bluep, allowing bluep to act as a
reverse proxy to reach MCP services running behind firewalls.

Usage:
    python bluep_mcp_reverse_proxy.py discover --port 5000
    python bluep_mcp_reverse_proxy.py register azure-devops --server https://192.168.0.133:8500 --token YOUR_SESSION_COOKIE --local-port 5000
    python bluep_mcp_reverse_proxy.py auto --server https://192.168.0.133:8500 --token YOUR_SESSION_COOKIE --local-port 5000
"""

import asyncio
import json
import logging
import ssl
import sys
from typing import Dict, Optional, Any, List

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


class MCPServiceDiscovery:
    """Discovers MCP services running on local ports."""
    
    @staticmethod
    async def discover_services(port: int) -> List[Dict[str, Any]]:
        """Discover MCP services on the specified port."""
        try:
            async with aiohttp.ClientSession() as session:
                # Try standard MCP discovery endpoint
                url = f"http://localhost:{port}"
                
                # First, try to get service info via MCP initialize request
                mcp_request = {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "clientInfo": {
                            "name": "bluep-discovery",
                            "version": "1.0.0"
                        }
                    },
                    "id": 1
                }
                
                try:
                    async with session.post(url, json=mcp_request, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200:
                            result = await response.json()
                            if "result" in result and "serverInfo" in result["result"]:
                                server_info = result["result"]["serverInfo"]
                                logger.info(f"Found MCP service: {server_info.get('name', 'Unknown')} v{server_info.get('version', 'Unknown')}")
                                return [{
                                    "name": server_info.get("name", "unknown"),
                                    "version": server_info.get("version", "1.0.0"),
                                    "port": port,
                                    "url": url
                                }]
                except Exception as e:
                    logger.debug(f"MCP initialize failed: {e}")
                
                # Try stdio detection by checking if service responds to basic JSON-RPC
                try:
                    test_request = {
                        "jsonrpc": "2.0",
                        "method": "tools/list",
                        "id": 1
                    }
                    async with session.post(url, json=test_request, timeout=aiohttp.ClientTimeout(total=2)) as response:
                        if response.status in [200, 400, 500]:  # Any JSON-RPC response
                            logger.info(f"Found JSON-RPC service on port {port}")
                            return [{
                                "name": f"mcp-service-{port}",
                                "version": "unknown",
                                "port": port,
                                "url": url
                            }]
                except Exception as e:
                    logger.debug(f"JSON-RPC test failed: {e}")
                
                # Try simple HTTP GET to see if anything is running
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as response:
                        if response.status < 500:
                            logger.info(f"Found HTTP service on port {port} (may not be MCP)")
                            return [{
                                "name": f"http-service-{port}",
                                "version": "unknown",
                                "port": port,
                                "url": url,
                                "warning": "HTTP service detected but MCP compatibility unknown"
                            }]
                except Exception as e:
                    logger.debug(f"HTTP GET failed: {e}")
                
                logger.warning(f"No service found on port {port}")
                return []
                
        except Exception as e:
            logger.error(f"Error discovering services: {e}")
            return []


class MCPReverseProxy:
    """Registers a local MCP service with bluep for reverse proxy access."""
    
    def __init__(self, bluep_server_url: str, token: str, verify_ssl: bool = False, use_ws_token: bool = False):
        self.bluep_server_url = bluep_server_url
        self.token = token
        self.use_ws_token = use_ws_token
        self.verify_ssl = verify_ssl
        self.ws_connection = None
        self.session = None
        self.registered_services = {}
        
        # Construct WebSocket URL based on token type
        if use_ws_token:
            # Use token in query parameter for WebSocket auth
            self.bluep_ws_url = bluep_server_url.replace("https://", "wss://").replace("http://", "ws://") + f"/ws?token={token}"
        else:
            # Use session cookie for traditional auth
            self.bluep_ws_url = bluep_server_url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"
            self.session_cookie = token
        
    async def connect(self):
        """Connect to bluep WebSocket server."""
        ssl_context = None
        if not self.verify_ssl and self.bluep_ws_url.startswith("wss://"):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context) if ssl_context else None
        
        if self.use_ws_token:
            # No cookies needed, token is in URL
            self.session = aiohttp.ClientSession(connector=connector)
        else:
            # Use session cookie
            cookies = {"bluep_session": self.session_cookie}
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
            
            # Start periodic ping to keep connection alive
            asyncio.create_task(self._send_periodic_ping())
            
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
                            logger.info("Received ping, sent pong")
                        
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
    
    async def _send_periodic_ping(self):
        """Send periodic ping to keep connection alive."""
        try:
            while self.ws_connection and not self.ws_connection.closed:
                await asyncio.sleep(15)  # Send ping every 15 seconds (more frequent than server's 20s)
                if not self.ws_connection.closed:
                    # Send our own pong message proactively
                    await self.ws_connection.send_json({"type": "pong"})
                    logger.info("Sent proactive pong to keep connection alive")
        except Exception as e:
            logger.error(f"Error in periodic ping: {e}")
    
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
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover MCP services on a local port')
    discover_parser.add_argument('--port', '-p', type=int, required=True,
                               help='Local port to check for MCP services')
    
    # Auto command
    auto_parser = subparsers.add_parser('auto', help='Auto-discover and register MCP services')
    auto_parser.add_argument('--server', '-s', default='https://localhost:8500',
                               help='Bluep server URL')
    auto_parser.add_argument('--token', '-t', required=True,
                               help='Session cookie or WebSocket token from bluep')
    auto_parser.add_argument('--local-port', '-p', type=int, required=True,
                               help='Local port where MCP service is running')
    auto_parser.add_argument('--verify-ssl', action='store_true',
                               help='Enable SSL verification')
    auto_parser.add_argument('--ws-token', action='store_true',
                               help='Use WebSocket token instead of session cookie')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register and proxy a local MCP service')
    register_parser.add_argument('service', help='MCP service name')
    register_parser.add_argument('--server', '-s', default='https://localhost:8500',
                               help='Bluep server URL')
    register_parser.add_argument('--token', '-t', required=True,
                               help='Session cookie or WebSocket token from bluep')
    register_parser.add_argument('--local-port', '-p', type=int, required=True,
                               help='Local port where MCP service is running')
    register_parser.add_argument('--description', '-d', default='',
                               help='Service description')
    register_parser.add_argument('--verify-ssl', action='store_true',
                               help='Enable SSL verification')
    register_parser.add_argument('--ws-token', action='store_true',
                               help='Use WebSocket token instead of session cookie')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'discover':
        # Just discover services on the port
        services = await MCPServiceDiscovery.discover_services(args.port)
        if services:
            print(f"\nDiscovered {len(services)} service(s) on port {args.port}:")
            for service in services:
                print(f"\n  Service: {service['name']}")
                print(f"  Version: {service['version']}")
                print(f"  URL: {service['url']}")
                if 'warning' in service:
                    print(f"  Warning: {service['warning']}")
        else:
            print(f"\nNo services found on port {args.port}")
            print("\nTroubleshooting tips:")
            print("1. Ensure the MCP service is running")
            print("2. Check if the port number is correct")
            print("3. Some MCP services may use stdio instead of HTTP")
        return
    
    elif args.command == 'auto':
        # Auto-discover and register
        print(f"Discovering MCP services on port {args.local_port}...")
        services = await MCPServiceDiscovery.discover_services(args.local_port)
        
        if not services:
            print(f"No services found on port {args.local_port}")
            sys.exit(1)
        
        service = services[0]  # Use the first discovered service
        service_name = service['name']
        
        # Clean up service name for registration
        if service_name.startswith('mcp-service-'):
            # Try to get a better name from environment or use port-based name
            service_name = f"mcp-{args.local_port}"
        
        print(f"\nFound service: {service_name}")
        if 'warning' in service:
            print(f"Warning: {service['warning']}")
            confirm = input("Continue with registration? (y/N): ")
            if confirm.lower() != 'y':
                print("Registration cancelled")
                return
        
        # Register the service
        proxy = MCPReverseProxy(args.server, args.token, verify_ssl=args.verify_ssl, use_ws_token=args.ws_token)
        
        try:
            await proxy.connect()
            description = f"Auto-discovered MCP service: {service.get('name', 'Unknown')} v{service.get('version', 'Unknown')}"
            await proxy.register_service(service_name, args.local_port, description)
            
            print(f"\nRegistered '{service_name}' running on localhost:{args.local_port}")
            print("The service is now accessible through bluep")
            print("Press Ctrl+C to stop")
            
            # Keep running with automatic reconnection
            reconnect_delay = 5
            last_check = 0
            while True:
                try:
                    # Check connection status more frequently
                    current_time = asyncio.get_event_loop().time()
                    if current_time - last_check > 1:  # Check every second
                        last_check = current_time
                        if proxy.ws_connection.closed:
                            print(f"Connection lost. Reconnecting in {reconnect_delay} seconds...")
                            await asyncio.sleep(reconnect_delay)
                            
                            # Reconnect and re-register
                            await proxy.close()
                            proxy = MCPReverseProxy(args.server, args.token, verify_ssl=args.verify_ssl, use_ws_token=args.ws_token)
                            await proxy.connect()
                            await proxy.register_service(service_name, args.local_port, description)
                            print(f"Reconnected and re-registered service '{service_name}'")
                            reconnect_delay = 5  # Reset delay on successful reconnection
                        else:
                            await asyncio.sleep(0.1)
                    else:
                        await asyncio.sleep(0.1)
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    reconnect_delay = min(reconnect_delay * 2, 60)  # Exponential backoff up to 60 seconds
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
            await proxy.close()
    
    elif args.command == 'register':
        proxy = MCPReverseProxy(args.server, args.token, verify_ssl=args.verify_ssl, use_ws_token=args.ws_token)
        
        try:
            await proxy.connect()
            await proxy.register_service(args.service, args.local_port, args.description)
            
            print(f"Registered '{args.service}' running on localhost:{args.local_port}")
            print("The service is now accessible through bluep")
            print("Press Ctrl+C to stop")
            
            # Keep running with automatic reconnection
            reconnect_delay = 5
            last_check = 0
            while True:
                try:
                    # Check connection status more frequently
                    current_time = asyncio.get_event_loop().time()
                    if current_time - last_check > 1:  # Check every second
                        last_check = current_time
                        if proxy.ws_connection.closed:
                            print(f"Connection lost. Reconnecting in {reconnect_delay} seconds...")
                            await asyncio.sleep(reconnect_delay)
                            
                            # Reconnect and re-register
                            await proxy.close()
                            proxy = MCPReverseProxy(args.server, args.token, verify_ssl=args.verify_ssl, use_ws_token=args.ws_token)
                            await proxy.connect()
                            await proxy.register_service(args.service, args.local_port, args.description or f"External MCP service on port {args.local_port}")
                            print(f"Reconnected and re-registered service '{args.service}'")
                            reconnect_delay = 5  # Reset delay on successful reconnection
                        else:
                            await asyncio.sleep(0.1)
                    else:
                        await asyncio.sleep(0.1)
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    reconnect_delay = min(reconnect_delay * 2, 60)  # Exponential backoff up to 60 seconds
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
            await proxy.close()


if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())