#!/usr/bin/env python3
"""
Native helper application for Bluep MCP Browser Extension

This creates a local HTTP server that the browser extension can communicate with
to provide a bridge for MCP services.
"""

import asyncio
import json
import logging
import struct
import sys
from typing import Dict, Optional
from aiohttp import web
import uuid

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('/tmp/bluep_mcp_bridge.log')]
)
logger = logging.getLogger(__name__)


class NativeMessagingHost:
    """Handles native messaging protocol with browser extension."""
    
    def __init__(self):
        self.app = web.Application()
        self.runner = None
        self.site = None
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.setup_routes()
        
    def setup_routes(self):
        """Setup HTTP routes for the local server."""
        self.app.router.add_post('/', self.handle_mcp_request)
        self.app.router.add_get('/health', self.handle_health)
        
    async def handle_mcp_request(self, request: web.Request) -> web.Response:
        """Handle incoming MCP requests from Claude Code."""
        try:
            payload = await request.json()
            request_id = str(uuid.uuid4())
            
            # Create a future to wait for response
            future = asyncio.create_future()
            self.pending_requests[request_id] = future
            
            # Send to browser extension
            self.send_message({
                'type': 'request',
                'id': request_id,
                'payload': payload
            })
            
            # Wait for response (timeout after 30 seconds)
            try:
                response = await asyncio.wait_for(future, timeout=30.0)
                return web.json_response(response)
            except asyncio.TimeoutError:
                del self.pending_requests[request_id]
                return web.json_response(
                    {'error': 'Request timeout'},
                    status=504
                )
                
        except Exception as e:
            logger.error(f"Error handling MCP request: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({'status': 'ok'})
    
    def send_message(self, message: dict):
        """Send a message to the browser extension using native messaging protocol."""
        encoded_message = json.dumps(message).encode('utf-8')
        # Native messaging protocol: 4-byte length + message
        sys.stdout.buffer.write(struct.pack('I', len(encoded_message)))
        sys.stdout.buffer.write(encoded_message)
        sys.stdout.buffer.flush()
    
    def read_message(self) -> Optional[dict]:
        """Read a message from the browser extension."""
        try:
            # Read the message length (4 bytes, little-endian)
            raw_length = sys.stdin.buffer.read(4)
            if not raw_length:
                return None
            
            message_length = struct.unpack('I', raw_length)[0]
            
            # Read the message
            message = sys.stdin.buffer.read(message_length).decode('utf-8')
            return json.loads(message)
        except Exception as e:
            logger.error(f"Error reading message: {e}")
            return None
    
    async def start_server(self, port: int = 4000):
        """Start the HTTP server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, 'localhost', port)
        await self.site.start()
        logger.info(f"HTTP server started on port {port}")
        
        # Notify extension that server is ready
        self.send_message({
            'type': 'server-started',
            'port': port
        })
    
    async def stop_server(self):
        """Stop the HTTP server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()
        logger.info("HTTP server stopped")
    
    async def handle_extension_message(self, message: dict):
        """Handle messages from the browser extension."""
        msg_type = message.get('type')
        
        if msg_type == 'response':
            # Handle response for a pending request
            request_id = message.get('requestId')
            if request_id in self.pending_requests:
                future = self.pending_requests.pop(request_id)
                future.set_result(message.get('payload', {}))
        
        elif msg_type == 'stop-server':
            await self.stop_server()
            sys.exit(0)
    
    async def run(self):
        """Main run loop."""
        # Handle initial message
        message = self.read_message()
        if message and message.get('action') == 'start-server':
            port = message.get('port', 4000)
            await self.start_server(port)
        
        # Message handling loop
        while True:
            message = self.read_message()
            if message:
                await self.handle_extension_message(message)
            else:
                # Extension disconnected
                break
        
        await self.stop_server()


async def main():
    """Main entry point."""
    host = NativeMessagingHost()
    try:
        await host.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    # Set up event loop for Windows compatibility
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())