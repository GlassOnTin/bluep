#!/usr/bin/env python3
"""
Bluep MCP Stdio Bridge

This bridges stdio-based MCP services to HTTP, allowing them to be used with the reverse proxy.

Usage:
    python bluep_mcp_stdio_bridge.py --port 5000 --command "npx -y @tiberriver256/mcp-server-azure-devops"
"""

import asyncio
import json
import logging
import sys
from typing import Optional
import subprocess
from aiohttp import web
import argparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MCPStdioBridge:
    """Bridges stdio MCP services to HTTP."""
    
    def __init__(self, command: str, port: int = 5000):
        self.command = command
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        self.app = web.Application()
        self.setup_routes()
        
    def setup_routes(self):
        """Setup HTTP routes."""
        self.app.router.add_post('/', self.handle_mcp_request)
        self.app.router.add_get('/health', self.handle_health)
        
    async def start_mcp_process(self):
        """Start the MCP service subprocess."""
        try:
            # Split command properly for shell execution
            if sys.platform == "win32":
                # Windows: use shell=True for complex commands
                self.process = await asyncio.create_subprocess_shell(
                    self.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                # Unix: use shell for complex commands with pipes
                self.process = await asyncio.create_subprocess_shell(
                    self.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            
            logger.info(f"Started MCP process: {self.command}")
            
            # Start error reader
            asyncio.create_task(self._read_stderr())
            
        except Exception as e:
            logger.error(f"Failed to start MCP process: {e}")
            raise
    
    async def _read_stderr(self):
        """Read and log stderr from the MCP process."""
        if not self.process or not self.process.stderr:
            return
            
        while True:
            line = await self.process.stderr.readline()
            if not line:
                break
            logger.info(f"MCP stderr: {line.decode().strip()}")
    
    async def handle_mcp_request(self, request: web.Request) -> web.Response:
        """Handle incoming MCP requests."""
        if not self.process or self.process.returncode is not None:
            # Process not running, try to start it
            await self.start_mcp_process()
            await asyncio.sleep(0.5)  # Give it time to start
        
        try:
            # Get request data
            data = await request.json()
            request_text = json.dumps(data) + '\n'
            
            # Send to MCP process
            self.process.stdin.write(request_text.encode())
            await self.process.stdin.drain()
            
            # Read response
            response_line = await self.process.stdout.readline()
            if not response_line:
                return web.json_response(
                    {"error": "No response from MCP service"},
                    status=500
                )
            
            # Parse and return response
            try:
                response_data = json.loads(response_line.decode())
                return web.json_response(response_data)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response: {response_line}")
                return web.json_response(
                    {"error": f"Invalid response: {str(e)}"},
                    status=500
                )
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500
            )
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        if self.process and self.process.returncode is None:
            return web.json_response({"status": "healthy", "pid": self.process.pid})
        else:
            return web.json_response({"status": "unhealthy"}, status=503)
    
    async def run(self):
        """Run the HTTP server."""
        # Start the MCP process
        await self.start_mcp_process()
        
        # Start HTTP server
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, 'localhost', self.port)
        await site.start()
        
        logger.info(f"HTTP bridge listening on http://localhost:{self.port}")
        logger.info("MCP stdio service is now accessible via HTTP")
        
        # Keep running
        try:
            while True:
                await asyncio.sleep(1)
                # Check if process is still alive
                if self.process and self.process.returncode is not None:
                    logger.warning("MCP process died, restarting...")
                    await self.start_mcp_process()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            if self.process:
                self.process.terminate()
                await self.process.wait()
            await runner.cleanup()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Bridge stdio MCP services to HTTP')
    parser.add_argument('--port', '-p', type=int, default=5000,
                       help='Port to listen on (default: 5000)')
    parser.add_argument('--command', '-c', required=True,
                       help='Command to run the MCP service')
    
    args = parser.parse_args()
    
    print(f"Starting stdio bridge for: {args.command}")
    print(f"Bridge will listen on: http://localhost:{args.port}")
    print()
    
    bridge = MCPStdioBridge(args.command, args.port)
    await bridge.run()


if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    asyncio.run(main())