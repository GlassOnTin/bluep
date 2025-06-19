#!/usr/bin/env python3
"""
Simplified Bluep MCP Client - Minimal version for debugging

Usage:
    python bluep_mcp_simple.py wss://192.168.0.133:8500/ws YOUR_SESSION_COOKIE
"""

import asyncio
import json
import logging
import ssl
import sys

try:
    import websockets
except ImportError:
    print("Error: websockets not found. Install with: pip install websockets")
    sys.exit(1)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def test_connection(url, session_cookie):
    """Test WebSocket connection with minimal code."""
    
    # Create SSL context for self-signed certificates
    ssl_context = None
    if url.startswith("wss://"):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    
    headers = {
        "Cookie": f"bluep_session={session_cookie}",
        "Origin": url.replace("wss://", "https://").replace("ws://", "http://").rsplit("/", 1)[0]
    }
    
    try:
        logger.info(f"Attempting to connect to {url}")
        logger.info(f"Headers: {headers}")
        
        # Simple connection attempt
        async with websockets.connect(
            url,
            ssl=ssl_context,
            extra_headers=headers
        ) as websocket:
            logger.info("Connected successfully!")
            
            # Handle messages
            async def receive_messages():
                async for message in websocket:
                    data = json.loads(message)
                    logger.info(f"Received: {data.get('type', 'unknown')}")
                    
                    if data.get("type") == "ping":
                        await websocket.send(json.dumps({"type": "pong"}))
                        logger.info("Sent pong")
            
            # Start receiving
            await receive_messages()
            
    except Exception as e:
        logger.error(f"Connection failed: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def main():
    if len(sys.argv) != 3:
        print("Usage: python bluep_mcp_simple.py <websocket_url> <session_cookie>")
        print("Example: python bluep_mcp_simple.py wss://192.168.0.133:8500/ws abc123...")
        sys.exit(1)
    
    url = sys.argv[1]
    cookie = sys.argv[2]
    
    await test_connection(url, cookie)


if __name__ == "__main__":
    asyncio.run(main())