from fastapi import FastAPI, WebSocket, Depends, HTTPException, security
from fastapi.security import APIKeyHeader
from fastapi.responses import Response, HTMLResponse
import secrets
import hmac
import uvicorn
from typing import List
import socket

import base64
from io import BytesIO
from PIL import Image

import signal
import asyncio

# Generate secure room keys
ROOM_KEY = secrets.token_urlsafe(32)
api_key_header = APIKeyHeader(name="X-Room-Key")

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if not hmac.compare_digest(api_key, ROOM_KEY):
        raise HTTPException(status_code=403)
    return api_key

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

app = FastAPI()
connected_clients: List[WebSocket] = []
shared_text = ""
HOST_IP = get_local_ip()
blue = "#0000ff"

@app.get("/")
async def get():
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>bluep</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <style>
        body, html {{
            margin: 0;
            padding: 8px;
            height: calc(100vh - 32px);
            width: calc(100vw - 32px);
            background: {blue};
            overflow: hidden;
        }}
        #editor {{
            width: 100%;
            height: 100%;
            margin: 0;
            padding: 16px;
            background-color: {blue};
            color: #fff;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px;
            resize: none;
            box-sizing: border-box;
        }}
        #editor::before {{
            content: "bluep";
            position: absolute;
            top: 0.5em;
            left: 3em;
            transform: translateX(-50%);
            background: {blue};
            padding: 0 10px;
        }}
        </style>
    </head>
    <body>
        <div id="editor">
            <textarea style="width: 100%; height: 100%; background-color: {blue}; color: #fff; border: none; outline: none; resize: none;"></textarea>
        </div>
        <script>
            const ROOM_KEY = "{ROOM_KEY}";  // Exposed only to initial page load
            const editor = document.querySelector('#editor textarea');
            const ws = new WebSocket("wss://{HOST_IP}:8500/ws");

            ws.onerror = (error) => {{
                console.error('WebSocket Error:', error);
            }};

            ws.onclose = (event) => {{
                console.log('WebSocket Closed:', event.code, event.reason);
            }};

            ws.onopen = () => {{
                ws.send(JSON.stringify({{
                    type: "auth",
                    key: ROOM_KEY
                }}));
                console.log('WebSocket opened');
            }};

            editor.oninput = () => {{
                ws.send(JSON.stringify({{
                    type: "content",
                    data: editor.value
                }}));
                console.log('WebSocket input', editor.value);
            }};

            let isReceiving = false;

            ws.onmessage = (event) => {{
                const msg = JSON.parse(event.data);
                if (msg.type === "content") {{
                    isReceiving = true;
                    editor.value = msg.data;
                    isReceiving = false;
                }} else if (msg.type === "cursor") {{
                    // Create or update cursor element for this client
                    let cursor = document.getElementById(`cursor-${{msg.clientId}}`);
                    if (!cursor) {{
                        cursor = document.createElement(\'div\');
                        cursor.id = `cursor-${{msg.clientId}}`;
                        cursor.style.position = 'absolute';
                        cursor.style.width = \'3px\';
                        cursor.style.height = \'20px\';
                        cursor.style.background = \'#ff0\';
                        document.body.appendChild(cursor);
                    }}
                    cursor.style.left = `${{msg.x}}px`;
                    cursor.style.top = `${{msg.y}}px`;
                }}
            }};

            editor.oninput = () => {{
                if (!isReceiving) {{
                    ws.send(JSON.stringify({{
                        type: "content",
                        data: editor.value
                    }}));
                }}
            }};

            editor.onselectionchange = () => {{
                const rect = editor.getBoundingClientRect();
                const pos = editor.selectionStart;
                // Calculate cursor position based on text position
                const text = editor.value.substr(0, pos);
                const lines = text.split("\\n");
                const lineHeight = 20; // Approximate
                const y = lines.length * lineHeight;
                const x = (lines[lines.length-1].length % editor.cols) * 10; // Approximate char width

                ws.send(JSON.stringify({{
                    type: "cursor",
                    x: rect.left + x,
                    y: rect.top + y
                }}));
            }};
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global shared_text
    await websocket.accept()
    try:
        auth_msg = await websocket.receive_json()
        if auth_msg["type"] != "auth" or not hmac.compare_digest(auth_msg["key"], ROOM_KEY):
            await websocket.close(code=1008)
            return

        connected_clients.append(websocket)
        print(f"Client connected. Total clients: {len(connected_clients)}")
        await websocket.send_json({"type": "content", "data": shared_text})

        while True:
            msg = await websocket.receive_json()
            if msg["type"] == "content":
                shared_text = msg["data"]
                print(f"Broadcasting message to {len(connected_clients)-1} clients")
                for client in connected_clients:
                    if client != websocket:
                        await client.send_json({"type": "content", "data": msg["data"]})
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
            print(f"Client disconnected. Total clients: {len(connected_clients)}")

@app.get("/favicon.png")
async def favicon():
    img = Image.new('RGB', (32, 32), blue)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return Response(content=buffer.getvalue(), media_type='image/png')

async def shutdown():
    print("\nClosing connections...")
    for client in connected_clients:
        await client.close()
    exit(0)

def handle_shutdown(signum, frame):
    loop = asyncio.get_event_loop()
    loop.create_task(shutdown())

signal.signal(signal.SIGINT, handle_shutdown)

if __name__ == "__main__":
    print(f"Server running at https://{HOST_IP}:8500")
    config = uvicorn.Config(app, host="0.0.0.0", port=8500, ssl_keyfile="key.pem", ssl_certfile="cert.pem", loop="asyncio", timeout_graceful_shutdown=0)
    server = uvicorn.Server(config=config)
    server.run()
