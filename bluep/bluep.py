from fastapi import FastAPI, WebSocket, HTTPException, Query
from fastapi.responses import Response, HTMLResponse
import secrets
import hmac
import uvicorn
from typing import Set
import socket
import base64
from io import BytesIO
from PIL import Image
import signal
import asyncio

ROOM_KEY = secrets.token_urlsafe(3)

async def verify_key(key: str = Query(None)):
    if not key or not hmac.compare_digest(key, ROOM_KEY):
        raise HTTPException(status_code=403)
    return key

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
connected_clients: Set[WebSocket] = set()
shared_text = ""
HOST_IP = get_local_ip()
blue = "#0000ff"

@app.get("/")
async def get(key: str = Query(...)):
    if not hmac.compare_digest(key, ROOM_KEY):
        raise HTTPException(status_code=403)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>bluep (0)</title>
        <link rel="icon" type="image/png" href="/favicon.png?key={key}">
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
            const ROOM_KEY = "{key}";
            const editor = document.querySelector('#editor textarea');
            const ws = new WebSocket(`wss://{HOST_IP}:8500/ws?key=${{ROOM_KEY}}`);

            ws.onmessage = (event) => {{
                const msg = JSON.parse(event.data);
                if (msg.type === "content") {{
                    editor.value = msg.data;
                }} else if (msg.type === "clients") {{
                    document.title = `bluep (${{msg.count}})`;
                }};
            }};

            let isReceiving = false;

            editor.oninput = () => {{
                if (!isReceiving) {{
                    ws.send(JSON.stringify({{
                        type: "content",
                        data: editor.value
                    }}));
                }}
            }};
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, key: str = Query(...)):
    global shared_text
    if not hmac.compare_digest(key, ROOM_KEY):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        connected_clients.add(websocket)
        client_count = len(connected_clients)
        print(f"Client connected. Total clients: {client_count}")

        for client in connected_clients:
            await client.send_json({"type": "clients", "count": client_count})

        await websocket.send_json({"type": "content", "data": shared_text})

        while True:
            msg = await websocket.receive_json()
            if msg["type"] == "content":
                shared_text = msg["data"]
                for client in connected_clients:
                    if client != websocket:
                        await client.send_json({"type": "content", "data": msg["data"]})
            elif msg["type"] == "cursor":
                for client in connected_clients:
                    if client != websocket:
                        await client.send_json({
                            "type": "cursor",
                            "clientId": id(websocket),
                            "x": msg["x"],
                            "y": msg["y"]
                        })
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
            client_count = len(connected_clients)
            print(f"Client disconnected. Total clients: {client_count}")
            for client in connected_clients:
                await client.send_json({"type": "clients", "count": client_count})

@app.get("/favicon.png")
async def favicon(key: str = Query(...)):
    if not hmac.compare_digest(key, ROOM_KEY):
        raise HTTPException(status_code=403)

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
    print(f"Room key: {ROOM_KEY}")
    print(f"Complete URL: https://{HOST_IP}:8500/?key={ROOM_KEY}")
    config = uvicorn.Config(app, host="0.0.0.0", port=8500, ssl_keyfile="key.pem", ssl_certfile="cert.pem", loop="asyncio", timeout_graceful_shutdown=0)
    server = uvicorn.Server(config=config)
    server.run()
