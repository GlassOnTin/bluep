from fastapi import FastAPI, WebSocket
from fastapi.responses import Response, HTMLResponse
import uvicorn
from typing import List
import socket

import base64
from io import BytesIO
from PIL import Image

import signal
import asyncio

async def shutdown():
    print("\nClosing connections...")
    for client in connected_clients:
        await client.close()
    exit(0)

def handle_shutdown(signum, frame):
    loop = asyncio.get_event_loop()
    loop.create_task(shutdown())

signal.signal(signal.SIGINT, handle_shutdown)

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
            const ws = new WebSocket("wss://{HOST_IP}:8500/ws");
            const editor = document.querySelector('#editor textarea');

            editor.oninput = () => {{
                ws.send(editor.value);
            }};

            ws.onmessage = (event) => {{
                editor.value = event.data;
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
    connected_clients.append(websocket)
    try:
        await websocket.send_text(shared_text)
        while True:
            data = await websocket.receive_text()
            shared_text = data
            for client in connected_clients:
                if client != websocket:
                    await client.send_text(data)
    except:
        connected_clients.remove(websocket)


@app.get("/favicon.png")
async def favicon():
    img = Image.new('RGB', (32, 32), blue)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return Response(content=buffer.getvalue(), media_type='image/png')

if __name__ == "__main__":
    print(f"Server running at https://{HOST_IP}:8500")
    config = uvicorn.Config(app, host="0.0.0.0", port=8500, ssl_keyfile="key.pem", ssl_certfile="cert.pem", loop="asyncio", timeout_graceful_shutdown=0)
    server = uvicorn.Server(config=config)
    server.run()
