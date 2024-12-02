#!/usr/bin/env python3
from fastapi import FastAPI, Query, WebSocket, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.templating import Jinja2Templates
import uvicorn
from PIL import Image
from io import BytesIO
import signal
import asyncio

from bluep.auth import TOTPAuth
from bluep.config import Settings
from bluep.websocket_manager import WebSocketManager
from bluep.models import WebSocketMessage

app = FastAPI()
templates = Jinja2Templates(directory="templates")
settings = Settings()
auth = TOTPAuth()
ws_manager = WebSocketManager()

@app.get("/setup")
async def setup():
    html = f"""
    <h1>Room Setup</h1>
    <img src="data:image/png;base64,{auth.qr_base64}">
    <p>Secret key: {auth.secret_key}</p>
    <p>Current token: {auth.totp.now()}</p>
    """
    return HTMLResponse(html)

@app.get("/login")
async def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/")
async def get(request: Request, response: Response, key: str = None):
    if not key:
        return RedirectResponse(url="/login")

    await auth.verify_and_create_session(key, request, response)

    return templates.TemplateResponse(
        "editor.html",
        {
            "request": request,
            "host_ip": settings.host_ip,
            "key": key,
            "blue": settings.blue_color
        }
    )

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, key: str = Query(...)):
    if not auth.verify(key):
        await websocket.close(code=1008)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            msg = WebSocketMessage.model_validate_message(await websocket.receive_text())
            if msg.type == "content":
                ws_manager.update_shared_text(msg.data)
                await ws_manager.broadcast(msg.model_dump(exclude_none=True), exclude=websocket)
            elif msg.type == "cursor":
                cursor_data = msg.model_dump(exclude_none=True)
                cursor_data["clientId"] = id(websocket)
                await ws_manager.broadcast(cursor_data, exclude=websocket)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await ws_manager.disconnect(websocket)

@app.get("/favicon.png")
async def favicon(key: str = None):
    if not auth.verify(key):
        raise HTTPException(status_code=403)

    img = Image.new('RGB', (32, 32), settings.blue_color)
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return Response(content=buffer.getvalue(), media_type='image/png')

async def shutdown():
    print("\nClosing connections...")
    for client in ws_manager.active_connections:
        await client.close()
    exit(0)

def handle_shutdown(signum, frame):
    loop = asyncio.get_event_loop()
    loop.create_task(shutdown())

def main():
    signal.signal(signal.SIGINT, handle_shutdown)
    print(f"Server running at https://{settings.host_ip}:{settings.port}")
    print(f"https://{settings.host_ip}:{settings.port}/setup")

    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=settings.port,
        ssl_keyfile=settings.ssl_keyfile,
        ssl_certfile=settings.ssl_certfile,
        loop="asyncio",
        timeout_graceful_shutdown=0
    )
    server = uvicorn.Server(config=config)
    server.run()

if __name__ == "__main__":
    main()
