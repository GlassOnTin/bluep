"""FastAPI application module for the bluep collaborative text editor.

This module implements the main FastAPI application for bluep, handling web routes,
WebSocket connections, and TOTP authentication for the collaborative text editor.
The editor provides real-time synchronization of text content between multiple
authenticated users.
"""

import asyncio
import signal
import sys
from io import BytesIO
from typing import Optional

from fastapi import FastAPI, Query, WebSocket, Request, HTTPException
from fastapi.responses import Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from PIL import Image
import qrcode
import uvicorn

from .auth import TOTPAuth
from .config import Settings
from .models import WebSocketMessage
from .middleware import configure_security
from .websocket_manager import WebSocketManager

# Initialize core application components
templates = Jinja2Templates(directory="templates")
settings = Settings()
ws_manager = WebSocketManager()


class BlueApp:
    def __init__(self) -> None:
        """Initialize the application context."""
        self.app = FastAPI()
        self.auth = TOTPAuth()
        configure_security(self.app)
        self._configure_routes()

    def _configure_routes(self) -> None:
        """Configure application routes and handlers."""
        self.app.get("/")(self.get)
        self.app.get("/qr-raw")(self.qr_raw)
        self.app.get("/setup")(self.setup)
        self.app.get("/login")(self.login)
        self.app.get("/favicon.png")(self.favicon)
        self.app.websocket("/ws")(self.websocket_endpoint)

    async def setup(self, request: Request) -> Response:
        """Serve the TOTP setup page."""
        return templates.TemplateResponse(
            "setup.html",
            {
                "request": request,
                "qr_code": self.auth.qr_base64,
                "secret_key": self.auth.secret_key,
                "current_token": self.auth.totp.now(),
            },
        )

    async def login(self, request: Request) -> Response:
        """Serve the login page."""
        return templates.TemplateResponse("login.html", {"request": request})

    async def get(
        self, request: Request, response: Response, key: Optional[str] = None
    ) -> Response:
        """Handle main page access and authentication."""
        if not key:
            return RedirectResponse(url="/login")

        await self.auth.verify_and_create_session(key, request, response)
        return templates.TemplateResponse(
            "editor.html",
            {
                "request": request,
                "host_ip": settings.host_ip,
                "key": key,
                "blue": settings.blue_color,
            },
        )

    async def websocket_endpoint(
        self, websocket: WebSocket, key: str = Query(...)
    ) -> None:
        """Handle WebSocket connections for real-time collaboration."""
        if not self.auth.verify(key):
            await websocket.close(code=1008)
            return

        await ws_manager.connect(websocket)
        try:
            while True:
                msg = WebSocketMessage.model_validate_message(
                    await websocket.receive_text()
                )
                if msg.type == "content" and msg.data is not None:
                    ws_manager.update_shared_text(msg.data)
                    await ws_manager.broadcast(
                        msg.model_dump(exclude_none=True), exclude=websocket
                    )
                elif msg.type == "cursor":
                    cursor_data = msg.model_dump(exclude_none=True)
                    cursor_data["clientId"] = id(websocket)
                    await ws_manager.broadcast(cursor_data, exclude=websocket)
        except asyncio.CancelledError:
            await ws_manager.disconnect(websocket)
        except Exception as exc:
            print(f"WebSocket error ({type(exc).__name__}): {exc}")
            await ws_manager.disconnect(websocket)

    async def shutdown(signal_type: signal.Signals) -> None:
        """Handle graceful shutdown of the application."""
        print(f"\nReceived {signal_type.name}, shutting down...")
        for client in ws_manager.active_connections:
            await client.close()
        sys.exit(0)

    async def favicon(self, key: Optional[str] = None) -> Response:
        """Serve the favicon with authentication check."""
        if not key or not self.auth.verify(key):
            raise HTTPException(status_code=403)

        img = Image.new("RGB", (32, 32), settings.blue_color)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return Response(content=buffer.getvalue(), media_type="image/png")

    async def qr_raw(self) -> Response:
        """Generate and serve the TOTP QR code.

        Returns:
            Response: PNG image of the QR code
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(self.auth.totp.provisioning_uri("Bluep Room", issuer_name="Bluep"))
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_bytes = BytesIO()
        img.save(img_bytes, format="PNG")
        img_bytes.seek(0)

        return Response(content=img_bytes.getvalue(), media_type="image/png")


async def shutdown(self, signal_type: signal.Signals) -> None:
    """Handle graceful shutdown of the application."""
    print(f"\nReceived {signal_type.name}, shutting down...")
    for client in ws_manager.active_connections:
        await client.close()
    sys.exit(0)


def main(self) -> None:
    """Entry point for running the application."""
    blue_app = BlueApp()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Setup signal handlers with proper typing
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig, lambda s=sig: asyncio.create_task(blue_app.shutdown(s))
        )

    print()
    print(f"Setup page: https://{settings.host_ip}:{settings.port}/setup")
    print()
    print(f"Server running at https://{settings.host_ip}:{settings.port}")
    print()

    config = uvicorn.Config(
        blue_app.app,
        host="0.0.0.0",
        port=settings.port,
        ssl_keyfile=settings.ssl_keyfile,
        ssl_certfile=settings.ssl_certfile,
        loop="asyncio",
        timeout_graceful_shutdown=0,
    )
    server = uvicorn.Server(config=config)
    server.run()


if __name__ == "__main__":
    main()
