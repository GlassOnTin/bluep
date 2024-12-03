"""FastAPI application module for the bluep collaborative text editor."""

import asyncio
import logging
import signal
import sys
from io import BytesIO
from typing import Optional

from fastapi import FastAPI, WebSocket, Request, HTTPException, WebSocketDisconnect
from fastapi.responses import Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from PIL import Image
import uvicorn

from .auth import TOTPAuth
from .config import Settings
from .models import WebSocketMessage
from .middleware import configure_security
from .websocket_manager import WebSocketManager

# Configure debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory="templates")
settings = Settings()

class BlueApp:
    def __init__(self) -> None:
        self.app = FastAPI()
        self.auth = TOTPAuth()
        self.session_manager = self.auth.session_manager
        self.ws_manager = WebSocketManager(session_manager=self.session_manager)
        configure_security(self.app)
        self._configure_routes()

    def _configure_routes(self) -> None:
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

    async def get(self, request: Request, response: Response, key: Optional[str] = None) -> Response:
        if not key:
            return RedirectResponse(url="/login")

        try:
            # Create session and get token
            verified = await self.auth.verify_and_create_session(key, request, response)
            if not verified:
                return RedirectResponse(url="/login")

            # Get the latest session
            latest_session = list(self.session_manager.sessions.values())[-1]
            logger.debug(f"Using session with token: {latest_session.websocket_token}")

            return templates.TemplateResponse(
                "editor.html",
                {
                    "request": request,
                    "host_ip": settings.host_ip,
                    "key": key,
                    "token": latest_session.websocket_token,
                    "blue": settings.blue_color,
                },
            )
        except Exception as e:
            logger.error(f"Error in get route: {e}", exc_info=True)
            return RedirectResponse(url="/login")

    async def websocket_endpoint(self, websocket: WebSocket) -> None:
        try:
            token = websocket.query_params.get('token')
            if not token:
                await websocket.close(code=4000)
                return

            logger.debug(f"WS connect attempt. Token: {token}")
            logger.debug(f"Valid tokens: {list(self.session_manager.websocket_tokens.keys())}")

            await self.ws_manager.connect(websocket, token)

            if websocket not in self.ws_manager.active_connections:
                await websocket.close(code=4001)
                return

            while True:
                raw_msg = await websocket.receive_text()
                if not raw_msg:
                    continue

                if raw_msg == '{"type": "pong"}':
                    await self.ws_manager.handle_pong(websocket)
                    continue

                msg = WebSocketMessage.model_validate_json(raw_msg)
                if msg.type == "content" and msg.data is not None:
                    self.ws_manager.update_shared_text(msg.data)
                    await self.ws_manager.broadcast(msg.model_dump(exclude_none=True), exclude=websocket)

        except WebSocketDisconnect:
            if websocket in self.ws_manager.active_connections:
                await self.ws_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            if websocket in self.ws_manager.active_connections:
                await self.ws_manager.disconnect(websocket)

    async def shutdown(signal_type: signal.Signals) -> None:
        """Handle graceful shutdown of the application."""
        print(f"\nReceived {signal_type.name}, shutting down...")
        for client in ws_manager.active_connections:
            await client.close()
        sys.exit(0)

    async def favicon(self, key: Optional[str] = None) -> Response:
        """Serve the favicon without auth check"""
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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.shutdown(s)))

        print(f"\nSetup page: https://{settings.host_ip}:{settings.port}/setup\n")
        print(f"Server running at https://{settings.host_ip}:{settings.port}\n")

        config = uvicorn.Config(
            self.app,
            host="0.0.0.0",
            port=settings.port,
            ssl_keyfile=settings.ssl_keyfile,
            ssl_certfile=settings.ssl_certfile,
            loop="asyncio",
            timeout_graceful_shutdown=0,
        )
        server = uvicorn.Server(config=config)
        server.run()

def main() -> None:
    blue_app = BlueApp()
    blue_app.main()

if __name__ == "__main__":
    main()
