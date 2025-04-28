"""FastAPI application module for the bluep collaborative text editor - Windows version."""

import asyncio
import logging
import signal
import sys
import json
import time
import secrets
import hashlib
import base64
import platform
import threading
from io import BytesIO
from typing import Optional, Dict, Any, Tuple, List, Union

from fastapi import FastAPI, WebSocket, Request, HTTPException, WebSocketDisconnect
from fastapi.responses import Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from PIL import Image
import uvicorn
import qrcode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Import from the project's modules
from .auth import TOTPAuth
from .config import Settings
from .models import (
    WebSocketMessage, 
    CertificateVerification, 
    TamperingReport,
    KeyExchangeRequest,
    KeyExchangeResponse,
    KeyExchangeData
)
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
        
        # Initialize certificate fingerprint with empty string
        self.cert_fingerprint = ""
        
        # Mount static files directory for serving JavaScript
        self.app.mount("/static", StaticFiles(directory="static"), name="static")
        
        # Calculate and store certificate fingerprint
        self._calculate_cert_fingerprint()
        
        self._configure_routes()
        
    def _calculate_cert_fingerprint(self) -> None:
        """Calculate SHA-256 fingerprint of the SSL certificate."""
        try:
            with open(settings.ssl_certfile, "rb") as f:
                cert_data = f.read()
                self.cert_fingerprint = hashlib.sha256(cert_data).hexdigest()
                logger.debug(f"Certificate fingerprint: {self.cert_fingerprint}")
        except Exception as e:
            logger.error(f"Error calculating certificate fingerprint: {e}")
            self.cert_fingerprint = None

    def _configure_routes(self) -> None:
        self.app.get("/")(self.get)
        self.app.post("/")(self.post)  # Added POST handler for secure TOTP submission
        self.app.get("/qr-raw")(self.qr_raw)
        self.app.get("/setup")(self.setup)
        self.app.get("/login")(self.login)
        self.app.get("/favicon.png")(self.favicon)
        self.app.websocket("/ws")(self.websocket_endpoint)
        self.app.post("/verify-cert")(self.verify_certificate)
        self.app.post("/key-exchange")(self.key_exchange)
        self.app.post("/tampering-report")(self.tampering_report)
        self.app.post("/csp-report")(self.csp_report)

    async def setup(self, request: Request) -> Response:
        """Serve the TOTP setup page."""
        # Generate fresh QR code base64 string using the auth instance
        qr_base64 = self.auth._generate_qr()

        return templates.TemplateResponse(
            "setup.html",
            {
                "request": request,
                "qr_code": qr_base64,
                "secret_key": self.auth.secret_key,
                "current_token": self.auth.totp.now(),
            },
        )

    async def qr_raw(self) -> Response:
        """Generate and serve the TOTP QR code."""
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            provisioning_uri = self.auth.totp.provisioning_uri("Bluep Room", issuer_name="Bluep")
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img_bytes = BytesIO()
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)

            return Response(content=img_bytes.read(), media_type="image/png")
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            return Response(
                content=json.dumps({"error": "Could not generate QR code"}),
                status_code=500,
                media_type="application/json",
            )

    async def login(self, request: Request) -> Response:
        """Serve the login page."""
        return templates.TemplateResponse("login.html", {"request": request})

    async def get(self, request: Request, response: Response) -> Response:
        """Handle GET request to root - check if user is already authenticated via cookie"""
        try:
            # Check for session cookie
            session_cookie = request.cookies.get("session")
            if session_cookie and self.session_manager.validate_session(session_cookie):
                # User is authenticated, serve the editor
                return templates.TemplateResponse(
                    "editor.html", 
                    {
                        "request": request,
                        "cert_fingerprint": self.cert_fingerprint,
                    }
                )
            else:
                # No valid session, redirect to login
                return RedirectResponse(url="/login")
                
        except Exception as e:
            logger.error(f"Error in GET handler: {e}")
            return Response(
                content=json.dumps({"error": "Internal server error"}),
                status_code=500,
                media_type="application/json",
            )

    async def post(self, request: Request, response: Response) -> Response:
        """Handle POST request for secure TOTP submission"""
        try:
            form_data = await request.form()
            totp_token = form_data.get("totp")
            
            if not totp_token:
                logger.warning("TOTP token missing from submission")
                return templates.TemplateResponse(
                    "login.html", 
                    {"request": request, "error": "TOTP token required"},
                    status_code=400
                )
            
            # Verify TOTP token
            if self.auth.verify_totp(totp_token):
                # Create new session
                session_id = self.session_manager.create_session()
                session_cookie = self.session_manager.generate_session_cookie(session_id)
                
                # Create response with session cookie
                editor_response = templates.TemplateResponse(
                    "editor.html", 
                    {
                        "request": request,
                        "cert_fingerprint": self.cert_fingerprint,
                    }
                )
                
                # Set secure, httpOnly cookie with 3-hour expiry
                editor_response.set_cookie(
                    key="session",
                    value=session_cookie,
                    httponly=True,
                    secure=True,
                    samesite="strict",
                    max_age=10800,  # 3 hours
                )
                
                return editor_response
            else:
                logger.warning("Invalid TOTP token submitted")
                return templates.TemplateResponse(
                    "login.html", 
                    {"request": request, "error": "Invalid TOTP token"},
                    status_code=401
                )
                
        except Exception as e:
            logger.error(f"Error in POST handler: {e}")
            return templates.TemplateResponse(
                "login.html", 
                {"request": request, "error": "An unexpected error occurred"},
                status_code=500
            )

    def _get_script_length(self, script_path: str) -> Optional[int]:
        """Get the length of a script file for integrity checks."""
        try:
            with open(script_path, "r", encoding="utf-8") as f:
                return len(f.read())
        except Exception as e:
            logger.error(f"Error reading script file {script_path}: {e}")
            return None

    async def websocket_endpoint(self, websocket: WebSocket) -> None:
        try:
            await websocket.accept()
            
            # Expect initial authentication message
            auth_message = await websocket.receive_json()
            
            # Validate token
            token = auth_message.get("token")
            if not token:
                logger.warning("No token provided in WebSocket connection")
                await websocket.close(code=1008)  # Policy violation
                return
                
            session_id = self.session_manager.validate_websocket_token(token)
            
            if not session_id:
                logger.warning(f"Invalid token provided: {token[:10]}...")
                await websocket.close(code=1008)  # Policy violation
                return
                
            # Mark token as used - single use only
            self.session_manager.websocket_tokens.pop(token, None)
            
            # Register connection with WebSocket manager
            await self.ws_manager.connect(websocket, session_id)
            
            logger.info(f"WebSocket connection established for session {session_id}")
            
            # Generate and send a fresh WebSocket token for reconnection
            new_token = self.session_manager.create_websocket_token(session_id)
            await websocket.send_json({
                "type": "refresh_token",
                "token": new_token
            })
            
            try:
                # Process messages
                async for data in websocket.iter_json():
                    try:
                        message = WebSocketMessage(**data)
                        
                        # Process based on message type
                        if message.type == "content_update":
                            await self.ws_manager.broadcast(message, websocket, session_id)
                        else:
                            logger.warning(f"Unknown message type: {message.type}")
                            
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        continue
                        
            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for session {session_id}")
            finally:
                await self.ws_manager.disconnect(websocket)
                
        except Exception as e:
            logger.error(f"Error in WebSocket connection: {e}")
            await websocket.close(code=1011)  # Internal error

    async def verify_certificate(self, request: Request) -> Response:
        """Verify certificate hasn't been replaced by a proxy"""
        try:
            data = await request.json()
            cert_verification = CertificateVerification(**data)
            
            client_fingerprint = cert_verification.fingerprint
            
            # Skip verification if we couldn't calculate our fingerprint
            if not self.cert_fingerprint:
                logger.warning("Server couldn't calculate certificate fingerprint, skipping verification")
                return Response(
                    content=json.dumps({"verified": True, "reason": "server_no_fingerprint"}),
                    media_type="application/json"
                )
            
            # Compare fingerprints
            if client_fingerprint == self.cert_fingerprint:
                return Response(
                    content=json.dumps({"verified": True}),
                    media_type="application/json"
                )
            else:
                logger.warning(f"Certificate fingerprint mismatch: client={client_fingerprint}, server={self.cert_fingerprint}")
                return Response(
                    content=json.dumps({
                        "verified": False,
                        "server_fingerprint": self.cert_fingerprint, 
                        "client_fingerprint": client_fingerprint
                    }),
                    media_type="application/json"
                )
        except Exception as e:
            logger.error(f"Error in certificate verification: {e}")
            return Response(
                status_code=500,
                content=json.dumps({"error": "Internal server error during certificate verification"}),
                media_type="application/json"
            )

    async def key_exchange(self, request: Request) -> Response:
        """Handle key exchange - client uses token-based key derivation"""
        try:
            data = await request.json()
            key_request = KeyExchangeRequest(**data)
            
            # Validate session token
            session_id = self.session_manager.validate_session(key_request.session_token)
            if not session_id:
                logger.warning(f"Invalid session token in key exchange")
                raise HTTPException(status_code=401, detail="Invalid session token")
            
            # Generate a single-use WebSocket authentication token
            ws_token = self.session_manager.create_websocket_token(session_id)
            
            # For now, we don't actually need to derive a shared key
            # because the client will derive its key from the token
            exchange_data = KeyExchangeData(
                websocket_token=ws_token,
                server_key=None  # No server key needed
            )
            
            response = KeyExchangeResponse(
                success=True,
                data=exchange_data
            )
            
            logger.debug(f"Key exchange completed for session {session_id}")
            
            return Response(
                content=response.model_dump_json(),
                media_type="application/json"
            )
            
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Error in key exchange: {e}")
            return Response(
                status_code=500,
                content=json.dumps({"error": "Internal server error during key exchange"}),
                media_type="application/json"
            )
    
    async def tampering_report(self, request: Request) -> Response:
        """Handle tampering reports from clients"""
        try:
            report_data = await request.json()
            report = TamperingReport(**report_data)
            
            logger.warning(f"Tampering detected: {report.model_dump()}")
            
            # Invalidate the session if there's a token
            token = report.token
            if token:
                session_id = self.session_manager.validate_websocket_token(token)
                if session_id:
                    # Remove all tokens associated with this session
                    tokens_to_remove = []
                    for session_token, sess_id in self.session_manager.websocket_tokens.items():
                        if sess_id == session_id:
                            tokens_to_remove.append(session_token)
                    
                    for token in tokens_to_remove:
                        self.session_manager.websocket_tokens.pop(token, None)
                    
                    # Remove the session
                    if session_id in self.session_manager.sessions:
                        self.session_manager.sessions.pop(session_id)
            
            return Response(status_code=204)
        except Exception as e:
            logger.error(f"Error handling tampering report: {e}")
            return Response(status_code=500)
    
    async def csp_report(self, request: Request) -> Response:
        """Handle CSP violation reports"""
        try:
            report_data = await request.json()
            logger.warning(f"CSP violation: {report_data}")
            return Response(status_code=204)
        except Exception as e:
            logger.error(f"Error handling CSP report: {e}")
            return Response(status_code=500)
        
    async def favicon(self, request: Request, key: Optional[str] = None) -> Response:
        """Serve the favicon, requiring auth via session cookie or key parameter"""
        # No authentication required for favicon.png
        img = Image.new("RGB", (32, 32), settings.blue_color)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return Response(content=buffer.getvalue(), media_type="image/png")

    async def shutdown(self) -> None:
        """Handle graceful shutdown of the application."""
        print("\nShutting down...")
        for connection in self.ws_manager.active_connections:
            await connection.close()

    def windows_signal_handler(self) -> None:
        """Handle Ctrl+C on Windows"""
        loop = asyncio.get_event_loop()
        loop.create_task(self.shutdown())
        loop.stop()

    def main(self) -> None:
        # Set up the event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Windows-specific signal handling (since add_signal_handler is not supported)
        if platform.system() == "Windows":
            # Use a separate thread to handle keyboard interrupts
            def signal_handler_thread():
                try:
                    # This will block until Ctrl+C is pressed
                    signal.signal(signal.SIGINT, lambda sig, frame: self.windows_signal_handler())
                    while True:
                        time.sleep(1)
                except (KeyboardInterrupt, SystemExit):
                    self.windows_signal_handler()

            # Start signal handler in a separate thread
            threading.Thread(target=signal_handler_thread, daemon=True).start()
        else:
            # Unix-style signal handling
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.shutdown()))

        print(f"\nSetup page: https://{settings.host_ip}:{settings.port}/setup\n")
        print(f"Server running at https://{settings.host_ip}:{settings.port}\n")

        config = uvicorn.Config(
            self.app,
            host="0.0.0.0",
            port=settings.port,
            ssl_keyfile=settings.ssl_keyfile,
            ssl_certfile=settings.ssl_certfile,
            loop="asyncio",
        )
        server = uvicorn.Server(config=config)
        server.run()

def main() -> None:
    blue_app = BlueApp()
    blue_app.main()

if __name__ == "__main__":
    main()
