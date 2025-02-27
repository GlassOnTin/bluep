"""FastAPI application module for the bluep collaborative text editor."""

import asyncio
import logging
import signal
import sys
import json
import time
import secrets
import hashlib
import base64
from io import BytesIO
from typing import Optional, Dict, Any

from fastapi import FastAPI, WebSocket, Request, HTTPException, WebSocketDisconnect
from fastapi.responses import Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from PIL import Image
import uvicorn
import qrcode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

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
        """Generate and serve the TOTP QR code.

        Returns:
            Response: PNG image of the QR code
        """
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            provisioning_uri = self.auth.totp.provisioning_uri("Bluep Room", issuer_name="Bluep")
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img_bytes = BytesIO()
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)

            return Response(
                content=img_bytes.getvalue(),
                media_type="image/png"
            )
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            # Return a simple error image
            img = Image.new('RGB', (100, 100), color='red')
            img_bytes = BytesIO()
            img.save(img_bytes, format='PNG')
            img_bytes.seek(0)
            return Response(
                content=img_bytes.getvalue(),
                media_type="image/png"
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
            
            # Calculate script lengths for integrity checks
            script_length = self._get_script_length("/static/js/crypto-utils.js")

            return templates.TemplateResponse(
                "editor.html",
                {
                    "request": request,
                    "host_ip": settings.host_ip,
                    "key": key,
                    "token": latest_session.websocket_token,
                    "blue": settings.blue_color,
                    "cert_fingerprint": self.cert_fingerprint,
                    "script_length": script_length,
                },
            )
        except Exception as e:
            logger.error(f"Error in get route: {e}", exc_info=True)
            return RedirectResponse(url="/login")
    
    def _get_script_length(self, script_path: str) -> int:
        """Get the length of a script file for integrity checks."""
        try:
            with open(script_path.lstrip("/"), "r") as f:
                return len(f.read())
        except Exception as e:
            logger.error(f"Error reading script file {script_path}: {e}")
            return 0

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
                    # For encrypted messages, store the encrypted form
                    # Clients will decrypt the content on their side
                    await self.ws_manager.update_shared_text(msg.data)
                    
                    # Preserve the encrypted flag when broadcasting
                    message_data = msg.model_dump(exclude_none=True)
                    await self.ws_manager.broadcast(message_data, exclude=websocket)

        except WebSocketDisconnect:
            if websocket in self.ws_manager.active_connections:
                await self.ws_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            if websocket in self.ws_manager.active_connections:
                await self.ws_manager.disconnect(websocket)

    async def verify_certificate(self, request: Request) -> Response:
        """Verify certificate hasn't been replaced by a proxy"""
        try:
            client_data = await request.json()
            verification = CertificateVerification(**client_data)
            
            # Compare the fingerprint
            expected_fingerprint = verification.expectedFingerprint
            actual_fingerprint = self.cert_fingerprint
            
            result = {
                "valid": True, 
                "fingerprint": actual_fingerprint,
                "serverTime": int(time.time())
            }
            
            if expected_fingerprint and expected_fingerprint != actual_fingerprint:
                result["valid"] = False
                logger.warning(f"Certificate fingerprint mismatch: expected {expected_fingerprint}, got {actual_fingerprint}")
            
            # Check for time skew which could indicate replay attacks
            client_time = verification.clientTime
            server_time = int(time.time() * 1000)
            time_diff = abs(server_time - client_time)
            
            if time_diff > 300000:  # 5 minutes
                result["valid"] = False
                logger.warning(f"Excessive time skew: {time_diff}ms")
                
            return Response(
                content=json.dumps(result),
                media_type="application/json"
            )
        except Exception as e:
            logger.error(f"Error in certificate verification: {e}")
            return Response(
                status_code=400,
                content=json.dumps({"valid": False, "error": str(e)}),
                media_type="application/json"
            )
    
    async def key_exchange(self, request: Request) -> Response:
        """Perform secure key exchange using ECDH"""
        try:
            # Parse request data
            data = await request.json()
            key_request = KeyExchangeRequest(**data)
            
            # Verify token
            session_id = self.session_manager.validate_websocket_token(key_request.token)
            if not session_id:
                raise HTTPException(status_code=403, detail="Invalid token")
            
            # Get client's public key
            try:
                client_key_raw = base64.b64decode(key_request.clientKey)
            except Exception as e:
                logger.error(f"Error decoding client key: {e}")
                raise HTTPException(status_code=400, detail="Invalid client key format")
            
            # Generate server's key pair
            server_private_key = ec.generate_private_key(ec.SECP256R1())
            server_public_key = server_private_key.public_key()
            
            # Serialize public key for transmission
            server_public_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Serialize private key for storage
            server_private_bytes = server_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Store key exchange data in session
            session = self.session_manager.get_session(session_id)
            if session:
                # Add key_exchange_data attribute since it's not in the Pydantic model
                session.key_exchange_data = KeyExchangeData(
                    server_private_key=server_private_bytes,
                    client_public_key=client_key_raw
                )
            
            # Generate a unique ID for this key exchange
            key_id = secrets.token_hex(8)
            
            # Create response
            response = KeyExchangeResponse(
                serverKey=base64.b64encode(server_public_bytes).decode(),
                keyId=key_id
            )
            
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
        
    async def favicon(self, key: Optional[str] = None) -> Response:
        """Serve the favicon, requiring auth if no key is provided"""
        # If key is provided, it was already authenticated via the route
        # If no key is provided, return 403 Forbidden
        if key is None:
            return Response(status_code=403, content="Authentication required")
            
        img = Image.new("RGB", (32, 32), settings.blue_color)
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return Response(content=buffer.getvalue(), media_type="image/png")

    async def shutdown(self, signal_type: signal.Signals) -> None:
        """Handle graceful shutdown of the application."""
        print(f"\nReceived {signal_type.name}, shutting down...")
        for connection in self.ws_manager.active_connections:
            await connection.close()
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
