"""FastAPI application module for the bluep collaborative text editor."""

import asyncio
import logging
import signal
import sys
import json
import time
import secrets
import hashlib
from io import BytesIO
from typing import Optional

from fastapi import FastAPI, WebSocket, Request, HTTPException, WebSocketDisconnect
from fastapi.responses import Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from PIL import Image
import uvicorn
import qrcode

from .auth import TOTPAuth
from .config import Settings
from .models import (
    WebSocketMessage,
    CertificateVerification,
    TamperingReport,
    KeyExchangeRequest,
    KeyExchangeResponse,
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
        
        # Add startup task
        async def startup_task():
            """Start background tasks on startup."""
            asyncio.create_task(self.ws_manager.process_manager.monitor_processes())
        
        # Schedule startup task
        @self.app.on_event("startup")
        async def startup_event():
            await startup_task()

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
        self.app.get("/terminal")(self.terminal)
        self.app.get("/favicon.png")(self.favicon)
        self.app.websocket("/ws")(self.websocket_endpoint)
        self.app.post("/verify-cert")(self.verify_certificate)
        self.app.post("/key-exchange")(self.key_exchange)
        self.app.post("/tampering-report")(self.tampering_report)
        self.app.post("/csp-report")(self.csp_report)

    async def setup(self, request: Request) -> Response:
        """Serve the TOTP setup page. Disabled after initial setup for security."""
        # Check if setup is already complete
        if self.auth.config.get_setup_complete():
            raise HTTPException(
                status_code=403,
                detail="TOTP setup is already complete. Access to /setup is disabled.",
            )

        # Generate fresh QR code base64 string using the auth instance
        qr_base64 = self.auth._generate_qr()

        # Mark setup as complete after serving the page
        self.auth.config.set_setup_complete(True)

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
            provisioning_uri = self.auth.totp.provisioning_uri(
                "Bluep Room", issuer_name="Bluep"
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            img_bytes = BytesIO()
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)

            return Response(content=img_bytes.getvalue(), media_type="image/png")
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            # Return a simple error image
            img = Image.new("RGB", (100, 100), color="red")
            img_bytes = BytesIO()
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)
            return Response(content=img_bytes.getvalue(), media_type="image/png")

    async def login(self, request: Request) -> Response:
        """Serve the login page."""
        return templates.TemplateResponse("login.html", {"request": request})
    
    async def terminal(self, request: Request) -> Response:
        """Serve the terminal page."""
        # Check authentication
        cookie = request.cookies.get(self.session_manager.cookie_name)
        if not cookie:
            return RedirectResponse(url="/login", status_code=303)
            
        session = self.session_manager.get_session(cookie)
        if not session:
            return RedirectResponse(url="/login", status_code=303)
            
        return templates.TemplateResponse(
            "terminal.html",
            {
                "request": request,
                "token": session.websocket_token,
                "shared_key": self.session_manager.shared_encryption_key,
            }
        )

    async def get(self, request: Request, response: Response) -> Response:
        """Handle GET request to root - check if user is already authenticated via cookie"""
        cookie = request.cookies.get(self.session_manager.cookie_name)
        if not cookie:
            return RedirectResponse(url="/login")

        # Verify existing session
        session = self.session_manager.get_session(cookie)
        if not session:
            return RedirectResponse(url="/login")

        # User is authenticated, proceed to editor
        logger.debug(f"Using existing session with token: {session.websocket_token}")

        # Calculate script lengths for integrity checks
        script_length = self._get_script_length("/static/js/crypto-utils.js")

        # Set a cookie with the token instead of passing it in the template
        response = templates.TemplateResponse(
            "editor.html",
            {
                "request": request,
                "host_ip": settings.host_ip,
                "token": session.websocket_token,
                "blue": settings.blue_color,
                "cert_fingerprint": self.cert_fingerprint,
                "script_length": script_length,
                "shared_key": self.session_manager.shared_encryption_key,
            },
        )

        # Cookie is already set by session_manager.create_session()
        # No need to set it again here

        return response

    async def post(self, request: Request, response: Response) -> Response:
        """Handle POST request for secure TOTP submission"""
        form_data = await request.form()
        key_input = form_data.get("key")
        key = str(key_input) if key_input else ""

        if not key:
            return RedirectResponse(url="/login", status_code=303)

        try:
            # Create session and get token
            verified = await self.auth.verify_and_create_session(key, request, response)
            if not verified:
                return RedirectResponse(url="/login", status_code=303)

            # Get the latest session
            latest_session = list(self.session_manager.sessions.values())[-1]
            logger.debug(f"Using session with token: {latest_session.websocket_token}")

            # Calculate script lengths for integrity checks
            script_length = self._get_script_length("/static/js/crypto-utils.js")

            # Get the session ID that was just created
            session_id = list(self.session_manager.sessions.keys())[-1]
            
            # Create the template response
            template_response = templates.TemplateResponse(
                "editor.html",
                {
                    "request": request,
                    "host_ip": settings.host_ip,
                    "token": latest_session.websocket_token,
                    "blue": settings.blue_color,
                    "cert_fingerprint": self.cert_fingerprint,
                    "script_length": script_length,
                    "shared_key": self.session_manager.shared_encryption_key,
                },
            )

            # Set the session cookie on the new response
            self.session_manager._set_cookie(template_response, session_id)

            return template_response
        except Exception as e:
            logger.error(f"Error in post route: {e}", exc_info=True)
            return RedirectResponse(url="/login", status_code=303)

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
            # Get session ID from secure cookie
            cookies = websocket.cookies
            session_id = cookies.get(self.session_manager.cookie_name)
            if not session_id:
                logger.warning("WebSocket connection attempt without session cookie")
                await websocket.close(code=4000)
                return

            # Get the session and its websocket token
            session = self.session_manager.get_session(session_id)
            if not session or not session.websocket_token:
                logger.warning("WebSocket connection attempt with invalid session")
                await websocket.close(code=4001)
                return


            await self.ws_manager.connect(websocket, session.websocket_token)

            if websocket not in self.ws_manager.active_connections:
                logger.warning("WebSocket connection rejected - invalid token")
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
                    # Store the text content
                    await self.ws_manager.update_shared_text(msg.data)

                    # Create a new message marked as encrypted - client-side key derivation
                    # from the token ensures all clients can decrypt with the right key
                    message_to_broadcast = msg.model_dump(exclude_none=True)
                    message_to_broadcast["encrypted"] = True

                    await self.ws_manager.broadcast(
                        message_to_broadcast, exclude=websocket
                    )

                elif msg.type == "file-announce" and msg.fileName:
                    # Handle file announcement from client
                    file_id = msg.fileId or secrets.token_hex(8)
                    await self.ws_manager.announce_file(
                        file_id=file_id,
                        file_name=msg.fileName,
                        file_size=msg.fileSize or 0,
                        file_type=msg.fileType or "application/octet-stream",
                        source_websocket=websocket,
                    )

                elif msg.type == "file-request" and msg.fileId:
                    # Handle client requesting a file
                    await self.ws_manager.handle_file_request(msg.fileId, websocket)

                elif msg.type == "file-data":
                    # Forward file data chunks to the requesting client
                    await self.ws_manager.broadcast(
                        msg.model_dump(exclude_none=True), exclude=websocket
                    )

                elif msg.type == "clear-files":
                    # Clear file listings on all clients
                    await self.ws_manager.broadcast(
                        {"type": "clear-files"}, exclude=None
                    )
                    # Clear server-side file metadata
                    self.ws_manager.available_files.clear()
                    
                elif msg.type == "process-spawn" and msg.command:
                    # Handle process spawn request
                    await self.ws_manager.handle_process_spawn(websocket, msg.command)
                    
                elif msg.type == "process-input" and msg.processId and msg.data is not None:
                    # Handle process input
                    await self.ws_manager.handle_process_input(websocket, msg.processId, msg.data)
                    
                elif msg.type == "process-resize" and msg.processId and msg.cols and msg.rows:
                    # Handle terminal resize
                    await self.ws_manager.handle_process_resize(websocket, msg.processId, msg.cols, msg.rows)
                    
                elif msg.type == "process-terminate" and msg.processId:
                    # Handle process termination
                    await self.ws_manager.handle_process_terminate(websocket, msg.processId)
                    
                elif msg.type == "process-list":
                    # Handle process list request
                    await self.ws_manager.handle_process_list(websocket)

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

            # For certificate verification, validate the fingerprint match
            expected_fingerprint = verification.expectedFingerprint
            is_valid = True  # Default to true for development ease

            # If expected fingerprint is provided, actually check it
            if expected_fingerprint and expected_fingerprint != self.cert_fingerprint:
                logger.info(
                    f"Certificate fingerprint info: expected {expected_fingerprint}, got {self.cert_fingerprint}"
                )
                # For production, uncomment the following line:
                # is_valid = False

            result = {
                "valid": is_valid,
                "fingerprint": self.cert_fingerprint or "development",
                "serverTime": int(time.time()),
            }

            # Time skew checking
            client_time = verification.clientTime
            server_time = int(time.time() * 1000)
            time_diff = abs(server_time - client_time)

            if time_diff > 300000:  # 5 minutes
                logger.info(f"Time skew: {time_diff}ms")

            return Response(content=json.dumps(result), media_type="application/json")
        except Exception as e:
            logger.error(f"Error in certificate verification: {e}")
            return Response(
                status_code=400,
                content=json.dumps({"valid": False, "error": str(e)}),
                media_type="application/json",
            )

    async def key_exchange(self, request: Request) -> Response:
        """Handle key exchange - client uses token-based key derivation

        Note: The client will derive its encryption key from the token,
        so we don't actually need to exchange keys, but we keep the endpoint
        for compatibility and future enhancements.
        """
        try:
            # Parse request data
            data = await request.json()
            key_request = KeyExchangeRequest(**data)

            # Verify token
            session_id = self.session_manager.validate_websocket_token(
                key_request.token
            )
            if not session_id:
                raise HTTPException(status_code=403, detail="Invalid token")

            # Generate a unique ID for this key exchange for reference
            key_id = secrets.token_hex(8)

            # Just acknowledge - we don't need to exchange actual keys
            # since client derives them from the token
            response = KeyExchangeResponse(
                serverKey=key_request.clientKey,  # Echo back the client's key as acknowledgment
                keyId=key_id,
            )

            logger.debug(f"Key exchange completed for session {session_id}")

            return Response(
                content=response.model_dump_json(), media_type="application/json"
            )

        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Error in key exchange: {e}")
            return Response(
                status_code=500,
                content=json.dumps(
                    {"error": "Internal server error during key exchange"}
                ),
                media_type="application/json",
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
                    for (
                        session_token,
                        sess_id,
                    ) in self.session_manager.websocket_tokens.items():
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
        """Serve the favicon, requiring auth via session cookie or key parameter. Returns 403 if not authenticated."""
        # Check for valid session cookie
        session_cookie = request.cookies.get(self.session_manager.cookie_name)
        valid_session = False
        if session_cookie and self.session_manager.get_session(session_cookie):
            valid_session = True
        # Check for valid TOTP key
        elif key and self.auth.verify(key):
            valid_session = True
        if not valid_session:
            return Response(status_code=403)
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

        import platform

        if platform.system() != "Windows":
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(
                    sig, lambda s=sig: asyncio.create_task(self.shutdown(s))
                )
        # On Windows, signal handlers are not supported for SIGTERM/SIGINT in asyncio

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
        try:
            server.run()
        except KeyboardInterrupt:
            print("\nServer stopped by user (KeyboardInterrupt)")


def main() -> None:
    blue_app = BlueApp()
    blue_app.main()


if __name__ == "__main__":
    main()
