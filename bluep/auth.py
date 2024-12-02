"""Authentication module for the bluep collaborative text editor.

This module handles TOTP-based authentication, QR code generation, and rate limiting
for the bluep application. It provides secure access control through time-based
one-time passwords and protects against brute force attempts.
"""
import base64
import secrets
import time
from io import BytesIO
from typing import Dict, Tuple

import pyotp
import qrcode
from fastapi import HTTPException, Request, Response

from bluep.models import SessionData
from bluep.secure_config import SecureConfig
from bluep.session_manager import SessionManager


class TOTPAuth:
    """Handles TOTP-based authentication and rate limiting.

    This class manages TOTP secret generation, QR code creation, and authentication
    verification with rate limiting to prevent brute force attacks.

    Attributes:
        config: Secure configuration manager for storing TOTP secrets
        secret_key: TOTP secret key for generating codes
        session_manager: Manager for user sessions
        totp: TOTP generator instance
        qr_base64: Base64 encoded QR code for TOTP setup
        max_attempts: Maximum failed authentication attempts before lockout
        lockout_time: Duration in seconds for authentication lockout
    """

    def __init__(self) -> None:
        """Initialize the TOTP authentication manager."""
        self.config = SecureConfig()
        self.secret_key = self.config.load_secret()

        if not self.secret_key:
            self.secret_key = pyotp.random_base32()
            self.config.save_secret(self.secret_key)

        self.session_manager = SessionManager()
        self.totp = pyotp.TOTP(self.secret_key)
        self.qr_base64 = self._generate_qr()
        self._failed_attempts: Dict[str, Tuple[int, float]] = {}
        self.max_attempts = 3
        self.lockout_time = 300  # 5 minutes

    async def verify_and_create_session(
        self, key: str, request: Request, response: Response
    ) -> bool:
        """Verify TOTP code and create a new session.

        Args:
            key: TOTP code to verify
            request: FastAPI request object
            response: FastAPI response object

        Returns:
            bool: True if authentication successful

        Raises:
            HTTPException: If authentication fails or rate limit exceeded
        """
        client_host = request.client.host if request.client else "0.0.0.0"

        if not self._check_rate_limit(client_host):
            raise HTTPException(status_code=429, detail="Too many failed attempts")

        if not self.totp.verify(key):
            self._record_failed_attempt(client_host)
            raise HTTPException(status_code=403, detail="Invalid TOTP key")

        session_id = self.session_manager.create_session(
            username=f"user_{secrets.token_hex(4)}", response=response
        )

        if not self.session_manager.validate_totp_use(session_id, key):
            raise HTTPException(status_code=403, detail="TOTP code already used")

        return True

    def _generate_qr(self) -> str:
        """Generate QR code for TOTP setup.

        Returns:
            str: Base64 encoded QR code image
        """
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            provisioning_uri = self.totp.provisioning_uri(
                "Bluep Room", issuer_name="Bluep"
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            buffered = BytesIO()
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(buffered, format="PNG")
            buffered.seek(0)
            qr_data = base64.b64encode(buffered.getvalue()).decode()
            return qr_data
        except Exception as e:
            print(f"QR generation error: {e}")
            return ""

    def verify(self, key: str) -> bool:
        """Verify a TOTP code.

        Args:
            key: TOTP code to verify

        Returns:
            bool: True if code is valid
        """
        return bool(key) and self.totp.verify(key)

    def _check_rate_limit(self, ip: str) -> bool:
        """Check if an IP has exceeded the rate limit.

        Args:
            ip: IP address to check

        Returns:
            bool: True if under rate limit
        """
        if ip in self._failed_attempts:
            attempts, timestamp = self._failed_attempts[ip]
            if attempts >= self.max_attempts:
                if time.time() - timestamp < self.lockout_time:
                    return False
                del self._failed_attempts[ip]
        return True

    def _record_failed_attempt(self, ip: str) -> None:
        """Record a failed authentication attempt.

        Args:
            ip: IP address of the failed attempt
        """
        if ip in self._failed_attempts:
            attempts, _ = self._failed_attempts[ip]
            self._failed_attempts[ip] = (attempts + 1, time.time())
        else:
            self._failed_attempts[ip] = (1, time.time())

    async def verify_session(self, request: Request) -> SessionData:
        """Verify an existing session.

        Args:
            request: FastAPI request object

        Returns:
            SessionData: Valid session data

        Raises:
            HTTPException: If session is invalid or expired
        """
        cookie = request.cookies.get(self.session_manager.cookie_name)
        if not cookie:
            raise HTTPException(status_code=401, detail="No session found")

        session = self.session_manager.get_session(cookie)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")

        return session
