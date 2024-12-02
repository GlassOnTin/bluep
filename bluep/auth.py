# bluep/auth.py
from fastapi import HTTPException, Query, Request, Response
from fastapi.security import APIKeyCookie
from typing import Optional
import pyotp
import qrcode
from io import BytesIO
import base64
import secrets
import time
from pydantic import BaseModel
from datetime import datetime, timedelta

from bluep.models import SessionData
from bluep.secure_config import SecureConfig
from bluep.session_manager import SessionManager

class TOTPAuth:
    def __init__(self):
        self.config = SecureConfig()
        self.secret_key = self.config.load_secret()

        if not self.secret_key:
            self.secret_key = pyotp.random_base32()
            self.config.save_secret(self.secret_key)

        self.totp = pyotp.TOTP(self.secret_key)
        self.qr_base64 = self._generate_qr()

        self.session_manager = SessionManager()

        self._failed_attempts = {}
        self.max_attempts = 3
        self.lockout_time = 0  # 5 minutes

    def _generate_qr(self) -> str:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        provisioning_uri = self.totp.provisioning_uri("Bluep Room", issuer_name="Bluep")
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        return base64.b64encode(buffered.getvalue()).decode()

    def verify(self, key: str) -> bool:
        return bool(key) and self.totp.verify(key)

    def _check_rate_limit(self, ip: str) -> bool:
        if ip in self._failed_attempts:
            attempts, timestamp = self._failed_attempts[ip]
            if attempts >= self.max_attempts:
                if time.time() - timestamp < self.lockout_time:
                    return False
                del self._failed_attempts[ip]
        return True

    def _record_failed_attempt(self, ip: str):
        if ip in self._failed_attempts:
            attempts, _ = self._failed_attempts[ip]
            self._failed_attempts[ip] = (attempts + 1, time.time())
        else:
            self._failed_attempts[ip] = (1, time.time())

    async def verify_and_create_session(self, key: str, request: Request, response: Response) -> bool:
        client_ip = request.client.host

        if not self._check_rate_limit(client_ip):
            raise HTTPException(status_code=429, detail="Too many failed attempts")

        if not self.totp.verify(key):
            self._record_failed_attempt(client_ip)
            raise HTTPException(status_code=403, detail="Invalid TOTP key")

        session_id = self.session_manager.create_session(
            username=f"user_{secrets.token_hex(4)}",
            response=response
        )

        if not self.session_manager.validate_totp_use(session_id, key):
            raise HTTPException(status_code=403, detail="TOTP code already used")

        return True

    async def verify_session(self, request: Request) -> SessionData:
        cookie = request.cookies.get(self.session_manager.cookie_name)
        if not cookie:
            raise HTTPException(status_code=401, detail="No session found")

        session = self.session_manager.get_session(cookie)
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")

        return session


