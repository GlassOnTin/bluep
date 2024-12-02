from fastapi import Response
from fastapi.security import APIKeyCookie
import secrets
from datetime import datetime, timedelta
from typing import Optional, Literal

from bluep.models import SessionData

class SessionManager:
    def __init__(self, cookie_name: str = "bluep_session", cookie_max_age: int = 3600):
        self.sessions = {}
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.cookie_security = APIKeyCookie(name=cookie_name, auto_error=False)

    def create_session(self, username: str, response: Response) -> str:
        session_id = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(seconds=self.cookie_max_age)

        self.sessions[session_id] = SessionData(
            username=username,
            expiry=expiry,
            last_totp_use=""
        )

        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            max_age=self.cookie_max_age,
            httponly=True,
            secure=True,
            samesite="strict"
        )

        return session_id

    def get_session(self, session_id: str) -> Optional[SessionData]:
        session = self.sessions.get(session_id)
        if not session:
            return None

        if datetime.now() > session.expiry:
            del self.sessions[session_id]
            return None

        return session

    def validate_totp_use(self, session_id: str, totp_code: str) -> bool:
        session = self.get_session(session_id)
        if not session:
            return False

        if session.last_totp_use == totp_code:
            return False

        session.last_totp_use = totp_code
        return True
