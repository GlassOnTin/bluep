"""Session management for bluep.

This module handles user session creation, validation, and cleanup for
authenticated users of the collaborative editor.
"""
from datetime import datetime, timedelta
import secrets
from typing import Dict, Optional

from fastapi import Response
from fastapi.security import APIKeyCookie

from bluep.models import SessionData

class SessionManager:
    """Manages user sessions with secure cookie-based authentication.

    Handles session lifecycle including creation, validation, and expiration
    of user sessions with secure cookie storage.
    """

    def __init__(self, cookie_name: str = "bluep_session", cookie_max_age: int = 3600):
        """Initialize session manager.

        Args:
            cookie_name: Name for session cookie
            cookie_max_age: Session lifetime in seconds
        """
        self.sessions: Dict[str, SessionData] = {}
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.cookie_security = APIKeyCookie(name=cookie_name, auto_error=False)

    def create_session(self, username: str, response: Response) -> str:
        """Create new user session with secure cookie.

        Args:
            username: User identifier
            response: FastAPI response for cookie setting

        Returns:
            str: New session identifier
        """
        session_id = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(seconds=self.cookie_max_age)

        self.sessions[session_id] = SessionData(
            username=username, expiry=expiry, last_totp_use=""
        )

        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            max_age=self.cookie_max_age,
            httponly=True,
            secure=True,
            samesite="strict",
        )

        return session_id

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session data if valid and not expired.

        Args:
            session_id: Session identifier to look up

        Returns:
            Optional[SessionData]: Session data if valid
        """
        session = self.sessions.get(session_id)
        if not session:
            return None

        if datetime.now() > session.expiry:
            del self.sessions[session_id]
            return None

        return session

    def validate_totp_use(self, session_id: str, totp_code: str) -> bool:
        """Validate TOTP code hasn't been reused.

        Args:
            session_id: Session to validate against
            totp_code: TOTP code to check

        Returns:
            bool: True if code is valid and unused
        """
        session = self.get_session(session_id)
        if not session:
            return False

        if session.last_totp_use == totp_code:
            return False

        session.last_totp_use = totp_code
        return True
