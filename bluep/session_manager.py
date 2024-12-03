"""Session management for bluep.

This module handles user session creation, validation, and cleanup for
authenticated users of the collaborative editor.
"""

from datetime import datetime, timedelta
import secrets
from typing import Dict, Optional
import logging

from fastapi import Response, Cookie
from fastapi.security import APIKeyCookie

from bluep.models import SessionData

logger = logging.getLogger(__name__)

class SessionManager:
    """Manages user sessions with secure cookie-based authentication."""

    def __init__(
        self,
        cookie_name: str = "bluep_session",
        cookie_max_age: int = 86400,  # 24 hours
        refresh_threshold: int = 3600  # 1 hour
    ):
        """Initialize session manager.

        Args:
            cookie_name: Name for session cookie
            cookie_max_age: Session lifetime in seconds
            refresh_threshold: Time before expiry to refresh session
        """
        self.sessions: Dict[str, SessionData] = {}
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.refresh_threshold = refresh_threshold
        self.cookie_security = APIKeyCookie(name=cookie_name, auto_error=False)

    def create_session(self, username: str, response: Response) -> str:
        """Create new user session with secure cookie."""
        session_id = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(seconds=self.cookie_max_age)

        self.sessions[session_id] = SessionData(
            username=username,
            expiry=expiry,
            last_totp_use=""
        )

        self._set_cookie(response, session_id)
        return session_id

    def refresh_session(self, session_id: str, response: Response) -> bool:
        """Refresh session if it's near expiration.

        Args:
            session_id: Session to refresh
            response: Response object to update cookie

        Returns:
            bool: True if session was refreshed
        """
        session = self.sessions.get(session_id)
        if not session:
            return False

        time_to_expiry = session.expiry - datetime.now()
        if time_to_expiry.total_seconds() < self.refresh_threshold:
            session.expiry = datetime.now() + timedelta(seconds=self.cookie_max_age)
            self._set_cookie(response, session_id)
            logger.debug(f"Refreshed session for {session.username}")
            return True

        return False

    def _set_cookie(self, response: Response, session_id: str) -> None:
        """Set secure session cookie."""
        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            max_age=self.cookie_max_age,
            httponly=True,
            secure=True,
            samesite="strict"
        )

    def get_session(self, session_id: str, response: Optional[Response] = None) -> Optional[SessionData]:
        """Get and optionally refresh session."""
        session = self.sessions.get(session_id)
        if not session:
            return None

        if datetime.now() > session.expiry:
            del self.sessions[session_id]
            return None

        # Refresh session if response object is provided
        if response:
            self.refresh_session(session_id, response)

        return session

    def validate_totp_use(self, session_id: str, totp_code: str) -> bool:
        """Validate TOTP code hasn't been reused."""
        session = self.get_session(session_id)
        if not session:
            return False

        if session.last_totp_use == totp_code:
            return False

        session.last_totp_use = totp_code
        return True
