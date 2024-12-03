"""Session management for bluep.

This module handles user session creation, validation, and cleanup for
authenticated users of the collaborative editor.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging
from fastapi import Response, Cookie
from .models import SessionData, ConnectionState

logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(
        self,
        cookie_name: str = "bluep_session",
        cookie_max_age: int = 86400,
        refresh_threshold: int = 3600
    ):
        self.sessions: Dict[str, SessionData] = {}
        self.websocket_tokens: Dict[str, str] = {}  # token -> session_id
        self.cookie_name = cookie_name
        self.cookie_max_age = cookie_max_age
        self.refresh_threshold = refresh_threshold

    def create_websocket_token(self, session_id: str) -> str:
        token = secrets.token_urlsafe(32)
        logger.debug(f"Creating new token {token} for session {session_id}")
        self.websocket_tokens[token] = session_id
        return token

    def validate_websocket_token(self, token: str) -> Optional[str]:
        return self.websocket_tokens.get(token)

    def create_session(self, username: str, response: Response) -> str:
        session_id = secrets.token_urlsafe(32)
        websocket_token = self.create_websocket_token(session_id)

        self.sessions[session_id] = SessionData(
            username=username,
            expiry=datetime.now() + timedelta(seconds=self.cookie_max_age),
            last_totp_use="",
            websocket_token=websocket_token,
            connection_state=ConnectionState.INITIALIZING
        )

        self._set_cookie(response, session_id)
        return session_id

    def refresh_session(self, session_id: str, response: Response) -> bool:
        session = self.sessions.get(session_id)
        if not session:
            return False

        time_to_expiry = session.expiry - datetime.now()
        if time_to_expiry.total_seconds() < self.refresh_threshold:
            session.expiry = datetime.now() + timedelta(seconds=self.cookie_max_age)
            self._set_cookie(response, session_id)
            # Maintain websocket token during refresh
            if not session.websocket_token:
                session.websocket_token = self.create_websocket_token(session_id)
            return True
        return False

    def _set_cookie(self, response: Response, session_id: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            max_age=self.cookie_max_age,
            httponly=True,
            secure=True,
            samesite="strict"
        )

    def get_session(self, session_id: str, response: Optional[Response] = None) -> Optional[SessionData]:
        session = self.sessions.get(session_id)
        if not session:
            return None

        if datetime.now() > session.expiry:
            del self.sessions[session_id]
            # Clean up associated websocket token
            if session.websocket_token:
                self.websocket_tokens.pop(session.websocket_token, None)
            return None

        if response:
            self.refresh_session(session_id, response)
        return session

    def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions and their associated tokens"""
        current_time = datetime.now()
        expired = [
            sid for sid, session in self.sessions.items()
            if current_time > session.expiry
        ]

        for sid in expired:
            session = self.sessions.pop(sid)
            if session.websocket_token:
                self.websocket_tokens.pop(session.websocket_token, None)

    def validate_totp_use(self, session_id: str, totp_code: str) -> bool:
        session = self.get_session(session_id)
        if not session:
            return False

        if session.last_totp_use == totp_code:
            return False

        # Check connection state
        if session.connection_state not in [None, ConnectionState.CLOSED, ConnectionState.INITIALIZING]:
            return False

        session.last_totp_use = totp_code
        session.connection_state = ConnectionState.INITIALIZING
        return True
