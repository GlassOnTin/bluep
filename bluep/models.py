"""Models module containing data structures used throughout the bluep application.

This module defines the core data structures used for session management and
websocket communication in the collaborative text editor.
"""

from typing import Optional, Literal, Any, Dict
from pydantic import BaseModel, field_validator
from datetime import datetime


class SessionData(BaseModel):
    """Data structure for storing session information.

    Contains user session data including username, expiry time, and TOTP usage
    tracking for replay attack prevention.

    Attributes:
        username: User identifier for the session
        expiry: Timestamp when the session expires
        last_totp_use: The last TOTP code used, to prevent replay attacks
    """

    username: str
    expiry: datetime
    last_totp_use: str


class WebSocketMessage(BaseModel):
    """Data structure for WebSocket communication messages.

    Defines the structure of messages exchanged between clients and server
    for content synchronization and cursor position updates.

    Attributes:
        type: Message type, either "content" or "cursor"
        data: Optional text content of the message
        x: Optional cursor x-coordinate
        y: Optional cursor y-coordinate
        clientId: Optional client identifier
    """

    type: Literal["content", "cursor"]
    data: Optional[str] = None
    x: Optional[int] = None
    y: Optional[int] = None
    clientId: Optional[int] = None

    @field_validator("data")
    def validate_data(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        """Validate data field for WebSocket messages."""
        if values.get("type") == "content" and v is None:
            return ""
        return v or ""

    @classmethod
    def model_validate_message(cls, data: str) -> "WebSocketMessage":
        """Create a WebSocketMessage instance from JSON string data.

        Args:
            data: JSON string containing message data

        Returns:
            WebSocketMessage: Validated message instance
        """
        return cls.model_validate_json(data)
