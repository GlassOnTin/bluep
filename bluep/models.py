"""Models module containing data structures used throughout the bluep application.

This module defines the core data structures used for session management and
websocket communication in the collaborative text editor.
"""

from enum import Enum
from typing import Optional, Literal, Any, Dict
from pydantic import BaseModel, field_validator, ValidationInfo
from datetime import datetime

class ConnectionState(Enum):
    INITIALIZING = "initializing"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    CLOSED = "closed"

class SessionData(BaseModel):
    username: str
    expiry: datetime
    last_totp_use: str
    websocket_token: Optional[str] = None
    connection_state: Optional[ConnectionState] = None

class WebSocketMessage(BaseModel):
    type: Literal["content", "cursor", "pong", "state", "error"]  # Added state and error
    data: Optional[str] = None
    x: Optional[int] = None
    y: Optional[int] = None
    clientId: Optional[int] = None
    state: Optional[str] = None
    error: Optional[str] = None
    encrypted: Optional[bool] = False

    @field_validator("data")
    def validate_data(cls, v: Optional[str], info: ValidationInfo) -> str:
        if info.data.get("type") == "content" and v is None:
            return ""
        return v or ""
        
    @field_validator("encrypted")
    def validate_encrypted(cls, v: Optional[bool], info: ValidationInfo) -> bool:
        # Default to False if not provided
        return bool(v)

    @classmethod
    def model_validate_message(cls, data: str) -> "WebSocketMessage":
        """Create a WebSocketMessage instance from JSON string data.

        Args:
            data: JSON string containing message data

        Returns:
            WebSocketMessage: Validated message instance
        """
        return cls.model_validate_json(data)
