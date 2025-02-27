"""Models module containing data structures used throughout the bluep application.

This module defines the core data structures used for session management and
websocket communication in the collaborative text editor.
"""

from enum import Enum
from typing import Optional, Literal, Any, Dict, Union, List
from pydantic import BaseModel, field_validator, ValidationInfo
from datetime import datetime

class ConnectionState(Enum):
    INITIALIZING = "initializing"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    CLOSED = "closed"

class KeyExchangeData:
    """Data for ECDH key exchange."""
    
    def __init__(self, server_private_key: bytes, client_public_key: bytes):
        self.server_private_key = server_private_key
        self.client_public_key = client_public_key
        self.created_at = datetime.now()

class SessionData(BaseModel):
    username: str
    expiry: datetime
    last_totp_use: str
    websocket_token: Optional[str] = None
    connection_state: Optional[ConnectionState] = None
    cert_verification_attempts: int = 0
    
    # We can't store KeyExchangeData directly in pydantic model, so it will be
    # added as an instance attribute after creation

class WebSocketMessage(BaseModel):
    type: Literal["content", "cursor", "pong", "state", "error", "file-announce", "file-request", "file-data", "clear-files"]
    data: Optional[str] = None
    x: Optional[int] = None
    y: Optional[int] = None
    clientId: Optional[int] = None
    state: Optional[str] = None
    error: Optional[str] = None
    encrypted: Optional[bool] = False
    keyId: Optional[str] = None  # Reference to the key used for encryption
    fileName: Optional[str] = None  # For file operations
    fileSize: Optional[int] = None  # For file operations
    fileId: Optional[str] = None  # Unique ID for the file
    fileType: Optional[str] = None  # MIME type
    fileChunk: Optional[int] = None  # Chunk number for file transfers
    totalChunks: Optional[int] = None  # Total chunks for file transfers

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

class CertificateVerification(BaseModel):
    """Certificate verification request/response model."""
    
    clientTime: int
    expectedFingerprint: Optional[str] = None
    
class TamperingReport(BaseModel):
    """Report of tampering detection from client."""
    
    type: str  # Type of tampering detected
    timestamp: int
    token: Optional[str] = None  # Session token if available
    details: Optional[Dict[str, Any]] = None

class KeyExchangeRequest(BaseModel):
    """Key exchange request model."""
    
    clientKey: str  # Base64-encoded client public key
    token: str  # Authentication token

class KeyExchangeResponse(BaseModel):
    """Key exchange response model."""
    
    serverKey: str  # Base64-encoded server public key
    keyId: str  # Identifier for this key exchange
