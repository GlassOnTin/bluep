"""Models module containing data structures used throughout the bluep application.

This module defines the core data structures used for session management and
websocket communication in the collaborative text editor.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, validator, field_validator, ValidationInfo


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
    type: Literal[
        "content",
        "cursor",
        "pong",
        "state",
        "error",
        "file-announce",
        "file-request",
        "file-data",
        "clear-files",
        "process-spawn",
        "process-input",
        "process-output",
        "process-resize",
        "process-terminate",
        "process-list",
        "process-status",
        "mcp-service-list",
        "mcp-service-start",
        "mcp-service-stop",
        "mcp-service-status",
        "mcp-service-register",
        "mcp-service-registered",
        "mcp-service-unregister",
        "mcp-service-unregistered",
        "mcp-request",
        "mcp-response",
        "mcp-stream",
    ]
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
    processId: Optional[str] = Field(None, max_length=100)  # Process identifier
    command: Optional[str] = Field(None, max_length=1000)  # Command to spawn
    cols: Optional[int] = Field(None, ge=1, le=500)  # Terminal columns for resize
    rows: Optional[int] = Field(None, ge=1, le=200)  # Terminal rows for resize
    
    @validator('processId')
    def validate_process_id(cls, v):
        if v and not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Invalid process ID format')
        return v
    
    @validator('data')
    def validate_data_size(cls, v, values):
        if v and values.get('type') == 'process-input' and len(v) > 10000:
            raise ValueError('Process input too large')
        elif v and values.get('type') == 'content' and len(v) > 1000000:  # 1MB limit for content
            raise ValueError('Content too large')
        return v
    
    @validator('fileSize')
    def validate_file_size(cls, v):
        if v and v > 100 * 1024 * 1024:  # 100MB limit
            raise ValueError('File size too large')
        return v
    outputData: Optional[str] = None  # Base64 encoded process output
    processes: Optional[List[Dict[str, Any]]] = None  # List of processes
    mcpServices: Optional[List[Dict[str, Any]]] = None  # List of MCP services
    serviceName: Optional[str] = Field(None, max_length=100)  # MCP service name
    servicePort: Optional[int] = Field(None, ge=1, le=65535)  # MCP service port
    mcpPayload: Optional[Dict[str, Any]] = None  # MCP protocol payload
    targetClient: Optional[str] = None  # Target client ID for MCP routing
    serviceUrl: Optional[str] = None  # URL for external MCP service
    description: Optional[str] = None  # Description for external MCP service

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
