"""Bluep collaborative text editor package.

This package provides a secure real-time collaborative text editor with TOTP
authentication and a blue theme. It enables multiple users to connect and edit
text simultaneously through their browsers.
"""
from .auth import TOTPAuth
from .cert_generator import generate_ssl_certs
from .config import Settings
from .models import WebSocketMessage
from .middleware import RateLimitMiddleware
from .secure_config import SecureConfig
from .session_manager import SessionData
from .websocket_manager import WebSocketManager

__version__ = "0.4.1"
__all__ = [
    "RateLimitMiddleware",
    "SessionData",
    "Settings",
    "SecureConfig",
    "TOTPAuth",
    "WebSocketManager",
    "WebSocketMessage",
]
