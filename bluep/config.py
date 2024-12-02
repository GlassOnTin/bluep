"""Configuration module for the bluep application.

This module handles application settings including network configuration,
SSL certificates, and appearance customization.
"""

from typing import Optional
import socket
from pydantic import BaseModel, model_validator

from bluep.cert_generator import generate_ssl_certs


class Settings(BaseModel):
    """Application settings and configuration.

    Handles core application settings including network configuration,
    SSL certificate paths, and UI customization.

    Attributes:
        host_ip: IP address to bind the server to
        port: Port number to listen on
        ssl_keyfile: Path to SSL private key file
        ssl_certfile: Path to SSL certificate file
        blue_color: Hex color code for UI theme
    """

    host_ip: Optional[str] = None
    port: int = 8500
    ssl_keyfile: str = "key.pem"
    ssl_certfile: str = "cert.pem"
    blue_color: str = "#0000ff"

    @model_validator(mode="after")
    def check_ssl_certs(self) -> "Settings":
        """Ensure SSL certificates exist, generating them if needed."""
        generate_ssl_certs(self.ssl_certfile, self.ssl_keyfile)
        return self

    @model_validator(mode="after")
    def set_host_ip(self) -> "Settings":
        """Set host IP if not provided, using local network detection."""
        if not self.host_ip:
            self.host_ip = self._get_local_ip()
        return self

    def _get_local_ip(self) -> str:
        """Detect local IP address for server binding."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 1))
            local_ip: str = s.getsockname()[0]
            return local_ip
        except Exception:
            return "127.0.0.1"
        finally:
            s.close()
