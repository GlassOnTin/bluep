"""Secure configuration management for bluep.

This module handles secure storage and retrieval of configuration data,
particularly TOTP secrets, using machine-specific encryption.
"""

import base64
import json
import os
import platform
import uuid
from pathlib import Path
from typing import Optional, Dict

from cryptography.fernet import Fernet


class SecureConfig:
    """Secure configuration manager using machine-specific encryption.

    Handles encrypted storage and retrieval of sensitive configuration data,
    using machine-specific identifiers for key generation.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """Initialize secure configuration manager.

        Args:
            config_path: Optional custom path for config file
        """
        if config_path is None:
            config_path = self._get_default_config_path()
            print(f"Config path: {config_path}")
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        machine_id = self._get_machine_id()
        self.key = base64.urlsafe_b64encode(machine_id[:32].encode().ljust(32)[:32])
        self.fernet = Fernet(self.key)

    def _get_default_config_path(self) -> Path:
        """Get the default platform-specific configuration path.

        Returns:
            Path: Default configuration file path
        """
        system = platform.system()
        if system == "Windows":
            return Path(os.environ["LOCALAPPDATA"]) / "bluep" / "config.enc"
        if system == "Darwin":  # macOS
            return (
                Path.home() / "Library" / "Application Support" / "bluep" / "config.enc"
            )
        return Path.home() / ".bluep" / "config.enc"  # Linux/Unix

    def _get_machine_id(self) -> str:
        """Get unique machine identifier for encryption key generation.

        Returns:
            str: Machine-specific identifier
        """
        system = platform.system()
        if system == "Windows":
            return str(uuid.UUID(int=uuid.getnode()))
        if system == "Darwin":
            try:
                return (
                    os.popen("ioreg -rd1 -c IOPlatformExpertDevice | grep UUID")
                    .read()
                    .split('"')[3]
                )
            except Exception as e:
                print(f"Error getting macOS UUID: {e}")
                return str(uuid.UUID(int=uuid.getnode()))

        # Linux fallbacks
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    return f.read().strip()
        return str(uuid.UUID(int=uuid.getnode()))

    def save_secret(self, totp_secret: str) -> None:
        """Save TOTP secret to encrypted configuration.

        Args:
            totp_secret: TOTP secret to store
        """
        config = {"totp_secret": totp_secret}
        encrypted = self.fernet.encrypt(json.dumps(config).encode())
        self.config_path.write_bytes(encrypted)

    def load_secret(self) -> Optional[str]:
        """Load TOTP secret from encrypted configuration."""
        if not self.config_path.exists():
            return None
        encrypted = self.config_path.read_bytes()
        config: Dict[str, str] = json.loads(self.fernet.decrypt(encrypted))
        print(config["totp_secret"])
        return config["totp_secret"]
