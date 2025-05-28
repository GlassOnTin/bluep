"""Secure configuration management for bluep.

This module handles secure storage and retrieval of configuration data,
particularly TOTP secrets, using machine-specific encryption.
"""

import base64
import hashlib
import json
import os
import platform
import secrets
import uuid
from pathlib import Path
from typing import Optional, Dict, Any

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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

        # Generate or load salt for key derivation
        self.salt_path = self.config_path.parent / ".salt"
        self.salt = self._get_or_create_salt()
        
        # Derive encryption key using PBKDF2
        machine_id = self._get_machine_id()
        self.key = self._derive_key(machine_id, self.salt)
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

    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one for key derivation.
        
        Returns:
            bytes: 32-byte salt for PBKDF2
        """
        if self.salt_path.exists():
            try:
                with open(self.salt_path, 'rb') as f:
                    salt = f.read()
                    if len(salt) == 32:
                        return salt
            except Exception:
                pass
        
        # Generate new salt
        salt = secrets.token_bytes(32)
        try:
            # Set restrictive permissions before writing
            self.salt_path.touch(mode=0o600, exist_ok=True)
            self.salt_path.write_bytes(salt)
        except Exception as e:
            print(f"Warning: Could not save salt: {e}")
        return salt
    
    def _derive_key(self, machine_id: str, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2 with machine ID and salt.
        
        Args:
            machine_id: Machine-specific identifier
            salt: Random salt for key derivation
            
        Returns:
            bytes: 32-byte encryption key
        """
        # Use PBKDF2 with 100,000 iterations for key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        # Combine machine ID with a fixed application-specific string
        key_material = f"bluep-{machine_id}-encryption-key".encode()
        return base64.urlsafe_b64encode(kdf.derive(key_material))

    def _get_machine_id(self) -> str:
        """Get unique machine identifier for encryption key generation.

        Returns:
            str: Machine-specific identifier with additional entropy
        """
        system = platform.system()
        machine_parts = []
        
        # Get multiple sources of machine identity
        if system == "Windows":
            # Windows: Use MAC address
            machine_parts.append(str(uuid.UUID(int=uuid.getnode())))
            # Add Windows product ID if available
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                    product_id = winreg.QueryValueEx(key, "ProductId")[0]
                    machine_parts.append(product_id)
            except Exception:
                pass
                
        elif system == "Darwin":
            # macOS: Use hardware UUID
            try:
                hw_uuid = (
                    os.popen("ioreg -rd1 -c IOPlatformExpertDevice | grep UUID")
                    .read()
                    .split('"')[3]
                )
                machine_parts.append(hw_uuid)
            except Exception:
                machine_parts.append(str(uuid.UUID(int=uuid.getnode())))
                
        else:
            # Linux: Use machine-id
            for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as f:
                        machine_parts.append(f.read().strip())
                        break
            else:
                machine_parts.append(str(uuid.UUID(int=uuid.getnode())))
        
        # Add hostname for additional entropy
        machine_parts.append(platform.node())
        
        # Combine all parts with SHA256 for consistent output
        combined = "|".join(machine_parts)
        return hashlib.sha256(combined.encode()).hexdigest()

    def save_secret(
        self, totp_secret: str, setup_complete: Optional[bool] = None
    ) -> None:
        """Save TOTP secret and setup_complete flag to encrypted configuration.

        Args:
            totp_secret: TOTP secret to store
            setup_complete: Optional setup complete flag
        """
        config = {"totp_secret": totp_secret}
        if setup_complete is not None:
            config["setup_complete"] = setup_complete
        else:
            # Preserve existing setup_complete flag if present
            if self.config_path.exists():
                try:
                    encrypted = self.config_path.read_bytes()
                    prev_config: Dict[str, Any] = json.loads(self.fernet.decrypt(encrypted))
                    if "setup_complete" in prev_config:
                        config["setup_complete"] = prev_config["setup_complete"]
                except Exception:
                    pass
        encrypted = self.fernet.encrypt(json.dumps(config).encode())
        self.config_path.write_bytes(encrypted)

    def load_secret(self) -> Optional[str]:
        """Load TOTP secret from encrypted configuration."""
        if not self.config_path.exists():
            return None
        try:
            encrypted = self.config_path.read_bytes()
            config: Dict[str, Any] = json.loads(self.fernet.decrypt(encrypted))
            return config.get("totp_secret")
        except Exception as e:
            # If decryption fails (e.g., due to key change), return None
            # This will trigger generation of a new secret
            print(f"Failed to load secret: {e}")
            return None

    def get_setup_complete(self) -> bool:
        """Return True if setup has been completed (flag set)."""
        if not self.config_path.exists():
            return False
        try:
            encrypted = self.config_path.read_bytes()
            config: Dict[str, Any] = json.loads(self.fernet.decrypt(encrypted))
            return bool(config.get("setup_complete", False))
        except Exception:
            # If decryption fails, assume setup is not complete
            return False

    def set_setup_complete(self, value: bool = True) -> None:
        """Set the setup_complete flag in the config."""
        if not self.config_path.exists():
            return
        try:
            encrypted = self.config_path.read_bytes()
            config: Dict[str, Any] = json.loads(self.fernet.decrypt(encrypted))
            config["setup_complete"] = value
            self.config_path.write_bytes(self.fernet.encrypt(json.dumps(config).encode()))
        except Exception:
            # If decryption fails, can't update the flag
            pass
