from cryptography.fernet import Fernet
from pathlib import Path
import json
import base64
import os
import platform
import uuid

class SecureConfig:
    def __init__(self, config_path=None):
        if config_path is None:
            config_path = self._get_default_config_path()
            print(f"Config path: config_path")
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        machine_id = self._get_machine_id()
        self.key = base64.urlsafe_b64encode(machine_id[:32].encode().ljust(32)[:32])
        self.fernet = Fernet(self.key)

    def _get_default_config_path(self):
        system = platform.system()
        if system == "Windows":
            return Path(os.environ["LOCALAPPDATA"]) / "bluep" / "config.enc"
        elif system == "Darwin":  # macOS
            return Path.home() / "Library" / "Application Support" / "bluep" / "config.enc"
        return Path.home() / ".bluep" / "config.enc"  # Linux/Unix

    def _get_machine_id(self):
        system = platform.system()
        if system == "Windows":
            return str(uuid.UUID(int=uuid.getnode()))  # Use MAC address
        elif system == "Darwin":
            # Use macOS system UUID
            try:
                return os.popen('ioreg -rd1 -c IOPlatformExpertDevice | grep UUID').read().split('"')[3]
            except:
                return str(uuid.UUID(int=uuid.getnode()))
        # Linux fallbacks
        for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            if os.path.exists(path):
                with open(path) as f:
                    return f.read().strip()
        return str(uuid.UUID(int=uuid.getnode()))

    def save_secret(self, totp_secret):
        config = {'totp_secret': totp_secret}
        encrypted = self.fernet.encrypt(json.dumps(config).encode())
        self.config_path.write_bytes(encrypted)

    def load_secret(self):
        if not self.config_path.exists():
            return None
        encrypted = self.config_path.read_bytes()
        config = json.loads(self.fernet.decrypt(encrypted))
        return config['totp_secret']
