import pytest
from bluep.secure_config import SecureConfig
from cryptography.fernet import Fernet
import tempfile
from pathlib import Path


def test_secure_config():
    with tempfile.TemporaryDirectory() as tmpdir:
        config = SecureConfig(Path(tmpdir) / "config.enc")
        secret = "test_secret"
        config.save_secret(secret)
        loaded_secret = config.load_secret()
        assert loaded_secret == secret


def test_ssl_cert_generation():
    from bluep.cert_generator import generate_ssl_certs

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "cert.pem"
        key_path = Path(tmpdir) / "key.pem"
        generate_ssl_certs(cert_path, key_path)
        assert cert_path.exists()
        assert key_path.exists()
