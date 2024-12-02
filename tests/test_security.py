import pytest
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from bluep.secure_config import SecureConfig
from bluep.cert_generator import generate_ssl_certs


def test_secure_config():
    """Test secure configuration storage and retrieval"""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = SecureConfig(Path(tmpdir) / "config.enc")
        secret = "test_secret"
        config.save_secret(secret)
        loaded_secret = config.load_secret()
        assert loaded_secret == secret

        # Test loading non-existent config
        empty_config = SecureConfig(Path(tmpdir) / "nonexistent.enc")
        assert empty_config.load_secret() is None


def test_ssl_cert_generation():
    """Test SSL certificate generation"""
    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = Path(tmpdir) / "cert.pem"
        key_path = Path(tmpdir) / "key.pem"

        # Test initial generation
        generate_ssl_certs(cert_path, key_path)
        assert cert_path.exists()
        assert key_path.exists()

        # Test no regeneration if files exist
        orig_cert_mtime = cert_path.stat().st_mtime
        generate_ssl_certs(cert_path, key_path)
        assert cert_path.stat().st_mtime == orig_cert_mtime
