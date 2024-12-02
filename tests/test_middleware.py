# tests/test_middleware.py
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from bluep.middleware import RateLimitMiddleware, configure_security


def test_rate_limit_middleware():
    """Test rate limiting middleware"""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, rate_limit=2, window=1)

    @app.get("/")
    async def test_endpoint():
        return {"status": "ok"}

    client = TestClient(app)

    # First two requests should succeed
    assert client.get("/").status_code == 200
    assert client.get("/").status_code == 200

    # Third request should be rate limited
    assert client.get("/").status_code == 429

    # Test rate limit reset
    import time

    time.sleep(1.1)
    assert client.get("/").status_code == 200


def test_security_headers():
    """Test security headers middleware"""
    app = FastAPI()
    configure_security(app)

    @app.get("/")
    async def test_endpoint():
        return {"message": "test"}

    client = TestClient(app)

    # Test with valid host
    response = client.get("/", headers={"host": "testserver"})
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]

    # Test CORS
    response = client.options(
        "/",
        headers={
            "origin": "https://example.com",
            "access-control-request-method": "GET",
            "host": "testserver",
        },
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers


def test_rate_limit_per_ip():
    """Test rate limiting tracks different IPs separately"""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, rate_limit=2, window=1)

    @app.get("/")
    async def test_endpoint(request: Request):
        return {"client_ip": request.client.host}

    client = TestClient(app)

    # Test first IP
    for _ in range(2):  # Should succeed
        response = client.get(
            "/", headers={"X-Forwarded-For": "1.1.1.1", "host": "testserver"}
        )
        assert response.status_code == 200

    # Should be rate limited
    response = client.get(
        "/", headers={"X-Forwarded-For": "1.1.1.1", "host": "testserver"}
    )
    assert response.status_code == 429

    # Different IP should still work
    response = client.get(
        "/", headers={"X-Forwarded-For": "2.2.2.2", "host": "testserver"}
    )
    assert response.status_code == 200
