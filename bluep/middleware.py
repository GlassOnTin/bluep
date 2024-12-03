"""Middleware components for security and rate limiting.

This module provides middleware components for the bluep application including
CORS configuration, trusted hosts, rate limiting, and security headers.
"""

import json
import time
from collections import defaultdict
from typing import DefaultDict, List, Any, Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


def configure_security(app: FastAPI) -> None:
    """Configure security middleware for the application."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,  # Enable credentials
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"]
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]
    )

    app.add_middleware(RateLimitMiddleware, rate_limit=100, window=60)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Callable) -> Response:
        """Add security headers to response."""
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline';"
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware to prevent abuse."""

    def __init__(self, app: FastAPI, rate_limit: int = 100, window: int = 60):
        """Initialize rate limiter.

        Args:
            app: FastAPI application instance
            rate_limit: Maximum requests per window
            window: Time window in seconds
        """
        super().__init__(app)
        self.rate_limit = rate_limit
        self.window = window
        self.requests: DefaultDict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle request and apply rate limiting.

        Args:
            request: Incoming request
            call_next: Next middleware function

        Returns:
            Response: Response with rate limit status
        """
        client_host = request.client.host if request.client else "0.0.0.0"
        if request.headers.get("X-Forwarded-For"):
            client_host = request.headers["X-Forwarded-For"].split(",")[0].strip()

        current_time = time.time()

        # Clean old requests
        self.requests[client_host] = [
            req_time
            for req_time in self.requests[client_host]
            if current_time - req_time < self.window
        ]

        # Check rate limit
        if len(self.requests[client_host]) >= self.rate_limit:
            return JSONResponse(
                status_code=429, content={"detail": "Too many requests"}
            )

        self.requests[client_host].append(current_time)
        return await call_next(request)
