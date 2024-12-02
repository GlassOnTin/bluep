"""Middleware components for security and rate limiting.

This module provides middleware components for the bluep application including
CORS configuration, trusted hosts, rate limiting, and security headers.
"""
import time
from collections import defaultdict
from typing import DefaultDict, List

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware


def configure_security(app: FastAPI) -> None:
    """Configure security middleware for the application.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
    app.add_middleware(RateLimitMiddleware, rate_limit=100, window=60)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
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
    """Rate limiting middleware for request throttling.

    Implements a sliding window rate limiter to prevent abuse.
    """

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

    async def dispatch(self, request: Request, call_next):
        """Process request and apply rate limiting.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response: Response with rate limit status
        """
        client_host = request.client.host if request.client else "0.0.0.0"
        current_time = time.time()

        # Clean old requests
        self.requests[client_host] = [
            req_time
            for req_time in self.requests[client_host]
            if current_time - req_time < self.window
        ]

        # Check rate limit
        if len(self.requests[client_host]) >= self.rate_limit:
            return Response(status_code=429, content={"detail": "Too many requests"})

        self.requests[client_host].append(current_time)
        return await call_next(request)
