"""Middleware components for security and rate limiting.

This module provides middleware components for the bluep application including
CORS configuration, trusted hosts, rate limiting, and security headers.
"""

import json
import time
import glob
import os
import base64
import hashlib
from collections import defaultdict
from typing import DefaultDict, List, Any, Callable, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


def configure_security(app: FastAPI) -> None:
    """Configure security middleware for the application."""
    # More restrictive CORS - only allow same-origin requests by default
    # In a production app, you'd specify the exact origins you trust
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://{host}"],  # Dynamically replaced with actual host
        allow_credentials=True,
        allow_methods=["GET", "POST"],  # Only allow necessary methods
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Content-Type"],
        max_age=3600  # Cache preflight requests for 1 hour
    )

    # Restrict trusted hosts - prevent host header attacks
    # In production, explicitly list your domain names
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "*"]  # Still allowing all for development
    )

    app.add_middleware(RateLimitMiddleware, rate_limit=100, window=60)

    # Generate integrity hashes for JS and CSS assets
    js_files: Dict[str, str] = {}
    
    for script_path in glob.glob("static/js/*.js"):
        try:
            with open(script_path, "rb") as f:
                content = f.read()
                # Generate base64-encoded SHA-384 hash
                digest = base64.b64encode(hashlib.sha384(content).digest()).decode()
                basename = os.path.basename(script_path)
                js_files[basename] = f"sha384-{digest}"
        except Exception as e:
            print(f"Error generating hash for {script_path}: {e}")
    
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Callable) -> Response:
        """Add security headers to response."""
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), document-domain=()"
        
        # Build CSP with script hashes
        script_hashes = " ".join([f"'{hash_value}'" for hash_value in js_files.values()])
        script_src = f"'self' {script_hashes}" if script_hashes else "'self'"
        
        csp_parts = [
            "default-src 'self'",
            f"script-src {script_src}",  # Include script hashes
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self' wss:",
            "img-src 'self' data:",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'"
        ]
        
        response.headers["Content-Security-Policy"] = "; ".join(csp_parts)
        
        # Add reporting endpoint for CSP violations
        response.headers["Report-To"] = '{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"/csp-report"}]}'
        
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
