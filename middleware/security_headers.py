"""
A05 – Security Misconfiguration
HTTP Security Headers middleware cho FastAPI.
"""
from __future__ import annotations

import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# Cho phép override từng header qua env var (empty string = bỏ header đó)
_CSP_DEFAULT = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Thêm HTTP security headers vào mọi response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        csp = os.getenv("CSP_POLICY", _CSP_DEFAULT)
        if csp:
            response.headers["Content-Security-Policy"] = csp

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-XSS-Protection", "1; mode=block")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )

        # HSTS: chỉ bật khi COOKIE_SECURE=true (production HTTPS)
        if os.getenv("COOKIE_SECURE", "false").lower() == "true":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )

        return response
