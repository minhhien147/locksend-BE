"""
A05 – Security Misconfiguration
HTTP Security Headers middleware cho FastAPI.

Pure ASGI thay vì BaseHTTPMiddleware: BaseHTTPMiddleware bọc mỗi request trong một
anyio task group + memory object stream, chi phí đó lớn hơn cả phần việc thật của
middleware này. Header cũng được dựng sẵn 1 lần lúc khởi tạo thay vì đọc env mỗi request.
"""
from __future__ import annotations

import os

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# API JSON không phục vụ HTML/JS — CSP chặt, không 'unsafe-inline'.
# FE host nên đặt CSP riêng; override bằng CSP_POLICY nếu cần.
_CSP_DEFAULT = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none';"
)

_STATIC_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("x-xss-protection", "1; mode=block"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
)


def _build_headers() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(headers ghi đè, headers chỉ set khi response chưa có)."""
    overwrite: list[tuple[str, str]] = []
    csp = os.getenv("CSP_POLICY", _CSP_DEFAULT)
    if csp:
        overwrite.append(("content-security-policy", csp))

    defaults = list(_STATIC_HEADERS)
    # HSTS: chỉ bật khi COOKIE_SECURE=true (production HTTPS)
    if os.getenv("COOKIE_SECURE", "false").lower() == "true":
        defaults.append(
            ("strict-transport-security", "max-age=63072000; includeSubDomains; preload")
        )
    return overwrite, defaults


class SecurityHeadersMiddleware:
    """Thêm HTTP security headers vào mọi response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._overwrite, self._defaults = _build_headers()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self._overwrite:
                    headers[name] = value
                for name, value in self._defaults:
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)
