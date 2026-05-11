"""
Structured audit logging.

Mọi event quan trọng (auth, upload, share, revoke, role-change) được ghi qua
hàm `log_event()`. Output là JSON-serialisable dict → dễ ingest vào Loki/Datadog.

Các field chứa dữ liệu nhạy cảm được redact tự động.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger("audit")

# Field names bị redact bất kể nằm ở depth nào trong kwargs
_REDACT_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "password_hash",
        "wrapped_file_key",
        "access_token",
        "refresh_token",
        "jti",
        "authorization",
        "cookie",
        "set_cookie",
        "x_api_key",
    }
)

_REDACTED = "***"


def _redact(obj: Any, depth: int = 0) -> Any:
    """Đệ quy redact các key nhạy cảm trong dict/list."""
    if depth > 5:
        return obj
    if isinstance(obj, dict):
        return {
            k: _REDACTED if k.lower().replace("-", "_") in _REDACT_KEYS
            else _redact(v, depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_redact(i, depth + 1) for i in obj]
    return obj


def log_event(
    event: str,
    *,
    user_id: str | None = None,
    email: str | None = None,
    role: str | None = None,
    request_id: str | None = None,
    ip: str | None = None,
    **extra: Any,
) -> None:
    """
    Ghi một audit event dạng structured JSON.

    Ví dụ:
        audit.log_event("user.login", user_id=user.id, email=user.email, ip=req.client.host)
        audit.log_event("file.revoke", user_id=..., file_id=..., recipient_id=...)
    """
    entry: dict[str, Any] = {
        "event": event,
        "ts": time.time(),
    }
    if user_id is not None:
        entry["user_id"] = user_id
    if email is not None:
        entry["email"] = email
    if role is not None:
        entry["role"] = role
    if request_id is not None:
        entry["request_id"] = request_id
    if ip is not None:
        entry["ip"] = ip
    entry.update(_redact(extra))

    try:
        logger.info(json.dumps(entry, default=str, ensure_ascii=False))
    except Exception:
        # Không bao giờ để audit fail crash request
        logger.info(repr(entry))


def get_request_id(request: Any) -> str | None:
    """Lấy request_id từ request.state (nếu có middleware gắn)."""
    try:
        return str(request.state.request_id)
    except AttributeError:
        return None


def get_ip(request: Any) -> str | None:
    """Lấy client IP, ưu tiên X-Forwarded-For (nếu đứng sau proxy)."""
    try:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else None
    except Exception:
        return None
