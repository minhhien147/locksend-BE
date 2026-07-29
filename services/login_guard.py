"""
A07 – Identification & Authentication Failures
In-memory brute-force login lockout.

Giới hạn:  LOGIN_MAX_ATTEMPTS lần thất bại trong LOGIN_LOCKOUT_WINDOW giây
           → khoá LOGIN_LOCKOUT_DURATION giây.
Key:       "<ip>:<email>" để tránh account enumeration qua timing.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException

MAX_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOCKOUT_WINDOW: int = int(os.getenv("LOGIN_LOCKOUT_WINDOW", "300"))   # 5 phút
LOCKOUT_DURATION: int = int(os.getenv("LOGIN_LOCKOUT_DURATION", "900"))  # 15 phút

_attempts: dict[str, list[float]] = defaultdict(list)
_lockouts: dict[str, float] = {}
_lock = Lock()


def _make_key(ip: str | None, email: str) -> str:
    return f"{(ip or 'unknown').split(',')[0].strip()}:{email.lower()}"


def check_and_record_attempt(ip: str | None, email: str) -> None:
    """
    Gọi TRƯỚC khi kiểm tra password.
    Raise 429 nếu account đang bị khoá.
    """
    key = _make_key(ip, email)
    now = time.monotonic()

    with _lock:
        # Kiểm tra lockout còn hiệu lực không
        locked_until = _lockouts.get(key)
        if locked_until and now < locked_until:
            retry_after = int(locked_until - now) + 1
            raise HTTPException(
                status_code=429,
                detail="Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau.",
                headers={"Retry-After": str(retry_after)},
            )

        # Lọc attempts cũ hơn window
        recent = [t for t in _attempts[key] if now - t < LOCKOUT_WINDOW]

        if len(recent) >= MAX_ATTEMPTS:
            _lockouts[key] = now + LOCKOUT_DURATION
            _attempts[key] = []
            raise HTTPException(
                status_code=429,
                detail="Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau.",
                headers={"Retry-After": str(LOCKOUT_DURATION)},
            )

        recent.append(now)
        _attempts[key] = recent


def record_failed_attempt(ip: str | None, email: str) -> None:
    """
    Gọi SAU khi xác nhận password sai.
    Nếu đủ số lần → tự động khoá.
    """
    key = _make_key(ip, email)
    now = time.monotonic()

    with _lock:
        recent = [t for t in _attempts[key] if now - t < LOCKOUT_WINDOW]
        recent.append(now)

        if len(recent) >= MAX_ATTEMPTS:
            _lockouts[key] = now + LOCKOUT_DURATION
            _attempts[key] = []
        else:
            _attempts[key] = recent


def clear_attempts(ip: str | None, email: str) -> None:
    """Xoá lịch sử sau khi đăng nhập thành công."""
    key = _make_key(ip, email)
    with _lock:
        _attempts.pop(key, None)
        _lockouts.pop(key, None)
