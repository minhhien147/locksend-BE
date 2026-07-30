"""
A07 – Identification & Authentication Failures
In-memory brute-force login lockout.

Hai lớp đếm, đều chỉ tăng khi đăng nhập THẤT BẠI:

  1. "<ip>:<email>"  → MAX_ATTEMPTS lần / LOCKOUT_WINDOW giây, khoá LOCKOUT_DURATION.
     Chặn brute-force từ một nguồn.
  2. "<email>"       → MAX_ATTEMPTS_PER_EMAIL lần / LOCKOUT_WINDOW giây.
     Chặn attacker luân phiên IP (hoặc giả X-Forwarded-For) để né lớp 1.

IP phải lấy qua services.client_ip.client_ip() — không tin hop đầu của
X-Forwarded-For, nếu không lớp 1 bị vô hiệu hoàn toàn.

Giới hạn: state trong RAM từng process nên hạn mức thực tế = limit × số worker,
và reset khi restart. Chuyển sang Redis nếu cần chính xác toàn cụm.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException

MAX_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
MAX_ATTEMPTS_PER_EMAIL: int = int(os.getenv("LOGIN_MAX_ATTEMPTS_PER_EMAIL", "15"))
LOCKOUT_WINDOW: int = int(os.getenv("LOGIN_LOCKOUT_WINDOW", "300"))   # 5 phút
LOCKOUT_DURATION: int = int(os.getenv("LOGIN_LOCKOUT_DURATION", "900"))  # 15 phút

_attempts: dict[str, list[float]] = defaultdict(list)
_lockouts: dict[str, float] = {}
_lock = Lock()

_TOO_MANY = "Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau."


def _ip_key(ip: str | None, email: str) -> str:
    return f"ip:{(ip or 'unknown').strip()}|{email.lower()}"


def _email_key(email: str) -> str:
    return f"email:{email.lower()}"


def _raise_locked(retry_after: int) -> None:
    raise HTTPException(
        status_code=429,
        detail=_TOO_MANY,
        headers={"Retry-After": str(max(1, retry_after))},
    )


def _recent_locked(key: str, now: float) -> list[float]:
    return [t for t in _attempts.get(key, []) if now - t < LOCKOUT_WINDOW]


def assert_login_allowed(ip: str | None, email: str) -> None:
    """
    Gọi TRƯỚC khi kiểm tra password. Chỉ ĐỌC trạng thái — không tăng bộ đếm,
    nên user hợp lệ không bao giờ tự khoá mình bằng các lần đăng nhập thành công.
    """
    now = time.monotonic()
    ip_key = _ip_key(ip, email)
    email_key = _email_key(email)

    with _lock:
        for key in (ip_key, email_key):
            locked_until = _lockouts.get(key)
            if locked_until:
                if now < locked_until:
                    _raise_locked(int(locked_until - now) + 1)
                _lockouts.pop(key, None)

        if len(_recent_locked(ip_key, now)) >= MAX_ATTEMPTS:
            _lockouts[ip_key] = now + LOCKOUT_DURATION
            _attempts[ip_key] = []
            _raise_locked(LOCKOUT_DURATION)

        if MAX_ATTEMPTS_PER_EMAIL > 0 and len(_recent_locked(email_key, now)) >= MAX_ATTEMPTS_PER_EMAIL:
            _lockouts[email_key] = now + LOCKOUT_DURATION
            _attempts[email_key] = []
            _raise_locked(LOCKOUT_DURATION)


# Tên cũ giữ lại để không phá call-site hiện có; hành vi nay là read-only.
check_and_record_attempt = assert_login_allowed


def record_failed_attempt(ip: str | None, email: str) -> None:
    """Gọi SAU khi xác nhận đăng nhập thất bại. Tăng cả hai lớp đếm."""
    now = time.monotonic()

    with _lock:
        for key, limit in ((_ip_key(ip, email), MAX_ATTEMPTS),
                           (_email_key(email), MAX_ATTEMPTS_PER_EMAIL)):
            if limit <= 0:
                continue
            recent = _recent_locked(key, now)
            recent.append(now)
            if len(recent) >= limit:
                _lockouts[key] = now + LOCKOUT_DURATION
                _attempts[key] = []
            else:
                _attempts[key] = recent


def clear_attempts(ip: str | None, email: str) -> None:
    """Xoá lịch sử sau khi đăng nhập thành công."""
    with _lock:
        for key in (_ip_key(ip, email), _email_key(email)):
            _attempts.pop(key, None)
            _lockouts.pop(key, None)
