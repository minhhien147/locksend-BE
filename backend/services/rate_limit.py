"""
A04/A07 – Sliding-window rate limit in-memory.

State nằm trong RAM của từng process: với N worker/replica hạn mức thực tế là
limit × N. Đủ để chặn brute-force và lạm dụng API tốn phí, nhưng nếu cần giới
hạn chính xác toàn cụm thì phải chuyển sang Redis.

Hai chế độ:
  - check_rate()      : đếm MỌI lần gọi (throttle endpoint).
  - guard_failures()  : chỉ đọc, raise khi số lần THẤT BẠI đã vượt ngưỡng;
                        dùng kèm record_failure() / clear().
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException

_buckets: dict[str, list[float]] = defaultdict(list)
_lock = Lock()

_MAX_TRACKED_KEYS = 50_000


def _prune_locked(now: float, window: int) -> None:
    """Chặn memory growth vô hạn khi số key quá lớn (key theo user/IP)."""
    if len(_buckets) <= _MAX_TRACKED_KEYS:
        return
    for key in [k for k, v in _buckets.items() if not v or now - v[-1] >= window]:
        _buckets.pop(key, None)


def _recent(composite: str, now: float, window: int) -> list[float]:
    return [t for t in _buckets.get(composite, []) if now - t < window]


def check_rate(
    bucket: str,
    key: str,
    *,
    limit: int,
    window: int,
    detail: str,
) -> None:
    """Raise 429 nếu vượt `limit` lần gọi trong `window` giây. limit<=0 = tắt."""
    if limit <= 0:
        return
    composite = f"{bucket}:{key}"
    now = time.monotonic()
    with _lock:
        _prune_locked(now, window)
        recent = _recent(composite, now, window)
        if len(recent) >= limit:
            raise HTTPException(
                status_code=429,
                detail=detail,
                headers={"Retry-After": str(window)},
            )
        recent.append(now)
        _buckets[composite] = recent


def guard_failures(
    bucket: str,
    key: str,
    *,
    limit: int,
    window: int,
    detail: str,
) -> None:
    """Raise 429 nếu đã có `limit` lần thất bại trong `window` giây (không đếm thêm)."""
    if limit <= 0:
        return
    composite = f"{bucket}:{key}"
    now = time.monotonic()
    with _lock:
        if len(_recent(composite, now, window)) >= limit:
            raise HTTPException(
                status_code=429,
                detail=detail,
                headers={"Retry-After": str(window)},
            )


def record_failure(bucket: str, key: str, *, window: int) -> None:
    composite = f"{bucket}:{key}"
    now = time.monotonic()
    with _lock:
        _prune_locked(now, window)
        recent = _recent(composite, now, window)
        recent.append(now)
        _buckets[composite] = recent


def clear(bucket: str, key: str) -> None:
    with _lock:
        _buckets.pop(f"{bucket}:{key}", None)
