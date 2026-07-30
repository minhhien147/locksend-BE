"""
A07/A09 – Xác định client IP đáng tin cậy.

`X-Forwarded-For` do client gửi nên hop bên trái có thể bị giả mạo hoàn toàn.
Proxy tin cậy luôn *append* IP mà nó thực sự thấy vào cuối chuỗi, nên IP thật
nằm ở vị trí thứ TRUSTED_PROXY_COUNT tính từ phải sang.

TRUSTED_PROXY_COUNT=0 → bỏ qua header, chỉ dùng peer TCP (khi không có proxy).
"""
from __future__ import annotations

import os
from typing import Any

TRUSTED_PROXY_COUNT: int = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))


def _peer(request: Any) -> str | None:
    try:
        return request.client.host if request.client else None
    except Exception:  # noqa: BLE001
        return None


def client_ip(request: Any) -> str | None:
    """IP client không thể bị spoof bằng cách tự thêm X-Forwarded-For."""
    peer = _peer(request)
    if TRUSTED_PROXY_COUNT <= 0:
        return peer

    try:
        xff = request.headers.get("X-Forwarded-For") or ""
    except Exception:  # noqa: BLE001
        return peer

    hops = [h.strip() for h in xff.split(",") if h.strip()]
    if not hops:
        return peer

    idx = len(hops) - TRUSTED_PROXY_COUNT
    if idx < 0:
        # Chuỗi ngắn hơn số proxy khai báo → chỉ hop ngoài cùng bên phải là đáng tin.
        return hops[-1]
    return hops[idx]
