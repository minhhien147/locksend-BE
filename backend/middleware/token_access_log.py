"""
Ghi TokenAccessLog cho mọi request mang Bearer token hợp lệ.

Trước đây phần này nằm trong request path: verify JWT, SELECT user theo external_id,
rồi INSERT log — cộng 2 round-trip DB vào mọi request đã xác thực và giữ một
connection của pool trong suốt thời gian đó. Ở 100 user upload đồng thời thì đây là
điểm nghẽn lớn hơn cả việc upload.

Bây giờ middleware chỉ đẩy một tuple vào queue trong RAM (không chạm DB, không verify
JWT). Một worker nền gom theo lô, verify + resolve user_id một lần cho cả lô, và cache
map external_id → user_id để bỏ hẳn phần lớn các SELECT.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

QUEUE_SIZE = max(100, int(os.getenv("TOKEN_ACCESS_LOG_QUEUE_SIZE", "5000")))
BATCH_SIZE = max(1, int(os.getenv("TOKEN_ACCESS_LOG_BATCH_SIZE", "50")))
USER_CACHE_TTL = float(os.getenv("TOKEN_ACCESS_LOG_USER_CACHE_TTL", "300"))
USER_CACHE_MAX = 2000


@dataclass(slots=True)
class _AccessEvent:
    token: str
    ip_address: str | None
    user_agent: str | None
    endpoint: str
    http_method: str
    status_code: int


_queue: asyncio.Queue[_AccessEvent] = asyncio.Queue(maxsize=QUEUE_SIZE)
_worker_task: asyncio.Task[None] | None = None
_dropped = 0

# external_id → (user_id, thời điểm cache)
_user_cache: dict[str, tuple[str | None, float]] = {}


# ── Middleware ────────────────────────────────────────────────────────────────


class TokenAccessLogMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        skip_paths: frozenset[str] = frozenset(),
        skip_prefixes: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self.skip_paths = skip_paths
        self.skip_prefixes = skip_prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope["path"]
        if path in self.skip_paths or path.startswith(self.skip_prefixes):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            await self.app(scope, receive, send)
            return

        status_code = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        await self.app(scope, receive, send_wrapper)

        xff = headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
        else:
            client = scope.get("client")
            ip = client[0] if client else None

        _enqueue(
            _AccessEvent(
                token=auth[7:],
                ip_address=ip,
                user_agent=headers.get("user-agent"),
                endpoint=path,
                http_method=scope["method"],
                status_code=status_code,
            )
        )


def _enqueue(event: _AccessEvent) -> None:
    global _dropped
    try:
        _queue.put_nowait(event)
    except asyncio.QueueFull:
        _dropped += 1
        if _dropped % 100 == 1:
            logger.warning(
                "TokenAccessLog queue đầy (%d) — đã bỏ %d event; "
                "tăng TOKEN_ACCESS_LOG_QUEUE_SIZE hoặc kiểm tra DB chậm",
                QUEUE_SIZE,
                _dropped,
            )


# ── Background worker ─────────────────────────────────────────────────────────


async def _resolve_user_ids(db, external_ids: set[str]) -> None:
    """Nạp các external_id chưa có trong cache bằng MỘT query."""
    from sqlalchemy import select

    from db.models import User

    now = time.monotonic()
    missing = [
        ext
        for ext in external_ids
        if ext not in _user_cache or now - _user_cache[ext][1] > USER_CACHE_TTL
    ]
    if not missing:
        return

    rows = (
        await db.execute(
            select(User.external_id, User.id).where(User.external_id.in_(missing))
        )
    ).all()
    found = {ext: uid for ext, uid in rows}

    if len(_user_cache) > USER_CACHE_MAX:
        _user_cache.clear()
    for ext in missing:
        _user_cache[ext] = (found.get(ext), now)


async def _flush(events: list[_AccessEvent]) -> None:
    from auth import verify_jwt
    from db.dependencies import get_db_context
    from services import token_security as ts

    decoded: list[tuple[_AccessEvent, str, str]] = []
    for event in events:
        try:
            payload = verify_jwt(event.token)
        except Exception:
            continue  # token hết hạn/không hợp lệ → không ghi log, giống hành vi cũ
        jti = str(payload.get("jti", ""))
        token_ref = f"{jti[:4]}…{jti[-4:]}" if len(jti) > 8 else "***"
        decoded.append((event, token_ref, str(payload.get("sub", ""))))

    if not decoded:
        return

    async with get_db_context() as db:
        await _resolve_user_ids(db, {ext for _, _, ext in decoded if ext})

        for event, token_ref, external_id in decoded:
            user_id = _user_cache.get(external_id, (None, 0.0))[0]
            await ts.log_token_access(
                db,
                token_type="jwt",
                token_ref=token_ref,
                user_id=user_id,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                endpoint=event.endpoint,
                http_method=event.http_method,
                status_code=event.status_code,
            )

            if user_id and event.status_code < 500:
                from services.ai_realtime import schedule_token_access_scan

                schedule_token_access_scan(
                    token_type="jwt",
                    token_ref=token_ref,
                    user_id=user_id,
                    endpoint=event.endpoint,
                    ip_address=event.ip_address,
                )


async def _worker() -> None:
    while True:
        batch = [await _queue.get()]
        # Gom thêm những event đã nằm sẵn trong queue → 1 transaction cho cả lô.
        while len(batch) < BATCH_SIZE:
            try:
                batch.append(_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        try:
            await _flush(batch)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("TokenAccessLog flush lỗi (%d event): %s", len(batch), exc)


def start_token_access_log_worker() -> asyncio.Task[None] | None:
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(_worker())
    return _worker_task


async def stop_token_access_log_worker() -> None:
    global _worker_task
    if _worker_task is None:
        return
    _worker_task.cancel()
    try:
        await _worker_task
    except (asyncio.CancelledError, Exception):
        pass
    _worker_task = None
