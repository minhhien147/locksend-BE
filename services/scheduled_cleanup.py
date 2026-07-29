"""
Lịch dọn token_access_logs + sas_token_records định kỳ (mặc định 7 ngày/lần).

Chạy background task khi backend khởi động. Dùng PostgreSQL advisory lock để
chỉ một instance (replica) thực hiện cleanup nếu scale nhiều pod.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from sqlalchemy import text

from db.session import AsyncSessionLocal
from services import token_security as ts

logger = logging.getLogger(__name__)

_ENABLED = os.getenv("TOKEN_CLEANUP_SCHEDULE_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
)
_INTERVAL_DAYS = float(os.getenv("TOKEN_CLEANUP_INTERVAL_DAYS", "7"))
_STARTUP_DELAY_SEC = int(os.getenv("TOKEN_CLEANUP_STARTUP_DELAY_SEC", "120"))
_VACUUM = os.getenv("TOKEN_CLEANUP_VACUUM", "true").lower() in ("1", "true", "yes")

# Khóa cố định — tránh nhiều worker Railway chạy cleanup cùng lúc
_ADVISORY_LOCK_ID = 83920421

_task: asyncio.Task[None] | None = None


async def _try_advisory_lock(db) -> bool:
    row = await db.execute(
        text("SELECT pg_try_advisory_lock(:lock_id)"),
        {"lock_id": _ADVISORY_LOCK_ID},
    )
    return bool(row.scalar())


async def _advisory_unlock(db) -> None:
    await db.execute(
        text("SELECT pg_advisory_unlock(:lock_id)"),
        {"lock_id": _ADVISORY_LOCK_ID},
    )


async def vacuum_token_security_tables() -> None:
    """VACUUM ANALYZE sau bulk delete — giúp Postgres tái sử dụng dung lượng."""
    if not _VACUUM:
        return
    from db.session import _get_engine

    engine = _get_engine()
    async with engine.connect() as conn:
        autocommit = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await autocommit.execute(text("VACUUM ANALYZE token_access_logs"))
        await autocommit.execute(text("VACUUM ANALYZE sas_token_records"))


async def run_scheduled_cleanup_once() -> dict[str, Any] | None:
    """
    Một lần cleanup. Trả về None nếu instance khác đang giữ lock.
    """
    async with AsyncSessionLocal() as db:
        if not await _try_advisory_lock(db):
            logger.info("Scheduled token cleanup skipped — another instance holds lock")
            return None
        try:
            result = await ts.cleanup_expired_tokens(db)
            await db.commit()
        except Exception:
            await db.rollback()
            await _advisory_unlock(db)
            raise
        else:
            await _advisory_unlock(db)

    await vacuum_token_security_tables()
    logger.info(
        "Scheduled token cleanup done: deleted_sas=%s deleted_access_logs=%s",
        result["deleted_sas_records"],
        result["deleted_access_logs"],
    )
    return result


async def _cleanup_loop() -> None:
    await asyncio.sleep(_STARTUP_DELAY_SEC)
    while True:
        try:
            await run_scheduled_cleanup_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Scheduled token cleanup failed: %s", exc)
        await asyncio.sleep(_INTERVAL_DAYS * 86400)


def start_scheduled_cleanup() -> asyncio.Task[None] | None:
    global _task
    if not _ENABLED:
        logger.info("Scheduled token cleanup disabled (TOKEN_CLEANUP_SCHEDULE_ENABLED=false)")
        return None
    _task = asyncio.create_task(_cleanup_loop(), name="token-cleanup-scheduler")
    logger.info(
        "Scheduled token cleanup: every %.1f day(s), log retention=%d d, sas retention=%d d",
        _INTERVAL_DAYS,
        ts.ACCESS_LOG_RETENTION_DAYS,
        ts.SAS_RECORD_RETENTION_DAYS,
    )
    return _task


async def stop_scheduled_cleanup(task: asyncio.Task[None] | None) -> None:
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
