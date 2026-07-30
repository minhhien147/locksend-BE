import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from db.database_url import get_database_url

_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        # Pool PER WORKER: tổng = WEB_CONCURRENCY × (pool_size + max_overflow).
        # Mặc định 4 worker × (3 + 3) = 24 — đủ cho burst nhẹ, dưới trần Postgres Railway (~100).
        _engine = create_async_engine(
            get_database_url(),
            echo=os.getenv("DB_ECHO", "false").lower() == "true",
            pool_pre_ping=True,
            pool_size=int(os.getenv("DB_POOL_SIZE", "3")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "3")),
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
        )
    return _engine


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


class _SessionLocalProxy:
    """Lazy proxy — tránh crash lúc import nếu DATABASE_URL chưa có."""

    def __call__(self, *args, **kwargs):
        return _get_session_factory()(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(_get_session_factory(), name)


AsyncSessionLocal = _SessionLocalProxy()
