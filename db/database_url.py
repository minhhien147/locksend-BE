"""Đọc / chuẩn hoá DATABASE_URL — không tạo engine (dùng được trong Alembic)."""
from __future__ import annotations

import os


def normalize_database_url(url: str) -> str:
    u = url.strip()
    if u.startswith("postgres://"):
        return "postgresql+asyncpg://" + u[len("postgres://") :]
    if u.startswith("postgresql://"):
        return "postgresql+asyncpg://" + u[len("postgresql://") :]
    return u


def get_database_url() -> str:
    raw = os.getenv("DATABASE_URL", "").strip()
    if not raw:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "On Railway: add PostgreSQL → service locksend-BE → Variables → "
            'Reference "${{Postgres.DATABASE_URL}}" or paste DATABASE_URL.'
        )
    return normalize_database_url(raw)
