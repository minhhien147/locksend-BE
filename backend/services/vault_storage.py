"""Helpers for personal vault (quota, folder validation)."""

from __future__ import annotations

import os

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import File as FileModel
from db.models import User
from db.models import VaultFolder

FREE_STORAGE_QUOTA_BYTES = int(os.getenv("STORAGE_QUOTA_BYTES", str(5 * 1024**3)))
PRO_STORAGE_QUOTA_BYTES = int(os.getenv("PRO_STORAGE_QUOTA_BYTES", str(50 * 1024**3)))
DEFAULT_STORAGE_PLAN = os.getenv("DEFAULT_STORAGE_PLAN", "free").strip().lower() or "free"


def normalize_storage_plan(plan: str | None) -> str:
    raw = (plan or DEFAULT_STORAGE_PLAN or "free").strip().lower()
    return "pro" if raw == "pro" else "free"


def get_plan_quota_bytes(plan: str | None) -> int:
    normalized = normalize_storage_plan(plan)
    if normalized == "pro":
        return PRO_STORAGE_QUOTA_BYTES
    return FREE_STORAGE_QUOTA_BYTES


def get_effective_quota_bytes(
    *,
    storage_plan: str | None,
    vault_quota_bytes: int | None,
) -> int:
    if vault_quota_bytes is not None and vault_quota_bytes > 0:
        return int(vault_quota_bytes)
    return get_plan_quota_bytes(storage_plan)


def get_effective_quota_bytes_for_user(user: User) -> int:
    return get_effective_quota_bytes(
        storage_plan=user.storage_plan,
        vault_quota_bytes=user.vault_quota_bytes,
    )


async def get_owner_quota_bytes(db: AsyncSession, owner_id: str) -> int:
    user = (
        await db.execute(
            select(User.storage_plan, User.vault_quota_bytes).where(User.id == owner_id)
        )
    ).one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    return get_effective_quota_bytes(
        storage_plan=user.storage_plan,
        vault_quota_bytes=user.vault_quota_bytes,
    )


async def get_owner_usage_bytes(db: AsyncSession, owner_id: str) -> int:
    total = (
        await db.execute(
            select(func.coalesce(func.sum(FileModel.file_size_bytes), 0)).where(
                FileModel.owner_id == owner_id,
                FileModel.storage_mode == "vault",
            )
        )
    ).scalar_one()
    return int(total or 0)


async def assert_vault_quota(
    db: AsyncSession, owner_id: str, additional_bytes: int
) -> None:
    used = await get_owner_usage_bytes(db, owner_id)
    quota_bytes = await get_owner_quota_bytes(db, owner_id)
    if used + additional_bytes > quota_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Vượt hạn mức kho lưu trữ ({quota_bytes // (1024**3)} GB). "
                f"Đã dùng {used // (1024**2)} MB."
            ),
        )


async def resolve_folder(
    db: AsyncSession, owner_id: str, folder_id: str | None
) -> VaultFolder | None:
    if not folder_id:
        return None
    folder = (
        await db.execute(
            select(VaultFolder).where(
                VaultFolder.id == folder_id,
                VaultFolder.owner_id == owner_id,
            )
        )
    ).scalar_one_or_none()
    if folder is None:
        raise HTTPException(status_code=404, detail="Thư mục không tồn tại")
    return folder
