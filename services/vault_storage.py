"""Helpers for personal vault (quota, folder validation)."""

from __future__ import annotations

import os

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import File as FileModel
from db.models import VaultFolder

STORAGE_QUOTA_BYTES = int(os.getenv("STORAGE_QUOTA_BYTES", str(5 * 1024**3)))


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
    if used + additional_bytes > STORAGE_QUOTA_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Vượt hạn mức kho lưu trữ ({STORAGE_QUOTA_BYTES // (1024**3)} GB). "
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
