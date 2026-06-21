"""_upload_helpers.py — Shared helpers dùng chung bởi upload sub-routers."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser
from db.models import File as FileModel, FileRecipient, RecipientStatus
from services.azure_storage import CONTAINER_NAME, STORAGE_ACCOUNT, generate_sas_url

logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str | None:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


async def generate_and_track_sas(
    request: Request,
    db: AsyncSession,
    current: CurrentUser,
    *,
    blob_name: str,
    file_id: str | None,
    hours: int,
    endpoint: str,
) -> tuple[str, str]:
    """Tạo SAS URL + ghi sas_token_records."""
    from services.token_security import is_sas_revoked, parse_sas_expires, track_sas_issue

    if await is_sas_revoked(db, blob_name, current.id):
        raise HTTPException(
            status_code=403,
            detail="SAS token cho blob này đã bị thu hồi bởi quản trị viên",
        )

    sas_url, expires_at = generate_sas_url(blob_name, hours=hours)
    expires_dt = parse_sas_expires(expires_at)
    await track_sas_issue(
        db,
        blob_name=blob_name,
        user_id=current.id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        expires_at=expires_dt,
        file_id=file_id,
        endpoint=endpoint,
        http_method=request.method,
    )
    return sas_url, expires_at


async def authorize_file_download(
    db: AsyncSession,
    file_row: FileModel,
    current: CurrentUser,
) -> None:
    """Owner, active recipient, hoặc admin được tải ciphertext."""
    if file_row.owner_id == current.id or current.role == "admin":
        return
    fr_row = (
        await db.execute(
            select(FileRecipient).where(
                FileRecipient.file_id == file_row.id,
                FileRecipient.recipient_id == current.id,
                FileRecipient.status == RecipientStatus.active,
            )
        )
    ).scalar_one_or_none()
    if fr_row is None:
        raise HTTPException(status_code=403, detail="Bạn không có quyền tải file này")


def metadata_for_file(file_row: FileModel) -> dict:
    return file_row.metadata_json if isinstance(file_row.metadata_json, dict) else {}


def blob_name_from_sas_url(sas_url: str) -> str:
    """Extract blob name và kiểm tra storage host/container hợp lệ."""
    parsed = urlparse(sas_url.strip())
    expected_host = f"{STORAGE_ACCOUNT}.blob.core.windows.net".lower()
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() != expected_host:
        raise HTTPException(status_code=422, detail="SAS URL không hợp lệ")
    path_parts = [p for p in parsed.path.split("/") if p]
    if len(path_parts) < 2:
        raise HTTPException(status_code=422, detail="SAS URL không hợp lệ")
    if path_parts[0] != CONTAINER_NAME:
        raise HTTPException(status_code=422, detail="SAS URL sai container")
    return "/".join(path_parts[1:])
