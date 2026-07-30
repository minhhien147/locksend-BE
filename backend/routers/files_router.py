"""files_router.py — File listing, SAS token, và revoke endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, require_roles, require_verified_email
from db.dependencies import get_db
from db.models import File as FileModel, FileRecipient, RecipientStatus, User
from schemas.files import (
    FileHistoryItem,
    FreshSasResponse,
    RecipientInfo,
    RevokeRequest,
    SasResponse,
    SharedFileResponse,
)

from routers._upload_helpers import generate_and_track_sas

logger = logging.getLogger(__name__)

router = APIRouter(tags=["files"], dependencies=[Depends(require_verified_email)])


@router.get("/sas-token/{blob_name:path}", response_model=SasResponse)
async def get_sas_token(
    blob_name: str,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tạo SAS token read-only 1h cho blob đã tồn tại (chỉ owner của blob)."""
    row = (await db.execute(select(FileModel).where(FileModel.blob_name == blob_name))).scalar_one_or_none()
    # A01: blob_name không được coi là bí mật — bắt buộc kiểm tra quyền sở hữu,
    # nếu không bất kỳ owner nào biết blob_name cũng mint được SAS đọc file người khác.
    if row is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy file")
    if row.owner_id != current.id and current.role != "admin":
        logger.warning(
            "SECURITY A01: từ chối SAS cho blob của người khác — user=%s blob=%s owner=%s",
            current.id, blob_name, row.owner_id,
        )
        raise HTTPException(status_code=403, detail="Bạn không có quyền truy cập file này")

    sas_url, expires_at = await generate_and_track_sas(
        request, db, current,
        blob_name=blob_name, file_id=row.id,
        hours=1, endpoint=f"/sas-token/{blob_name}",
    )
    return SasResponse(
        sas_url=sas_url, blob_name=blob_name, expires_at=expires_at, file_id=row.id
    )


@router.get("/files/shared-with-me", response_model=list[SharedFileResponse])
async def shared_with_me(
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Danh sách file được chia sẻ cho user hiện tại (status=active)."""
    stmt = (
        select(FileRecipient, FileModel, User)
        .join(FileModel, FileRecipient.file_id == FileModel.id)
        .join(User, FileModel.owner_id == User.id)
        .where(
            FileRecipient.recipient_id == current.id,
            FileRecipient.status == RecipientStatus.active,
        )
        .order_by(FileModel.created_at.desc())
    )
    rows = (await db.execute(stmt)).all()
    return [
        SharedFileResponse(
            file_id=file.id,
            blob_name=file.blob_name,
            original_filename=file.original_filename,
            content_type=file.content_type,
            file_size_bytes=file.file_size_bytes,
            encryption_alg=file.encryption_alg,
            granted_at=fr.granted_at.isoformat(),
            wrapped_file_key=fr.wrapped_file_key,
            wrapped_key_alg=fr.wrapped_key_alg,
            key_id=fr.key_id,
            wrapped_key_version=fr.wrapped_key_version,
            sender_name=sender.display_name or sender.email,
            sender_email=sender.email,
        )
        for fr, file, sender in rows
    ]


@router.get("/files/shared/{file_id}/sas", response_model=FreshSasResponse)
async def shared_file_sas(
    file_id: str,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tạo SAS URL cho file được chia sẻ — chỉ cho phép active recipient."""
    fr_row = (
        await db.execute(
            select(FileRecipient).where(
                FileRecipient.file_id == file_id,
                FileRecipient.recipient_id == current.id,
                FileRecipient.status == RecipientStatus.active,
            )
        )
    ).scalar_one_or_none()
    if fr_row is None:
        raise HTTPException(status_code=404, detail="File không tồn tại hoặc bạn không phải recipient")

    file = (await db.execute(select(FileModel).where(FileModel.id == file_id))).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại")

    sas_url, expires_at = await generate_and_track_sas(
        request, db, current,
        blob_name=file.blob_name, file_id=file.id,
        hours=24, endpoint=f"/files/shared/{file_id}/sas",
    )
    return FreshSasResponse(file_id=file.id, blob_name=file.blob_name, sas_url=sas_url, expires_at=expires_at)


@router.get("/files/my-files", response_model=list[FileHistoryItem])
async def my_files(
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Lịch sử file đã upload của user hiện tại, mới nhất trước."""
    files = (
        await db.execute(
            select(FileModel).where(FileModel.owner_id == current.id).order_by(FileModel.created_at.desc())
        )
    ).scalars().all()

    file_ids = [f.id for f in files]
    recipients_map: dict[str, list[RecipientInfo]] = {fid: [] for fid in file_ids}
    if file_ids:
        fr_rows = (
            await db.execute(
                select(FileRecipient, User)
                .join(User, FileRecipient.recipient_id == User.id)
                .where(FileRecipient.file_id.in_(file_ids))
                .order_by(FileRecipient.granted_at)
            )
        ).all()
        for fr, usr in fr_rows:
            recipients_map[fr.file_id].append(
                RecipientInfo(
                    recipient_id=fr.recipient_id,
                    email=usr.email,
                    display_name=usr.display_name,
                    status=fr.status.value if hasattr(fr.status, "value") else str(fr.status),
                    granted_at=fr.granted_at.isoformat(),
                )
            )

    return [
        FileHistoryItem(
            file_id=f.id,
            blob_name=f.blob_name,
            original_filename=f.original_filename,
            content_type=f.content_type,
            file_size_bytes=f.file_size_bytes,
            encryption_alg=f.encryption_alg,
            chunk_count=f.chunk_count,
            created_at=f.created_at.isoformat(),
            updated_at=f.updated_at.isoformat(),
            recipients=recipients_map.get(f.id, []),
            storage_mode=f.storage_mode,
            folder_id=f.folder_id,
            shared_count=sum(1 for r in recipients_map.get(f.id, []) if r.status == "active"),
        )
        for f in files
    ]


@router.get("/files/{file_id}/sas", response_model=FreshSasResponse)
async def refresh_sas(
    file_id: str,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tạo lại SAS URL mới (24h) cho file đã upload."""
    file = (
        await db.execute(
            select(FileModel).where(FileModel.id == file_id, FileModel.owner_id == current.id)
        )
    ).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại hoặc không thuộc về bạn")

    sas_url, expires_at = await generate_and_track_sas(
        request, db, current,
        blob_name=file.blob_name, file_id=file.id,
        hours=24, endpoint=f"/files/{file_id}/sas",
    )
    return FreshSasResponse(file_id=file.id, blob_name=file.blob_name, sas_url=sas_url, expires_at=expires_at)


@router.post("/files/{file_id}/revoke/{recipient_id}")
async def revoke_recipient(
    file_id: str,
    recipient_id: str,
    body: RevokeRequest,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Revoke quyền truy cập của recipient — chỉ owner hoặc admin."""
    file_rec = (await db.execute(select(FileModel).where(FileModel.id == file_id))).scalar_one_or_none()
    if file_rec is None:
        raise HTTPException(status_code=404, detail="File không tồn tại")
    if file_rec.owner_id != current.id and current.role != "admin":
        raise HTTPException(status_code=403, detail="Chỉ owner mới được revoke")

    fr = (
        await db.execute(
            select(FileRecipient).where(
                FileRecipient.file_id == file_id,
                FileRecipient.recipient_id == recipient_id,
            )
        )
    ).scalar_one_or_none()
    if fr is None:
        raise HTTPException(status_code=404, detail="Recipient không tồn tại cho file này")
    if fr.status == RecipientStatus.revoked:
        raise HTTPException(status_code=409, detail="Recipient đã bị revoke trước đó")

    fr.status = RecipientStatus.revoked
    fr.revoked_at = datetime.now(timezone.utc)
    fr.revoke_reason = body.reason

    audit.log_event(
        "file.revoke",
        user_id=current.id,
        role=current.role,
        file_id=file_id,
        recipient_id=recipient_id,
        reason=body.reason,
    )
    return {
        "file_id": file_id,
        "recipient_id": recipient_id,
        "status": "revoked",
        "revoked_at": fr.revoked_at.isoformat(),
    }
