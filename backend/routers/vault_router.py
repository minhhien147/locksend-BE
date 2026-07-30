"""Personal vault — folders, quota, list, patch, share-from-vault, delete."""

from __future__ import annotations

import base64
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, require_roles, require_verified_email
from db.dependencies import get_db
from db.models import File as FileModel
from db.models import FileRecipient, RecipientStatus, VaultFolder
from db.models import User
from schemas.files import (
    ShareVaultRequest,
    VaultFileOut,
    VaultFilePatch,
    VaultFolderCreate,
    VaultFolderOut,
    VaultQuotaOut,
)
from routers._upload_helpers import content_disposition_attachment
from services.azure_storage import CONTAINER_NAME, delete_blob, get_blob_service_client
from services.vault_storage import (
    assert_vault_quota,
    get_owner_quota_bytes,
    get_owner_usage_bytes,
    resolve_folder,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["vault"], dependencies=[Depends(require_verified_email)])


def _shared_count(recipients: list) -> int:
    return sum(
        1
        for r in recipients
        if (r.status.value if hasattr(r.status, "value") else str(r.status)) == "active"
    )


@router.get("/vault/quota", response_model=VaultQuotaOut)
async def vault_quota(
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    used = await get_owner_usage_bytes(db, current.id)
    quota_bytes = await get_owner_quota_bytes(db, current.id)
    count = (
        await db.execute(
            select(func.count())
            .select_from(FileModel)
            .where(
                FileModel.owner_id == current.id,
                FileModel.storage_mode == "vault",
            )
        )
    ).scalar_one()
    return VaultQuotaOut(
        used_bytes=used,
        quota_bytes=quota_bytes,
        file_count=int(count or 0),
    )


@router.get("/vault/folders", response_model=list[VaultFolderOut])
async def list_folders(
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    folders = (
        await db.execute(
            select(VaultFolder)
            .where(VaultFolder.owner_id == current.id)
            .order_by(VaultFolder.name)
        )
    ).scalars().all()

    counts: dict[str | None, int] = {}
    rows = (
        await db.execute(
            select(FileModel.folder_id, func.count())
            .where(
                FileModel.owner_id == current.id,
                FileModel.storage_mode == "vault",
            )
            .group_by(FileModel.folder_id)
        )
    ).all()
    for fid, cnt in rows:
        counts[fid] = int(cnt)

    return [
        VaultFolderOut(
            id=f.id,
            name=f.name,
            parent_id=f.parent_id,
            file_count=counts.get(f.id, 0),
            created_at=f.created_at.isoformat(),
        )
        for f in folders
    ]


@router.post("/vault/folders", response_model=VaultFolderOut, status_code=201)
async def create_folder(
    body: VaultFolderCreate,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    if body.parent_id:
        await resolve_folder(db, current.id, body.parent_id)

    existing = (
        await db.execute(
            select(VaultFolder).where(
                VaultFolder.owner_id == current.id,
                VaultFolder.parent_id == body.parent_id,
                VaultFolder.name == body.name.strip(),
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Tên thư mục đã tồn tại")

    folder = VaultFolder(
        owner_id=current.id,
        name=body.name.strip(),
        parent_id=body.parent_id,
    )
    db.add(folder)
    await db.commit()
    await db.refresh(folder)
    return VaultFolderOut(
        id=folder.id,
        name=folder.name,
        parent_id=folder.parent_id,
        file_count=0,
        created_at=folder.created_at.isoformat(),
    )


@router.delete("/vault/folders/{folder_id}", status_code=204)
async def delete_folder(
    folder_id: str,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    folder = await resolve_folder(db, current.id, folder_id)
    in_folder = (
        await db.execute(
            select(func.count())
            .select_from(FileModel)
            .where(FileModel.folder_id == folder.id)
        )
    ).scalar_one()
    if int(in_folder or 0) > 0:
        raise HTTPException(
            status_code=400,
            detail="Thư mục còn file — di chuyển hoặc xóa file trước",
        )
    child = (
        await db.execute(
            select(func.count())
            .select_from(VaultFolder)
            .where(VaultFolder.parent_id == folder.id)
        )
    ).scalar_one()
    if int(child or 0) > 0:
        raise HTTPException(status_code=400, detail="Thư mục còn thư mục con")

    await db.delete(folder)
    await db.commit()


@router.get("/vault/files", response_model=list[VaultFileOut])
async def list_vault_files(
    folder_id: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    if folder_id:
        await resolve_folder(db, current.id, folder_id)

    stmt = (
        select(FileModel)
        .where(
            FileModel.owner_id == current.id,
            FileModel.storage_mode == "vault",
        )
        .order_by(FileModel.created_at.desc())
    )
    if folder_id:
        stmt = stmt.where(FileModel.folder_id == folder_id)
    else:
        stmt = stmt.where(FileModel.folder_id.is_(None))

    if q and q.strip():
        stmt = stmt.where(FileModel.original_filename.ilike(f"%{q.strip()}%"))

    files = (await db.execute(stmt)).scalars().all()
    file_ids = [f.id for f in files]
    recipients_map: dict[str, list] = {fid: [] for fid in file_ids}
    if file_ids:
        fr_rows = (
            await db.execute(
                select(FileRecipient).where(FileRecipient.file_id.in_(file_ids))
            )
        ).scalars().all()
        for fr in fr_rows:
            recipients_map[fr.file_id].append(fr)

    out: list[VaultFileOut] = []
    for f in files:
        recs = recipients_map.get(f.id, [])
        meta = f.metadata_json or {}
        envelope = bool(meta.get("envelopeMode"))
        out.append(
            VaultFileOut(
                file_id=f.id,
                blob_name=f.blob_name,
                original_filename=f.original_filename,
                content_type=f.content_type,
                file_size_bytes=f.file_size_bytes,
                encryption_alg=f.encryption_alg,
                chunk_count=f.chunk_count,
                created_at=f.created_at.isoformat(),
                updated_at=f.updated_at.isoformat(),
                folder_id=f.folder_id,
                shared_count=_shared_count(recs),
                can_share=envelope and f.chunk_count == 1,
                encryption_metadata=meta,
            )
        )
    return out


@router.patch("/vault/files/{file_id}", response_model=VaultFileOut)
async def patch_vault_file(
    file_id: str,
    body: VaultFilePatch,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    file = (
        await db.execute(
            select(FileModel).where(
                FileModel.id == file_id,
                FileModel.owner_id == current.id,
                FileModel.storage_mode == "vault",
            )
        )
    ).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại trong kho")

    if body.folder_id is not None:
        if body.folder_id:
            await resolve_folder(db, current.id, body.folder_id)
        file.folder_id = body.folder_id or None

    if body.original_filename:
        file.original_filename = body.original_filename.strip()

    await db.commit()
    await db.refresh(file)

    recs = (
        await db.execute(
            select(FileRecipient).where(FileRecipient.file_id == file.id)
        )
    ).scalars().all()
    meta = file.metadata_json or {}
    return VaultFileOut(
        file_id=file.id,
        blob_name=file.blob_name,
        original_filename=file.original_filename,
        content_type=file.content_type,
        file_size_bytes=file.file_size_bytes,
        encryption_alg=file.encryption_alg,
        chunk_count=file.chunk_count,
        created_at=file.created_at.isoformat(),
        updated_at=file.updated_at.isoformat(),
        folder_id=file.folder_id,
        shared_count=_shared_count(recs),
        can_share=bool(meta.get("envelopeMode")) and file.chunk_count == 1,
        encryption_metadata=meta,
    )


@router.post("/vault/files/{file_id}/share")
async def share_vault_file(
    file_id: str,
    body: ShareVaultRequest,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Chia sẻ file kho — bọc lại content key cho recipient (không upload lại blob)."""
    file = (
        await db.execute(
            select(FileModel).where(
                FileModel.id == file_id,
                FileModel.owner_id == current.id,
                FileModel.storage_mode == "vault",
            )
        )
    ).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại trong kho")

    meta = file.metadata_json or {}
    if not meta.get("envelopeMode") or file.chunk_count != 1:
        raise HTTPException(
            status_code=400,
            detail="Chỉ chia sẻ được file kho dạng envelope (file nhỏ hơn ngưỡng chunked)",
        )

    recipient_ids = [r.recipient_id for r in body.recipients]
    if len(recipient_ids) != len(set(recipient_ids)):
        raise HTTPException(status_code=422, detail="Danh sách recipients có ID bị trùng")
    if current.id in recipient_ids:
        raise HTTPException(status_code=422, detail="Không thể chia sẻ cho chính mình")

    found_ids = set(
        (await db.execute(select(User.id).where(User.id.in_(recipient_ids)))).scalars().all()
    )
    missing = set(recipient_ids) - found_ids
    if missing:
        raise HTTPException(status_code=422, detail=f"Recipient không tồn tại: {sorted(missing)}")

    added = 0
    for r in body.recipients:
        existing = (
            await db.execute(
                select(FileRecipient).where(
                    FileRecipient.file_id == file.id,
                    FileRecipient.recipient_id == r.recipient_id,
                )
            )
        ).scalar_one_or_none()
        if existing and existing.status == RecipientStatus.active:
            continue
        if existing:
            existing.wrapped_file_key = r.wrapped_file_key
            existing.wrapped_key_alg = r.wrapped_key_alg
            existing.key_id = r.key_id
            existing.wrapped_key_version = r.wrapped_key_version
            existing.status = RecipientStatus.active
            existing.revoked_at = None
        else:
            db.add(
                FileRecipient(
                    file_id=file.id,
                    recipient_id=r.recipient_id,
                    wrapped_file_key=r.wrapped_file_key,
                    wrapped_key_alg=r.wrapped_key_alg,
                    key_id=r.key_id,
                    wrapped_key_version=r.wrapped_key_version,
                    status=RecipientStatus.active,
                )
            )
        added += 1

    await db.commit()
    audit.log_event(
        "vault.share",
        user_id=current.id,
        file_id=file.id,
        recipient_count=added,
        request_id=audit.get_request_id(request),
    )
    return {"status": "shared", "recipients_added": added}


@router.get("/vault/files/{file_id}/ciphertext")
async def download_vault_ciphertext(
    file_id: str,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Proxy ciphertext qua API (tránh CORS Azure Blob từ browser).
    Metadata mã hóa lấy từ DB (files.metadata_json).
    """
    file = (
        await db.execute(
            select(FileModel).where(
                FileModel.id == file_id,
                FileModel.owner_id == current.id,
                FileModel.storage_mode == "vault",
            )
        )
    ).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại trong kho")

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(
            container=CONTAINER_NAME, blob=file.blob_name
        )
        # A06/A10: stream thay vì readall() — tránh OOM khi proxy file lớn.
        downloader = blob_client.download_blob()
        content_length = getattr(downloader, "size", None)
    except Exception as exc:
        logger.exception("download_vault_ciphertext failed: %s", exc)
        raise HTTPException(status_code=502, detail="Không đọc được file từ storage")

    meta_b64 = base64.b64encode(
        json.dumps(file.metadata_json, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")

    headers = {
        "X-Encryption-Metadata-B64": meta_b64,
        "X-File-Id": file.id,
        # A03: tên file có nguồn từ client — helper chặn CR/LF chèn header.
        "Content-Disposition": content_disposition_attachment(f"{file.original_filename}.lsc"),
    }
    if content_length is not None:
        headers["Content-Length"] = str(content_length)

    return StreamingResponse(
        downloader.chunks(),
        media_type="application/octet-stream",
        headers=headers,
    )


@router.delete("/vault/files/{file_id}", status_code=204)
async def delete_vault_file(
    file_id: str,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    file = (
        await db.execute(
            select(FileModel).where(
                FileModel.id == file_id,
                FileModel.owner_id == current.id,
                FileModel.storage_mode == "vault",
            )
        )
    ).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại trong kho")

    try:
        delete_blob(file.blob_name)
    except Exception as exc:
        logger.warning("Azure delete_blob failed for %s: %s", file.blob_name, exc)

    await db.delete(file)
    await db.commit()
