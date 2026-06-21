"""download_router.py — Ciphertext download và download logging."""
from __future__ import annotations

import base64 as b64mod
import json
import logging

import audit
from azure.storage.blob import BlobClient
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser, require_roles, require_verified_email
from db.dependencies import get_db
from db.models import DownloadLog, File as FileModel
from schemas.files import CiphertextInfoResponse, DownloadLogRequest, SasCiphertextRequest
from services.azure_storage import CONTAINER_NAME, get_blob_service_client
from services.chunk_layout import encrypted_chunk_byte_length, encrypted_chunk_offset, is_chunked_metadata

from routers._upload_helpers import authorize_file_download, blob_name_from_sas_url, metadata_for_file

logger = logging.getLogger(__name__)

router = APIRouter(tags=["download"], dependencies=[Depends(require_verified_email)])


# ── Ciphertext by SAS ─────────────────────────────────────────────────────────

@router.post("/files/ciphertext/info-by-sas", response_model=CiphertextInfoResponse)
async def ciphertext_info_by_sas(
    body: SasCiphertextRequest,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Trả metadata + file_id từ SAS URL — không tải blob."""
    blob_name = blob_name_from_sas_url(body.sas_url)
    file_row = (await db.execute(select(FileModel).where(FileModel.blob_name == blob_name))).scalar_one_or_none()
    if file_row is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy file")
    await authorize_file_download(db, file_row, current)
    metadata = metadata_for_file(file_row)
    if not metadata:
        raise HTTPException(status_code=404, detail="Không tìm thấy metadata mã hóa")
    return CiphertextInfoResponse(
        file_id=file_row.id,
        original_filename=file_row.original_filename,
        metadata=metadata,
    )


@router.post("/files/ciphertext/by-sas")
async def download_ciphertext_by_sas(
    body: SasCiphertextRequest,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Proxy tải ciphertext từ SAS URL qua backend (tránh CORS ở browser)."""
    blob_name = blob_name_from_sas_url(body.sas_url)
    file_row = (await db.execute(select(FileModel).where(FileModel.blob_name == blob_name))).scalar_one_or_none()
    if file_row is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy file")
    await authorize_file_download(db, file_row, current)

    try:
        blob_client = BlobClient.from_blob_url(body.sas_url)
        data = blob_client.download_blob().readall()
        blob_meta = blob_client.get_blob_properties().metadata or {}
    except Exception as exc:
        logger.exception("download_ciphertext_by_sas failed: %s", exc)
        raise HTTPException(status_code=502, detail="Không tải được file từ storage")

    metadata_b64 = blob_meta.get("encryption_metadata_b64")
    if not metadata_b64 and file_row.metadata_json:
        metadata_b64 = b64mod.b64encode(
            json.dumps(file_row.metadata_json, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")

    headers = {
        "X-File-Id": file_row.id,
        "Content-Disposition": f'attachment; filename="{file_row.original_filename}.enc"',
    }
    if metadata_b64:
        headers["X-Encryption-Metadata-B64"] = metadata_b64

    return Response(content=data, media_type="application/octet-stream", headers=headers)


# ── Chunk download ────────────────────────────────────────────────────────────

@router.get("/files/{file_id}/ciphertext/chunks/{chunk_index}")
async def download_ciphertext_chunk(
    file_id: str,
    chunk_index: int,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tải một encrypted chunk — peak RAM server ≈ 1 chunk (~64MB + tag)."""
    if chunk_index < 0 or chunk_index > 49_999:
        raise HTTPException(status_code=400, detail="chunk_index ngoài giới hạn (0–49999)")

    file_row = (await db.execute(select(FileModel).where(FileModel.id == file_id))).scalar_one_or_none()
    if file_row is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy file")

    await authorize_file_download(db, file_row, current)
    metadata = metadata_for_file(file_row)
    if not is_chunked_metadata(metadata):
        raise HTTPException(status_code=400, detail="File không dùng chế độ chunked")

    chunk_count = metadata.get("chunkCount") or metadata.get("chunk_count")
    if chunk_index >= int(chunk_count):
        raise HTTPException(status_code=400, detail="chunk_index vượt chunk_count")

    offset = encrypted_chunk_offset(metadata, chunk_index)
    length = encrypted_chunk_byte_length(metadata, chunk_index)

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=file_row.blob_name)
        data = blob_client.download_blob(offset=offset, length=length).readall()
    except Exception as exc:
        logger.exception("download_ciphertext_chunk failed file=%s chunk=%s: %s", file_id, chunk_index, exc)
        raise HTTPException(status_code=502, detail="Không đọc được chunk từ storage")

    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "X-Chunk-Index": str(chunk_index),
            "X-Chunk-Length": str(length),
            "X-Chunk-Offset": str(offset),
        },
    )


# ── Download logs ─────────────────────────────────────────────────────────────

async def _persist_download_log(
    request: Request,
    current: CurrentUser,
    db: AsyncSession,
    *,
    file_id: str | None,
    blob_name: str | None,
) -> dict:
    if not file_id and not blob_name:
        raise HTTPException(status_code=422, detail="Cần có file_id hoặc blob_name")

    file_row = None
    if file_id:
        file_row = (await db.execute(select(FileModel).where(FileModel.id == file_id))).scalar_one_or_none()
    if file_row is None and blob_name:
        file_row = (await db.execute(select(FileModel).where(FileModel.blob_name == blob_name))).scalar_one_or_none()

    blob_logged = file_row.blob_name if file_row else (blob_name or file_id or "unknown")
    orig_logged = file_row.original_filename if file_row else "unknown"
    size_logged = file_row.file_size_bytes if file_row else 0
    fid_logged = file_row.id if file_row else None

    db.add(DownloadLog(
        user_id=current.id,
        file_id=fid_logged,
        blob_name=blob_logged,
        original_filename=orig_logged,
        file_size_bytes=size_logged,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    ))
    await db.flush()
    if fid_logged:
        from services import owner_security
        await owner_security.maybe_alert_multi_ip_access(db, fid_logged)
    audit.log_event("file.download", user_id=current.id, role=current.role, file_id=fid_logged, blob_name=blob_logged)
    return {"status": "logged"}


@router.post("/files/download-log", status_code=201)
async def record_download_log_body(
    request: Request,
    body: DownloadLogRequest,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Ghi download_logs — gửi file_id (ưu tiên) hoặc blob_name."""
    return await _persist_download_log(request, current, db, file_id=body.file_id, blob_name=body.blob_name)


@router.post("/files/{file_id}/download-log", status_code=201)
async def record_download_log_by_path(
    request: Request,
    file_id: str,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tương thích: chỉ cần file_id trên URL."""
    return await _persist_download_log(request, current, db, file_id=file_id, blob_name=None)
