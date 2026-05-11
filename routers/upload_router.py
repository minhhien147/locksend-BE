from __future__ import annotations

import base64 as b64mod
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser, require_roles
from db.dependencies import get_db
from db.models import File as FileModel
from db.models import FileRecipient, RecipientStatus, UploadSession, User
from schemas.files import (
    MultipartFinalizeRequest,
    MultipartInitResponse,
    RevokeRequest,
    SasResponse,
    SharedFileResponse,
)
from services.azure_storage import CONTAINER_NAME, generate_sas_url, get_blob_service_client
import audit


logger = logging.getLogger(__name__)

router = APIRouter(tags=["upload"])


@router.post("/upload", response_model=SasResponse)
async def upload_file(
    file: UploadFile = File(...),
    metadata_json: str = Form(...),
    current: CurrentUser = Depends(require_roles("owner", "admin")),
):
    """Nhận ciphertext + metadata đã mã hóa client-side, upload lên Azure Blob."""
    blob_name = f"{uuid.uuid4()}/{file.filename}"
    ciphertext = await file.read()

    ciphertext_checksum = hashlib.sha256(ciphertext).hexdigest()

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.upload_blob(
            ciphertext,
            overwrite=True,
            metadata={
                "encryption_metadata": metadata_json,
                "ciphertext_checksum": ciphertext_checksum,
            },
        )
    except Exception as exc:  # pragma: no cover - network failure
        logger.exception("Upload failed for user %s: %s", current.id, exc)
        raise HTTPException(status_code=500, detail="Upload failed")

    sas_url, expires_at = generate_sas_url(blob_name)
    logger.info(
        "Upload success blob=%s user=%s ciphertext_sha256=%s request_id=%s",
        blob_name,
        current.id,
        ciphertext_checksum,
        getattr(current, "request_id", "-"),
    )
    return SasResponse(sas_url=sas_url, blob_name=blob_name, expires_at=expires_at)


@router.get("/sas-token/{blob_name:path}", response_model=SasResponse)
def get_sas_token(blob_name: str, _: CurrentUser = Depends(require_roles("owner", "admin"))):
    """Tạo SAS token read-only 1h cho blob đã tồn tại."""
    sas_url, expires_at = generate_sas_url(blob_name, hours=1)
    return SasResponse(sas_url=sas_url, blob_name=blob_name, expires_at=expires_at)


@router.post("/upload/multipart/init", response_model=MultipartInitResponse)
async def multipart_init(
    filename: str = Form(...),
    chunk_size_bytes: int = Form(default=5 * 1024 * 1024, gt=0),
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Bước 1: Khởi tạo phiên multipart upload."""
    safe_name = filename.replace("/", "_").replace("..", "_")
    blob_name = f"{uuid.uuid4()}/{safe_name}.enc"
    session_id = str(uuid.uuid4())

    db.add(
        UploadSession(
            owner_id=current.id,
            blob_name=blob_name,
            upload_id=session_id,
            original_filename=filename,
            chunk_size_bytes=chunk_size_bytes,
            status="initiated",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    )
    return MultipartInitResponse(blob_name=blob_name, upload_id=session_id)


@router.put("/upload/multipart/{blob_name:path}/chunk/{chunk_index}")
async def multipart_upload_chunk(
    blob_name: str,
    chunk_index: int,
    chunk: UploadFile = File(...),
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Bước 2: Stage một block (chunk) lên Azure Block Blob."""
    if chunk_index < 0 or chunk_index > 49_999:
        raise HTTPException(status_code=400, detail="chunk_index ngoài giới hạn (0–49999)")

    result = await db.execute(
        select(UploadSession).where(
            UploadSession.blob_name == blob_name,
            UploadSession.owner_id == current.id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session không tồn tại")

    block_id = b64mod.b64encode(f"{chunk_index:08d}".encode()).decode()
    data = await chunk.read()
    if not data:
        raise HTTPException(status_code=400, detail="Chunk rỗng")

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.stage_block(block_id, data)
    except Exception as exc:  # pragma: no cover - network failure
        logger.exception("Stage block failed: %s", exc)
        raise HTTPException(status_code=500, detail="Stage block failed")

    await db.execute(
        update(UploadSession)
        .where(UploadSession.blob_name == blob_name)
        .values(
            uploaded_chunk_count=UploadSession.uploaded_chunk_count + 1,
            status="uploading",
        )
    )
    return {"chunk_index": chunk_index, "block_id": block_id, "size": len(data)}


@router.post("/upload/multipart/{blob_name:path}/finalize", response_model=SasResponse)
async def multipart_finalize(
    blob_name: str,
    body: MultipartFinalizeRequest,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Bước 3: Commit blob + lưu metadata + ghi wrapped keys cho từng recipient."""
    result = await db.execute(
        select(UploadSession).where(
            UploadSession.blob_name == blob_name,
            UploadSession.owner_id == current.id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session không tồn tại")

    block_ids = [
        b64mod.b64encode(f"{i:08d}".encode()).decode() for i in range(body.chunk_count)
    ]

    try:
        meta_preview = json.loads(body.metadata_json)
        has_chunk_checksums = bool(meta_preview.get("chunkChecksums"))
    except (json.JSONDecodeError, AttributeError):
        has_chunk_checksums = False

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.commit_block_list(
            block_ids,
            metadata={
                "encryption_metadata": body.metadata_json,
                "has_chunk_checksums": str(has_chunk_checksums).lower(),
            },
        )
    except Exception as exc:  # pragma: no cover - network failure
        logger.exception("Commit block list failed: %s", exc)
        raise HTTPException(status_code=500, detail="Commit block list failed")

    try:
        meta = json.loads(body.metadata_json)
    except json.JSONDecodeError:
        meta = {}

    original_filename = (
        body.original_filename or meta.get("filename") or blob_name.split("/")[-1]
    )

    file_record = FileModel(
        owner_id=current.id,
        blob_name=blob_name,
        original_filename=original_filename,
        content_type=body.content_type or meta.get("content_type"),
        file_size_bytes=body.file_size_bytes or meta.get("file_size_bytes", 0),
        encryption_alg=body.encryption_alg,
        chunk_size_bytes=body.chunk_size_bytes,
        chunk_count=body.chunk_count,
        metadata_json=meta,
    )
    db.add(file_record)
    await db.flush()

    if body.recipients:
        recipient_ids = [r.recipient_id for r in body.recipients]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise HTTPException(
                status_code=422, detail="Danh sách recipients có ID bị trùng"
            )
        if current.id in recipient_ids:
            raise HTTPException(
                status_code=422, detail="Owner không thể thêm chính mình làm recipient"
            )

        found_ids = set(
            (await db.execute(select(User.id).where(User.id.in_(recipient_ids))))
            .scalars()
            .all()
        )
        missing = set(recipient_ids) - found_ids
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"Recipient không tồn tại: {sorted(missing)}",
            )

        for r in body.recipients:
            db.add(
                FileRecipient(
                    file_id=file_record.id,
                    recipient_id=r.recipient_id,
                    wrapped_file_key=r.wrapped_file_key,
                    wrapped_key_alg=r.wrapped_key_alg,
                    key_id=r.key_id,
                    wrapped_key_version=r.wrapped_key_version,
                    status=RecipientStatus.active,
                )
            )

        audit.log_event(
            "file.share",
            user_id=current.id,
            role=current.role,
            file_id=file_record.id,
            recipient_count=len(body.recipients),
        )

    await db.execute(
        update(UploadSession)
        .where(UploadSession.blob_name == blob_name)
        .values(status="finalized", expected_chunk_count=body.chunk_count)
    )

    sas_url, expires_at = generate_sas_url(blob_name)
    logger.info(
        "Multipart finalize success blob=%s user=%s chunks=%d has_chunk_checksums=%s",
        blob_name,
        current.id,
        body.chunk_count,
        has_chunk_checksums,
    )
    return SasResponse(sas_url=sas_url, blob_name=blob_name, expires_at=expires_at)


@router.get("/files/shared-with-me", response_model=list[SharedFileResponse])
async def shared_with_me(
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Danh sách file được chia sẻ cho user hiện tại (status=active)."""
    stmt = (
        select(FileRecipient, FileModel)
        .join(FileModel, FileRecipient.file_id == FileModel.id)
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
        )
        for fr, file in rows
    ]


@router.post("/files/{file_id}/revoke/{recipient_id}")
async def revoke_recipient(
    file_id: str,
    recipient_id: str,
    body: RevokeRequest,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke quyền truy cập của recipient.
    Chỉ owner của file hoặc admin mới được revoke.
    """
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    file_rec = result.scalar_one_or_none()
    if file_rec is None:
        raise HTTPException(status_code=404, detail="File không tồn tại")
    if file_rec.owner_id != current.id and current.role != "admin":
        raise HTTPException(status_code=403, detail="Chỉ owner mới được revoke")

    result2 = await db.execute(
        select(FileRecipient).where(
            FileRecipient.file_id == file_id,
            FileRecipient.recipient_id == recipient_id,
        )
    )
    fr = result2.scalar_one_or_none()
    if fr is None:
        raise HTTPException(status_code=404, detail="Recipient không tồn tại cho file này")
    if fr.status == RecipientStatus.revoked:
        raise HTTPException(status_code=409, detail="Recipient đã bị revoke trước đó")

    from datetime import datetime, timezone

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

