"""upload_router.py — Upload endpoints: single-shot và multipart."""
from __future__ import annotations

import base64 as b64mod
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, require_roles, require_verified_email
from db.dependencies import get_db
from db.models import File as FileModel, FileRecipient, RecipientStatus, UploadLog, UploadSession, User
from schemas.files import MultipartFinalizeRequest, MultipartInitResponse, SasResponse
from services.azure_storage import CONTAINER_NAME, get_blob_service_client
from services.vault_storage import assert_vault_quota, resolve_folder

from routers._upload_helpers import generate_and_track_sas, get_client_ip, sanitize_filename
from routers.files_router import router as files_router
from routers.download_router import router as download_router

logger = logging.getLogger(__name__)

router = APIRouter(tags=["upload"], dependencies=[Depends(require_verified_email)])
router.include_router(files_router)
router.include_router(download_router)


# ── Single-shot upload ────────────────────────────────────────────────────────

@router.post("/upload", response_model=SasResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    metadata_json: str = Form(...),
    recipients_json: str = Form(default=None),
    storage_mode: str = Form(default="share"),
    folder_id: str | None = Form(default=None),
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Nhận ciphertext + metadata đã mã hóa client-side, upload lên Azure Blob."""
    mode = storage_mode.strip().lower()
    if mode not in ("share", "vault"):
        raise HTTPException(status_code=422, detail="storage_mode phải là share hoặc vault")

    # A03: Sanitize tên file blob để tránh path traversal
    safe_blob_filename = sanitize_filename(file.filename or "upload")
    blob_name = f"{uuid.uuid4()}/{safe_blob_filename}"
    ciphertext = await file.read()
    file_size = len(ciphertext)

    if mode == "vault":
        await assert_vault_quota(db, current.id, file_size)
        await resolve_folder(db, current.id, folder_id)
        recipients_json = None

    ciphertext_checksum = hashlib.sha256(ciphertext).hexdigest()
    metadata_b64 = b64mod.b64encode(metadata_json.encode("utf-8")).decode("ascii")

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.upload_blob(
            ciphertext,
            overwrite=True,
            metadata={
                "encryption_metadata_b64": metadata_b64,
                "ciphertext_checksum": ciphertext_checksum,
            },
        )
    except Exception as exc:
        logger.exception("Upload failed for user %s: %s", current.id, exc)
        raise HTTPException(status_code=500, detail="Upload failed")

    try:
        meta = json.loads(metadata_json)
    except json.JSONDecodeError:
        meta = {}

    original_filename = meta.get("filename") or file.filename or blob_name.split("/")[-1]
    encryption_alg = meta.get("encryption_alg") or meta.get("algorithm") or "X25519+HKDF+AES-256-GCM"
    meta["storage_mode"] = mode

    file_record = FileModel(
        owner_id=current.id,
        storage_mode=mode,
        folder_id=folder_id if mode == "vault" else None,
        blob_name=blob_name,
        original_filename=original_filename,
        content_type=file.content_type or meta.get("content_type"),
        file_size_bytes=file_size,
        encryption_alg=encryption_alg,
        chunk_size_bytes=None,
        chunk_count=1,
        metadata_json=meta,
    )
    db.add(file_record)
    await db.flush()

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.set_blob_metadata({
            "encryption_metadata_b64": metadata_b64,
            "ciphertext_checksum": ciphertext_checksum,
            "file_id": file_record.id,
        })
    except Exception as exc:
        logger.warning("set_blob_metadata(file_id) failed: %s", exc)

    if mode == "share" and recipients_json:
        try:
            recipients_data = json.loads(recipients_json)
        except json.JSONDecodeError:
            recipients_data = []

        if recipients_data:
            recipient_ids = [r["recipient_id"] for r in recipients_data]
            if len(recipient_ids) != len(set(recipient_ids)):
                raise HTTPException(status_code=422, detail="Danh sách recipients có ID bị trùng")
            if current.id in recipient_ids:
                raise HTTPException(status_code=422, detail="Owner không thể thêm chính mình làm recipient")

            found_ids = set(
                (await db.execute(select(User.id).where(User.id.in_(recipient_ids)))).scalars().all()
            )
            missing = set(recipient_ids) - found_ids
            if missing:
                raise HTTPException(status_code=422, detail=f"Recipient không tồn tại: {sorted(missing)}")

            for r in recipients_data:
                db.add(FileRecipient(
                    file_id=file_record.id,
                    recipient_id=r["recipient_id"],
                    wrapped_file_key=r.get("wrapped_file_key", ""),
                    wrapped_key_alg=r.get("wrapped_key_alg", "X25519-HKDF"),
                    key_id=r.get("key_id"),
                    wrapped_key_version=r.get("wrapped_key_version", 1),
                    status=RecipientStatus.active,
                ))
            audit.log_event(
                "file.share",
                user_id=current.id,
                role=current.role,
                file_id=file_record.id,
                recipient_count=len(recipients_data),
            )

    db.add(UploadLog(
        user_id=current.id,
        file_id=file_record.id,
        blob_name=blob_name,
        original_filename=original_filename,
        file_size_bytes=file_size,
        upload_type="single",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    ))

    audit.log_event(
        "file.upload",
        user_id=current.id,
        role=current.role,
        file_id=file_record.id,
        blob_name=blob_name,
        file_size_bytes=file_size,
        ciphertext_sha256=ciphertext_checksum,
    )

    sas_url, expires_at = await generate_and_track_sas(
        request, db, current,
        blob_name=blob_name, file_id=file_record.id, hours=24, endpoint="/upload",
    )
    logger.info("Upload success blob=%s user=%s sha256=%s", blob_name, current.id, ciphertext_checksum)
    return SasResponse(sas_url=sas_url, blob_name=blob_name, expires_at=expires_at, file_id=file_record.id)


# ── Multipart upload ──────────────────────────────────────────────────────────

@router.post("/upload/multipart/init", response_model=MultipartInitResponse)
async def multipart_init(
    filename: str = Form(...),
    chunk_size_bytes: int = Form(default=5 * 1024 * 1024, gt=0),
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Bước 1: Khởi tạo phiên multipart upload."""
    safe_name = sanitize_filename(filename)
    blob_name = f"{uuid.uuid4()}/{safe_name}.lsc"
    session_id = str(uuid.uuid4())

    db.add(UploadSession(
        owner_id=current.id,
        blob_name=blob_name,
        upload_id=session_id,
        original_filename=filename,
        chunk_size_bytes=chunk_size_bytes,
        status="initiated",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    ))
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

    session = (
        await db.execute(
            select(UploadSession).where(
                UploadSession.blob_name == blob_name,
                UploadSession.owner_id == current.id,
            )
        )
    ).scalar_one_or_none()
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
    except Exception as exc:
        logger.exception("Stage block failed: %s", exc)
        raise HTTPException(status_code=500, detail="Stage block failed")

    await db.execute(
        update(UploadSession)
        .where(UploadSession.blob_name == blob_name)
        .values(uploaded_chunk_count=UploadSession.uploaded_chunk_count + 1, status="uploading")
    )
    return {"chunk_index": chunk_index, "block_id": block_id, "size": len(data)}


@router.post("/upload/multipart/{blob_name:path}/finalize", response_model=SasResponse)
async def multipart_finalize(
    request: Request,
    blob_name: str,
    body: MultipartFinalizeRequest,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Bước 3: Commit blob + lưu metadata + ghi wrapped keys cho từng recipient."""
    session = (
        await db.execute(
            select(UploadSession).where(
                UploadSession.blob_name == blob_name,
                UploadSession.owner_id == current.id,
            )
        )
    ).scalar_one_or_none()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session không tồn tại")

    block_ids = [b64mod.b64encode(f"{i:08d}".encode()).decode() for i in range(body.chunk_count)]

    try:
        meta_preview = json.loads(body.metadata_json)
        has_chunk_checksums = bool(meta_preview.get("chunkChecksums"))
    except (json.JSONDecodeError, AttributeError):
        has_chunk_checksums = False

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.commit_block_list(block_ids)
    except Exception as exc:
        logger.exception("Commit block list failed: %s", exc)
        raise HTTPException(status_code=500, detail="Commit block list failed")

    try:
        meta = json.loads(body.metadata_json)
    except json.JSONDecodeError:
        meta = {}

    original_filename = body.original_filename or meta.get("filename") or blob_name.split("/")[-1]
    mode = (body.storage_mode or "share").strip().lower()
    if mode not in ("share", "vault"):
        raise HTTPException(status_code=422, detail="storage_mode phải là share hoặc vault")

    file_size = body.file_size_bytes or meta.get("file_size_bytes", 0) or meta.get("fileSize", 0)
    if mode == "vault":
        await assert_vault_quota(db, current.id, int(file_size))
        await resolve_folder(db, current.id, body.folder_id)

    meta["storage_mode"] = mode
    file_record = FileModel(
        owner_id=current.id,
        storage_mode=mode,
        folder_id=body.folder_id if mode == "vault" else None,
        blob_name=blob_name,
        original_filename=original_filename,
        content_type=body.content_type or meta.get("content_type"),
        file_size_bytes=int(file_size),
        encryption_alg=body.encryption_alg,
        chunk_size_bytes=body.chunk_size_bytes,
        chunk_count=body.chunk_count,
        metadata_json=meta,
    )
    db.add(file_record)
    await db.flush()

    if mode == "share" and body.recipients:
        recipient_ids = [r.recipient_id for r in body.recipients]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise HTTPException(status_code=422, detail="Danh sách recipients có ID bị trùng")
        if current.id in recipient_ids:
            raise HTTPException(status_code=422, detail="Owner không thể thêm chính mình làm recipient")

        found_ids = set((await db.execute(select(User.id).where(User.id.in_(recipient_ids)))).scalars().all())
        missing = set(recipient_ids) - found_ids
        if missing:
            raise HTTPException(status_code=422, detail=f"Recipient không tồn tại: {sorted(missing)}")

        for r in body.recipients:
            db.add(FileRecipient(
                file_id=file_record.id,
                recipient_id=r.recipient_id,
                wrapped_file_key=r.wrapped_file_key,
                wrapped_key_alg=r.wrapped_key_alg,
                key_id=r.key_id,
                wrapped_key_version=r.wrapped_key_version,
                status=RecipientStatus.active,
            ))
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
    db.add(UploadLog(
        user_id=current.id,
        file_id=file_record.id,
        blob_name=blob_name,
        original_filename=original_filename,
        file_size_bytes=body.file_size_bytes or meta.get("file_size_bytes", 0),
        upload_type="multipart",
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    ))

    try:
        client2 = get_blob_service_client()
        blob_client2 = client2.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client2.set_blob_metadata({
            "encryption_metadata_b64": metadata_b64,
            "has_chunk_checksums": str(has_chunk_checksums).lower(),
            "file_id": file_record.id,
        })
    except Exception as exc:
        logger.warning("set_blob_metadata(file_id) multipart failed: %s", exc)

    sas_url, expires_at = await generate_and_track_sas(
        request, db, current,
        blob_name=blob_name, file_id=file_record.id, hours=24,
        endpoint=f"/upload/multipart/{blob_name}/finalize",
    )
    logger.info("Multipart finalize success blob=%s user=%s chunks=%d", blob_name, current.id, body.chunk_count)
    return SasResponse(sas_url=sas_url, blob_name=blob_name, expires_at=expires_at, file_id=file_record.id)
