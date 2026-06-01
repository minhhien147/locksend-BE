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

from auth import CurrentUser, require_roles
from db.dependencies import get_db
from db.models import File as FileModel
from db.models import (
    DownloadLog,
    FileRecipient,
    RecipientStatus,
    UploadLog,
    UploadSession,
    User,
)
from schemas.files import (
    DownloadLogRequest,
    FileHistoryItem,
    FreshSasResponse,
    MultipartFinalizeRequest,
    MultipartInitResponse,
    RecipientInfo,
    RevokeRequest,
    SasResponse,
    SharedFileResponse,
)
from services.azure_storage import CONTAINER_NAME, generate_sas_url, get_blob_service_client
from services.vault_storage import assert_vault_quota, resolve_folder
import audit


logger = logging.getLogger(__name__)


def _get_ip(request: Request) -> str | None:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


async def _generate_and_track_sas(
    request: Request,
    db: AsyncSession,
    current: CurrentUser,
    *,
    blob_name: str,
    file_id: str | None,
    hours: int,
    endpoint: str,
) -> tuple[str, str]:
    """Tạo SAS URL + ghi sas_token_records và token_access_logs."""
    from services.token_security import (
        is_sas_revoked,
        parse_sas_expires,
        track_sas_issue,
    )

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
        ip_address=_get_ip(request),
        user_agent=request.headers.get("User-Agent"),
        expires_at=expires_dt,
        file_id=file_id,
        endpoint=endpoint,
        http_method=request.method,
    )
    return sas_url, expires_at


router = APIRouter(tags=["upload"])


async def _persist_download_log(
    request: Request,
    current: CurrentUser,
    db: AsyncSession,
    *,
    file_id: str | None,
    blob_name: str | None,
) -> dict:
    if not file_id and not blob_name:
        raise HTTPException(
            status_code=422, detail="Cần có file_id hoặc blob_name"
        )
    file_row = None
    if file_id:
        file_row = (
            await db.execute(select(FileModel).where(FileModel.id == file_id))
        ).scalar_one_or_none()
    if file_row is None and blob_name:
        file_row = (
            await db.execute(
                select(FileModel).where(FileModel.blob_name == blob_name)
            )
        ).scalar_one_or_none()

    blob_logged = (
        file_row.blob_name
        if file_row
        else (blob_name or file_id or "unknown")
    )
    orig_logged = file_row.original_filename if file_row else "unknown"
    size_logged = file_row.file_size_bytes if file_row else 0
    fid_logged = file_row.id if file_row else None

    db.add(
        DownloadLog(
            user_id=current.id,
            file_id=fid_logged,
            blob_name=blob_logged,
            original_filename=orig_logged,
            file_size_bytes=size_logged,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    )
    audit.log_event(
        "file.download",
        user_id=current.id,
        role=current.role,
        file_id=fid_logged,
        blob_name=blob_logged,
    )
    return {"status": "logged"}


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

    blob_name = f"{uuid.uuid4()}/{file.filename}"
    ciphertext = await file.read()
    file_size = len(ciphertext)

    if mode == "vault":
        await assert_vault_quota(db, current.id, file_size)
        await resolve_folder(db, current.id, folder_id)
        recipients_json = None

    ciphertext_checksum = hashlib.sha256(ciphertext).hexdigest()

    # Azure Blob metadata chỉ chấp nhận latin-1; encode base64 để an toàn với Unicode
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
    except Exception as exc:  # pragma: no cover - network failure
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
        blob_client.set_blob_metadata(
            {
                "encryption_metadata_b64": metadata_b64,
                "ciphertext_checksum": ciphertext_checksum,
                "file_id": file_record.id,
            }
        )
    except Exception as exc:  # pragma: no cover
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
                db.add(
                    FileRecipient(
                        file_id=file_record.id,
                        recipient_id=r["recipient_id"],
                        wrapped_file_key=r.get("wrapped_file_key", ""),
                        wrapped_key_alg=r.get("wrapped_key_alg", "X25519-HKDF"),
                        key_id=r.get("key_id"),
                        wrapped_key_version=r.get("wrapped_key_version", 1),
                        status=RecipientStatus.active,
                    )
                )
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

    sas_url, expires_at = await _generate_and_track_sas(
        request,
        db,
        current,
        blob_name=blob_name,
        file_id=file_record.id,
        hours=24,
        endpoint="/upload",
    )
    logger.info(
        "Upload success blob=%s user=%s ciphertext_sha256=%s request_id=%s",
        blob_name,
        current.id,
        ciphertext_checksum,
        getattr(current, "request_id", "-"),
    )
    return SasResponse(
        sas_url=sas_url, blob_name=blob_name, expires_at=expires_at, file_id=file_record.id
    )


@router.get("/sas-token/{blob_name:path}", response_model=SasResponse)
async def get_sas_token(
    blob_name: str,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tạo SAS token read-only 1h cho blob đã tồn tại. Ghi nhận vào sas_token_records."""
    row = (
        await db.execute(select(FileModel).where(FileModel.blob_name == blob_name))
    ).scalar_one_or_none()

    sas_url, expires_at = await _generate_and_track_sas(
        request,
        db,
        current,
        blob_name=blob_name,
        file_id=row.id if row else None,
        hours=1,
        endpoint=f"/sas-token/{blob_name}",
    )

    return SasResponse(
        sas_url=sas_url,
        blob_name=blob_name,
        expires_at=expires_at,
        file_id=row.id if row else None,
    )


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
    request: Request,
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

    # Azure Blob metadata chỉ chấp nhận latin-1; encode base64 để an toàn với Unicode
    metadata_b64 = b64mod.b64encode(body.metadata_json.encode("utf-8")).decode("ascii")

    try:
        client = get_blob_service_client()
        blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
        blob_client.commit_block_list(
            block_ids,
            metadata={
                "encryption_metadata_b64": metadata_b64,
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
        blob_client2.set_blob_metadata(
            {
                "encryption_metadata_b64": metadata_b64,
                "has_chunk_checksums": str(has_chunk_checksums).lower(),
                "file_id": file_record.id,
            }
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("set_blob_metadata(file_id) multipart failed: %s", exc)

    sas_url, expires_at = await _generate_and_track_sas(
        request,
        db,
        current,
        blob_name=blob_name,
        file_id=file_record.id,
        hours=24,
        endpoint=f"/upload/multipart/{blob_name}/finalize",
    )
    logger.info(
        "Multipart finalize success blob=%s user=%s chunks=%d has_chunk_checksums=%s",
        blob_name,
        current.id,
        body.chunk_count,
        has_chunk_checksums,
    )
    return SasResponse(
        sas_url=sas_url,
        blob_name=blob_name,
        expires_at=expires_at,
        file_id=file_record.id,
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
    """
    Tạo SAS URL cho file được chia sẻ.
    Chỉ cho phép recipient đang active của file đó truy cập.
    """
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

    file = (
        await db.execute(select(FileModel).where(FileModel.id == file_id))
    ).scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại")

    sas_url, expires_at = await _generate_and_track_sas(
        request,
        db,
        current,
        blob_name=file.blob_name,
        file_id=file.id,
        hours=24,
        endpoint=f"/files/shared/{file_id}/sas",
    )
    return FreshSasResponse(
        file_id=file.id,
        blob_name=file.blob_name,
        sas_url=sas_url,
        expires_at=expires_at,
    )


@router.post("/files/download-log", status_code=201)
async def record_download_log_body(
    request: Request,
    body: DownloadLogRequest,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Ghi download_logs — gửi file_id (ưu tiên) hoặc blob_name (parse từ SAS URL)."""
    return await _persist_download_log(
        request,
        current,
        db,
        file_id=body.file_id,
        blob_name=body.blob_name,
    )


@router.post("/files/{file_id}/download-log", status_code=201)
async def record_download_log_by_path(
    request: Request,
    file_id: str,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Tương thích: chỉ cần file_id trên URL."""
    return await _persist_download_log(
        request, current, db, file_id=file_id, blob_name=None
    )


@router.get("/files/my-files", response_model=list[FileHistoryItem])
async def my_files(
    current: CurrentUser = Depends(require_roles("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Lịch sử file đã upload của user hiện tại, mới nhất trước."""
    result = await db.execute(
        select(FileModel)
        .where(FileModel.owner_id == current.id)
        .order_by(FileModel.created_at.desc())
    )
    files = result.scalars().all()

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
            shared_count=sum(
                1
                for r in recipients_map.get(f.id, [])
                if r.status == "active"
            ),
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
    """Tạo lại SAS URL mới (24h) cho file đã upload — dùng khi link cũ hết hạn."""
    result = await db.execute(
        select(FileModel).where(
            FileModel.id == file_id,
            FileModel.owner_id == current.id,
        )
    )
    file = result.scalar_one_or_none()
    if file is None:
        raise HTTPException(status_code=404, detail="File không tồn tại hoặc không thuộc về bạn")

    sas_url, expires_at = await _generate_and_track_sas(
        request,
        db,
        current,
        blob_name=file.blob_name,
        file_id=file.id,
        hours=24,
        endpoint=f"/files/{file_id}/sas",
    )
    return FreshSasResponse(
        file_id=file.id,
        blob_name=file.blob_name,
        sas_url=sas_url,
        expires_at=expires_at,
    )


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

