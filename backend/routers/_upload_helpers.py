"""_upload_helpers.py — Shared constants, schemas và helpers dùng chung bởi upload sub-routers."""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import unicodedata
from urllib.parse import quote, urlparse

from fastapi import HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser
from db.models import File as FileModel, FileRecipient, RecipientStatus
from services.azure_storage import CONTAINER_NAME, STORAGE_ACCOUNT, generate_sas_url

logger = logging.getLogger(__name__)

# A03: Filename sanitization ──────────────────────────────────────────────────

_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_DOT_SEGMENTS = re.compile(r'\.{2,}')
_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f]')
_MAX_FILENAME_LEN = 200


def sanitize_filename(filename: str) -> str:
    """
    A03 – Injection: Làm sạch tên file, loại bỏ path traversal và ký tự nguy hiểm.
    - Strip null bytes, control chars
    - Loại bỏ directory separators, double-dots
    - Normalize unicode (NFC)
    - Giới hạn độ dài
    """
    if not filename:
        return "upload"

    # Normalize unicode
    name = unicodedata.normalize("NFC", filename)

    # Chỉ lấy phần basename (tránh path traversal)
    name = re.split(r'[/\\]', name)[-1]

    # Xoá ký tự nguy hiểm
    name = _UNSAFE_CHARS.sub("_", name)

    # Loại bỏ double-dot sequences
    name = _DOT_SEGMENTS.sub("_", name)

    # Strip leading/trailing dots và spaces
    name = name.strip(". ")

    # Giới hạn độ dài
    if len(name) > _MAX_FILENAME_LEN:
        base, _, ext = name.rpartition(".")
        if ext and len(ext) <= 10:
            name = base[: _MAX_FILENAME_LEN - len(ext) - 1] + "." + ext
        else:
            name = name[:_MAX_FILENAME_LEN]

    return name or "upload"


def sanitize_display_filename(filename: str) -> str:
    """
    A03: Tên hiển thị / lưu DB. Giữ dấu tiếng Việt và khoảng trắng (khác
    sanitize_filename dùng cho blob path), nhưng loại control char + CR/LF để
    không thể chèn header khi tên được đưa vào Content-Disposition sau này.
    """
    if not filename:
        return "upload"
    name = unicodedata.normalize("NFC", filename)
    name = _CONTROL_CHARS.sub("", name)
    name = re.split(r'[/\\]', name)[-1]
    name = name.strip(". ")
    return name[:_MAX_FILENAME_LEN] or "upload"


def content_disposition_attachment(filename: str) -> str:
    """
    A03: Dựng Content-Disposition theo RFC 6266 — ASCII fallback đã escape dấu
    ngoặc kép + filename* UTF-8 percent-encoded cho tên có dấu.
    """
    safe = sanitize_display_filename(filename)
    ascii_fallback = (
        safe.encode("ascii", "replace")
        .decode("ascii")
        .replace('"', "_")
        .replace("\\", "_")
    )
    return (
        f'attachment; filename="{ascii_fallback}"; '
        f"filename*=UTF-8''{quote(safe, safe='')}"
    )


def get_client_ip(request: Request) -> str | None:
    """A09: IP dùng cho sas_token_records — không tin hop client tự thêm."""
    from services.client_ip import client_ip

    return client_ip(request)


# A04: Hạn mức kích thước upload ──────────────────────────────────────────────
# Single-shot đọc trọn ciphertext vào RAM nên phải chặt hơn; file lớn dùng
# multipart. 0 = tắt kiểm tra.
MAX_SINGLE_UPLOAD_BYTES = int(os.getenv("MAX_SINGLE_UPLOAD_BYTES", str(200 * 1024 * 1024)))
MAX_CHUNK_UPLOAD_BYTES = int(os.getenv("MAX_CHUNK_UPLOAD_BYTES", str(128 * 1024 * 1024)))

# Azure Blob user metadata: tổng tên + giá trị ≤ 8 KB. File chunked lớn có
# chunkChecksums[] làm JSON/base64 vượt ngưỡng → finalize commit_block_list 500.
_AZURE_BLOB_METADATA_BUDGET = int(os.getenv("AZURE_BLOB_METADATA_BUDGET", "8192"))
_AZURE_METADATA_KEY_OVERHEAD = 256

_READ_BLOCK = 1024 * 1024


def azure_encryption_blob_metadata(
    metadata_json: str,
    *,
    file_id: str | None = None,
    ciphertext_checksum: str | None = None,
    has_chunk_checksums: bool | None = None,
) -> dict[str, str]:
    """
  Ghi metadata mã hoá lên Azure Blob trong giới hạn 8 KB.

  Metadata đầy đủ (kể cả chunkChecksums) luôn lưu trong files.metadata_json.
  Khi quá lớn chỉ ghi cờ metadata_in_db — download đọc từ DB.
  """
    result: dict[str, str] = {}
    b64 = base64.b64encode(metadata_json.encode("utf-8")).decode("ascii")
    max_b64_len = max(512, _AZURE_BLOB_METADATA_BUDGET - _AZURE_METADATA_KEY_OVERHEAD)

    if len(b64) <= max_b64_len:
        result["encryption_metadata_b64"] = b64
    else:
        result["metadata_in_db"] = "true"
        if has_chunk_checksums is None:
            try:
                parsed = json.loads(metadata_json)
                has_chunk_checksums = bool(parsed.get("chunkChecksums"))
            except json.JSONDecodeError:
                has_chunk_checksums = False
        result["has_chunk_checksums"] = str(has_chunk_checksums).lower()
        logger.info(
            "Azure blob metadata quá lớn (%d bytes b64, budget %d) — chỉ ghi metadata_in_db",
            len(b64),
            max_b64_len,
        )

    if ciphertext_checksum:
        result["ciphertext_checksum"] = ciphertext_checksum
    if file_id:
        result["file_id"] = file_id
    return result


async def read_upload_capped(upload: UploadFile, max_bytes: int, *, what: str) -> bytes:
    """
    A04: Đọc UploadFile theo stream và huỷ ngay khi vượt hạn mức.

    Không dùng Content-Length để kiểm tra vì client hoàn toàn có thể khai sai;
    chỉ có số byte đã đọc thật mới đáng tin.
    """
    blocks: list[bytes] = []
    total = 0
    while True:
        block = await upload.read(_READ_BLOCK)
        if not block:
            break
        total += len(block)
        if max_bytes > 0 and total > max_bytes:
            logger.warning("A04: %s vượt hạn mức %d bytes — từ chối", what, max_bytes)
            raise HTTPException(
                status_code=413,
                detail=f"{what} vượt giới hạn {max_bytes // (1024 * 1024)} MB",
            )
        blocks.append(block)
    return b"".join(blocks)


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


async def ensure_sas_download_allowed(db: AsyncSession, sas_url: str) -> str:
    """
    SAS URL là bearer credential cho blob — dùng thay authorize_file_download
    khi client gửi link tải (trang Download / proxy CORS).
    """
    from services.token_security import is_sas_revoked

    blob_name = blob_name_from_sas_url(sas_url)
    if await is_sas_revoked(db, blob_name, None):
        raise HTTPException(
            status_code=403,
            detail="SAS token cho blob này đã bị thu hồi bởi quản trị viên",
        )
    return blob_name


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
