from __future__ import annotations

import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from azure.storage.blob import (
    BlobSasPermissions,
    BlobServiceClient,
    generate_blob_sas,
)
from services.azure_credentials import get_azure_credential

logger = logging.getLogger(__name__)

STORAGE_ACCOUNT = os.getenv("AZURE_STORAGE_ACCOUNT_NAME", "")
CONTAINER_NAME = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "secure-files")
# On recipient revoke: copy ciphertext to a new blob path and delete the old one
# so previously issued Azure SAS URLs stop working at the storage layer.
REVOKE_ROTATE_BLOB: bool = os.getenv("REVOKE_ROTATE_BLOB", "true").lower() == "true"


def check_container_not_public() -> None:
    """
    Fix #8 — A01/A05: Kiểm tra Azure Blob Container không để public access.
    Chỉ cảnh báo (warning) vì không muốn block startup nếu Azure chưa sẵn sàng.
    Gọi từ lifespan startup của FastAPI.
    """
    if not STORAGE_ACCOUNT:
        return
    try:
        client = get_blob_service_client()
        container_client = client.get_container_client(CONTAINER_NAME)
        props = container_client.get_container_properties()
        public_access = props.get("public_access") or ""
        if public_access:
            logger.error(
                "SECURITY A01/A05: Azure container '%s' có public_access='%s'! "
                "Ciphertext có thể bị download tự do. "
                "Vào Azure Portal → Storage Account → Containers → %s → "
                "Change access level → Private.",
                CONTAINER_NAME, public_access, CONTAINER_NAME,
            )
        else:
            logger.info(
                "Azure container '%s' access: Private ✅", CONTAINER_NAME
            )
    except Exception as exc:
        logger.warning(
            "Không kiểm tra được Azure container access: %s", exc
        )


_blob_service_client: BlobServiceClient | None = None


def get_blob_service_client() -> BlobServiceClient:
    """Return a cached BlobServiceClient to reuse the underlying connection pool."""
    global _blob_service_client
    if _blob_service_client is None:
        account_url = f"https://{STORAGE_ACCOUNT}.blob.core.windows.net"
        _blob_service_client = BlobServiceClient(
            account_url=account_url,
            credential=get_azure_credential(),
        )
    return _blob_service_client


def generate_sas_url(blob_name: str, hours: int = 24) -> Tuple[str, str]:
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    sas_token = generate_blob_sas(
        account_name=STORAGE_ACCOUNT,
        container_name=CONTAINER_NAME,
        blob_name=blob_name,
        account_key=None,
        user_delegation_key=_get_delegation_key(expires),
        permission=BlobSasPermissions(read=True),
        expiry=expires,
        protocol="https",
    )
    sas_url = (
        f"https://{STORAGE_ACCOUNT}.blob.core.windows.net"
        f"/{CONTAINER_NAME}/{blob_name}?{sas_token}"
    )
    return sas_url, expires.isoformat()


def generate_stage_sas_url(blob_name: str, hours: int = 24) -> Tuple[str, str]:
    """
    SAS ghi block (Put Block) — client stage trực tiếp lên Azure, không proxy qua BE.
    Cần CORS trên Storage Account cho origin frontend.
    """
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    sas_token = generate_blob_sas(
        account_name=STORAGE_ACCOUNT,
        container_name=CONTAINER_NAME,
        blob_name=blob_name,
        account_key=None,
        user_delegation_key=_get_delegation_key(expires),
        permission=BlobSasPermissions(create=True, write=True),
        expiry=expires,
        protocol="https",
    )
    sas_url = (
        f"https://{STORAGE_ACCOUNT}.blob.core.windows.net"
        f"/{CONTAINER_NAME}/{blob_name}?{sas_token}"
    )
    return sas_url, expires.isoformat()


def _get_delegation_key(expiry: datetime):
    client = get_blob_service_client()
    start = datetime.now(timezone.utc)
    return client.get_user_delegation_key(start, expiry)


def delete_blob(blob_name: str) -> None:
    """Xóa ciphertext trên Azure Blob (best-effort cho vault delete)."""
    client = get_blob_service_client()
    blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
    blob_client.delete_blob()


def rotate_blob(old_blob_name: str, *, wait_timeout_sec: float = 60.0) -> str:
    """
    Copy ciphertext to a new blob name and delete the old object.

    Azure user-delegation SAS cannot be revoked in place. Rotating the object
    path makes any previously issued SAS URL for ``old_blob_name`` fail (404)
    while active recipients can mint a fresh SAS against the new path.
    """
    if not STORAGE_ACCOUNT:
        raise RuntimeError("AZURE_STORAGE_ACCOUNT_NAME is not configured")
    if not old_blob_name or old_blob_name.strip() != old_blob_name:
        raise ValueError("invalid blob_name")

    if "/" in old_blob_name:
        prefix, leaf = old_blob_name.rsplit("/", 1)
        # Preserve a stable-looking extension when present.
        ext = ""
        if "." in leaf:
            ext = "." + leaf.rsplit(".", 1)[-1]
        new_blob_name = f"{prefix}/{uuid.uuid4()}{ext}"
    else:
        new_blob_name = str(uuid.uuid4())

    client = get_blob_service_client()
    source = client.get_blob_client(container=CONTAINER_NAME, blob=old_blob_name)
    dest = client.get_blob_client(container=CONTAINER_NAME, blob=new_blob_name)

    source_url = source.url
    dest.start_copy_from_url(source_url)

    deadline = time.monotonic() + wait_timeout_sec
    while True:
        props = dest.get_blob_properties()
        copy = props.copy
        status = (getattr(copy, "status", None) or "success").lower()
        if status == "success":
            break
        if status == "failed":
            detail = getattr(copy, "status_description", None) or "unknown"
            raise RuntimeError(
                f"Azure blob copy failed for {old_blob_name!r}: {detail}"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for Azure blob copy of {old_blob_name!r}"
            )
        time.sleep(0.2)

    # Best-effort delete of the old object so captured SAS URLs stop working.
    try:
        source.delete_blob()
    except Exception as exc:
        logger.warning(
            "rotate_blob: copied %s → %s but failed to delete old blob: %s",
            old_blob_name,
            new_blob_name,
            exc,
        )
        raise

    logger.info("rotate_blob: %s → %s", old_blob_name, new_blob_name)
    return new_blob_name

