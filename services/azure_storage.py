from __future__ import annotations

import logging
import os
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


def _get_delegation_key(expiry: datetime):
    client = get_blob_service_client()
    start = datetime.now(timezone.utc)
    return client.get_user_delegation_key(start, expiry)


def delete_blob(blob_name: str) -> None:
    """Xóa ciphertext trên Azure Blob (best-effort cho vault delete)."""
    client = get_blob_service_client()
    blob_client = client.get_blob_client(container=CONTAINER_NAME, blob=blob_name)
    blob_client.delete_blob()

