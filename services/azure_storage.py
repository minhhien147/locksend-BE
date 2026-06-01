from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from typing import Tuple

from azure.storage.blob import (
    BlobSasPermissions,
    BlobServiceClient,
    generate_blob_sas,
)
from services.azure_credentials import get_azure_credential

STORAGE_ACCOUNT = os.getenv("AZURE_STORAGE_ACCOUNT_NAME", "")
CONTAINER_NAME = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "secure-files")


def get_blob_service_client() -> BlobServiceClient:
    account_url = f"https://{STORAGE_ACCOUNT}.blob.core.windows.net"
    return BlobServiceClient(account_url=account_url, credential=get_azure_credential())


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

