from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, model_validator


class KeyRecord(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    public_key_x25519: str = Field(min_length=1)
    public_key_ed25519: str = Field(min_length=1)


class SasResponse(BaseModel):
    sas_url: str
    blob_name: str
    expires_at: str
    file_id: Optional[str] = None


class DownloadLogRequest(BaseModel):
    """Ghi download_logs — cần ít nhất một trong hai."""

    file_id: Optional[str] = None
    blob_name: Optional[str] = None

    @model_validator(mode="after")
    def require_identifier(self) -> "DownloadLogRequest":
        if not self.file_id and not self.blob_name:
            raise ValueError("Cần có file_id hoặc blob_name")
        return self


class SasCiphertextRequest(BaseModel):
    sas_url: str = Field(min_length=1)


class MultipartInitResponse(BaseModel):
    blob_name: str
    upload_id: str


class RecipientIn(BaseModel):
    recipient_id: str = Field(min_length=1)
    wrapped_file_key: str = Field(min_length=1)
    wrapped_key_alg: str = Field(default="X25519-HKDF")
    key_id: Optional[str] = None
    wrapped_key_version: int = Field(default=1, ge=1)


class MultipartFinalizeRequest(BaseModel):
    chunk_count: int = Field(gt=0, le=50_000)
    metadata_json: str
    original_filename: Optional[str] = None
    content_type: Optional[str] = None
    file_size_bytes: Optional[int] = Field(default=None, ge=0)
    encryption_alg: str = "X25519+HKDF+AES-256-GCM"
    chunk_size_bytes: Optional[int] = Field(default=None, gt=0)
    recipients: Optional[List[RecipientIn]] = None
    chunk_checksums_present: bool = False
    storage_mode: str = Field(default="share")
    folder_id: Optional[str] = None


class RevokeRequest(BaseModel):
    reason: Optional[str] = None


class RecipientInfo(BaseModel):
    recipient_id: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    status: str
    granted_at: str


class FileHistoryItem(BaseModel):
    file_id: str
    blob_name: str
    original_filename: str
    content_type: Optional[str]
    file_size_bytes: int
    encryption_alg: str
    chunk_count: int
    created_at: str
    updated_at: str
    recipients: List[RecipientInfo] = []
    storage_mode: str = "share"
    folder_id: Optional[str] = None
    shared_count: int = 0


class VaultFolderOut(BaseModel):
    id: str
    name: str
    parent_id: Optional[str] = None
    file_count: int = 0
    created_at: str


class VaultFolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    parent_id: Optional[str] = None


class VaultQuotaOut(BaseModel):
    used_bytes: int
    quota_bytes: int
    file_count: int


class VaultFileOut(BaseModel):
    file_id: str
    blob_name: str
    original_filename: str
    content_type: Optional[str]
    file_size_bytes: int
    encryption_alg: str
    chunk_count: int
    created_at: str
    updated_at: str
    folder_id: Optional[str] = None
    shared_count: int = 0
    can_share: bool = True
    encryption_metadata: dict = Field(default_factory=dict)


class VaultFilePatch(BaseModel):
    folder_id: Optional[str] = None
    original_filename: Optional[str] = Field(default=None, min_length=1, max_length=512)


class ShareVaultRequest(BaseModel):
    recipients: List[RecipientIn] = Field(min_length=1)


class FreshSasResponse(BaseModel):
    file_id: str
    blob_name: str
    sas_url: str
    expires_at: str


class SharedFileResponse(BaseModel):
    file_id: str
    blob_name: str
    original_filename: str
    content_type: Optional[str]
    file_size_bytes: int
    encryption_alg: str
    granted_at: str
    wrapped_file_key: str
    wrapped_key_alg: str
    key_id: Optional[str] = None
    wrapped_key_version: int = 1
    sender_name: Optional[str] = None
    sender_email: Optional[str] = None

