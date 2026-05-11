from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class KeyRecord(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    public_key_x25519: str = Field(min_length=1)
    public_key_ed25519: str = Field(min_length=1)


class SasResponse(BaseModel):
    sas_url: str
    blob_name: str
    expires_at: str


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


class RevokeRequest(BaseModel):
    reason: Optional[str] = None


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

