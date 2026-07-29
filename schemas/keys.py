from __future__ import annotations

import base64 as b64mod

from pydantic import BaseModel, Field, field_validator


def _validate_base64(v: str, field_name: str) -> str:
    """Validate base64 encoding và độ dài hợp lệ (X25519/Ed25519 = 32 bytes)."""
    try:
        decoded = b64mod.b64decode(v, validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} phải là base64 hợp lệ") from exc
    if len(decoded) not in (32, 64):
        raise ValueError(f"{field_name} phải là 32 hoặc 64 bytes sau khi decode")
    return v


class KeyRecord(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    public_key_x25519: str = Field(min_length=1)
    public_key_ed25519: str = Field(min_length=1)
    # Zero-knowledge: client mã hóa private key bằng passphrase trước khi gửi.
    # Server chỉ lưu blob này, không bao giờ thấy private key hay passphrase.
    encrypted_key_blob: str | None = Field(default=None)

    @field_validator("public_key_x25519")
    @classmethod
    def validate_x25519(cls, v: str) -> str:
        return _validate_base64(v, "public_key_x25519")

    @field_validator("public_key_ed25519")
    @classmethod
    def validate_ed25519(cls, v: str) -> str:
        return _validate_base64(v, "public_key_ed25519")

