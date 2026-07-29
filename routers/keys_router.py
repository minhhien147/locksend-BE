"""keys_router.py — Public key management: GET/POST /keys, GET /keys/my-encrypted-blob."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from azure.core.exceptions import ResourceNotFoundError
from azure.keyvault.secrets import SecretClient
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser, require_verified_email
from db.dependencies import get_db
from db.models import User, UserPublicKey
from schemas.keys import KeyRecord
from services import owner_security
from services.azure_credentials import get_azure_credential
from services.owner_security import keypair_expires_at_from_now

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/keys", tags=["keys"])

KEY_VAULT_URL = os.getenv("AZURE_KEY_VAULT_URL", "")


def _get_secret_client() -> SecretClient:
    if not KEY_VAULT_URL:
        raise HTTPException(status_code=503, detail="Key Vault not configured")
    return SecretClient(vault_url=KEY_VAULT_URL, credential=get_azure_credential())


async def _latest_encrypted_blob_for_user(
    db: AsyncSession, user_id: int, active: UserPublicKey | None
) -> str | None:
    """Active row first; else newest rotated row that still has a blob."""
    if active and active.encrypted_key_blob:
        return active.encrypted_key_blob
    row = (
        await db.execute(
            select(UserPublicKey.encrypted_key_blob)
            .where(
                UserPublicKey.user_id == user_id,
                UserPublicKey.encrypted_key_blob.isnot(None),
            )
            .order_by(desc(UserPublicKey.key_version))
            .limit(1)
        )
    ).scalar_one_or_none()
    return row


@router.get("/my-encrypted-blob")
async def get_my_encrypted_blob(
    current: CurrentUser = Depends(require_verified_email),
    db: AsyncSession = Depends(get_db),
):
    """
    Trả encrypted_key_blob của user hiện tại.
    Zero-knowledge: server chỉ lưu blob đã mã hóa, không biết passphrase.
    """
    user_row = (
        await db.execute(select(User).where(User.external_id == current.external_id))
    ).scalar_one_or_none()
    if user_row is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    krow = (
        await db.execute(
            select(UserPublicKey).where(
                UserPublicKey.user_id == user_row.id,
                UserPublicKey.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()

    if krow is None:
        return {"encrypted_key_blob": None, "has_keys": False}

    await owner_security.sync_keypair_expiry_alerts(db, user_row.id)
    kp = owner_security.keypair_status(krow)

    blob = await _latest_encrypted_blob_for_user(db, user_row.id, krow)
    if blob and not krow.encrypted_key_blob:
        krow.encrypted_key_blob = blob

    return {
        "encrypted_key_blob": blob,
        "has_keys": True,
        "public_key_x25519": krow.public_key_x25519,
        "public_key_ed25519": krow.public_key_ed25519,
        "keypair_expires_at": kp.get("expires_at"),
        "keypair_days_left": kp.get("days_left"),
        "keypair_expired": kp.get("expired", False),
        "keypair_expiring_soon": kp.get("expiring_soon", False),
        "key_version": kp.get("key_version"),
    }


@router.get("/{user_id}")
async def get_public_key(
    user_id: str,
    _: CurrentUser = Depends(require_verified_email),
    db: AsyncSession = Depends(get_db),
):
    """Lấy public key của user từ DB (fallback từ Key Vault nếu có)."""
    if KEY_VAULT_URL:
        try:
            client = _get_secret_client()
            x25519 = client.get_secret(f"pubkey-x25519-{user_id}").value
            ed25519 = client.get_secret(f"pubkey-ed25519-{user_id}").value
            return {"user_id": user_id, "public_key_x25519": x25519, "public_key_ed25519": ed25519}
        except ResourceNotFoundError:
            pass
        except Exception as exc:
            logger.warning("Key Vault get error, falling back to DB: %s", exc)

    user_row = (await db.execute(select(User).where(User.external_id == user_id))).scalar_one_or_none()
    if user_row:
        krow = (
            await db.execute(
                select(UserPublicKey).where(
                    UserPublicKey.user_id == user_row.id, UserPublicKey.is_active.is_(True)
                )
            )
        ).scalar_one_or_none()
        if krow:
            return {
                "user_id": user_id,
                "public_key_x25519": krow.public_key_x25519,
                "public_key_ed25519": krow.public_key_ed25519,
            }
    raise HTTPException(status_code=404, detail=f"Key not found for user '{user_id}'")


@router.post("", status_code=201)
async def store_public_key(
    record: KeyRecord,
    current: CurrentUser = Depends(require_verified_email),
    db: AsyncSession = Depends(get_db),
):
    """
    Lưu public key lên Key Vault + upsert vào DB.
    User chỉ được tự ghi key của mình (hoặc admin ghi cho người khác).
    """
    if record.user_id != current.external_id and current.role != "admin":
        raise HTTPException(status_code=403, detail="Chỉ được lưu key của chính mình")

    if KEY_VAULT_URL:
        try:
            client = _get_secret_client()
            client.set_secret(f"pubkey-x25519-{record.user_id}", record.public_key_x25519)
            client.set_secret(f"pubkey-ed25519-{record.user_id}", record.public_key_ed25519)
        except Exception as exc:
            logger.warning("Key Vault set error (non-fatal): %s", exc)

    user = (await db.execute(select(User).where(User.external_id == record.user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại trong hệ thống")

    existing = (
        await db.execute(
            select(UserPublicKey).where(
                UserPublicKey.user_id == user.id, UserPublicKey.is_active.is_(True)
            )
        )
    ).scalar_one_or_none()

    if existing:
        existing.is_active = False
        existing.rotated_at = datetime.now(timezone.utc)
        new_version = existing.key_version + 1
    else:
        new_version = 1

    blob = record.encrypted_key_blob
    if not blob and existing and existing.encrypted_key_blob:
        blob = existing.encrypted_key_blob

    db.add(UserPublicKey(
        user_id=user.id,
        public_key_x25519=record.public_key_x25519,
        public_key_ed25519=record.public_key_ed25519,
        encrypted_key_blob=blob,
        key_version=new_version,
        is_active=True,
        expires_at=keypair_expires_at_from_now(),
    ))
    await owner_security.sync_keypair_expiry_alerts(db, user.id)
    logger.info("Public key stored for user %s (version %d)", user.id, new_version)
    return {"status": "stored", "user_id": record.user_id}
