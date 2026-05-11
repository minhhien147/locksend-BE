"""
Secure File Sharing — FastAPI backend
Phase 1: JWT auth + RBAC bảo vệ tất cả endpoint nhạy cảm.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
import uuid

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser, get_current_user, require_roles
from db.dependencies import get_db
from db.models import User
from routers.auth_router import router as auth_router
from routers.upload_router import router as upload_router
from schemas.keys import KeyRecord

logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Secure File Sharing API", version="1.0.0")

_RAW_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _RAW_ORIGINS.split(",") if o.strip()]

app.include_router(auth_router)
app.include_router(upload_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request-ID middleware ─────────────────────────────────────────────────────


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


KEY_VAULT_URL = os.getenv("AZURE_KEY_VAULT_URL", "")

_credential = DefaultAzureCredential()


def get_secret_client() -> SecretClient:
    if not KEY_VAULT_URL:
        raise HTTPException(status_code=503, detail="Key Vault not configured")
    return SecretClient(vault_url=KEY_VAULT_URL, credential=_credential)


# ── Health (public) ───────────────────────────────────────────────────────────


@app.get("/health", tags=["ops"])
def health():
    return {"status": "ok"}


# ── Keys ──────────────────────────────────────────────────────────────────────


@app.get("/keys/{user_id}", tags=["keys"])
def get_public_key(
    user_id: str,
    _: CurrentUser = Depends(get_current_user),
):
    """Lấy public key của user từ Azure Key Vault (cần auth)."""
    client = get_secret_client()
    try:
        x25519 = client.get_secret(f"pubkey-x25519-{user_id}").value
        ed25519 = client.get_secret(f"pubkey-ed25519-{user_id}").value
    except ResourceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Key not found for user '{user_id}'")
    except Exception as exc:
        logger.exception("Key Vault get error: %s", exc)
        raise HTTPException(status_code=502, detail="Key Vault unavailable")
    return {
        "user_id": user_id,
        "public_key_x25519": x25519,
        "public_key_ed25519": ed25519,
    }


@app.post("/keys", status_code=201, tags=["keys"])
async def store_public_key(
    record: KeyRecord,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Lưu public key lên Key Vault + upsert vào DB.
    User chỉ được tự ghi key của mình (hoặc admin ghi cho người khác).
    """
    if record.user_id != current.external_id and current.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Chỉ được lưu key của chính mình",
        )

    client = get_secret_client()
    try:
        client.set_secret(f"pubkey-x25519-{record.user_id}", record.public_key_x25519)
        client.set_secret(f"pubkey-ed25519-{record.user_id}", record.public_key_ed25519)
    except Exception as exc:
        logger.exception("Key Vault set error: %s", exc)
        raise HTTPException(status_code=502, detail="Key Vault unavailable")

    result = await db.execute(select(User).where(User.external_id == record.user_id))
    user = result.scalar_one_or_none()
    if user:
        from db.models import UserPublicKey

        result2 = await db.execute(
            select(UserPublicKey)
            .where(UserPublicKey.user_id == user.id, UserPublicKey.is_active.is_(True))
        )
        existing = result2.scalar_one_or_none()
        if existing:
            existing.is_active = False
            existing.rotated_at = datetime.now(timezone.utc)
            new_version = existing.key_version + 1
        else:
            new_version = 1

        from db.models import UserPublicKey as UPK
        db.add(
            UPK(
                user_id=user.id,
                public_key_x25519=record.public_key_x25519,
                public_key_ed25519=record.public_key_ed25519,
                key_version=new_version,
                is_active=True,
            )
        )

    return {"status": "stored", "user_id": record.user_id}

# ── Admin: list users ─────────────────────────────────────────────────────────


@app.get(
    "/admin/users",
    tags=["admin"],
    dependencies=[Depends(require_roles("admin"))],
)
async def list_users(db: AsyncSession = Depends(get_db)):
    """Xem danh sách tất cả users — chỉ admin."""
    rows = (await db.execute(select(User))).scalars().all()
    return [
        {"id": u.id, "external_id": u.external_id, "email": u.email, "role": u.role}
        for u in rows
    ]

