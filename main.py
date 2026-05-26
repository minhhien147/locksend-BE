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

from auth import CurrentUser, get_current_user, verify_jwt
from db.dependencies import get_db, get_db_context
from db.models import User, UserPublicKey
from routers.auth_router import router as auth_router
from routers.token_security_router import router as token_security_router
from routers.upload_router import router as upload_router
from schemas.keys import KeyRecord
from services import token_security as ts

logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Secure File Sharing API", version="1.0.0")

_RAW_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _RAW_ORIGINS.split(",") if o.strip()]

app.include_router(auth_router)
app.include_router(token_security_router)
app.include_router(upload_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request-ID middleware ─────────────────────────────────────────────────────


_SKIP_LOG_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})
_SENSITIVE_PREFIXES = ("/auth/admin/token-security",)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def jwt_access_log_middleware(request: Request, call_next):
    """
    Ghi TokenAccessLog cho mọi request có Bearer token hợp lệ.
    Bỏ qua: health, docs, token-security admin endpoints (tránh vòng lặp).
    """
    response = await call_next(request)

    path = request.url.path
    if path in _SKIP_LOG_PATHS or any(path.startswith(p) for p in _SENSITIVE_PREFIXES):
        return response

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return response

    token_val = auth_header[7:]
    try:
        payload = verify_jwt(token_val)
        jti: str = payload.get("jti", "")
        user_ext_id: str = payload.get("sub", "")
        token_ref = f"{jti[:4]}…{jti[-4:]}" if len(jti) > 8 else "***"

        xff = request.headers.get("X-Forwarded-For")
        ip = xff.split(",")[0].strip() if xff else (
            request.client.host if request.client else None
        )

        from db.dependencies import get_db_context

        async with get_db_context() as db:
            from sqlalchemy import select
            from db.models import User as _User

            user_row = (
                await db.execute(select(_User).where(_User.external_id == user_ext_id))
            ).scalar_one_or_none()
            user_id = user_row.id if user_row else None

            await ts.log_token_access(
                db,
                token_type="jwt",
                token_ref=token_ref,
                user_id=user_id,
                ip_address=ip,
                user_agent=request.headers.get("User-Agent"),
                endpoint=path,
                http_method=request.method,
                status_code=response.status_code,
            )
    except Exception:
        pass

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


@app.get("/keys/my-encrypted-blob", tags=["keys"])
async def get_my_encrypted_blob(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trả encrypted_key_blob của user hiện tại.
    Zero-knowledge: server chỉ lưu blob đã mã hóa, không biết passphrase.
    Frontend dùng endpoint này sau F5 nếu sessionStorage wrapper không còn.
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

    return {
        "encrypted_key_blob": krow.encrypted_key_blob,
        "has_keys": True,
        "public_key_x25519": krow.public_key_x25519,
        "public_key_ed25519": krow.public_key_ed25519,
    }


@app.get("/keys/{user_id}", tags=["keys"])
async def get_public_key(
    user_id: str,
    _: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lấy public key của user từ DB (fallback từ Key Vault nếu có)."""
    # Thử Key Vault trước nếu được cấu hình
    if KEY_VAULT_URL:
        try:
            client = get_secret_client()
            x25519 = client.get_secret(f"pubkey-x25519-{user_id}").value
            ed25519 = client.get_secret(f"pubkey-ed25519-{user_id}").value
            return {
                "user_id": user_id,
                "public_key_x25519": x25519,
                "public_key_ed25519": ed25519,
            }
        except ResourceNotFoundError:
            pass  # fallback sang DB
        except Exception as exc:
            logger.warning("Key Vault get error, falling back to DB: %s", exc)

    # Fallback: đọc từ DB qua external_id
    user_row = (await db.execute(
        select(User).where(User.external_id == user_id)
    )).scalar_one_or_none()
    if user_row:
        krow = (await db.execute(
            select(UserPublicKey).where(UserPublicKey.user_id == user_row.id, UserPublicKey.is_active.is_(True))
        )).scalar_one_or_none()
        if krow:
            return {
                "user_id": user_id,
                "public_key_x25519": krow.public_key_x25519,
                "public_key_ed25519": krow.public_key_ed25519,
            }
    raise HTTPException(status_code=404, detail=f"Key not found for user '{user_id}'")


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

    # Key Vault là tuỳ chọn — bỏ qua nếu chưa cấu hình (local dev)
    if KEY_VAULT_URL:
        try:
            client = get_secret_client()
            client.set_secret(f"pubkey-x25519-{record.user_id}", record.public_key_x25519)
            client.set_secret(f"pubkey-ed25519-{record.user_id}", record.public_key_ed25519)
        except Exception as exc:
            logger.warning("Key Vault set error (non-fatal): %s", exc)

    result = await db.execute(select(User).where(User.external_id == record.user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại trong hệ thống")

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

    db.add(
        UserPublicKey(
            user_id=user.id,
            public_key_x25519=record.public_key_x25519,
            public_key_ed25519=record.public_key_ed25519,
            encrypted_key_blob=record.encrypted_key_blob,  # zero-knowledge blob
            key_version=new_version,
            is_active=True,
        )
    )
    logger.info("Public key stored for user %s (version %d)", user.id, new_version)
    return {"status": "stored", "user_id": record.user_id}

