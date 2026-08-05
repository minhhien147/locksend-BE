"""
_auth_helpers.py — Shared constants, schemas và helpers dùng chung bởi auth sub-routers.
"""
from __future__ import annotations

import os
import uuid as _uuid_mod
from datetime import datetime, timedelta, timezone
from typing import Literal
import re

import jwt
from fastapi import HTTPException, Request, Response
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, JWT_ALGORITHM, _signing_key
from db.models import RefreshToken, User
from services import email_verification
from services.vault_storage import get_effective_quota_bytes_for_user, normalize_storage_plan

# ── Constants ─────────────────────────────────────────────────────────────────

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
_samesite_env = os.getenv("COOKIE_SAMESITE", "").strip().lower()
if _samesite_env in ("lax", "strict", "none"):
    COOKIE_SAMESITE = _samesite_env
else:
    COOKIE_SAMESITE = "strict" if COOKIE_SECURE else "lax"
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    COOKIE_SECURE = True
# Mặc định refresh cookie là session cookie (không Expires/Max-Age) → đóng trình
# duyệt là mất, user phải đăng nhập lại. Đặt true nếu muốn giữ session 7 ngày.
REFRESH_COOKIE_PERSIST = os.getenv("REFRESH_COOKIE_PERSIST", "false").lower() == "true"

VALID_ROLES = {"owner", "recipient", "admin"}
RoleType = Literal["owner", "recipient", "admin"]

# Block HTML/script-like display names (stored-XSS PoC / layout-breaking payloads).
_UNSAFE_DISPLAY_NAME = re.compile(
    r"[<>`]|javascript:|data:text/html|on(?:error|load|click|mouse\w+)\s*=",
    re.IGNORECASE,
)


def _validate_display_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Tên hiển thị không được để trống")
    if _UNSAFE_DISPLAY_NAME.search(cleaned):
        raise ValueError("Tên hiển thị không được chứa HTML hoặc script")
    return cleaned

# ── Password context ──────────────────────────────────────────────────────────

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ── Token helpers ─────────────────────────────────────────────────────────────

def create_access_token(user: User) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user.external_id,
        "email": user.email,
        "name": user.display_name,
        "role": user.role,
        # Server-checked revocation marker — must match users.token_version.
        "tv": int(getattr(user, "token_version", 0) or 0),
        "jti": str(_uuid_mod.uuid4()),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _signing_key(), algorithm=JWT_ALGORITHM)


async def bump_token_version(db: AsyncSession, user_id: str) -> int:
    """
    Invalidate all outstanding access JWTs for this user by advancing
    users.token_version. Call on logout, password change, and admin revoke.
    Returns the new version.
    """
    from sqlalchemy import select

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if user is None:
        return 0
    user.token_version = int(user.token_version or 0) + 1
    await db.flush()
    return user.token_version


async def issue_refresh_token(
    db: AsyncSession,
    user: User,
    request: Request,
    old_jti: str | None = None,
) -> tuple[str, datetime]:
    jti = str(_uuid_mod.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    if old_jti:
        from sqlalchemy import update
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.jti == old_jti)
            .values(replaced_by_jti=jti)
        )

    db.add(
        RefreshToken(
            jti=jti,
            user_id=user.id,
            expires_at=expires_at,
            ip_address=audit.get_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )
    )
    await db.flush()
    return jti, expires_at


def set_refresh_cookie(response: Response, jti: str, expires_at: datetime) -> None:
    lifetime = (
        {"expires": expires_at, "max_age": REFRESH_TOKEN_EXPIRE_DAYS * 86400}
        if REFRESH_COOKIE_PERSIST
        else {}
    )
    response.set_cookie(
        key="sf_refresh_token",
        value=jti,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/auth",
        **lifetime,
    )


def clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key="sf_refresh_token",
        path="/auth",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )


def make_token_response(user: User) -> "TokenResponse":
    return TokenResponse(
        access_token=create_access_token(user),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        email=user.email or "",
        display_name=user.display_name,
        role=user.role,
        email_verified=email_verification.is_user_email_verified(user),
    )


# ── RBAC helper ───────────────────────────────────────────────────────────────

def require_admin(current: CurrentUser) -> None:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Yêu cầu quyền admin")


def to_user_out(u: User, has_public_key: bool = False) -> "UserOut":
    return UserOut(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        role=u.role,
        storage_plan=normalize_storage_plan(u.storage_plan),
        vault_quota_bytes=u.vault_quota_bytes,
        effective_vault_quota_bytes=get_effective_quota_bytes_for_user(u),
        created_at=u.created_at.isoformat(),
        has_public_key=has_public_key,
    )


def to_user_search_out(u: User, has_public_key: bool = False) -> "UserSearchOut":
    """Minimal fields for recipient picker — no role/quota/created_at."""
    return UserSearchOut(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        has_public_key=has_public_key,
    )


# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    role: RoleType = "owner"

    @field_validator("display_name")
    @classmethod
    def _check_display_name(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return _validate_display_name(v)


class LoginRequest(BaseModel):
    username: EmailStr
    password: str = Field(min_length=1)


class GoogleLoginRequest(BaseModel):
    credential: str = Field(min_length=10)


class GoogleOAuthConfigResponse(BaseModel):
    enabled: bool
    client_id: str = ""


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str
    display_name: str | None
    role: RoleType
    email_verified: bool = True


class VerifyEmailRequest(BaseModel):
    code: str = Field(min_length=4, max_length=8)


class VerificationStatusResponse(BaseModel):
    email_verified: bool
    email: str | None
    verification_required: bool
    resend_cooldown_sec: int = 0


class ChangeRoleRequest(BaseModel):
    role: RoleType


class ChangeStoragePlanRequest(BaseModel):
    storage_plan: Literal["free", "pro"]
    vault_quota_gb: int | None = Field(default=None, ge=1, le=1024)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class UpdateProfileRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)

    @field_validator("display_name")
    @classmethod
    def _check_display_name(cls, v: str) -> str:
        return _validate_display_name(v)


class UpdateEmailRequest(BaseModel):
    email: EmailStr


class UserOut(BaseModel):
    id: str
    email: str | None
    display_name: str | None
    role: str
    storage_plan: Literal["free", "pro"] = "free"
    vault_quota_bytes: int | None = None
    effective_vault_quota_bytes: int
    created_at: str
    has_public_key: bool = False


class UserSearchOut(BaseModel):
    """Least-privilege response for GET /auth/users/search (recipient selection)."""

    id: str
    email: str | None
    display_name: str | None
    has_public_key: bool = False


class DisplayNameHistoryOut(BaseModel):
    id: str
    old_display_name: str | None
    new_display_name: str
    changed_at: str
    ip_address: str | None = None


class PublicKeyOut(BaseModel):
    user_id: str
    public_key_x25519: str
    public_key_ed25519: str
    key_version: int
