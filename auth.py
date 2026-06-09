"""
JWT authentication + RBAC for FastAPI.

Flow:
  1. Client gửi  Authorization: Bearer <token>
  2. verify_jwt()  decode + validate signature, expiry, issuer, audience
  3. get_current_user()  resolve User row từ DB (tạo mới nếu chưa có)
  4. require_roles()  factory tạo dependency kiểm tra role

Supported token formats:
  - HS256 symmetric (dev/test): JWT_SECRET phải set
  - RS256 / ES256 asymmetric (production): JWT_PUBLIC_KEY phải set
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.dependencies import get_db
from db.models import User

logger = logging.getLogger(__name__)

# ── Config (từ environment) ───────────────────────────────────────────────────

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_SECRET = os.getenv("JWT_SECRET", "")            # dùng cho HS256
JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", "")    # dùng cho RS256/ES256
JWT_ISSUER = os.getenv("JWT_ISSUER", "")            # bỏ trống = không check
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "")        # bỏ trống = không check
JWT_LEEWAY_SECONDS = int(os.getenv("JWT_LEEWAY_SECONDS", "10"))


@lru_cache(maxsize=1)
def _signing_key() -> str:
    """Trả về key để verify JWT (chỉ load 1 lần)."""
    if JWT_ALGORITHM.startswith("HS"):
        if not JWT_SECRET:
            raise RuntimeError("JWT_SECRET must be set for HS256")
        return JWT_SECRET
    if not JWT_PUBLIC_KEY:
        raise RuntimeError("JWT_PUBLIC_KEY must be set for RS256/ES256")
    # Hỗ trợ inline PEM hoặc đường dẫn file
    if JWT_PUBLIC_KEY.startswith("-----"):
        return JWT_PUBLIC_KEY
    with open(JWT_PUBLIC_KEY) as f:
        return f.read()


# ── Bearer scheme ─────────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── JWT verification ──────────────────────────────────────────────────────────


def verify_jwt(token: str) -> dict:
    """
    Decode và validate JWT.
    Trả về payload dict nếu hợp lệ, raise 401 nếu không.
    """
    options: dict = {"require": ["sub", "exp"]}
    decode_kwargs: dict = {
        "algorithms": [JWT_ALGORITHM],
        "options": options,
        "leeway": JWT_LEEWAY_SECONDS,
    }
    if JWT_ISSUER:
        decode_kwargs["issuer"] = JWT_ISSUER
    if JWT_AUDIENCE:
        decode_kwargs["audience"] = JWT_AUDIENCE

    try:
        return jwt.decode(token, _signing_key(), **decode_kwargs)
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token đã hết hạn")
    except jwt.InvalidAudienceError:
        raise _unauthorized("Token audience không hợp lệ")
    except jwt.InvalidIssuerError:
        raise _unauthorized("Token issuer không hợp lệ")
    except jwt.DecodeError as exc:
        raise _unauthorized(f"Token không hợp lệ: {exc}")


# ── Current user dependency ───────────────────────────────────────────────────


class CurrentUser:
    """Thông tin user đã xác thực, gắn vào request state."""

    def __init__(self, user: User, payload: dict) -> None:
        self.user = user
        self.id: str = user.id
        self.external_id: str = user.external_id
        self.email: str | None = user.email
        self.role: str = user.role
        self.email_verified: bool = user.email_verified_at is not None
        self.payload = payload

    def __repr__(self) -> str:
        return f"<CurrentUser id={self.id} role={self.role}>"


async def get_current_user(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    """
    FastAPI dependency: xác thực Bearer token, trả CurrentUser.
    Tự động tạo User row nếu là lần đăng nhập đầu tiên.
    """
    if credentials is None:
        raise _unauthorized("Thiếu Authorization header")

    payload = verify_jwt(credentials.credentials)

    sub: str = payload["sub"]
    email: str | None = payload.get("email")
    name: str | None = payload.get("name") or payload.get("preferred_username")
    # Ưu tiên claim "role", fallback "roles" (array), default "owner"
    role: str = payload.get("role") or (
        payload.get("roles", ["owner"])[0]
        if isinstance(payload.get("roles"), list)
        else "owner"
    )

    result = await db.execute(select(User).where(User.external_id == sub))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(external_id=sub, email=email, display_name=name, role=role)
        db.add(user)
        await db.flush()
        logger.info("New user provisioned: sub=%s role=%s", sub, role)
    else:
        # Sync email/name nếu thay đổi ở IdP
        updated = False
        if email and user.email != email:
            user.email = email
            updated = True
        if name and user.display_name != name:
            user.display_name = name
            updated = True
        if updated:
            await db.flush()

    current = CurrentUser(user=user, payload=payload)
    request.state.current_user = current
    return current


# ── RBAC guard ────────────────────────────────────────────────────────────────


def require_roles(*roles: str):
    """
    Dependency factory kiểm tra role.

    Dùng:
        @app.post("/admin/...", dependencies=[Depends(require_roles("admin"))])
        async def admin_endpoint(): ...

    Hoặc kết hợp với get_current_user:
        async def endpoint(user: CurrentUser = Depends(require_roles("owner", "admin"))):
    """
    async def _check(
        current: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        if current.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Yêu cầu role: {list(roles)}. Role hiện tại: {current.role}",
            )
        return current

    return _check


async def require_verified_email(
    current: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Chặn thao tác nhạy cảm khi email chưa xác minh OTP."""
    from services.email_verification import is_user_email_verified, verification_required

    if verification_required() and not is_user_email_verified(current.user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="EMAIL_NOT_VERIFIED",
        )
    return current
