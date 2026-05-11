"""
Auth router — /auth/*

3 role: owner | recipient | admin
  owner     : upload file, chia sẻ, revoke file của mình
  recipient : chỉ xem/tải file được chia sẻ, không upload
  admin     : full access + quản lý user

Token strategy (production-hardened):
  - Access token:  JWT HS256/RS256, short-lived (configurable, default 15 min),
                   chứa claim jti để tracing.
  - Refresh token: UUID ngẫu nhiên lưu trong DB, trả về qua httpOnly cookie
                   path=/auth (không gửi kèm mọi API call khác).
  - Rotation:      Mỗi lần refresh → token cũ bị mark replaced_by_jti → token mới.
                   Nếu ai dùng lại token đã replaced → reuse attack
                   → revoke toàn bộ session của user.
"""

from __future__ import annotations

import logging
import os
import uuid as _uuid_mod
from datetime import datetime, timedelta, timezone
from typing import Literal

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, JWT_ALGORITHM, _signing_key, get_current_user
from db.dependencies import get_db
from db.models import RefreshToken, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = "strict" if COOKIE_SECURE else "lax"

# Role hợp lệ trong hệ thống
VALID_ROLES = {"owner", "recipient", "admin"}
RoleType = Literal["owner", "recipient", "admin"]


# ── Schemas ───────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    # Tự đăng ký luôn nhận role "owner" (bỏ qua field này).
    # Dùng POST /admin/users để tạo account với role khác.
    role: RoleType = "owner"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str
    display_name: str | None
    role: RoleType


class ChangeRoleRequest(BaseModel):
    role: RoleType


class UserOut(BaseModel):
    id: str
    email: str | None
    display_name: str | None
    role: str
    created_at: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def _hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def _verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


def _create_access_token(user: User) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user.external_id,
        "email": user.email,
        "name": user.display_name,
        "role": user.role,
        "jti": str(_uuid_mod.uuid4()),   # unique ID cho token này
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _signing_key(), algorithm=JWT_ALGORITHM)


async def _issue_refresh_token(
    db: AsyncSession,
    user: User,
    request: Request,
    old_jti: str | None = None,
) -> tuple[str, datetime]:
    """
    Tạo RefreshToken row, trả về (jti, expires_at).
    Nếu old_jti được truyền → đánh dấu token cũ là replaced (rotation).
    """
    jti = str(_uuid_mod.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    if old_jti:
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


def _set_refresh_cookie(response: Response, jti: str, expires_at: datetime) -> None:
    response.set_cookie(
        key="sf_refresh_token",
        value=jti,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/auth",          # chỉ gửi tới /auth/* — không lộ ra mọi request
        expires=expires_at,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key="sf_refresh_token",
        path="/auth",
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
    )


def _token_response(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=_create_access_token(user),
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Đăng ký tài khoản mới.
    - Tự đăng ký → role luôn là 'owner' (role field bị ignore khi không có admin token)
    - Muốn tạo account với role khác → dùng POST /admin/users
    """
    existing = (
        await db.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email đã được đăng ký",
        )

    user = User(
        external_id=str(_uuid_mod.uuid4()),
        email=body.email,
        display_name=body.display_name or body.email.split("@")[0],
        role="owner",
        password_hash=_hash_password(body.password),
    )
    db.add(user)
    await db.flush()

    jti, expires_at = await _issue_refresh_token(db, user, request)
    await db.commit()
    _set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.register",
        user_id=user.id,
        email=user.email,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Đăng nhập, trả access_token + set refresh_token cookie."""
    user = (
        await db.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()

    if user is None or not user.password_hash:
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")
    if not _verify_password(body.password, user.password_hash):
        audit.log_event(
            "user.login.failed",
            email=body.email,
            ip=audit.get_ip(request),
            request_id=audit.get_request_id(request),
        )
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

    jti, expires_at = await _issue_refresh_token(db, user, request)
    await db.commit()
    _set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.login",
        user_id=user.id,
        email=user.email,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Phát access_token mới từ refresh token cookie (silent refresh).

    Rotation: refresh token cũ bị mark replaced → token mới được set vào cookie.
    Token reuse attack: nếu ai dùng token đã replaced → revoke toàn bộ session user.
    """
    jti = request.cookies.get("sf_refresh_token")
    if not jti:
        raise HTTPException(status_code=401, detail="Refresh token không tồn tại")

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.jti == jti)
    )
    rt = result.scalar_one_or_none()

    if rt is None:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token không hợp lệ")

    now = datetime.now(timezone.utc)

    if rt.revoked_at is not None:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token đã bị thu hồi")

    if rt.replaced_by_jti is not None:
        # Reuse attack: token đã được rotate rồi nhưng vẫn bị dùng lại
        # → revoke toàn bộ session của user này
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == rt.user_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await db.commit()
        _clear_refresh_cookie(response)
        audit.log_event(
            "security.refresh_token_reuse",
            user_id=rt.user_id,
            ip=audit.get_ip(request),
            request_id=audit.get_request_id(request),
        )
        raise HTTPException(
            status_code=401,
            detail="Phát hiện tái sử dụng refresh token — vui lòng đăng nhập lại",
        )

    rt_expires = rt.expires_at
    if rt_expires.tzinfo is None:
        rt_expires = rt_expires.replace(tzinfo=timezone.utc)
    if rt_expires < now:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token đã hết hạn")

    user = (
        await db.execute(select(User).where(User.id == rt.user_id))
    ).scalar_one_or_none()
    if user is None:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="User không tồn tại")

    new_jti, new_expires = await _issue_refresh_token(db, user, request, old_jti=jti)
    await db.commit()
    _set_refresh_cookie(response, new_jti, new_expires)

    audit.log_event(
        "user.token_refresh",
        user_id=user.id,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Thu hồi refresh token hiện tại + xóa cookie.
    Không cần access token hợp lệ (vẫn logout được khi access token hết hạn).
    """
    jti = request.cookies.get("sf_refresh_token")
    if jti:
        now = datetime.now(timezone.utc)
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.jti == jti,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await db.commit()

        # Lấy user_id để log (best-effort)
        rt = (
            await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))
        ).scalar_one_or_none()
        user_id = rt.user_id if rt else None

        audit.log_event(
            "user.logout",
            user_id=user_id,
            ip=audit.get_ip(request),
            request_id=audit.get_request_id(request),
        )

    _clear_refresh_cookie(response)
    return {"message": "Đã đăng xuất"}


# ── Admin: quản lý users ──────────────────────────────────────────────────────


@router.get("/admin/users", response_model=list[UserOut], tags=["admin"])
async def list_users(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Danh sách tất cả user — chỉ admin."""
    _require_admin(current)
    rows = (
        await db.execute(select(User).order_by(User.created_at.desc()))
    ).scalars().all()
    audit.log_event(
        "admin.list_users",
        user_id=current.id,
        role=current.role,
        request_id=audit.get_request_id(request),
        count=len(rows),
    )
    return [_to_user_out(u) for u in rows]


@router.post("/admin/users", response_model=TokenResponse, status_code=201, tags=["admin"])
async def admin_create_user(
    body: RegisterRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin tạo tài khoản với role tuỳ chọn (owner / recipient / admin)."""
    _require_admin(current)

    existing = (
        await db.execute(select(User).where(User.email == body.email))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email đã được đăng ký")

    user = User(
        external_id=str(_uuid_mod.uuid4()),
        email=body.email,
        display_name=body.display_name or body.email.split("@")[0],
        role=body.role,
        password_hash=_hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    await db.commit()

    audit.log_event(
        "admin.create_user",
        user_id=current.id,
        role=current.role,
        target_email=user.email,
        target_role=user.role,
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


@router.patch(
    "/admin/users/{user_id}/role", response_model=UserOut, tags=["admin"]
)
async def change_user_role(
    user_id: str,
    body: ChangeRoleRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Đổi role của user — chỉ admin. Admin không thể tự hạ role của mình."""
    _require_admin(current)
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="Không thể đổi role của chính mình")

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    old_role = user.role
    user.role = body.role
    await db.commit()

    audit.log_event(
        "admin.change_role",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        old_role=old_role,
        new_role=body.role,
        request_id=audit.get_request_id(request),
    )
    return _to_user_out(user)


@router.delete("/admin/users/{user_id}", status_code=204, tags=["admin"])
async def delete_user(
    user_id: str,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Xóa user — chỉ admin. Admin không thể xóa chính mình."""
    _require_admin(current)
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="Không thể xóa chính mình")

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    await db.delete(user)
    await db.commit()

    audit.log_event(
        "admin.delete_user",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        request_id=audit.get_request_id(request),
    )


# ── Helpers nội bộ ─────────────────────────────────────────────────────────────


def _require_admin(current: CurrentUser) -> None:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Yêu cầu quyền admin")


def _to_user_out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        role=u.role,
        created_at=u.created_at.isoformat(),
    )
