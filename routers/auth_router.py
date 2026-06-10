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
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, JWT_ALGORITHM, _signing_key, get_current_user
from db.dependencies import get_db
from db.models import (
    File,
    FileRecipient,
    RefreshToken,
    User,
    UserDisplayNameHistory,
    UserPublicKey,
    UserSecurityAlert,
)
from services.azure_storage import delete_blob
from schemas.user_security import MarkAlertReadRequest, UserSecurityAlertOut, UserSecurityAlertsResponse
from services import email_verification, google_oauth, owner_security
from services.user_email import is_valid_alert_email, normalize_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
_samesite_env = os.getenv("COOKIE_SAMESITE", "").strip().lower()
if _samesite_env in ("lax", "strict", "none"):
    COOKIE_SAMESITE = _samesite_env
else:
    COOKIE_SAMESITE = "strict" if COOKIE_SECURE else "lax"
if COOKIE_SAMESITE == "none" and not COOKIE_SECURE:
    COOKIE_SECURE = True  # browser yêu cầu Secure khi SameSite=None

# Role hợp lệ trong hệ thống
VALID_ROLES = {"owner", "recipient", "admin"}
RoleType = Literal["owner", "recipient", "admin"]


# ── Schemas ───────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    username: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str | None = Field(default=None, max_length=128)
    role: RoleType = "owner"


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


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class UpdateProfileRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)


class UpdateEmailRequest(BaseModel):
    email: EmailStr


class UserOut(BaseModel):
    id: str
    email: str | None
    display_name: str | None
    role: str
    created_at: str
    has_public_key: bool = False


class DisplayNameHistoryOut(BaseModel):
    id: str
    old_display_name: str | None
    new_display_name: str
    changed_at: str
    ip_address: str | None = None


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
        email=user.email or "",
        display_name=user.display_name,
        role=user.role,
        email_verified=email_verification.is_user_email_verified(user),
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
        await db.execute(select(User).where(User.email == body.username))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tên đăng nhập đã được sử dụng",
        )

    email = normalize_email(str(body.username))
    user = User(
        external_id=str(_uuid_mod.uuid4()),
        email=email,
        display_name=body.display_name or email,
        role="owner",
        password_hash=_hash_password(body.password),
        email_verified_at=None,
    )
    db.add(user)
    await db.flush()

    try:
        await email_verification.issue_verification_challenge(db, user, email=email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    jti, expires_at = await _issue_refresh_token(db, user, request)
    await db.commit()
    _set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.register",
        user_id=user.id,
        username=user.email,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


@router.get("/google/config", response_model=GoogleOAuthConfigResponse)
async def google_oauth_config():
    """Cấu hình public cho nút Đăng nhập bằng Google (frontend)."""
    cfg = google_oauth.public_config()
    return GoogleOAuthConfigResponse(
        enabled=bool(cfg["enabled"]),
        client_id=str(cfg.get("client_id") or ""),
    )


async def _get_or_create_google_user(
    db: AsyncSession,
    info: google_oauth.GoogleUserInfo,
) -> User:
    ext_id = google_oauth.google_external_id(info.sub)

    user = (
        await db.execute(select(User).where(User.external_id == ext_id))
    ).scalar_one_or_none()
    if user:
        return user

    user = (
        await db.execute(select(User).where(User.email == info.email))
    ).scalar_one_or_none()
    if user:
        if info.name and not user.display_name:
            user.display_name = info.name
        return user

    user = User(
        external_id=ext_id,
        email=info.email,
        display_name=info.name or info.email,
        role="owner",
        password_hash=None,
    )
    db.add(user)
    await db.flush()
    return user


@router.post("/google", response_model=TokenResponse)
async def google_login(
    body: GoogleLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Đăng nhập / đăng ký bằng Google ID token từ frontend."""
    if not google_oauth.is_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Đăng nhập Google chưa được bật",
        )

    try:
        info = await google_oauth.verify_id_token(body.credential)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    user = await _get_or_create_google_user(db, info)
    await email_verification.mark_email_verified(db, user)
    jti, expires_at = await _issue_refresh_token(db, user, request)
    await owner_security.sync_keypair_expiry_alerts(db, user.id)
    await db.commit()
    _set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.login.google",
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
    """Đăng nhập bằng email + mật khẩu."""
    email = normalize_email(str(body.username))
    user = (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()

    if user is None or not user.password_hash:
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")
    if not _verify_password(body.password, user.password_hash):
        audit.log_event(
            "user.login.failed",
            username=email,
            ip=audit.get_ip(request),
            request_id=audit.get_request_id(request),
        )
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

    jti, expires_at = await _issue_refresh_token(db, user, request)
    await owner_security.sync_keypair_expiry_alerts(db, user.id)
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


@router.patch("/me/email", response_model=TokenResponse)
async def update_email(
    body: UpdateEmailRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cập nhật email nhận cảnh báo bảo mật (phải là địa chỉ email hợp lệ)."""
    user = (
        await db.execute(select(User).where(User.id == current.id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User không tồn tại")

    new_email = normalize_email(str(body.email))
    if not is_valid_alert_email(new_email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email không hợp lệ",
        )

    if (user.email or "").strip().lower() == new_email:
        return _token_response(user)

    existing = (
        await db.execute(
            select(User).where(User.email == new_email, User.id != user.id)
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email đã được sử dụng bởi tài khoản khác",
        )

    user.email = new_email
    user.email_verified_at = None
    try:
        await email_verification.issue_verification_challenge(db, user, email=new_email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await db.commit()

    audit.log_event(
        "user.email_changed",
        user_id=user.id,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


@router.get("/me/verification-status", response_model=VerificationStatusResponse)
async def verification_status(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trạng thái xác minh email + cooldown gửi lại OTP."""
    user = (
        await db.execute(select(User).where(User.id == current.id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    return VerificationStatusResponse(
        email_verified=email_verification.is_user_email_verified(user),
        email=user.email,
        verification_required=email_verification.verification_required(),
        resend_cooldown_sec=await email_verification.resend_cooldown_remaining(
            db, user.id
        ),
    )


@router.post("/verify-email", response_model=TokenResponse)
async def verify_email(
    body: VerifyEmailRequest,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Xác minh email bằng mã OTP 6 số."""
    user = (
        await db.execute(select(User).where(User.id == current.id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    if email_verification.is_user_email_verified(user):
        return _token_response(user)

    ok = await email_verification.verify_otp(db, user, body.code)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="Mã xác minh không đúng hoặc đã hết hạn",
        )
    await db.commit()
    return _token_response(user)


@router.post("/resend-verification")
async def resend_verification(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Gửi lại mã OTP xác minh email."""
    user = (
        await db.execute(select(User).where(User.id == current.id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    if email_verification.is_user_email_verified(user):
        return {"status": "already_verified"}

    try:
        await email_verification.issue_verification_challenge(db, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await db.commit()
    return {"status": "sent"}


@router.patch("/me", response_model=TokenResponse)
async def update_profile(
    body: UpdateProfileRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cập nhật tên hiển thị; trả access token mới (claim name trong JWT)."""
    user = (
        await db.execute(select(User).where(User.id == current.id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User không tồn tại")

    name = body.display_name.strip()
    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tên hiển thị không được để trống",
        )

    previous_name = user.display_name
    if (previous_name or "").strip() == name:
        return _token_response(user)

    client_ip = audit.get_ip(request)
    db.add(
        UserDisplayNameHistory(
            user_id=user.id,
            old_display_name=previous_name,
            new_display_name=name,
            ip_address=client_ip,
            user_agent=request.headers.get("User-Agent"),
        )
    )
    user.display_name = name
    await db.commit()

    audit.log_event(
        "user.display_name_changed",
        user_id=user.id,
        email=user.email,
        role=user.role,
        ip=client_ip,
        request_id=audit.get_request_id(request),
        old_display_name=previous_name,
        new_display_name=name,
    )
    return _token_response(user)


@router.get("/me/display-name-history", response_model=list[DisplayNameHistoryOut])
async def get_my_display_name_history(
    limit: int = 50,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lịch sử đổi tên hiển thị của user đang đăng nhập (mới nhất trước)."""
    cap = min(max(limit, 1), 100)
    rows = (
        await db.execute(
            select(UserDisplayNameHistory)
            .where(UserDisplayNameHistory.user_id == current.id)
            .order_by(UserDisplayNameHistory.changed_at.desc())
            .limit(cap)
        )
    ).scalars().all()
    return [
        DisplayNameHistoryOut(
            id=r.id,
            old_display_name=r.old_display_name,
            new_display_name=r.new_display_name,
            changed_at=r.changed_at.isoformat(),
            ip_address=r.ip_address,
        )
        for r in rows
    ]


@router.get(
    "/admin/users/{user_id}/display-name-history",
    response_model=list[DisplayNameHistoryOut],
    tags=["admin"],
)
async def admin_get_display_name_history(
    user_id: str,
    request: Request,
    limit: int = 50,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin xem lịch sử đổi tên của một user."""
    _require_admin(current)
    cap = min(max(limit, 1), 100)

    user = (
        await db.execute(
            select(User).where(
                (User.id == user_id) | (User.external_id == user_id)
            )
        )
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    rows = (
        await db.execute(
            select(UserDisplayNameHistory)
            .where(UserDisplayNameHistory.user_id == user.id)
            .order_by(UserDisplayNameHistory.changed_at.desc())
            .limit(cap)
        )
    ).scalars().all()

    audit.log_event(
        "admin.view_display_name_history",
        user_id=current.id,
        role=current.role,
        target_user_id=user.id,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
        count=len(rows),
    )
    return [
        DisplayNameHistoryOut(
            id=r.id,
            old_display_name=r.old_display_name,
            new_display_name=r.new_display_name,
            changed_at=r.changed_at.isoformat(),
            ip_address=r.ip_address,
        )
        for r in rows
    ]


@router.post("/change-password", response_model=TokenResponse)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Đổi mật khẩu khi đã đăng nhập (Bearer access token).
    Thu hồi mọi refresh session cũ, phát access + refresh mới.
    """
    user = (
        await db.execute(select(User).where(User.id == current.id))
    ).scalar_one_or_none()
    if user is None or not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tài khoản không hỗ trợ đổi mật khẩu kiểu này",
        )
    if not _verify_password(body.current_password, user.password_hash):
        audit.log_event(
            "user.password_change.failed",
            user_id=user.id,
            ip=audit.get_ip(request),
            request_id=audit.get_request_id(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mật khẩu hiện tại không đúng",
        )
    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mật khẩu mới phải khác mật khẩu hiện tại",
        )

    user.password_hash = _hash_password(body.new_password)
    now = datetime.now(timezone.utc)
    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    jti, expires_at = await _issue_refresh_token(db, user, request)
    await db.commit()
    _set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.password_changed",
        user_id=user.id,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return _token_response(user)


# ── Admin: quản lý users ──────────────────────────────────────────────────────


class PublicKeyOut(BaseModel):
    user_id: str
    public_key_x25519: str
    public_key_ed25519: str
    key_version: int


@router.get("/users/{user_id}/public-key", response_model=PublicKeyOut, tags=["users"])
async def get_user_public_key(
    user_id: str,
    _: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lấy public key (X25519 + Ed25519) của một user theo internal UUID, từ DB."""
    row = (
        await db.execute(
            select(UserPublicKey)
            .where(UserPublicKey.user_id == user_id, UserPublicKey.is_active.is_(True))
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="User chưa đăng ký public key")
    return PublicKeyOut(
        user_id=user_id,
        public_key_x25519=row.public_key_x25519,
        public_key_ed25519=row.public_key_ed25519,
        key_version=row.key_version,
    )


@router.get("/users/search", response_model=list[UserOut], tags=["users"])
async def search_users(
    q: str,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Tìm user theo email (partial match, case-insensitive).
    Dùng khi sender chọn recipient khi upload.
    Trả về tối đa 10 kết quả, không bao gồm chính người gọi.
    """
    if len(q.strip()) < 2:
        return []
    pattern = f"%{q.strip().lower()}%"
    rows = (
        await db.execute(
            select(User)
            .where(User.email.ilike(pattern), User.id != current.id)
            .limit(10)
        )
    ).scalars().all()

    user_ids = [u.id for u in rows]
    active_key_ids: set[str] = set()
    if user_ids:
        key_rows = (
            await db.execute(
                select(UserPublicKey.user_id)
                .where(
                    UserPublicKey.user_id.in_(user_ids),
                    UserPublicKey.is_active.is_(True),
                )
            )
        ).scalars().all()
        active_key_ids = set(key_rows)

    return [_to_user_out(u, has_public_key=u.id in active_key_ids) for u in rows]


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
        await db.execute(select(User).where(User.email == body.username))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Tên đăng nhập đã được sử dụng")

    user = User(
        external_id=str(_uuid_mod.uuid4()),
        email=body.username,
        display_name=body.display_name or body.username,
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
        target_username=user.email,
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

    # SQLAlchemy nullify FK mặc định khi xóa user; recipient_id NOT NULL → phải xóa tay
    await db.execute(delete(FileRecipient).where(FileRecipient.recipient_id == user_id))

    # files.owner_id dùng ON DELETE RESTRICT — phải xóa file (và blob) trước user
    files_result = await db.execute(select(File).where(File.owner_id == user_id))
    for file in files_result.scalars().all():
        try:
            delete_blob(file.blob_name)
        except Exception as exc:
            logger.warning("delete_blob failed for %s: %s", file.blob_name, exc)
        await db.delete(file)

    await db.delete(user)
    await db.commit()

    audit.log_event(
        "admin.delete_user",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        request_id=audit.get_request_id(request),
    )


@router.get("/me/security-alerts", response_model=UserSecurityAlertsResponse)
async def my_security_alerts(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 20,
    unread_only: bool = False,
):
    """Cảnh báo bảo mật cho user (IP bất thường, keypair hết hạn, …)."""
    await owner_security.sync_keypair_expiry_alerts(db, current.id)
    rows, unread = await owner_security.list_user_alerts(
        db, current.id, limit=limit, unread_only=unread_only
    )
    return UserSecurityAlertsResponse(
        alerts=[
            UserSecurityAlertOut(
                id=a.id,
                alert_type=a.alert_type,
                file_id=a.file_id,
                file_name=a.file_name,
                title_vi=a.title_vi,
                message_vi=a.message_vi,
                detail_json=a.detail_json,
                is_read=a.is_read,
                created_at=a.created_at,
            )
            for a in rows
        ],
        unread_count=unread,
    )


@router.patch("/me/security-alerts/read")
async def mark_security_alerts_read(
    body: MarkAlertReadRequest,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Đánh dấu cảnh báo đã đọc (để trống alert_ids = đọc tất cả)."""
    q = select(UserSecurityAlert).where(UserSecurityAlert.user_id == current.id)
    if body.alert_ids:
        q = q.where(UserSecurityAlert.id.in_(body.alert_ids))
    rows = (await db.execute(q)).scalars().all()
    for row in rows:
        row.is_read = True
    return {"marked": len(rows)}


# ── Helpers nội bộ ─────────────────────────────────────────────────────────────


def _require_admin(current: CurrentUser) -> None:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Yêu cầu quyền admin")


def _to_user_out(u: User, has_public_key: bool = False) -> UserOut:
    return UserOut(
        id=u.id,
        email=u.email,
        display_name=u.display_name,
        role=u.role,
        created_at=u.created_at.isoformat(),
        has_public_key=has_public_key,
    )
