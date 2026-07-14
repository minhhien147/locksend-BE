"""
auth_router.py — Core auth: register, login, Google OAuth, refresh, logout.
"""
from __future__ import annotations

import logging
import uuid as _uuid_mod

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import get_current_user
from db.dependencies import get_db
from db.models import RefreshToken, User
from services import email_verification, google_oauth, owner_security
from services.user_email import normalize_email

from routers._auth_helpers import (
    GoogleLoginRequest,
    GoogleOAuthConfigResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    clear_refresh_cookie,
    hash_password,
    issue_refresh_token,
    make_token_response,
    set_refresh_cookie,
    verify_password,
)
from services.login_guard import check_and_record_attempt, clear_attempts, record_failed_attempt
from routers.profile_router import router as profile_router
from routers.users_router import router as users_router
from routers.verification_router import router as verification_router

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Gắn sub-routers vào cùng prefix /auth
router.include_router(profile_router)
router.include_router(users_router)
router.include_router(verification_router)


# ── Register ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    body: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Đăng ký tài khoản mới (role luôn là 'owner')."""
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
        password_hash=hash_password(body.password),
        email_verified_at=None,
    )
    db.add(user)
    await db.flush()

    try:
        await email_verification.issue_verification_challenge(db, user, email=email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    jti, expires_at = await issue_refresh_token(db, user, request)
    await db.commit()
    set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.register",
        user_id=user.id,
        username=user.email,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return make_token_response(user)


# ── Google OAuth ──────────────────────────────────────────────────────────────

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
    user = (await db.execute(select(User).where(User.external_id == ext_id))).scalar_one_or_none()
    if user:
        return user
    user = (await db.execute(select(User).where(User.email == info.email))).scalar_one_or_none()
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
        raise HTTPException(status_code=503, detail="Đăng nhập Google chưa được bật")
    try:
        info = await google_oauth.verify_id_token(body.credential)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    user = await _get_or_create_google_user(db, info)
    await email_verification.mark_email_verified(db, user)
    jti, expires_at = await issue_refresh_token(db, user, request)
    await owner_security.sync_keypair_expiry_alerts(db, user.id)
    await db.commit()
    set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.login.google",
        user_id=user.id,
        email=user.email,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return make_token_response(user)


# ── Login ─────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Đăng nhập bằng email + mật khẩu."""
    email = normalize_email(str(body.username))
    client_ip = request.headers.get("X-Forwarded-For", "")
    if not client_ip and request.client:
        client_ip = request.client.host

    # A07: Kiểm tra brute-force lockout trước khi truy vấn DB
    check_and_record_attempt(client_ip, email)

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()

    if user is None or not user.password_hash:
        record_failed_attempt(client_ip, email)
        audit.log_event(
            "user.login.failed",
            username=email,
            reason="user_not_found_or_no_password",
            ip=audit.get_ip(request),
            user_agent=request.headers.get("User-Agent"),
            request_id=audit.get_request_id(request),
        )
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")
    if not verify_password(body.password, user.password_hash):
        record_failed_attempt(client_ip, email)
        audit.log_event(
            "user.login.failed",
            username=email,
            user_id=user.id,
            reason="wrong_password",
            ip=audit.get_ip(request),
            user_agent=request.headers.get("User-Agent"),
            request_id=audit.get_request_id(request),
        )
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng")

    # Đăng nhập thành công — xoá lịch sử attempts
    clear_attempts(client_ip, email)

    jti, expires_at = await issue_refresh_token(db, user, request)
    await owner_security.sync_keypair_expiry_alerts(db, user.id)
    await db.commit()
    set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.login",
        user_id=user.id,
        email=user.email,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return make_token_response(user)


# ── Refresh ───────────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Silent refresh: phát access_token mới từ refresh token cookie."""
    from datetime import timezone
    jti = request.cookies.get("sf_refresh_token")
    if not jti:
        raise HTTPException(status_code=401, detail="Refresh token không tồn tại")

    rt = (await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))).scalar_one_or_none()
    if rt is None:
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token không hợp lệ")

    now = __import__("datetime").datetime.now(timezone.utc)
    if rt.revoked_at is not None:
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token đã bị thu hồi")

    if rt.replaced_by_jti is not None:
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == rt.user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.commit()
        clear_refresh_cookie(response)
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
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="Refresh token đã hết hạn")

    user = (await db.execute(select(User).where(User.id == rt.user_id))).scalar_one_or_none()
    if user is None:
        clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="User không tồn tại")

    new_jti, new_expires = await issue_refresh_token(db, user, request, old_jti=jti)
    await db.commit()
    set_refresh_cookie(response, new_jti, new_expires)

    audit.log_event(
        "user.token_refresh",
        user_id=user.id,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return make_token_response(user)


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Thu hồi refresh token + xóa cookie."""
    from datetime import timezone
    jti = request.cookies.get("sf_refresh_token")
    if jti:
        now = __import__("datetime").datetime.now(timezone.utc)
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.jti == jti, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await db.commit()
        rt = (await db.execute(select(RefreshToken).where(RefreshToken.jti == jti))).scalar_one_or_none()
        user_id = rt.user_id if rt else None
        audit.log_event(
            "user.logout",
            user_id=user_id,
            ip=audit.get_ip(request),
            request_id=audit.get_request_id(request),
        )

    clear_refresh_cookie(response)
    return {"message": "Đã đăng xuất"}
