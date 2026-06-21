"""profile_router.py — Profile endpoints: display name, email, password, history, security alerts."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, get_current_user
from db.dependencies import get_db
from db.models import RefreshToken, User, UserDisplayNameHistory, UserSecurityAlert
from schemas.user_security import MarkAlertReadRequest, UserSecurityAlertOut, UserSecurityAlertsResponse
from services import email_verification, owner_security
from services.user_email import is_valid_alert_email, normalize_email

from routers._auth_helpers import (
    ChangePasswordRequest,
    DisplayNameHistoryOut,
    TokenResponse,
    UpdateEmailRequest,
    UpdateProfileRequest,
    hash_password,
    issue_refresh_token,
    make_token_response,
    set_refresh_cookie,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["profile"])


# ── Email ─────────────────────────────────────────────────────────────────────

@router.patch("/me/email", response_model=TokenResponse)
async def update_email(
    body: UpdateEmailRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cập nhật email nhận cảnh báo bảo mật."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User không tồn tại")

    new_email = normalize_email(str(body.email))
    if not is_valid_alert_email(new_email):
        raise HTTPException(status_code=400, detail="Email không hợp lệ")
    if (user.email or "").strip().lower() == new_email:
        return make_token_response(user)

    existing = (
        await db.execute(select(User).where(User.email == new_email, User.id != user.id))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email đã được sử dụng bởi tài khoản khác")

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
    return make_token_response(user)


# ── Display name ──────────────────────────────────────────────────────────────

@router.patch("/me", response_model=TokenResponse)
async def update_profile(
    body: UpdateProfileRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cập nhật tên hiển thị; trả access token mới."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    name = body.display_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Tên hiển thị không được để trống")

    previous_name = user.display_name
    if (previous_name or "").strip() == name:
        return make_token_response(user)

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
    return make_token_response(user)


@router.get("/me/display-name-history", response_model=list[DisplayNameHistoryOut])
async def get_my_display_name_history(
    limit: int = 50,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lịch sử đổi tên hiển thị của user đang đăng nhập."""
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


# ── Password ──────────────────────────────────────────────────────────────────

@router.post("/change-password", response_model=TokenResponse)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Đổi mật khẩu khi đã đăng nhập. Thu hồi session cũ, phát token mới."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None or not user.password_hash:
        raise HTTPException(status_code=400, detail="Tài khoản không hỗ trợ đổi mật khẩu kiểu này")
    if not verify_password(body.current_password, user.password_hash):
        audit.log_event("user.password_change.failed", user_id=user.id, ip=audit.get_ip(request))
        raise HTTPException(status_code=401, detail="Mật khẩu hiện tại không đúng")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=400, detail="Mật khẩu mới phải khác mật khẩu hiện tại")

    user.password_hash = hash_password(body.new_password)
    now = datetime.now(timezone.utc)
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    jti, expires_at = await issue_refresh_token(db, user, request)
    await db.commit()
    set_refresh_cookie(response, jti, expires_at)

    audit.log_event(
        "user.password_changed",
        user_id=user.id,
        role=user.role,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
    )
    return make_token_response(user)


# ── Security alerts ───────────────────────────────────────────────────────────

@router.get("/me/security-alerts", response_model=UserSecurityAlertsResponse)
async def my_security_alerts(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 20,
    unread_only: bool = False,
):
    """Cảnh báo bảo mật cho user."""
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
    """Đánh dấu cảnh báo đã đọc."""
    q = select(UserSecurityAlert).where(UserSecurityAlert.user_id == current.id)
    if body.alert_ids:
        q = q.where(UserSecurityAlert.id.in_(body.alert_ids))
    rows = (await db.execute(q)).scalars().all()
    for row in rows:
        row.is_read = True
    return {"marked": len(rows)}
