"""verification_router.py — Email verification endpoints."""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser, get_current_user
from db.dependencies import get_db
from db.models import User
from services import email_verification, rate_limit
from services.client_ip import client_ip as get_trusted_client_ip

logger = logging.getLogger(__name__)

# A07: OTP chỉ 6 số (10^6 khả năng) và sống 15 phút — không giới hạn số lần thử
# thì brute-force xong trước khi mã hết hạn.
_OTP_MAX_FAILURES = int(os.getenv("EMAIL_OTP_MAX_FAILURES", "8"))
_OTP_FAILURE_WINDOW = int(os.getenv("EMAIL_OTP_FAILURE_WINDOW", "900"))
_OTP_TOO_MANY = "Nhập sai mã quá nhiều lần. Vui lòng yêu cầu mã mới sau ít phút."

_RESEND_MAX = int(os.getenv("EMAIL_OTP_RESEND_MAX", "5"))
_RESEND_WINDOW = int(os.getenv("EMAIL_OTP_RESEND_WINDOW", "3600"))

from routers._auth_helpers import (
    TokenResponse,
    VerificationStatusResponse,
    VerifyEmailRequest,
    make_token_response,
)

router = APIRouter(tags=["auth"])


@router.get("/me/verification-status", response_model=VerificationStatusResponse)
async def verification_status(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trạng thái xác minh email + cooldown gửi lại OTP."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    return VerificationStatusResponse(
        email_verified=email_verification.is_user_email_verified(user),
        email=user.email,
        verification_required=email_verification.verification_required(),
        resend_cooldown_sec=await email_verification.resend_cooldown_remaining(db, user.id),
    )


@router.post("/verify-email", response_model=TokenResponse)
async def verify_email(
    body: VerifyEmailRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Xác minh email bằng mã OTP 6 số."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    if email_verification.is_user_email_verified(user):
        return make_token_response(user)

    # A07: chặn brute-force OTP. Đếm theo user_id (token đã xác thực) nên attacker
    # không né được bằng cách đổi IP.
    rate_limit.guard_failures(
        "otp_verify", current.id,
        limit=_OTP_MAX_FAILURES, window=_OTP_FAILURE_WINDOW, detail=_OTP_TOO_MANY,
    )

    ok = await email_verification.verify_otp(db, user, body.code)
    if not ok:
        rate_limit.record_failure("otp_verify", current.id, window=_OTP_FAILURE_WINDOW)
        logger.warning(
            "A07: OTP sai — user=%s ip=%s", current.id, get_trusted_client_ip(request)
        )
        raise HTTPException(status_code=400, detail="Mã xác minh không đúng hoặc đã hết hạn")

    rate_limit.clear("otp_verify", current.id)
    await db.commit()
    return make_token_response(user)


@router.post("/resend-verification")
async def resend_verification(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Gửi lại mã OTP xác minh email."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    if email_verification.is_user_email_verified(user):
        return {"status": "already_verified"}

    # A04: cooldown 60s trong service chỉ chặn spam liên tiếp; thêm hạn mức giờ
    # để không dùng được endpoint này làm công cụ email-bombing.
    rate_limit.check_rate(
        "otp_resend", current.id,
        limit=_RESEND_MAX, window=_RESEND_WINDOW,
        detail="Đã yêu cầu gửi lại mã quá nhiều lần. Vui lòng thử lại sau.",
    )

    try:
        await email_verification.issue_verification_challenge(db, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await db.commit()
    return {"status": "sent"}
