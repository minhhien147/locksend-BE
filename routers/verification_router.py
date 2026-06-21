"""verification_router.py — Email verification endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser, get_current_user
from db.dependencies import get_db
from db.models import User
from services import email_verification

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
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Xác minh email bằng mã OTP 6 số."""
    user = (await db.execute(select(User).where(User.id == current.id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")
    if email_verification.is_user_email_verified(user):
        return make_token_response(user)
    ok = await email_verification.verify_otp(db, user, body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Mã xác minh không đúng hoặc đã hết hạn")
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
    try:
        await email_verification.issue_verification_challenge(db, user)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await db.commit()
    return {"status": "sent"}
