"""
Xác minh email bằng OTP 6 số (gửi qua Gmail SMTP).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import EmailVerificationCode, User
from services import email_service
from services.user_email import is_valid_alert_email, normalize_email

logger = logging.getLogger(__name__)

EMAIL_VERIFICATION_ENABLED: bool = (
    os.getenv("EMAIL_VERIFICATION_ENABLED", "true").lower() == "true"
)
OTP_LENGTH = int(os.getenv("EMAIL_OTP_LENGTH", "6"))
OTP_EXPIRE_MINUTES = int(os.getenv("EMAIL_OTP_EXPIRE_MINUTES", "15"))
OTP_RESEND_COOLDOWN_SEC = int(os.getenv("EMAIL_OTP_RESEND_COOLDOWN_SEC", "60"))


def verification_required() -> bool:
    """Bật khi EMAIL_VERIFICATION_ENABLED và Gmail đã cấu hình."""
    return EMAIL_VERIFICATION_ENABLED and email_service.is_configured()


def is_user_email_verified(user: User) -> bool:
    if not verification_required():
        return True
    return user.email_verified_at is not None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_code(user_id: str, email: str, code: str) -> str:
    raw = f"{user_id}:{normalize_email(email)}:{code}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _generate_otp() -> str:
    upper = 10**OTP_LENGTH
    return str(secrets.randbelow(upper)).zfill(OTP_LENGTH)


async def mark_email_verified(db: AsyncSession, user: User) -> None:
    user.email_verified_at = _utc_now()
    await db.execute(
        delete(EmailVerificationCode).where(EmailVerificationCode.user_id == user.id)
    )


async def issue_verification_challenge(
    db: AsyncSession,
    user: User,
    *,
    email: str | None = None,
) -> None:
    """Tạo OTP mới và gửi email (nếu verification bật)."""
    if not verification_required():
        await mark_email_verified(db, user)
        return

    target = normalize_email(email or user.email or "")
    if not is_valid_alert_email(target):
        raise ValueError("Email không hợp lệ")

    now = _utc_now()
    latest = (
        await db.execute(
            select(EmailVerificationCode)
            .where(EmailVerificationCode.user_id == user.id)
            .order_by(EmailVerificationCode.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if latest and latest.created_at:
        created = latest.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if (now - created).total_seconds() < OTP_RESEND_COOLDOWN_SEC:
            raise ValueError(
                f"Vui lòng đợi {OTP_RESEND_COOLDOWN_SEC} giây trước khi gửi lại mã"
            )

    await db.execute(
        delete(EmailVerificationCode).where(EmailVerificationCode.user_id == user.id)
    )

    code = _generate_otp()
    expires = now + timedelta(minutes=OTP_EXPIRE_MINUTES)
    db.add(
        EmailVerificationCode(
            user_id=user.id,
            email=target,
            code_hash=_hash_code(user.id, target, code),
            expires_at=expires,
        )
    )
    await db.flush()

    await email_service.send_verification_otp_email(
        to_email=target,
        code=code,
        expires_minutes=OTP_EXPIRE_MINUTES,
    )
    logger.info("Verification OTP issued for user_id=%s", user.id)


async def verify_otp(db: AsyncSession, user: User, code: str) -> bool:
    if not verification_required():
        return True

    normalized = code.strip()
    if not normalized.isdigit() or len(normalized) != OTP_LENGTH:
        return False

    row = (
        await db.execute(
            select(EmailVerificationCode)
            .where(EmailVerificationCode.user_id == user.id)
            .order_by(EmailVerificationCode.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        return False

    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < _utc_now():
        return False

    expected = _hash_code(user.id, row.email, normalized)
    if not secrets.compare_digest(row.code_hash, expected):
        return False

    user.email = row.email
    await mark_email_verified(db, user)
    return True


async def resend_cooldown_remaining(db: AsyncSession, user_id: str) -> int:
    row = (
        await db.execute(
            select(EmailVerificationCode)
            .where(EmailVerificationCode.user_id == user_id)
            .order_by(EmailVerificationCode.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        return 0
    created = row.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    elapsed = int((_utc_now() - created).total_seconds())
    return max(0, OTP_RESEND_COOLDOWN_SEC - elapsed)
