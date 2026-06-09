"""
Cảnh báo bảo mật cho file owner — IP bất thường, keypair hết hạn.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import DownloadLog, File, User, UserPublicKey, UserSecurityAlert
from services import email_service
from services.user_email import is_valid_alert_email

logger = logging.getLogger(__name__)

MULTI_IP_ALERT_THRESHOLD = int(os.getenv("MULTI_IP_ALERT_THRESHOLD", "3"))
MULTI_IP_ALERT_WINDOW_DAYS = int(os.getenv("MULTI_IP_ALERT_WINDOW_DAYS", "7"))
MULTI_IP_ALERT_COOLDOWN_DAYS = int(os.getenv("MULTI_IP_ALERT_COOLDOWN_DAYS", "7"))

KEYPAIR_LIFETIME_DAYS = int(os.getenv("KEYPAIR_LIFETIME_DAYS", "365"))
KEYPAIR_EXPIRY_WARN_DAYS = int(os.getenv("KEYPAIR_EXPIRY_WARN_DAYS", "30"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def keypair_expires_at_from_now() -> datetime:
    return _utc_now() + timedelta(days=KEYPAIR_LIFETIME_DAYS)


async def _recent_alert_exists(
    db: AsyncSession,
    *,
    dedupe_key: str,
    cooldown_days: int,
) -> bool:
    since = _utc_now() - timedelta(days=cooldown_days)
    row = (
        await db.execute(
            select(UserSecurityAlert.id).where(
                UserSecurityAlert.dedupe_key == dedupe_key,
                UserSecurityAlert.created_at >= since,
            )
        )
    ).scalar_one_or_none()
    return row is not None


async def _create_alert(
    db: AsyncSession,
    *,
    user_id: str,
    alert_type: str,
    title_vi: str,
    message_vi: str,
    file_id: str | None = None,
    file_name: str | None = None,
    detail_json: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
) -> UserSecurityAlert | None:
    if dedupe_key and await _recent_alert_exists(
        db, dedupe_key=dedupe_key, cooldown_days=MULTI_IP_ALERT_COOLDOWN_DAYS
    ):
        return None

    alert = UserSecurityAlert(
        user_id=user_id,
        alert_type=alert_type,
        file_id=file_id,
        file_name=file_name,
        title_vi=title_vi,
        message_vi=message_vi,
        detail_json=detail_json,
        dedupe_key=dedupe_key,
    )
    db.add(alert)

    # Gửi email thông báo (best-effort, không block luồng chính)
    if email_service.is_configured():
        try:
            user_row = (
                await db.execute(select(User).where(User.id == user_id))
            ).scalar_one_or_none()
            if user_row and is_valid_alert_email(user_row.email):
                asyncio.create_task(
                    email_service.send_security_alert_email(
                        to_email=user_row.email,  # type: ignore[arg-type]
                        alert_type=alert_type,
                        title=title_vi,
                        message=message_vi,
                        file_name=file_name,
                    )
                )
        except Exception:  # noqa: BLE001
            pass  # email là tính năng phụ, không ảnh hưởng đến alert chính

    return alert


async def count_unique_download_ips(
    db: AsyncSession,
    file_id: str,
    *,
    days: int | None = None,
) -> int:
    window = days if days is not None else MULTI_IP_ALERT_WINDOW_DAYS
    since = _utc_now() - timedelta(days=max(1, window))
    rows = (
        await db.execute(
            select(DownloadLog.ip_address)
            .where(
                DownloadLog.file_id == file_id,
                DownloadLog.created_at >= since,
                DownloadLog.ip_address.isnot(None),
            )
            .distinct()
        )
    ).scalars().all()
    return len(rows)


async def maybe_alert_multi_ip_access(
    db: AsyncSession,
    file_id: str,
    *,
    force: bool = False,
    triggered_by: str = "auto",
) -> UserSecurityAlert | None:
    """Cảnh báo owner khi file có hơn N IP tải xuống (mặc định > 3)."""
    file_row = (
        await db.execute(select(File).where(File.id == file_id))
    ).scalar_one_or_none()
    if not file_row or not file_row.owner_id:
        return None

    unique_ips = await count_unique_download_ips(db, file_id)
    if not force and unique_ips <= MULTI_IP_ALERT_THRESHOLD:
        return None

    fname = file_row.original_filename or "file"
    dedupe = f"multi_ip:{file_id}"
    if force:
        dedupe = f"{dedupe}:admin:{_utc_now().strftime('%Y%m%d%H%M')}"

    return await _create_alert(
        db,
        user_id=file_row.owner_id,
        alert_type="admin_notify" if force and triggered_by == "admin" else "multi_ip_access",
        title_vi="Truy cập file từ nhiều IP",
        message_vi=(
            f'File "{fname}" có {unique_ips} địa chỉ IP khác nhau tải xuống '
            f"trong {MULTI_IP_ALERT_WINDOW_DAYS} ngày qua (ngưỡng: > {MULTI_IP_ALERT_THRESHOLD}). "
            "SAS link có thể đã bị lộ. Nên thu hồi link, kiểm tra recipient và "
            "cân nhắc tạo keypair mới tại trang Keys."
        ),
        file_id=file_id,
        file_name=fname,
        detail_json={
            "unique_ips": unique_ips,
            "threshold": MULTI_IP_ALERT_THRESHOLD,
            "window_days": MULTI_IP_ALERT_WINDOW_DAYS,
            "triggered_by": triggered_by,
        },
        dedupe_key=dedupe if not force else None,
    )


async def sync_keypair_expiry_alerts(
    db: AsyncSession,
    user_id: str,
) -> None:
    """Tạo/cập nhật cảnh báo hết hạn keypair cho user."""
    krow = (
        await db.execute(
            select(UserPublicKey).where(
                UserPublicKey.user_id == user_id,
                UserPublicKey.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if not krow:
        return

    now = _utc_now()
    expires = krow.expires_at
    if expires is None:
        krow.expires_at = krow.created_at + timedelta(days=KEYPAIR_LIFETIME_DAYS)
        expires = krow.expires_at

    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    days_left = (expires - now).days

    if days_left < 0:
        await _create_alert(
            db,
            user_id=user_id,
            alert_type="keypair_expired",
            title_vi="Keypair đã hết hạn",
            message_vi=(
                f"Keypair của bạn đã hết hạn vào {expires.date().isoformat()}. "
                "Tạo keypair mới tại trang Keys để tiếp tục mã hóa file an toàn. "
                "Lưu ý: file cũ mã hóa cho public key cũ vẫn cần private key cũ để mở."
            ),
            detail_json={
                "expires_at": expires.isoformat(),
                "days_left": days_left,
                "key_version": krow.key_version,
            },
            dedupe_key=f"keypair_expired:{user_id}:{krow.key_version}",
        )
        return

    if days_left <= KEYPAIR_EXPIRY_WARN_DAYS:
        await _create_alert(
            db,
            user_id=user_id,
            alert_type="keypair_expiring",
            title_vi="Keypair sắp hết hạn",
            message_vi=(
                f"Keypair sẽ hết hạn sau {days_left} ngày ({expires.date().isoformat()}). "
                "Hãy lên kế hoạch tạo keypair mới tại trang Keys trước ngày hết hạn."
            ),
            detail_json={
                "expires_at": expires.isoformat(),
                "days_left": days_left,
                "key_version": krow.key_version,
            },
            dedupe_key=f"keypair_expiring:{user_id}:{krow.key_version}",
        )


async def list_user_alerts(
    db: AsyncSession,
    user_id: str,
    *,
    limit: int = 20,
    unread_only: bool = False,
) -> tuple[list[UserSecurityAlert], int]:
    limit = max(1, min(limit, 50))
    base = select(UserSecurityAlert).where(UserSecurityAlert.user_id == user_id)
    if unread_only:
        base = base.where(UserSecurityAlert.is_read.is_(False))

    unread = (
        await db.execute(
            select(func.count(UserSecurityAlert.id)).where(
                UserSecurityAlert.user_id == user_id,
                UserSecurityAlert.is_read.is_(False),
            )
        )
    ).scalar() or 0

    rows = (
        await db.execute(
            base.order_by(UserSecurityAlert.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    return list(rows), int(unread)


def keypair_status(krow: UserPublicKey | None) -> dict[str, Any]:
    if not krow:
        return {"has_keys": False}
    now = _utc_now()
    expires = krow.expires_at
    if expires and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    days_left: int | None = None
    expired = False
    if expires:
        days_left = (expires - now).days
        expired = days_left < 0
    return {
        "has_keys": True,
        "expires_at": expires.isoformat() if expires else None,
        "days_left": days_left,
        "expired": expired,
        "expiring_soon": days_left is not None and 0 <= days_left <= KEYPAIR_EXPIRY_WARN_DAYS,
        "key_version": krow.key_version,
    }
