"""
Admin — thống kê hoạt động file (upload/download) + file rủi ro.
Không đọc nội dung file — chỉ metadata và logs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from db.models import DownloadLog, File, SasTokenRecord, TokenSecurityAlert, UploadLog
from services.owner_security import MULTI_IP_ALERT_THRESHOLD
from services.user_email import is_valid_alert_email

SUSPICIOUS_MIN_IPS = MULTI_IP_ALERT_THRESHOLD


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _day_key(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _fill_days(days: int) -> list[str]:
    today = _utc_now().date()
    return [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]


def _bucket_by_day(day_labels: list[str], timestamps: list[datetime]) -> list[int]:
    counts = {d: 0 for d in day_labels}
    for dt in timestamps:
        if dt is None:
            continue
        key = _day_key(dt)
        if key in counts:
            counts[key] += 1
    return [counts[d] for d in day_labels]


async def build_file_overview(db: AsyncSession, *, days: int = 7, limit: int = 20) -> dict[str, Any]:
    days = max(1, min(days, 30))
    since = _utc_now() - timedelta(days=days)
    day_labels = _fill_days(days)

    upload_ts = (
        await db.execute(select(UploadLog.created_at).where(UploadLog.created_at >= since))
    ).scalars().all()
    download_ts = (
        await db.execute(select(DownloadLog.created_at).where(DownloadLog.created_at >= since))
    ).scalars().all()

    # Top files by download count
    dl_agg = (
        await db.execute(
            select(
                DownloadLog.file_id,
                DownloadLog.original_filename,
                func.count(DownloadLog.id).label("downloads"),
                func.count(func.distinct(DownloadLog.ip_address)).label("unique_ips"),
                func.count(func.distinct(DownloadLog.user_id)).label("unique_users"),
            )
            .where(DownloadLog.created_at >= since, DownloadLog.file_id.isnot(None))
            .group_by(DownloadLog.file_id, DownloadLog.original_filename)
            .order_by(func.count(DownloadLog.id).desc())
            .limit(limit)
        )
    ).all()

    file_ids = [row.file_id for row in dl_agg if row.file_id]
    owners: dict[str, dict[str, Any]] = {}
    if file_ids:
        files = (
            await db.execute(
                select(File)
                .where(File.id.in_(file_ids))
                .options(selectinload(File.owner))
            )
        ).scalars().all()
        for f in files:
            owner_email = f.owner.email if f.owner else None
            owners[f.id] = {
                "owner_id": f.owner_id,
                "owner_email": owner_email,
                "owner_email_valid": is_valid_alert_email(owner_email),
                "storage_mode": f.storage_mode,
            }

    # SAS records per file (active links)
    sas_counts: dict[str | None, int] = {}
    if file_ids:
        sas_rows = (
            await db.execute(
                select(SasTokenRecord.file_id, func.count(SasTokenRecord.id))
                .where(
                    SasTokenRecord.file_id.in_(file_ids),
                    SasTokenRecord.is_revoked.is_(False),
                    SasTokenRecord.expires_at > _utc_now(),
                )
                .group_by(SasTokenRecord.file_id)
            )
        ).all()
        sas_counts = {r[0]: int(r[1]) for r in sas_rows}

    # Alerts linked to files
    alert_by_file: dict[str, int] = {}
    if file_ids:
        alert_rows = (
            await db.execute(
                select(TokenSecurityAlert.file_id, func.count(TokenSecurityAlert.id))
                .where(
                    TokenSecurityAlert.file_id.in_(file_ids),
                    TokenSecurityAlert.created_at >= since,
                )
                .group_by(TokenSecurityAlert.file_id)
            )
        ).all()
        alert_by_file = {r[0]: int(r[1]) for r in alert_rows if r[0]}

    top_files: list[dict[str, Any]] = []
    for row in dl_agg:
        fid = row.file_id
        downloads = int(row.downloads)
        unique_ips = int(row.unique_ips or 0)
        suspicious = unique_ips > SUSPICIOUS_MIN_IPS
        owner = owners.get(fid or "", {})
        top_files.append({
            "file_id": fid,
            "file_name": row.original_filename,
            "downloads": downloads,
            "unique_ips": unique_ips,
            "unique_users": int(row.unique_users or 0),
            "active_sas_links": sas_counts.get(fid, 0),
            "ai_alerts": alert_by_file.get(fid, 0),
            "suspicious": suspicious,
            "owner_email": owner.get("owner_email"),
            "owner_email_valid": owner.get("owner_email_valid", False),
            "owner_id": owner.get("owner_id"),
            "storage_mode": owner.get("storage_mode"),
        })

    suspicious_count = sum(1 for f in top_files if f["suspicious"] or f["ai_alerts"] > 0)

    top_file_trends: list[dict[str, Any]] = []
    for f in top_files[:5]:
        fid = f.get("file_id")
        if not fid:
            continue
        file_dl_ts = (
            await db.execute(
                select(DownloadLog.created_at).where(
                    DownloadLog.file_id == fid,
                    DownloadLog.created_at >= since,
                )
            )
        ).scalars().all()
        top_file_trends.append({
            "file_id": fid,
            "file_name": f["file_name"],
            "downloads_per_day": _bucket_by_day(day_labels, list(file_dl_ts)),
        })

    return {
        "days": days,
        "labels": day_labels,
        "summary": {
            "uploads": len(upload_ts),
            "downloads": len(download_ts),
            "unique_files_downloaded": len(dl_agg),
            "suspicious_files": suspicious_count,
        },
        "trend": {
            "uploads_per_day": _bucket_by_day(day_labels, list(upload_ts)),
            "downloads_per_day": _bucket_by_day(day_labels, list(download_ts)),
        },
        "top_file_trends": top_file_trends,
        "top_files": top_files,
    }


async def get_file_detail(db: AsyncSession, file_id: str, *, days: int = 7) -> dict[str, Any] | None:
    days = max(1, min(days, 30))
    since = _utc_now() - timedelta(days=days)

    file_row = (
        await db.execute(
            select(File).where(File.id == file_id).options(selectinload(File.owner))
        )
    ).scalar_one_or_none()
    if not file_row:
        return None

    downloads = (
        await db.execute(
            select(DownloadLog)
            .where(DownloadLog.file_id == file_id, DownloadLog.created_at >= since)
            .order_by(DownloadLog.created_at.desc())
            .limit(50)
        )
    ).scalars().all()

    uploads = (
        await db.execute(
            select(UploadLog)
            .where(UploadLog.file_id == file_id, UploadLog.created_at >= since)
            .order_by(UploadLog.created_at.desc())
            .limit(20)
        )
    ).scalars().all()

    sas_active = (
        await db.execute(
            select(func.count(SasTokenRecord.id)).where(
                SasTokenRecord.file_id == file_id,
                SasTokenRecord.is_revoked.is_(False),
                SasTokenRecord.expires_at > _utc_now(),
            )
        )
    ).scalar() or 0

    alerts = (
        await db.execute(
            select(TokenSecurityAlert)
            .where(TokenSecurityAlert.file_id == file_id)
            .order_by(TokenSecurityAlert.created_at.desc())
            .limit(10)
        )
    ).scalars().all()

    unique_ips = len({d.ip_address for d in downloads if d.ip_address})

    return {
        "file_id": file_id,
        "file_name": file_row.original_filename,
        "owner_email": file_row.owner.email if file_row.owner else None,
        "owner_email_valid": is_valid_alert_email(
            file_row.owner.email if file_row.owner else None
        ),
        "owner_id": file_row.owner_id,
        "storage_mode": file_row.storage_mode,
        "file_size_bytes": file_row.file_size_bytes,
        "created_at": file_row.created_at.isoformat(),
        "stats": {
            "downloads": len(downloads),
            "uploads": len(uploads),
            "unique_ips": unique_ips,
            "active_sas_links": int(sas_active),
            "suspicious": unique_ips > SUSPICIOUS_MIN_IPS,
        },
        "recent_downloads": [
            {
                "user_id": d.user_id,
                "ip_address": d.ip_address,
                "created_at": d.created_at.isoformat(),
            }
            for d in downloads[:15]
        ],
        "recent_alerts": [
            {
                "id": a.id,
                "ai_score_pct": a.ai_score_pct,
                "decision": a.decision,
                "summary_vi": a.summary_vi,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
    }
