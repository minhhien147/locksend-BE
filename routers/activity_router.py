"""
activity_router.py — Admin user activity monitoring.
Prefix: /auth/admin/activity  (admin only)

Endpoints:
  GET /  - paginated activity feed (uploads + downloads + api calls)
  GET /users/{user_id}/summary - per-user activity summary
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, get_current_user
from db.dependencies import get_db
from db.models import DownloadLog, TokenAccessLog, UploadLog, User

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin/activity",
    tags=["activity"],
)


def _require_admin(current: CurrentUser) -> None:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Yêu cầu quyền admin")


# ── Response schemas ──────────────────────────────────────────────────────────

class ActivityItem(BaseModel):
    id: str
    type: Literal["upload", "download", "api"]
    user_id: str | None
    user_email: str | None
    user_display_name: str | None
    detail: str
    ip_address: str | None
    user_agent: str | None
    status_code: int | None
    size_bytes: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ActivityResponse(BaseModel):
    items: list[ActivityItem]
    total: int
    page: int
    pages: int
    has_next: bool
    has_prev: bool


class UserActivitySummary(BaseModel):
    user_id: str
    user_email: str | None
    user_display_name: str | None
    total_uploads: int
    total_downloads: int
    total_api_calls: int
    last_upload_at: datetime | None
    last_download_at: datetime | None
    last_api_at: datetime | None
    total_bytes_uploaded: int
    total_bytes_downloaded: int


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


async def _get_user_map(db: AsyncSession, user_ids: set[str]) -> dict[str, User]:
    """Fetch users by internal ID set."""
    if not user_ids:
        return {}
    rows = (
        await db.execute(select(User).where(User.id.in_(user_ids)))
    ).scalars().all()
    return {u.id: u for u in rows}


# ── Main activity feed ────────────────────────────────────────────────────────

@router.get("", response_model=ActivityResponse)
async def list_activity(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    # filters
    type: Literal["all", "upload", "download", "api"] = Query("all"),
    user_id: str | None = Query(None, description="Filter by internal user UUID"),
    q: str | None = Query(None, description="Search by email (partial match)"),
    date_from: str | None = Query(None, description="ISO datetime (inclusive)"),
    date_to: str | None = Query(None, description="ISO datetime (inclusive)"),
    # pagination
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
):
    """
    Trả về activity feed tổng hợp từ upload_logs, download_logs, token_access_logs.
    Chỉ admin.
    """
    _require_admin(current)

    dt_from = _parse_dt(date_from)
    dt_to = _parse_dt(date_to)
    offset = (page - 1) * limit

    # ── Resolve q (email search) to user_ids ─────────────────────────────────
    search_user_ids: set[str] | None = None
    if q:
        matched = (
            await db.execute(
                select(User.id).where(User.email.ilike(f"%{q}%"))
            )
        ).scalars().all()
        search_user_ids = set(matched)
        if not search_user_ids:
            return ActivityResponse(
                items=[], total=0, page=page, pages=0, has_next=False, has_prev=False
            )

    def _apply_user_filter(stmt: Any, col: Any) -> Any:
        if user_id:
            stmt = stmt.where(col == user_id)
        if search_user_ids is not None:
            stmt = stmt.where(col.in_(search_user_ids))
        return stmt

    def _apply_date_filter(stmt: Any, col: Any) -> Any:
        if dt_from:
            stmt = stmt.where(col >= dt_from)
        if dt_to:
            stmt = stmt.where(col <= dt_to)
        return stmt

    items: list[ActivityItem] = []
    total = 0

    # ── UPLOAD ───────────────────────────────────────────────────────────────
    if type in ("all", "upload"):
        base = select(UploadLog)
        base = _apply_user_filter(base, UploadLog.user_id)
        base = _apply_date_filter(base, UploadLog.created_at)

        count_q = select(func.count()).select_from(base.subquery())
        upload_total = (await db.execute(count_q)).scalar_one()

        if type == "upload":
            total = upload_total
            rows = (
                await db.execute(
                    base.order_by(UploadLog.created_at.desc()).offset(offset).limit(limit)
                )
            ).scalars().all()
            user_map = await _get_user_map(db, {r.user_id for r in rows if r.user_id})
            for r in rows:
                u = user_map.get(r.user_id) if r.user_id else None
                items.append(ActivityItem(
                    id=r.id,
                    type="upload",
                    user_id=r.user_id,
                    user_email=u.email if u else None,
                    user_display_name=u.display_name if u else None,
                    detail=r.original_filename,
                    ip_address=r.ip_address,
                    user_agent=r.user_agent,
                    status_code=None,
                    size_bytes=r.file_size_bytes,
                    created_at=r.created_at,
                ))
        else:
            # "all" – fetch all for merging (bounded by limit*2 for performance)
            upload_rows = (
                await db.execute(
                    base.order_by(UploadLog.created_at.desc()).limit(limit * 3)
                )
            ).scalars().all()
            user_map = await _get_user_map(db, {r.user_id for r in upload_rows if r.user_id})
            for r in upload_rows:
                u = user_map.get(r.user_id) if r.user_id else None
                items.append(ActivityItem(
                    id=r.id,
                    type="upload",
                    user_id=r.user_id,
                    user_email=u.email if u else None,
                    user_display_name=u.display_name if u else None,
                    detail=r.original_filename,
                    ip_address=r.ip_address,
                    user_agent=r.user_agent,
                    status_code=None,
                    size_bytes=r.file_size_bytes,
                    created_at=r.created_at,
                ))
            total += upload_total

    # ── DOWNLOAD ─────────────────────────────────────────────────────────────
    if type in ("all", "download"):
        base = select(DownloadLog)
        base = _apply_user_filter(base, DownloadLog.user_id)
        base = _apply_date_filter(base, DownloadLog.created_at)

        count_q = select(func.count()).select_from(base.subquery())
        dl_total = (await db.execute(count_q)).scalar_one()

        if type == "download":
            total = dl_total
            rows = (
                await db.execute(
                    base.order_by(DownloadLog.created_at.desc()).offset(offset).limit(limit)
                )
            ).scalars().all()
            user_map = await _get_user_map(db, {r.user_id for r in rows if r.user_id})
            for r in rows:
                u = user_map.get(r.user_id) if r.user_id else None
                items.append(ActivityItem(
                    id=r.id,
                    type="download",
                    user_id=r.user_id,
                    user_email=u.email if u else None,
                    user_display_name=u.display_name if u else None,
                    detail=r.original_filename,
                    ip_address=r.ip_address,
                    user_agent=r.user_agent,
                    status_code=None,
                    size_bytes=r.file_size_bytes,
                    created_at=r.created_at,
                ))
        else:
            dl_rows = (
                await db.execute(
                    base.order_by(DownloadLog.created_at.desc()).limit(limit * 3)
                )
            ).scalars().all()
            user_map = await _get_user_map(db, {r.user_id for r in dl_rows if r.user_id})
            for r in dl_rows:
                u = user_map.get(r.user_id) if r.user_id else None
                items.append(ActivityItem(
                    id=r.id,
                    type="download",
                    user_id=r.user_id,
                    user_email=u.email if u else None,
                    user_display_name=u.display_name if u else None,
                    detail=r.original_filename,
                    ip_address=r.ip_address,
                    user_agent=r.user_agent,
                    status_code=None,
                    size_bytes=r.file_size_bytes,
                    created_at=r.created_at,
                ))
            total += dl_total

    # ── API ACCESS ───────────────────────────────────────────────────────────
    if type == "api":
        base = select(TokenAccessLog)
        base = _apply_user_filter(base, TokenAccessLog.user_id)
        base = _apply_date_filter(base, TokenAccessLog.created_at)

        count_q = select(func.count()).select_from(base.subquery())
        total = (await db.execute(count_q)).scalar_one()

        rows = (
            await db.execute(
                base.order_by(TokenAccessLog.created_at.desc()).offset(offset).limit(limit)
            )
        ).scalars().all()
        user_map = await _get_user_map(db, {r.user_id for r in rows if r.user_id})
        for r in rows:
            u = user_map.get(r.user_id) if r.user_id else None
            method = r.http_method or ""
            endpoint = r.endpoint or ""
            items.append(ActivityItem(
                id=r.id,
                type="api",
                user_id=r.user_id,
                user_email=u.email if u else None,
                user_display_name=u.display_name if u else None,
                detail=f"{method} {endpoint}".strip(),
                ip_address=r.ip_address,
                user_agent=r.user_agent,
                status_code=r.status_code,
                size_bytes=None,
                created_at=r.created_at,
            ))

    # ── Merge + paginate for "all" ────────────────────────────────────────────
    if type == "all":
        items.sort(key=lambda x: x.created_at, reverse=True)
        items = items[offset: offset + limit]

    pages = max(1, (total + limit - 1) // limit) if total > 0 else 1

    audit.log_event(
        "admin.activity.list",
        user_id=current.id,
        role=current.role,
        type=type,
        page=page,
        request_id=audit.get_request_id(request),
        ip=audit.get_ip(request),
    )

    return ActivityResponse(
        items=items,
        total=total,
        page=page,
        pages=pages,
        has_next=page < pages,
        has_prev=page > 1,
    )


# ── Per-user summary ──────────────────────────────────────────────────────────

@router.get("/users/{user_id}/summary", response_model=UserActivitySummary)
async def get_user_activity_summary(
    user_id: str,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Tổng hợp hoạt động của một user cụ thể. Chỉ admin."""
    _require_admin(current)

    user = (
        await db.execute(select(User).where(User.id == user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    # Upload stats
    upload_count = (
        await db.execute(
            select(func.count()).where(UploadLog.user_id == user_id)
        )
    ).scalar_one()
    upload_bytes = (
        await db.execute(
            select(func.coalesce(func.sum(UploadLog.file_size_bytes), 0)).where(
                UploadLog.user_id == user_id
            )
        )
    ).scalar_one()
    last_upload = (
        await db.execute(
            select(func.max(UploadLog.created_at)).where(UploadLog.user_id == user_id)
        )
    ).scalar_one()

    # Download stats
    download_count = (
        await db.execute(
            select(func.count()).where(DownloadLog.user_id == user_id)
        )
    ).scalar_one()
    download_bytes = (
        await db.execute(
            select(func.coalesce(func.sum(DownloadLog.file_size_bytes), 0)).where(
                DownloadLog.user_id == user_id
            )
        )
    ).scalar_one()
    last_download = (
        await db.execute(
            select(func.max(DownloadLog.created_at)).where(DownloadLog.user_id == user_id)
        )
    ).scalar_one()

    # API call stats
    api_count = (
        await db.execute(
            select(func.count()).where(TokenAccessLog.user_id == user_id)
        )
    ).scalar_one()
    last_api = (
        await db.execute(
            select(func.max(TokenAccessLog.created_at)).where(
                TokenAccessLog.user_id == user_id
            )
        )
    ).scalar_one()

    audit.log_event(
        "admin.activity.user_summary",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        request_id=audit.get_request_id(request),
        ip=audit.get_ip(request),
    )

    return UserActivitySummary(
        user_id=user.id,
        user_email=user.email,
        user_display_name=user.display_name,
        total_uploads=upload_count,
        total_downloads=download_count,
        total_api_calls=api_count,
        last_upload_at=last_upload,
        last_download_at=last_download,
        last_api_at=last_api,
        total_bytes_uploaded=upload_bytes or 0,
        total_bytes_downloaded=download_bytes or 0,
    )
