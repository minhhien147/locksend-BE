"""
LockSend AI — cảnh báo realtime sau khi token được dùng + dữ liệu trend.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.dependencies import get_db_context
from db.models import TokenAccessLog, TokenAiScoreSnapshot, TokenSecurityAlert
from services import locksend_ai, token_security

logger = logging.getLogger(__name__)

# Mặc định tắt — mỗi request JWT gọi ML tốn RAM/CPU (đặc biệt trên Railway).
REALTIME_ENABLED = os.getenv("LOCKSEND_AI_REALTIME_ENABLED", "false").lower() in (
    "1",
    "true",
    "yes",
)
MIN_RULE_SCORE = int(os.getenv("LOCKSEND_AI_REALTIME_MIN_RULE", "20"))
MIN_AI_ALERT_PCT = int(os.getenv("LOCKSEND_AI_REALTIME_MIN_AI", "50"))
DEBOUNCE_SEC = int(os.getenv("LOCKSEND_AI_REALTIME_DEBOUNCE", "300"))
ALERT_COOLDOWN_SEC = int(os.getenv("LOCKSEND_AI_ALERT_COOLDOWN", "900"))

_last_scan_at: dict[str, float] = {}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _debounce_key(token_type: str, user_id: str | None, token_ref: str) -> str:
    return f"{token_type}:{user_id or token_ref}"


def _is_debounced(key: str) -> bool:
    last = _last_scan_at.get(key, 0.0)
    return (time.monotonic() - last) < DEBOUNCE_SEC


def _touch_debounce(key: str) -> None:
    _last_scan_at[key] = time.monotonic()


def schedule_token_access_scan(
    *,
    token_type: str,
    token_ref: str,
    user_id: str | None,
    endpoint: str | None,
    ip_address: str | None,
) -> None:
    """Fire-and-forget — không chặn HTTP response."""
    if not REALTIME_ENABLED:
        return
    asyncio.create_task(
        _run_scan_safe(
            token_type=token_type,
            token_ref=token_ref,
            user_id=user_id,
            endpoint=endpoint,
            ip_address=ip_address,
        )
    )


async def _run_scan_safe(**kwargs: Any) -> None:
    try:
        async with get_db_context() as db:
            await process_token_access(db, **kwargs)
    except Exception as exc:
        logger.warning("AI realtime scan failed: %s", exc)


async def _resolve_metric(
    db: AsyncSession,
    token_type: str,
    user_id: str | None,
    token_ref: str,
) -> dict[str, Any] | None:
    if token_type == "jwt" and user_id:
        rows = await token_security.get_jwt_token_metrics(db, user_id=user_id)
        return rows[0] if rows else None
    if token_type == "sas":
        rows = await token_security.get_sas_token_metrics(db, include_expired=True)
        return next((m for m in rows if m.get("token_id") == token_ref), None)
    return None


def _should_run_ai(metric: dict[str, Any]) -> bool:
    """Debounce (DEBOUNCE_SEC) là rào chính; ưu tiên khi rule/rate cao."""
    if not metric:
        return False
    rule_score = int(metric.get("risk_score") or 0)
    rate = float(metric.get("accesses_per_hour") or metric.get("downloads_per_hour") or 0)
    if rule_score >= MIN_RULE_SCORE or rate >= 1:
        return True
    return os.getenv("LOCKSEND_AI_REALTIME_SCAN_ALL", "false").lower() in ("1", "true", "yes")


def _should_alert(result: dict[str, Any]) -> bool:
    pct = int(result.get("risk_score_pct") or 0)
    if pct >= MIN_AI_ALERT_PCT:
        return True
    if result.get("decision") == "REVOKE":
        return True
    agreement = result.get("agreement") or {}
    if agreement.get("status") == "disagree" and pct >= 40:
        return True
    return False


async def process_token_access(
    db: AsyncSession,
    *,
    token_type: str,
    token_ref: str,
    user_id: str | None,
    endpoint: str | None,
    ip_address: str | None,
) -> None:
    key = _debounce_key(token_type, user_id, token_ref)
    if _is_debounced(key):
        return

    health = await locksend_ai.health()
    if not health.get("ready"):
        return

    metric = await _resolve_metric(db, token_type, user_id, token_ref)
    if not metric or not _should_run_ai(metric):
        return

    _touch_debounce(key)

    try:
        result = await locksend_ai.analyze_token(metric)
    except Exception as exc:
        logger.info("AI realtime analyze skipped: %s", exc)
        return

    await _save_snapshot(db, metric, result, source="realtime")

    if not _should_alert(result):
        return

    if await _recent_alert_exists(db, token_ref):
        return

    badges = result.get("behavior_badges") or []
    file_id = metric.get("file_id") if token_type == "sas" else None
    file_name = (
        (metric.get("blob_name") or metric.get("original_filename"))
        if token_type == "sas"
        else None
    )
    alert = TokenSecurityAlert(
        token_type=token_type,
        token_ref=token_ref,
        user_id=user_id,
        file_id=file_id,
        file_name=file_name,
        subject_label=metric.get("email") or metric.get("blob_name") or token_ref[:16],
        rule_score=int(result.get("rule_score") or metric.get("risk_score") or 0),
        ai_score_pct=int(result.get("risk_score_pct") or 0),
        ai_level=str(result.get("ai_level_raw") or result.get("risk_level") or ""),
        decision=str(result.get("decision") or "MONITOR"),
        agreement_status=(result.get("agreement") or {}).get("status"),
        behavior_badges=json.dumps(badges, ensure_ascii=False) if badges else None,
        summary_vi=result.get("summary_vi"),
        endpoint=endpoint,
        ip_address=ip_address,
    )
    db.add(alert)


async def _save_snapshot(
    db: AsyncSession,
    metric: dict[str, Any],
    result: dict[str, Any],
    *,
    source: str,
) -> None:
    db.add(_build_snapshot_obj(metric, result, source=source))


async def save_manual_snapshot(
    db: AsyncSession,
    metric: dict[str, Any],
    result: dict[str, Any],
) -> None:
    await _save_snapshot(db, metric, result, source="manual")


async def bulk_save_manual_snapshots(
    db: AsyncSession,
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> int:
    """
    Bulk save AI snapshots thay vì từng dòng — giảm round-trip DB.
    Trả về số lượng record đã được add (commit ở caller).
    """
    if not pairs:
        return 0
    batch: list[TokenAiScoreSnapshot] = []
    for metric, result in pairs:
        batch.append(_build_snapshot_obj(metric, result, source="bulk_manual"))
    db.add_all(batch)
    await db.flush()
    return len(batch)


INCREMENTAL_WINDOW_SEC = int(os.getenv("LOCKSEND_AI_INCREMENTAL_WINDOW", "1800"))  # mặc định 30 phút


async def find_recently_analyzed_token_refs(
    db: AsyncSession,
    *,
    token_refs: list[str],
) -> set[str]:
    """
    Trả về set các token_ref đã có snapshot trong INCREMENTAL_WINDOW_SEC.
    Dùng cho incremental analysis (bỏ qua token đã được phân tích gần đây).
    """
    if not token_refs:
        return set()
    cutoff = _utc_now() - timedelta(seconds=INCREMENTAL_WINDOW_SEC)
    q = (
        select(TokenAiScoreSnapshot.token_ref)
        .where(
            TokenAiScoreSnapshot.token_ref.in_(token_refs),
            TokenAiScoreSnapshot.created_at >= cutoff,
        )
        .distinct()
    )
    rows = (await db.execute(q)).scalars().all()
    return set(rows)


def _build_snapshot_obj(
    metric: dict[str, Any],
    result: dict[str, Any],
    *,
    source: str,
) -> TokenAiScoreSnapshot:
    """Helper tạo Snapshot ORM object (không add vào session)."""
    import uuid as _uuid_mod
    token_ref = (
        str(metric.get("token_id"))
        or str(metric.get("user_id"))
        or f"unknown:{_uuid_mod.uuid4().hex[:8]}"
    )
    user_id = metric.get("user_id")
    if isinstance(user_id, str) and len(user_id) > 36:
        user_id = user_id[:36]
    rule_score_raw = int(metric.get("risk_score") or 0)
    return TokenAiScoreSnapshot(
        id=str(_uuid_mod.uuid4()),
        token_type=str(metric.get("token_type") or "unknown"),
        token_ref=token_ref,
        user_id=user_id,
        rule_score=rule_score_raw,
        ai_score_pct=int(result.get("risk_score_pct") or 0),
        ai_level=str(result.get("ai_level_raw") or ""),
        decision=str(result.get("decision") or "MONITOR"),
        source=source,
    )


async def _save_snapshot(
    db: AsyncSession,
    metric: dict[str, Any],
    result: dict[str, Any],
    *,
    source: str,
) -> None:
    db.add(_build_snapshot_obj(metric, result, source=source))
    await db.flush()


async def _recent_alert_exists(db: AsyncSession, token_ref: str) -> bool:
    cutoff = _utc_now() - timedelta(seconds=ALERT_COOLDOWN_SEC)
    row = (
        await db.execute(
            select(TokenSecurityAlert.id)
            .where(
                TokenSecurityAlert.token_ref == token_ref,
                TokenSecurityAlert.created_at >= cutoff,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    return row is not None


def _alert_to_dict(row: TokenSecurityAlert) -> dict[str, Any]:
    badges: list[dict[str, str]] = []
    if row.behavior_badges:
        try:
            badges = json.loads(row.behavior_badges)
        except json.JSONDecodeError:
            pass
    return {
        "id": row.id,
        "token_type": row.token_type,
        "token_ref": row.token_ref,
        "user_id": row.user_id,
        "file_id": row.file_id,
        "file_name": row.file_name,
        "subject_label": row.subject_label,
        "rule_score": row.rule_score,
        "ai_score_pct": row.ai_score_pct,
        "ai_level": row.ai_level,
        "decision": row.decision,
        "agreement_status": row.agreement_status,
        "behavior_badges": badges,
        "summary_vi": row.summary_vi,
        "endpoint": row.endpoint,
        "ip_address": row.ip_address,
        "is_read": row.is_read,
        "created_at": row.created_at.isoformat(),
    }


async def list_alerts(
    db: AsyncSession,
    *,
    unread_only: bool = False,
    limit: int = 30,
) -> list[dict[str, Any]]:
    q = select(TokenSecurityAlert).order_by(TokenSecurityAlert.created_at.desc()).limit(limit)
    if unread_only:
        q = q.where(TokenSecurityAlert.is_read.is_(False))
    rows = (await db.execute(q)).scalars().all()
    return [_alert_to_dict(r) for r in rows]


async def unread_alert_count(db: AsyncSession) -> int:
    return int(
        (
            await db.execute(
                select(func.count(TokenSecurityAlert.id)).where(
                    TokenSecurityAlert.is_read.is_(False)
                )
            )
        ).scalar()
        or 0
    )


async def mark_alert_read(db: AsyncSession, alert_id: str) -> bool:
    row = (
        await db.execute(
            select(TokenSecurityAlert).where(TokenSecurityAlert.id == alert_id)
        )
    ).scalar_one_or_none()
    if not row:
        return False
    row.is_read = True
    return True


async def mark_all_alerts_read(db: AsyncSession) -> int:
    rows = (
        await db.execute(select(TokenSecurityAlert).where(TokenSecurityAlert.is_read.is_(False)))
    ).scalars().all()
    for r in rows:
        r.is_read = True
    return len(rows)


def _day_key(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _fill_days(days: int) -> list[str]:
    today = _utc_now().date()
    return [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]


def _bucket_datetimes(day_labels: list[str], timestamps: list[datetime]) -> dict[str, int]:
    out = {d: 0 for d in day_labels}
    for dt in timestamps:
        if dt is None:
            continue
        key = _day_key(dt)
        if key in out:
            out[key] += 1
    return out


async def build_trends(db: AsyncSession, days: int = 7) -> dict[str, Any]:
    days = max(1, min(days, 30))
    since = _utc_now() - timedelta(days=days)
    day_labels = _fill_days(days)

    access_ts = (
        await db.execute(
            select(TokenAccessLog.created_at).where(TokenAccessLog.created_at >= since)
        )
    ).scalars().all()

    alert_rows = (
        await db.execute(
            select(TokenSecurityAlert.created_at, TokenSecurityAlert.agreement_status).where(
                TokenSecurityAlert.created_at >= since
            )
        )
    ).all()

    snapshot_ts = (
        await db.execute(
            select(TokenAiScoreSnapshot.created_at).where(
                TokenAiScoreSnapshot.created_at >= since,
                TokenAiScoreSnapshot.ai_score_pct >= MIN_AI_ALERT_PCT,
            )
        )
    ).scalars().all()

    access_b = _bucket_datetimes(day_labels, list(access_ts))
    alert_b = _bucket_datetimes(day_labels, [r[0] for r in alert_rows])
    high_ai_b = _bucket_datetimes(day_labels, list(snapshot_ts))
    disagree_b = _bucket_datetimes(
        day_labels,
        [r[0] for r in alert_rows if r[1] == "disagree"],
    )

    return {
        "days": days,
        "labels": day_labels,
        "access_events": [access_b[d] for d in day_labels],
        "ai_alerts": [alert_b[d] for d in day_labels],
        "ai_high_scores": [high_ai_b[d] for d in day_labels],
        "rule_ai_disagree": [disagree_b[d] for d in day_labels],
        "totals": {
            "access_events": sum(access_b.values()),
            "ai_alerts": sum(alert_b.values()),
            "ai_high_scores": sum(high_ai_b.values()),
            "rule_ai_disagree": sum(disagree_b.values()),
        },
    }
