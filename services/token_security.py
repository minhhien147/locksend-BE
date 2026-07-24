"""
Token Security Management — rule engine + data collector.

Pipeline:
  1. build_security_snapshot() → tổng hợp JWT + SAS metrics từ DB
  2. score_token()             → rule engine cho risk score 0-100
  3. auto_revoke / manual revoke theo recommendation

Nguyên tắc bảo mật:
  - Không lưu giá trị JWT/SAS token.
  - jti được mask; SAS được tham chiếu qua token_id UUID.
  - snapshot chỉ chứa metrics, không chứa secret (sẵn sàng cho AI tích hợp sau).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from db.models import RefreshToken, SasTokenRecord, TokenAccessLog, User

TokenType = Literal["jwt", "sas"]
RiskLevel = Literal["low", "medium", "high", "critical"]
Recommendation = Literal["ALLOW", "MONITOR", "REVOKE"]

# Ngưỡng cấu hình (TOKEN_SECURITY_* hoặc legacy AI_*)
def _env_int(name: str, legacy: str, default: str) -> int:
    return int(os.getenv(name, os.getenv(legacy, default)))


JWT_ACTIVE_SESSION_THRESHOLD = _env_int("TOKEN_SECURITY_JWT_MAX_SESSIONS", "AI_JWT_MAX_SESSIONS", "5")
JWT_MULTI_IP_THRESHOLD = _env_int("TOKEN_SECURITY_JWT_MAX_IPS", "AI_JWT_MAX_IPS", "3")
SAS_MULTI_IP_THRESHOLD = _env_int("TOKEN_SECURITY_SAS_MAX_IPS", "AI_SAS_MAX_IPS", "3")
SAS_DOWNLOAD_RATE_THRESHOLD = _env_int(
    "TOKEN_SECURITY_SAS_MAX_ACCESSES_PER_HOUR", "AI_SAS_MAX_ACCESSES_PER_HOUR", "30"
)
SAS_MAX_AGE_HOURS = _env_int("TOKEN_SECURITY_SAS_MAX_AGE_HOURS", "AI_SAS_MAX_AGE_HOURS", "48")
RISK_AUTO_REVOKE_THRESHOLD = _env_int("TOKEN_SECURITY_AUTO_REVOKE_SCORE", "AI_AUTO_REVOKE_SCORE", "80")

ACCESS_LOG_RETENTION_DAYS = _env_int("TOKEN_ACCESS_LOG_RETENTION_DAYS", "AI_ACCESS_LOG_RETENTION_DAYS", "14")
SAS_RECORD_RETENTION_DAYS = _env_int("TOKEN_SAS_RECORD_RETENTION_DAYS", "AI_SAS_RECORD_RETENTION_DAYS", "30")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _mask_ref(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def _hours_since(dt: datetime) -> float:
    return (_utc_now() - _aware(dt)).total_seconds() / 3600


def _risk_level(score: int) -> RiskLevel:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _recommendation(score: int) -> Recommendation:
    if score >= RISK_AUTO_REVOKE_THRESHOLD:
        return "REVOKE"
    if score >= 40:
        return "MONITOR"
    return "ALLOW"


# ── JWT (Refresh Token) Analysis ───────────────────────────────────────────────

def _score_jwt(
    active_count: int,
    unique_ips: int,
    access_per_hour: float,
    reuse_detected: bool,
    mass_revoke_detected: bool,
    token_age_hours: float,
    refresh_ttl_days: int,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if active_count > JWT_ACTIVE_SESSION_THRESHOLD:
        score += 30
        reasons.append(f"Too many active sessions ({active_count} > {JWT_ACTIVE_SESSION_THRESHOLD})")
    elif active_count > 3:
        score += 15
        reasons.append(f"Elevated active sessions ({active_count})")

    if unique_ips >= JWT_MULTI_IP_THRESHOLD:
        score += 35
        reasons.append(f"Multiple IP addresses ({unique_ips} distinct IPs)")
    elif unique_ips == 2:
        score += 15
        reasons.append("Dual IP usage detected")

    if access_per_hour > 20:
        score += 20
        reasons.append(f"High request frequency ({access_per_hour:.1f}/hr)")

    if reuse_detected:
        score += 50
        reasons.append("Refresh token reuse attack pattern detected")

    if mass_revoke_detected:
        score += 30
        reasons.append("Mass session revocation detected recently")

    age_ratio = token_age_hours / max(refresh_ttl_days * 24, 1)
    if age_ratio > 0.95:
        score += 15
        reasons.append("Token lifetime nearly exhausted")

    return min(score, 100), reasons


# ── SAS Token Analysis ─────────────────────────────────────────────────────────

def _score_sas(
    ip_count: int,
    access_count: int,
    token_age_hours: float,
    downloads_per_hour: float,
    is_expired: bool,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if ip_count >= SAS_MULTI_IP_THRESHOLD:
        score += 35
        reasons.append(f"SAS token accessed from {ip_count} different IPs")
    elif ip_count == 2:
        score += 15
        reasons.append("SAS accessed from 2 IPs")

    if downloads_per_hour > SAS_DOWNLOAD_RATE_THRESHOLD:
        score += 35
        reasons.append(f"Abnormal download rate ({downloads_per_hour:.1f}/hr)")
    elif downloads_per_hour > 10:
        score += 15
        reasons.append(f"Elevated access frequency ({downloads_per_hour:.1f}/hr)")

    if token_age_hours > SAS_MAX_AGE_HOURS:
        score += 20
        reasons.append(f"Token lifetime exceeded threshold ({token_age_hours:.0f}h > {SAS_MAX_AGE_HOURS}h)")

    if access_count > 100:
        score += 15
        reasons.append(f"High total access count ({access_count})")

    if is_expired:
        score += 10
        reasons.append("Token already expired (still in access logs)")

    return min(score, 100), reasons


# ── DB Queries ─────────────────────────────────────────────────────────────────

async def get_jwt_token_metrics(
    db: AsyncSession,
    user_id: str | None = None,
    window_hours: int = 24,
) -> list[dict[str, Any]]:
    """Tổng hợp metrics JWT (refresh token) theo user."""
    now = _utc_now()
    window_start = now - timedelta(hours=window_hours)
    refresh_ttl_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

    q = select(RefreshToken).options(selectinload(RefreshToken.user))
    if user_id:
        q = q.where(RefreshToken.user_id == user_id)
    tokens = (await db.execute(q)).scalars().all()

    by_user: dict[str, list[RefreshToken]] = {}
    for rt in tokens:
        by_user.setdefault(rt.user_id, []).append(rt)

    results = []
    for uid, user_tokens in by_user.items():
        active = [
            t for t in user_tokens
            if t.revoked_at is None
            and t.replaced_by_jti is None
            and _aware(t.expires_at) > now
        ]
        all_ips = {t.ip_address for t in user_tokens if t.ip_address}
        active_ips = {t.ip_address for t in active if t.ip_address}

        reuse_detected = any(
            t.revoked_at is not None
            and t.replaced_by_jti is not None
            and _aware(t.revoked_at) >= window_start
            for t in user_tokens
        )

        recent_revoked = [
            t for t in user_tokens
            if t.revoked_at and _aware(t.revoked_at) >= window_start
        ]
        mass_revoke = False
        if len(recent_revoked) >= 3:
            times = sorted(_aware(t.revoked_at) for t in recent_revoked if t.revoked_at)
            if times and (times[-1] - times[0]).total_seconds() < 120:
                mass_revoke = True

        # Access log per-hour count from TokenAccessLog
        log_count_result = await db.execute(
            select(func.count(TokenAccessLog.id)).where(
                TokenAccessLog.user_id == uid,
                TokenAccessLog.token_type == "jwt",
                TokenAccessLog.created_at >= window_start,
            )
        )
        log_count = log_count_result.scalar() or 0
        accesses_per_hour = log_count / max(window_hours, 1)

        oldest_active = min(
            (_aware(t.created_at) for t in active),
            default=now,
        )
        token_age_hours = _hours_since(oldest_active)

        score, reasons = _score_jwt(
            active_count=len(active),
            unique_ips=len(active_ips),
            access_per_hour=accesses_per_hour,
            reuse_detected=reuse_detected,
            mass_revoke_detected=mass_revoke,
            token_age_hours=token_age_hours,
            refresh_ttl_days=refresh_ttl_days,
        )

        u = user_tokens[0].user
        results.append({
            "token_id": f"jwt:{uid[:8]}",
            "token_type": "jwt",
            "user_id": uid,
            "email": u.email if u else None,
            "role": u.role if u else None,
            "active_sessions": len(active),
            "total_sessions": len(user_tokens),
            "ip_count": len(active_ips),
            "all_ip_count": len(all_ips),
            "accesses_per_hour": round(accesses_per_hour, 2),
            "token_age_hours": round(token_age_hours, 1),
            "reuse_detected": reuse_detected,
            "mass_revoke_detected": mass_revoke,
            "risk_score": score,
            "risk_level": _risk_level(score),
            "recommendation": _recommendation(score),
            "reasons": reasons,
            "refresh_ttl_days": refresh_ttl_days,
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


async def get_sas_token_metrics(
    db: AsyncSession,
    *,
    limit: int = 100,
    include_expired: bool = False,
    include_revoked: bool = True,
) -> list[dict[str, Any]]:
    """Metrics các SAS token đã cấp."""
    now = _utc_now()
    q = select(SasTokenRecord).order_by(SasTokenRecord.created_at.desc()).limit(limit)
    if not include_expired:
        q = q.where(SasTokenRecord.expires_at > now)
    if not include_revoked:
        q = q.where(SasTokenRecord.is_revoked.is_(False))

    records = (await db.execute(q)).scalars().all()
    results = []

    for rec in records:
        token_age_hours = _hours_since(rec.created_at)
        is_expired = _aware(rec.expires_at) <= now

        # Tính download rate từ access logs
        window_start = now - timedelta(hours=1)
        rate_result = await db.execute(
            select(func.count(TokenAccessLog.id)).where(
                TokenAccessLog.token_ref == rec.token_id,
                TokenAccessLog.created_at >= window_start,
            )
        )
        accesses_last_hour = rate_result.scalar() or 0

        score, reasons = _score_sas(
            ip_count=rec.unique_ip_count,
            access_count=rec.access_count,
            token_age_hours=token_age_hours,
            downloads_per_hour=float(accesses_last_hour),
            is_expired=is_expired,
        )

        results.append({
            "token_id": rec.token_id,
            "token_type": "sas",
            "db_id": rec.id,
            "file_id": rec.file_id,
            "blob_name": rec.blob_name,
            "user_id": rec.user_id,
            "ip_address": rec.ip_address,
            "ip_count": rec.unique_ip_count,
            "access_count": rec.access_count,
            "downloads_per_hour": accesses_last_hour,
            "token_age_hours": round(token_age_hours, 1),
            "expires_at": _aware(rec.expires_at).isoformat(),
            "is_expired": is_expired,
            "is_revoked": rec.is_revoked,
            "last_accessed_at": _aware(rec.last_accessed_at).isoformat() if rec.last_accessed_at else None,
            "risk_score": rec.ai_risk_score if rec.ai_risk_score is not None else score,
            "risk_level": rec.ai_risk_level or _risk_level(score),
            "recommendation": rec.ai_recommendation or _recommendation(score),
            "reasons": reasons,
            "created_at": _aware(rec.created_at).isoformat(),
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


_overview_cache: dict[tuple[int, int], tuple[float, dict[str, Any]]] = {}
_overview_lock = asyncio.Lock()
OVERVIEW_TTL_SEC = 15.0


async def build_overview(
    db: AsyncSession,
    *,
    include_top_risk: bool = False,
    skip_cache: bool = False,
) -> dict[str, Any]:
    """
    Dashboard stats cho admin (tối ưu hiệu năng).
    - JWT/SAS counts dùng SERVER-SIDE COUNT (SQL) thay vì fetch all rows.
    - Top risk tokens bỏ qua (lazy load riêng qua API /overview/top-risk).
    - Cache TTL 15s để tránh làm nặng DB khi mở dashboard liên tục.
    """
    import time as _time

    now = _utc_now()
    cache_key: tuple[int, int] = (
        int(include_top_risk),
        int(skip_cache),
    )

    if not skip_cache and cache_key in _overview_cache:
        ts, cached = _overview_cache[cache_key]
        if _time.monotonic() - ts < OVERVIEW_TTL_SEC:
            return cached

    async with _overview_lock:
        if not skip_cache and cache_key in _overview_cache:
            ts, cached = _overview_cache[cache_key]
            if _time.monotonic() - ts < OVERVIEW_TTL_SEC:
                return cached

        refresh_ttl_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

        # ── JWT counts (server-side COUNT) ──────────────────────────
        all_rt_count = (await db.execute(
            select(func.count(RefreshToken.id))
        )).scalar() or 0

        jwt_active = (await db.execute(
            select(func.count(RefreshToken.id)).where(
                RefreshToken.revoked_at.is_(None),
                RefreshToken.replaced_by_jti.is_(None),
                RefreshToken.expires_at > now,
            )
        )).scalar() or 0
        jwt_revoked = (await db.execute(
            select(func.count(RefreshToken.id)).where(
                RefreshToken.revoked_at.is_not(None)
            )
        )).scalar() or 0
        jwt_expired = (await db.execute(
            select(func.count(RefreshToken.id)).where(
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at <= now,
            )
        )).scalar() or 0

        # ── SAS counts (server-side COUNT) ──────────────────────────
        all_sas_count = (await db.execute(
            select(func.count(SasTokenRecord.id))
        )).scalar() or 0

        sas_active = (await db.execute(
            select(func.count(SasTokenRecord.id)).where(
                SasTokenRecord.is_revoked.is_(False),
                SasTokenRecord.expires_at > now,
            )
        )).scalar() or 0
        sas_revoked = (await db.execute(
            select(func.count(SasTokenRecord.id)).where(
                SasTokenRecord.is_revoked.is_(True)
            )
        )).scalar() or 0
        sas_expired = (await db.execute(
            select(func.count(SasTokenRecord.id)).where(
                SasTokenRecord.is_revoked.is_(False),
                SasTokenRecord.expires_at <= now,
            )
        )).scalar() or 0

        # ── Risk counts + access events (server-side COUNTs) ────────
        # Cache full metrics để tính risk counts (không tránh được vì cần rule engine logic)
        jwt_metrics: list[dict[str, Any]] = []
        sas_metrics: list[dict[str, Any]] = []

        if include_top_risk:
            jwt_metrics = await get_jwt_token_metrics(db)
            sas_metrics = await get_sas_token_metrics(db, include_expired=True)

        high_risk_count = (
            sum(1 for m in (jwt_metrics + sas_metrics) if m["risk_score"] >= 50)
            if include_top_risk else 0
        )
        critical_count = (
            sum(1 for m in (jwt_metrics + sas_metrics) if m["risk_score"] >= 75)
            if include_top_risk else 0
        )
        auto_revoke_candidates = (
            sum(
                1 for m in (jwt_metrics + sas_metrics)
                if m["recommendation"] == "REVOKE" and not m.get("is_revoked")
            ) if include_top_risk else 0
        )

        window_24h = now - timedelta(hours=24)
        access_events_24h = (await db.execute(
            select(func.count(TokenAccessLog.id)).where(
                TokenAccessLog.created_at >= window_24h
            )
        )).scalar() or 0

        result: dict[str, Any] = {
            "generated_at": now.isoformat(),
            "jwt": {
                "active": jwt_active,
                "revoked": jwt_revoked,
                "expired": jwt_expired,
                "total": all_rt_count,
            },
            "sas": {
                "active": sas_active,
                "revoked": sas_revoked,
                "expired": sas_expired,
                "total": all_sas_count,
            },
            "risk_summary": {
                "high_risk_tokens": high_risk_count,
                "critical_tokens": critical_count,
                "auto_revoke_candidates": auto_revoke_candidates,
                "access_events_24h": access_events_24h,
            },
            "config": {
                "access_token_ttl_minutes": int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
                "refresh_token_ttl_days": refresh_ttl_days,
                "auto_revoke_score_threshold": RISK_AUTO_REVOKE_THRESHOLD,
            },
        }
        if include_top_risk:
            result["top_risk_tokens"] = (jwt_metrics + sas_metrics)[:10]

        _overview_cache[cache_key] = (_time.monotonic(), result)
        return result


async def get_high_risk_tokens(db: AsyncSession, *, limit: int = 15) -> list[dict[str, Any]]:
    """Lấy top-N tokens có risk_score cao nhất (sau khi overview skeleton render)."""
    jwt_metrics = await get_jwt_token_metrics(db)
    sas_metrics = await get_sas_token_metrics(db, include_expired=True)
    combined = jwt_metrics + sas_metrics
    combined.sort(key=lambda x: x["risk_score"], reverse=True)
    return combined[:limit]


async def build_security_snapshot(
    db: AsyncSession,
    *,
    token_type: str = "all",
    target_id: str | None = None,
) -> dict[str, Any]:
    """
    Snapshot không chứa secret — metrics cho rule engine / AI tích hợp sau.
    target_id: user_id cho jwt, token_id cho sas, None = toàn hệ thống.
    """
    jwt_metrics = await get_jwt_token_metrics(db, user_id=target_id if token_type in ("jwt", "all") else None)
    sas_metrics = await get_sas_token_metrics(db, include_expired=True)

    if token_type == "sas" and target_id:
        sas_metrics = [m for m in sas_metrics if m["token_id"] == target_id]
    elif token_type == "jwt":
        sas_metrics = []

    # Lấy các access logs gần đây (không chứa giá trị token)
    recent_logs_q = (
        select(TokenAccessLog)
        .order_by(TokenAccessLog.created_at.desc())
        .limit(50)
    )
    if target_id and token_type == "jwt":
        recent_logs_q = recent_logs_q.where(TokenAccessLog.user_id == target_id)
    elif target_id and token_type == "sas":
        recent_logs_q = recent_logs_q.where(TokenAccessLog.token_ref == target_id)

    recent_logs = (await db.execute(recent_logs_q)).scalars().all()
    log_samples = [
        {
            "type": l.token_type,
            "ip": l.ip_address,
            "endpoint": l.endpoint,
            "method": l.http_method,
            "status": l.status_code,
            "at": _aware(l.created_at).isoformat(),
        }
        for l in recent_logs
    ]

    all_tokens = (jwt_metrics + sas_metrics)[:30]
    return {
        "product": "LockSend Secure File Sharing",
        "analysis_scope": token_type,
        "target_id": target_id,
        "token_metrics": all_tokens,
        "recent_access_log_sample": log_samples,
        "thresholds": {
            "jwt_max_sessions": JWT_ACTIVE_SESSION_THRESHOLD,
            "jwt_max_ips": JWT_MULTI_IP_THRESHOLD,
            "sas_max_ips": SAS_MULTI_IP_THRESHOLD,
            "sas_max_age_hours": SAS_MAX_AGE_HOURS,
            "auto_revoke_score": RISK_AUTO_REVOKE_THRESHOLD,
        },
        "privacy_note": "No JWT values, cookies, or private keys included",
    }


# ── Actions ────────────────────────────────────────────────────────────────────

async def revoke_jwt_sessions(db: AsyncSession, user_id: str, reason: str = "Token security") -> int:
    """Thu hồi toàn bộ refresh session active của user."""
    now = _utc_now()
    tokens = (
        await db.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.replaced_by_jti.is_(None),
            )
        )
    ).scalars().all()
    count = 0
    for rt in tokens:
        if _aware(rt.expires_at) > now:
            rt.revoked_at = now
            count += 1
    return count


async def revoke_sas_token(db: AsyncSession, token_id: str, reason: str = "Token security") -> bool:
    """Soft-revoke một SAS token — ngăn cấp lại SAS cho blob này."""
    result = await db.execute(
        select(SasTokenRecord).where(SasTokenRecord.token_id == token_id)
    )
    rec = result.scalar_one_or_none()
    if not rec or rec.is_revoked:
        return False
    rec.is_revoked = True
    rec.revoked_at = _utc_now()
    rec.revoke_reason = reason
    return True


async def cleanup_expired_tokens(
    db: AsyncSession,
    *,
    access_log_retention_days: int | None = None,
    sas_retention_days: int | None = None,
) -> dict[str, int]:
    """Xóa SAS records và access logs cũ để giảm DB bloat (bulk DELETE)."""
    now = _utc_now()
    log_days = (
        access_log_retention_days
        if access_log_retention_days is not None
        else ACCESS_LOG_RETENTION_DAYS
    )
    sas_days = (
        sas_retention_days
        if sas_retention_days is not None
        else SAS_RECORD_RETENTION_DAYS
    )
    cutoff_sas = now - timedelta(days=sas_days)
    cutoff_logs = now - timedelta(days=log_days)

    sas_result = await db.execute(
        delete(SasTokenRecord).where(SasTokenRecord.expires_at < cutoff_sas)
    )
    log_result = await db.execute(
        delete(TokenAccessLog).where(TokenAccessLog.created_at < cutoff_logs)
    )

    return {
        "deleted_sas_records": sas_result.rowcount or 0,
        "deleted_access_logs": log_result.rowcount or 0,
    }


async def auto_revoke_high_risk(db: AsyncSession) -> dict[str, Any]:
    """
    Tự động revoke các token có risk score >= threshold (rule engine only).
    Chạy theo lịch hoặc khi admin trigger.
    """
    jwt_metrics = await get_jwt_token_metrics(db)
    sas_metrics = await get_sas_token_metrics(db)

    revoked_jwt = 0
    revoked_sas = 0
    acted_on = []

    for m in jwt_metrics:
        if m["risk_score"] >= RISK_AUTO_REVOKE_THRESHOLD and m["recommendation"] == "REVOKE":
            n = await revoke_jwt_sessions(db, m["user_id"], reason="auto-revoke: rule engine")
            revoked_jwt += n
            acted_on.append({"type": "jwt", "user_id": m["user_id"], "score": m["risk_score"]})

    for m in sas_metrics:
        if (
            m["risk_score"] >= RISK_AUTO_REVOKE_THRESHOLD
            and m["recommendation"] == "REVOKE"
            and not m["is_revoked"]
        ):
            await revoke_sas_token(db, m["token_id"], reason="auto-revoke: rule engine")
            revoked_sas += 1
            acted_on.append({"type": "sas", "token_id": m["token_id"], "score": m["risk_score"]})

    return {
        "revoked_jwt_sessions": revoked_jwt,
        "revoked_sas_tokens": revoked_sas,
        "acted_on": acted_on,
    }


# ── SAS Token Tracking ─────────────────────────────────────────────────────────

def parse_sas_expires(expires_at_str: str) -> datetime:
    """Chuyển expires từ generate_sas_url (isoformat) sang datetime aware."""
    dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


async def record_sas_issued(
    db: AsyncSession,
    *,
    blob_name: str,
    user_id: str | None,
    ip_address: str | None,
    user_agent: str | None,
    expires_at: datetime,
    file_id: str | None = None,
) -> str:
    """Ghi nhận SAS token vừa được cấp. Trả về token_id."""
    rec = SasTokenRecord(
        blob_name=blob_name,
        user_id=user_id,
        file_id=file_id,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255],
        expires_at=expires_at,
    )
    db.add(rec)
    await db.flush()
    return rec.token_id


async def track_sas_issue(
    db: AsyncSession,
    *,
    blob_name: str,
    user_id: str | None,
    ip_address: str | None,
    user_agent: str | None,
    expires_at: datetime,
    file_id: str | None,
    endpoint: str,
    http_method: str = "GET",
) -> str:
    """Ghi sas_token_records + token_access_logs (token_type=sas)."""
    token_id = await record_sas_issued(
        db,
        blob_name=blob_name,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
        file_id=file_id,
    )
    await log_token_access(
        db,
        token_type="sas",
        token_ref=token_id,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        endpoint=endpoint,
        http_method=http_method,
        status_code=200,
    )
    from services.ai_realtime import schedule_token_access_scan

    schedule_token_access_scan(
        token_type="sas",
        token_ref=token_id,
        user_id=user_id,
        endpoint=endpoint,
        ip_address=ip_address,
    )
    return token_id


async def is_sas_revoked(db: AsyncSession, blob_name: str, user_id: str | None) -> bool:
    """Kiểm tra blob_name + user_id có SAS bị revoke không."""
    result = await db.execute(
        select(SasTokenRecord).where(
            SasTokenRecord.blob_name == blob_name,
            SasTokenRecord.is_revoked.is_(True),
        ).order_by(SasTokenRecord.revoked_at.desc()).limit(1)
    )
    revoked = result.scalar_one_or_none()
    return revoked is not None


async def log_token_access(
    db: AsyncSession,
    *,
    token_type: TokenType,
    token_ref: str,
    user_id: str | None,
    ip_address: str | None,
    user_agent: str | None,
    endpoint: str | None,
    http_method: str | None,
    status_code: int | None,
) -> None:
    """Ghi 1 access event vào TokenAccessLog (fire-and-forget, không raise)."""
    try:
        log = TokenAccessLog(
            token_type=token_type,
            token_ref=token_ref,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:200],
            endpoint=endpoint,
            http_method=http_method,
            status_code=status_code,
        )
        db.add(log)
    except Exception:
        pass
