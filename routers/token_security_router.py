"""
Token Security Management router (rule engine + LockSend AI).
Prefix: /auth/admin/token-security  (admin only)

Endpoints:
  GET  /overview              - dashboard stats
  GET  /tokens                - list JWT + SAS metrics (paginated)
  POST /analyze               - rule-engine snapshot (metrics only)
  POST /auto-revoke           - rule-engine auto revoke (trigger manual)
  POST /revoke/jwt/{user_id}  - thu hồi session JWT của user
  POST /revoke/sas/{token_id} - soft-revoke SAS token
  POST /cleanup               - xóa expired records cũ
  POST /adaptive-renewal      - đề xuất TTL mới theo risk level
  GET  /ai/health             - kiểm tra LockSend AI model
  GET  /ai/trends             - biểu đồ trend 7–30 ngày
  GET  /alerts                - cảnh báo AI realtime
  POST /alerts/{id}/read      - đánh dấu đã đọc
  GET  /files/activity        - thống kê upload/download theo file
  GET  /files/{file_id}/activity - chi tiết hoạt động 1 file
  POST /ai/analyze            - phân tích toàn bộ token bằng LockSend AI
  POST /ai/analyze/token      - phân tích 1 token bằng LockSend AI
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import audit
from auth import CurrentUser, get_current_user
from db.dependencies import get_db
from services import ai_realtime, file_activity, locksend_ai, token_security
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth/admin/token-security",
    tags=["token-security"],
)


def _require_admin(current: CurrentUser) -> None:
    if current.role != "admin":
        raise HTTPException(status_code=403, detail="Yêu cầu quyền admin")


# ── Schemas ────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    token_type: Literal["all", "jwt", "sas"] = "all"
    target_id: str | None = Field(
        default=None,
        description="user_id cho jwt | token_id cho sas | None = toàn hệ thống",
    )


class RevokeJwtRequest(BaseModel):
    reason: str = "Manual admin revoke"


class RevokeSasRequest(BaseModel):
    reason: str = "Manual admin revoke"


class AdaptiveRenewalRequest(BaseModel):
    risk_level: Literal["low", "medium", "high", "critical"]
    token_type: Literal["jwt", "sas"]


class AiSingleTokenRequest(BaseModel):
    token_id: str
    token_type: Literal["jwt", "sas"]


class AiAnalyzeRequest(BaseModel):
    token_type: Literal["all", "jwt", "sas"] = "all"
    top_n: int = Field(default=20, ge=1, le=100, description="Số token phân tích (theo risk_score cao nhất)")


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/overview")
async def get_overview(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard stats: JWT/SAS counts, risk summary."""
    _require_admin(current)
    overview = await token_security.build_overview(db)
    audit.log_event(
        "admin.token_security.overview",
        user_id=current.id,
        role=current.role,
        request_id=audit.get_request_id(request),
    )
    return {"overview": overview}


@router.get("/tokens")
async def list_tokens(
    request: Request,
    token_type: Literal["all", "jwt", "sas"] = Query(default="all"),
    include_expired: bool = Query(default=False),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Danh sách token + risk score (rule engine). Admin only."""
    _require_admin(current)

    jwt_list: list[dict[str, Any]] = []
    sas_list: list[dict[str, Any]] = []

    if token_type in ("all", "jwt"):
        jwt_list = await token_security.get_jwt_token_metrics(db)
    if token_type in ("all", "sas"):
        sas_list = await token_security.get_sas_token_metrics(
            db, include_expired=include_expired
        )

    combined = jwt_list + sas_list
    combined.sort(key=lambda x: x["risk_score"], reverse=True)

    audit.log_event(
        "admin.token_security.list_tokens",
        user_id=current.id,
        role=current.role,
        request_id=audit.get_request_id(request),
        token_type=token_type,
        count=len(combined),
    )
    return {"tokens": combined, "total": len(combined)}


@router.post("/analyze")
async def analyze_tokens(
    body: AnalyzeRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Phân tích bảo mật token bằng rule engine (không gọi LLM).
    Trả snapshot metrics đã redact — dùng làm input cho AI tích hợp sau này.
    """
    _require_admin(current)

    snapshot = await token_security.build_security_snapshot(
        db,
        token_type=body.token_type,
        target_id=body.target_id,
    )

    audit.log_event(
        "admin.token_security.analyze",
        user_id=current.id,
        role=current.role,
        token_type=body.token_type,
        request_id=audit.get_request_id(request),
    )

    return {
        "snapshot_summary": {
            "tokens_analyzed": len(snapshot.get("token_metrics", [])),
            "access_logs_sampled": len(snapshot.get("recent_access_log_sample", [])),
        },
        "token_metrics": snapshot.get("token_metrics", []),
        "thresholds": snapshot.get("thresholds", {}),
    }


@router.post("/auto-revoke")
async def trigger_auto_revoke(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Trigger rule-engine auto-revoke thủ công.
    Thu hồi token có risk score >= ngưỡng AUTO_REVOKE.
    """
    _require_admin(current)
    result = await token_security.auto_revoke_high_risk(db)
    await db.commit()

    audit.log_event(
        "admin.token_security.auto_revoke",
        user_id=current.id,
        role=current.role,
        **result,
        request_id=audit.get_request_id(request),
    )
    return result


@router.post("/revoke/jwt/{target_user_id}")
async def revoke_jwt_sessions(
    target_user_id: str,
    body: RevokeJwtRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Thu hồi toàn bộ refresh session JWT của user (buộc đăng nhập lại)."""
    _require_admin(current)
    if target_user_id == current.id:
        raise HTTPException(
            status_code=400,
            detail="Không thể thu hồi session của chính admin đang đăng nhập",
        )
    count = await token_security.revoke_jwt_sessions(db, target_user_id, reason=body.reason)
    await db.commit()

    audit.log_event(
        "admin.token_security.revoke_jwt",
        user_id=current.id,
        role=current.role,
        target_user_id=target_user_id,
        revoked_count=count,
        reason=body.reason,
        request_id=audit.get_request_id(request),
    )
    return {"revoked_sessions": count, "user_id": target_user_id}


@router.post("/revoke/sas/{token_id}")
async def revoke_sas_token(
    token_id: str,
    body: RevokeSasRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Soft-revoke SAS token — ngăn cấp SAS mới cho blob này."""
    _require_admin(current)
    ok = await token_security.revoke_sas_token(db, token_id, reason=body.reason)
    if not ok:
        raise HTTPException(status_code=404, detail="SAS token không tìm thấy hoặc đã bị revoke")
    await db.commit()

    audit.log_event(
        "admin.token_security.revoke_sas",
        user_id=current.id,
        role=current.role,
        sas_token_id=token_id,
        reason=body.reason,
        request_id=audit.get_request_id(request),
    )
    return {"revoked": True, "token_id": token_id}


@router.post("/cleanup")
async def cleanup_old_records(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Dọn dẹp SAS records + access logs cũ.
    SAS records expired > 30 ngày; access logs > 14 ngày.
    """
    _require_admin(current)
    result = await token_security.cleanup_expired_tokens(db)
    await db.commit()

    audit.log_event(
        "admin.token_security.cleanup",
        user_id=current.id,
        role=current.role,
        **result,
        request_id=audit.get_request_id(request),
    )
    return result


@router.post("/adaptive-renewal")
async def adaptive_renewal(
    body: AdaptiveRenewalRequest,
    current: CurrentUser = Depends(get_current_user),
):
    """
    Smart Token Renewal: đề xuất TTL phù hợp dựa trên risk level hiện tại.
    Không thay đổi cấu hình — chỉ trả về recommendation.
    """
    _require_admin(current)

    if body.token_type == "jwt":
        ttl_map = {
            "low": {"minutes": 60, "rationale": "Phiên an toàn — cho phép access token dài hơn"},
            "medium": {"minutes": 15, "rationale": "Giữ TTL mặc định — theo dõi thêm"},
            "high": {"minutes": 5, "rationale": "Rủi ro cao — rút ngắn TTL để giảm exposure window"},
            "critical": {"minutes": 2, "rationale": "Nguy hiểm — TTL tối thiểu, yêu cầu re-auth liên tục"},
        }
        rec = ttl_map[body.risk_level]
        return {
            "token_type": "jwt",
            "risk_level": body.risk_level,
            "current_env": "ACCESS_TOKEN_EXPIRE_MINUTES",
            "suggested_ttl_minutes": rec["minutes"],
            "rationale": rec["rationale"],
            "action": f"Đặt ACCESS_TOKEN_EXPIRE_MINUTES={rec['minutes']} trong .env rồi restart backend",
        }
    else:
        ttl_map = {
            "low": {"hours": 24, "rationale": "File chia sẻ an toàn — TTL dài thuận tiện"},
            "medium": {"hours": 4, "rationale": "Giới hạn TTL vừa phải"},
            "high": {"hours": 1, "rationale": "Rủi ro cao — SAS ngắn hạn để giảm leak damage"},
            "critical": {"hours": 0, "rationale": "Nguy hiểm — không cấp SAS, revoke ngay"},
        }
        rec = ttl_map[body.risk_level]
        return {
            "token_type": "sas",
            "risk_level": body.risk_level,
            "suggested_ttl_hours": rec["hours"],
            "rationale": rec["rationale"],
            "action": "Cập nhật tham số SAS expiry trong /sas-token endpoint"
            if rec["hours"] > 0 else "Revoke ngay token hiện tại, audit người dùng",
        }


# ── LockSend AI endpoints ──────────────────────────────────────────────────────

@router.get("/ai/health")
async def ai_health(
    current: CurrentUser = Depends(get_current_user),
):
    """Kiểm tra LockSend AI model đã train và load được chưa."""
    _require_admin(current)
    return await locksend_ai.health()


@router.post("/ai/analyze")
async def ai_analyze(
    body: AiAnalyzeRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Phân tích token bằng LockSend AI (Random Forest CIC-IDS2017).
    Lấy top_n token có risk_score cao nhất từ rule engine, sau đó chạy qua ML model.
    """
    _require_admin(current)

    # Lấy metrics từ rule engine trước
    jwt_list: list[dict[str, Any]] = []
    sas_list: list[dict[str, Any]] = []
    if body.token_type in ("all", "jwt"):
        jwt_list = await token_security.get_jwt_token_metrics(db)
    if body.token_type in ("all", "sas"):
        sas_list = await token_security.get_sas_token_metrics(db, include_expired=False)

    all_metrics = jwt_list + sas_list
    all_metrics.sort(key=lambda x: x["risk_score"], reverse=True)
    top_metrics = all_metrics[: body.top_n]

    ai_error: str | None = None
    ai_results: list[dict[str, Any]] = []

    try:
        ai_results = await locksend_ai.analyze_batch(top_metrics)
        for metric, result in zip(top_metrics, ai_results):
            if result and not result.get("error"):
                await ai_realtime.save_manual_snapshot(db, metric, result)
    except RuntimeError as exc:
        ai_error = str(exc)
        logger.info("LockSend AI skipped: %s", exc)

    audit.log_event(
        "admin.token_security.ai_analyze",
        user_id=current.id,
        role=current.role,
        token_type=body.token_type,
        analyzed=len(ai_results),
        ai_ok=ai_error is None,
        request_id=audit.get_request_id(request),
    )

    return {
        "analyzed": len(ai_results),
        "ai_results": ai_results,
        "ai_error": ai_error,
        "rule_metrics": top_metrics,
    }


@router.post("/ai/analyze/token")
async def ai_analyze_single(
    body: AiSingleTokenRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Phân tích nhanh 1 token cụ thể bằng LockSend AI."""
    _require_admin(current)

    if body.token_type == "jwt":
        metrics = await token_security.get_jwt_token_metrics(db, user_id=body.token_id)
        token_data = next(
            (m for m in metrics if body.token_id in (m.get("user_id") or "")), None
        )
    else:
        metrics = await token_security.get_sas_token_metrics(db, include_expired=True)
        token_data = next((m for m in metrics if m["token_id"] == body.token_id), None)

    if not token_data:
        raise HTTPException(status_code=404, detail="Token không tìm thấy")

    ai_result: dict[str, Any] | None = None
    ai_error: str | None = None

    try:
        ai_result = await locksend_ai.analyze_token(token_data)
    except RuntimeError as exc:
        ai_error = str(exc)

    if ai_result and not ai_error:
        await ai_realtime.save_manual_snapshot(db, token_data, ai_result)

    return {
        "token_metrics": token_data,
        "ai": ai_result,
        "ai_error": ai_error,
    }


@router.get("/alerts")
async def list_security_alerts(
    unread_only: bool = Query(default=False),
    limit: int = Query(default=30, ge=1, le=100),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cảnh báo AI realtime (admin)."""
    _require_admin(current)
    alerts = await ai_realtime.list_alerts(db, unread_only=unread_only, limit=limit)
    unread = await ai_realtime.unread_alert_count(db)
    return {"alerts": alerts, "unread_count": unread}


@router.post("/alerts/{alert_id}/read")
async def read_security_alert(
    alert_id: str,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_admin(current)
    ok = await ai_realtime.mark_alert_read(db, alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Không tìm thấy cảnh báo")
    return {"ok": True}


@router.post("/alerts/read-all")
async def read_all_security_alerts(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_admin(current)
    n = await ai_realtime.mark_all_alerts_read(db)
    return {"marked": n}


@router.get("/ai/trends")
async def ai_security_trends(
    days: int = Query(default=7, ge=1, le=30),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Biểu đồ trend: access, cảnh báo AI, score cao, Rule≠AI."""
    _require_admin(current)
    return await ai_realtime.build_trends(db, days=days)


@router.get("/files/activity")
async def file_activity_overview(
    request: Request,
    days: int = Query(default=7, ge=1, le=30),
    limit: int = Query(default=20, ge=1, le=50),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Top file theo lượt tải, IP, SAS link và trend upload/download."""
    _require_admin(current)
    data = await file_activity.build_file_overview(db, days=days, limit=limit)
    audit.log_event(
        "admin.token_security.file_activity",
        user_id=current.id,
        role=current.role,
        days=days,
        request_id=audit.get_request_id(request),
    )
    return data


@router.get("/files/{file_id}/activity")
async def file_activity_detail(
    file_id: str,
    days: int = Query(default=7, ge=1, le=30),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Chi tiết hoạt động một file (download gần đây, cảnh báo AI)."""
    _require_admin(current)
    detail = await file_activity.get_file_detail(db, file_id, days=days)
    if not detail:
        raise HTTPException(status_code=404, detail="File không tìm thấy")
    return detail
