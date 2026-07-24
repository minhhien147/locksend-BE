"""
Token Security Management router (rule engine + LockSend AI).
Prefix: /auth/admin/token-security  (admin only)

Endpoints:
  GET  /overview              - dashboard stats
  GET  /overview/top-risk     - lazy load top 15 high-risk tokens (không block render)
  GET  /tokens                - list JWT + SAS metrics (paginated)
  POST /analyze               - rule-engine snapshot (metrics only)
  POST /auto-revoke           - rule-engine auto revoke (trigger manual)
  POST /revoke/jwt/{user_id}  - thu hồi session JWT của user
  POST /revoke/sas/{token_id} - soft-revoke SAS token
  POST /cleanup               - xóa expired records cũ
  POST /adaptive-renewal      - đề xuất TTL mới theo risk level
  GET  /ai/health             - kiểm tra LockSend AI model
  GET  /ai/trends             - biểu đồ trend 7–30 ngày
  GET  /ai/snapshots          - load danh sách AI Report snapshots mới nhất (dedup theo token_ref)
  GET  /alerts                - cảnh báo AI realtime
  POST /alerts/{id}/read      - đánh dấu đã đọc
  GET  /files/activity        - thống kê upload/download theo file
  GET  /files/{file_id}/activity - chi tiết hoạt động 1 file
  POST /ai/analyze            - KHỞI TẠO background job phân tích token (trả job_id)
  GET  /ai/jobs               - list các AI analysis jobs gần đây
  GET  /ai/jobs/{job_id}      - xem trạng thái + kết quả 1 job
  POST /ai/analyze/token      - phân tích 1 token bằng LockSend AI (sync, cho single token)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

import audit
from auth import CurrentUser, get_current_user
from db.dependencies import get_db, get_db_context
from db.models import AiJobStatus, TokenAiAnalysisJob, TokenAiScoreSnapshot
from services import ai_realtime, file_activity, locksend_ai, owner_security, token_security
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

logger = logging.getLogger(__name__)
AI_ANALYZE_BATCH_SIZE = 50

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
    top_n: int | None = Field(
        default=None,
        ge=1,
        description="Số token phân tích theo risk_score cao nhất. None = phân tích toàn bộ.",
    )
    skip_recent: bool = Field(
        default=True,
        description="Bỏ qua các token đã được phân tích trong vòng INCREMENTAL_WINDOW (tăng tốc)",
    )
    force_all: bool = Field(
        default=False,
        description="Bỏ qua cache và incremental check — phân tích lại toàn bộ từ đầu",
    )


# ── Helpers: metric ref + parallel batch analyzer ──────────────────────────────

def _metric_ref(m: dict[str, Any]) -> str:
    return str(m.get("token_id") or m.get("user_id") or "")


async def _analyze_metrics_in_parallel_batches(
    metrics: list[dict[str, Any]],
    *,
    skip_cache: bool = False,
    progress_cb=None,
) -> list[dict[str, Any]]:
    """
    Chia metrics thành các batch kích thước AI_ANALYZE_BATCH_SIZE.
    Chạy các batch SONG SONG với giới hạn semaphore (MAX_PARALLEL_BATCHES từ locksend_ai).
    Từng batch xong gọi progress_cb(processed, total) nếu có.
    """
    total = len(metrics)
    if total == 0:
        return []
    batches: list[list[dict[str, Any]]] = []
    for start in range(0, total, AI_ANALYZE_BATCH_SIZE):
        batches.append(metrics[start : start + AI_ANALYZE_BATCH_SIZE])

    from services.locksend_ai import _parallel_sem  # reuse semaphore

    results_map: dict[int, list[dict[str, Any]]] = {}
    processed_lock = asyncio.Lock()
    processed_count = 0

    async def _run_batch(batch_idx: int, batch: list[dict[str, Any]]) -> None:
        nonlocal processed_count
        async with _parallel_sem:
            try:
                batch_results = await locksend_ai.analyze_batch(
                    batch, skip_cache=skip_cache
                )
            except Exception as exc:
                logger.warning("Batch %d failed: %s", batch_idx, exc)
                batch_results = [
                    {
                        "token_id": _metric_ref(m),
                        "token_type": m.get("token_type"),
                        "error": f"Batch error: {exc}",
                    }
                    for m in batch
                ]
            results_map[batch_idx] = batch_results
            if progress_cb is not None:
                async with processed_lock:
                    processed_count += len(batch)
                    try:
                        await progress_cb(processed_count, total)
                    except Exception as cb_err:
                        logger.warning("progress_cb error: %s", cb_err)

    tasks = [_run_batch(i, b) for i, b in enumerate(batches)]
    await asyncio.gather(*tasks)

    combined: list[dict[str, Any]] = []
    for i in range(len(batches)):
        combined.extend(results_map.get(i, []))
    return combined


# ── Background Job Engine ──────────────────────────────────────────────────────

def _aware_now():
    from datetime import datetime
    return datetime.now(timezone.utc)


async def _create_job_record(
    db: AsyncSession,
    *,
    triggered_by: str,
    token_type: str,
    total_tokens: int,
) -> TokenAiAnalysisJob:
    job = TokenAiAnalysisJob(
        triggered_by=triggered_by,
        token_type=token_type,
        total_tokens=total_tokens,
        status=AiJobStatus.pending,
    )
    db.add(job)
    await db.flush()
    return job


async def _run_ai_analysis_job(
    job_id: str,
    *,
    selected_metrics: list[dict[str, Any]],
    skip_recent: bool,
    force_all: bool,
    triggered_by: str,
) -> None:
    """
    Background coroutine — chạy full pipeline, cập nhật job progress liên tục.
    Pipeline:
      1. Incremental filter (lọc bỏ tokens đã snapshot gần đây, nếu skip_recent=True)
      2. Parallel batches qua AI (có cache nếu không force_all)
      3. Bulk save snapshots vào DB
      4. Cập nhật job status = completed / failed
    """
    try:
        async with get_db_context() as db:
            job = (
                await db.execute(
                    select(TokenAiAnalysisJob).where(TokenAiAnalysisJob.id == job_id)
                )
            ).scalar_one_or_none()
            if job is None:
                logger.error("Job %s không tồn tại khi start", job_id)
                return
            job.status = AiJobStatus.running
            job.started_at = _aware_now()
            job.progress_pct = 1
            job.analyzed_count = 0
            job.failed_count = 0
            job.skipped_cached = 0
            await db.flush()
            await db.commit()

            # ── Step 1: Incremental filter ────────────────────────────
            refs = [_metric_ref(m) for m in selected_metrics]
            skip_incremental_refs: set[str] = set()
            if skip_recent and not force_all:
                try:
                    job.progress_pct = 2
                    job.error_message = None
                    await db.flush()
                    await db.commit()
                    skip_incremental_refs = (
                        await ai_realtime.find_recently_analyzed_token_refs(
                            db, token_refs=refs
                        )
                    )
                except Exception as q_err:
                    logger.warning("incremental query failed, skip filter: %s", q_err)

            to_analyze: list[dict[str, Any]] = []
            skipped_recent = 0
            for m in selected_metrics:
                if _metric_ref(m) in skip_incremental_refs:
                    skipped_recent += 1
                else:
                    to_analyze.append(m)
            job.skipped_cached = skipped_recent
            if to_analyze:
                job.progress_pct = 5
            else:
                job.progress_pct = 100
                job.status = AiJobStatus.completed
                job.completed_at = _aware_now()
                job.result_summary = {
                    "total_requested": len(selected_metrics),
                    "skipped_recent": skipped_recent,
                    "skipped_cache": 0,
                    "ai_analyzed": 0,
                    "failed": 0,
                    "saved_snapshots": 0,
                }
                await db.commit()
                return
            await db.flush()
            await db.commit()

            # ── Step 2: Progress callback (update job after each batch) ──
            progress_lock = asyncio.Lock()

            async def _progress_cb(done: int, total: int) -> None:
                async with progress_lock:
                    pct = 5 + int(85 * (done / max(total, 1)))
                    job.progress_pct = pct
                    job.analyzed_count = done
                    try:
                        await db.flush()
                        await db.commit()
                    except Exception as cb_err:
                        logger.debug("progress_cb commit skip: %s", cb_err)
                        try:
                            await db.rollback()
                        except Exception:
                            pass

            try:
                ai_results = await _analyze_metrics_in_parallel_batches(
                    to_analyze,
                    skip_cache=force_all,
                    progress_cb=_progress_cb,
                )
            except Exception as exc:
                job.status = AiJobStatus.failed
                job.error_message = f"AI analysis failed: {exc}"
                job.completed_at = _aware_now()
                await db.commit()
                logger.exception("Job %s failed at AI step", job_id)
                return

            # ── Step 3: Bulk save snapshots ────────────────────────────
            failed = 0
            cache_hit = 0
            pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for metric, result in zip(to_analyze, ai_results):
                if result.get("error"):
                    failed += 1
                else:
                    pairs.append((metric, result))
            try:
                saved = await ai_realtime.bulk_save_manual_snapshots(db, pairs)
            except Exception as save_err:
                logger.warning("bulk save failed, fallback one-by-one: %s", save_err)
                saved = 0
                for m, r in pairs:
                    try:
                        await ai_realtime.save_manual_snapshot(db, m, r)
                        saved += 1
                    except Exception as perr:
                        logger.warning("single save failed: %s", perr)

            job.analyzed_count = len(ai_results) - failed
            job.failed_count = failed
            job.skipped_cached = skipped_recent + cache_hit
            job.progress_pct = 95
            await db.flush()

            # ── Step 4: Finalize ───────────────────────────────────────
            high_risk = sum(
                1
                for r in ai_results
                if not r.get("error") and int(r.get("risk_score_pct") or 0) >= 75
            )
            revoke_count = sum(
                1
                for r in ai_results
                if not r.get("error") and str(r.get("decision") or "") == "REVOKE"
            )
            total_requested = len(selected_metrics)
            total_analyzed_ok = max(0, len(ai_results) - failed)
            job.result_summary = {
                "total_requested": total_requested,
                "skipped_recent": skipped_recent,
                "skipped_cache": cache_hit,
                "ai_analyzed": total_analyzed_ok,
                "failed": failed,
                "saved_snapshots": saved,
                "high_risk_count": high_risk,
                "revoke_recommendations": revoke_count,
            }
            # ── Critical fix: Job ALL FAILED? → status=FAILED + error_message!
            fail_rate = failed / max(total_requested, 1)
            all_zero = (total_analyzed_ok == 0 and total_requested > 0)
            if fail_rate >= 0.5 or all_zero:
                job.status = AiJobStatus.failed
                job.error_message = (
                    f"Analysis failed: analyzed 0/{total_requested} tokens OK. "
                    f"fail_rate={fail_rate*100:.0f}%. "
                    f"Skipped recent: {skipped_recent}. "
                    "Kiểm tra locksend-ai server (remote) hoặc model.pkl (local)."
                )
            else:
                job.status = AiJobStatus.completed
            job.progress_pct = 100
            job.completed_at = _aware_now()
            await db.commit()
            logger.info(
                "Job %s %s. total=%d ai_ok=%d failed=%d skipped=%d saved_snapshots=%d",
                job_id, job.status, total_requested, total_analyzed_ok, failed, skipped_recent, saved,
            )
    except Exception as exc:
        logger.exception("Job %s crashed at outer try: %s", job_id, exc)
        try:
            async with get_db_context() as db:
                job = (
                    await db.execute(
                        select(TokenAiAnalysisJob).where(TokenAiAnalysisJob.id == job_id)
                    )
                ).scalar_one_or_none()
                if job is not None:
                    job.status = AiJobStatus.failed
                    job.error_message = f"Job crashed: {exc}"
                    job.completed_at = _aware_now()
                    await db.commit()
        except Exception:
            pass


# ── Overview Endpoints (Lazy + Cache) ─────────────────────────────────────────

@router.get("/overview")
async def get_overview(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip_cache: bool = Query(default=False),
):
    """
    Dashboard stats: JWT/SAS counts, risk summary.
    Tối ưu: Chỉ trả COUNTs (server-side), bỏ top_risk_tokens (lazy load riêng).
    """
    _require_admin(current)
    overview = await token_security.build_overview(db, include_top_risk=False, skip_cache=skip_cache)
    audit.log_event(
        "admin.token_security.overview",
        user_id=current.id,
        role=current.role,
        request_id=audit.get_request_id(request),
    )
    return {"overview": overview}


@router.get("/overview/top-risk")
async def get_overview_top_risk(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=15, ge=1, le=100),
):
    """Lazy-load top N tokens có risk_score cao nhất (sau khi overview skeleton render)."""
    _require_admin(current)
    top_list = await token_security.get_high_risk_tokens(db, limit=limit)
    return {"top_risk_tokens": top_list}


# ── Token list / Rule engine endpoints ─────────────────────────────────────────

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
    Retention: TOKEN_SAS_RECORD_RETENTION_DAYS (mặc định 30), TOKEN_ACCESS_LOG_RETENTION_DAYS (14).
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


# ── LockSend AI endpoints (Bulk analysis via Background Jobs) ───────────────────

@router.get("/ai/health")
async def ai_health(
    current: CurrentUser = Depends(get_current_user),
):
    """Kiểm tra LockSend AI model đã train và load được chưa."""
    _require_admin(current)
    health = await locksend_ai.health()
    health["realtime_enabled"] = ai_realtime.REALTIME_ENABLED
    return health


@router.post("/ai/analyze")
async def ai_analyze_start_job(
    body: AiAnalyzeRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    KHỞI TẠO background job phân tích toàn bộ token bằng LockSend AI.
    Trả về job_id ngay lập tức — FE poll /ai/jobs/{job_id} để lấy tiến trình + kết quả.
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

    if body.top_n is not None:
        selected_metrics = all_metrics[: body.top_n]
    else:
        selected_metrics = all_metrics

    job = await _create_job_record(
        db,
        triggered_by=current.id,
        token_type=body.token_type,
        total_tokens=len(selected_metrics),
    )
    await db.commit()

    # Dispatch background job (không block request)
    task = asyncio.create_task(
        _run_ai_analysis_job(
            str(job.id),
            selected_metrics=selected_metrics,
            skip_recent=body.skip_recent,
            force_all=body.force_all,
            triggered_by=current.id,
        )
    )
    task.add_done_callback(lambda t: (
        None if not t.exception() else logger.error("Background AI job raised: %s", t.exception())
    ))

    audit.log_event(
        "admin.token_security.ai_analyze",
        user_id=current.id,
        role=current.role,
        token_type=body.token_type,
        analyzed=len(selected_metrics),
        job_id=str(job.id),
        request_id=audit.get_request_id(request),
    )

    return {
        "job_id": str(job.id),
        "status": job.status.value if isinstance(job.status, AiJobStatus) else str(job.status),
        "total_tokens": job.total_tokens,
        "message": (
            f"Job AI phân tích {len(selected_metrics)} tokens đã khởi tạo. "
            f"Poll /ai/jobs/{job.id} để xem tiến trình."
        ),
        "poll_url": f"/auth/admin/token-security/ai/jobs/{job.id}",
    }


@router.get("/ai/jobs")
async def ai_list_jobs(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
):
    """List các AI analysis jobs gần đây (mới nhất trước)."""
    _require_admin(current)
    q = (
        select(TokenAiAnalysisJob)
        .order_by(desc(TokenAiAnalysisJob.created_at))
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()

    def _to_dict(j: TokenAiAnalysisJob) -> dict[str, Any]:
        return {
            "job_id": str(j.id),
            "triggered_by": j.triggered_by,
            "token_type": j.token_type,
            "total_tokens": j.total_tokens,
            "analyzed_count": j.analyzed_count,
            "skipped_cached": j.skipped_cached,
            "failed_count": j.failed_count,
            "status": j.status.value if isinstance(j.status, AiJobStatus) else str(j.status),
            "error_message": j.error_message,
            "progress_pct": j.progress_pct,
            "result_summary": j.result_summary,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }

    return {"jobs": [_to_dict(j) for j in rows]}


@router.get("/ai/jobs/{job_id}")
async def ai_get_job_detail(
    job_id: str,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    include_details: bool = Query(default=True),
    snapshots_limit: int = Query(default=200, ge=0, le=500),
):
    """Xem trạng thái + (tùy chọn) danh sách snapshots của 1 AI analysis job."""
    _require_admin(current)
    job = (
        await db.execute(
            select(TokenAiAnalysisJob).where(TokenAiAnalysisJob.id == job_id)
        )
    ).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Job không tồn tại")

    status_val = job.status.value if isinstance(job.status, AiJobStatus) else str(job.status)
    payload: dict[str, Any] = {
        "job_id": str(job.id),
        "triggered_by": job.triggered_by,
        "token_type": job.token_type,
        "total_tokens": job.total_tokens,
        "analyzed_count": job.analyzed_count,
        "skipped_cached": job.skipped_cached,
        "failed_count": job.failed_count,
        "status": status_val,
        "error_message": job.error_message,
        "progress_pct": job.progress_pct,
        "result_summary": job.result_summary,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }

    if include_details and snapshots_limit > 0:
        # Lấy các snapshot gần nhất sau thời điểm job khởi tạo
        snap_q = select(TokenAiScoreSnapshot).order_by(desc(TokenAiScoreSnapshot.created_at))
        if job.created_at is not None:
            from datetime import timedelta
            window_start = job.created_at - timedelta(seconds=30)
            snap_q = snap_q.where(TokenAiScoreSnapshot.created_at >= window_start)
        snap_q = snap_q.limit(snapshots_limit)
        snaps = (await db.execute(snap_q)).scalars().all()
        payload["snapshots"] = [
            {
                "id": str(s.id),
                "token_type": s.token_type,
                "token_ref": s.token_ref,
                "user_id": s.user_id,
                "rule_score": s.rule_score,
                "ai_score_pct": s.ai_score_pct,
                "ai_level": s.ai_level,
                "decision": s.decision,
                "source": s.source,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in snaps
        ]
    return payload


@router.get("/ai/snapshots")
async def ai_get_recent_snapshots(
    limit: int = Query(default=200, ge=1, le=500),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Load danh sách AI Report snapshots mới nhất.
    Deduplicate theo token_ref để FE luôn hiện báo cáo gần nhất cho mỗi token.
    FE gọi endpoint này khi mở tab AI Report thay vì phụ thuộc vào payload job.
    """
    _require_admin(current)
    rows = (
        await db.execute(
            select(TokenAiScoreSnapshot)
            .order_by(desc(TokenAiScoreSnapshot.created_at))
            .limit(limit)
        )
    ).scalars().all()
    seen: set[str] = set()
    deduped: list[TokenAiScoreSnapshot] = []
    for s in rows:
        if s.token_ref not in seen:
            seen.add(s.token_ref)
            deduped.append(s)
    return {
        "snapshots": [
            {
                "id": str(s.id),
                "token_type": s.token_type,
                "token_ref": s.token_ref,
                "user_id": s.user_id,
                "rule_score": s.rule_score,
                "ai_score_pct": s.ai_score_pct,
                "ai_level": s.ai_level,
                "decision": s.decision,
                "source": s.source,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in deduped
        ],
        "total_raw": len(rows),
        "total_deduped": len(deduped),
    }


@router.post("/ai/analyze/token")
async def ai_analyze_single(
    body: AiSingleTokenRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Phân tích nhanh 1 token cụ thể bằng LockSend AI (sync, không background)."""
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
        ai_result = await locksend_ai.analyze_token(token_data, skip_cache=True)
    except RuntimeError as exc:
        ai_error = str(exc)

    if ai_result and not ai_error:
        await ai_realtime.save_manual_snapshot(db, token_data, ai_result)
        await db.commit()

    audit.log_event(
        "admin.token_security.ai_analyze_single",
        user_id=current.id,
        role=current.role,
        token_type=body.token_type,
        token_ref=_metric_ref(token_data),
        request_id=audit.get_request_id(request),
    )

    return {
        "token_metrics": token_data,
        "ai": ai_result,
        "ai_error": ai_error,
    }


# ── Alerts Endpoints ───────────────────────────────────────────────────────────

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
    await db.commit()
    return {"ok": True}


@router.post("/alerts/read-all")
async def read_all_security_alerts(
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    _require_admin(current)
    n = await ai_realtime.mark_all_alerts_read(db)
    await db.commit()
    return {"marked": n}


# ── AI Trends Endpoints ────────────────────────────────────────────────────────

@router.get("/ai/trends")
async def ai_security_trends(
    days: int = Query(default=7, ge=1, le=30),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Biểu đồ trend: access, cảnh báo AI, score cao, Rule≠AI."""
    _require_admin(current)
    return await ai_realtime.build_trends(db, days=days)


# ── File Activity Endpoints ────────────────────────────────────────────────────

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


@router.post("/files/{file_id}/notify-owner")
async def notify_file_owner(
    file_id: str,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin gửi cảnh báo tới owner file (IP bất thường / rủi ro SAS)."""
    _require_admin(current)
    from db.models import File

    from db.models import User
    from services import email_service
    from services.user_email import is_valid_alert_email

    file_row = (
        await db.execute(
            select(File).where(File.id == file_id).options(selectinload(File.owner))
        )
    ).scalar_one_or_none()
    if not file_row:
        raise HTTPException(status_code=404, detail="File không tìm thấy")

    owner = file_row.owner
    if owner is None and file_row.owner_id:
        owner = (
            await db.execute(select(User).where(User.id == file_row.owner_id))
        ).scalar_one_or_none()

    email_sent = False
    if email_service.is_configured():
        if not owner or not is_valid_alert_email(owner.email):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Owner chưa có email hợp lệ để nhận cảnh báo qua mail. "
                    "Yêu cầu owner cập nhật email trong trang Hồ sơ."
                ),
            )
        email_sent = True

    alert = await owner_security.maybe_alert_multi_ip_access(
        db, file_id, force=True, triggered_by="admin"
    )
    if alert is None:
        raise HTTPException(status_code=500, detail="Không tạo được cảnh báo")
    await db.commit()
    audit.log_event(
        "admin.token_security.notify_owner",
        user_id=current.id,
        role=current.role,
        file_id=file_id,
        alert_id=alert.id,
        request_id=audit.get_request_id(request),
    )
    return {
        "status": "sent",
        "alert_id": alert.id,
        "owner_user_id": alert.user_id,
        "owner_email": owner.email if owner else None,
        "email_sent": email_sent,
    }
