"""
LockSend AI — HTTP service (VPS, Railway, local).

Chạy:
  uvicorn server:app --host 0.0.0.0 --port 8100
  # Railway: sh start.sh (railway.json)

Env:
  LOCKSEND_AI_API_KEY       - [BẮT BUỘC trên production] Bearer token
  LOCKSEND_AI_MODELS_DIR    - thư mục chứa model.pkl (Volume Railway: /data)
  LOCKSEND_AI_MODEL_URL     - URL tải model.pkl lúc startup nếu file chưa có
  APP_ENV                   - set "development" để bỏ qua kiểm tra API key
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys
import warnings
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from predict import analyze_access, analyze_batch_access, load_bundle

API_KEY = os.getenv("LOCKSEND_AI_API_KEY", "").strip()
_IS_PRODUCTION = os.getenv("APP_ENV", "production").lower() not in ("development", "dev", "test")

# A04: Trần số item cho /analyze/batch
MAX_BATCH_ITEMS = int(os.getenv("LOCKSEND_AI_MAX_BATCH_ITEMS", "512"))

# Fix #5 — Bắt buộc API key trên production
if _IS_PRODUCTION:
    if not API_KEY:
        print(
            "\n🔒 SECURITY: LOCKSEND_AI_API_KEY chưa được set!\n"
            "  AI service từ chối khởi động trên production.\n"
            "  Tạo key: python -c \"import secrets; print(secrets.token_urlsafe(32))\"\n"
            "  Để bỏ qua (chỉ dev): set APP_ENV=development\n",
            file=sys.stderr,
        )
        sys.exit(1)
    elif len(API_KEY) < 16:
        print(
            f"\n🔒 SECURITY: LOCKSEND_AI_API_KEY quá ngắn ({len(API_KEY)} ký tự, cần ≥ 16).\n",
            file=sys.stderr,
        )
        sys.exit(1)
else:
    if not API_KEY:
        warnings.warn(
            "SECURITY: LOCKSEND_AI_API_KEY chưa set — AI service mở không xác thực (dev mode).",
            stacklevel=1,
        )

_preload_task: asyncio.Task[None] | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """
    Nạp model.pkl ngay lúc boot thay vì ở request đầu tiên — pickle.load của rừng
    ~95MB mất hàng chục giây trên vCPU chia sẻ, đủ làm client timeout rồi fallback
    sang gọi lẻ từng token.

    Chạy nền (không await) để /health/live phản hồi ngay cho Railway healthcheck.
    """
    global _preload_task

    def _load() -> None:
        try:
            _get_bundle()
            print("[locksend-ai] model preloaded", flush=True)
        except Exception as exc:
            print(f"[locksend-ai] WARN: preload model thất bại — {exc}", file=sys.stderr, flush=True)

    _preload_task = asyncio.create_task(asyncio.to_thread(_load))
    try:
        yield
    finally:
        if _preload_task and not _preload_task.done():
            _preload_task.cancel()


app = FastAPI(
    title="LockSend AI Service",
    version="1.0.0",
    lifespan=lifespan,
    # Ẩn docs trên production
    docs_url="/docs" if not _IS_PRODUCTION else None,
    redoc_url="/redoc" if not _IS_PRODUCTION else None,
    openapi_url="/openapi.json" if not _IS_PRODUCTION else None,
)
_bundle: dict[str, Any] | None = None
_load_error: str | None = None


def _get_bundle() -> dict[str, Any]:
    global _bundle, _load_error
    if _bundle is not None:
        return _bundle
    if _load_error is not None:
        raise RuntimeError(_load_error)
    try:
        _bundle = load_bundle()
        _load_error = None
        return _bundle
    except Exception as exc:
        _load_error = str(exc)
        raise


def _verify_api_key(authorization: str | None = Header(default=None)) -> None:
    # Production: API_KEY đã được enforce ở startup → luôn có giá trị
    # Development: nếu không set key thì bỏ qua xác thực
    if not API_KEY:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    # A07: so sánh constant-time để giảm timing side-channel.
    presented = authorization[7:]
    if len(presented) != len(API_KEY) or not secrets.compare_digest(presented, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")


class AnalyzeRequest(BaseModel):
    features: dict[str, float] = Field(
        description="Partial CIC-IDS2017 feature dict (missing cols → 0)"
    )


class BatchAnalyzeRequest(BaseModel):
    # A04: Không giới hạn số item thì một request đủ để đốt hết CPU/RAM của
    # service (SHAP + sklearn chạy đồng bộ) — DoS chỉ bằng một POST.
    items: list[dict[str, float]] = Field(max_length=MAX_BATCH_ITEMS)
    explain_top_n: int = Field(
        default=10,
        ge=0,
        le=100,
        description="Số token rủi ro cao nhất được tính SHAP (0 = tắt giải thích)",
    )


@app.get("/health/live")
def health_live() -> dict[str, str]:
    """Liveness — Railway healthcheck (không load model)."""
    return {"status": "ok"}


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        bundle = _get_bundle()
        metrics = dict(bundle.get("metrics") or {})
        # dataset / description nằm top-level bundle (train.py) — merge vào metrics cho FE
        if "dataset" not in metrics and bundle.get("dataset"):
            metrics["dataset"] = bundle["dataset"]
        if "dataset_description" not in metrics and bundle.get("dataset_description"):
            metrics["dataset_description"] = bundle["dataset_description"]
        if "combine_profiles" not in metrics and bundle.get("combine_profiles"):
            metrics["combine_profiles"] = bundle["combine_profiles"]
        return {
            "ready": True,
            "version": bundle.get("version", "unknown"),
            "trained_at": bundle.get("trained_at"),
            "dataset": metrics.get("dataset") or bundle.get("dataset"),
            "dataset_description": metrics.get("dataset_description")
            or bundle.get("dataset_description"),
            "metrics": metrics,
        }
    except Exception as exc:
        # A05: /health không cần API key — không lộ đường dẫn/stack ở production.
        hint = (
            "Ensure model.pkl on Volume (LOCKSEND_AI_MODELS_DIR) matching models/model.pkl.sha256, "
            "or set LOCKSEND_AI_MODEL_URL + LOCKSEND_AI_MODEL_SHA256"
        )
        if _IS_PRODUCTION:
            return {"ready": False, "error": "model_unavailable", "hint": hint}
        return {
            "ready": False,
            "error": str(exc),
            "hint": hint,
        }


@app.post("/analyze", dependencies=[Depends(_verify_api_key)])
def analyze_one(body: AnalyzeRequest) -> dict[str, Any]:
    import pandas as pd

    bundle = _get_bundle()
    row = pd.DataFrame([body.features])
    return analyze_access(row, bundle=bundle)


@app.post("/analyze/batch", dependencies=[Depends(_verify_api_key)])
def analyze_many(body: BatchAnalyzeRequest) -> dict[str, Any]:
    import pandas as pd

    bundle = _get_bundle()
    rows = pd.DataFrame(body.items)
    results = analyze_batch_access(
        rows, bundle=bundle, explain_top_n=body.explain_top_n
    )
    return {"results": results, "count": len(results)}
