"""
LockSend AI — gọi model local (nhúng) hoặc remote (host riêng Ubuntu).

Chế độ:
  - Local:  không set LOCKSEND_AI_URL → import predict.py từ LOCKSEND_AI_DIR
  - Remote: LOCKSEND_AI_URL=http://ai-server:8100 → HTTP tới AI service

Env:
  LOCKSEND_AI_URL      - base URL service AI (vd. http://10.0.0.5:8100)
  LOCKSEND_AI_API_KEY  - Bearer token (khớp LOCKSEND_AI_API_KEY trên server)
  LOCKSEND_AI_DIR      - path local (mặc định <repo>/locksend-ai), chỉ khi remote tắt
  LOCKSEND_AI_TIMEOUT  - giây (mặc định 30)
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import httpx

from services.ai_explain import enrich_ai_result
from services.ssrf_guard import validate_locksend_ai_url

logger = logging.getLogger(__name__)

LOCKSEND_AI_URL = os.getenv("LOCKSEND_AI_URL", "").rstrip("/")
LOCKSEND_AI_API_KEY = os.getenv("LOCKSEND_AI_API_KEY", "").strip()

# A10: Validate SSRF trước khi sử dụng URL
if LOCKSEND_AI_URL:
    try:
        LOCKSEND_AI_URL = validate_locksend_ai_url(LOCKSEND_AI_URL)
    except ValueError as _ssrf_err:
        logger.error("SECURITY A10: LOCKSEND_AI_URL bị từ chối — %s", _ssrf_err)
        LOCKSEND_AI_URL = ""
def _default_ai_dir() -> str:
    """Monorepo: <repo>/locksend-ai (cạnh backend/, frontend/)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "locksend-ai"))


_env_dir = os.getenv("LOCKSEND_AI_DIR", "").strip()
LOCKSEND_AI_DIR = (_env_dir if _env_dir else _default_ai_dir()).replace("\\", "/")
LOCKSEND_AI_TIMEOUT = float(os.getenv("LOCKSEND_AI_TIMEOUT", "30"))

REMOTE_MODE = bool(LOCKSEND_AI_URL)

if not REMOTE_MODE and LOCKSEND_AI_DIR not in sys.path:
    sys.path.insert(0, LOCKSEND_AI_DIR)

_bundle: dict[str, Any] | None = None
_load_error: str | None = None

_LEVEL_MAP = {
    "NORMAL": "low",
    "LOW": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def _auth_headers() -> dict[str, str]:
    if LOCKSEND_AI_API_KEY:
        return {"Authorization": f"Bearer {LOCKSEND_AI_API_KEY}"}
    return {}


def _ensure_loaded() -> None:
    global _bundle, _load_error
    if REMOTE_MODE:
        return
    if _bundle is not None:
        return
    if _load_error is not None:
        raise RuntimeError(_load_error)
    try:
        from predict import load_bundle  # type: ignore[import]
        _bundle = load_bundle()
        logger.info("LockSend AI model loaded locally (version=%s)", _bundle.get("version"))
    except FileNotFoundError as exc:
        _load_error = f"model.pkl chưa có — chạy: python train.py trong {LOCKSEND_AI_DIR}"
        logger.warning("LockSend AI: %s", _load_error)
        raise RuntimeError(_load_error) from exc
    except ImportError as exc:
        _load_error = f"Không import được predict.py từ {LOCKSEND_AI_DIR}: {exc}"
        logger.warning("LockSend AI: %s", _load_error)
        raise RuntimeError(_load_error) from exc


def reload_bundle() -> dict[str, Any]:
    """
    Hot-reload model.pkl vào RAM sau khi train.py chạy xong.

    Reset cache buộc _ensure_loaded() đọc lại file từ disk.
    An toàn khi gọi từ thread pool (asyncio.to_thread) vì chỉ thao tác
    global module-level và pickle.load — không có race condition với
    inference đang chạy (CPython GIL bảo vệ việc gán _bundle).
    """
    global _bundle, _load_error
    _bundle = None
    _load_error = None
    _ensure_loaded()
    assert _bundle is not None
    logger.info(
        "LockSend AI bundle reloaded (version=%s, trained_at=%s)",
        _bundle.get("version"),
        _bundle.get("trained_at"),
    )
    return _bundle


def _token_metric_to_cic(metric: dict[str, Any]) -> dict[str, float]:
    raw_rate = float(
        metric.get("accesses_per_hour")
        or metric.get("downloads_per_hour")
        or 0
    )
    flow_packets_s = raw_rate / 3600.0
    active_sessions = float(metric.get("active_sessions") or 1)
    ip_count = float(metric.get("ip_count") or 1)
    token_age_hours = float(metric.get("token_age_hours") or 0)

    # A03: Clamp giá trị về range hợp lệ — tránh NaN/Inf làm lệch model
    flow_packets_s = max(0.0, min(flow_packets_s, 1e6))
    active_sessions = max(0.0, min(active_sessions, 1e5))
    ip_count = max(1.0, min(ip_count, 1e4))
    token_age_hours = max(0.0, min(token_age_hours, 8760.0))  # tối đa 1 năm

    # TRUST Lab / CICFlowMeter 4.x (Pkts, Byts, Dst Port) + alias CIC-IDS2017 cũ
    flow_bytes_s = flow_packets_s * 1024.0
    duration_us = token_age_hours * 3_600_000_000.0
    active_max = token_age_hours * 1_000_000.0
    dst_port = ip_count * 100.0
    return {
        # TRUST Lab 2026 / combined model (ưu tiên)
        "Flow Pkts/s": flow_packets_s,
        "Flow Byts/s": flow_bytes_s,
        "Flow Duration": duration_us,
        "Active Max": active_max,
        "Idle Max": 0.0,
        "Tot Fwd Pkts": active_sessions,
        "Tot Bwd Pkts": 0.0,
        "Subflow Fwd Pkts": active_sessions,
        "Dst Port": dst_port,
        # CIC-IDS2017 legacy (model cũ)
        "Flow Packets/s": flow_packets_s,
        "Flow Bytes/s": flow_bytes_s,
        "Fwd Packets/s": flow_packets_s * 0.7,
        "Bwd Packets/s": flow_packets_s * 0.3,
        "Total Fwd Packets": active_sessions,
        "Total Backward Packets": 0.0,
        "Subflow Fwd Packets": active_sessions,
        "Destination Port": dst_port,
    }


def _normalize_result(result: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    risk_raw: float = float(result["risk_score"])
    ai_level: str = str(result["risk_level"])
    base = {
        "risk_score_pct": round(risk_raw * 100),
        "risk_score_raw": risk_raw,
        "risk_level": _LEVEL_MAP.get(ai_level, "medium"),
        "ai_level_raw": ai_level,
        "decision": result["decision"],
        "is_attack": result["is_attack"],
        "explanation": result["explanation"],
        "token_id": metric.get("token_id"),
        "token_type": metric.get("token_type"),
    }
    return enrich_ai_result(base, metric)


async def _remote_health() -> dict[str, Any]:
    # Lần đầu AI có thể đang tải model.pkl (~95MB) — cần timeout dài hơn 10s
    health_timeout = max(LOCKSEND_AI_TIMEOUT, 120.0)
    try:
        async with httpx.AsyncClient(timeout=health_timeout) as client:
            res = await client.get(f"{LOCKSEND_AI_URL}/health", headers=_auth_headers())
            res.raise_for_status()
            data = res.json()
            data["mode"] = "remote"
            data["ai_url"] = LOCKSEND_AI_URL
            return data
    except httpx.HTTPError as exc:
        return {
            "ready": False,
            "mode": "remote",
            "ai_url": LOCKSEND_AI_URL,
            "error": str(exc),
            "hint": "Kiểm tra locksend-ai Online, /health → ready:true, LOCKSEND_AI_API_KEY khớp BE↔AI",
        }


async def health() -> dict[str, Any]:
    if REMOTE_MODE:
        return await _remote_health()
    try:
        _ensure_loaded()
        assert _bundle is not None
        return {
            "ready": True,
            "mode": "local",
            "version": _bundle.get("version", "unknown"),
            "trained_at": _bundle.get("trained_at"),
            "metrics": _bundle.get("metrics", {}),
            "model_path": os.path.join(LOCKSEND_AI_DIR, "models", "model.pkl"),
            "ai_dir": LOCKSEND_AI_DIR,
        }
    except RuntimeError as exc:
        return {
            "ready": False,
            "mode": "local",
            "error": str(exc),
            "ai_dir": LOCKSEND_AI_DIR,
            "hint": f"cd {LOCKSEND_AI_DIR} && python train.py",
        }


async def _remote_analyze_token(metric: dict[str, Any]) -> dict[str, Any]:
    features = _token_metric_to_cic(metric)
    async with httpx.AsyncClient(timeout=LOCKSEND_AI_TIMEOUT) as client:
        res = await client.post(
            f"{LOCKSEND_AI_URL}/analyze",
            json={"features": features},
            headers=_auth_headers(),
        )
        res.raise_for_status()
        return _normalize_result(res.json(), metric)


def _local_analyze_token(metric: dict[str, Any]) -> dict[str, Any]:
    _ensure_loaded()
    assert _bundle is not None
    import pandas as pd
    from predict import analyze_access  # type: ignore[import]

    row = pd.DataFrame([_token_metric_to_cic(metric)])
    return _normalize_result(analyze_access(row, bundle=_bundle), metric)


async def analyze_token(metric: dict[str, Any]) -> dict[str, Any]:
    if REMOTE_MODE:
        return await _remote_analyze_token(metric)
    return _local_analyze_token(metric)


async def analyze_batch(metrics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if REMOTE_MODE:
        features_list = [_token_metric_to_cic(m) for m in metrics]
        try:
            async with httpx.AsyncClient(timeout=LOCKSEND_AI_TIMEOUT) as client:
                res = await client.post(
                    f"{LOCKSEND_AI_URL}/analyze/batch",
                    json={"items": features_list},
                    headers=_auth_headers(),
                )
                res.raise_for_status()
                raw_results = res.json().get("results", [])
        except httpx.HTTPError as exc:
            raise RuntimeError(f"LockSend AI remote error: {exc}") from exc

        results: list[dict[str, Any]] = []
        for metric, raw in zip(metrics, raw_results):
            try:
                results.append(_normalize_result(raw, metric))
            except Exception as exc:
                results.append({
                    "token_id": metric.get("token_id"),
                    "token_type": metric.get("token_type"),
                    "error": str(exc),
                })
        if len(raw_results) < len(metrics):
            for metric in metrics[len(raw_results) :]:
                results.append({
                    "token_id": metric.get("token_id"),
                    "token_type": metric.get("token_type"),
                    "error": "No result from AI service",
                })
        return results

    _ensure_loaded()
    results = []
    for m in metrics:
        try:
            results.append(_local_analyze_token(m))
        except Exception as exc:
            logger.warning("analyze_token failed for %s: %s", m.get("token_id"), exc)
            results.append({
                "token_id": m.get("token_id"),
                "token_type": m.get("token_type"),
                "error": str(exc),
            })
    return results
