"""
Auto-retrain LockSend AI theo lịch.

Chỉ chạy trong local mode (LOCKSEND_AI_URL không được set).
Train được chạy trong subprocess riêng (CPU-bound, scikit-learn) để không
block event loop và cô lập khỏi tiến trình FastAPI.

Sau khi subprocess hoàn thành, bundle mới được hot-reload vào RAM —
backend không cần restart.

Dùng PostgreSQL advisory lock để đảm bảo chỉ một instance (Railway replica)
chạy train tại một thời điểm.

Env:
    AI_RETRAIN_SCHEDULE_ENABLED   true|false  (mặc định: true)
    AI_RETRAIN_INTERVAL_DAYS      float       (mặc định: 7)
    AI_RETRAIN_STARTUP_DELAY_SEC  int         (mặc định: 300)
    AI_RETRAIN_DATASET            str         (mặc định: auto)
    AI_RETRAIN_MAX_ROWS           int         (mặc định: 120000; 0 = dùng hết)
    AI_RETRAIN_TIMEOUT_SEC        int         (mặc định: 3600 — giới hạn thời gian train)
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import text

from db.session import AsyncSessionLocal

logger = logging.getLogger(__name__)

# ── Cấu hình từ env ───────────────────────────────────────────────────────────

_ENABLED = os.getenv("AI_RETRAIN_SCHEDULE_ENABLED", "true").lower() in (
    "1", "true", "yes",
)
_INTERVAL_DAYS = float(os.getenv("AI_RETRAIN_INTERVAL_DAYS", "7"))
_STARTUP_DELAY_SEC = int(os.getenv("AI_RETRAIN_STARTUP_DELAY_SEC", "300"))
_DATASET = os.getenv("AI_RETRAIN_DATASET", "auto").strip()
_MAX_ROWS = int(os.getenv("AI_RETRAIN_MAX_ROWS", "120000"))
_TIMEOUT_SEC = int(os.getenv("AI_RETRAIN_TIMEOUT_SEC", "3600"))

# Khóa riêng — khác với cleanup lock (83920421)
_ADVISORY_LOCK_ID = 83920422

_task: asyncio.Task[None] | None = None

# ── Đường dẫn đến train.py ────────────────────────────────────────────────────

def _train_script_path() -> Path:
    """Tìm train.py trong locksend-ai/ (monorepo: cạnh backend/)."""
    env_dir = os.getenv("LOCKSEND_AI_DIR", "").strip()
    if env_dir:
        candidate = Path(env_dir) / "train.py"
    else:
        candidate = Path(__file__).resolve().parent.parent.parent / "locksend-ai" / "train.py"
    return candidate.resolve()


# ── Advisory lock ─────────────────────────────────────────────────────────────

async def _try_advisory_lock(db) -> bool:
    row = await db.execute(
        text("SELECT pg_try_advisory_lock(:lock_id)"),
        {"lock_id": _ADVISORY_LOCK_ID},
    )
    return bool(row.scalar())


async def _advisory_unlock(db) -> None:
    await db.execute(
        text("SELECT pg_advisory_unlock(:lock_id)"),
        {"lock_id": _ADVISORY_LOCK_ID},
    )


# ── Subprocess train ──────────────────────────────────────────────────────────

def _build_train_cmd(train_script: Path) -> list[str]:
    cmd = [sys.executable, str(train_script)]
    if _DATASET and _DATASET != "auto":
        cmd += ["--dataset", _DATASET]
    if _MAX_ROWS > 0:
        cmd += ["--max-rows", str(_MAX_ROWS)]
    return cmd


def _run_train_subprocess(train_script: Path) -> dict[str, Any]:
    """
    Chạy train.py đồng bộ trong subprocess (sẽ được bọc asyncio.to_thread).
    Trả về dict chứa returncode, stdout (cuối cùng 4KB), stderr (nếu có lỗi).
    """
    cmd = _build_train_cmd(train_script)
    logger.info("AI retrain subprocess: %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_TIMEOUT_SEC,
        cwd=str(train_script.parent),
    )

    # Chỉ giữ 4KB cuối stdout để log (train.py rất verbose)
    stdout_tail = result.stdout[-4096:] if result.stdout else ""
    return {
        "returncode": result.returncode,
        "stdout_tail": stdout_tail,
        "stderr": result.stderr[-2048:] if result.stderr else "",
    }


# ── Hot-reload bundle ─────────────────────────────────────────────────────────

def _reload_bundle_sync() -> str | None:
    """
    Import locksend_ai và gọi reload_bundle() để nạp pkl mới vào RAM.
    Trả về version string của model mới, hoặc None nếu lỗi.
    """
    try:
        from services import locksend_ai
        bundle = locksend_ai.reload_bundle()
        return str(bundle.get("version", "unknown"))
    except Exception as exc:
        logger.warning("AI hot-reload failed: %s", exc)
        return None


# ── Một lần retrain ───────────────────────────────────────────────────────────

async def run_scheduled_retrain_once() -> dict[str, Any] | None:
    """
    Thực hiện một chu kỳ retrain.
    Trả về None nếu instance khác đang giữ lock hoặc không ở local mode.
    """
    from services.locksend_ai import REMOTE_MODE

    if REMOTE_MODE:
        logger.debug("AI retrain skipped — remote mode; retrain do AI service tự quản lý")
        return None

    train_script = _train_script_path()
    if not train_script.is_file():
        logger.warning(
            "AI retrain skipped — train.py không tìm thấy tại %s. "
            "Set LOCKSEND_AI_DIR nếu cấu trúc thư mục khác.",
            train_script,
        )
        return None

    async with AsyncSessionLocal() as db:
        if not await _try_advisory_lock(db):
            logger.info("AI retrain skipped — instance khác đang giữ advisory lock")
            return None

        try:
            logger.info(
                "AI retrain bắt đầu (dataset=%s, max_rows=%s, timeout=%ss)",
                _DATASET, _MAX_ROWS if _MAX_ROWS > 0 else "unlimited", _TIMEOUT_SEC,
            )

            # Chạy subprocess trong thread pool — không block event loop
            proc_result = await asyncio.to_thread(_run_train_subprocess, train_script)

            if proc_result["returncode"] != 0:
                logger.error(
                    "AI retrain THẤT BẠI (exit=%d).\nstderr: %s\nstdout tail: %s",
                    proc_result["returncode"],
                    proc_result["stderr"],
                    proc_result["stdout_tail"],
                )
                await _advisory_unlock(db)
                return {"status": "failed", **proc_result}

            logger.info("AI retrain subprocess OK. Đang hot-reload model vào RAM …")

            # Hot-reload bundle (chạy đồng bộ nhanh — chỉ pickle.load)
            new_version = await asyncio.to_thread(_reload_bundle_sync)
            if new_version:
                logger.info("AI hot-reload thành công — version=%s", new_version)
            else:
                logger.warning("AI subprocess OK nhưng hot-reload thất bại — model cũ vẫn chạy")

        except subprocess.TimeoutExpired:
            logger.error("AI retrain TIMEOUT sau %ds", _TIMEOUT_SEC)
            await _advisory_unlock(db)
            return {"status": "timeout", "timeout_sec": _TIMEOUT_SEC}
        except Exception as exc:
            logger.exception("AI retrain lỗi không mong đợi: %s", exc)
            await _advisory_unlock(db)
            raise
        else:
            await _advisory_unlock(db)

    return {
        "status": "ok",
        "version": new_version,
        "returncode": proc_result["returncode"],
    }


# ── Vòng lặp nền ──────────────────────────────────────────────────────────────

async def _retrain_loop() -> None:
    await asyncio.sleep(_STARTUP_DELAY_SEC)
    while True:
        try:
            await run_scheduled_retrain_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("AI retrain loop error: %s", exc)
        await asyncio.sleep(_INTERVAL_DAYS * 86400)


# ── Public API ────────────────────────────────────────────────────────────────

def start_scheduled_retrain() -> asyncio.Task[None] | None:
    global _task
    if not _ENABLED:
        logger.info("AI retrain scheduler disabled (AI_RETRAIN_SCHEDULE_ENABLED=false)")
        return None

    from services.locksend_ai import REMOTE_MODE
    if REMOTE_MODE:
        logger.info(
            "AI retrain scheduler disabled — remote mode "
            "(LOCKSEND_AI_URL=%s); retrain do AI service tự quản lý",
            os.getenv("LOCKSEND_AI_URL", ""),
        )
        return None

    _task = asyncio.create_task(_retrain_loop(), name="ai-retrain-scheduler")
    logger.info(
        "AI retrain scheduler started: every %.1f day(s), startup_delay=%ds, "
        "dataset=%s, max_rows=%s",
        _INTERVAL_DAYS,
        _STARTUP_DELAY_SEC,
        _DATASET,
        _MAX_ROWS if _MAX_ROWS > 0 else "unlimited",
    )
    return _task


async def stop_scheduled_retrain(task: asyncio.Task[None] | None) -> None:
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
