"""Gemini trợ lý LockSend — system prompt + tài liệu project, không fine-tune."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

from services.assistant_knowledge import (
    LOCKSEND_ASSISTANT_KNOWLEDGE,
    LOCKSEND_ASSISTANT_RULES,
)
from services.ssrf_guard import validate_gemini_base

logger = logging.getLogger(__name__)

MAX_HISTORY_TURNS = 10
_MAX_ATTEMPTS = 4
_RETRYABLE_STATUS = frozenset({429, 503})


def _enabled() -> bool:
    return os.getenv("GEMINI_ENABLED", "true").lower() in ("1", "true", "yes")


def _api_key() -> str:
    return os.getenv("GEMINI_API_KEY", "").strip()


def get_model() -> str:
    return os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()


def _timeout() -> float:
    return float(os.getenv("GEMINI_TIMEOUT", "60"))


def _api_base() -> str:
    raw = os.getenv(
        "GEMINI_API_BASE",
        "https://generativelanguage.googleapis.com/v1beta",
    ).rstrip("/")
    # A10: Chỉ cho phép googleapis.com
    try:
        return validate_gemini_base(raw)
    except Exception as exc:
        logger.error("SECURITY A10: GEMINI_API_BASE bị từ chối — %s", exc)
        return "https://generativelanguage.googleapis.com/v1beta"


def is_configured() -> bool:
    return _enabled() and bool(_api_key())


def _system_instruction() -> str:
    return f"{LOCKSEND_ASSISTANT_RULES}\n\n---\n\n{LOCKSEND_ASSISTANT_KNOWLEDGE}"


def _build_contents(history: list[dict[str, str]], message: str) -> list[dict[str, Any]]:
    contents: list[dict[str, Any]] = []
    for turn in history[-MAX_HISTORY_TURNS:]:
        role = turn.get("role", "user")
        text = (turn.get("content") or "").strip()
        if not text:
            continue
        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": text}]})
    contents.append({"role": "user", "parts": [{"text": message.strip()}]})
    return contents


async def chat(message: str, history: list[dict[str, str]] | None = None) -> str:
    if not is_configured():
        raise RuntimeError(
            "Gemini chưa cấu hình — đặt GEMINI_API_KEY trong backend/.env"
        )

    text = message.strip()
    if not text:
        raise ValueError("Tin nhắn trống")
    if len(text) > 4000:
        raise ValueError("Tin nhắn quá dài (tối đa 4000 ký tự)")

    model = get_model()
    url = f"{_api_base()}/models/{model}:generateContent"
    payload = {
        "systemInstruction": {"parts": [{"text": _system_instruction()}]},
        "contents": _build_contents(history or [], text),
        "generationConfig": {
            "temperature": 0.35,
            "maxOutputTokens": 1024,
        },
    }

    res: httpx.Response | None = None
    async with httpx.AsyncClient(timeout=_timeout()) as client:
        for attempt in range(_MAX_ATTEMPTS):
            res = await client.post(
                url,
                params={"key": _api_key()},
                json=payload,
            )
            if res.status_code not in _RETRYABLE_STATUS or attempt == _MAX_ATTEMPTS - 1:
                break
            wait = 1.0 * (2**attempt)
            logger.info(
                "Gemini HTTP %s — retry %s/%s sau %.0fs",
                res.status_code,
                attempt + 2,
                _MAX_ATTEMPTS,
                wait,
            )
            await asyncio.sleep(wait)

    assert res is not None

    if res.status_code == 429:
        raise RuntimeError("Gemini rate limit — thử lại sau.")

    if res.status_code == 503:
        raise RuntimeError("Gemini đang quá tải — thử lại sau vài giây.")

    if res.status_code >= 400:
        logger.warning("Gemini HTTP %s: %s", res.status_code, res.text[:300])
        detail = res.text[:200] if res.text else str(res.status_code)
        raise RuntimeError(f"Gemini lỗi: {detail}")

    body = res.json()
    candidates = body.get("candidates") or []
    if not candidates:
        raise RuntimeError("Gemini không trả lời — thử câu hỏi khác.")

    parts = (candidates[0].get("content") or {}).get("parts") or []
    reply = "".join(p.get("text", "") for p in parts).strip()
    if not reply:
        raise RuntimeError("Gemini trả lời rỗng.")
    return reply
