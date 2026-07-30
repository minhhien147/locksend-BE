"""VirusTotal hash check + Gemini trợ lý — API key chỉ trên server."""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request

import audit
from auth import CurrentUser, require_roles
from services import rate_limit
from schemas.integrations import (
    AssistantChatRequest,
    AssistantChatResponse,
    HashCheckRequest,
    HashCheckResponse,
    IntegrationsStatusResponse,
)
from services import gemini_assistant, virustotal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations", tags=["integrations"])

# A04/A05: hai endpoint dưới gọi API bên thứ ba có quota và có phí. Không throttle
# thì một account bị chiếm đủ để đốt hết quota (DoS) hoặc gây hoá đơn lớn.
_VT_MAX = int(os.getenv("VIRUSTOTAL_MAX_PER_USER", "30"))
_VT_WINDOW = int(os.getenv("VIRUSTOTAL_RATE_WINDOW", "60"))
_CHAT_MAX = int(os.getenv("ASSISTANT_MAX_PER_USER", "15"))
_CHAT_WINDOW = int(os.getenv("ASSISTANT_RATE_WINDOW", "60"))


@router.get("/status", response_model=IntegrationsStatusResponse)
async def integrations_status(
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
):
    """Cho frontend biết tính năng nào đang bật (không lộ API key)."""
    return IntegrationsStatusResponse(
        virustotal=virustotal.is_configured(),
        gemini=gemini_assistant.is_configured(),
        gemini_model=gemini_assistant.get_model() if gemini_assistant.is_configured() else None,
    )


@router.post("/virustotal/hash", response_model=HashCheckResponse)
async def check_file_hash(
    body: HashCheckRequest,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
):
    """
    Tra cứu SHA-256 plaintext trên VirusTotal.
    Client chỉ gửi hash sau khi giải mã — zero-knowledge giữ nguyên.
    """
    rate_limit.check_rate(
        "vt_lookup", current.id,
        limit=_VT_MAX, window=_VT_WINDOW,
        detail=f"Vượt giới hạn tra cứu VirusTotal ({_VT_MAX}/{_VT_WINDOW}s). Thử lại sau.",
    )
    try:
        result = await virustotal.lookup_sha256(body.sha256)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    audit.log_event(
        "integrations.virustotal.lookup",
        user_id=current.id,
        role=current.role,
        sha256_prefix=body.sha256[:12],
        reputation=result.get("reputation"),
        request_id=audit.get_request_id(request),
    )
    return HashCheckResponse(**result)


@router.post("/assistant/chat", response_model=AssistantChatResponse)
async def assistant_chat(
    body: AssistantChatRequest,
    request: Request,
    current: CurrentUser = Depends(require_roles("owner", "recipient", "admin")),
):
    """Trợ lý Gemini — system prompt + tài liệu LockSend."""
    rate_limit.check_rate(
        "assistant_chat", current.id,
        limit=_CHAT_MAX, window=_CHAT_WINDOW,
        detail=f"Vượt giới hạn hỏi trợ lý ({_CHAT_MAX}/{_CHAT_WINDOW}s). Thử lại sau.",
    )
    try:
        history = [{"role": t.role, "content": t.content} for t in body.history]
        reply = await gemini_assistant.chat(body.message, history)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    audit.log_event(
        "integrations.assistant.chat",
        user_id=current.id,
        role=current.role,
        message_len=len(body.message),
        request_id=audit.get_request_id(request),
    )
    return AssistantChatResponse(reply=reply)
