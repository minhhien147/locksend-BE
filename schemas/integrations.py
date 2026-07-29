from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class IntegrationsStatusResponse(BaseModel):
    virustotal: bool
    gemini: bool
    gemini_model: str | None = None


class HashCheckRequest(BaseModel):
    sha256: str = Field(min_length=64, max_length=64)


class HashCheckResponse(BaseModel):
    sha256: str
    known: bool
    reputation: Literal["clean", "suspicious", "malicious", "unknown"]
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    total_engines: int
    message: str = ""
    permalink: str | None = None


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=4000)


class AssistantChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    history: list[ChatTurn] = Field(default_factory=list, max_length=20)


class AssistantChatResponse(BaseModel):
    reply: str
