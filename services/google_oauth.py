"""
Google Sign-In — xác minh ID token từ Google Identity Services (frontend).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

GOOGLE_OAUTH_ENABLED: bool = os.getenv("GOOGLE_OAUTH_ENABLED", "false").lower() == "true"
GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")

_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"


@dataclass(frozen=True)
class GoogleUserInfo:
    sub: str
    email: str
    name: str | None
    picture: str | None


def is_enabled() -> bool:
    return GOOGLE_OAUTH_ENABLED and bool(GOOGLE_CLIENT_ID)


def public_config() -> dict[str, str | bool]:
    return {
        "enabled": is_enabled(),
        "client_id": GOOGLE_CLIENT_ID if is_enabled() else "",
    }


def google_external_id(sub: str) -> str:
    return f"google:{sub}"


async def verify_id_token(credential: str) -> GoogleUserInfo:
    """Xác minh JWT id_token từ Google, trả về thông tin user."""
    if not is_enabled():
        raise ValueError("Google OAuth chưa được bật")

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(_TOKENINFO_URL, params={"id_token": credential})

    if resp.status_code != 200:
        logger.warning("Google tokeninfo failed: %s", resp.status_code)
        raise ValueError("Token Google không hợp lệ")

    data = resp.json()

    if data.get("aud") != GOOGLE_CLIENT_ID:
        raise ValueError("Token Google không khớp client_id")

    if data.get("email_verified") != "true":
        raise ValueError("Email Google chưa được xác minh")

    email = (data.get("email") or "").strip().lower()
    sub = (data.get("sub") or "").strip()
    if not email or not sub:
        raise ValueError("Token Google thiếu email hoặc sub")

    return GoogleUserInfo(
        sub=sub,
        email=email,
        name=(data.get("name") or "").strip() or None,
        picture=(data.get("picture") or "").strip() or None,
    )
