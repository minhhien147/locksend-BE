"""
Google Sign-In — xác minh ID token từ Google Identity Services (frontend).
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass

import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

GOOGLE_OAUTH_ENABLED: bool = os.getenv("GOOGLE_OAUTH_ENABLED", "false").lower() == "true"
GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")

# JWKS Google — verify chữ ký cục bộ, không gửi id_token lên query string
# (tránh lộ token trong proxy/access logs / Referer).
_GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
_GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

_jwk_client: PyJWKClient | None = None


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


def _get_jwk_client() -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(_GOOGLE_JWKS_URL, cache_keys=True)
    return _jwk_client


def _decode_google_id_token(credential: str) -> dict:
    key = _get_jwk_client().get_signing_key_from_jwt(credential)
    return jwt.decode(
        credential,
        key.key,
        algorithms=["RS256"],
        audience=GOOGLE_CLIENT_ID,
        issuer=_GOOGLE_ISSUERS,
        options={"require": ["exp", "iat", "sub", "email"]},
    )


async def verify_id_token(credential: str) -> GoogleUserInfo:
    """Xác minh JWT id_token từ Google (JWKS), trả về thông tin user."""
    if not is_enabled():
        raise ValueError("Google OAuth chưa được bật")

    try:
        # PyJWKClient I/O đồng bộ — chạy trong thread để không block event loop.
        data = await asyncio.to_thread(_decode_google_id_token, credential)
    except jwt.PyJWTError as exc:
        logger.warning("Google ID token verify failed: %s", exc)
        raise ValueError("Token Google không hợp lệ") from exc
    except Exception as exc:
        logger.warning("Google JWKS fetch/verify failed: %s", exc)
        raise ValueError("Token Google không hợp lệ") from exc

    email_verified = data.get("email_verified")
    if email_verified is not True and str(email_verified).lower() != "true":
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
