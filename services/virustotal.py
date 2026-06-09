"""VirusTotal hash lookup — chỉ SHA-256, không upload file."""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _enabled() -> bool:
    return os.getenv("VIRUSTOTAL_ENABLED", "true").lower() in ("1", "true", "yes")


def _api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def _timeout() -> float:
    return float(os.getenv("VIRUSTOTAL_TIMEOUT", "30"))


def is_configured() -> bool:
    return _enabled() and bool(_api_key())


def _reputation(stats: dict[str, int]) -> str:
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    total = sum(int(v or 0) for v in stats.values())
    if total == 0:
        return "unknown"
    return "clean"


async def lookup_sha256(sha256_hex: str) -> dict[str, Any]:
    if not is_configured():
        raise RuntimeError(
            "VirusTotal chưa cấu hình — đặt VIRUSTOTAL_API_KEY trong backend/.env"
        )

    normalized = sha256_hex.strip().lower()
    if not _SHA256_RE.match(normalized):
        raise ValueError("SHA-256 không hợp lệ (cần 64 ký tự hex)")

    url = f"{VT_API_BASE}/files/{normalized}"
    headers = {"x-apikey": _api_key(), "Accept": "application/json"}

    async with httpx.AsyncClient(timeout=_timeout()) as client:
        res = await client.get(url, headers=headers)

    if res.status_code == 404:
        return {
            "sha256": normalized,
            "known": False,
            "reputation": "unknown",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total_engines": 0,
            "message": "Hash chưa có trong cơ sở dữ liệu VirusTotal.",
            "permalink": f"https://www.virustotal.com/gui/file/{normalized}",
        }

    if res.status_code == 429:
        raise RuntimeError("VirusTotal rate limit — thử lại sau vài phút.")

    if res.status_code >= 400:
        logger.warning("VirusTotal HTTP %s: %s", res.status_code, res.text[:200])
        raise RuntimeError(f"VirusTotal lỗi HTTP {res.status_code}")

    data = res.json().get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = malicious + suspicious + harmless + undetected + int(stats.get("timeout") or 0)

    return {
        "sha256": normalized,
        "known": True,
        "reputation": _reputation(stats),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "message": attrs.get("meaningful_name") or attrs.get("type_description") or "",
        "permalink": f"https://www.virustotal.com/gui/file/{normalized}",
    }
