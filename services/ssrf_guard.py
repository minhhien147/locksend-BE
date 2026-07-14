"""
A10 – Server-Side Request Forgery (SSRF)
Validate URL trước khi backend gửi outbound HTTP request.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / Azure IMDS
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Domain whitelist cho từng service (pattern prefix)
_GEMINI_ALLOWED_HOSTS = {"generativelanguage.googleapis.com"}
_VIRUSTOTAL_ALLOWED_HOSTS = {"www.virustotal.com", "virustotal.com"}


def _resolve_and_check(host: str) -> None:
    """Resolve hostname, từ chối nếu trỏ về private/loopback."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return  # Không resolve được → httpx sẽ tự lỗi

    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                raise HTTPException(
                    status_code=422,
                    detail="URL đích không được phép (internal network)",
                )


def validate_url(
    url: str,
    *,
    allowed_hosts: set[str] | None = None,
    require_https: bool = True,
    check_dns: bool = False,
) -> str:
    """
    Validate URL trước khi dùng làm outbound request target.

    Parameters
    ----------
    url           : URL cần kiểm tra (str).
    allowed_hosts : Nếu set, hostname phải nằm trong tập này.
    require_https : Bắt buộc scheme phải là https (mặc định True).
    check_dns     : Resolve DNS và từ chối private IP (mặc định False vì chậm).

    Returns
    -------
    str — URL đã strip, hợp lệ.
    """
    url = url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL không được để trống")

    parsed = urlparse(url)

    if require_https and parsed.scheme.lower() != "https":
        raise HTTPException(status_code=422, detail="Chỉ cho phép HTTPS URL")

    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=422, detail="URL thiếu hostname")

    if allowed_hosts and host not in allowed_hosts:
        raise HTTPException(
            status_code=422,
            detail=f"Host '{host}' không nằm trong danh sách cho phép",
        )

    if check_dns:
        _resolve_and_check(host)

    return url


def validate_gemini_base(url: str) -> str:
    """Validate GEMINI_API_BASE — chỉ cho phép googleapis.com."""
    return validate_url(url, allowed_hosts=_GEMINI_ALLOWED_HOSTS, require_https=True)


def validate_locksend_ai_url(url: str) -> str:
    """
    Validate LOCKSEND_AI_URL — cho phép HTTP (internal), nhưng phải là
    domain/IP không phải cloud metadata endpoint.
    Không dùng allowed_hosts vì AI server có thể self-hosted.
    """
    if not url:
        return url
    url = url.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"LOCKSEND_AI_URL phải là http/https, nhận: {url}")

    host = (parsed.hostname or "").lower()
    # Chặn Azure IMDS và link-local
    if host in ("169.254.169.254", "metadata.azure.internal"):
        raise ValueError(f"LOCKSEND_AI_URL trỏ tới địa chỉ bị cấm: {host}")

    # Cố gắng parse IP để chặn private range nếu cần (check_dns tốn kém hơn)
    try:
        addr = ipaddress.ip_address(host)
        # Chỉ chặn link-local + loopback khi không phải localhost dev
        if addr in ipaddress.ip_network("169.254.0.0/16") or addr == ipaddress.ip_address("::1"):
            raise ValueError(f"LOCKSEND_AI_URL trỏ tới địa chỉ bị cấm: {host}")
    except ValueError as exc:
        if "bị cấm" in str(exc):
            raise
    return url
