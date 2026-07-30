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


# Metadata service của cloud provider — luôn chặn, kể cả với AI service self-hosted.
_METADATA_HOSTNAMES = {
    "metadata.azure.internal",
    "metadata.google.internal",
    "instance-data",
}

# Link-local: nơi đặt IMDS (169.254.169.254). Chặn cả khi private range được cho phép.
_LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]


def _normalize_ip(value: str) -> ipaddress._BaseAddress | None:
    """
    Parse IP và gỡ bọc IPv4-mapped IPv6.

    Không có bước unmap, `::ffff:169.254.169.254` sẽ không khớp 169.254.0.0/16
    (so sánh IPv6 với network IPv4 luôn False) → bypass được mọi rule IPv4.
    """
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return mapped
        if getattr(addr, "sixtofour", None):
            return addr.sixtofour
    return addr


def _resolved_ips(host: str) -> list[ipaddress._BaseAddress]:
    """
    Resolve hostname thành danh sách IP đã normalize.

    Bắt buộc phải resolve: dạng IP thập phân ("2130706433") hay hostname trỏ về
    IMDS không thể phát hiện bằng cách so khớp chuỗi hostname.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []  # Không resolve được → httpx sẽ tự lỗi

    out: list[ipaddress._BaseAddress] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = _normalize_ip(str(sockaddr[0]))
        if addr is not None:
            out.append(addr)
    return out


def _resolve_and_check(host: str) -> None:
    """Resolve hostname, từ chối nếu trỏ về private/loopback."""
    for addr in _resolved_ips(host):
        for net in _BLOCKED_NETWORKS:
            if addr.version == net.version and addr in net:
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
    Validate LOCKSEND_AI_URL — cho phép HTTP và private range vì AI service là
    dịch vụ nội bộ self-hosted, nhưng luôn chặn link-local / cloud metadata.

    Khác các guard trên: kiểm tra trên IP đã RESOLVE, không phải chuỗi hostname,
    nên chặn được cả `::ffff:169.254.169.254`, `2130706433` và hostname trỏ IMDS.
    """
    if not url:
        return url
    url = url.strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"LOCKSEND_AI_URL phải là http/https, nhận: {url}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"LOCKSEND_AI_URL thiếu hostname: {url}")
    if host in _METADATA_HOSTNAMES:
        raise ValueError(f"LOCKSEND_AI_URL trỏ tới địa chỉ bị cấm: {host}")

    literal = _normalize_ip(host)
    candidates = [literal] if literal is not None else _resolved_ips(host)

    for addr in candidates:
        for net in _LINK_LOCAL_NETWORKS:
            if addr.version == net.version and addr in net:
                raise ValueError(
                    f"LOCKSEND_AI_URL trỏ tới địa chỉ bị cấm ({addr}): {host}"
                )
    return url
