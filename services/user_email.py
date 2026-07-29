"""Kiểm tra và chuẩn hóa email user (nhận cảnh báo bảo mật)."""

from __future__ import annotations

from email_validator import EmailNotValidError, validate_email


def normalize_email(raw: str) -> str:
    return raw.strip().lower()


def is_valid_alert_email(email: str | None) -> bool:
    """Email hợp lệ để gửi cảnh báo (định dạng @, không phải username kiểu 'admin')."""
    if not email or not str(email).strip():
        return False
    try:
        validate_email(str(email).strip(), check_deliverability=False)
        return True
    except EmailNotValidError:
        return False
