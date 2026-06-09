"""
Gmail email service — gửi cảnh báo bảo mật đến email người dùng.

Hỗ trợ hai backend:
  gmail_apppassword  — Gmail SMTP dùng App Password (đơn giản, khuyến nghị)
  gmail_oauth2       — Gmail SMTP dùng OAuth2 / XOAUTH2 (bảo mật hơn cho production)

Kích hoạt bằng cách set EMAIL_ENABLED=true trong .env.
Không cài thêm package nào cho App Password (dùng smtplib tích hợp sẵn).
Để dùng OAuth2 cần: pip install google-auth
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)

# ── Cấu hình từ biến môi trường ───────────────────────────────────────────────

EMAIL_ENABLED: bool = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
EMAIL_BACKEND: str = os.getenv("EMAIL_BACKEND", "gmail_apppassword")

# Backend 1 — App Password
GMAIL_USER: str = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD: str = os.getenv("GMAIL_APP_PASSWORD", "").replace(" ", "")

# Backend 2 — OAuth2
GMAIL_CLIENT_ID: str = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET: str = os.getenv("GMAIL_CLIENT_SECRET", "")
GMAIL_REFRESH_TOKEN: str = os.getenv("GMAIL_REFRESH_TOKEN", "")

# Địa chỉ gửi đi (From)
GMAIL_FROM: str = os.getenv("GMAIL_FROM", GMAIL_USER)

_SMTP_HOST = "smtp.gmail.com"
_SMTP_PORT = 587

# ── Kiểm tra cấu hình ─────────────────────────────────────────────────────────


def is_configured() -> bool:
    if not EMAIL_ENABLED:
        return False
    if EMAIL_BACKEND == "gmail_oauth2":
        return bool(
            GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET and GMAIL_REFRESH_TOKEN and GMAIL_FROM
        )
    if EMAIL_BACKEND == "gmail_apppassword":
        return bool(GMAIL_USER and GMAIL_APP_PASSWORD)
    return False


# ── OAuth2 helper ──────────────────────────────────────────────────────────────


def _refresh_oauth2_token() -> str:
    """Làm mới và trả về access_token qua google-auth."""
    try:
        from google.auth.transport.requests import Request  # type: ignore[import-untyped]
        from google.oauth2.credentials import Credentials  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "google-auth chưa được cài. Chạy: pip install google-auth"
        ) from exc

    creds = Credentials(
        token=None,
        refresh_token=GMAIL_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GMAIL_CLIENT_ID,
        client_secret=GMAIL_CLIENT_SECRET,
        scopes=["https://mail.google.com/"],
    )
    creds.refresh(Request())
    return creds.token  # type: ignore[return-value]


def _build_xoauth2_b64(user_email: str, access_token: str) -> str:
    raw = f"user={user_email}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode()).decode()


# ── SMTP send helpers (synchronous — chạy trong thread executor) ───────────────


def _send_apppassword(to_email: str, msg: MIMEMultipart) -> None:
    ctx = ssl.create_default_context()
    with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ctx)
        smtp.ehlo()
        smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        smtp.sendmail(GMAIL_FROM or GMAIL_USER, to_email, msg.as_string())


def _send_oauth2(to_email: str, msg: MIMEMultipart) -> None:
    access_token = _refresh_oauth2_token()
    xoauth2 = _build_xoauth2_b64(GMAIL_FROM, access_token)
    ctx = ssl.create_default_context()
    with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ctx)
        smtp.ehlo()
        code, _ = smtp.docmd("AUTH", f"XOAUTH2 {xoauth2}")
        if code != 235:
            raise smtplib.SMTPAuthenticationError(code, b"XOAUTH2 auth failed")
        smtp.sendmail(GMAIL_FROM, to_email, msg.as_string())


def _dispatch_sync(to_email: str, subject: str, html_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = GMAIL_FROM or GMAIL_USER
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    if EMAIL_BACKEND == "gmail_oauth2":
        _send_oauth2(to_email, msg)
    else:
        _send_apppassword(to_email, msg)


# ── HTML email template ────────────────────────────────────────────────────────

_ALERT_LABELS: dict[str, str] = {
    "multi_ip_access": "Truy cập file từ nhiều IP",
    "keypair_expiring": "Keypair sắp hết hạn",
    "keypair_expired": "Keypair đã hết hạn",
    "admin_notify": "Thông báo từ Admin",
}

_BADGE_COLORS: dict[str, str] = {
    "multi_ip_access": "#f59e0b",
    "keypair_expiring": "#f97316",
    "keypair_expired": "#ef4444",
    "admin_notify": "#3b82f6",
}


def _build_html(
    title: str,
    message: str,
    *,
    file_name: str | None,
    alert_type: str,
) -> str:
    file_row = ""
    if file_name:
        file_row = f"""
        <tr>
          <td style="padding:4px 24px 8px;">
            <span style="font-size:12px;color:#6b7280;">File liên quan:&nbsp;</span>
            <strong style="color:#1f2937;">{file_name}</strong>
          </td>
        </tr>"""

    badge_color = _BADGE_COLORS.get(alert_type, "#6b7280")
    msg_html = message.replace("\n", "<br>")

    return f"""<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:32px 0;">
    <tr><td align="center">
      <table width="540" cellpadding="0" cellspacing="0"
        style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.10);">
        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#1e3a5f 0%,#2563eb 100%);padding:28px 24px;text-align:center;">
            <div style="font-size:24px;font-weight:700;color:#fff;letter-spacing:0.5px;">&#128274; LockSend</div>
            <div style="color:#bfdbfe;font-size:13px;margin-top:4px;">Hệ thống chia sẻ file mã hóa an toàn</div>
          </td>
        </tr>
        <!-- Badge -->
        <tr>
          <td style="padding:20px 24px 6px;">
            <span style="display:inline-block;background:{badge_color};color:#fff;
              font-size:11px;font-weight:600;padding:4px 12px;border-radius:20px;
              text-transform:uppercase;letter-spacing:0.5px;">Cảnh báo bảo mật</span>
          </td>
        </tr>
        <!-- Title -->
        <tr>
          <td style="padding:8px 24px 4px;">
            <h2 style="margin:0;color:#1f2937;font-size:18px;font-weight:700;">{title}</h2>
          </td>
        </tr>
        {file_row}
        <!-- Message -->
        <tr>
          <td style="padding:10px 24px 20px;">
            <p style="margin:0;color:#374151;font-size:14px;line-height:1.75;">{msg_html}</p>
          </td>
        </tr>
        <!-- CTA -->
        <tr>
          <td style="padding:16px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;text-align:center;">
            <a href="#"
              style="display:inline-block;background:#2563eb;color:#fff;padding:11px 28px;
                border-radius:8px;font-size:13px;font-weight:600;text-decoration:none;">
              Xem chi tiết tại LockSend
            </a>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="padding:14px 24px;text-align:center;">
            <p style="margin:0;color:#9ca3af;font-size:11px;">
              Email này được gửi tự động từ hệ thống LockSend. Vui lòng không trả lời email này.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _build_otp_html(code: str, expires_minutes: int) -> str:
    return f"""<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 0;">
    <tr><td align="center">
      <table width="480" style="background:#fff;border-radius:12px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
        <tr><td style="text-align:center;">
          <div style="font-size:22px;font-weight:700;color:#1e3a5f;">&#128274; LockSend</div>
          <p style="color:#6b7280;font-size:14px;margin:16px 0 24px;">Mã xác minh email của bạn</p>
          <div style="font-size:32px;font-weight:700;letter-spacing:8px;color:#2563eb;padding:16px 24px;background:#eff6ff;border-radius:8px;display:inline-block;">{code}</div>
          <p style="color:#6b7280;font-size:13px;margin-top:24px;">Mã hết hạn sau <strong>{expires_minutes} phút</strong>.</p>
          <p style="color:#9ca3af;font-size:11px;margin-top:16px;">Nếu bạn không yêu cầu mã này, hãy bỏ qua email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


async def send_verification_otp_email(
    to_email: str,
    code: str,
    *,
    expires_minutes: int = 15,
) -> None:
    """Gửi mã OTP xác minh email."""
    if not is_configured():
        logger.warning("Email not configured — cannot send verification OTP to %s", to_email)
        return

    subject = f"[LockSend] Mã xác minh: {code}"
    html_body = _build_otp_html(code, expires_minutes)
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _dispatch_sync, to_email, subject, html_body)
        logger.info("Verification OTP sent to %s", to_email)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to send verification OTP to %s: %s", to_email, exc)
        raise


# ── Public API ─────────────────────────────────────────────────────────────────


async def send_security_alert_email(
    to_email: str,
    alert_type: str,
    title: str,
    message: str,
    *,
    file_name: str | None = None,
) -> None:
    """Gửi email cảnh báo bảo mật bất đồng bộ (chạy SMTP trong thread pool).

    Hàm này không raise exception — lỗi chỉ được log ở mức WARNING.
    """
    if not is_configured():
        return

    label = _ALERT_LABELS.get(alert_type, "Cảnh báo bảo mật")
    subject = f"[LockSend] {label}"
    html_body = _build_html(title, message, file_name=file_name, alert_type=alert_type)

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _dispatch_sync, to_email, subject, html_body)
        logger.info(
            "Alert email sent | to=%s type=%s",
            to_email,
            alert_type,
        )
    except smtplib.SMTPAuthenticationError as exc:
        logger.warning(
            "Gmail auth failed (check GMAIL_USER/GMAIL_APP_PASSWORD or OAuth2 token): %s", exc
        )
    except smtplib.SMTPException as exc:
        logger.warning("SMTP error sending alert email to %s: %s", to_email, exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Unexpected error sending alert email to %s: %s", to_email, exc)
