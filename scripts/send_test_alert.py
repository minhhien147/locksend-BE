"""Gửi email cảnh báo test tới một địa chỉ (dùng cấu hình Gmail trong .env)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# backend/ on path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from services import email_service  # noqa: E402


async def main() -> None:
    to_email = sys.argv[1] if len(sys.argv) > 1 else "hiennmce182232@fpt.edu.vn"
    if not email_service.is_configured():
        print("EMAIL_ENABLED=false or missing GMAIL_* — cannot send.")
        sys.exit(1)

    print(f"Sending test alert to {to_email} ...")
    await email_service.send_security_alert_email(
        to_email=to_email,
        alert_type="admin_notify",
        title="Cảnh báo bảo mật từ admin (test)",
        message=(
            "Đây là email test từ LockSend. Admin đã gửi cảnh báo thử nghiệm "
            "để xác nhận hộp thư nhận cảnh báo hoạt động đúng."
        ),
        file_name="test-file.pdf",
    )
    print("Done — check inbox (and Spam) for the alert email.")


if __name__ == "__main__":
    asyncio.run(main())
