"""
Tạo hàng loạt tài khoản load test (email đã verify) và xuất CSV cho JMeter/k6.

Chạy từ thư mục backend (cần DATABASE_URL trỏ DB production/staging):

    python scripts/create_loadtest_users.py --count 100
    python scripts/create_loadtest_users.py --count 100 --password "LoadTest123!"
    python scripts/create_loadtest_users.py --count 100 --output loadtest_users.csv

Railway (khuyến nghị — dùng đúng venv của service):

    railway link
    railway run python scripts/create_loadtest_users.py --count 100

CSV output (username,password) dùng với Azure Load Testing JMX hoặc k6.
Không commit file CSV vào git.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import uuid
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select

from db.models import User
from db.session import AsyncSessionLocal
from routers._auth_helpers import hash_password
from services.user_email import normalize_email

DEFAULT_DOMAIN = "loadtest.com"
DEFAULT_PASSWORD = "LoadTest123!"


def _email_for_index(prefix: str, index: int, domain: str) -> str:
    return normalize_email(f"{prefix}{index:03d}@{domain}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Tạo N tài khoản load test (owner, email verified)")
    parser.add_argument("--count", type=int, default=100, help="Số tài khoản (mặc định: 100)")
    parser.add_argument("--prefix", default="loaduser", help="Tiền tố email (loaduser001@...)")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN, help=f"Domain email (mặc định: {DEFAULT_DOMAIN})")
    parser.add_argument(
        "--password",
        "-p",
        default=DEFAULT_PASSWORD,
        help="Mật khẩu chung cho tất cả user (tối thiểu 8 ký tự)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="loadtest_users.csv",
        help="File CSV xuất ra (username,password)",
    )
    parser.add_argument(
        "--reset-existing",
        action="store_true",
        help="User đã tồn tại: đặt lại mật khẩu và verify email",
    )
    args = parser.parse_args()

    if args.count < 1 or args.count > 1000:
        print("count phải từ 1 đến 1000.")
        raise SystemExit(1)
    if len(args.password) < 8:
        print("Mật khẩu phải có ít nhất 8 ký tự.")
        raise SystemExit(1)

    hashed = hash_password(args.password)
    now = datetime.now(timezone.utc)
    created = updated = skipped = 0
    rows: list[tuple[str, str]] = []

    async with AsyncSessionLocal() as session:
        for i in range(1, args.count + 1):
            email = _email_for_index(args.prefix, i, args.domain)
            result = await session.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()

            if user is None:
                user = User(
                    external_id=str(uuid.uuid4()),
                    email=email,
                    display_name=f"Load Test {i:03d}",
                    role="owner",
                    password_hash=hashed,
                    email_verified_at=now,
                )
                session.add(user)
                created += 1
            elif args.reset_existing:
                user.password_hash = hashed
                user.email_verified_at = now
                if user.role not in ("owner", "admin"):
                    user.role = "owner"
                updated += 1
            else:
                if user.email_verified_at is None:
                    user.email_verified_at = now
                    updated += 1
                else:
                    skipped += 1

            rows.append((email, args.password))

        await session.commit()

    out_path = Path(args.output)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password"])
        writer.writerows(rows)

    print(f"OK — created={created}, updated={updated}, skipped={skipped}")
    print(f"  Emails: {_email_for_index(args.prefix, 1, args.domain)} … {_email_for_index(args.prefix, args.count, args.domain)}")
    print(f"  Password: {args.password}")
    print(f"  CSV: {out_path.resolve()}")
    print("  (Không commit CSV vào git.)")


if __name__ == "__main__":
    asyncio.run(main())
