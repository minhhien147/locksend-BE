"""
Gán role admin cho một user theo tên đăng nhập (lưu trong cột users.email).

Chạy từ thư mục backend (cần DATABASE_URL trong .env):

    python promote_admin.py <username>

Ví dụ:

    python promote_admin.py minhhien

Sau đó đăng nhập lại để JWT có claim role=admin.
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy import select

from db.models import User
from db.session import AsyncSessionLocal


async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python promote_admin.py <username>")
        sys.exit(1)
    username = sys.argv[1].strip()
    if not username:
        print("Username required.")
        sys.exit(1)

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == username))
        user = result.scalar_one_or_none()
        if user is None:
            print(f"Không tìm thấy user: {username}")
            sys.exit(1)
        user.role = "admin"
        await session.commit()
        print(f"OK — '{username}' đã là admin. Hãy đăng xuất và đăng nhập lại.")


if __name__ == "__main__":
    asyncio.run(main())
