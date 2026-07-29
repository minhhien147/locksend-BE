"""
Tạo tài khoản admin mới, hoặc nếu username đã tồn tại thì gán role admin
và (theo mặc định) đặt lại mật khẩu.

Chạy từ thư mục backend (cần DATABASE_URL trong .env):

    python create_admin.py myadmin --generate
    python create_admin.py myadmin --password "YourLongPass1"
    python create_admin.py owner1 --password "NewPass12" --keep-role

Không commit mật khẩu vào git; dùng --generate cho môi trường local.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import string
import uuid

import bcrypt
from sqlalchemy import select

from db.models import User
from db.session import AsyncSessionLocal


def _hash_password(plain: str) -> str:
    # Trùng định dạng với passlib/bcrypt trong auth_router (chuỗi bcrypt ASCII)
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap hoặc reset tài khoản admin")
    parser.add_argument(
        "username",
        nargs="?",
        default="admin",
        help="Tên đăng nhập (mặc định: admin)",
    )
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--password",
        "-p",
        metavar="PLAIN",
        help="Mật khẩu tối thiểu 8 ký tự",
    )
    g.add_argument(
        "--generate",
        action="store_true",
        help="Sinh mật khẩu ngẫu nhiên và in ra stdout (một lần)",
    )
    parser.add_argument(
        "--keep-role",
        action="store_true",
        help="User da ton tai: chi doi mat khau, khong gan role admin",
    )
    args = parser.parse_args()

    plain = args.password if args.password else _random_password()
    if len(plain) < 8:
        print("Mật khẩu phải có ít nhất 8 ký tự.")
        raise SystemExit(1)

    username = args.username.strip()
    if not username:
        print("Username không được để trống.")
        raise SystemExit(1)

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.email == username))
        user = result.scalar_one_or_none()
        hashed = _hash_password(plain)

        if user is None:
            user = User(
                external_id=str(uuid.uuid4()),
                email=username,
                display_name=username,
                role="admin",
                password_hash=hashed,
            )
            session.add(user)
            await session.commit()
            action = "created"
        else:
            if not args.keep_role:
                user.role = "admin"
            user.password_hash = hashed
            await session.commit()
            action = "updated"

    print(f"OK — {action} for user {username}.")
    print(f"  Username: {username}")
    if args.generate:
        print(f"  Password: {plain}")
        print("  (Save now; shown once.)")
    else:
        print("  Password: (set via --password)")
    print("Sign in on the web with the credentials above.")


if __name__ == "__main__":
    asyncio.run(main())
