"""
Mô phỏng dấu hiệu tấn công trên JWT token (dev/test only).

Tạo dữ liệu thật trong DB:
  - Nhiều RefreshToken active từ IP khác nhau
  - Refresh token reuse pattern (revoked + replaced)
  - Hàng loạt TokenAccessLog (tần suất cao, nhiều IP)

Sau đó in metrics rule engine + kết quả LockSend AI.

Usage:
  cd backend
  python scripts/simulate_token_attack.py toilahien147@gmail.com
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from db.models import RefreshToken, TokenAccessLog, User  # noqa: E402
from db.session import AsyncSessionLocal  # noqa: E402
from services import locksend_ai, token_security  # noqa: E402


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/simulate_token_attack.py <user_email>")
        sys.exit(1)

    email = sys.argv[1].strip().lower()
    now = _utc_now()

    async with AsyncSessionLocal() as db:
        user = (
            await db.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        if not user:
            print(f"Không tìm thấy user: {email}")
            sys.exit(1)

        uid = user.id
        print(f"Target: {email} (id={uid[:8]}…)")

        # ── 1. Nhiều session active từ IP khác nhau (botnet / credential stuffing) ──
        fake_ips = [f"203.0.113.{i}" for i in range(1, 8)]  # 7 IP
        for i, ip in enumerate(fake_ips):
            db.add(
                RefreshToken(
                    jti=str(uuid.uuid4()),
                    user_id=uid,
                    expires_at=now + timedelta(days=7),
                    ip_address=ip,
                    user_agent=f"AttackBot/1.{i}",
                    created_at=now - timedelta(hours=i),
                )
            )

        # ── 2. Refresh token reuse (token cũ bị thay nhưng vẫn dùng lại) ──
        old_jti = str(uuid.uuid4())
        new_jti = str(uuid.uuid4())
        db.add(
            RefreshToken(
                jti=old_jti,
                user_id=uid,
                expires_at=now + timedelta(days=7),
                revoked_at=now - timedelta(minutes=30),
                replaced_by_jti=new_jti,
                ip_address="198.51.100.99",
                user_agent="SuspiciousClient/2.0",
                created_at=now - timedelta(hours=2),
            )
        )

        # ── 3. Burst access log — >100 req/giờ, nhiều IP ──
        token_ref = f"sim-{uid[:8]}"
        access_count = 500
        for n in range(access_count):
            db.add(
                TokenAccessLog(
                    token_type="jwt",
                    token_ref=token_ref,
                    user_id=uid,
                    ip_address=fake_ips[n % len(fake_ips)],
                    user_agent="AttackBot/1.0",
                    endpoint="/files/my-files",
                    http_method="GET",
                    status_code=200,
                    created_at=now - timedelta(minutes=n % 60),
                )
            )

        await db.commit()
        print(f"Inserted: 7 active sessions, 1 reuse pattern, {access_count} access logs")

        metrics = await token_security.get_jwt_token_metrics(db, user_id=uid)
        if not metrics:
            print("Không có metrics JWT sau simulate.")
            sys.exit(1)

        m = metrics[0]
        print("\n── Rule engine ──")
        print(f"  risk_score: {m['risk_score']}/100 ({m['risk_level']})")
        print(f"  recommendation: {m['recommendation']}")
        print(f"  active_sessions: {m['active_sessions']}, ip_count: {m['ip_count']}")
        print(f"  accesses_per_hour: {m['accesses_per_hour']}")
        print(f"  reuse_detected: {m['reuse_detected']}")
        for r in m.get("reasons") or []:
            print(f"    • {r}")

        ai = await locksend_ai.analyze_token(m)
        print("\n── LockSend AI ──")
        print(f"  score: {ai.get('risk_score_pct')}% ({ai.get('ai_level_raw')})")
        print(f"  decision: {ai.get('decision')}, is_attack: {ai.get('is_attack')}")
        print(f"  agreement: {ai.get('agreement', {}).get('label')}")
        print(f"  summary: {ai.get('summary_vi')}")
        badges = ai.get("behavior_badges") or []
        if badges:
            print(f"  badges: {', '.join(b['label'] for b in badges)}")

        print("\n── Next steps ──")
        print("  1. Admin → Token Security → Phân tích AI")
        print(f"  2. Hoặc POST /auth/admin/token-security/ai/analyze/token")
        print(f'     body: {{"token_type":"jwt","token_id":"{m["user_id"]}"}}')


if __name__ == "__main__":
    asyncio.run(main())
