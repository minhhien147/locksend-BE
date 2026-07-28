"""
Dọn dữ liệu test do simulate_token_security_anomalies.py tạo ra.

Xóa:
  - RefreshToken giả (AttackBot / ReuseProbe / MassRevokeProbe)
  - TokenAccessLog giả cho JWT/SAS
  - SasTokenRecord giả (theo user_agent mô phỏng)
  - TokenSecurityAlert / TokenAiScoreSnapshot liên quan đến token test
  - File placeholder synthetic nếu script seed đã tự tạo

Usage:
  cd backend
  python scripts/cleanup_token_security_anomalies.py user@example.com
  python scripts/cleanup_token_security_anomalies.py user@example.com --dry-run
  python scripts/cleanup_token_security_anomalies.py user@example.com --keep-ai-artifacts
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import delete, select

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from db.models import (  # noqa: E402
    File,
    RefreshToken,
    SasTokenRecord,
    TokenAccessLog,
    TokenAiScoreSnapshot,
    TokenSecurityAlert,
    User,
)
from db.session import AsyncSessionLocal  # noqa: E402

SIM_SOURCE = "simulate_token_security_anomalies.py"
JWT_LOG_REF_PREFIX = "jwt-sim-"
JWT_SNAPSHOT_REF_PREFIX = "jwt:"
JWT_REFRESH_AGENTS = ("AttackBot/", "ReuseProbe/", "MassRevokeProbe/")
SAS_SIM_AGENTS = (
    "DownloaderSwarm/5.2",
    "ExpiredReplay/3.4",
    "LongLivedMirror/1.9",
)


async def _get_user(db, email: str) -> User | None:
    return (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cleanup dữ liệu test do simulate_token_security_anomalies.py tạo ra"
    )
    parser.add_argument("user_email", help="Email user mục tiêu")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Chỉ in số lượng sẽ xóa, không commit",
    )
    parser.add_argument(
        "--keep-ai-artifacts",
        action="store_true",
        help="Giữ lại TokenAiScoreSnapshot và TokenSecurityAlert",
    )
    args = parser.parse_args()

    email = args.user_email.strip().lower()

    async with AsyncSessionLocal() as db:
        user = await _get_user(db, email)
        if not user:
            print(f"Không tìm thấy user: {email}")
            sys.exit(1)

        uid = user.id
        jwt_log_ref = f"{JWT_LOG_REF_PREFIX}{uid[:8]}"
        jwt_snapshot_ref = f"{JWT_SNAPSHOT_REF_PREFIX}{uid[:8]}"

        files = (
            await db.execute(select(File).where(File.owner_id == uid))
        ).scalars().all()
        fake_file_ids = [
            f.id
            for f in files
            if isinstance(f.metadata_json, dict)
            and f.metadata_json.get("source") == SIM_SOURCE
        ]

        seeded_sas_records = (
            await db.execute(
                select(SasTokenRecord).where(
                    SasTokenRecord.user_id == uid,
                    SasTokenRecord.user_agent.in_(SAS_SIM_AGENTS),
                )
            )
        ).scalars().all()
        sas_token_ids = [r.token_id for r in seeded_sas_records]

        refresh_tokens = (
            await db.execute(select(RefreshToken).where(RefreshToken.user_id == uid))
        ).scalars().all()
        refresh_ids = [
            rt.jti
            for rt in refresh_tokens
            if any((rt.user_agent or "").startswith(prefix) for prefix in JWT_REFRESH_AGENTS)
        ]

        jwt_log_count = (
            await db.execute(
                select(TokenAccessLog).where(
                    TokenAccessLog.user_id == uid,
                    TokenAccessLog.token_ref == jwt_log_ref,
                )
            )
        ).scalars().all()
        jwt_log_ids = [row.id for row in jwt_log_count]

        sas_log_ids: list[str] = []
        if sas_token_ids:
            sas_logs = (
                await db.execute(
                    select(TokenAccessLog).where(TokenAccessLog.token_ref.in_(sas_token_ids))
                )
            ).scalars().all()
            sas_log_ids = [row.id for row in sas_logs]

        snapshot_ids: list[str] = []
        alert_ids: list[str] = []
        if not args.keep_ai_artifacts:
            snapshot_refs = [jwt_snapshot_ref, *sas_token_ids]
            alert_refs = [jwt_log_ref, *sas_token_ids]

            if snapshot_refs:
                snaps = (
                    await db.execute(
                        select(TokenAiScoreSnapshot).where(
                            TokenAiScoreSnapshot.token_ref.in_(snapshot_refs)
                        )
                    )
                ).scalars().all()
                snapshot_ids = [row.id for row in snaps]

            if alert_refs:
                alerts = (
                    await db.execute(
                        select(TokenSecurityAlert).where(
                            TokenSecurityAlert.token_ref.in_(alert_refs)
                        )
                    )
                ).scalars().all()
                alert_ids = [row.id for row in alerts]

        print(f"Target user: {email} (id={uid})")
        print("Sẽ dọn:")
        print(f"  RefreshToken giả: {len(refresh_ids)}")
        print(f"  JWT access logs giả: {len(jwt_log_ids)}")
        print(f"  SAS records giả: {len(sas_token_ids)}")
        print(f"  SAS access logs giả: {len(sas_log_ids)}")
        print(f"  File placeholder synthetic: {len(fake_file_ids)}")
        if not args.keep_ai_artifacts:
            print(f"  AI snapshots liên quan: {len(snapshot_ids)}")
            print(f"  AI alerts liên quan: {len(alert_ids)}")

        if args.dry_run:
            print("\nDry-run mode: không xóa gì cả.")
            return

        if alert_ids:
            await db.execute(
                delete(TokenSecurityAlert).where(TokenSecurityAlert.id.in_(alert_ids))
            )
        if snapshot_ids:
            await db.execute(
                delete(TokenAiScoreSnapshot).where(TokenAiScoreSnapshot.id.in_(snapshot_ids))
            )
        if sas_log_ids:
            await db.execute(
                delete(TokenAccessLog).where(TokenAccessLog.id.in_(sas_log_ids))
            )
        if jwt_log_ids:
            await db.execute(
                delete(TokenAccessLog).where(TokenAccessLog.id.in_(jwt_log_ids))
            )
        if sas_token_ids:
            await db.execute(
                delete(SasTokenRecord).where(SasTokenRecord.token_id.in_(sas_token_ids))
            )
        if refresh_ids:
            await db.execute(
                delete(RefreshToken).where(RefreshToken.jti.in_(refresh_ids))
            )
        if fake_file_ids:
            await db.execute(delete(File).where(File.id.in_(fake_file_ids)))

        await db.commit()
        print("\nĐã cleanup xong dữ liệu test token security.")


if __name__ == "__main__":
    asyncio.run(main())
