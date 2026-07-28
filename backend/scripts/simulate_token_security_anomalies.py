"""
Seed dữ liệu bất thường cho Token Security (JWT + SAS) để test rule engine + LockSend AI.

Mục tiêu:
  - Tạo JWT access bất thường: nhiều session/IP, token reuse, mass revoke, burst request.
  - Tạo SAS link bất thường: multi-IP, download rate cao, token già/quá hạn vẫn còn access.
  - (Tuỳ chọn) gọi LockSend AI để lưu snapshots thủ công và phát alert realtime.

Usage:
  cd backend
  python scripts/simulate_token_security_anomalies.py user@example.com
  python scripts/simulate_token_security_anomalies.py user@example.com --jwt-only
  python scripts/simulate_token_security_anomalies.py user@example.com --no-ai
  python scripts/simulate_token_security_anomalies.py user@example.com --emit-alerts
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from dotenv import load_dotenv
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from db.models import File, RefreshToken, SasTokenRecord, TokenAccessLog, User  # noqa: E402
from db.session import AsyncSessionLocal  # noqa: E402
from services import ai_realtime, locksend_ai, token_security  # noqa: E402


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ip_range(prefix: str, start: int, count: int) -> list[str]:
    return [f"{prefix}.{i}" for i in range(start, start + count)]


@dataclass
class SeededCase:
    label: str
    token_type: str
    token_ref: str
    user_id: str
    endpoint: str
    ip_address: str


async def _get_user_by_email(db, email: str) -> User | None:
    return (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()


async def _pick_or_create_file(db, user: User) -> tuple[File, bool]:
    row = (
        await db.execute(
            select(File)
            .where(File.owner_id == user.id)
            .order_by(File.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if row:
        return row, False

    fake_file = File(
        owner_id=user.id,
        storage_mode="vault",
        folder_id=None,
        blob_name=f"simulated/{uuid.uuid4()}/dangerous-sas-seed.lsc",
        original_filename="dangerous-sas-seed.pdf.lsc",
        content_type="application/octet-stream",
        file_size_bytes=5 * 1024 * 1024,
        encryption_alg="X25519+HKDF+AES-256-GCM",
        signature_alg="Ed25519",
        chunk_size_bytes=None,
        chunk_count=1,
        metadata_json={
            "simulated": True,
            "source": "simulate_token_security_anomalies.py",
        },
    )
    db.add(fake_file)
    await db.flush()
    return fake_file, True


def _build_log(
    *,
    token_type: str,
    token_ref: str,
    user_id: str,
    ip_address: str,
    user_agent: str,
    endpoint: str,
    method: str,
    status_code: int,
    created_at: datetime,
    country_code: str | None = None,
) -> TokenAccessLog:
    return TokenAccessLog(
        token_type=token_type,
        token_ref=token_ref,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        endpoint=endpoint,
        http_method=method,
        status_code=status_code,
        country_code=country_code,
        created_at=created_at,
    )


async def _seed_jwt_case(db, user: User, now: datetime) -> SeededCase:
    uid = user.id
    attack_ips = _ip_range("203.0.113", 10, 7)

    for i, ip in enumerate(attack_ips):
        db.add(
            RefreshToken(
                jti=str(uuid.uuid4()),
                user_id=uid,
                expires_at=now + timedelta(days=7),
                ip_address=ip,
                user_agent=f"AttackBot/7.{i}",
                created_at=now - timedelta(minutes=12 * i),
            )
        )

    old_jti = str(uuid.uuid4())
    replacement_jti = str(uuid.uuid4())
    db.add(
        RefreshToken(
            jti=old_jti,
            user_id=uid,
            expires_at=now + timedelta(days=7),
            revoked_at=now - timedelta(minutes=24),
            replaced_by_jti=replacement_jti,
            ip_address="198.51.100.77",
            user_agent="ReuseProbe/2.1",
            created_at=now - timedelta(hours=3),
        )
    )

    for sec_offset in (30, 70, 105):
        db.add(
            RefreshToken(
                jti=str(uuid.uuid4()),
                user_id=uid,
                expires_at=now + timedelta(days=7),
                revoked_at=now - timedelta(seconds=sec_offset),
                ip_address="198.51.100.88",
                user_agent="MassRevokeProbe/1.0",
                created_at=now - timedelta(hours=1, seconds=sec_offset),
            )
        )

    token_ref = f"jwt-sim-{uid[:8]}"
    endpoints = [
        "/files/my-files",
        "/auth/refresh",
        "/files/shared-with-me",
        "/auth/me",
        "/vault/files",
    ]
    countries = ["VN", "US", "DE", "SG", "BR", "NL", "JP"]
    for n in range(480):
        db.add(
            _build_log(
                token_type="jwt",
                token_ref=token_ref,
                user_id=uid,
                ip_address=attack_ips[n % len(attack_ips)],
                user_agent=f"AttackBot/{1 + (n % 3)}.0",
                endpoint=endpoints[n % len(endpoints)],
                method="GET" if n % 5 else "POST",
                status_code=200 if n % 11 else 401,
                created_at=now - timedelta(minutes=n % 50, seconds=(n * 7) % 60),
                country_code=countries[n % len(countries)],
            )
        )

    return SeededCase(
        label="jwt-burst-reuse",
        token_type="jwt",
        token_ref=token_ref,
        user_id=uid,
        endpoint="/auth/refresh",
        ip_address=attack_ips[0],
    )


async def _seed_sas_cases(db, user: User, file_row: File, now: datetime) -> list[SeededCase]:
    uid = user.id
    cases: list[SeededCase] = []

    sas_blueprints = [
        {
            "label": "sas-multi-ip-burst",
            "created_at": now - timedelta(hours=4),
            "expires_at": now + timedelta(hours=18),
            "access_count": 180,
            "unique_ip_count": 6,
            "log_count": 120,
            "ip_pool": _ip_range("198.51.100", 20, 6),
            "user_agent": "DownloaderSwarm/5.2",
            "endpoint": "/files/ciphertext/by-sas",
        },
        {
            "label": "sas-expired-still-accessed",
            "created_at": now - timedelta(hours=72),
            "expires_at": now - timedelta(hours=2),
            "access_count": 36,
            "unique_ip_count": 4,
            "log_count": 16,
            "ip_pool": _ip_range("203.0.113", 90, 4),
            "user_agent": "ExpiredReplay/3.4",
            "endpoint": "/files/ciphertext/info-by-sas",
        },
        {
            "label": "sas-old-heavy-total-access",
            "created_at": now - timedelta(hours=60),
            "expires_at": now + timedelta(hours=8),
            "access_count": 115,
            "unique_ip_count": 2,
            "log_count": 18,
            "ip_pool": _ip_range("192.0.2", 140, 2),
            "user_agent": "LongLivedMirror/1.9",
            "endpoint": "/files/ciphertext/by-sas",
        },
    ]

    for blueprint in sas_blueprints:
        token_id = str(uuid.uuid4())
        record = SasTokenRecord(
            token_id=token_id,
            user_id=uid,
            blob_name=file_row.blob_name,
            file_id=file_row.id,
            ip_address=blueprint["ip_pool"][0],
            user_agent=blueprint["user_agent"],
            expires_at=blueprint["expires_at"],
            access_count=blueprint["access_count"],
            unique_ip_count=blueprint["unique_ip_count"],
            last_accessed_at=now - timedelta(minutes=5),
            created_at=blueprint["created_at"],
        )
        db.add(record)

        for n in range(blueprint["log_count"]):
            db.add(
                _build_log(
                    token_type="sas",
                    token_ref=token_id,
                    user_id=uid,
                    ip_address=blueprint["ip_pool"][n % len(blueprint["ip_pool"])],
                    user_agent=blueprint["user_agent"],
                    endpoint=blueprint["endpoint"],
                    method="GET",
                    status_code=200 if n % 9 else 206,
                    created_at=now - timedelta(minutes=n % 55, seconds=(n * 9) % 60),
                    country_code=("US" if n % 2 == 0 else "VN"),
                )
            )

        cases.append(
            SeededCase(
                label=str(blueprint["label"]),
                token_type="sas",
                token_ref=token_id,
                user_id=uid,
                endpoint=str(blueprint["endpoint"]),
                ip_address=str(blueprint["ip_pool"][0]),
            )
        )

    return cases


def _print_metric(metric: dict) -> None:
    print(f"  token_id: {metric.get('token_id')}")
    print(f"  type: {metric.get('token_type')}")
    print(f"  rule_score: {metric.get('risk_score')}/100 ({metric.get('risk_level')})")
    print(f"  recommendation: {metric.get('recommendation')}")
    if metric.get("token_type") == "jwt":
        print(
            "  sessions/IP/rate: "
            f"{metric.get('active_sessions')} sessions, "
            f"{metric.get('ip_count')} active IPs, "
            f"{metric.get('accesses_per_hour')}/hr"
        )
        print(
            "  flags: "
            f"reuse={metric.get('reuse_detected')}, "
            f"mass_revoke={metric.get('mass_revoke_detected')}"
        )
    else:
        print(
            "  sas/IP/rate: "
            f"{metric.get('access_count')} total, "
            f"{metric.get('ip_count')} IPs, "
            f"{metric.get('downloads_per_hour')}/hr"
        )
        print(
            "  age/expiry: "
            f"{metric.get('token_age_hours')}h old, "
            f"expired={metric.get('is_expired')}, revoked={metric.get('is_revoked')}"
        )
    for reason in metric.get("reasons") or []:
        print(f"    • {reason}")


async def _collect_case_metrics(
    db,
    user_id: str,
    sas_token_ids: set[str],
) -> dict[str, dict]:
    results: dict[str, dict] = {}

    jwt_metrics = await token_security.get_jwt_token_metrics(db, user_id=user_id)
    if jwt_metrics:
        results["jwt"] = jwt_metrics[0]

    sas_metrics = await token_security.get_sas_token_metrics(
        db, include_expired=True, limit=500
    )
    for metric in sas_metrics:
        token_id = metric.get("token_id")
        if isinstance(token_id, str) and token_id in sas_token_ids:
            results[token_id] = metric

    return results


async def _run_ai_for_cases(
    db,
    cases: Iterable[SeededCase],
    metrics_by_key: dict[str, dict],
    *,
    save_snapshots: bool,
    emit_alerts: bool,
) -> None:
    health = await locksend_ai.health()
    if not health.get("ready"):
        print("\n[AI] LockSend AI chưa sẵn sàng, bỏ qua bước AI.")
        if health.get("error"):
            print(f"  error: {health['error']}")
        return

    print("\n── LockSend AI ──")
    for case in cases:
        metric_key = "jwt" if case.token_type == "jwt" else case.token_ref
        metric = metrics_by_key.get(metric_key)
        if not metric:
            print(f"\n[{case.label}] Không tìm thấy metric sau khi seed.")
            continue

        print(f"\n[{case.label}]")
        _print_metric(metric)
        result = await locksend_ai.analyze_token(metric)
        print(
            f"  ai_score: {result.get('risk_score_pct')}% "
            f"({result.get('ai_level_raw')}) -> {result.get('decision')}"
        )
        print(f"  summary: {result.get('summary_vi')}")
        badges = result.get("behavior_badges") or []
        if badges:
            print("  badges: " + ", ".join(str(b.get("label")) for b in badges))

        if save_snapshots:
            await ai_realtime.save_manual_snapshot(db, metric, result)

        if emit_alerts:
            await ai_realtime.process_token_access(
                db,
                token_type=case.token_type,
                token_ref=case.token_ref,
                user_id=case.user_id,
                endpoint=case.endpoint,
                ip_address=case.ip_address,
            )

    if save_snapshots or emit_alerts:
        await db.commit()


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed dữ liệu JWT/SAS bất thường để test Token Security + LockSend AI"
    )
    parser.add_argument("user_email", help="Email user mục tiêu")
    parser.add_argument("--jwt-only", action="store_true", help="Chỉ seed JWT anomalies")
    parser.add_argument("--sas-only", action="store_true", help="Chỉ seed SAS anomalies")
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Chỉ seed DB, không gọi LockSend AI / không lưu snapshots",
    )
    parser.add_argument(
        "--emit-alerts",
        action="store_true",
        help="Gọi pipeline realtime để tạo alerts nếu AI score đủ cao",
    )
    args = parser.parse_args()

    if args.jwt_only and args.sas_only:
        print("Không thể dùng đồng thời --jwt-only và --sas-only")
        sys.exit(1)

    email = args.user_email.strip().lower()
    now = _utc_now()

    async with AsyncSessionLocal() as db:
        user = await _get_user_by_email(db, email)
        if not user:
            print(f"Không tìm thấy user: {email}")
            sys.exit(1)

        print(f"Target user: {email} (id={user.id})")
        cases: list[SeededCase] = []

        if not args.jwt_only:
            file_row, created_fake = await _pick_or_create_file(db, user)
            file_note = "placeholder synthetic" if created_fake else "existing file"
            print(
                f"Using file for SAS tests: {file_row.original_filename} "
                f"(id={file_row.id}, {file_note})"
            )

        if not args.sas_only:
            cases.append(await _seed_jwt_case(db, user, now))

        if not args.jwt_only:
            cases.extend(await _seed_sas_cases(db, user, file_row, now))

        await db.commit()
        print(f"Seeded {len(cases)} anomaly case(s) into DB.")

        sas_ids = {c.token_ref for c in cases if c.token_type == "sas"}
        metrics_by_key = await _collect_case_metrics(db, user.id, sas_ids)

        print("\n── Rule engine metrics ──")
        jwt_metric = metrics_by_key.get("jwt")
        if jwt_metric:
            print("\n[jwt-burst-reuse]")
            _print_metric(jwt_metric)

        for case in [c for c in cases if c.token_type == "sas"]:
            metric = metrics_by_key.get(case.token_ref)
            if metric:
                print(f"\n[{case.label}]")
                _print_metric(metric)

        if not args.no_ai:
            await _run_ai_for_cases(
                db,
                cases,
                metrics_by_key,
                save_snapshots=True,
                emit_alerts=args.emit_alerts,
            )

        print("\n── Gợi ý kiểm tra trên UI ──")
        print("1. Vào Admin -> Token Security -> bấm Analyze AI với force_all nếu muốn refresh toàn bộ.")
        print("2. Mở phần Per-token details để xem rule reasons, AI summary và access log sample.")
        print("3. Với SAS cases, kiểm tra thêm File Activity nếu muốn đối chiếu file liên quan.")

        print("\n── Token IDs để test API single-token ──")
        print(f'JWT user_id: {user.id}')
        for case in [c for c in cases if c.token_type == "sas"]:
            print(f"SAS token_id ({case.label}): {case.token_ref}")


if __name__ == "__main__":
    asyncio.run(main())
