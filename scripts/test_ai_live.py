"""Smoke test các chức năng AI trên backend đang chạy (local)."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv
from sqlalchemy import select

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from db.models import User  # noqa: E402
from db.session import AsyncSessionLocal  # noqa: E402
from routers.auth_router import _create_access_token  # noqa: E402

BASE = "http://localhost:8000"
results: list[tuple[str, str, str]] = []


def ok(name: str, detail: str = "") -> None:
    results.append(("PASS", name, detail))
    line = f"[PASS] {name}" + (f" — {detail}" if detail else "")
    print(line.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


def fail(name: str, detail: str = "") -> None:
    results.append(("FAIL", name, detail))
    line = f"[FAIL] {name}" + (f" — {detail}" if detail else "")
    print(line.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


async def main() -> None:
    async with AsyncSessionLocal() as db:
        row = await db.execute(select(User).where(User.role == "admin").limit(1))
        admin = row.scalar_one_or_none()
        if not admin:
            fail("setup", "no admin user — chạy: python promote_admin.py <email>")
            return
        token = _create_access_token(admin)

    headers = {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(base_url=BASE, timeout=60) as client:
        r = await client.get("/health")
        ai = r.json().get("locksend_ai", {})
        if r.status_code == 200 and ai.get("ready"):
            ok("GET /health", f"locksend_ai ready, mode={ai.get('mode')}")
        else:
            fail("GET /health", str(r.json()))

        r = await client.get("/integrations/status", headers=headers)
        if r.status_code == 200:
            data = r.json()
            ok(
                "GET /integrations/status",
                f"gemini={data.get('gemini')}, model={data.get('gemini_model')}",
            )
        else:
            fail("GET /integrations/status", str(r.status_code))

        r = await client.get("/auth/admin/token-security/ai/health", headers=headers)
        if r.status_code == 200 and r.json().get("ready"):
            data = r.json()
            roc = data.get("metrics", {}).get("roc_auc", 0)
            ok("GET /auth/admin/token-security/ai/health", f"version={data.get('version')}, ROC-AUC={roc:.4f}")
        else:
            fail("GET /auth/admin/token-security/ai/health", r.text[:200])

        r = await client.post(
            "/auth/admin/token-security/ai/analyze",
            headers=headers,
            json={"token_type": "all", "top_n": 5},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("ai_error"):
                fail("POST /auth/admin/token-security/ai/analyze", data["ai_error"])
            else:
                sample = (data.get("ai_results") or [{}])[0]
                ok(
                    "POST /auth/admin/token-security/ai/analyze",
                    f"analyzed={data.get('analyzed')}, decision={sample.get('decision')}, "
                    f"score={sample.get('risk_score_pct')}%",
                )
        else:
            fail("POST /auth/admin/token-security/ai/analyze", str(r.status_code))

        r = await client.post(
            "/integrations/assistant/chat",
            headers=headers,
            json={
                "message": "LockSend mã hóa file bằng thuật toán gì? Trả lời ngắn.",
                "history": [],
            },
        )
        if r.status_code == 200:
            reply = r.json().get("reply", "")[:120].replace("\n", " ")
            ok("POST /integrations/assistant/chat", reply)
        else:
            fail("POST /integrations/assistant/chat", f"{r.status_code}: {r.text[:200]}")

        r = await client.get("/auth/admin/token-security/ai/trends?days=7", headers=headers)
        if r.status_code == 200:
            daily = r.json().get("daily") or []
            ok("GET /auth/admin/token-security/ai/trends", f"daily_points={len(daily)}")
        else:
            fail("GET /auth/admin/token-security/ai/trends", str(r.status_code))

    passed = sum(1 for x in results if x[0] == "PASS")
    print(f"--- Summary: {passed}/{len(results)} passed ---")


if __name__ == "__main__":
    asyncio.run(main())
