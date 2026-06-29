"""
Secure File Sharing — FastAPI backend
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

# Load .env trước mọi import đọc os.getenv
load_dotenv(Path(__file__).resolve().parent / ".env")

import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from auth import verify_jwt
from db.dependencies import get_db_context
from routers import (
    auth_router,
    integrations_router,
    keys_router,
    token_security_router,
    upload_router,
    vault_router,
)
from services import token_security as ts

logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    from services.scheduled_cleanup import start_scheduled_cleanup, stop_scheduled_cleanup
    from services.scheduled_retrain import start_scheduled_retrain, stop_scheduled_retrain

    cleanup_task = start_scheduled_cleanup()
    retrain_task = start_scheduled_retrain()
    try:
        yield
    finally:
        await stop_scheduled_cleanup(cleanup_task)
        await stop_scheduled_retrain(retrain_task)


app = FastAPI(title="Secure File Sharing API", version="1.0.0", lifespan=lifespan)

_RAW_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _RAW_ORIGINS.split(",") if o.strip()]

app.include_router(auth_router)
app.include_router(integrations_router)
app.include_router(keys_router)
app.include_router(token_security_router)
app.include_router(upload_router)
app.include_router(vault_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Encryption-Metadata-B64", "X-File-Id"],
)

# ── Middleware ────────────────────────────────────────────────────────────────

_SKIP_LOG_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})
_SENSITIVE_PREFIXES = ("/auth/admin/token-security",)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def jwt_access_log_middleware(request: Request, call_next):
    """
    Ghi TokenAccessLog cho mọi request có Bearer token hợp lệ.
    Bỏ qua: health, docs, token-security admin endpoints.
    """
    response = await call_next(request)

    path = request.url.path
    if path in _SKIP_LOG_PATHS or any(path.startswith(p) for p in _SENSITIVE_PREFIXES):
        return response

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return response

    token_val = auth_header[7:]
    try:
        payload = verify_jwt(token_val)
        jti: str = payload.get("jti", "")
        user_ext_id: str = payload.get("sub", "")
        token_ref = f"{jti[:4]}…{jti[-4:]}" if len(jti) > 8 else "***"

        xff = request.headers.get("X-Forwarded-For")
        ip = xff.split(",")[0].strip() if xff else (
            request.client.host if request.client else None
        )

        async with get_db_context() as db:
            from sqlalchemy import select
            from db.models import User as _User

            user_row = (
                await db.execute(select(_User).where(_User.external_id == user_ext_id))
            ).scalar_one_or_none()
            user_id = user_row.id if user_row else None

            await ts.log_token_access(
                db,
                token_type="jwt",
                token_ref=token_ref,
                user_id=user_id,
                ip_address=ip,
                user_agent=request.headers.get("User-Agent"),
                endpoint=path,
                http_method=request.method,
                status_code=response.status_code,
            )

        if user_id and response.status_code < 500:
            from services.ai_realtime import schedule_token_access_scan

            schedule_token_access_scan(
                token_type="jwt",
                token_ref=token_ref,
                user_id=user_id,
                endpoint=path,
                ip_address=ip,
            )
    except Exception:
        pass

    return response


# ── Health & root (public) ────────────────────────────────────────────────────


@app.get("/health", tags=["ops"])
async def health():
    from services import locksend_ai

    ai = await locksend_ai.health()
    payload: dict = {
        "status": "ok",
        "locksend_ai": {
            "ready": bool(ai.get("ready")),
            "mode": ai.get("mode", "unknown"),
        },
    }
    if ai.get("ai_url"):
        payload["locksend_ai"]["ai_url"] = ai["ai_url"]
    if ai.get("error"):
        payload["locksend_ai"]["error"] = ai["error"]
    if ai.get("hint"):
        payload["locksend_ai"]["hint"] = ai["hint"]
    return payload


@app.get("/", tags=["ops"])
def root():
    return {
        "status": "ok",
        "service": "secure-file-sharing-backend",
        "docs": "/docs",
        "health": "/health",
    }
