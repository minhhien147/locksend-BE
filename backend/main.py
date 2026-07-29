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
import warnings
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from middleware import (
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
    TokenAccessLogMiddleware,
    start_token_access_log_worker,
    stop_token_access_log_worker,
)
from routers import (
    auth_router,
    integrations_router,
    keys_router,
    token_security_router,
    upload_router,
    vault_router,
)

logger = logging.getLogger(__name__)


# ── A02: Startup secret-strength check ────────────────────────────────────────

def _validate_startup_config() -> None:
    """
    Kiểm tra cấu hình bảo mật khi khởi động.
    - Development (APP_ENV=development): chỉ warning, không block.
    - Production (mặc định): raise RuntimeError nếu vi phạm → server không start.
    """
    is_production = os.getenv("APP_ENV", "production").lower() not in ("development", "dev", "test")
    errors: list[str] = []

    # Fix #1 — A02: JWT_SECRET đủ mạnh
    jwt_secret = os.getenv("JWT_SECRET", "")
    jwt_algo = os.getenv("JWT_ALGORITHM", "HS256")
    if jwt_algo.startswith("HS"):
        if not jwt_secret:
            errors.append(
                "[A02] JWT_SECRET chưa được set. "
                "Tạo bằng: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        elif len(jwt_secret) < 32:
            errors.append(
                f"[A02] JWT_SECRET quá ngắn ({len(jwt_secret)} ký tự, cần ≥ 32). "
                "Tạo bằng: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

    # Fix #2 — A05: CORS không wildcard
    raw_origins = os.getenv("ALLOWED_ORIGINS", "")
    origins_list = [o.strip() for o in raw_origins.split(",") if o.strip()]
    if "*" in origins_list or not origins_list:
        errors.append(
            "[A05] ALLOWED_ORIGINS chứa '*' hoặc chưa được set. "
            "Ví dụ: ALLOWED_ORIGINS=https://locksend.app"
        )

    # Fix #4 — A05: COOKIE_SECURE phải bật trên production
    cookie_secure = os.getenv("COOKIE_SECURE", "false").lower()
    if cookie_secure != "true":
        errors.append(
            "[A05] COOKIE_SECURE=false trên production — refresh token cookie "
            "có thể bị gửi qua HTTP. Set COOKIE_SECURE=true khi đã có HTTPS."
        )

    if errors:
        if is_production:
            msg = "\n".join(f"  • {e}" for e in errors)
            raise RuntimeError(
                f"\n\n🔒 SECURITY: Server từ chối khởi động — vi phạm bảo mật production:\n{msg}\n\n"
                "Để bỏ qua (chỉ dev): set APP_ENV=development\n"
            )
        else:
            for e in errors:
                warnings.warn(f"SECURITY (dev mode, bỏ qua): {e}", stacklevel=2)
                logger.warning("SECURITY dev-mode warning: %s", e)


_validate_startup_config()

# ── App ───────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):
    from services.scheduled_cleanup import start_scheduled_cleanup, stop_scheduled_cleanup
    from services.scheduled_retrain import start_scheduled_retrain, stop_scheduled_retrain
    from services.azure_storage import check_container_not_public

    # Fix #8 — A01/A05: Kiểm tra Azure container không public khi khởi động
    import asyncio
    asyncio.get_event_loop().run_in_executor(None, check_container_not_public)

    cleanup_task = start_scheduled_cleanup()
    retrain_task = start_scheduled_retrain()
    start_token_access_log_worker()
    try:
        yield
    finally:
        await stop_token_access_log_worker()
        await stop_scheduled_cleanup(cleanup_task)
        await stop_scheduled_retrain(retrain_task)
        from services.locksend_ai import close_http_client
        await close_http_client()


app = FastAPI(
    title="Secure File Sharing API",
    version="1.0.0",
    lifespan=lifespan,
    # A05: ẩn thông tin lỗi nội bộ trên production
    openapi_url="/openapi.json" if os.getenv("APP_ENV", "production") != "production" else None,
    docs_url="/docs" if os.getenv("APP_ENV", "production") != "production" else None,
    redoc_url="/redoc" if os.getenv("APP_ENV", "production") != "production" else None,
)

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

# A05: Security headers (phải add sau CORS để không bị ghi đè)
app.add_middleware(SecurityHeadersMiddleware)


# A05: Custom exception handler — ẩn internal error details trên production
@app.exception_handler(Exception)
async def _generic_error_handler(request: Request, exc: Exception):
    if os.getenv("APP_ENV", "production") != "production":
        raise exc  # Dev: vẫn hiện traceback qua Starlette default
    logger.exception("Unhandled error: %s %s — %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Lỗi máy chủ nội bộ. Vui lòng thử lại sau."},
    )


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )

# ── Middleware ────────────────────────────────────────────────────────────────

_SKIP_LOG_PATHS = frozenset({"/health", "/health/deps", "/docs", "/openapi.json", "/redoc"})
_SENSITIVE_PREFIXES = ("/auth/admin/token-security",)

# Thứ tự add = từ trong ra ngoài, nên TokenAccessLog là lớp ngoài cùng (giữ nguyên
# thứ tự trước đây). Cả ba đều là pure ASGI — không dùng BaseHTTPMiddleware.
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    TokenAccessLogMiddleware,
    skip_paths=_SKIP_LOG_PATHS,
    skip_prefixes=_SENSITIVE_PREFIXES,
)


# ── Health & root (public) ────────────────────────────────────────────────────


@app.get("/health", tags=["ops"])
async def health():
    # Railway healthcheck phải phản hồi thật nhanh; không gọi service ngoài ở đây.
    return {
        "status": "ok",
        "service": "secure-file-sharing-backend",
    }


@app.get("/health/deps", tags=["ops"])
async def health_deps():
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
        "deps_health": "/health/deps",
    }
