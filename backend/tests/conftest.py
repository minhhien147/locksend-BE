"""
Shared fixtures cho toàn bộ test suite.

Chiến lược:
  - setup_test_db: sync fixture (asyncio.run), tạo bảng 1 lần, drop khi xong session
  - engine + db_session: function-scoped → mỗi test dùng loop riêng
  - clean_db: TRUNCATE sau mỗi test
  - client: HTTPx AsyncClient + override get_db

Lý do tách engine ra fixture:
  Async DB connections bị bind vào event loop tạo chúng.
  pytest-asyncio 1.x mặc định mỗi test function có loop riêng.
  Nếu tạo engine ở module level, connections từ loop cũ sẽ invalid trong loop mới.
  Giải pháp: tạo engine MỚI trong mỗi test, dispose sau test.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio
import sqlalchemy as sa
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Set env TRƯỚC khi import app (tránh RuntimeError "JWT_SECRET not set")
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/secure_file_sharing_test",
)
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-ci-only-do-not-use-in-prod")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("AZURE_STORAGE_ACCOUNT_NAME", "test")
os.environ.setdefault("AZURE_STORAGE_CONTAINER_NAME", "test")
os.environ.setdefault("AZURE_KEY_VAULT_URL", "")

from db.base import Base  # noqa: E402
from db.dependencies import get_db  # noqa: E402
from db.models import File, FileRecipient, RecipientStatus, User  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = os.environ["DATABASE_URL"]

_TABLES_TO_TRUNCATE = [
    "email_verification_codes",
    "refresh_tokens",
    "sas_token_records",
    "token_access_logs",
    "file_recipients",
    "vault_folders",
    "upload_sessions",
    "files",
    "user_public_keys",
    "users",
]


# ── Schema setup/teardown (sync, dùng asyncio.run) ───────────────────────────

def _run(coro):
    """Chạy coroutine trong loop tạm thời (dùng trong sync fixture)."""
    return asyncio.run(coro)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """
    Tạo tables + extensions trên test DB trước khi chạy tests.
    Drop sau khi session kết thúc.
    Sync fixture → dùng asyncio.run() → tránh vấn đề event loop sharing.
    """
    async def _create():
        engine = create_async_engine(TEST_DB_URL, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    async def _drop():
        engine = create_async_engine(TEST_DB_URL, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()

    _run(_create())
    yield
    _run(_drop())


# ── Engine per test ───────────────────────────────────────────────────────────

@pytest_asyncio.fixture()
async def engine() -> AsyncEngine:
    """
    Tạo engine MỚI cho mỗi test → bound vào đúng event loop của test.
    """
    e = create_async_engine(TEST_DB_URL, echo=False)
    yield e
    await e.dispose()


# ── Truncate sau mỗi test ─────────────────────────────────────────────────────

@pytest_asyncio.fixture(autouse=True)
async def clean_db(engine: AsyncEngine):
    """Xóa toàn bộ dữ liệu bảng sau mỗi test → DB sạch."""
    yield
    async with engine.begin() as conn:
        await conn.execute(
            sa.text(
                f"TRUNCATE TABLE {', '.join(_TABLES_TO_TRUNCATE)} RESTART IDENTITY CASCADE"
            )
        )


# ── Session per test ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture()
async def db_session(engine: AsyncEngine) -> AsyncSession:
    """AsyncSession cho test, dùng chung engine với clean_db."""
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session


# ── HTTP client với DB override ───────────────────────────────────────────────

@pytest_asyncio.fixture()
async def client(db_session: AsyncSession):
    """
    AsyncClient kết nối với FastAPI app.
    Override get_db để dùng db_session của test.
    """
    async def _override_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_db
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _make_user(
    db: AsyncSession,
    email: str,
    role: str = "owner",
    password: str = "password123",
) -> User:
    """Tạo và commit user trực tiếp (bỏ qua endpoint)."""
    from passlib.context import CryptContext

    ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    user = User(
        external_id=str(uuid.uuid4()),
        email=email,
        display_name=email.split("@")[0],
        role=role,
        password_hash=ctx.hash(password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _login(client: AsyncClient, email: str, password: str = "password123") -> str:
    """Đăng nhập qua API, trả access_token."""
    resp = await client.post(
        "/auth/login",
        json={"username": email, "password": password},
    )
    assert resp.status_code == 200, f"Login failed ({resp.status_code}): {resp.text}"
    return resp.json()["access_token"]


def _auth(token: str) -> dict:
    """Tạo Authorization header từ token."""
    return {"Authorization": f"Bearer {token}"}


__all__ = ["_make_user", "_login", "_auth"]
