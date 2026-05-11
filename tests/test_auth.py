"""
Tests cho luồng xác thực và RBAC.

Bao gồm:
  - Đăng ký tài khoản mới
  - Đăng nhập đúng / sai mật khẩu
  - Truy cập endpoint bảo vệ khi có/không có token
  - Role guard: owner, recipient, admin
  - Admin đổi role user
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import _auth, _login, _make_user


# ── Register ──────────────────────────────────────────────────────────────────

class TestRegister:
    async def test_register_success(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "alice@test.com",
            "password": "password123",
            "display_name": "Alice",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "alice@test.com"
        assert data["role"] == "owner"          # tự đăng ký luôn là owner
        assert "access_token" in data
        assert data["display_name"] == "Alice"

    async def test_register_default_role_is_owner(self, client: AsyncClient):
        """Dù gửi role=admin, tự đăng ký vẫn nhận owner."""
        resp = await client.post("/auth/register", json={
            "email": "sneaky@test.com",
            "password": "password123",
            "role": "admin",                    # cố tình gửi admin
        })
        assert resp.status_code == 201
        assert resp.json()["role"] == "owner"   # phải bị ignore

    async def test_register_duplicate_email(self, client: AsyncClient, db_session: AsyncSession):
        await _make_user(db_session, "dup@test.com")
        resp = await client.post("/auth/register", json={
            "email": "dup@test.com",
            "password": "password123",
        })
        assert resp.status_code == 409
        assert "đã được đăng ký" in resp.json()["detail"]

    async def test_register_password_too_short(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "short@test.com",
            "password": "123",
        })
        assert resp.status_code == 422           # Pydantic validation error

    async def test_register_invalid_email(self, client: AsyncClient):
        resp = await client.post("/auth/register", json={
            "email": "not-an-email",
            "password": "password123",
        })
        assert resp.status_code == 422


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:
    async def test_login_success(self, client: AsyncClient, db_session: AsyncSession):
        await _make_user(db_session, "bob@test.com", password="secret1234")
        resp = await client.post("/auth/login", json={
            "email": "bob@test.com",
            "password": "secret1234",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "owner"

    async def test_login_wrong_password(self, client: AsyncClient, db_session: AsyncSession):
        await _make_user(db_session, "carol@test.com")
        resp = await client.post("/auth/login", json={
            "email": "carol@test.com",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401
        assert "không đúng" in resp.json()["detail"]

    async def test_login_unknown_email(self, client: AsyncClient):
        resp = await client.post("/auth/login", json={
            "email": "nobody@test.com",
            "password": "password123",
        })
        assert resp.status_code == 401

    async def test_login_returns_correct_role(self, client: AsyncClient, db_session: AsyncSession):
        await _make_user(db_session, "adminuser@test.com", role="admin")
        resp = await client.post("/auth/login", json={
            "email": "adminuser@test.com",
            "password": "password123",
        })
        assert resp.status_code == 200
        assert resp.json()["role"] == "admin"


# ── Protected endpoints ───────────────────────────────────────────────────────

class TestProtectedEndpoints:
    async def test_health_is_public(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200

    async def test_shared_with_me_requires_auth(self, client: AsyncClient):
        resp = await client.get("/files/shared-with-me")
        assert resp.status_code == 401

    async def test_sas_token_requires_auth(self, client: AsyncClient):
        resp = await client.get("/sas-token/some/blob.enc")
        assert resp.status_code == 401

    async def test_keys_endpoint_requires_auth(self, client: AsyncClient):
        resp = await client.get("/keys/some-user-id")
        assert resp.status_code == 401

    async def test_valid_token_grants_access_to_shared_with_me(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_user(db_session, "dave@test.com")
        token = await _login(client, "dave@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json() == []            # chưa có file nào được share

    async def test_invalid_token_returns_401(self, client: AsyncClient):
        resp = await client.get(
            "/files/shared-with-me",
            headers={"Authorization": "Bearer totally.fake.token"},
        )
        assert resp.status_code == 401

    async def test_malformed_header_returns_401(self, client: AsyncClient):
        resp = await client.get(
            "/files/shared-with-me",
            headers={"Authorization": "NotBearer something"},
        )
        assert resp.status_code == 401


# ── Role-based access control ─────────────────────────────────────────────────

class TestRBAC:
    async def test_recipient_cannot_access_admin_users(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_user(db_session, "recip@test.com", role="recipient")
        token = await _login(client, "recip@test.com")
        resp = await client.get("/auth/admin/users", headers=_auth(token))
        assert resp.status_code == 403

    async def test_owner_cannot_access_admin_users(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_user(db_session, "owner2@test.com", role="owner")
        token = await _login(client, "owner2@test.com")
        resp = await client.get("/auth/admin/users", headers=_auth(token))
        assert resp.status_code == 403

    async def test_admin_can_access_admin_users(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_user(db_session, "superadmin@test.com", role="admin")
        token = await _login(client, "superadmin@test.com")
        resp = await client.get("/auth/admin/users", headers=_auth(token))
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    async def test_admin_change_role(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        admin = await _make_user(db_session, "mgr@test.com", role="admin")
        target = await _make_user(db_session, "changeme@test.com", role="owner")
        token = await _login(client, "mgr@test.com")

        resp = await client.patch(
            f"/auth/admin/users/{target.id}/role",
            json={"role": "recipient"},
            headers=_auth(token),
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "recipient"

    async def test_admin_cannot_change_own_role(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        admin = await _make_user(db_session, "self@test.com", role="admin")
        token = await _login(client, "self@test.com")

        resp = await client.patch(
            f"/auth/admin/users/{admin.id}/role",
            json={"role": "recipient"},
            headers=_auth(token),
        )
        assert resp.status_code == 400
        assert "chính mình" in resp.json()["detail"]

    async def test_admin_delete_user(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        admin = await _make_user(db_session, "boss@test.com", role="admin")
        victim = await _make_user(db_session, "bye@test.com", role="owner")
        token = await _login(client, "boss@test.com")

        resp = await client.delete(
            f"/auth/admin/users/{victim.id}",
            headers=_auth(token),
        )
        assert resp.status_code == 204

    async def test_admin_cannot_delete_self(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        admin = await _make_user(db_session, "nodelete@test.com", role="admin")
        token = await _login(client, "nodelete@test.com")

        resp = await client.delete(
            f"/auth/admin/users/{admin.id}",
            headers=_auth(token),
        )
        assert resp.status_code == 400
