"""
Regression tests for Strix / Pentest remediations:

  - Access JWT invalidated after logout / password change (token_version)
  - Share revoke soft-revokes recipient SAS + proxy re-checks FileRecipient
  - /auth/users/search is a hardened recipient picker (prefix, eligible-only)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import SasTokenRecord, UserPublicKey
from tests.conftest import _auth, _login, _make_user
from tests.test_share import _make_file, _share


class TestAccessTokenRevocation:
    async def test_access_token_rejected_after_logout(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_user(db_session, "logout_tv@test.com")
        token = await _login(client, "logout_tv@test.com")

        before = await client.get("/files/my-files", headers=_auth(token))
        assert before.status_code == 200

        logout = await client.post("/auth/logout", headers=_auth(token))
        assert logout.status_code == 200

        after = await client.get("/files/my-files", headers=_auth(token))
        assert after.status_code == 401

    async def test_access_token_rejected_after_password_change(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_user(db_session, "pwd_tv@test.com", password="oldpass123")
        old_token = await _login(client, "pwd_tv@test.com", password="oldpass123")

        change = await client.post(
            "/auth/change-password",
            headers=_auth(old_token),
            json={"current_password": "oldpass123", "new_password": "newpass123"},
        )
        assert change.status_code == 200
        new_token = change.json()["access_token"]
        assert new_token != old_token

        stale = await client.get("/files/my-files", headers=_auth(old_token))
        assert stale.status_code == 401

        fresh = await client.get("/files/my-files", headers=_auth(new_token))
        assert fresh.status_code == 200


class TestShareRevokeInvalidatesSasProxy:
    async def test_proxy_rejects_sas_after_recipient_revoke(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        owner = await _make_user(db_session, "owner_sas@test.com")
        recip = await _make_user(db_session, "recip_sas@test.com", role="recipient")
        file = await _make_file(db_session, owner.id, blob_name="owner/revoke-sas.bin")
        await _share(db_session, file.id, recip.id)

        # Simulate a previously issued recipient SAS tracked in DB.
        db_session.add(
            SasTokenRecord(
                blob_name=file.blob_name,
                file_id=file.id,
                user_id=recip.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                is_revoked=False,
            )
        )
        await db_session.commit()

        owner_token = await _login(client, "owner_sas@test.com")
        revoke = await client.post(
            f"/files/{file.id}/revoke/{recip.id}",
            json={"reason": "strix revoke test"},
            headers=_auth(owner_token),
        )
        assert revoke.status_code == 200
        body = revoke.json()
        assert body["status"] == "revoked"
        # Without Azure credentials in tests, rotate is skipped / fails soft.
        assert "blob_rotated" in body

        row = (
            await db_session.execute(
                select(SasTokenRecord).where(
                    SasTokenRecord.file_id == file.id,
                    SasTokenRecord.user_id == recip.id,
                )
            )
        ).scalar_one()
        assert row.is_revoked is True

        recip_token = await _login(client, "recip_sas@test.com")
        fake_sas = (
            f"https://test.blob.core.windows.net/test/{file.blob_name}"
            f"?sv=2024-01-01&sig=fake"
        )
        # Even with a fresh login, revoked recipient must not proxy-download.
        info = await client.post(
            "/files/ciphertext/info-by-sas",
            headers=_auth(recip_token),
            json={"sas_url": fake_sas},
        )
        assert info.status_code in (403, 400)


class TestUserSearchLeastPrivilege:
    async def _seed_eligible(
        self, db: AsyncSession, email: str, *, role: str = "owner"
    ):
        user = await _make_user(db, email, role=role)
        user.email_verified_at = datetime.now(timezone.utc)
        db.add(
            UserPublicKey(
                user_id=user.id,
                public_key_x25519="A" * 44,
                public_key_ed25519="B" * 44,
                is_active=True,
            )
        )
        await db.commit()
        await db.refresh(user)
        return user

    async def test_search_omits_sensitive_metadata(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await self._seed_eligible(db_session, "searcher@test.com")
        await self._seed_eligible(db_session, "targetuser@test.com")
        token = await _login(client, "searcher@test.com")

        resp = await client.get(
            "/auth/users/search",
            params={"q": "target"},
            headers=_auth(token),
        )
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) >= 1
        row = rows[0]
        assert "id" in row
        assert "email" in row
        assert "display_name" in row
        assert row["has_public_key"] is True
        assert "role" not in row
        assert "storage_plan" not in row
        assert "vault_quota_bytes" not in row
        assert "effective_vault_quota_bytes" not in row
        assert "created_at" not in row

    async def test_search_requires_prefix_and_excludes_admin(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await self._seed_eligible(db_session, "picker@test.com")
        await self._seed_eligible(db_session, "adminlook@test.com", role="admin")
        await self._seed_eligible(db_session, "alice.share@test.com")
        # No public key → must not appear.
        await _make_user(db_session, "alice.nokey@test.com")
        token = await _login(client, "picker@test.com")

        short = await client.get(
            "/auth/users/search",
            params={"q": "al"},
            headers=_auth(token),
        )
        assert short.status_code == 200
        assert short.json() == []

        # Prefix match: "alice.s" hits alice.share, not domain substring fishing.
        domain = await client.get(
            "/auth/users/search",
            params={"q": "test.com"},
            headers=_auth(token),
        )
        assert domain.status_code == 200
        assert domain.json() == []

        admin_q = await client.get(
            "/auth/users/search",
            params={"q": "admin"},
            headers=_auth(token),
        )
        assert admin_q.status_code == 200
        assert admin_q.json() == []

        ok = await client.get(
            "/auth/users/search",
            params={"q": "alice.s"},
            headers=_auth(token),
        )
        assert ok.status_code == 200
        emails = [r["email"] for r in ok.json()]
        assert "alice.share@test.com" in emails
        assert "alice.nokey@test.com" not in emails
        assert "adminlook@test.com" not in emails
