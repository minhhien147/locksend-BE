"""
Tests cho luồng revoke recipient.

Yêu cầu cốt lõi:
  - Revoke không re-encrypt blob (chỉ đổi status)
  - Sau revoke, recipient không còn thấy file trong shared-with-me
  - Chỉ owner (hoặc admin) mới được revoke
  - Revoke 1 recipient không ảnh hưởng recipient khác
  - Revoke 2 lần → 409
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import File, FileRecipient, RecipientStatus
from tests.conftest import _auth, _login, _make_user
from tests.test_share import _make_file, _share


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestRevoke:
    async def test_owner_can_revoke_recipient(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Owner revoke thành công → trả status=revoked + revoked_at."""
        owner = await _make_user(db_session, "owner@rev.com")
        recip = await _make_user(db_session, "recip@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id)

        token = await _login(client, "owner@rev.com")
        resp = await client.post(
            f"/files/{file.id}/revoke/{recip.id}",
            json={"reason": "không còn cần thiết"},
            headers=_auth(token),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "revoked"
        assert data["file_id"] == file.id
        assert data["recipient_id"] == recip.id
        assert "revoked_at" in data

    async def test_revoked_recipient_disappears_from_shared_with_me(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Sau khi bị revoke, file không còn trong shared-with-me của recipient."""
        owner = await _make_user(db_session, "owner2@rev.com")
        recip = await _make_user(db_session, "recip2@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id)

        # Trước revoke: thấy file
        recip_token = await _login(client, "recip2@rev.com")
        before = await client.get("/files/shared-with-me", headers=_auth(recip_token))
        assert len(before.json()) == 1

        # Owner revoke
        owner_token = await _login(client, "owner2@rev.com")
        await client.post(
            f"/files/{file.id}/revoke/{recip.id}",
            json={},
            headers=_auth(owner_token),
        )

        # Sau revoke: không còn thấy
        after = await client.get("/files/shared-with-me", headers=_auth(recip_token))
        assert after.json() == []

    async def test_revoke_one_does_not_affect_others(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Revoke 1 recipient không ảnh hưởng recipient còn lại."""
        owner = await _make_user(db_session, "owner3@rev.com")
        recip_a = await _make_user(db_session, "recip_a@rev.com", role="recipient")
        recip_b = await _make_user(db_session, "recip_b@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip_a.id, wrapped_key="WK-A")
        await _share(db_session, file.id, recip_b.id, wrapped_key="WK-B")

        owner_token = await _login(client, "owner3@rev.com")
        await client.post(
            f"/files/{file.id}/revoke/{recip_a.id}",
            json={},
            headers=_auth(owner_token),
        )

        # A bị revoke → không thấy
        tok_a = await _login(client, "recip_a@rev.com")
        assert (await client.get("/files/shared-with-me", headers=_auth(tok_a))).json() == []

        # B vẫn thấy
        tok_b = await _login(client, "recip_b@rev.com")
        items_b = (await client.get("/files/shared-with-me", headers=_auth(tok_b))).json()
        assert len(items_b) == 1
        assert items_b[0]["wrapped_file_key"] == "WK-B"

    async def test_non_owner_cannot_revoke(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """User không phải owner của file không được revoke."""
        owner = await _make_user(db_session, "owner4@rev.com")
        stranger = await _make_user(db_session, "stranger@rev.com")
        recip = await _make_user(db_session, "recip4@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id)

        stranger_token = await _login(client, "stranger@rev.com")
        resp = await client.post(
            f"/files/{file.id}/revoke/{recip.id}",
            json={},
            headers=_auth(stranger_token),
        )
        assert resp.status_code == 403

    async def test_admin_can_revoke_any_file(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Admin revoke được file của bất kỳ owner nào."""
        owner = await _make_user(db_session, "owner5@rev.com")
        admin = await _make_user(db_session, "admin@rev.com", role="admin")
        recip = await _make_user(db_session, "recip5@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id)

        admin_token = await _login(client, "admin@rev.com")
        resp = await client.post(
            f"/files/{file.id}/revoke/{recip.id}",
            json={"reason": "vi phạm chính sách"},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    async def test_double_revoke_returns_409(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Revoke 2 lần → 409 Conflict."""
        owner = await _make_user(db_session, "owner6@rev.com")
        recip = await _make_user(db_session, "recip6@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id)

        token = await _login(client, "owner6@rev.com")
        await client.post(f"/files/{file.id}/revoke/{recip.id}", json={}, headers=_auth(token))
        resp2 = await client.post(f"/files/{file.id}/revoke/{recip.id}", json={}, headers=_auth(token))
        assert resp2.status_code == 409
        assert "đã bị revoke" in resp2.json()["detail"]

    async def test_revoke_nonexistent_recipient_returns_404(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Revoke recipient không tồn tại → 404."""
        owner = await _make_user(db_session, "owner7@rev.com")
        file = await _make_file(db_session, owner.id)
        fake_id = str(uuid.uuid4())

        token = await _login(client, "owner7@rev.com")
        resp = await client.post(
            f"/files/{file.id}/revoke/{fake_id}",
            json={},
            headers=_auth(token),
        )
        assert resp.status_code == 404

    async def test_revoke_nonexistent_file_returns_404(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Revoke file không tồn tại → 404."""
        owner = await _make_user(db_session, "owner8@rev.com")
        recip = await _make_user(db_session, "recip8@rev.com", role="recipient")
        fake_file_id = str(uuid.uuid4())

        token = await _login(client, "owner8@rev.com")
        resp = await client.post(
            f"/files/{fake_file_id}/revoke/{recip.id}",
            json={},
            headers=_auth(token),
        )
        assert resp.status_code == 404

    async def test_blob_not_re_encrypted_after_revoke(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """
        Sau revoke, blob_name và metadata của file không thay đổi.
        Chứng minh: revoke KHÔNG re-encrypt ciphertext.
        """
        from sqlalchemy import select
        from db.models import File as FileModel

        owner = await _make_user(db_session, "owner9@rev.com")
        recip = await _make_user(db_session, "recip9@rev.com", role="recipient")
        file = await _make_file(db_session, owner.id, blob_name="blobs/immutable.enc")
        original_blob = file.blob_name
        await _share(db_session, file.id, recip.id)

        token = await _login(client, "owner9@rev.com")
        await client.post(f"/files/{file.id}/revoke/{recip.id}", json={}, headers=_auth(token))

        # Reload file từ DB
        result = await db_session.execute(
            select(FileModel).where(FileModel.id == file.id)
        )
        updated_file = result.scalar_one()
        assert updated_file.blob_name == original_blob  # không đổi
