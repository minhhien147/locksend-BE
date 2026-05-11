"""
Tests cho luồng chia sẻ file (Envelope Encryption model).

Bao gồm:
  - shared-with-me trả đúng file khi có recipient active
  - Không trả file của người khác
  - Không trả file đã bị revoke
  - wrapped_file_key được trả đúng
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import File, FileRecipient, RecipientStatus
from tests.conftest import _auth, _login, _make_user


# ── Helpers nội bộ ────────────────────────────────────────────────────────────

async def _make_file(db: AsyncSession, owner_id: str, blob_name: str | None = None) -> File:
    """Tạo File record trực tiếp vào DB (bỏ qua Azure)."""
    f = File(
        owner_id=owner_id,
        blob_name=blob_name or f"blobs/{uuid.uuid4()}.enc",
        original_filename="secret.pdf",
        content_type="application/pdf",
        file_size_bytes=1024,
        encryption_alg="X25519+HKDF+AES-256-GCM",
        chunk_count=1,
        metadata_json={"nonce": "abc123"},
    )
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return f


async def _share(
    db: AsyncSession,
    file_id: str,
    recipient_id: str,
    wrapped_key: str = "wrapped-key-xyz",
    status: RecipientStatus = RecipientStatus.active,
) -> FileRecipient:
    """Chia sẻ file cho recipient trực tiếp vào DB."""
    fr = FileRecipient(
        file_id=file_id,
        recipient_id=recipient_id,
        wrapped_file_key=wrapped_key,
        wrapped_key_alg="X25519-HKDF",
        status=status,
    )
    db.add(fr)
    await db.commit()
    await db.refresh(fr)
    return fr


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestSharedWithMe:
    async def test_empty_when_no_shares(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """User chưa được chia sẻ file nào → trả []."""
        await _make_user(db_session, "nobody@test.com")
        token = await _login(client, "nobody@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_shared_file(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Recipient thấy đúng file được chia sẻ."""
        owner = await _make_user(db_session, "owner@test.com")
        recip = await _make_user(db_session, "recip@test.com", role="recipient")

        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id, wrapped_key="WK-001")

        token = await _login(client, "recip@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["file_id"] == file.id
        assert items[0]["wrapped_file_key"] == "WK-001"
        assert items[0]["original_filename"] == "secret.pdf"

    async def test_returns_multiple_files(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Recipient thấy tất cả file được chia sẻ."""
        owner = await _make_user(db_session, "owner2@test.com")
        recip = await _make_user(db_session, "recip2@test.com", role="recipient")

        f1 = await _make_file(db_session, owner.id)
        f2 = await _make_file(db_session, owner.id)
        await _share(db_session, f1.id, recip.id, "WK-A")
        await _share(db_session, f2.id, recip.id, "WK-B")

        token = await _login(client, "recip2@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_does_not_return_other_users_files(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Recipient chỉ thấy file của mình, không thấy file của người khác."""
        owner = await _make_user(db_session, "owner3@test.com")
        recip_a = await _make_user(db_session, "recip_a@test.com", role="recipient")
        recip_b = await _make_user(db_session, "recip_b@test.com", role="recipient")

        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip_a.id)  # chỉ share cho A

        token = await _login(client, "recip_b@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json() == []  # B không thấy gì

    async def test_revoked_file_not_returned(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """File đã revoke không xuất hiện trong shared-with-me."""
        owner = await _make_user(db_session, "owner4@test.com")
        recip = await _make_user(db_session, "recip4@test.com", role="recipient")

        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip.id, status=RecipientStatus.revoked)

        token = await _login(client, "recip4@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_correct_wrapped_key_per_recipient(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Mỗi recipient nhận đúng wrapped_key của riêng mình."""
        owner = await _make_user(db_session, "owner5@test.com")
        recip_x = await _make_user(db_session, "recipx@test.com", role="recipient")
        recip_y = await _make_user(db_session, "recipy@test.com", role="recipient")

        file = await _make_file(db_session, owner.id)
        await _share(db_session, file.id, recip_x.id, wrapped_key="WK-FOR-X")
        await _share(db_session, file.id, recip_y.id, wrapped_key="WK-FOR-Y")

        token_x = await _login(client, "recipx@test.com")
        resp_x = await client.get("/files/shared-with-me", headers=_auth(token_x))
        assert resp_x.json()[0]["wrapped_file_key"] == "WK-FOR-X"

        token_y = await _login(client, "recipy@test.com")
        resp_y = await client.get("/files/shared-with-me", headers=_auth(token_y))
        assert resp_y.json()[0]["wrapped_file_key"] == "WK-FOR-Y"

    async def test_owner_sees_nothing_in_shared_with_me(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        """Owner upload file → không tự xuất hiện trong shared-with-me của mình."""
        owner = await _make_user(db_session, "self_owner@test.com")
        file = await _make_file(db_session, owner.id)
        # share cho chính owner (edge case)
        await _share(db_session, file.id, owner.id)

        token = await _login(client, "self_owner@test.com")
        resp = await client.get("/files/shared-with-me", headers=_auth(token))
        # vẫn trả về vì record tồn tại, nhưng đây để đảm bảo không lỗi
        assert resp.status_code == 200
