"""users_router.py — User search, public keys, admin CRUD."""
from __future__ import annotations

import logging
import uuid as _uuid_mod

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

import audit
from auth import CurrentUser, get_current_user
from db.dependencies import get_db
from db.models import File, FileRecipient, User, UserDisplayNameHistory, UserPublicKey
from services.azure_storage import delete_blob

from routers._auth_helpers import (
    ChangeStoragePlanRequest,
    ChangeRoleRequest,
    DisplayNameHistoryOut,
    PublicKeyOut,
    RegisterRequest,
    UserOut,
    UserSearchOut,
    hash_password,
    require_admin,
    to_user_out,
    to_user_search_out,
)
from services.vault_storage import normalize_storage_plan

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


# ── User search & public keys ─────────────────────────────────────────────────

@router.get("/users/{user_id}/public-key", response_model=PublicKeyOut)
async def get_user_public_key(
    user_id: str,
    _: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lấy public key (X25519 + Ed25519) của một user theo internal UUID."""
    row = (
        await db.execute(
            select(UserPublicKey).where(
                UserPublicKey.user_id == user_id, UserPublicKey.is_active.is_(True)
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="User chưa đăng ký public key")
    return PublicKeyOut(
        user_id=user_id,
        public_key_x25519=row.public_key_x25519,
        public_key_ed25519=row.public_key_ed25519,
        key_version=row.key_version,
    )


@router.get("/users/search", response_model=list[UserSearchOut])
async def search_users(
    q: str,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Recipient picker — not a general directory search.

    Hardening (pentest #9):
      - minimum 3-character prefix
      - email prefix match only (not substring / domain fishing)
      - eligible share recipients only: non-admin + active public key
      - when email verification is enforced, require verified email
    """
    from services.email_verification import verification_required

    prefix = q.strip().lower()
    if len(prefix) < 3:
        return []

    conditions = [
        User.email.ilike(f"{prefix}%"),
        User.id != current.id,
        User.role != "admin",
        UserPublicKey.is_active.is_(True),
    ]
    if verification_required():
        conditions.append(User.email_verified_at.is_not(None))

    rows = (
        await db.execute(
            select(User)
            .join(UserPublicKey, UserPublicKey.user_id == User.id)
            .where(*conditions)
            .limit(10)
        )
    ).scalars().unique().all()

    # has_public_key is always true for this result set (join filter).
    return [to_user_search_out(u, has_public_key=True) for u in rows]


# ── Admin: display name history ───────────────────────────────────────────────

@router.get(
    "/admin/users/{user_id}/display-name-history",
    response_model=list[DisplayNameHistoryOut],
    tags=["admin"],
)
async def admin_get_display_name_history(
    user_id: str,
    request: Request,
    limit: int = 50,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin xem lịch sử đổi tên của một user."""
    require_admin(current)
    cap = min(max(limit, 1), 100)
    user = (
        await db.execute(select(User).where((User.id == user_id) | (User.external_id == user_id)))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    rows = (
        await db.execute(
            select(UserDisplayNameHistory)
            .where(UserDisplayNameHistory.user_id == user.id)
            .order_by(UserDisplayNameHistory.changed_at.desc())
            .limit(cap)
        )
    ).scalars().all()

    audit.log_event(
        "admin.view_display_name_history",
        user_id=current.id,
        role=current.role,
        target_user_id=user.id,
        ip=audit.get_ip(request),
        request_id=audit.get_request_id(request),
        count=len(rows),
    )
    return [
        DisplayNameHistoryOut(
            id=r.id,
            old_display_name=r.old_display_name,
            new_display_name=r.new_display_name,
            changed_at=r.changed_at.isoformat(),
            ip_address=r.ip_address,
        )
        for r in rows
    ]


# ── Admin: user CRUD ──────────────────────────────────────────────────────────

@router.get("/admin/users", response_model=list[UserOut], tags=["admin"])
async def list_users(
    request: Request,
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
        description="Tìm theo email hoặc tên hiển thị (không phân biệt hoa thường)",
    ),
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Danh sách user — chỉ admin. Có thể lọc theo email/tên qua ?q=."""
    require_admin(current)
    stmt = select(User).order_by(User.created_at.desc())
    query = (q or "").strip()
    if query:
        term = f"%{query}%"
        stmt = stmt.where(
            or_(
                User.email.ilike(term),
                User.display_name.ilike(term),
            )
        )
    rows = (await db.execute(stmt)).scalars().all()
    audit.log_event(
        "admin.list_users",
        user_id=current.id,
        role=current.role,
        request_id=audit.get_request_id(request),
        count=len(rows),
        query=query or None,
    )
    return [to_user_out(u) for u in rows]


@router.post("/admin/users", response_model=UserOut, status_code=201, tags=["admin"])
async def admin_create_user(
    body: RegisterRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admin tạo tài khoản với role tuỳ chọn.

    A01: Không cấp access token của user mới cho admin — trả UserOut thôi
    để tránh credential impersonation bị log/cache ở phía client.
    """
    require_admin(current)
    existing = (await db.execute(select(User).where(User.email == body.username))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Tên đăng nhập đã được sử dụng")

    user = User(
        external_id=str(_uuid_mod.uuid4()),
        email=body.username,
        display_name=body.display_name or body.username,
        role=body.role,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    await db.commit()

    audit.log_event(
        "admin.create_user",
        user_id=current.id,
        role=current.role,
        target_username=user.email,
        target_role=user.role,
        request_id=audit.get_request_id(request),
    )
    return to_user_out(user)


@router.patch("/admin/users/{user_id}/role", response_model=UserOut, tags=["admin"])
async def change_user_role(
    user_id: str,
    body: ChangeRoleRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Đổi role của user — chỉ admin. Admin không thể tự hạ role của mình."""
    require_admin(current)
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="Không thể đổi role của chính mình")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    old_role = user.role
    user.role = body.role
    await db.commit()

    audit.log_event(
        "admin.change_role",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        old_role=old_role,
        new_role=body.role,
        request_id=audit.get_request_id(request),
    )
    return to_user_out(user)


@router.patch("/admin/users/{user_id}/storage-plan", response_model=UserOut, tags=["admin"])
async def change_user_storage_plan(
    user_id: str,
    body: ChangeStoragePlanRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Đổi gói dung lượng vault của user — free/pro hoặc override quota riêng."""
    require_admin(current)

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    old_plan = normalize_storage_plan(user.storage_plan)
    old_quota = user.vault_quota_bytes

    user.storage_plan = normalize_storage_plan(body.storage_plan)
    user.vault_quota_bytes = (
        int(body.vault_quota_gb) * 1024**3 if body.vault_quota_gb is not None else None
    )
    await db.commit()
    await db.refresh(user)

    audit.log_event(
        "admin.change_storage_plan",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        old_plan=old_plan,
        new_plan=user.storage_plan,
        old_quota_bytes=old_quota,
        new_quota_bytes=user.vault_quota_bytes,
        request_id=audit.get_request_id(request),
    )
    return to_user_out(user)


@router.delete("/admin/users/{user_id}", status_code=204, tags=["admin"])
async def delete_user(
    user_id: str,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Xóa user — chỉ admin. Admin không thể xóa chính mình."""
    require_admin(current)
    if user_id == current.id:
        raise HTTPException(status_code=400, detail="Không thể xóa chính mình")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User không tồn tại")

    await db.execute(delete(FileRecipient).where(FileRecipient.recipient_id == user_id))
    files_result = await db.execute(select(File).where(File.owner_id == user_id))
    for file in files_result.scalars().all():
        try:
            delete_blob(file.blob_name)
        except Exception as exc:
            logger.warning("delete_blob failed for %s: %s", file.blob_name, exc)
        await db.delete(file)

    await db.delete(user)
    await db.commit()

    audit.log_event(
        "admin.delete_user",
        user_id=current.id,
        role=current.role,
        target_user_id=user_id,
        request_id=audit.get_request_id(request),
    )
