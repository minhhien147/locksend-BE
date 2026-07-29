"""add_refresh_tokens_and_recipient_key_fields

Revision ID: c3d4e5f6a7b8
Revises: b2c87edc0639
Create Date: 2026-04-23

Thay đổi:
  1. file_recipients: thêm key_id (Text nullable), wrapped_key_version (Integer, default 1)
  2. Bảng mới: refresh_tokens (jti, user_id, expires_at, revoked_at, replaced_by_jti,
                               ip_address, user_agent, created_at)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "b2c87edc0639"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── file_recipients: key rotation fields ─────────────────────────────────
    op.add_column(
        "file_recipients",
        sa.Column("key_id", sa.Text, nullable=True),
    )
    op.add_column(
        "file_recipients",
        sa.Column(
            "wrapped_key_version",
            sa.Integer,
            nullable=False,
            server_default="1",
        ),
    )

    # ── refresh_tokens table ──────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("jti", sa.Text, nullable=False, unique=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_jti", sa.Text, nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index(
        "ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"]
    )
    op.create_unique_constraint(
        "uq_refresh_tokens_jti", "refresh_tokens", ["jti"]
    )


def downgrade() -> None:
    op.drop_table("refresh_tokens")
    op.drop_column("file_recipients", "wrapped_key_version")
    op.drop_column("file_recipients", "key_id")
