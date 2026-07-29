"""add_user_display_name_history

Revision ID: h8i9j0k1l2m3
Revises: g7h8i9j0k1l2
Create Date: 2026-06-01

Lưu lịch sử đổi tên hiển thị (audit).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "h8i9j0k1l2m3"
down_revision: Union[str, None] = "g7h8i9j0k1l2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_display_name_history",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("old_display_name", sa.Text(), nullable=True),
        sa.Column("new_display_name", sa.Text(), nullable=False),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_display_name_history_user_changed",
        "user_display_name_history",
        ["user_id", "changed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_display_name_history_user_changed", "user_display_name_history")
    op.drop_table("user_display_name_history")
