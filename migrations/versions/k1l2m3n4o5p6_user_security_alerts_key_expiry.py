"""user security alerts + keypair expiry

Revision ID: k1l2m3n4o5p6
Revises: j0k1l2m3n4o5
Create Date: 2026-06-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "k1l2m3n4o5p6"
down_revision = "j0k1l2m3n4o5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_public_keys",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Keypair hiện có: hết hạn sau 365 ngày kể từ created_at
    op.execute(
        sa.text(
            "UPDATE user_public_keys SET expires_at = created_at + interval '365 days' "
            "WHERE expires_at IS NULL AND is_active = true"
        )
    )

    op.create_table(
        "user_security_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_type", sa.Text, nullable=False),
        sa.Column("file_id", sa.String(36), sa.ForeignKey("files.id", ondelete="SET NULL"), nullable=True),
        sa.Column("file_name", sa.Text, nullable=True),
        sa.Column("title_vi", sa.Text, nullable=False),
        sa.Column("message_vi", sa.Text, nullable=False),
        sa.Column("detail_json", sa.JSON, nullable=True),
        sa.Column("dedupe_key", sa.Text, nullable=True),
        sa.Column("is_read", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_usa_user_created", "user_security_alerts", ["user_id", "created_at"])
    op.create_index("ix_usa_user_unread", "user_security_alerts", ["user_id", "is_read"])
    op.create_index("ix_usa_dedupe", "user_security_alerts", ["dedupe_key"])


def downgrade() -> None:
    op.drop_index("ix_usa_dedupe", table_name="user_security_alerts")
    op.drop_index("ix_usa_user_unread", table_name="user_security_alerts")
    op.drop_index("ix_usa_user_created", table_name="user_security_alerts")
    op.drop_table("user_security_alerts")
    op.drop_column("user_public_keys", "expires_at")
