"""alert file columns

Revision ID: j0k1l2m3n4o5
Revises: i9j0k1l2m3n4
Create Date: 2026-06-08

Thêm file_id, file_name vào token_security_alerts (liên kết SAS → file).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "j0k1l2m3n4o5"
down_revision = "i9j0k1l2m3n4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "token_security_alerts",
        sa.Column("file_id", sa.String(36), sa.ForeignKey("files.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column("token_security_alerts", sa.Column("file_name", sa.Text, nullable=True))
    op.create_index("ix_tsa_file_id", "token_security_alerts", ["file_id"])


def downgrade() -> None:
    op.drop_index("ix_tsa_file_id", "token_security_alerts")
    op.drop_column("token_security_alerts", "file_name")
    op.drop_column("token_security_alerts", "file_id")
