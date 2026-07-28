"""add_user_storage_plan_and_quota

Revision ID: n5o6p7q8r9s0
Revises: m4n5o6p7q8r9
Create Date: 2026-07-28

Thêm storage_plan và vault_quota_bytes để admin nâng cấp user lên Pro 50GB.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "n5o6p7q8r9s0"
down_revision: Union[str, None] = "m4n5o6p7q8r9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("storage_plan", sa.Text(), nullable=False, server_default="free"),
    )
    op.add_column(
        "users",
        sa.Column("vault_quota_bytes", sa.BigInteger(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "vault_quota_bytes")
    op.drop_column("users", "storage_plan")
