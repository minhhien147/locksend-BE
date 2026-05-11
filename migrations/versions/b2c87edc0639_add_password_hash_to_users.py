"""add_password_hash_to_users

Revision ID: b2c87edc0639
Revises: ec6623f8a01f
Create Date: 2026-04-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b2c87edc0639"
down_revision: Union[str, None] = "ec6623f8a01f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_hash", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "password_hash")
