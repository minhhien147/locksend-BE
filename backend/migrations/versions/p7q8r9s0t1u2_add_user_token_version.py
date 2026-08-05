"""add_user_token_version

Revision ID: p7q8r9s0t1u2
Revises: o6p7q8r9s0t1
Create Date: 2026-08-05

Server-side access-token revocation: bump users.token_version on logout /
password change so JWTs with a stale `tv` claim are rejected immediately.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "p7q8r9s0t1u2"
down_revision: Union[str, None] = "o6p7q8r9s0t1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
