"""add_encrypted_key_blob_to_user_public_keys

Revision ID: f1a2b3c4d5e6
Revises: e1f2a3b4c5d6
Create Date: 2026-05-26

Thêm cột encrypted_key_blob vào user_public_keys cho zero-knowledge key management.
Server lưu private key đã mã hóa (PBKDF2+AES-256-GCM) của client.
Server KHÔNG biết passphrase hay private key plaintext.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, None] = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "user_public_keys",
        sa.Column("encrypted_key_blob", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_public_keys", "encrypted_key_blob")
