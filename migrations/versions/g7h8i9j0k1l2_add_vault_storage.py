"""add_vault_storage

Revision ID: g7h8i9j0k1l2
Revises: f1a2b3c4d5e6
Create Date: 2026-06-01

Kho lưu trữ cá nhân: vault_folders, files.storage_mode, files.folder_id
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "g7h8i9j0k1l2"
down_revision: Union[str, None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vault_folders",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("parent_id", sa.String(36), sa.ForeignKey("vault_folders.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"), nullable=False),
        sa.UniqueConstraint("owner_id", "parent_id", "name", name="uq_vault_folder_name"),
    )
    op.create_index("ix_vault_folders_owner", "vault_folders", ["owner_id"])

    op.add_column(
        "files",
        sa.Column("storage_mode", sa.Text(), nullable=False, server_default="share"),
    )
    op.add_column(
        "files",
        sa.Column("folder_id", sa.String(36), sa.ForeignKey("vault_folders.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_files_owner_storage", "files", ["owner_id", "storage_mode", "created_at"])
    op.create_index("ix_files_folder", "files", ["folder_id"])


def downgrade() -> None:
    op.drop_index("ix_files_folder", table_name="files")
    op.drop_index("ix_files_owner_storage", table_name="files")
    op.drop_column("files", "folder_id")
    op.drop_column("files", "storage_mode")
    op.drop_index("ix_vault_folders_owner", table_name="vault_folders")
    op.drop_table("vault_folders")
