"""add_upload_logs_and_download_logs

Revision ID: d1e2f3a4b5c6
Revises: c3d4e5f6a7b8
Create Date: 2026-05-13

Thêm 2 bảng audit:
  upload_logs   — ghi nhận mỗi lần upload thành công
  download_logs — ghi nhận mỗi lần user tải file thành công
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d1e2f3a4b5c6"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "upload_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("file_id", sa.String(36),
                  sa.ForeignKey("files.id", ondelete="SET NULL"), nullable=True),
        sa.Column("blob_name", sa.Text, nullable=False),
        sa.Column("original_filename", sa.Text, nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("upload_type", sa.Text, nullable=False, server_default="single"),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_upload_logs_user_id", "upload_logs", ["user_id"])
    op.create_index("ix_upload_logs_file_id", "upload_logs", ["file_id"])
    op.create_index("ix_upload_logs_created_at", "upload_logs", ["created_at"])

    op.create_table(
        "download_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("file_id", sa.String(36),
                  sa.ForeignKey("files.id", ondelete="SET NULL"), nullable=True),
        sa.Column("blob_name", sa.Text, nullable=False),
        sa.Column("original_filename", sa.Text, nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    )
    op.create_index("ix_download_logs_user_id", "download_logs", ["user_id"])
    op.create_index("ix_download_logs_file_id", "download_logs", ["file_id"])
    op.create_index("ix_download_logs_created_at", "download_logs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_download_logs_created_at", "download_logs")
    op.drop_index("ix_download_logs_file_id", "download_logs")
    op.drop_index("ix_download_logs_user_id", "download_logs")
    op.drop_table("download_logs")

    op.drop_index("ix_upload_logs_created_at", "upload_logs")
    op.drop_index("ix_upload_logs_file_id", "upload_logs")
    op.drop_index("ix_upload_logs_user_id", "upload_logs")
    op.drop_table("upload_logs")
