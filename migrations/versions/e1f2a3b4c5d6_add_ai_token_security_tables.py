"""add_ai_token_security_tables

Revision ID: e1f2a3b4c5d6
Revises: d1e2f3a4b5c6
Create Date: 2026-05-19

Thêm hai bảng:
  - sas_token_records: bản ghi SAS URL được cấp + soft-revoke
  - token_access_logs: log chi tiết truy cập JWT/SAS (không lưu giá trị token)
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "e1f2a3b4c5d6"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sas_token_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_id", sa.Text, nullable=False, unique=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("blob_name", sa.Text, nullable=False),
        sa.Column("file_id", sa.String(36), sa.ForeignKey("files.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_revoked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.Text, nullable=True),
        sa.Column("access_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("unique_ip_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("last_accessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ai_risk_score", sa.Integer, nullable=True),
        sa.Column("ai_risk_level", sa.Text, nullable=True),
        sa.Column("ai_recommendation", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_sas_records_user_id", "sas_token_records", ["user_id"])
    op.create_index("ix_sas_records_blob_name", "sas_token_records", ["blob_name"])
    op.create_index("ix_sas_records_expires_at", "sas_token_records", ["expires_at"])
    op.create_index("ix_sas_records_created_at", "sas_token_records", ["created_at"])

    op.create_table(
        "token_access_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_type", sa.Text, nullable=False),
        sa.Column("token_ref", sa.Text, nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("user_agent", sa.Text, nullable=True),
        sa.Column("endpoint", sa.Text, nullable=True),
        sa.Column("http_method", sa.Text, nullable=True),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("country_code", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_tal_user_id", "token_access_logs", ["user_id"])
    op.create_index("ix_tal_token_type", "token_access_logs", ["token_type"])
    op.create_index("ix_tal_token_ref", "token_access_logs", ["token_ref"])
    op.create_index("ix_tal_ip_address", "token_access_logs", ["ip_address"])
    op.create_index("ix_tal_created_at", "token_access_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("token_access_logs")
    op.drop_table("sas_token_records")
