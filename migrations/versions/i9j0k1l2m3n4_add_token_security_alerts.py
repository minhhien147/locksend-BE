"""add_token_security_alerts

Revision ID: i9j0k1l2m3n4
Revises: h8i9j0k1l2m3
Create Date: 2026-06-08

Bảng:
  - token_security_alerts: cảnh báo AI realtime
  - token_ai_score_snapshots: lịch sử score cho biểu đồ trend
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "i9j0k1l2m3n4"
down_revision = "h8i9j0k1l2m3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "token_security_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_type", sa.Text, nullable=False),
        sa.Column("token_ref", sa.Text, nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("subject_label", sa.Text, nullable=True),
        sa.Column("rule_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("ai_score_pct", sa.Integer, nullable=False),
        sa.Column("ai_level", sa.Text, nullable=False),
        sa.Column("decision", sa.Text, nullable=False),
        sa.Column("agreement_status", sa.Text, nullable=True),
        sa.Column("behavior_badges", sa.Text, nullable=True),
        sa.Column("summary_vi", sa.Text, nullable=True),
        sa.Column("endpoint", sa.Text, nullable=True),
        sa.Column("ip_address", sa.Text, nullable=True),
        sa.Column("is_read", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_tsa_created_at", "token_security_alerts", ["created_at"])
    op.create_index("ix_tsa_is_read", "token_security_alerts", ["is_read"])
    op.create_index("ix_tsa_token_ref", "token_security_alerts", ["token_ref"])

    op.create_table(
        "token_ai_score_snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("token_type", sa.Text, nullable=False),
        sa.Column("token_ref", sa.Text, nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("rule_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("ai_score_pct", sa.Integer, nullable=False),
        sa.Column("ai_level", sa.Text, nullable=False),
        sa.Column("decision", sa.Text, nullable=False),
        sa.Column("source", sa.Text, nullable=False, server_default="realtime"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_tass_created_at", "token_ai_score_snapshots", ["created_at"])
    op.create_index("ix_tass_token_ref", "token_ai_score_snapshots", ["token_ref"])


def downgrade() -> None:
    op.drop_table("token_ai_score_snapshots")
    op.drop_table("token_security_alerts")
