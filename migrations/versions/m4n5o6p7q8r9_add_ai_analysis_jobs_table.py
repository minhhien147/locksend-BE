"""Add token_ai_analysis_jobs table for background job tracking.

Revision ID: m4n5o6p7q8r9
Revises: l1m2n3o4p5q6
Create Date: 2026-07-25 00:00:00.000000

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "m4n5o6p7q8r9"
down_revision = "l1m2n3o4p5q6"
branch_labels = None
depends_on = None

AI_JOB_STATUS_ENUM = sa.Enum(
    "pending", "running", "completed", "failed", name="aijobstatus", create_constraint=True
)


def upgrade() -> None:
    op.create_table(
        "token_ai_analysis_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("triggered_by", sa.String(length=36), nullable=True),
        sa.Column("token_type", sa.Text(), nullable=False, server_default="all"),
        sa.Column("total_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("analyzed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_cached", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "status",
            AI_JOB_STATUS_ENUM,
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("progress_pct", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("result_summary", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["triggered_by"],
            ["users.id"],
            name="fk_taaj_triggered_by_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_taaj_created_at", "token_ai_analysis_jobs", ["created_at"], unique=False
    )
    op.create_index(
        "ix_taaj_status", "token_ai_analysis_jobs", ["status"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_taaj_status", table_name="token_ai_analysis_jobs")
    op.drop_index("ix_taaj_created_at", table_name="token_ai_analysis_jobs")
    op.drop_table("token_ai_analysis_jobs")
    AI_JOB_STATUS_ENUM.drop(op.get_bind(), checkfirst=False)
