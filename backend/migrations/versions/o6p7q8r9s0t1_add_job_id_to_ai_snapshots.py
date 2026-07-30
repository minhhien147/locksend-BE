"""add_job_id_to_ai_snapshots

Revision ID: o6p7q8r9s0t1
Revises: n5o6p7q8r9s0
Create Date: 2026-07-29

Gắn token_ai_score_snapshots với job Analyze đã sinh ra nó, để admin mở lại
đúng chi tiết của từng lần analyze trước đó (thay vì suy đoán theo mốc thời gian).
Thêm index (token_ref, created_at) để truy vấn "snapshot mới nhất" nhanh hơn.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "o6p7q8r9s0t1"
down_revision: Union[str, None] = "n5o6p7q8r9s0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "token_ai_score_snapshots",
        sa.Column("job_id", sa.String(length=36), nullable=True),
    )
    op.create_index(
        "ix_tass_job_id", "token_ai_score_snapshots", ["job_id"], unique=False
    )
    op.create_index(
        "ix_tass_token_ref_created",
        "token_ai_score_snapshots",
        ["token_ref", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_tass_token_ref_created", table_name="token_ai_score_snapshots")
    op.drop_index("ix_tass_job_id", table_name="token_ai_score_snapshots")
    op.drop_column("token_ai_score_snapshots", "job_id")
