"""initial_schema

Revision ID: ec6623f8a01f
Revises:
Create Date: 2026-04-23

Creates all tables for the Secure File Sharing system:
  users, user_public_keys, files, file_recipients, upload_sessions
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "ec6623f8a01f"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("external_id", sa.Text, nullable=False),
        sa.Column("email", sa.Text, nullable=True),
        sa.Column("display_name", sa.Text, nullable=True),
        sa.Column("role", sa.Text, nullable=False, server_default="owner"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("external_id", name="uq_users_external_id"),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )

    op.create_table(
        "user_public_keys",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("public_key_x25519", sa.Text, nullable=False),
        sa.Column("public_key_ed25519", sa.Text, nullable=False),
        sa.Column("key_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="TRUE"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "user_id", "key_version", name="uq_user_public_keys_version"
        ),
    )

    op.create_table(
        "files",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "owner_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("blob_name", sa.Text, nullable=False),
        sa.Column("original_filename", sa.Text, nullable=False),
        sa.Column("content_type", sa.Text, nullable=True),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=False),
        sa.Column("encryption_alg", sa.Text, nullable=False),
        sa.Column(
            "signature_alg", sa.Text, nullable=False, server_default="Ed25519"
        ),
        sa.Column("chunk_size_bytes", sa.Integer, nullable=True),
        sa.Column("chunk_count", sa.Integer, nullable=False),
        sa.Column(
            "metadata_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("blob_name", name="uq_files_blob_name"),
        sa.CheckConstraint("file_size_bytes >= 0", name="ck_files_size"),
        sa.CheckConstraint("chunk_count > 0", name="ck_files_chunk_count"),
        sa.CheckConstraint(
            "chunk_size_bytes IS NULL OR chunk_size_bytes > 0",
            name="ck_files_chunk_size",
        ),
    )

    op.create_table(
        "file_recipients",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "file_id",
            sa.String(length=36),
            sa.ForeignKey("files.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "recipient_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("wrapped_file_key", sa.Text, nullable=False),
        sa.Column(
            "wrapped_key_alg", sa.Text, nullable=False, server_default="X25519-HKDF"
        ),
        sa.Column(
            "status",
            sa.Enum(
                "active",
                "revoked",
                "pending",
                name="recipient_status",
                native_enum=False,
            ),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "granted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.Text, nullable=True),
        sa.UniqueConstraint(
            "file_id", "recipient_id", name="uq_file_recipient"
        ),
    )

    op.create_table(
        "upload_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "owner_id",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("blob_name", sa.Text, nullable=False),
        sa.Column("upload_id", sa.Text, nullable=False),
        sa.Column("original_filename", sa.Text, nullable=False),
        sa.Column("chunk_size_bytes", sa.Integer, nullable=False),
        sa.Column("expected_chunk_count", sa.Integer, nullable=True),
        sa.Column(
            "uploaded_chunk_count", sa.Integer, nullable=False, server_default="0"
        ),
        sa.Column(
            "status", sa.Text, nullable=False, server_default="initiated"
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("blob_name", name="uq_session_blob_name"),
        sa.UniqueConstraint("upload_id", name="uq_session_upload_id"),
        sa.CheckConstraint("chunk_size_bytes > 0", name="ck_session_chunk_size"),
        sa.CheckConstraint(
            "expected_chunk_count IS NULL OR expected_chunk_count > 0",
            name="ck_session_expected_chunks",
        ),
        sa.CheckConstraint(
            "uploaded_chunk_count >= 0", name="ck_session_uploaded_chunks"
        ),
    )

    op.create_index(
        "idx_files_owner_created",
        "files",
        ["owner_id", sa.text("created_at DESC")],
    )
    op.create_index(
        "idx_file_recipients_recipient_status",
        "file_recipients",
        ["recipient_id", "status"],
    )
    op.create_index(
        "idx_upload_sessions_owner_status",
        "upload_sessions",
        ["owner_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("idx_upload_sessions_owner_status", table_name="upload_sessions")
    op.drop_index("idx_file_recipients_recipient_status", table_name="file_recipients")
    op.drop_index("idx_files_owner_created", table_name="files")

    op.drop_table("upload_sessions")
    op.drop_table("file_recipients")
    op.drop_table("files")
    op.drop_table("user_public_keys")
    op.drop_table("users")

