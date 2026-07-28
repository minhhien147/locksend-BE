"""
SQLAlchemy ORM models — mirrors schema.sql exactly.

Relationships:
  User  ──< File            (owner)
  User  ──< UserPublicKey
  File  ──< FileRecipient
  User  ──< FileRecipient   (recipient)
  User  ──< UploadSession
  User  ──< RefreshToken
"""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from .base import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Enum ──────────────────────────────────────────────────────────────────────


class RecipientStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    pending = "pending"


class AiJobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


# ── Tables ────────────────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(Text, unique=True)
    display_name: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, nullable=False, default="owner")
    storage_plan: Mapped[str] = mapped_column(Text, nullable=False, default="free")
    vault_quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    public_keys: Mapped[list["UserPublicKey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    files: Mapped[list["File"]] = relationship(
        back_populates="owner", foreign_keys="File.owner_id"
    )
    vault_folders: Mapped[list["VaultFolder"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    received_files: Mapped[list["FileRecipient"]] = relationship(
        back_populates="recipient",
        foreign_keys="FileRecipient.recipient_id",
        passive_deletes=True,
    )
    upload_sessions: Mapped[list["UploadSession"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    display_name_history: Mapped[list["UserDisplayNameHistory"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    security_alerts: Mapped[list["UserSecurityAlert"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    email_verification_codes: Mapped[list["EmailVerificationCode"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class EmailVerificationCode(Base):
    """OTP xác minh email — 6 chữ số, hết hạn sau vài phút."""

    __tablename__ = "email_verification_codes"
    __table_args__ = (Index("ix_evc_user_created", "user_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(Text, nullable=False)
    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="email_verification_codes")


class UserDisplayNameHistory(Base):
    """Audit: mỗi lần user đổi display_name qua PATCH /auth/me."""

    __tablename__ = "user_display_name_history"
    __table_args__ = (Index("ix_display_name_history_user_changed", "user_id", "changed_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    old_display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_display_name: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="display_name_history")


class UserPublicKey(Base):
    __tablename__ = "user_public_keys"
    __table_args__ = (
        UniqueConstraint("user_id", "key_version", name="uq_user_public_keys_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    public_key_x25519: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_ed25519: Mapped[str] = mapped_column(Text, nullable=False)
    # Zero-knowledge: server lưu private key đã mã hóa bằng passphrase client.
    # Server KHÔNG biết passphrase hay private key plaintext.
    encrypted_key_blob: Mapped[str | None] = mapped_column(Text, nullable=True)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(back_populates="public_keys")


class VaultFolder(Base):
    __tablename__ = "vault_folders"
    __table_args__ = (
        UniqueConstraint("owner_id", "parent_id", "name", name="uq_vault_folder_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    parent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("vault_folders.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    owner: Mapped["User"] = relationship(back_populates="vault_folders")
    files: Mapped[list["File"]] = relationship(back_populates="folder")


class File(Base):
    __tablename__ = "files"
    __table_args__ = (
        CheckConstraint("file_size_bytes >= 0", name="ck_files_size"),
        CheckConstraint("chunk_count > 0", name="ck_files_chunk_count"),
        CheckConstraint(
            "chunk_size_bytes IS NULL OR chunk_size_bytes > 0",
            name="ck_files_chunk_size",
        ),
        CheckConstraint(
            "storage_mode IN ('share', 'vault')",
            name="ck_files_storage_mode",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    storage_mode: Mapped[str] = mapped_column(Text, nullable=False, default="share")
    folder_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("vault_folders.id", ondelete="SET NULL"), nullable=True
    )
    blob_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str | None] = mapped_column(Text)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    encryption_alg: Mapped[str] = mapped_column(Text, nullable=False)
    signature_alg: Mapped[str] = mapped_column(
        Text, nullable=False, default="Ed25519"
    )
    chunk_size_bytes: Mapped[int | None] = mapped_column(Integer)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    owner: Mapped["User"] = relationship(
        back_populates="files", foreign_keys=[owner_id]
    )
    recipients: Mapped[list["FileRecipient"]] = relationship(
        back_populates="file", cascade="all, delete-orphan"
    )
    folder: Mapped["VaultFolder | None"] = relationship(back_populates="files")


class FileRecipient(Base):
    __tablename__ = "file_recipients"
    __table_args__ = (
        UniqueConstraint("file_id", "recipient_id", name="uq_file_recipient"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    file_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    recipient_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    wrapped_file_key: Mapped[str] = mapped_column(Text, nullable=False)
    wrapped_key_alg: Mapped[str] = mapped_column(
        Text, nullable=False, default="X25519-HKDF"
    )
    # Key rotation tracking: ID của UserPublicKey dùng để wrap + version số
    key_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    wrapped_key_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    status: Mapped[RecipientStatus] = mapped_column(
        Enum(RecipientStatus, name="recipient_status", native_enum=False),
        nullable=False,
        default=RecipientStatus.active,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(Text)

    file: Mapped["File"] = relationship(back_populates="recipients")
    recipient: Mapped["User"] = relationship(
        back_populates="received_files", foreign_keys=[recipient_id]
    )


class UploadSession(Base):
    __tablename__ = "upload_sessions"
    __table_args__ = (
        CheckConstraint("chunk_size_bytes > 0", name="ck_session_chunk_size"),
        CheckConstraint(
            "expected_chunk_count IS NULL OR expected_chunk_count > 0",
            name="ck_session_expected_chunks",
        ),
        CheckConstraint(
            "uploaded_chunk_count >= 0", name="ck_session_uploaded_chunks"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    blob_name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    upload_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    chunk_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_chunk_count: Mapped[int | None] = mapped_column(Integer)
    uploaded_chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="initiated")
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    owner: Mapped["User"] = relationship(back_populates="upload_sessions")


# ── Refresh Tokens ─────────────────────────────────────────────────────────────


class RefreshToken(Base):
    """
    Mỗi row là 1 refresh token đang hoạt động (hoặc đã bị thu hồi).

    Rotation strategy:
      - Khi refresh: mark cũ bằng replaced_by_jti, phát token mới.
      - Nếu ai dùng token đã bị replaced → reuse attack → revoke all của user.
    """

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    jti: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_jti: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")


class UploadLog(Base):
    """
    Ghi nhận mỗi lần upload thành công (single-shot hoặc multipart finalize).
    Không xoá theo file — giữ audit trail kể cả khi file bị xoá.
    """
    __tablename__ = "upload_logs"
    __table_args__ = (
        Index("ix_upload_logs_user_id", "user_id"),
        Index("ix_upload_logs_file_id", "file_id"),
        Index("ix_upload_logs_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    file_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="SET NULL"), nullable=True
    )
    blob_name: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    upload_type: Mapped[str] = mapped_column(Text, nullable=False, default="single")  # single | multipart
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User | None"] = relationship()


class DownloadLog(Base):
    """
    Ghi nhận mỗi lần tải file thành công.
    FE gọi POST /files/{file_id}/download-log sau khi giải mã xong.
    """
    __tablename__ = "download_logs"
    __table_args__ = (
        Index("ix_download_logs_user_id", "user_id"),
        Index("ix_download_logs_file_id", "file_id"),
        Index("ix_download_logs_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    file_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="SET NULL"), nullable=True
    )
    blob_name: Mapped[str] = mapped_column(Text, nullable=False)
    original_filename: Mapped[str] = mapped_column(Text, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


# ── AI Token Security ──────────────────────────────────────────────────────────


class SasTokenRecord(Base):
    """
    Bản ghi mỗi SAS URL được cấp. Không lưu token thực — chỉ lưu token_id (UUID)
    để tham chiếu trong access logs và cho phép soft-revoke.

    Soft revoke: khi is_revoked=True, backend từ chối cấp SAS mới cho blob này
    với user này cho đến khi hết thời gian phân tích hoặc admin reset.
    (Azure SAS không có true revoke nếu không dùng Stored Access Policy.)
    """
    __tablename__ = "sas_token_records"
    __table_args__ = (
        Index("ix_sas_records_user_id", "user_id"),
        Index("ix_sas_records_blob_name", "blob_name"),
        Index("ix_sas_records_expires_at", "expires_at"),
        Index("ix_sas_records_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    token_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True, default=_uuid)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    blob_name: Mapped[str] = mapped_column(Text, nullable=False)
    file_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="SET NULL"), nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(Text)
    # Thống kê: cập nhật khi access log ghi nhận thêm
    access_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_ip_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ai_risk_score: Mapped[int | None] = mapped_column(Integer)
    ai_risk_level: Mapped[str | None] = mapped_column(Text)
    ai_recommendation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User | None"] = relationship()


class TokenAccessLog(Base):
    """
    Log chi tiết mỗi lần token được sử dụng (JWT access token hoặc SAS request).
    Dùng làm nguồn dữ liệu cho token security rule engine / AI tích hợp.
    Không lưu giá trị token — chỉ lưu token_ref (jti ẩn hoặc sas token_id).
    """
    __tablename__ = "token_access_logs"
    __table_args__ = (
        Index("ix_tal_user_id", "user_id"),
        Index("ix_tal_token_type", "token_type"),
        Index("ix_tal_token_ref", "token_ref"),
        Index("ix_tal_ip_address", "ip_address"),
        Index("ix_tal_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # "jwt" hoặc "sas"
    token_type: Mapped[str] = mapped_column(Text, nullable=False)
    # jti (masked) cho JWT; token_id cho SAS
    token_ref: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    country_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User | None"] = relationship()


class TokenSecurityAlert(Base):
    """Cảnh báo AI realtime khi token được sử dụng bất thường."""
    __tablename__ = "token_security_alerts"
    __table_args__ = (
        Index("ix_tsa_created_at", "created_at"),
        Index("ix_tsa_is_read", "is_read"),
        Index("ix_tsa_token_ref", "token_ref"),
        Index("ix_tsa_file_id", "file_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    token_type: Mapped[str] = mapped_column(Text, nullable=False)
    token_ref: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    file_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="SET NULL"), nullable=True
    )
    file_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ai_score_pct: Mapped[int] = mapped_column(Integer, nullable=False)
    ai_level: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    agreement_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    behavior_badges: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary_vi: Mapped[str | None] = mapped_column(Text, nullable=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User | None"] = relationship()


class TokenAiScoreSnapshot(Base):
    """Lịch sử AI score — dùng cho biểu đồ trend."""
    __tablename__ = "token_ai_score_snapshots"
    __table_args__ = (
        Index("ix_tass_created_at", "created_at"),
        Index("ix_tass_token_ref", "token_ref"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    token_type: Mapped[str] = mapped_column(Text, nullable=False)
    token_ref: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rule_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ai_score_pct: Mapped[int] = mapped_column(Integer, nullable=False)
    ai_level: Mapped[str] = mapped_column(Text, nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False, default="realtime")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User | None"] = relationship()


class TokenAiAnalysisJob(Base):
    """Bảng track tiến trình background job phân tích AI cho token list."""

    __tablename__ = "token_ai_analysis_jobs"
    __table_args__ = (
        Index("ix_taaj_created_at", "created_at"),
        Index("ix_taaj_status", "status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    triggered_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    token_type: Mapped[str] = mapped_column(Text, nullable=False, default="all")
    total_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    analyzed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped_cached: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[AiJobStatus] = mapped_column(
        Enum(AiJobStatus, name="aijobstatus", create_constraint=True),
        nullable=False,
        default=AiJobStatus.pending,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User | None"] = relationship()


class UserSecurityAlert(Base):
    """Cảnh báo bảo mật gửi tới owner/recipient — IP bất thường, keypair hết hạn, …"""

    __tablename__ = "user_security_alerts"
    __table_args__ = (
        Index("ix_usa_user_created", "user_id", "created_at"),
        Index("ix_usa_user_unread", "user_id", "is_read"),
        Index("ix_usa_dedupe", "dedupe_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    alert_type: Mapped[str] = mapped_column(Text, nullable=False)
    file_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("files.id", ondelete="SET NULL"), nullable=True
    )
    file_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    title_vi: Mapped[str] = mapped_column(Text, nullable=False)
    message_vi: Mapped[str] = mapped_column(Text, nullable=False)
    detail_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    dedupe_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="security_alerts")
