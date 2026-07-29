-- Secure File Sharing - Metadata schema (PostgreSQL 14+)
-- Scope: file metadata + per-recipient wrapped keys for envelope encryption.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'recipient_status') THEN
        CREATE TYPE recipient_status AS ENUM ('active', 'revoked', 'pending');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    external_id TEXT NOT NULL UNIQUE, -- subject from auth provider
    email TEXT UNIQUE,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'owner',
    storage_plan TEXT NOT NULL DEFAULT 'free',
    vault_quota_bytes BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_public_keys (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    public_key_x25519 TEXT NOT NULL,
    public_key_ed25519 TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ NULL,
    CONSTRAINT uq_user_public_keys_version UNIQUE (user_id, key_version),
    CONSTRAINT fk_user_public_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS files (
    id VARCHAR(36) PRIMARY KEY,
    owner_id VARCHAR(36) NOT NULL,
    blob_name TEXT NOT NULL UNIQUE,
    original_filename TEXT NOT NULL,
    content_type TEXT,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes >= 0),
    encryption_alg TEXT NOT NULL, -- e.g. X25519+HKDF+AES-256-GCM
    signature_alg TEXT NOT NULL DEFAULT 'Ed25519',
    chunk_size_bytes INTEGER CHECK (chunk_size_bytes > 0),
    chunk_count INTEGER NOT NULL CHECK (chunk_count > 0),
    metadata_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS file_recipients (
    id VARCHAR(36) PRIMARY KEY,
    file_id VARCHAR(36) NOT NULL,
    recipient_id VARCHAR(36) NOT NULL,
    wrapped_file_key TEXT NOT NULL,
    wrapped_key_alg TEXT NOT NULL DEFAULT 'X25519-HKDF',
    status recipient_status NOT NULL DEFAULT 'active',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL,
    revoke_reason TEXT,
    CONSTRAINT uq_file_recipient UNIQUE (file_id, recipient_id),
    CONSTRAINT fk_file_recipients_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
    CONSTRAINT fk_file_recipients_recipient FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS upload_sessions (
    id VARCHAR(36) PRIMARY KEY,
    owner_id VARCHAR(36) NOT NULL,
    blob_name TEXT NOT NULL UNIQUE,
    upload_id TEXT NOT NULL UNIQUE,
    original_filename TEXT NOT NULL,
    chunk_size_bytes INTEGER NOT NULL CHECK (chunk_size_bytes > 0),
    expected_chunk_count INTEGER CHECK (expected_chunk_count > 0),
    uploaded_chunk_count INTEGER NOT NULL DEFAULT 0 CHECK (uploaded_chunk_count >= 0),
    status TEXT NOT NULL DEFAULT 'initiated', -- initiated|uploading|finalized|aborted
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_upload_sessions_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_files_owner_created ON files(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_file_recipients_recipient_status ON file_recipients(recipient_id, status);
CREATE INDEX IF NOT EXISTS idx_upload_sessions_owner_status ON upload_sessions(owner_id, status);

