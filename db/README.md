# Database structure (PostgreSQL)

This schema is designed for Phase 2 in project roadmap:

- Envelope encryption (`wrapped_file_key` per recipient)
- Recipient revoke without re-encrypting blob
- Metadata-first access control for file sharing

## Tables

- `users`: identity mapped from external auth (JWT subject).
- `user_public_keys`: X25519 + Ed25519 public key versions per user.
- `files`: blob metadata (owner, algorithms, chunk information, metadata JSON).
- `file_recipients`: per-recipient wrapped DEK + revoke state.
- `upload_sessions`: tracks multipart upload lifecycle before finalize.

## Core relationships

- One `users` -> many `files` (owner)
- One `users` -> many `user_public_keys`
- One `files` -> many `file_recipients`
- One `users` -> many `file_recipients` (as recipient)
- One `users` -> many `upload_sessions`

## Suggested API mapping

- `POST /upload/multipart/init`: insert `upload_sessions` row.
- `PUT /upload/multipart/{blob}/chunk/{i}`: increment `uploaded_chunk_count`.
- `POST /upload/multipart/{blob}/finalize`:
  1. validate session,
  2. insert into `files`,
  3. insert many rows into `file_recipients`,
  4. mark session `finalized`.
- `GET /files/shared-with-me`: query `file_recipients` where `recipient_id` and `status='active'`.
- `POST /files/{file_id}/revoke/{recipient_id}`: update `file_recipients.status='revoked'`, set `revoked_at`.

## Notes

- Store only encrypted/wrapped material in DB (`wrapped_file_key`, ciphertext metadata).
- Never store private keys or plaintext file keys.
- You can keep Azure Key Vault for keys and only persist metadata in PostgreSQL.
