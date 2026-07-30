# Tài liệu dự án Secure File Sharing — Hướng dẫn tái hiện / làm clone tương tự

Tài liệu này mô tả **trạng thái code thực tế** trong repo (không chỉ ý đồ ban đầu trong README): kiến trúc, luồng bảo mật, schema DB, REST API, cấu hình môi trường, và chỗ frontend/backend **chưa nối hết**. Dùng khi viết lại một hệ thống tương tự (client-side encryption + Azure Blob + API FastAPI).

---

## 1. Bản chất sản phẩm

- **Zero-knowledge theo plaintext**: Backend và Azure chỉ nhận **ciphertext**; giải mã chỉ trong trình duyệt (Web Crypto API + `@noble/curves`).
- **Lưu trữ**: Azure Blob Storage (metadata blob chứa JSON mã hóa và checksum).
- **Khóa công khai người dùng**: X25519 (trao đổi khóa) + Ed25519 (chữ ký), public lưu **Azure Key Vault** (secrets theo naming convention).
- **Metadata chia sẻ & revoke**: PostgreSQL 14+ (SQLAlchemy async + Alembic) — bảng `files`, `file_recipients`, `users`, `user_public_keys`, `upload_sessions`, `refresh_tokens`.
- **Đăng nhập**: Email/password + bcrypt; JWT access token (Bearer) + refresh token trong **cookie httpOnly** (`path=/auth`), có **rotation** và phát hiện **reuse**.
- **RBAC**: `owner` | `recipient` | `admin` — ảnh hưởng route và quyền API.

---

## 2. Cấu trúc thư mục (thực tế)

```
secure-file-sharing/
├── backend/                 # Canonical FastAPI API (Railway Root Directory)
│   ├── main.py              # FastAPI app, CORS, routers, lifespan
│   ├── auth.py              # verify JWT, get_current_user, require_roles
│   ├── audit.py             # structured audit log + redaction
│   ├── routers/             # auth, upload, download, vault, keys, …
│   ├── services/            # Azure, email, token security, AI helpers
│   ├── db/
│   │   ├── models.py        # ORM mirrors schema.sql + migrations mở rộng
│   │   ├── session.py       # AsyncEngine PostgreSQL (asyncpg)
│   │   ├── dependencies.py
│   │   ├── schema.sql       # DDL tham chiếu ban đầu
│   │   └── README.md
│   ├── migrations/          # Alembic revisions
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.tsx          # routes, role-based nav (Upload ẩn với recipient)
│   │   ├── contexts/        # AuthContext, ThemeContext
│   │   ├── hooks/           # useUpload, useDownload, useDraftState, useKeySync
│   │   ├── components/      # ProtectedRoute, KeyUnlockModal, VaultShareDialog, …
│   │   ├── pages/           # Login, Register, Upload, Download, Keys, Profile, Admin, Stress
│   │   └── utils/
│   │       ├── crypto.ts    # client crypto (chunked + single-shot + key blob)
│   │       ├── keyVault.ts  # RAM + sessionStorage wrapper (zero-knowledge)
│   │       ├── pageDraft.ts # draft form khi đổi trang (sessionStorage + RAM)
│   │       └── api.ts       # axios, silent refresh, upload helpers
│   ├── vite.config.ts       # proxy /api → localhost:8000
│   └── .env.example         # VITE_API_URL
├── locksend-ai/             # ML token security (tùy chọn)
├── docs/                    # Tài liệu đồ án / API / security / flow
│   └── DOCUMENTATION_VI.md  # file này
└── README.md
```

---

## 3. Stack kỹ thuật

Nguồn phiên bản: `frontend/package.json`, `backend/requirements.txt`.

### 3.1 Frontend

| Công nghệ | Phiên bản (repo) | Ghi chú |
|-----------|------------------|---------|
| React / React DOM | 19.2.x | SPA chính |
| React Router | 7.x | Protected routes, profile tabs |
| Vite | 8.0.x | Build; production: `serve dist` (Railway) hoặc static (Vercel) |
| TypeScript | ~5.9 | |
| Tailwind CSS | 4.2.x | Plugin `@tailwindcss/vite` |
| @noble/curves | **2.x** | X25519, Ed25519 trong browser |
| Web Crypto API | built-in | AES-256-GCM, HKDF-SHA256, SHA-256, PBKDF2 (bọc keypair) |
| Axios | 1.13.x | API client |
| Node.js | ≥ 20.19 | `engines` trong `package.json`; Nixpacks/Railway dùng Node 20 |

### 3.2 Backend

| Công nghệ | Phiên bản (repo) | Ghi chú |
|-----------|------------------|---------|
| Python | 3.11+ (dev: 3.13) | Không pin trong repo; dùng venv tương thích FastAPI stack |
| FastAPI | 0.135.x | |
| Uvicorn | 0.42.x | |
| Pydantic | 2.12.x | |
| SQLAlchemy | 2.0.x + asyncpg 0.30.x | Async PostgreSQL |
| Alembic | 1.15.x | Migrations |
| PyJWT | 2.12.x | **Không dùng python-jose**. Mặc định `JWT_ALGORITHM=HS256`; RS256/ES256 nếu set `JWT_PUBLIC_KEY` |
| Passlib + bcrypt | 1.7.x / 4.2.x | Mật khẩu đăng nhập |

### 3.3 Azure, DB, crypto

| Lớp | Công nghệ |
|-----|-----------|
| Azure | `azure-storage-blob`, `azure-keyvault-secrets`, `azure-keyvault-keys`, `azure-identity` — **DefaultAzureCredential** / Managed Identity |
| DB | PostgreSQL **14+** (JSONB, enum `recipient_status`) — không khóa version 15 trong repo |
| Crypto (file) | X25519 (RFC 7748), HKDF-SHA256 (RFC 5869), AES-256-GCM, Ed25519 (RFC 8032), SHA-256 checksum |
| Crypto (keypair) | PBKDF2-SHA256 (310 000 iter) + AES-256-GCM — passphrase chỉ trên client |

### 3.4 LockSend AI (tùy chọn)

| Công nghệ | Mục đích |
|-----------|----------|
| `locksend-ai/` + `backend/requirements-ai.txt` | Random Forest + SHAP; Admin Token Security — xem [locksend-ai/README.md](../locksend-ai/README.md) |

### 3.5 Triển khai (tham khảo)

- **Frontend**: Vercel (`vercel.json`) hoặc Railway (`nixpacks.toml`, `railway.json`) — bắt buộc `VITE_API_URL`.
- **Backend**: Railway / Azure App Service / máy chủ tùy env — không có Docker Compose trong monorepo.
- **Công cụ kiểm thử ngoài repo** (OWASP ZAP, Burp, Locust, Postman, …): dùng trong báo cáo/QA, không phải dependency runtime.

---

## 4. Nguyên tắc mật mã trên client

### 4.1 File nhỏ (single-shot)

1. Sender tạo **ephemeral X25519** cho từng file.
2. `sharedSecret = X25519(ephemeral_sk, recipient_x25519_pk)`.
3. **HKDF** (salt = ephemeral pubkey, info cố định) → **AES-256 key + 12-byte nonce**.
4. Tính **SHA-256 hex** của **toàn bộ plaintext** (`plaintextChecksum` trong metadata).
5. Encrypt AES-GCM; **Ed25519 ký ciphertext** (`signerPublicKey` trong metadata).
6. Backend lưu blob + blob metadata chứa `encryption_metadata`; có thêm `ciphertext_checksum` server-side để audit.

### 4.2 File lớn (chunked, ngưỡng trong `crypto.ts`)

- Chunk size mặc định (ví dụ 64 MiB — xem `DEFAULT_CHUNK_SIZE`, `CHUNKED_THRESHOLD`).
- **Một** shared secret HKDF chỉ sinh **AES key** (info khác single-shot).
- Nonce **từng chunk**: ghép base nonce (8 byte) + index chunk big-endian (mô tả trong comment `crypto.ts`).
- Mỗi chunk plaintext: SHA-256 → lưu array `chunkChecksums` trong metadata.
- **Manifest** chứa các trường quan trọng → **sign manifest**, không phải toàn bộ blob (tiết kiệm RAM và ký được file rất lớn).

### 4.3 Người nhận (download)

1. Fetch blob qua SAS URL (GET trực tiếp Azure).
2. Metadata từ header `x-ms-meta-encryption_metadata` (đã encode URI trong response).
3. Verify Ed25519 (ciphertext hoặc manifest tuỳ chế độ).
4. Giải mã với **private X25519** của recipient.
5. So khớp `plaintextChecksum` hoặc từng `chunkChecksums` để phát hiện thay thế plaintext/mã độc sau giải mã.

---

## 5. Lưu trữ khóa trên người dùng cuối

- **JWT access token**: chỉ trong **bộ nhớ JS** (`api.ts` `_accessToken`) — không `localStorage`.
- **Private key plaintext**: chỉ **RAM** (`keyVault.ts`); không lưu plaintext vào `localStorage` / cookie.
- **sessionStorage**: wrapper AES ephemeral (per-tab) — hỗ trợ F5 không nhập lại passphrase; đóng tab / logout / idle 15 phút → xóa.
- **PostgreSQL**: `public_key_x25519`, `public_key_ed25519`, `encrypted_key_blob` (PBKDF2 + AES-GCM từ passphrase client) — server **không** biết passphrase hay private key.
- **localStorage**: chỉ dùng cho **migrate** key cũ một lần (`decryptLegacyLocalStorage`); sau migrate nên xóa.
- **Draft form** (`useDraftState` / `pageDraft.ts`): ô nhập trên Upload, Download, Keys, Profile, Admin… — RAM khi đổi trang; JSON-safe fields còn sau F5 trong `sessionStorage` (không lưu passphrase).

Chi tiết luồng: mục “Quản lý private key” trong `README.md`.

**Key Vault naming (secret names)**:

- `pubkey-x25519-{user_id}` — trong API, `user_id` ở body `POST /keys` là **chuỗi external subject** được phép là chính user hoặc admin set cho người khác (`record.user_id`).

---

## 6. Backend — các endpoint quan trọng

Giả định base URL của API (vd. `http://localhost:8080`). OpenAPI có tại `/docs` khi chạy uvicorn.

| Phương thức | Path | Auth / Role | Ý nghĩa |
|-------------|------|-------------|---------|
| GET | `/health` | Public | Probe |
| POST | `/auth/register` | Public | Đăng ký owner, set refresh cookie |
| POST | `/auth/login` | Public | Login + cookie |
| POST | `/auth/refresh` | Cookie `sf_refresh_token` | Rotate refresh, token access mới |
| POST | `/auth/logout` | Cookie | Revoke refresh |
| GET/PATCH/POST/DELETE | `/auth/admin/users*` | Admin Bearer | CRUD vai trò người dùng |
| GET | `/keys/{user_id}` | Bearer | Đọc public keys từ Key Vault |
| POST | `/keys` | Bearer | Ghi KV + upsert rotation `UserPublicKey` trong DB |
| POST | `/upload` | owner/admin | Upload một file ciphertext + form metadata_json |
| GET | `/sas-token/{blob_name:path}` | Bearer | SAS read delegated key |
| POST | `/upload/multipart/init` | owner/admin | Tạo `UploadSession`, blob path |
| PUT | `/upload/multipart/{blob_name}/chunk/{i}` | owner/admin | `stage_block` |
| POST | `/upload/multipart/{blob_name}/finalize` | owner/admin | `commit_block_list`, tạo `File`, optional **`recipients[]`** envelope |
| GET | `/files/shared-with-me` | Bearer | File được chia sẻ (`active`) + `wrapped_file_key` |
| POST | `/files/{file_id}/revoke/{recipient_id}` | owner/admin | Soft revoke trong `file_recipients` |
| GET | `/admin/users` | admin | Duplicate list users so với auth router |

**Lưu ý triển khai**:

- **`POST /upload` (single-shot)**: chỉ đẩy blob lên Storage; **không** insert `files`/`file_recipients` trong PostgreSQL. Muốn quản lý share/revoke theo DB, cần dùng **multipart finalize** hoặc mở rộng single-shot tương tự finalize.
- **Multipart finalize**: `recipients[].recipient_id` phải là **UUID của bảng `users.id`** (không nhầm `external_id` string). Frontend `UploadPage` hiện **chưa gửi** `recipients` trong `finalizeMultipartUpload()` — chỉ gửi `chunk_count` + `metadata_json`. Backend envelope + `/files/shared-with-me` là **đã có** nhưng **UI upload chưa nối** đầy đủ envelope.

---

## 7. Pydantic / payload điển hình

### 7.1 `POST /upload/multipart/.../finalize`

Body JSON (`MultipartFinalizeRequest`):

- `chunk_count`, `metadata_json` (string JSON — trùng structured metadata frontend),
- `original_filename`, `content_type`, `file_size_bytes`, `encryption_alg`, `chunk_size_bytes` (optional overrides),
- `recipients`: list optional, mỗi phần tử `{ recipient_id, wrapped_file_key, wrapped_key_alg, key_id?, wrapped_key_version? }`,
- `chunk_checksums_present`: boolean audit flag.

Để tái hiện **envelope** đúng nghĩa: sender sinh DEK/file key ngẫu nhiên, mã hóa file với DEK; với **mỗi** recipient bọc DEK (vd. ECDH-X25519 + HKDF AEAD tùy bạn định nghĩa) và gửi `wrapped_file_key` (base64) — **spec chi tiết thuật bọc khóa cần bạn cố định** vì chỉ có vài trường string trên backend.

### 7.2 `GET /files/shared-with-me`

Trả về list `SharedFileResponse`: có `wrapped_file_key` để client unwrap DEK và giải mã blob (flow download “đăng nhập” thay cho chỉ SAS dán tay).

---

## 8. Cơ sở dữ liệu PostgreSQL

Bảng chính (ORM `db/models.py` + migrations đồng bộ):

- **`users`**: `id` (UUID PK), `external_id` unique (JWT `sub` cho user external; user đăng ký local dùng UUID string), `email`, `password_hash`, `role`, timestamps.
- **`user_public_keys`**: versioning + `is_active` khi rotate; `POST /keys` deactivate bản active cũ, tạo bản version mới.
- **`files`**: owner, blob path unique, encryption/signature algo, chunked info, **`metadata_json` JSON** (mirror metadata client).
- **`file_recipients`**: FK file + recipient, `wrapped_*`, status `active|revoked|pending`, revoked audit fields.
- **`upload_sessions`**: multipart state, TTL `expires_at`.
- **`refresh_tokens`**: `jti` unique, `replaced_by_jti`, `revoked_at` — chống reuse.

Chạy migration: trong `backend` dùng Alembic (`alembic upgrade head`). URL async: `postgresql+asyncpg://...` trong `DATABASE_URL`.

---

## 9. Biến môi trường Backend (`backend/.env.example`)

**Bắt buộc / thường dùng**:

- `DATABASE_URL`
- `AZURE_STORAGE_ACCOUNT_NAME`, `AZURE_STORAGE_CONTAINER_NAME`
- `AZURE_KEY_VAULT_URL`
- `ALLOWED_ORIGINS` (comma-separated; **không wildcard** trong production)
- JWT: `JWT_ALGORITHM`, `JWT_SECRET` (HS256) hoặc `JWT_PUBLIC_KEY` (RS256 decode), optional `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_LEEWAY_SECONDS`
- `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`, `COOKIE_SECURE`
- `DB_ECHO`

**Credential Azure**: không connection string cứng; **`DefaultAzureCredential`** (local: Azure CLI / env; cloud: Managed Identity).

SAS được tạo bằng **user delegation key** (`_generate_sas` trong `main.py`): read-only, HTTPS-only, TTL mặc định có thể 24h (upload response) hay 1h (`/sas-token`).

---

## 10. Frontend

### 10.1 `VITE_API_URL`

- `.env.example` / `.env.local.example`: ví dụ `http://localhost:8000`.
- `vite.config.ts` proxy `/api` → `http://localhost:8000` (strip prefix `/api`). Nếu set full `VITE_API_URL`, có thể bỏ qua proxy.
- Production Vercel: bắt buộc `VITE_API_URL` (build fail nếu thiếu khi `VERCEL=1`).

### 10.2 Trang và hành vi

- **`/login`, `/register`**: public; draft username giữ khi đổi trang (passphrase chỉ RAM).
- **Protected shell**: Upload (ẩn với `recipient`), Download, Keys, Hồ sơ (`/profile`: kho + lịch sử + cài đặt tài khoản), Admin (users, token security, stress).
- **Upload**: tìm user theo email (public key từ DB), hoặc dán key X25519; chế độ **gửi share** / **lưu kho**; multipart chunked ≥ 64 MB; draft form giữ khi đổi route.
- **Download**: dán SAS link (draft lưu); giải mã client với private X25519 đã unlock.
- **Keys**: tạo/mở khóa keypair, đổi passphrase, đồng bộ public key + `encrypted_key_blob` lên server.
- **Profile → Lịch sử**: tab upload / download local / hộp nhận (`shared-with-me`); revoke recipient trên file đã upload.
- **Profile → Kho**: upload vault, chia sẻ envelope, thư mục.

### 10.3 Axios interceptor

401 → `POST /auth/refresh` (withCredentials); thành công thì gắn lại Bearer và retry; thất bại redirect `/login`.

---

## 11. Middleware & observability

- **`X-Request-ID`**: middleware gắn `request.state.request_id`; response header mirror.
- **`audit.log_event`**: ghi JSON, redact các key nhạy cảm (`wrapped_file_key`, token, cookie, ...).

---

## 12. Test

- Pytest trong `backend/tests/` (`pytest.ini`): có `test_auth.py`, `test_share.py`, `test_revoke.py`, `conftest.py` — dùng khi tái hiện hành vi API + DB fixtures.

---

## 13. Checklist triển khai local để tái hiện từ đầu

1. PostgreSQL tạo database; set `DATABASE_URL`; `alembic upgrade head`.
2. Blob container tồn tại (`AZURE_STORAGE_CONTAINER_NAME`).
3. Azure Key Vault + quyền cho credential bạn chạy (local: `az login` + RBAC KV Secrets Officer / Storage).
4. Backend: `pip install -r requirements.txt`, `uvicorn main:app --reload --port 8000` (đồng bộ với proxy Vite mặc định).
5. Frontend: Node ≥ 20.19, `npm install`, `npm run dev` (port 5173), `VITE_API_URL` trỏ đúng API và `ALLOWED_ORIGINS`.
6. Đăng ký → login → Keys page tạo cặp khóa → `POST /keys` với Bearer.
7. Thử nhỏ: single-shot upload → copy SAS → download page.
8. Lớn: multipart flow → finalize (và sau này thêm envelope recipients khi làm chức inbox).

---

## 14. Chuẩn “clone” có thể cải tiến (ngoài scope code hiện tại)

- Nối **finalize** với **`recipients`** + UI chọn recipient từ `GET /auth/admin/users` hoặc tìm user theo email.
- Trang Download: tab “Shared with me” gọi `/files/shared-with-me` → SAS per file → unwrap key → decrypt.
- **Single-shot** cũng tạo row `files` + recipients để thống nhất model.
- Key Vault: chỉ public key là đủ; cân nhắc dùng key version từ bảng `user_public_keys` khi bọc envelope.
- Harden browser key storage (passphrase wrapping, WebAuthn) như backlog README.

---

## 15. Mối quan hệ với `README.md`

`README.md` tóm tắt kiến trúc, stack (bảng phiên bản), zero-knowledge key flow và chạy local. Hai file nên **đồng bộ** khi đổi dependency major (React, @noble/curves, JWT) hoặc luồng lưu key.

---

*Tài liệu sinh để tái hiện dự án. Cập nhật lần cuối: stack React 19, @noble/curves 2.x, PyJWT, draft form (`useDraftState`), zero-knowledge key vault.*
