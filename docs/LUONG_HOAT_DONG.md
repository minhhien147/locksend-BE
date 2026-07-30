# LockSend — Luồng hoạt động hệ thống

Tài liệu mô tả **luồng thực tế theo code hiện tại** của monorepo Secure File Sharing (thương hiệu UI: **LockSend**). Dùng khi onboard thành viên mới, demo, hoặc đối chiếu hành vi FE/BE.

**Cập nhật theo code:** tháng 6/2026.

**Tài liệu liên quan:**

| File | Mục đích |
|------|----------|
| [README.md](../README.md) | Tổng quan, chạy local, nguyên tắc bảo mật |
| [DOCUMENTATION_VI.md](./DOCUMENTATION_VI.md) | API chi tiết, schema DB, env, gap FE/BE |
| [HUONG_DAN_CHUC_NANG_VA_FLOW_WEB.md](./HUONG_DAN_CHUC_NANG_VA_FLOW_WEB.md) | Hướng dẫn chức năng từng trang web |

---

## 1. Bản chất sản phẩm

LockSend là hệ thống **chia sẻ file zero-knowledge**:

- Trình duyệt **mã hóa và giải mã** file; backend và Azure Blob **không bao giờ thấy plaintext**.
- Server chỉ lưu **ciphertext**, metadata mã hóa, public key, và `encrypted_key_blob` (private key đã bọc bằng passphrase phía client).
- Chia sẻ file qua **SAS URL read-only** thời hạn ngắn, hoặc qua **hộp nhận in-app** (PostgreSQL + envelope key).

### Stack mật mã

| Lớp | Thuật toán | Vai trò |
|-----|------------|---------|
| Trao đổi khóa file | X25519 (ECDH) | Sinh shared secret per-file |
| Dẫn xuất khóa | HKDF-SHA256 | AES key + nonce từ shared secret |
| Mã hóa nội dung | AES-256-GCM | Ciphertext file |
| Chữ ký | Ed25519 | Xác thực ciphertext / manifest |
| Toàn vẹn plaintext | SHA-256 | Checksum trước mã hóa, verify sau giải mã |
| Bọc keypair | PBKDF2-SHA256 (310k) + AES-256-GCM | Passphrase → `encrypted_key_blob` |

### Thành phần monorepo

```
secure-file-sharing/
├── frontend/       React 19 + Vite 8 + TypeScript + Tailwind v4
├── backend/        FastAPI + SQLAlchemy async + PostgreSQL + Azure SDK
└── locksend-ai/    ML token security (Random Forest + SHAP, tùy chọn)
```

---

## 2. Kiến trúc tổng quan

```text
                 +------------------------------+
                 |   Recipient Browser (React)  |
                 | - Paste SAS URL              |
                 | - Verify Ed25519 signature   |
                 | - Decrypt AES-GCM (client)   |
                 +---------------^--------------+
                                 |
                                 | HTTPS (SAS URL, read-only, time-limited)
                                 |
+----------------+      +--------+---------+      +---------------------------+
| Sender Browser | ---> |   FastAPI API    | ---> | Azure Blob Storage        |
| (React)        |      |   (backend)      |      | - ciphertext only         |
| - Encrypt file |      | - Upload/SAS     |      | - encryption_metadata     |
| - Sign payload |      | - Auth, vault    |      +---------------------------+
+----------------+      +--------+---------+
                                 |
                                 v
                      +---------------------------+
                      | PostgreSQL                |
                      | users, keys, files, vault |
                      | refresh_tokens, alerts    |
                      +---------------------------+
                      | Azure Key Vault (tùy chọn)|
                      | mirror public keys        |
                      +---------------------------+
```

### Trust boundaries

| Vùng | Dữ liệu nhạy cảm | Ghi chú |
|------|------------------|---------|
| **Browser RAM** | Plaintext file, private key plaintext | Mất khi logout / đóng tab / timeout 15 phút |
| **sessionStorage** | AES wrapper bọc private key (không có passphrase) | Per-tab; hỗ trợ F5 không nhập lại passphrase |
| **Backend** | JWT, metadata, blob đã mã hóa | Không biết passphrase; không giải mã file |
| **Azure Blob** | Chỉ ciphertext + metadata blob | Zero-knowledge storage |
| **PostgreSQL** | Public keys, `encrypted_key_blob`, file records | Không có private key plaintext |

---

## 3. Hai lớp “đăng nhập” (quan trọng)

Hệ thống tách **xác thực tài khoản** và **mở khóa key mật mã**. Hai lớp này hoàn toàn độc lập.

| Lớp | Cơ chế | Lưu ở đâu |
|-----|--------|-----------|
| **Auth** | Email/password hoặc Google OAuth → JWT access (RAM) + refresh **httpOnly cookie** | `users`, `refresh_tokens` |
| **Crypto vault** | Passphrase → giải `encrypted_key_blob` → private key vào RAM | Server: blob đã mã hóa; Client: RAM + sessionStorage wrapper |

### Hành vi chi tiết

| Sự kiện | Auth (JWT) | Crypto vault |
|---------|------------|--------------|
| Đăng nhập thành công | Có access token + refresh cookie | **Chưa** có private key — cần passphrase |
| F5 cùng tab | Silent `POST /auth/refresh` | `restoreFromSession()` nếu wrapper còn |
| Tab mới / wrapper hết | Refresh cookie vẫn có thể login | Phải nhập passphrase (KeyUnlockModal) |
| Khóa phiên (soft lock) | Vẫn đăng nhập | Xóa RAM, giữ wrapper — F5 không cần passphrase |
| Logout | Xóa token + revoke refresh | `clearAll()` — xóa RAM + sessionStorage |
| Idle 15 phút | Vẫn đăng nhập | Auto-lock → hiện KeyUnlockModal |

Module FE chính: `frontend/src/utils/keyVault.ts`, `frontend/src/utils/crypto.ts`.

API BE chính: `GET /keys/my-encrypted-blob`, `POST /keys`.

---

## 4. Xác thực tài khoản & email

### Đăng ký / đăng nhập

```text
POST /auth/register  → user role mặc định: owner
POST /auth/login     → JWT + refresh cookie (rotation, phát hiện reuse)
POST /auth/google    → Google OAuth (email tự verified)
POST /auth/refresh   → silent refresh khi load trang (cookie httpOnly, path=/auth)
POST /auth/logout    → revoke refresh token
```

- Access token chỉ trong **memory** (`api.ts`), không localStorage.
- 401 → silent refresh → retry hoặc redirect `/login`.

### Xác minh email

Nhiều endpoint nhạy cảm yêu cầu `require_verified_email` (upload, keys, vault, …).

```text
Đăng ký → redirect /verify-email
    → POST /auth/verify-email (mã OTP)
    → hoặc POST /auth/resend-verification
```

Google OAuth bỏ qua bước OTP vì email đã được Google xác nhận.

### Role (RBAC)

| Role | Quyền chính |
|------|-------------|
| `owner` | Upload, share, vault, revoke file của mình |
| `recipient` | Chỉ Download + Hộp nhận; **không** thấy menu Upload |
| `admin` | Quản lý user, Token Security, stress test |

---

## 5. Luồng onboarding — lần đầu sử dụng

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Đăng ký (email + password) hoặc Google OAuth             │
│ 2. Xác minh email (/verify-email) — nếu đăng ký thường      │
│ 3. Đăng nhập → JWT + refresh cookie                         │
│ 4. Trang Keys (/keys) hoặc KeyUnlockModal:                  │
│      • Sinh cặp khóa X25519 + Ed25519                       │
│      • Đặt passphrase                                       │
│      • encryptKeyBlob → POST /keys                          │
│      • setKeys() → private key vào RAM + session wrapper    │
│ 5. Sẵn sàng Upload / Download                               │
└─────────────────────────────────────────────────────────────┘
```

**Lưu ý:** Đăng nhập xong vẫn phải tạo/mở khóa keypair trước khi mã hóa hoặc giải mã file.

---

## 6. Quản lý keypair (`/keys`)

| Thao tác | Mô tả |
|----------|-------|
| **Tạo keypair** | Sinh X25519 + Ed25519; passphrase → `encryptKeyBlob` |
| **Đồng bộ server** | `POST /keys`: public keys + `encrypted_key_blob` |
| **Mở khóa** | Nhập passphrase → `decryptKeyBlob` → `setKeys()` |
| **Khóa phiên** | Xóa RAM, giữ session wrapper |
| **Xóa session** | Xóa RAM + sessionStorage |
| **Migrate** | Key cũ trong localStorage → upload blob → xóa local (một lần) |
| **Rotate key** | Tạo key mới → version tăng; file cũ **không** mở được bằng key mới |

Server trả thêm trạng thái hết hạn keypair: `keypair_expires_at`, `keypair_days_left`, cảnh báo qua `SecurityAlertsBanner`.

**Zero-knowledge:** Server không nhận passphrase hay private key plaintext.

---

## 7. Luồng Upload (`/`)

Trang Upload có **hai chế độ** (draft được giữ khi chuyển trang qua `useDraftState`).

### 7.1 Gửi cho người khác (share)

```text
Chọn file
    → Tìm recipient theo email (GET /auth/users/search)
       hoặc dán public key X25519 thủ công
    → Mã hóa trên client:
         • 1 người nhận: encryptFile
         • Nhiều người (file nhỏ): encryptFileForRecipients (envelope)
         • File ≥ 64 MB: chunked encrypt + multipart upload
    → Upload ciphertext + metadata
    → Nhận SAS URL read-only
    → Gửi link cho recipient (email, chat, v.v.)
```

**UI states:** `idle` → `encrypting` → `uploading` → `done` / `error`.

### 7.2 Lưu vào kho cá nhân (vault)

```text
Chọn chế độ "Lưu vào kho"
    → Mã hóa bằng public key của chính mình
    → Chọn thư mục vault (tùy chọn)
    → Upload → ghi DB (storage_mode = vault)
    → Quản lý tại Profile → Kho
```

### 7.3 Kích thước file

| Kích thước | Pipeline |
|------------|----------|
| Nhỏ | `POST /upload` single-shot |
| Lớn (≥ 64 MB) | `POST /upload/multipart/init` → `PUT .../chunk/{i}` → `POST .../finalize` |

Multipart finalize có thể ghi `files` + `file_recipients` (envelope) — phù hợp quản lý share/revoke đầy đủ hơn single-shot.

### 7.4 Metadata mã hóa (tóm tắt)

**Single-shot / envelope:**

| Trường | Ý nghĩa |
|--------|----------|
| `ephemeralPublicKey` | X25519 ephemeral (base64) |
| `nonce` | IV AES-GCM hoặc nonce bọc envelope |
| `signature` | Ed25519 trên ciphertext |
| `signerPublicKey` | Ed25519 public của sender |
| `plaintextChecksum` | SHA-256 hex plaintext |
| `envelopeMode`, `contentKeyEnvelope` | Nhiều recipient / vault share |

**Chunked (file lớn):**

| Trường | Ý nghĩa |
|--------|----------|
| `isChunked`, `chunkSize`, `chunkCount` | Cấu hình chunk |
| `baseNonce` | Sinh nonce per-chunk |
| `chunkChecksums` | SHA-256 từng chunk plaintext |
| `chunkBlobFormat` | `azure_blocks` hoặc `packed` |

---

## 8. Luồng Download (`/download`)

```text
Dán SAS URL (draft được lưu)
    → Kiểm tra keypair đã unlock (keyVault)
    → Tải ciphertext:
         • Trực tiếp từ Azure Blob qua SAS
         • Hoặc proxy BE nếu CORS (POST /files/ciphertext/by-sas)
    → decryptFile hoặc decryptFileChunked:
         • Verify Ed25519
         • HKDF → AES-GCM giải mã
         • So SHA-256 plaintext với metadata
    → Tải file về máy
    → Ghi download log (POST /files/download-log)
```

**Lỗi thường gặp:** *Nonce không khớp* — sai private key (ví dụ đã rotate keypair sau khi file được mã hóa).

**Tích hợp tùy chọn:** sau giải mã có thể tra SHA-256 qua VirusTotal (`POST /integrations/virustotal/hash`).

---

## 9. Hộp nhận & lịch sử (`/profile`)

### Hộp nhận in-app (Flow E)

```text
Profile → tab Lịch sử → Hộp nhận
    → GET /files/shared-with-me
    → Metadata + wrapped_file_key (envelope) từ DB
    → GET /files/shared/{file_id}/sas → SAS mới
    → Giải mã trong Download hoặc inline
```

### Lịch sử upload

```text
GET /files/my-files
    → Danh sách file đã gửi
    → Copy SAS / refresh SAS (GET /files/{file_id}/sas)
    → Revoke recipient
```

### Kho cá nhân (vault)

```text
GET /vault/folders, GET /vault/files
    → Tạo/xóa thư mục, đổi tên/di chuyển file
    → GET /vault/quota — dung lượng đã dùng
    → Tải về: GET /vault/files/{file_id}/ciphertext
    → Chia sẻ: POST /vault/files/{file_id}/share (re-wrap, không upload lại blob)
    → Xóa: DELETE /vault/files/{file_id}
```

---

## 10. Thu hồi quyền (Flow F)

```text
Profile → Lịch sử → Đã upload → danh sách recipient → Revoke
    → POST /files/{file_id}/revoke/{recipient_id}
```

- **Envelope mode:** chỉ xóa `wrapped_file_key` của recipient; blob ciphertext **không** đổi.
- Recipient đã revoke không còn metadata giải mã trong hộp nhận.

---

## 11. Bảo mật & giám sát

### 11.1 JWT access logging

Middleware `jwt_access_log_middleware` ghi mọi request có Bearer JWT hợp lệ vào `TokenAccessLog`. Kích hoạt scan AI realtime (`schedule_token_access_scan`).

### 11.2 Admin Token Security (`/admin/token-security`)

| Chức năng | API |
|-----------|-----|
| Tổng quan | `GET /auth/admin/token-security/overview` |
| Phân tích token | `POST /auth/admin/token-security/analyze` |
| AI phân tích | `POST /auth/admin/token-security/ai/analyze` |
| Revoke JWT user | `POST /auth/admin/token-security/revoke/jwt/{user_id}` |
| Revoke SAS | `POST /auth/admin/token-security/revoke/sas/{token_id}` |
| Cảnh báo | `GET /auth/admin/token-security/alerts` |

**LockSend AI** (`locksend-ai/`): Random Forest + SHAP; chạy local hoặc qua `LOCKSEND_AI_URL`.

### 11.3 Cảnh báo người dùng

`SecurityAlertsBanner` hiển thị:

- Keypair sắp hết hạn / đã hết hạn
- Truy cập file từ nhiều IP (`multi_ip_access`)
- Thông báo từ admin

API: `GET /auth/me/security-alerts`, `PATCH /auth/me/security-alerts/read`.

### 11.4 Trợ lý AI

`AssistantChatWidget` → `POST /integrations/assistant/chat` (Gemini, khi cấu hình).

---

## 12. Route Frontend

| Route | Trang | Ghi chú |
|-------|-------|---------|
| `/login` | Đăng nhập | Public |
| `/register` | Đăng ký | Public |
| `/verify-email` | Xác minh email | Protected, cho phép chưa verified |
| `/` | Upload | Ẩn với `recipient` → redirect Download |
| `/download` | Download | Tất cả role |
| `/keys` | Quản lý keypair | |
| `/profile` | Hồ sơ, Kho, Lịch sử | `?tab=history` cho lịch sử |
| `/admin/users` | Quản lý user | Admin only |
| `/admin/token-security` | Token Security | Admin only |
| `/admin/stress` | Stress test crypto | Admin only |

Redirect cũ: `/shared`, `/history`, `/vault` → `/profile`.

---

## 13. API Backend — nhóm endpoint

### Ops

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/health` | Health + trạng thái LockSend AI |
| GET | `/` | Thông tin service |

### Auth (`/auth/*`)

Đăng ký, login, Google OAuth, refresh, logout, verify email, đổi mật khẩu, profile, tìm user, admin users, security alerts.

### Keys

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/keys/my-encrypted-blob` | Blob đã mã hóa + trạng thái keypair |
| GET | `/keys/{user_id}` | Public keys (Key Vault hoặc DB) |
| POST | `/keys` | Lưu public keys + encrypted blob |

### Upload & files

| Method | Path | Mô tả |
|--------|------|-------|
| POST | `/upload` | Upload single-shot |
| POST | `/upload/multipart/init` | Bắt đầu multipart |
| PUT | `/upload/multipart/{blob}/chunk/{i}` | Gửi chunk |
| POST | `/upload/multipart/{blob}/finalize` | Hoàn tất + SAS |
| GET | `/sas-token/{blob_name}` | Cấp lại SAS |
| GET | `/files/my-files` | Lịch sử upload |
| GET | `/files/shared-with-me` | Hộp nhận |
| GET | `/files/{file_id}/sas` | SAS mới |
| POST | `/files/{file_id}/revoke/{recipient_id}` | Thu hồi |
| POST | `/files/ciphertext/by-sas` | Proxy tải ciphertext (CORS) |

### Vault

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/vault/quota` | Dung lượng kho |
| GET/POST | `/vault/folders` | Thư mục |
| GET/PATCH/DELETE | `/vault/files/...` | File trong kho |
| POST | `/vault/files/{id}/share` | Chia sẻ re-wrap |

### Integrations

| Method | Path | Mô tả |
|--------|------|-------|
| GET | `/integrations/status` | VirusTotal / Gemini có bật không |
| POST | `/integrations/virustotal/hash` | Tra SHA-256 |
| POST | `/integrations/assistant/chat` | Chat trợ lý |

Chi tiết request/response: [DOCUMENTATION_VI.md](./DOCUMENTATION_VI.md).

---

## 14. Sơ đồ luồng end-to-end

```text
                    ┌──────────────────────┐
                    │   ONBOARDING         │
                    │ Register → Verify    │
                    │ → Login → Keys       │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   MỖI PHIÊN          │
                    │ Refresh JWT          │
                    │ Unlock key (pass /   │
                    │   session restore)   │
                    └──────────┬───────────┘
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │ SHARE       │    │ VAULT       │    │ DOWNLOAD    │
    │ encrypt →   │    │ encrypt self│    │ SAS → verify│
    │ upload →    │    │ → vault DB  │    │ → decrypt → │
    │ SAS link    │    │ → re-wrap   │    │ checksum    │
    │             │    │   share     │    │             │
    └──────┬──────┘    └─────────────┘    └──────▲──────┘
           │                                     │
           └──────── recipient: SAS hoặc ─────────┘
                    hộp nhận in-app
```

---

## 15. Biến môi trường quan trọng

### Backend (`backend/.env`)

| Biến | Mục đích |
|------|----------|
| `DATABASE_URL` | PostgreSQL async (`postgresql+asyncpg://...`) |
| `AZURE_STORAGE_ACCOUNT_NAME`, `AZURE_STORAGE_CONTAINER_NAME` | Blob Storage |
| `AZURE_KEY_VAULT_URL` | Mirror public keys (tùy chọn) |
| `JWT_SECRET` / `JWT_PUBLIC_KEY`, `JWT_ALGORITHM` | JWT (mặc định HS256) |
| `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS` | Thời hạn token |
| `ALLOWED_ORIGINS`, `COOKIE_SECURE`, `COOKIE_SAMESITE` | CORS & cookie |
| `LOCKSEND_AI_URL` | ML service (tùy chọn) |
| `GOOGLE_CLIENT_ID` | Google OAuth (tùy chọn) |

### Frontend (`frontend/.env.local`)

| Biến | Mục đích |
|------|----------|
| `VITE_API_URL` | URL backend (bắt buộc production) |

---

## 16. Checklist vận hành nhanh

1. **Đăng ký / đăng nhập** tài khoản.
2. **Xác minh email** (nếu chưa).
3. **Keys**: tạo keypair + passphrase; đồng bộ `POST /keys`.
4. **Mở khóa key** (passphrase hoặc F5 cùng tab).
5. **Upload**: chọn recipient hoặc lưu kho → mã hóa & upload → copy SAS (nếu share).
6. **Recipient**: đăng nhập + mở khóa **đúng keypair** → Download dán SAS hoặc Hộp nhận.
7. **Thu hồi** (nếu cần): Lịch sử upload → Revoke recipient.
8. **SAS hết hạn**: lấy SAS mới qua UI lịch sử hoặc `GET /files/{id}/sas`.

---

## 17. Giới hạn & lưu ý vận hành

| Chủ đề | Ghi chú |
|--------|---------|
| Rotate keypair | File mã hóa bằng public key **cũ** không mở được bằng key **mới** |
| Lộ private key | Attacker giải mã được mọi file đã bọc cho key đó |
| Single-shot upload | Có thể **không** tạo row `files` — dùng multipart finalize hoặc vault để quản lý share/revoke đầy đủ |
| Recipient role | Không upload; chỉ Download + Hộp nhận |
| Draft form | Giữ khi đổi trang; passphrase chỉ RAM, không sessionStorage |
| Email chưa verified | Bị chặn upload, keys, vault |

---

## 18. Chạy local (tóm tắt)

```bash
# Backend
cd backend
pip install -r requirements.txt
python -m alembic upgrade head
uvicorn main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev   # cần VITE_API_URL → http://localhost:8000
```

Chi tiết: [README.md](../README.md).

---

*Tài liệu đồng bộ với monorepo LockSend. Cập nhật khi thay đổi luồng envelope, vault, xác minh email hoặc lưu key.*
