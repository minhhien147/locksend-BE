# Hướng Dẫn Chức Năng Và Flow Hoạt Động Web

Tài liệu mô tả **luồng thực tế theo code hiện tại** của LockSend / Secure File Sharing. Chi tiết API, schema DB và stack: [DOCUMENTATION_VI.md](./DOCUMENTATION_VI.md), [README.md](../README.md).

---

## 1) Mục tiêu hệ thống

- Chia sẻ file theo mô hình **client-side encryption** (zero-knowledge plaintext).
- Trình duyệt mã hóa/giải mã; backend và Azure Blob chỉ xử lý **ciphertext**.
- Bộ kỹ thuật file:
  - **X25519**: trao đổi khóa (ECDH)
  - **HKDF-SHA256**: dẫn xuất khóa AES + nonce
  - **AES-256-GCM**: mã hóa nội dung
  - **Ed25519**: chữ ký ciphertext hoặc manifest (chunked)
  - **SHA-256**: checksum plaintext (và từng chunk nếu chunked)
- Bộ kỹ thuật keypair (client):
  - **PBKDF2-SHA256** (310 000 lần) + **AES-256-GCM** bọc private key bằng passphrase → `encrypted_key_blob` trên server

---

## 2) Cấu trúc thành phần

### Frontend (`frontend/`)

| Thành phần | Vai trò |
|------------|---------|
| `App.tsx` | Routing, nav theo role, modal mở khóa key, auto-restore session |
| `LoginPage` / `RegisterPage` | Đăng nhập tài khoản (JWT) |
| `UploadPage` | Mã hóa + upload (share / vault) |
| `DownloadPage` | Tải ciphertext qua SAS + giải mã |
| `KeyManagement` | Tạo/mở khóa/đổi passphrase keypair |
| `ProfilePage` | Cài đặt tài khoản, **Kho**, **Lịch sử** |
| `AdminLayout` | Users, Token Security, Stress test |
| `utils/crypto.ts` | Toàn bộ mật mã file + bọc keypair |
| `utils/keyVault.ts` | Private key trong RAM + session wrapper |
| `utils/api.ts` | Axios, Bearer, silent refresh, upload/download |
| `hooks/useDraftState.ts` | Giữ draft form khi đổi trang |

**Route chính (sau đăng nhập):**

- `/` — Upload (ẩn với role `recipient`)
- `/download` — Download
- `/keys` — Quản lý keypair
- `/profile` — Hồ sơ (`?tab=history` cho lịch sử)
- `/admin/*` — Admin only

### Backend (`backend/`)

FastAPI, router tách module:

| Nhóm | Ví dụ endpoint |
|------|----------------|
| Ops | `GET /health`, `GET /` |
| Auth | `POST /auth/register`, `/login`, `/refresh`, `/logout`, `/change-password`, `/users/search`, … |
| Keys | `GET /keys/my-encrypted-blob`, `GET /keys/{user_id}`, `POST /keys` |
| Upload | `POST /upload`, multipart `init` / `chunk` / `finalize`, `GET /sas-token/{blob_name}` |
| Files | `GET /files/my-files`, `shared-with-me`, `POST .../revoke/...`, SAS refresh |
| Vault | `GET/POST /vault/...`, chia sẻ file kho không upload lại blob |
| Token security | Admin phân tích/revoke JWT & SAS |

### Azure & PostgreSQL

| Dịch vụ | Vai trò |
|---------|---------|
| **Blob Storage** | Ciphertext + metadata blob (`encryption_metadata`, checksum audit) |
| **Key Vault** (tùy chọn) | Mirror public key (`pubkey-x25519-{user_id}`, `pubkey-ed25519-{user_id}`) |
| **PostgreSQL** | Users, public keys, `encrypted_key_blob`, files, recipients, refresh tokens, vault |
| **Managed Identity / DefaultAzureCredential** | Kết nối Azure khi deploy (local: `az login`) |

---

## 3) Hai lớp “đăng nhập” (quan trọng)

Hệ thống tách **xác thực tài khoản** và **mở khóa key mật mã**:

| Lớp | Cơ chế | Lưu ở đâu |
|-----|--------|-----------|
| **Auth** | Email/password → JWT access (RAM) + refresh **httpOnly cookie** | Server: `users`, `refresh_tokens` |
| **Crypto vault** | Passphrase → giải `encrypted_key_blob` → private key vào RAM | Server: blob đã mã hóa; client: RAM + **sessionStorage** wrapper |

- Đăng nhập **không** tự có private key.
- Sau login, user nhập **passphrase** (modal hoặc trang Keys) hoặc **F5 cùng tab** (restore session wrapper).
- **Logout** / idle 15 phút / đóng tab: xóa RAM + sessionStorage; blob trên DB vẫn còn.

---

## 4) Nhiệm vụ từng chức năng (Frontend)

### 4.1 Đăng ký / Đăng nhập

- Đăng ký tạo user role `owner` (mặc định).
- Access token chỉ trong memory; refresh qua cookie.
- 401 → silent `POST /auth/refresh` → retry hoặc redirect `/login`.

### 4.2 Trang `Keys`

| Nhiệm vụ | Chi tiết |
|----------|----------|
| Tạo keypair | X25519 + Ed25519; passphrase → `encryptKeyBlob` |
| Upload server | `POST /keys`: public keys + `encrypted_key_blob` |
| Mở khóa | `decryptKeyBlob` → `setKeys()` (RAM + session wrapper) |
| Khóa phiên | Xóa RAM, giữ wrapper (F5 không cần passphrase) |
| Xóa session | Xóa RAM + sessionStorage |
| Migrate | Key cũ trong localStorage → upload blob → xóa local |

**Không** lưu private key plaintext vào localStorage (trừ migrate một lần).

### 4.3 Trang `Upload`

| Chế độ | Mô tả |
|--------|--------|
| **Gửi cho người khác** | Tìm user theo email (public key từ DB) hoặc dán key X25519; nhiều người nhận |
| **Lưu vào kho cá nhân** | Mã hóa cho **public key của chính mình**; chọn thư mục vault |

**Xử lý file:**

- Nhỏ: `encryptFile` / `encryptFileForRecipients` (envelope) → `POST /upload` hoặc finalize multipart.
- ≥ 64 MB: chunked encrypt từng phần → multipart upload Azure.

**UI:** `idle` → `encrypting` → `uploading` → `done` (SAS link nếu share) hoặc `error`.

**Draft:** người nhận, file, chế độ… giữ khi chuyển trang (`useDraftState`).

### 4.4 Trang `Download`

- Dán **SAS URL** (draft được lưu).
- Tải ciphertext (trực tiếp Azure hoặc qua proxy BE nếu CORS).
- Cần **keypair đã mở khóa** (`keyVault`).
- `decryptFile` / `decryptFileChunked`: verify Ed25519 → HKDF → AES-GCM → so SHA-256 plaintext.
- Lỗi thường gặp: **Nonce không khớp** = sai private key (ví dụ đã rotate keypair sau khi file được mã hóa).

### 4.5 Trang `Hồ sơ` (`/profile`)

| Tab / khối | Nhiệm vụ |
|------------|----------|
| Cài đặt | Đổi tên hiển thị, đổi mật khẩu đăng nhập |
| **Kho** | Upload vào vault, thư mục, tải về, chia sẻ (re-wrap key), xóa |
| **Lịch sử** | File đã upload (SAS, revoke recipient), đã tải (local), **hộp nhận** (`shared-with-me` + lấy SAS) |

### 4.6 Admin

- Quản lý user/role.
- Token Security (rule + AI tùy chọn).
- Stress test crypto (benchmark browser).

---

## 5) Backend — endpoint tiêu biểu

### 5.1 Keys & zero-knowledge

| API | Mô tả |
|-----|--------|
| `GET /keys/my-encrypted-blob` | Blob đã mã hóa của user đang login |
| `POST /keys` | Lưu public keys + `encrypted_key_blob` vào DB; ghi Key Vault nếu cấu hình |
| `GET /keys/{user_id}` | Public keys (KV hoặc DB fallback) |

### 5.2 Upload & SAS

| API | Mô tả |
|-----|--------|
| `POST /upload` | Single-shot ciphertext + metadata → blob + SAS read-only |
| Multipart `init` / `chunk` / `finalize` | File lớn; finalize có thể ghi `files` + `file_recipients` (envelope) |
| `GET /sas-token/{blob_name}` | Cấp lại SAS đọc blob |

### 5.3 Chia sẻ & thu hồi (DB)

| API | Mô tả |
|-----|--------|
| `GET /files/my-files` | Lịch sử upload của owner |
| `GET /files/shared-with-me` | File được chia sẻ + `wrapped_file_key` (metadata envelope) |
| `POST /files/{file_id}/revoke/{recipient_id}` | Thu hồi quyền recipient |
| `GET /files/{file_id}/sas` | SAS mới cho file đã biết `file_id` |

### 5.4 Vault

- CRUD thư mục/file metadata; upload dùng chung pipeline mã hóa.
- `POST /vault/files/{file_id}/share`: bọc lại content key cho recipient **không** upload lại blob.

Chi tiết request/response: [DOCUMENTATION_VI.md](./DOCUMENTATION_VI.md) mục 6–8.

---

## 6) Flow end-to-end

### Flow 0 — Lần đầu dùng hệ thống

```text
Đăng ký → Đăng nhập (JWT)
    → Trang Keys: tạo keypair + passphrase
    → POST /keys (public + encrypted_key_blob)
    → Private key trong RAM (modal đóng khi đã unlock)
```

### Flow A — Mở khóa key (mỗi phiên / sau F5)

```text
Đã login
    → Có sessionStorage wrapper? → restoreFromSession() (không cần passphrase)
    → Không? → KeyUnlockModal / Keys: nhập passphrase → decryptKeyBlob → setKeys()
```

### Flow B — Gửi file cho người khác (share)

```text
Upload → chọn file
    → Tìm recipient (email) hoặc dán public key X25519
    → encryptFile (1 người) hoặc encryptFileForRecipients (nhiều người, file nhỏ)
    → Upload ciphertext + metadata
    → Nhận SAS URL → gửi link cho recipient
```

Recipient cần **cùng keypair** lúc mã hóa (public key đã đăng ký). Đổi keypair sau đó → file cũ không giải mã được (trừ khi còn private key cũ).

### Flow C — Lưu kho cá nhân (vault)

```text
Upload → chế độ "Lưu vào kho"
    → Mã hóa với public key của chính mình
    → finalize / upload → ghi DB vault
    → Quản lý tại Profile → Kho; chia sẻ sau bằng re-wrap envelope
```

### Flow D — Nhận file qua SAS (Download)

```text
Download → dán SAS URL
    → Đã unlock keypair
    → Tải blob + metadata
    → verify Ed25519 → decrypt → verify plaintextChecksum
    → Tải file về máy
```

### Flow E — Hộp nhận (in-app)

```text
Profile → Lịch sử → Hộp nhận
    → GET /files/shared-with-me
    → Lấy SAS → dán Download hoặc tải/giải mã (metadata/wrapped key từ DB)
```

### Flow F — Thu hồi quyền

```text
Profile → Lịch sử → Đã upload → mở danh sách recipient → Revoke
    → POST /files/{file_id}/revoke/{recipient_id}
```

Với **envelope**: chỉ xóa bản wrapped key của recipient; **không** cần mã hóa lại toàn bộ blob.

---

## 7) Metadata mã hóa

### Single-shot / envelope (metadata chính)

| Trường | Ý nghĩa |
|--------|----------|
| `ephemeralPublicKey` | X25519 ephemeral (base64) |
| `nonce` | IV AES-GCM hoặc nonce bọc envelope |
| `signature` | Ed25519 trên ciphertext |
| `signerPublicKey` | Ed25519 public của sender |
| `fileName`, `fileSize`, `mimeType` | Thông tin file |
| `plaintextChecksum` | SHA-256 hex plaintext — verify sau giải mã |
| `envelopeMode`, `contentKeyEnvelope` | Nhiều người nhận / vault share |

### Chunked (file lớn)

| Trường | Ý nghĩa |
|--------|----------|
| `isChunked`, `chunkSize`, `chunkCount` | Cấu hình chunk |
| `baseNonce` | Sinh nonce per-chunk |
| `chunkChecksums` | SHA-256 từng chunk plaintext |
| `chunkBlobFormat` | `azure_blocks` (multipart) hoặc `packed` |

Metadata lưu trên blob Azure (`encryption_metadata` / header khi download).

---

## 8) Biến môi trường quan trọng

### Backend (`backend/.env`)

- `DATABASE_URL` — PostgreSQL async
- `AZURE_STORAGE_ACCOUNT_NAME`, `AZURE_STORAGE_CONTAINER_NAME`
- `AZURE_KEY_VAULT_URL` (tùy chọn)
- `JWT_SECRET` / `JWT_PUBLIC_KEY`, `JWT_ALGORITHM` (mặc định HS256)
- `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`, `COOKIE_SECURE`, `ALLOWED_ORIGINS`

### Frontend (`frontend/.env.local`)

- `VITE_API_URL` — URL backend (bắt buộc trên Vercel production)

---

## 9) Checklist vận hành nhanh

1. **Đăng ký / đăng nhập** tài khoản.
2. **Keys**: tạo keypair + passphrase; đồng bộ lên server.
3. **Mở khóa key** (passphrase hoặc F5 cùng tab).
4. **Upload**: chọn recipient hoặc lưu kho → mã hóa & upload → copy SAS (nếu share).
5. **Recipient**: đăng nhập + mở khóa **đúng keypair** → Download dán SAS (hoặc Hộp nhận).
6. **Thu hồi** (nếu cần): Lịch sử upload → Revoke recipient.
7. **Link hết hạn**: lấy SAS mới (`/files/.../sas` hoặc refresh trên UI lịch sử).

---

## 10) Lưu ý vận hành & giới hạn

| Chủ đề | Ghi chú |
|--------|---------|
| Rotate keypair | File/blob mã hóa bằng public key **cũ** không mở được bằng key **mới** |
| Lộ private key | Attacker có thể giải mã mọi file đã bọc cho key đó |
| Single-shot `POST /upload` | Có thể **không** tạo row `files` trong DB — dùng multipart finalize hoặc vault flow để quản lý share/revoke đầy đủ |
| Recipient role | Không thấy menu Upload; dùng Download + Hộp nhận |
| Draft form | Giữ khi đổi trang; mật khẩu/passphrase chỉ RAM (không sessionStorage) |

---

*Tài liệu đồng bộ với monorepo hiện tại. Cập nhật khi đổi luồng envelope, vault hoặc lưu key.*
