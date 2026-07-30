# LockSend

**IAP491 — Information Security** · Hệ thống chia sẻ file mã hóa end-to-end

**Tài liệu đầy đủ để tái hiện / clone dự án:** [docs/DOCUMENTATION_VI.md](./docs/DOCUMENTATION_VI.md) (kiến trúc thực tế, API, DB, crypto, env, gap FE/BE).

Hệ thống lưu trữ và chia sẻ file an toàn trên Azure Blob Storage sử dụng mã hóa hybrid:
**X25519 + HKDF + AES-256-GCM + Ed25519**

## Kiến trúc

```
secure-file-sharing/
├── backend/        # FastAPI + Azure SDK + PostgreSQL (canonical API)
├── frontend/       # React 19 + Vite 8 + TypeScript + Tailwind v4
├── locksend-ai/    # ML token security (Random Forest + optional HTTP service)
├── docs/           # Tài liệu đồ án, API, security, flow
├── start.sh        # Helper → backend/start.sh (Railway Root Directory = backend)
└── README.md
```

## Công nghệ

Phiên bản pin trong `frontend/package.json` và `backend/requirements.txt`. Bảng dưới là tóm tắt stack chính.

### Frontend

| Công nghệ | Phiên bản (repo) | Mục đích |
|---|---|---|
| React / React DOM | 19.2.x | SPA |
| React Router | 7.x | Điều hướng, protected routes |
| Vite | 8.0.x | Build, HMR |
| TypeScript | ~5.9 | Type safety |
| Tailwind CSS | 4.2.x (`@tailwindcss/vite`) | UI |
| @noble/curves | 2.x | X25519 ECDH, Ed25519 (browser) |
| Web Crypto API | built-in | AES-256-GCM, HKDF-SHA256, SHA-256, PBKDF2 bọc keypair |
| Axios | 1.13.x | Gọi API + silent refresh |
| Node.js | ≥ 20.19 (`.node-version`: 20.19.0) | Dev/build (Vite 8 yêu cầu Node 20.19+) |

Deploy FE thường dùng **Vercel** hoặc **Railway** (`vercel.json`, `nixpacks.toml`); cần `VITE_API_URL` trỏ backend.

### Backend

| Công nghệ | Phiên bản (repo) | Mục đích |
|---|---|---|
| Python | 3.11+ (khuyến nghị 3.13 khi dev local) | Runtime |
| FastAPI | 0.135.x | REST API, OpenAPI |
| Uvicorn | 0.42.x | ASGI server |
| SQLAlchemy | 2.0.x (async) + asyncpg | ORM PostgreSQL |
| Alembic | 1.15.x | Migration |
| PyJWT | 2.12.x | JWT — **HS256 mặc định**; RS256/ES256 khi cấu hình `JWT_PUBLIC_KEY` |
| Passlib + bcrypt | 1.7.x / 4.2.x | Hash mật khẩu đăng nhập |
| Azure SDK | pin trong `requirements.txt` | `azure-storage-blob`, `azure-keyvault-secrets`, `azure-keyvault-keys`, `azure-identity` |

Repo **không** chứa Dockerfile / Docker Compose; chạy local bằng venv + `uvicorn` (xem mục dưới).

### Database & Azure

| Lớp | Stack |
|---|---|
| Database | PostgreSQL **14+** (`encrypted_key_blob`, public keys, auth, file metadata) |
| Azure | Blob Storage (ciphertext), Key Vault *(public keys, tùy chọn)*, **DefaultAzureCredential** / Managed Identity |
| Mã hóa file (client) | X25519, HKDF-SHA256, AES-256-GCM, Ed25519, SHA-256 (checksum) |
| Mã hóa keypair (client) | PBKDF2-SHA256 (310k iter) + AES-256-GCM (passphrase) |

### LockSend AI (tùy chọn)

| Công nghệ | Mục đích |
|---|---|
| scikit-learn, SHAP (`locksend-ai/`, `requirements-ai.txt`) | Phân tích rủi ro JWT/SAS (Admin Token Security) |

## Chạy local

### Backend
```bash
cd backend
# Sao chép .env.example → .env, điền DATABASE_URL
venv\Scripts\activate   # Windows
pip install -r requirements.txt
# Migration DB (cột encrypted_key_blob trên user_public_keys)
$env:DATABASE_URL = "postgresql+asyncpg://user:pass@localhost:5433/secure_file_sharing"
python -m alembic upgrade head
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
# Node >= 20.19 (xem package.json engines)
npm install
# Sao chép .env.example → .env.local, set VITE_API_URL (vd. http://localhost:8000)
npm run dev
```

### LockSend AI (tuỳ chọn — Admin Token Security)

Monorepo: thư mục `locksend-ai/`. Backend mặc định load model local từ đó (hoặc `LOCKSEND_AI_URL` nếu host riêng Ubuntu).

```bash
cd locksend-ai
pip install -r requirements.txt
# Đặt CSV vào data/ (xem locksend-ai/data/README.md), rồi:
python train.py
```

Chi tiết: [locksend-ai/README.md](./locksend-ai/README.md) (local, VPS, Railway)

## Nguyên tắc bảo mật
- Client-side encryption 100% — mã hóa/giải mã file hoàn toàn ở trình duyệt
- Azure chỉ lưu ciphertext file, không bao giờ thấy plaintext
- **Zero-knowledge keypair**: server không nhận private key plaintext hay passphrase; chỉ lưu `encrypted_key_blob` (đã mã hóa bằng passphrase phía client)
- Private key plaintext chỉ trong **RAM**; không lưu vào localStorage / IndexedDB / cookie
- **sessionStorage** chỉ giữ session wrapper (key bọc AES ephemeral per-tab) — đóng tab là mất; không chứa passphrase
- Managed Identity cho kết nối Azure (khi deploy cloud)
- SAS Token ngắn hạn, chỉ quyền Read, HTTPS only
- **SHA-256 checksum plaintext 2 chiều**: tính trước mã hóa → verify sau giải mã
- Auto-lock vault sau **15 phút** không hoạt động; **logout** xóa RAM + sessionStorage

## Quản lý private key (zero-knowledge)

### Dữ liệu lưu ở đâu

| Vị trí | Nội dung | Ghi chú |
|--------|----------|---------|
| **RAM** (`keyVault`) | Private key plaintext | Mất khi đóng tab / logout / timeout |
| **sessionStorage** | Wrapper AES (không có passphrase) | Chỉ cùng tab; hỗ trợ F5 không nhập lại passphrase |
| **PostgreSQL** | `public_key_*`, `encrypted_key_blob` | Server không giải mã được blob |
| **localStorage** | ❌ Không dùng cho private key | Có thể migrate key cũ một lần rồi xóa |

Module FE: `frontend/src/utils/keyVault.ts`, `crypto.ts` (`encryptKeyBlob` / `decryptKeyBlob`).

API BE:
- `GET /keys/my-encrypted-blob` — lấy blob của user đang đăng nhập
- `POST /keys` — lưu public keys + `encrypted_key_blob` (optional)

Migration: `f1a2b3c4d5e6_add_encrypted_key_blob.py` → cột `user_public_keys.encrypted_key_blob`.

### Luồng chính

1. **Tạo key lần đầu** (`/keys`): sinh X25519 + Ed25519 → passphrase → mã hóa blob → upload server → `setKeys()` (RAM + session wrapper).
2. **Đăng nhập máy/tab mới**: login (JWT + refresh cookie) ≠ unlock key → nhập passphrase → giải blob trên client.
3. **F5 cùng tab**: `restoreFromSession()` từ sessionStorage → không cần passphrase (nếu wrapper còn).
4. **Logout / đóng tab / 15 phút idle**: `clearAll()` — xóa RAM + sessionStorage; blob trên DB vẫn còn.
5. **Khóa phiên** (UI Keys): khóa mềm — xóa RAM, giữ wrapper; F5 có thể vào lại không cần passphrase.
6. **Xóa session…** (UI Keys): bỏ phiên unlock trên trình duyệt; blob server vẫn còn — mở lại bằng passphrase.

Đăng nhập tài khoản và mở khóa key là **hai lớp độc lập** (auth cookie vs crypto vault).

## Sơ đồ kiến trúc tổng quan

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
| - Encrypt file |      | - Upload endpoint|      | - metadata encryption     |
| - Sign payload |      | - SAS generator  |      | - no plaintext            |
+----------------+      +--------+---------+      +---------------------------+
                                 |
                                 | Managed Identity
                                 v
                      +---------------------------+
                      | PostgreSQL                |
                      | - public keys             |
                      | - encrypted_key_blob (ZK) |
                      +---------------------------+
                      | Azure Key Vault (optional)|
                      | - public keys mirror      |
                      +---------------------------+
```

## Trust boundaries

- **Boundary A — Browser trust zone**: plaintext file và private key chỉ trong RAM; session wrapper trong sessionStorage (per-tab).
- **Boundary B — Backend/API zone**: upload/cấp SAS, lưu blob key đã mã hóa; không biết passphrase, không giải mã file.
- **Boundary C — Storage zone (Azure Blob)**: chỉ ciphertext file + metadata.
- **Boundary D — DB zone (PostgreSQL)**: public keys + `encrypted_key_blob`; không có private key plaintext.

## Luồng dữ liệu file (upload / download)

1. User mở khóa keypair (passphrase hoặc restore session) — `keyVault.getKeys()`.
2. Sender chọn file ở trang **Upload**.
3. Browser tính SHA-256 plaintext → mã hóa X25519 + HKDF + AES-256-GCM → ký Ed25519.
4. Backend lưu ciphertext lên Azure Blob, trả SAS URL.
5. Recipient tải ciphertext qua SAS → verify chữ ký → giải mã trong browser → so sánh SHA-256 plaintext.

Chi tiết API, schema DB, gap FE/BE: [docs/DOCUMENTATION_VI.md](./docs/DOCUMENTATION_VI.md).
