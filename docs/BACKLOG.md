# Product Backlog — Secure File Sharing

> Dự án: mã hóa file client-side · Azure Blob Storage · X25519 + AES-256-GCM + Ed25519 · FastAPI + React 19

**Effort legend:** S < 1 ngày · M = 1–3 ngày · L = 3–7 ngày · XL > 1 tuần

---

## Tổng quan

| Epic | Items | In Progress | Done |
|------|------:|------------:|-----:|
| E1 Security & Cryptography | 6 | 0 | 0 |
| E2 File Management | 6 | 1 | 0 |
| E3 AI & Security Monitoring | 5 | 1 | 0 |
| E4 UX / Frontend | 6 | 1 | 0 |
| E5 Backend & Infrastructure | 6 | 0 | 0 |
| E6 Testing & Quality | 4 | 0 | 0 |
| **Total** | **33** | **3** | **0** |

---

## E1 — Security & Cryptography

| ID | Title | Priority | Status | Area | Effort |
|----|-------|----------|--------|------|--------|
| E1-1 | WebAuthn / Passkey cho unlock private key | High | Todo | Security | L |
| E1-2 | Key rotation — re-encrypt files khi đổi keypair | High | Todo | Security | XL |
| E1-3 | Thu hồi quyền truy cập file của recipient cụ thể | High | Todo | BE | M |
| E1-4 | TOTP / 2FA cho tài khoản | Medium | Todo | BE | M |
| E1-5 | SAS URL expiry cấu hình per-upload | Medium | Todo | BE | S |
| E1-6 | Private key encrypted backup / export | Low | Todo | Security | M |

### Chi tiết

**E1-1 — WebAuthn / Passkey cho unlock private key** `High` `L`
Thay thế passphrase text bằng WebAuthn (fingerprint/FaceID/hardware key) để mở khóa keypair — tăng UX và bảo mật.

**E1-2 — Key rotation — re-encrypt files khi đổi keypair** `High` `XL`
Khi user tạo keypair mới, tự động re-encrypt `encrypted_key_blob` và cập nhật shared keys cho các file cũ.

**E1-3 — Thu hồi quyền truy cập file của recipient cụ thể** `High` `M`
API + UI để owner xóa một recipient khỏi `file_recipients`; SAS mới không còn khả dụng cho người đó.

**E1-4 — TOTP / 2FA cho tài khoản** `Medium` `M`
Tích hợp TOTP (Google Authenticator) như bước xác thực thứ hai khi đăng nhập.

**E1-5 — SAS URL expiry cấu hình per-upload** `Medium` `S`
Cho phép sender chọn thời gian hết hạn SAS (1h / 24h / 7d) thay vì dùng mặc định toàn hệ thống.

**E1-6 — Private key encrypted backup / export** `Low` `M`
Cho phép user tải về `encrypted_key_blob` hoặc xuất keypair ra file mã hóa để dự phòng.

---

## E2 — File Management

| ID | Title | Priority | Status | Area | Effort |
|----|-------|----------|--------|------|--------|
| E2-1 | Streaming decrypt per-chunk (tránh OOM file lớn) | **Critical** | 🔄 In Progress | FE | L |
| E2-2 | File expiry — tự động xóa sau ngày hết hạn | High | Todo | BE | M |
| E2-3 | Batch upload nhiều file cùng lúc | Medium | Todo | FE | L |
| E2-4 | Audit log download — log khi recipient tải file | Medium | Todo | BE | S |
| E2-5 | File size limit enforcement (BE + FE) | Medium | Todo | BE | S |
| E2-6 | File versioning (upload version mới của cùng file) | Low | Todo | BE | XL |

### Chi tiết

**E2-1 — Streaming decrypt per-chunk (tránh OOM file lớn)** `Critical` `L` 🔄
Download và giải mã theo chunk (`ReadableStream`) thay vì load toàn bộ blob vào RAM — cần thiết cho file > 500MB.
> Liên quan: `backend/routers/download_router.py`, `frontend/src/hooks/useDownload.ts`

**E2-2 — File expiry — tự động xóa sau ngày hết hạn** `High` `M`
Cột `expires_at` trong bảng `files`; scheduled job (APScheduler/ARQ) xóa blob và DB row khi quá hạn.

**E2-3 — Batch upload nhiều file cùng lúc** `Medium` `L`
Drag & drop nhiều file; mã hóa và upload song song (`Promise.all` với concurrency limit).

**E2-4 — Audit log download** `Medium` `S`
Ghi audit event khi SAS URL được dùng để tải (Azure Event Grid / webhook) và hiển thị trong trang admin/owner.

**E2-5 — File size limit enforcement** `Medium` `S`
Check file size trước khi upload; trả lỗi rõ ràng 413 với limit có thể cấu hình qua env.

**E2-6 — File versioning** `Low` `XL`
Cho phép sender upload bản mới của file (giữ blob cũ, thêm version mới) — recipient có thể chọn version.

---

## E3 — AI & Security Monitoring

| ID | Title | Priority | Status | Area | Effort |
|----|-------|----------|--------|------|--------|
| E3-1 | VirusTotal API — tra cứu SHA-256 sau khi giải mã | High | Todo | AI | M |
| E3-2 | SHAP explanation trong Admin Token Security UI | Medium | 🔄 In Progress | AI | M |
| E3-3 | Anomaly detection threshold cấu hình được | Medium | Todo | AI | S |
| E3-4 | Real-time alert dashboard (WebSocket) | Medium | Todo | FE | L |
| E3-5 | Model retrain tự động theo lịch (weekly) | Low | Done | AI | M |

### Chi tiết

**E3-1 — VirusTotal API** `High` `M`
Sau khi verify checksum thành công, gọi VirusTotal API với SHA-256 plaintext để kiểm tra malware; cảnh báo nếu phát hiện.

**E3-2 — SHAP explanation trong Admin UI** `Medium` `M` 🔄
Hiển thị SHAP feature importance (bar chart) cho mỗi token được phân tích — giải thích tại sao LockSend AI đánh dấu suspicious.

**E3-3 — Anomaly detection threshold cấu hình được** `Medium` `S`
Admin có thể điều chỉnh ngưỡng risk score (0.0–1.0) trong UI thay vì hardcode trong model.

**E3-4 — Real-time alert dashboard (WebSocket)** `Medium` `L`
Admin dashboard nhận security alert qua WebSocket (FastAPI WebSocket endpoint) thay vì polling.

**E3-5 — Model retrain tự động theo lịch** `Low` `Done`
`backend/services/scheduled_retrain.py` — subprocess `train.py` theo lịch (env `AI_RETRAIN_INTERVAL_DAYS`, mặc định 7 ngày), advisory lock tránh multi-replica, hot-reload bundle vào RAM sau khi train xong. Hook vào `lifespan` trong `main.py`.

---

## E4 — UX / Frontend

| ID | Title | Priority | Status | Area | Effort |
|----|-------|----------|--------|------|--------|
| E4-1 | Progress indicator chunk upload (per-file) | High | 🔄 In Progress | FE | S |
| E4-2 | Mobile responsive toàn bộ các trang | High | Todo | FE | M |
| E4-3 | Notification center (in-app toasts / bell) | Medium | Todo | FE | M |
| E4-4 | Drag & drop upload vùng file picker | Medium | Todo | FE | S |
| E4-5 | i18n đầy đủ (VI / EN toggle) | Low | Todo | FE | L |
| E4-6 | Onboarding wizard cho user mới | Low | Todo | FE | M |

### Chi tiết

**E4-1 — Progress indicator chunk upload** `High` `S` 🔄
Thanh progress bar chính xác theo bytes uploaded, không chỉ % chunk count — dùng `onUploadProgress` của Axios.
> Liên quan: `backend/routers/_upload_helpers.py`, `frontend/src/utils/api/files.ts`

**E4-2 — Mobile responsive** `High` `M`
Admin, Upload, Download, Keys, Profile — đảm bảo usable trên màn hình < 768px.

**E4-3 — Notification center** `Medium` `M`
Lưu các thông báo (file shared, security alert, download event) vào notification feed; mark as read.

**E4-4 — Drag & drop upload** `Medium` `S`
Hỗ trợ kéo thả file vào vùng upload thay vì chỉ click chọn file.

**E4-5 — i18n đầy đủ (VI / EN toggle)** `Low` `L`
Hoàn thiện i18n (hiện tại mới 1 phần) — dịch toàn bộ UI string, lưu preference vào localStorage.

**E4-6 — Onboarding wizard cho user mới** `Low` `M`
Hướng dẫn từng bước khi user mới đăng ký: tạo keypair → nhập passphrase → xác nhận → sẵn sàng.

---

## E5 — Backend & Infrastructure

| ID | Title | Priority | Status | Area | Effort |
|----|-------|----------|--------|------|--------|
| E5-1 | Docker Compose cho local dev (BE + DB) | High | Todo | DevOps | M |
| E5-2 | Rate limiting (upload / download / auth) | High | Todo | BE | M |
| E5-3 | OpenTelemetry traces + structured logging | Medium | Todo | DevOps | L |
| E5-4 | Background job queue (ARQ/Celery) cho cleanup | Medium | Todo | BE | L |
| E5-5 | DB connection pool tuning + health endpoint | Medium | Todo | BE | S |
| E5-6 | CI/CD pipeline (GitHub Actions) | Medium | Todo | DevOps | M |

### Chi tiết

**E5-1 — Docker Compose cho local dev** `High` `M`
`docker-compose.yml` chạy PostgreSQL + backend + optional AI service; giảm friction onboarding contributor.

**E5-2 — Rate limiting** `High` `M`
Dùng `slowapi` hoặc middleware tự viết để limit request/minute theo IP + user — ngăn abuse và brute-force.

**E5-3 — OpenTelemetry traces + structured logging** `Medium` `L`
Tích hợp OpenTelemetry vào FastAPI; export traces tới Jaeger/Honeycomb; chuẩn hóa log format JSON.

**E5-4 — Background job queue** `Medium` `L`
Chuyển file expiry, email alert, token cleanup sang background jobs; tránh block request thread.

**E5-5 — DB connection pool tuning + health endpoint** `Medium` `S`
Expose `/health` endpoint trả DB ping + Azure Blob ping; cấu hình `pool_size` / `max_overflow` trong `session.py`.

**E5-6 — CI/CD pipeline (GitHub Actions)** `Medium` `M`
Workflow: lint → test → build Docker → deploy to Railway (BE) + Vercel (FE) khi push to `main`.

---

## E6 — Testing & Quality

| ID | Title | Priority | Status | Area | Effort |
|----|-------|----------|--------|------|--------|
| E6-1 | pytest integration tests cho toàn bộ BE API | High | Todo | BE | L |
| E6-2 | FE unit tests cho crypto.ts / keyVault.ts | High | Todo | FE | M |
| E6-3 | E2E tests (Playwright) — upload/download flow | Medium | Todo | FE | L |
| E6-4 | Security fuzzing upload endpoint | Medium | Todo | Security | M |

### Chi tiết

**E6-1 — pytest integration tests** `High` `L`
Test coverage > 80% cho auth, upload, download, keys, admin routes — dùng `pytest-asyncio` + `httpx` AsyncClient.

**E6-2 — FE unit tests cho crypto.ts / keyVault.ts** `High` `M`
Vitest tests cho encrypt/decrypt round-trip, checksum verify, blob encrypt/decrypt — đảm bảo crypto logic đúng.

**E6-3 — E2E tests (Playwright)** `Medium` `L`
Playwright test toàn bộ happy path: register → create keys → upload → share → download → verify checksum.

**E6-4 — Security fuzzing upload endpoint** `Medium` `M`
Dùng OWASP ZAP / Burp Suite fuzzing trên `/upload`, `/download`, `/auth` endpoints; fix bất kỳ lỗi input validation.

---

*Cập nhật lần cuối: 2026-06-29*
