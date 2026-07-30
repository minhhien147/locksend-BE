# Rà soát bảo mật mã nguồn theo OWASP Top 10 — LockSend

| | |
|---|---|
| **Ngày thực hiện** | 29/07/2026 |
| **Loại đánh giá** | Static code review (SAST thủ công) trên mã nguồn local |
| **Khung tham chiếu** | OWASP Top 10:2021 (chi tiết từng lỗi) + map sang [OWASP Top 10:2025](https://owasp.org/Top10/2025/) (Phụ lục A) |
| **Phạm vi** | `backend/` (FastAPI), `frontend/` (React + TS), `locksend-ai/` (AI service); mitigation cây Python trùng ở root |
| **Commit gốc** | `c226175` + các thay đổi chưa commit |
| **Lần rà soát trước** | `docs/OWASP_SECURITY_REPORT.md` (08/07/2026) |
| **Lịch sử phiên** | Pass 1 (Opus): 29 lỗi chính trên `backend/`/`frontend/`/`locksend-ai/`. Pass 2 (Grok, cùng ngày sau khi hết usage): bổ sung JWT RS256, Google JWKS, admin token, CSP API, stream download, AI key compare, fail-closed root `start.sh`. |

> **Không thực hiện pentest.** Toàn bộ kết luận dựa trên đọc mã nguồn, không có
> request nào được gửi tới hệ thống đang chạy. Vì vậy các lỗi được mô tả là
> *khả năng khai thác theo luồng code*, chưa được xác nhận bằng khai thác thực tế.

---

## 1. Tổng quan kết quả

Rà soát 4 nhóm miền (auth/access control, file & storage, injection/SSRF/config,
client-side) trên backend, `frontend/src` và `locksend-ai/`, cộng mitigation cây
Python trùng ở root repo.

| Pass | Phát hiện | Đã vá | Ghi chú |
|------|-----------|-------|---------|
| **Pass 1** | 29 | 29 | Canonical `backend/` + FE + AI |
| **Pass 2** | 8 mới (+ harden root) | 8 | Bổ sung sau Pass 1; root fail-closed |
| **Tổng** | **37** | **37** | Còn 14+ rủi ro tồn dư (mục 5) — cần hạ tầng / UX |

| Mức độ (gộp 2 pass) | Số lượng | Đã vá |
|--------|---------|-------|
| 🔴 Critical | 2 | 2 |
| 🟠 High | 6 (+ harden root Critical/High đã có bản tương đương ở `backend/`) | 6 |
| 🟡 Medium | 12 + 5 (Pass 2) | 17 |
| 🟢 Low | 9 + 1 (Pass 2) | 10 |

### Theo hạng mục OWASP Top 10:2021 (Pass 1)

| # | Hạng mục | Số lỗi | Mức cao nhất | Trạng thái |
|---|----------|-------|-------------|-----------|
| A01 | Broken Access Control | 4 | 🔴 Critical | ✅ Đã vá |
| A02 | Cryptographic Failures | 4 | 🟠 High | ✅ Đã vá |
| A03 | Injection | 3 | 🟡 Medium | ✅ Đã vá |
| A04 | Insecure Design | 7 | 🟠 High | ✅ Đã vá |
| A05 | Security Misconfiguration | 5 | 🟢 Low | ✅ Đã vá (+ Pass 2 CSP) |
| A06 | Vulnerable & Outdated Components | 1 | 🟡 Medium | ⚠️ Vá một phần (SCA định kỳ còn lại) |
| A07 | Identification & Authentication Failures | 4 | 🔴 Critical | ✅ Đã vá |
| A08 | Software & Data Integrity Failures | 3 | 🟠 High | ✅ Đã vá |
| A09 | Security Logging & Monitoring Failures | 2 | 🟢 Low | ✅ Đã vá |
| A10 | Server-Side Request Forgery | 1 | 🟡 Medium | ✅ Đã vá |

### Kết quả kiểm chứng lại lần rà soát trước (08/07/2026)

Bốn bản vá được `OWASP_SECURITY_REPORT.md` tuyên bố hoàn thành nhưng thực tế
**không có hiệu lực** trước Pass 1:

| Tuyên bố trước đây | Thực tế trước Pass 1 |
|--------------------|----------------------|
| “Giới hạn 20 download/recipient/file/giờ” | Chỉ áp ở `POST /files/download-log` — client bỏ qua là tải không giới hạn (#4) |
| “Verify SHA-256 model trước `pickle.load()`” | Bỏ qua khi thiếu `.sha256`; bản tải về tự hash chính mình (#7) |
| “Chặn private network cho `LOCKSEND_AI_URL`” | So khớp hostname; `::ffff:169.254.169.254` lọt (#9) |
| “Lockout brute-force login theo `IP:email`” | IP từ hop đầu `X-Forwarded-For` → né hoàn toàn (#3) |

Ngược lại, kiểm tra `JWT_SECRET` / `ALLOWED_ORIGINS` lúc khởi động nay *chặn server
start* trên production chứ không chỉ cảnh báo.

---

## 2. Lỗi Critical (Pass 1)

### #1 — IDOR: `GET /sas-token/{blob_name}` phát SAS cho blob của người khác

| | |
|---|---|
| **Mức độ** | 🔴 Critical |
| **OWASP 2021** | A01 – Broken Access Control |
| **OWASP 2025** | A01 – Broken Access Control |
| **File** | `backend/routers/files_router.py` → `get_sas_token()` |

Endpoint nhận `blob_name` từ URL, tra DB rồi phát SAS **không kiểm tra `owner_id`**.
Khi `row is None` vẫn phát SAS → mint SAS cho **bất kỳ đường dẫn nào** trong container.

**Kịch bản.** `blob_name` lộ qua `/files/shared-with-me`, log, URL SAS. User
`owner` bất kỳ gọi `GET /sas-token/<blob nạn nhân>` nhận SAS đọc ciphertext.

**Đã vá.** Bắt buộc tồn tại record và `owner_id == current.id` (hoặc admin);
từ chối ghi log `SECURITY A01`.

---

### #2 — Chiếm tài khoản qua Google OAuth trên email chưa xác minh

| | |
|---|---|
| **Mức độ** | 🔴 Critical |
| **OWASP 2021** | A07 |
| **OWASP 2025** | A07 – Authentication Failures |
| **File** | `backend/routers/auth_router.py` → `_get_or_create_google_user()` |

Gộp theo email khi không khớp `external_id` mà **không** thu hồi password của
account chưa verified → attacker đăng ký trước email nạn nhân, nạn nhân Google
login → chung account, attacker vẫn vào bằng mật khẩu.

**Đã vá.** Nếu `email_verified_at IS NULL`: wipe `password_hash`, rebind
`external_id`, revoke refresh tokens, audit `security.google_claim_unverified_account`.
*(Pass 2 cũng backport tương tự lên cây root stale.)*

---

## 3. Lỗi High (Pass 1)

### #3 — Bypass lockout đăng nhập bằng `X-Forwarded-For` giả

| | |
|---|---|
| **Mức độ** | 🟠 High |
| **OWASP** | A07 (2021) / A07 (2025) |
| **File** | `backend/routers/auth_router.py`, `backend/services/login_guard.py`, `backend/services/client_ip.py` |

IP lấy hop trái XFF do client gửi → đổi header mỗi lần = bypass lockout. `audit.get_ip()`
cũng bị giả.

**Đã vá.**
1. `client_ip.py`: lấy hop thứ `TRUSTED_PROXY_COUNT` từ phải.
2. `login_guard.py`: đếm 2 lớp `ip+email` và `email` thuần; chỉ tăng khi thất bại.
3. `audit.get_ip()` / upload helpers dùng cùng helper.
*(Pass 2: root login bỏ tin XFF trái, dùng peer TCP.)*

---

### #4 — Giới hạn download không áp trên các đường tải thật

| | |
|---|---|
| **Mức độ** | 🟠 High |
| **OWASP** | A04 (2021) / A06 (2025) |
| **File** | `backend/routers/download_router.py` |

Rate limit chỉ trong `_persist_download_log()`. Đường tải thật
(`by-sas`, chunks, vault ciphertext) không gọi → bỏ ghi log = tải không giới hạn.

**Đã vá.** Rate tại chỗ tải; chunk dùng budget `DOWNLOAD_MAX × chunk_count`.
*(Pass 2: backport rate lên root `by-sas`.)*

---

### #5 — Không giới hạn kích thước upload (DoS bộ nhớ)

| | |
|---|---|
| **Mức độ** | 🟠 High |
| **OWASP** | A04 / A06 (2025) |
| **File** | `backend/routers/upload_router.py`, `_upload_helpers.py` |

`await file.read()` không hạn mức → OOM.

**Đã vá.** `read_upload_capped()` theo block 1 MB; mặc định 200 MB single / 128 MB chunk.

---

### #6 — Multipart finalize tin `file_size_bytes` do client khai (né quota)

| | |
|---|---|
| **Mức độ** | 🟠 High |
| **OWASP** | A04 / A08 |
| **File** | `backend/routers/upload_router.py` → `multipart_finalize()` |

**Đã vá.** Lấy size thật từ Azure blob properties sau commit; lệch với client → log A08.

---

### #7 — Kiểm tra toàn vẹn model AI bị vô hiệu hoá

| | |
|---|---|
| **Mức độ** | 🟠 High |
| **OWASP** | A08 |
| **File** | `locksend-ai/model_store.py` |

Thiếu `.sha256` thì bỏ qua; tải URL rồi tự hash = không phải integrity check.

**Đã vá.** Neo `LOCKSEND_AI_MODEL_SHA256` out-of-band; production thiếu digest = từ chối
load; URL bắt buộc HTTPS + digest khớp ngay sau tải.

---

### #8 — SAS URL lưu vào `localStorage` (200 bản)

| | |
|---|---|
| **Mức độ** | 🟠 High |
| **OWASP** | A02 (2021 crypto) / A04 (2025) |
| **File** | `frontend/src/utils/downloadHistory.ts`, hooks, HistoryPage |

**Đã vá.** Bỏ field `sasUrl`; lần đọc đầu strip dữ liệu cũ; xoá UI copy SAS.

---

## 4. Lỗi Medium và Low (Pass 1) — bảng tóm tắt

| # | Lỗi | OWASP 2021 | Mức | Bản vá |
|---|-----|------------|-----|--------|
| 9 | SSRF IPv6-mapped IMDS | A10 | 🟡 | `_normalize_ip()` + resolve IP |
| 10 | Header injection `Content-Disposition` | A03 | 🟡 | `sanitize_display_filename` + RFC 6266 |
| 11 | HTML injection email cảnh báo | A03 | 🟡 | `html.escape()` |
| 12 | Brute-force OTP | A07 | 🟡 | 8 lần/15 phút per user |
| 13 | Không rate limit Gemini / VT | A04 | 🟡 | 15 chat/phút, 30 VT/phút |
| 14 | IDOR download-log | A01 | 🟡 | `authorize_file_download()` |
| 15 | Draft SAS trong `sessionStorage` | A02 | 🟡 | mode `"memory"` + purge legacy |
| 16 | `href` VirusTotal không allowlist | A03 | 🟡 | https + virustotal.com |
| 17 | Upload session hết hạn vẫn dùng | A04 | 🟡 | `_assert_session_usable()` |
| 18 | Finalize không đối chiếu chunk_count | A08 | 🟡 | 422 nếu vượt uploaded |
| 19 | `/analyze/batch` không trần item | A04 | 🟡 | `max_length=MAX_BATCH_ITEMS` |
| 20 | `python-dotenv` không pin | A06 | 🟡 | pin `==1.2.2` |
| 21 | Provision user lấy `role` từ JWT | A01 | 🟢 | luôn `"owner"` |
| 22 | Health/docs lộ nội bộ | A05 | 🟢 | chi tiết chỉ non-prod |
| 23 | JWT decode detail ra client | A05 | 🟢 | message generic |
| 24 | OTP trong subject email | A09 | 🟢 | OTP chỉ body |
| 25 | Thiếu TrustedHost | A05 | 🟢 | bật khi `ALLOWED_HOSTS` |
| 26 | AI remote không bắt buộc API key | A05 | 🟢 | startup validate |
| 27 | `.env.example` JWT placeholder lọt check | A02 | 🟢 | `JWT_SECRET=` trống |
| 28 | Vite sourcemap không tắt tường minh | A05 | 🟢 | `sourcemap: false` |
| 29 | Resend OTP email-bomb | A04 | 🟢 | trần 5 lần/giờ |

---

## 4b. Lỗi bổ sung Pass 2 (Grok) — đã vá

| # | Lỗi | OWASP 2025 | Mức | File | Bản vá |
|---|-----|------------|-----|------|--------|
| 30 | RS256/ES256 dùng public key cho cả encode | A04 Cryptographic Failures | 🟡 | `backend/auth.py`, `main.py`, `.env.example` | Tách `_verify_key()` / `_signing_key()`; thêm `JWT_PRIVATE_KEY`; startup validate |
| 31 | Google `id_token` gửi qua query tokeninfo (lộ log/proxy) | A04 / A07 | 🟡 | `backend/services/google_oauth.py` | Verify JWKS cục bộ (`PyJWKClient` + PyJWT) |
| 32 | `POST /admin/users` trả access token user mới (impersonation) | A01 | 🟡 | `backend/routers/users_router.py` | Response `UserOut` only |
| 33 | CSP API cho `'unsafe-inline'` | A02 Security Misconfiguration | 🟡 | `backend/middleware/security_headers.py` | Default `default-src 'none'; frame-ancestors 'none'; …` |
| 34 | Proxy download `readall()` → OOM worker | A06 / A10 | 🟡 | `download_router.py`, `vault_router.py` | `StreamingResponse(downloader.chunks())` |
| 35 | AI API key so sánh `!=` (timing) | A07 | 🟢 | `locksend-ai/server.py` | `secrets.compare_digest` |
| 36 | Root deploy ship code stale Critical | A02 | 🟠→mitigated | `start.sh` (root) | **Fail-closed**: exit 1, bắt buộc `cd backend` |
| 37 | ~~Root còn role-from-claim / XFF / Google squat / download rate / header CR/LF~~ | A01/A05/A07 | — | ~~root `auth.py`, `routers/*`~~ | **Đã xoá cây root stale** (2026-07-30); chỉ còn `backend/` |

---

## 5. Rủi ro tồn dư — cần quyết định của bạn

### Cần hạ tầng

| Rủi ro | Ảnh hưởng | Đề xuất |
|--------|----------|---------|
| **Rate limit in-memory per-process** | `WEB_CONCURRENCY` × limit; restart reset | Redis + TTL |
| **SAS đã phát không revoke thật** | Azure SAS sống tới hết hạn | Stored Access Policy / giảm TTL; nói rõ revoke = revoke khoá mã hoá |

### Cần migration DB

| Rủi ro | Ảnh hưởng | Đề xuất |
|--------|----------|---------|
| **`refresh_tokens.jti` plaintext** | Rò DB backup = cookie dùng được | Lưu `sha256(jti)` |

### Cần đánh đổi UX

| Rủi ro | Ảnh hưởng | Đề xuất |
|--------|----------|---------|
| **`keyVault.ts`: AES session key extractable trong sessionStorage** | XSS → exfil private key | CryptoKey non-extractable / chỉ RAM |
| **Không CSP frontend** (inline boot script) | XSS tối đa impact | CSP hosting + nonce; cẩn thận Google OAuth `connect-src` |
| **Legacy `secure_file_sharing_keys` localStorage** | XSS đọc key cũ nếu chưa migrate | Ép migrate / auto-clear |

### Quyết định thiết kế (có thể cố ý)

| Điểm | Hiện trạng |
|------|-----------|
| Admin đọc ciphertext mọi file | Break-glass? Nên tách quyền + audit |
| Proxy `/files/ciphertext/by-sas` + SAS rò rỉ | Login bất kỳ + SAS = tải được |
| `is_sas_revoked()` bỏ qua `user_id` | Revoke một user chặn mọi user trên blob |
| `sas_url` query param ở chunk download | Lộ access log — nên POST body |
| VirusTotal chỉ tham khảo | OK zero-knowledge — nói rõ UI |
| `register` 409 email tồn tại | Enumeration (login đã 401 chung) |
| `JWT_ISSUER` / `AUDIENCE` trống | Set trên production |
| FE deps caret `^` | Pin lockfile + `npm audit` |

### Cấu trúc repo

Hai cây backend (root vs `backend/`). Pass 1 chỉ vá `backend/`. Pass 2:
- Root `start.sh` **từ chối start**.
- Backport một số Critical/High tối thiểu trên root.

**Vẫn khuyến nghị:** Railway Root Directory = `backend`, rồi **xoá cây Python trùng ở root**.

---

## 6. Những gì đã xác nhận là an toàn

**Injection** — ORM/`select()`; không `shell=True`/`eval`; `pickle` chỉ sau `ensure_model()`.

**XSS / client** — Không `dangerouslySetInnerHTML`; access token RAM; refresh httpOnly;
password draft memory; không `Math.random()` cho crypto.

**Crypto** — AES-GCM / X25519 / HKDF / Ed25519 / PBKDF2 310k; bcrypt; OTP
`secrets` + `compare_digest`; JWT algorithms tường minh.

**Access control** — Role từ DB; register hardcode owner; admin guards; vault
`owner_id`; `authorize_file_download`.

**Config** — Startup block secret yếu / CORS `*` / `COOKIE_SECURE`; SAS read-only
HTTPS; redact audit; VT host cố định; OpenAPI tắt production.

---

## 7. Biến môi trường mới

Không biến nào bắt buộc trừ ghi chú. `LOCKSEND_AI_MODEL_SHA256` **bắt buộc** nếu
AI tải model từ URL trên production. RS256 cần `JWT_PRIVATE_KEY` + `JWT_PUBLIC_KEY`.

```env
TRUSTED_PROXY_COUNT=1
LOGIN_MAX_ATTEMPTS_PER_EMAIL=15
EMAIL_OTP_MAX_FAILURES=8
EMAIL_OTP_FAILURE_WINDOW=900
EMAIL_OTP_RESEND_MAX=5
EMAIL_OTP_RESEND_WINDOW=3600
MAX_SINGLE_UPLOAD_BYTES=209715200
MAX_CHUNK_UPLOAD_BYTES=134217728
ASSISTANT_MAX_PER_USER=15
ASSISTANT_RATE_WINDOW=60
VIRUSTOTAL_MAX_PER_USER=30
VIRUSTOTAL_RATE_WINDOW=60
ALLOWED_HOSTS=api.locksend.app
LOCKSEND_AI_MODEL_SHA256=
LOCKSEND_AI_MAX_BATCH_ITEMS=512

# Pass 2 — RS256/ES256 (chỉ khi JWT_ALGORITHM không phải HS*)
# JWT_PRIVATE_KEY=/path/to/private.pem
# JWT_PUBLIC_KEY=/path/to/public.pem

# Override CSP API (mặc định default-src 'none')
# CSP_POLICY=
```

---

## 8. Kiểm chứng đã thực hiện (Pass 1)

| Hạng mục | Kết quả |
|----------|--------|
| Lint (backend + frontend + AI) | ✅ |
| `tsc --noEmit` | ✅ |
| `compileall` | ✅ |
| Import `main.app` + đếm route | ✅ 84 route |
| Kiểm thử hành vi hàm đã sửa | ✅ 27/27 |
| `pytest` suite | ⚠️ Cần Postgres; `test_token_security` import lệch (trước khi sửa) |

Pass 2: import `google_oauth`, `auth`, routers patched — OK; chưa chạy lại full 27-case suite.

---

## 9. File đã thay đổi

### Pass 1 — tạo mới
| File | Mục đích |
|------|---------|
| `backend/services/client_ip.py` | IP không spoof qua XFF |
| `backend/services/rate_limit.py` | Sliding-window dùng chung |

### Pass 1 — backend / frontend / locksend-ai
Xem chi tiết thay đổi #1–#29 trong lịch sử git working tree: `files_router`,
`auth_router`, `login_guard`, `download_router`, `upload_router`, `_upload_helpers`,
`vault_router`, `verification_router`, `integrations_router`, `ssrf_guard`,
`email_service`, `auth`, `main`, `requirements.txt`, `.env.example`,
`downloadHistory`, `useDownload`, `HistoryPage`, `DownloadPage`, `pageDraft`,
`VirusTotalCheck`, `LoginPage`, `vite.config`, `model_store`, `locksend-ai/server`
(batch + health).

### Pass 2 — bổ sung
| File | Thay đổi |
|------|---------|
| `backend/auth.py` | `_verify_key` / `_signing_key` + `JWT_PRIVATE_KEY` |
| `backend/main.py` | Startup check RS256 keys |
| `backend/.env.example` | Document private/public PEM |
| `backend/services/google_oauth.py` | JWKS verify |
| `backend/routers/users_router.py` | Admin create → `UserOut` |
| `backend/middleware/security_headers.py` | CSP `default-src 'none'` |
| `backend/routers/download_router.py` | StreamingResponse |
| `backend/routers/vault_router.py` | StreamingResponse |
| `locksend-ai/server.py` | `compare_digest` API key |
| `start.sh` (root) | Fail-closed → dùng `backend/` |
| Root `auth.py`, `routers/auth_router.py`, `routers/download_router.py` | Backport tối thiểu |

---

## 10. Checklist trước khi deploy

**Bắt buộc**
- [ ] Railway Root Directory = `backend/` (root `start.sh` sẽ **refuse** nếu trỏ nhầm)
- [ ] `JWT_SECRET` ≥ 32 ký tự random (hoặc cặp PEM nếu RS256)
- [ ] `TRUSTED_PROXY_COUNT` khớp số proxy thật
- [ ] AI model URL → set `LOCKSEND_AI_MODEL_SHA256`
- [ ] Có `LOCKSEND_AI_URL` → `LOCKSEND_AI_API_KEY` ≥ 16 ký tự

**Nên làm**
- [ ] `ALLOWED_HOSTS`, `JWT_ISSUER`, `JWT_AUDIENCE`
- [ ] CSP frontend ở hosting
- [ ] `pytest` + test tay upload → share → download (single + chunked)
- [ ] `pip-audit` / `npm audit`
- [ ] Xoá cây backend trùng ở root

**Alert log**
- `SECURITY A01: từ chối SAS…`
- `security.google_claim_unverified_account`
- `A08: file_size_bytes client khai…`
- `A07: OTP sai`
- `SECURITY A09: Lượt download bất thường`

---

## 11. Giới hạn của đánh giá

- Chỉ static analysis — không PoC runtime.
- Không tra CVE database đầy đủ — chạy `pip-audit` / `npm audit`.
- Không đánh giá cấu hình Azure / Railway / Cloudflare ngoài mã nguồn.
- Không formal verification giao thức E2E crypto.
- Map chi tiết từng lỗi theo OWASP 2021; Phụ lục A map sang 2025.

---

## Phụ lục A — Map OWASP Top 10:2025

| 2025 | Tên | Finding liên quan (số #) |
|------|-----|---------------------------|
| A01 | Broken Access Control | #1, #14, #21, #32 |
| A02 | Security Misconfiguration | #22, #23, #25, #26, #28, #33, #36 |
| A03 | Software Supply Chain Failures | #20 (+ residual SCA) |
| A04 | Cryptographic Failures | #8, #15, #27, #30, #31 |
| A05 | Injection | #10, #11, #16 |
| A06 | Insecure Design | #4, #5, #6, #13, #17, #19, #29, #34 |
| A07 | Authentication Failures | #2, #3, #12, #31, #35 |
| A08 | Software or Data Integrity Failures | #6, #7, #18 |
| A09 | Security Logging & Alerting Failures | #24 (+ residual Redis limits) |
| A10 | Mishandling of Exceptional Conditions | #34 (OOM), generic 500 prod; SSRF #9 map gần A10-2021 |

Ghi chú: SSRF (#9) trong 2021 là A10 riêng; trong 2025 thường gắn Insecure Design /
Broken Access / misconfiguration tùy ngữ cảnh — vẫn liệt kê rõ ở mục #9.

---

*Báo cáo gộp Pass 1 (Opus) + Pass 2 (Grok), 29/07/2026. Bản vá áp vào `backend/`, `frontend/`, `locksend-ai/`; root fail-closed.*
