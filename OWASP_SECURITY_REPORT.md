# OWASP Top 10 — Báo cáo Bảo mật LockSend

**Ngày thực hiện:** 08/07/2026  
**Phiên bản OWASP:** 2021  
**Phạm vi:** Backend (FastAPI), Frontend (React), AI Service (locksend-ai)

---

## Tổng quan

| # | Rủi ro | Mức độ trước | Mức độ sau | Trạng thái |
|---|--------|-------------|------------|------------|
| A01 | Broken Access Control | 🟠 Trung bình | 🟢 Thấp | ✅ Đã vá |
| A02 | Cryptographic Failures | 🟠 Trung bình | 🟢 Thấp | ✅ Đã vá |
| A03 | Injection | 🔴 Cao | 🟢 Thấp | ✅ Đã vá |
| A04 | Insecure Design | 🟠 Trung bình | 🟢 Thấp | ✅ Đã vá |
| A05 | Security Misconfiguration | 🔴 Cao | 🟢 Thấp | ✅ Đã vá |
| A06 | Vulnerable & Outdated Components | 🟡 Chưa kiểm tra | 🟢 Có giám sát | ✅ Đã vá |
| A07 | Identification & Authentication Failures | 🔴 Cao | 🟢 Thấp | ✅ Đã vá |
| A08 | Software & Data Integrity Failures | 🔴 Cao | 🟢 Thấp | ✅ Đã vá |
| A09 | Security Logging & Monitoring Failures | 🟠 Trung bình | 🟢 Thấp | ✅ Đã vá |
| A10 | Server-Side Request Forgery (SSRF) | 🔴 Cao | 🟢 Thấp | ✅ Đã vá |

---

## A01 — Broken Access Control

### Vấn đề trước khi vá
- Chưa có giới hạn số lần download cho recipient — có thể download không giới hạn.
- Admin sub-routes cần kiểm tra rõ ràng hơn ở từng endpoint.

### Thay đổi đã thực hiện

**File:** `backend/routers/download_router.py`

```python
# In-memory rate limiter per recipient per file
_DOWNLOAD_MAX = int(os.getenv("DOWNLOAD_MAX_PER_RECIPIENT", "20"))
_DOWNLOAD_WINDOW = int(os.getenv("DOWNLOAD_RATE_WINDOW", "3600"))

def _check_download_rate(user_id: str, file_id: str | None) -> None:
    """Giới hạn 20 lần download / recipient / file / giờ."""
    ...
    if len(recent) >= _DOWNLOAD_MAX:
        raise HTTPException(status_code=429, detail="Vượt giới hạn download...")
```

### Cấu hình
| Biến môi trường | Mặc định | Mô tả |
|-----------------|----------|-------|
| `DOWNLOAD_MAX_PER_RECIPIENT` | `20` | Số lần download tối đa mỗi giờ |
| `DOWNLOAD_RATE_WINDOW` | `3600` | Cửa sổ thời gian tính (giây) |

### Kiểm tra
- Vault: mọi endpoint `/vault/files/{file_id}` đã có `FileModel.owner_id == current.id`
- SAS URL: validate host + container trước khi dùng (đã có từ trước)

---

## A02 — Cryptographic Failures

### Vấn đề trước khi vá
- `JWT_SECRET` không kiểm tra độ dài — có thể đặt chuỗi ngắn yếu.
- Không có cảnh báo nếu `ALLOWED_ORIGINS=*` trên production.

### Thay đổi đã thực hiện

**File:** `backend/main.py`

```python
def _validate_startup_config() -> None:
    jwt_secret = os.getenv("JWT_SECRET", "")
    jwt_algo = os.getenv("JWT_ALGORITHM", "HS256")
    if jwt_algo.startswith("HS") and len(jwt_secret) < 32:
        warnings.warn("SECURITY A02: JWT_SECRET quá ngắn (< 32 ký tự)...")
        logger.warning("SECURITY A02: JWT_SECRET quá ngắn — rủi ro brute-force!")

    if "*" in os.getenv("ALLOWED_ORIGINS", "").split(","):
        logger.warning("SECURITY A05: ALLOWED_ORIGINS='*' không được dùng trên production!")

_validate_startup_config()  # Chạy ngay khi khởi động
```

### Khuyến nghị thêm
- Dùng tối thiểu **256-bit random string** cho `JWT_SECRET`:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- Cân nhắc chuyển sang **RS256** (asymmetric) cho production.

---

## A03 — Injection

### Vấn đề trước khi vá
- Tên file từ client được dùng trực tiếp làm blob name trên Azure → path traversal.
- AI feature vector không kiểm tra giá trị — NaN/Inf có thể làm lệch model.

### Thay đổi đã thực hiện

**File:** `backend/routers/_upload_helpers.py` — hàm `sanitize_filename()`

```python
def sanitize_filename(filename: str) -> str:
    """Loại bỏ path traversal, null bytes, control chars, unicode tricks."""
    name = unicodedata.normalize("NFC", filename)
    name = re.split(r'[/\\]', name)[-1]          # chỉ lấy basename
    name = _UNSAFE_CHARS.sub("_", name)           # xoá ký tự nguy hiểm
    name = _DOT_SEGMENTS.sub("_", name)           # loại double-dots
    name = name.strip(". ")
    return name[:200] or "upload"                 # giới hạn 200 ký tự
```

**File:** `backend/services/locksend_ai.py` — AI feature clamping

```python
# Clamp về range hợp lệ — tránh NaN/Inf làm lệch model
flow_packets_s = max(0.0, min(flow_packets_s, 1e6))
active_sessions = max(0.0, min(active_sessions, 1e5))
ip_count        = max(1.0, min(ip_count, 1e4))
token_age_hours = max(0.0, min(token_age_hours, 8760.0))
```

**File:** `backend/routers/upload_router.py`

```python
# Trước: blob_name = f"{uuid.uuid4()}/{file.filename}"
# Sau:
safe_blob_filename = sanitize_filename(file.filename or "upload")
blob_name = f"{uuid.uuid4()}/{safe_blob_filename}"
```

---

## A04 — Insecure Design

### Vấn đề trước khi vá
- Recipient có thể download file không giới hạn số lần — không có thiết kế rate limit từ đầu.

### Thay đổi đã thực hiện

Xem chi tiết tại **A01** — cùng cơ chế `_check_download_rate()`.

**SAS expiry** đã được enforce bắt buộc 24h qua `generate_and_track_sas(..., hours=24)`.  
Không thể tạo SAS link "vĩnh viễn" — `expires_at` luôn được set và lưu vào `sas_token_records`.

---

## A05 — Security Misconfiguration

### Vấn đề trước khi vá
- Không có HTTP security headers (CSP, HSTS, X-Frame-Options, ...).
- Lỗi 500 có thể leak stack trace.
- Swagger UI `/docs` có thể hiển thị trên production.

### Thay đổi đã thực hiện

**File mới:** `backend/middleware/security_headers.py`

Pure ASGI middleware (không dùng `BaseHTTPMiddleware` để tránh chi phí task group
mỗi request); danh sách header được dựng sẵn 1 lần lúc khởi tạo:

```python
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app
        # ("content-security-policy", "default-src 'self'; ..."), X-Frame-Options: DENY,
        # X-Content-Type-Options: nosniff, X-XSS-Protection, Referrer-Policy,
        # Permissions-Policy, + HSTS khi COOKIE_SECURE=true
        self._overwrite, self._defaults = _build_headers()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self._overwrite:
                    headers[name] = value
                for name, value in self._defaults:
                    if name not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)
```

**File:** `backend/main.py` — custom error handler + ẩn docs

```python
@app.exception_handler(Exception)
async def _generic_error_handler(request, exc):
    logger.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Lỗi máy chủ nội bộ."})
```

Swagger UI tắt khi `APP_ENV=production` (mặc định).

### Cấu hình
| Biến môi trường | Mặc định | Mô tả |
|-----------------|----------|-------|
| `APP_ENV` | `production` | Set `development` để bật `/docs` |
| `CSP_POLICY` | *(built-in)* | Override Content-Security-Policy |
| `COOKIE_SECURE` | `false` | Set `true` để bật HSTS |

---

## A06 — Vulnerable & Outdated Components

### Vấn đề trước khi vá
- Không có quy trình kiểm tra dependency vulnerabilities.

### Thay đổi đã thực hiện

**File mới:** `backend/scripts/security_audit.sh`

```bash
# Kiểm tra tất cả dependencies trong một lệnh
bash backend/scripts/security_audit.sh
```

Script sẽ chạy:
1. `pip-audit -r backend/requirements.txt` — Python backend
2. `pip-audit -r locksend-ai/requirements.txt` — AI service
3. `npm audit --audit-level=moderate` — Frontend

### Tích hợp CI
Thêm vào GitHub Actions / Railway deploy hook:
```yaml
- name: Security Audit
  run: bash backend/scripts/security_audit.sh
```

---

## A07 — Identification & Authentication Failures

### Vấn đề trước khi vá
- Endpoint `/auth/login` không có rate limiting → có thể brute-force mật khẩu.
- Failed login chỉ log username, thiếu IP + User-Agent.

### Thay đổi đã thực hiện

**File mới:** `backend/services/login_guard.py`

```python
# Lockout sau 5 lần thất bại trong 5 phút → khoá 15 phút
MAX_ATTEMPTS    = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOCKOUT_WINDOW  = int(os.getenv("LOGIN_LOCKOUT_WINDOW", "300"))   # 5 phút
LOCKOUT_DURATION= int(os.getenv("LOGIN_LOCKOUT_DURATION", "900")) # 15 phút

# Key = "IP:email" — ngăn account enumeration qua timing
def check_and_record_attempt(ip, email) -> None: ...
def record_failed_attempt(ip, email) -> None: ...
def clear_attempts(ip, email) -> None: ...
```

**File:** `backend/routers/auth_router.py`

```python
# Kiểm tra brute-force TRƯỚC khi query DB
check_and_record_attempt(client_ip, email)

user = await db.execute(...)

if not verify_password(...):
    record_failed_attempt(client_ip, email)
    audit.log_event("user.login.failed", reason="wrong_password",
                    ip=..., user_agent=request.headers.get("User-Agent"), ...)
    raise HTTPException(401, ...)

# Đăng nhập thành công → xoá lịch sử
clear_attempts(client_ip, email)
```

### Cấu hình
| Biến môi trường | Mặc định | Mô tả |
|-----------------|----------|-------|
| `LOGIN_MAX_ATTEMPTS` | `5` | Số lần thất bại tối đa |
| `LOGIN_LOCKOUT_WINDOW` | `300` | Cửa sổ đếm (giây) |
| `LOGIN_LOCKOUT_DURATION` | `900` | Thời gian khoá (giây) |

> **Lưu ý:** Refresh token reuse detection + full-family revocation đã có sẵn từ trước tại `auth_router.py` → `refresh_token()`.

---

## A08 — Software & Data Integrity Failures

### Vấn đề trước khi vá
- `model.pkl` được load qua `pickle.load()` mà không kiểm tra tính toàn vẹn.
- Nếu file bị thay thế (supply chain attack), model độc hại có thể được load.

### Thay đổi đã thực hiện

**File:** `locksend-ai/model_store.py`

```python
def save_checksum(model_file_path: str) -> str:
    """Tính SHA-256 và lưu vào model.pkl.sha256 sau khi train/download."""
    digest = compute_sha256(model_file_path)
    with open(model_file_path + ".sha256", "w") as f:
        f.write(digest)
    return digest

def verify_checksum(model_file_path: str) -> None:
    """A08: Xác minh SHA-256 trước khi pickle.load(). Raise nếu không khớp."""
    expected = open(model_file_path + ".sha256").read().strip()
    actual   = compute_sha256(model_file_path)
    if actual != expected:
        raise ValueError(f"[A08] Model checksum KHÔNG KHỚP! Có thể bị tamper.")

def ensure_model() -> str:
    path = model_path()
    if os.path.isfile(path):
        verify_checksum(path)   # ← Verify mỗi lần load
        return path
    # ... download + save_checksum(path)
```

**File:** `locksend-ai/predict.py`

```python
def load_bundle():
    path = ensure_model()  # checksum verified bên trong
    with open(path, "rb") as f:
        bundle = pickle.load(f)  # nosec B301 — đã verify SHA-256 trước khi load
    ...
```

### Lưu ý khi train
Sau mỗi lần train xong, gọi thủ công để cập nhật checksum:
```python
from model_store import save_checksum, model_path
save_checksum(model_path())
```

---

## A09 — Security Logging & Monitoring Failures

### Vấn đề trước khi vá
- Failed login thiếu User-Agent → khó trace bot/scanner.
- Không có cảnh báo khi download bất thường.

### Thay đổi đã thực hiện

**File:** `backend/routers/auth_router.py` — enriched failed login log

```json
{
  "event": "user.login.failed",
  "username": "user@example.com",
  "user_id": "...",
  "reason": "wrong_password",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "request_id": "..."
}
```

**File:** `backend/routers/download_router.py` — anomaly detection

```python
# Cảnh báo khi đạt 50% ngưỡng rate limit
if recent_count >= max(1, _DOWNLOAD_MAX // 2):
    logger.warning(
        "SECURITY A09: Lượt download bất thường — user=%s file=%s count=%d/%d",
        current.id, fid_logged, recent_count, _DOWNLOAD_MAX
    )
```

### Các event audit đang được ghi
| Event | Khi nào |
|-------|---------|
| `user.login` | Đăng nhập thành công |
| `user.login.failed` | Sai mật khẩu / user không tồn tại |
| `user.login.google` | Google OAuth |
| `user.logout` | Đăng xuất |
| `user.token_refresh` | Refresh access token |
| `security.refresh_token_reuse` | Phát hiện tái dùng refresh token |
| `file.upload` | Upload file |
| `file.download` | Download file |
| `file.share` | Chia sẻ file |
| `vault.share` | Chia sẻ từ vault |

---

## A10 — Server-Side Request Forgery (SSRF)

### Vấn đề trước khi vá
- `GEMINI_API_BASE` env var có thể bị set thành URL nội bộ.
- `LOCKSEND_AI_URL` có thể trỏ tới Azure IMDS (169.254.169.254) để leak metadata.

### Thay đổi đã thực hiện

**File mới:** `backend/services/ssrf_guard.py`

```python
# Danh sách private network bị chặn
_BLOCKED_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",   # ← Azure IMDS
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"
]

def validate_gemini_base(url: str) -> str:
    """Chỉ cho phép generativelanguage.googleapis.com."""
    return validate_url(url, allowed_hosts={"generativelanguage.googleapis.com"})

def validate_locksend_ai_url(url: str) -> str:
    """Chặn Azure IMDS và link-local."""
    ...
```

**File:** `backend/services/gemini_assistant.py`

```python
def _api_base() -> str:
    raw = os.getenv("GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta")
    try:
        return validate_gemini_base(raw)   # ← SSRF guard
    except Exception:
        return "https://generativelanguage.googleapis.com/v1beta"  # fallback an toàn
```

**File:** `backend/services/locksend_ai.py`

```python
if LOCKSEND_AI_URL:
    try:
        LOCKSEND_AI_URL = validate_locksend_ai_url(LOCKSEND_AI_URL)
    except ValueError as _ssrf_err:
        logger.error("SECURITY A10: LOCKSEND_AI_URL bị từ chối — %s", _ssrf_err)
        LOCKSEND_AI_URL = ""  # fallback về local mode
```

> **VirusTotal**: Không bị ảnh hưởng — URL cố định `https://www.virustotal.com/api/v3`, hash được validate regex `^[a-fA-F0-9]{64}$` từ trước.

---

## Danh sách file đã thay đổi

### File mới tạo
| File | Mục đích |
|------|---------|
| `backend/middleware/__init__.py` | Export SecurityHeadersMiddleware |
| `backend/middleware/security_headers.py` | A05: HTTP security headers |
| `backend/services/login_guard.py` | A07: Brute-force lockout |
| `backend/services/ssrf_guard.py` | A10: SSRF URL validation |
| `backend/scripts/security_audit.sh` | A06: pip-audit + npm audit |

### File đã sửa
| File | OWASP | Thay đổi |
|------|-------|---------|
| `backend/main.py` | A02, A05 | Startup config check, security headers, error handler, ẩn docs |
| `backend/routers/auth_router.py` | A07, A09 | Brute-force lockout, enriched logging |
| `backend/routers/upload_router.py` | A03 | Filename sanitization |
| `backend/routers/download_router.py` | A04, A09 | Rate limit, anomaly warning |
| `backend/routers/_upload_helpers.py` | A03 | `sanitize_filename()` |
| `backend/services/locksend_ai.py` | A03, A10 | Feature clamping, SSRF guard |
| `backend/services/gemini_assistant.py` | A10 | SSRF guard cho API base URL |
| `locksend-ai/model_store.py` | A08 | SHA-256 checksum save/verify |
| `locksend-ai/predict.py` | A08 | nosec annotation + verified load |

---

## Biến môi trường mới

Thêm vào `backend/.env`:

```env
# A02: JWT Secret (tối thiểu 32 ký tự)
JWT_SECRET=<256-bit-random-string>

# A05: Environment mode
APP_ENV=production          # development để bật /docs
CSP_POLICY=                 # Override CSP header (để trống = dùng mặc định)

# A07: Login brute-force lockout
LOGIN_MAX_ATTEMPTS=5
LOGIN_LOCKOUT_WINDOW=300
LOGIN_LOCKOUT_DURATION=900

# A04: Download rate limit
DOWNLOAD_MAX_PER_RECIPIENT=20
DOWNLOAD_RATE_WINDOW=3600
```

---

## Checklist Production Deployment

- [ ] `JWT_SECRET` ≥ 32 ký tự random
- [ ] `ALLOWED_ORIGINS` không chứa `*`
- [ ] `APP_ENV=production` để ẩn Swagger UI
- [ ] `COOKIE_SECURE=true` để bật HSTS
- [ ] `LOCKSEND_AI_API_KEY` được set (không để optional)
- [ ] Chạy `bash backend/scripts/security_audit.sh` trước mỗi deploy
- [ ] `model.pkl.sha256` đã được commit cùng model (hoặc sinh sau train)
- [ ] Azure Blob Container không để public access

---

*Tài liệu này được tạo tự động — cập nhật khi có thay đổi bảo mật mới.*
