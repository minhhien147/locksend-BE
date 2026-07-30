# Hướng dẫn Load Testing — Secure File Sharing (LockSend)

> **Mục tiêu:** Giả lập nhiều người dùng đồng thời truy cập hệ thống, đo hiệu năng thực tế và kiểm tra hệ thống đáp ứng được kỳ vọng.  
> **Thời gian thực hiện:** ~30–45 phút  
> **Công cụ:** Azure Load Testing (Azure Portal) + Railway (backend)

---

## Mục lục

1. [Tổng quan kịch bản test](#1-tổng-quan-kịch-bản-test)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Chuẩn bị trước khi test](#3-chuẩn-bị-trước-khi-test)
4. [Tạo Azure Load Testing Resource](#4-tạo-azure-load-testing-resource)
5. [Tạo và cấu hình test](#5-tạo-và-cấu-hình-test)
6. [Chạy test theo 4 mức tải](#6-chạy-test-theo-4-mức-tải)
7. [Đọc và phân tích kết quả](#7-đọc-và-phân-tích-kết-quả)
8. [Theo dõi Railway Metrics song song](#8-theo-dõi-railway-metrics-song-song)
9. [Bảng kết quả tổng hợp](#9-bảng-kết-quả-tổng-hợp)
10. [Kết quả kỳ vọng](#10-kết-quả-kỳ-vọng)
11. [Xử lý lỗi thường gặp](#11-xử-lý-lỗi-thường-gặp)
12. [(Tùy chọn) Tạo test user để test endpoint có auth](#12-tùy-chọn-tạo-test-user-để-test-endpoint-có-auth)
13. [Load test Upload/Download — 100 tài khoản](#13-load-test-uploaddownload--100-tài-khoản)

---

## 1. Tổng quan kịch bản test

### Mục tiêu đo lường

| Chỉ số | Mô tả | Ngưỡng kỳ vọng |
|---|---|---|
| **p50 latency** | 50% request hoàn thành trong thời gian này | < 200 ms |
| **p95 latency** | 95% request hoàn thành trong thời gian này | **< 3,000 ms** tại 100 users |
| **p99 latency** | 99% request hoàn thành trong thời gian này | < 5,000 ms |
| **Error rate** | % request thất bại | **< 1%** tại 100 users |
| **Throughput** | Số request/giây hệ thống xử lý được | > 30 req/s |
| **CPU backend** | Mức CPU của Railway service | < 80% |
| **RAM backend** | Mức RAM của Railway service | < 80% (< 400 MB) |

### 4 mức tải cần test

```
10 users  →  50 users  →  100 users  →  500 users
  (nhẹ)       (vừa)      (mục tiêu)     (stress)
```

### Endpoint được test

| Endpoint | Mô tả | Auth cần |
|---|---|---|
| `GET /health` | Health check, đo latency cơ bản | ❌ Không cần |
| `GET /` | Root endpoint, trả về service info | ❌ Không cần |

> **Tại sao dùng `/health` mà không cần tạo tài khoản?**  
> `/health` là endpoint **public hoàn toàn** — không cần JWT, không cần đăng ký, không bị ảnh hưởng token hết hạn. Đây là lựa chọn tốt nhất để đo latency thuần của infrastructure.  
> Muốn test endpoint có auth (như `/vault/files`) → xem Mục 12.

> **Lưu ý về các endpoint KHÔNG dùng được cho load test:**
> - ❌ `/files/` — route chưa được đăng ký trong production
> - ❌ `/vault/files` — cần email verification (phức tạp hơn)
> - ❌ `/docs` — bị tắt trên production (APP_ENV=production)

---

## 2. Kiến trúc hệ thống

```
Azure Load Testing Engine
        │
        │ HTTP requests
        ▼
Railway (FastAPI Backend)  ←── locksend-be-production.up.railway.app
        │
        ├── PostgreSQL (Database)
        ├── Azure Blob Storage (File storage)
        └── LockSend AI Service (locksend-ai-production.up.railway.app)
```

**Thông tin hệ thống:**
- **Backend URL:** `https://locksend-be-production.up.railway.app`
- **Framework:** FastAPI + Uvicorn (Python 3.11+)
- **Hosting:** Railway (shared vCPU, 512 MB RAM trên free plan)
- **Database:** PostgreSQL (Railway)

---

## 3. Chuẩn bị trước khi test

### Yêu cầu tài khoản
- [ ] Tài khoản Azure (Azure for Students hoặc Pay-as-you-go)
- [ ] Quyền truy cập Railway project `locksend-BE`
- [ ] PowerShell (Windows) hoặc Terminal (Mac/Linux)

### Kiểm tra backend đang chạy

Mở PowerShell, chạy lệnh:

```powershell
Invoke-RestMethod -Uri "https://locksend-be-production.up.railway.app/health"
```

**Kết quả mong đợi:**
```json
{
  "status": "ok",
  "locksend_ai": {
    "ready": true,
    "mode": "remote"
  }
}
```

Nếu thấy `status: ok` → backend đang chạy, tiếp tục bước tiếp theo.  
Nếu lỗi → vào Railway → service `locksend-BE` → kiểm tra deployment.

### Warm-up backend (quan trọng)

Railway có thể sleep khi không có traffic. Chạy lệnh này 1 phút trước khi test để backend "thức dậy":

```powershell
1..10 | ForEach-Object {
    $r = Invoke-RestMethod -Uri "https://locksend-be-production.up.railway.app/health"
    Write-Host "[$_/10] status: $($r.status)"
    Start-Sleep -Seconds 2
}
```

---

## 4. Tạo Azure Load Testing Resource

### Bước 4.1

1. Vào **[portal.azure.com](https://portal.azure.com)**
2. Thanh search gõ: **`Azure Load Testing`**
3. Click kết quả **Azure Load Testing**
4. Click **+ Create**

### Bước 4.2 — Điền thông tin

| Field | Giá trị |
|---|---|
| Subscription | Azure for Students |
| Resource group | `rg-secure-filesharing` (tạo mới nếu chưa có) |
| Name | `alt-securefs` |
| Region | **East US** |

5. Click **Review + Create** → **Create**
6. Đợi ~1-2 phút → Click **Go to resource**

> ✅ Bạn sẽ thấy trang Overview của `alt-securefs` với các tab: *Get started, Test runs, Tutorials*

---

## 5. Tạo và cấu hình test

Từ trang Overview của `alt-securefs`:

1. Click **"Create"** dưới mục **"Create by adding HTTP requests"**

### Tab: Basics

| Field | Giá trị |
|---|---|
| Test name | `health-stress-test` |
| Description | `Load test FastAPI Railway - 4 mức tải` |

### Tab: Test plan

Click **"+ Add request"** → điền:

| Field | Giá trị |
|---|---|
| Request name | `health` |
| URL | `https://locksend-be-production.up.railway.app/health` |
| HTTP method | `GET` |

**KHÔNG thêm header gì** — `/health` là endpoint public, không cần Authorization

→ Click **Add**

### Tab: Load

> ⚠️ **Quan trọng:** Test duration tính bằng **phút**, không phải giây!

| Field | Giá trị cho Run đầu tiên |
|---|---|
| Engine instances | `1` |
| Concurrent users per engine | `10` |
| Test duration (minutes) | `2` |
| Ramp-up time (minutes) | `1` |
| Load pattern | `Linear` |

### Tab: Test criteria (tùy chọn)

Click **+ Add** để thiết lập ngưỡng tự động PASS/FAIL:

| Metric | Aggregation | Condition | Threshold | Unit |
|---|---|---|---|---|
| Response time | 95th percentile | Greater than | `3000` | ms |
| Error rate | Percentage | Greater than | `1` | % |

### Tab: Monitoring (bỏ qua)

### → Review + create → Create

---

## 6. Chạy test theo 4 mức tải

### Cách thay đổi số users giữa các lần chạy

Từ trang test → Click **Configure** → **Test** → Tab **Load** → sửa `Concurrent users per engine` → **Apply**

Đợi validation xong (~1 phút) → Click **Run** → **Start**

---

### Run 1 — 10 Concurrent Users

```
Engine instances:             1
Concurrent users per engine:  10
Test duration (minutes):      2
Ramp-up time (minutes):       1
```

**Chạy và đợi ~4 phút → ghi kết quả vào bảng Mục 9.**

---

### Run 2 — 50 Concurrent Users

```
Engine instances:             1
Concurrent users per engine:  50
Test duration (minutes):      2
Ramp-up time (minutes):       1
```

**Chạy và đợi ~4 phút → ghi kết quả vào bảng Mục 9.**

---

### Run 3 — 100 Concurrent Users ⭐ (Mức kỳ vọng chính)

```
Engine instances:             2
Concurrent users per engine:  50
Test duration (minutes):      2
Ramp-up time (minutes):       1
```

**Kỳ vọng: p95 < 3,000ms và Error rate < 1%**

---

### Run 4 — 500 Concurrent Users (Stress test)

```
Engine instances:             5
Concurrent users per engine:  100
Test duration (minutes):      2
Ramp-up time (minutes):       1
```

> ⚠️ Mức này có thể gây Railway free tier bị throttle (HTTP 429/503). Đây là giới hạn hosting, không phải lỗi code.

---

## 7. Đọc và phân tích kết quả

Sau khi mỗi run **Completed**, click vào tên run để xem chi tiết.

### Tab: Statistics (quan trọng nhất)

```
┌─────────────────────────────────────────────────────────────┐
│  Load           │  Response time       │  Error %  │ Req/s  │
│  (Total reqs)   │  (90th percentile)   │           │        │
└─────────────────────────────────────────────────────────────┘
```

**Lưu ý:** Azure hiển thị **p90** mặc định. Để xem p95/p99, click dropdown **"Response Time Aggregation"** → chọn `95th percentile` hoặc `99th percentile`.

### Tab: Client side metrics

Xem các biểu đồ theo thời gian:

| Biểu đồ | Ý nghĩa |
|---|---|
| **Virtual Users (Max)** | Số users thực tế đang test — phải đạt đúng số cấu hình |
| **Response time (successful responses)** | Latency của các request thành công |
| **Requests/sec (Avg)** | Throughput — request mỗi giây |
| **Errors (total)** | Số lỗi theo loại HTTP status code |

### Tab: Engine health

| Biểu đồ | Giải thích |
|---|---|
| **CPU percentage** | CPU của load test engine (Azure), không phải backend |
| **Memory percentage** | RAM của load test engine |
| **Network bytes/sec** | Traffic từ engine đến backend |

> 📌 Engine health là metric của **Azure load engine**, không phải Railway backend. Để xem Railway backend → xem Bước 9.

### So sánh các run

Từ trang test → tab **Test runs** → tick chọn nhiều runs → Click **Compare**

Azure tự vẽ biểu đồ chồng các runs lên nhau để so sánh trực quan.

---

## 8. Theo dõi Railway Metrics song song

Trong lúc test đang chạy, mở tab mới theo dõi Railway:

1. Vào **[railway.app](https://railway.app)** → project → service **locksend-BE**
2. Tab **Metrics**
3. Chọn time range **1h**

### Các metric cần quan tâm

| Metric | Vị trí | Ngưỡng lo ngại |
|---|---|---|
| **CPU** | Biểu đồ CPU (vCPU) | > 0.8 vCPU (gần đạt limit) |
| **Memory** | Biểu đồ Memory (MB) | > 400 MB (Railway free: 512 MB) |
| **Requests** | Biểu đồ Requests | Màu vàng (4xx) hay đỏ (5xx) chiếm nhiều |
| **Response Time** | Biểu đồ Response Time | p95 > 3,000ms |
| **Request Error Rate** | Biểu đồ Error Rate | > 1% |

### Ví dụ Railway metrics tốt

```
CPU:          0.1 - 0.4 vCPU  ← Bình thường
Memory:       100 - 200 MB    ← Bình thường
Error rate:   0.0%            ← Tuyệt vời
Response p90: 100 - 150ms     ← Xuất sắc
```

---

## 9. Bảng kết quả tổng hợp

Ghi kết quả vào bảng này sau mỗi run:

| Mức tải | p50 (ms) | p90 (ms) | p95 (ms) | p99 (ms) | Error% | Req/s | CPU Railway | RAM Railway |
|---|---|---|---|---|---|---|---|---|
| **10 users** | | | | | | | | |
| **50 users** | | | | | | | | |
| **100 users** | | | | | | | | |
| **500 users** | | | | | | | | |

### Kết quả thực tế đã đo (Run 1 — 10 users)

| Metric | Giá trị thực tế | Đánh giá |
|---|---|---|
| p90 latency | **115.75 ms** | Xuất sắc ✓ |
| Throughput | **71.51 req/s** | Rất tốt ✓ |
| Error rate | **0%** | Perfect ✓ |
| CPU Railway | **~0.4 vCPU** | Bình thường ✓ |
| RAM Railway | **100-200 MB** | Bình thường ✓ |

---

## 10. Kết quả kỳ vọng

### Ngưỡng PASS/FAIL

| Mức tải | p95 PASS | Error% PASS | Ghi chú |
|---|---|---|---|
| 10 users | < 500 ms | < 0.1% | Baseline nhẹ |
| 50 users | < 1,500 ms | < 0.5% | Tải vừa |
| **100 users** | **< 3,000 ms** | **< 1%** | **Mức kỳ vọng chính** |
| 500 users | < 8,000 ms | < 5% | Stress — Railway free có thể fail |

### Đường cong latency dự kiến

```
p95 (ms)
│
8000 │                                    ●  500 users
│                                         
3000 │─────────────────────────── PASS/FAIL LINE ─────
│                              ●  100 users
1500 │                  ●  50 users
│
500  │     ●  10 users
│
0    └────────────────────────────────────────────
     10    50    100    500    users
```

### Phân tích kết quả

**Nếu p95 tăng tuyến tính** (x2 users → x2 latency): Backend scale tốt, bottleneck là Railway free tier.

**Nếu p95 tăng đột biến** ở 1 mức cụ thể: Đó là điểm giới hạn — cần tăng resource hoặc tối ưu code.

**Nếu error rate tăng vọt**: Kiểm tra Railway logs — thường do:
- `503 Service Unavailable`: Railway đang throttle
- `504 Gateway Timeout`: Request quá lâu, timeout
- `429 Too Many Requests`: Rate limit của Railway

---

## 11. Xử lý lỗi thường gặp

### ❌ Lỗi: "Test script does not exist"
**Nguyên nhân:** Test bị mất cấu hình sau khi edit  
**Giải pháp:** Xóa test → Tạo test mới từ đầu (Bước 6)

---

### ❌ Lỗi: "Policy violation" khi tạo App Service Plan
**Nguyên nhân:** Azure for Students hạn chế một số SKU/region  
**Giải pháp:** Dùng Azure Load Testing để test trực tiếp URL Railway (không cần App Service Plan)

---

### ❌ Error rate 100% — tất cả 404
**Nguyên nhân:** URL endpoint sai  
**Giải pháp:** Dùng đúng URL `/health` — KHÔNG dùng `/files/` hay `/api/files/`

> **Endpoint hoạt động được:**
> - ✅ `GET /health` — public, không cần auth
> - ✅ `GET /` — public, trả về service info  
> - ✅ `POST /auth/login` — không cần email verified
> - ✅ `POST /auth/register` — public
> - ❌ `GET /files/` — không tồn tại (route chưa được include)
> - ❌ `GET /vault/files` — cần email verified
> - ❌ `/docs` — tắt trên production

---

### ❌ JWT token expired giữa chừng
**Nguyên nhân:** Token hết hạn sau 15 phút (`expires_in: 900`)  
**Giải pháp:** Test với `/health` (không cần token). Nếu cần test endpoint có auth, lấy token ngay trước khi bấm Run.

```powershell
# Lấy token mới
$r = Invoke-RestMethod `
    -Uri "https://locksend-be-production.up.railway.app/auth/login" `
    -Method POST -ContentType "application/json" `
    -Body '{"username": "loadtest@test.com", "password": "LoadTest123!"}'
Write-Host "Bearer $($r.access_token)"
```

---

### ❌ "ModuleNotFoundError" trong Railway Console
**Nguyên nhân:** Railway Console chạy shell riêng, không có venv của app  
**Giải pháp:** Không dùng Railway Console cho script Python phức tạp — thay vào đó gọi API từ PowerShell

---

### ❌ VUH (Virtual User Hours) vượt giới hạn
**Nguyên nhân:** Azure for Students có giới hạn VUH hàng tháng  
**Giải pháp:** Giữ test duration ở **2 phút** mỗi run. Ước tính VUH:
```
VUH = (concurrent users) × (duration in hours)
    = 10 users × (2/60 hours) = 0.33 VUH per run
    = 100 users × (2/60 hours) = 3.33 VUH per run
```

---

### ❌ Auto-stop triggered
**Nguyên nhân:** Error rate vượt 90% trong 60 giây — Azure tự dừng để tiết kiệm chi phí  
**Giải pháp:** Kiểm tra URL có đúng không. Nếu đang test endpoint cần auth → lấy token mới.

---

---

## 12. (Tùy chọn) Tạo test user để test endpoint có auth

> **Bỏ qua mục này nếu chỉ test `/health`.** Chỉ cần làm khi muốn test các endpoint như `POST /auth/login` liên tục với nhiều users.

### Đăng ký user test (PowerShell)

```powershell
$body = '{"username": "loadtest@test.com", "password": "LoadTest123!", "display_name": "Load Tester"}'

$result = Invoke-RestMethod `
    -Uri "https://locksend-be-production.up.railway.app/auth/register" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body

Write-Host "Đăng ký thành công! Email: $($result.email)"
```

> Nếu lỗi **409 Conflict** → user đã tồn tại, bỏ qua.

### Lấy JWT token (hết hạn sau 15 phút)

```powershell
$r = Invoke-RestMethod `
    -Uri "https://locksend-be-production.up.railway.app/auth/login" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"username": "loadtest@test.com", "password": "LoadTest123!"}'

Write-Host "Bearer $($r.access_token)"
```

Copy chuỗi `Bearer eyJ...` → paste vào header `Authorization` trong Azure Load Testing.

> **Lưu ý:** Token hết hạn sau 15 phút. Phải lấy token mới ngay trước mỗi lần bấm Run.

---

## 13. Load test Upload/Download — 100 tài khoản

> **Khác với test `/health`:** Upload/download **bắt buộc** có tài khoản đăng nhập + email đã verify.  
> Azure Load Testing dạng **URL-based** không đủ — cần **JMeter script + CSV** (mỗi virtual user 1 account).

### Tại sao cần 100 tài khoản?

| Yêu cầu | Lý do |
|---|---|
| Mỗi user 1 JWT riêng | Tránh 100 VU dùng chung 1 token → không realistic |
| `email_verified_at` phải có giá trị | `/upload`, `/files/my-files`, `/vault/files` đều gọi `require_verified_email` |
| Role `owner` | Chỉ owner/admin mới được `POST /upload` |

### Bước 1 — Lấy DATABASE_URL từ Railway

1. **railway.app** → project → service **locksend-BE** → tab **Variables**
2. Copy giá trị `DATABASE_URL`

### Bước 2 — Chạy script tạo 100 user (trên máy local)

```powershell
cd e:\secure-file-sharing\backend

# Tạo .env tạm hoặc set biến môi trường
$env:DATABASE_URL = "postgresql+asyncpg://..."   # paste từ Railway

# Kích hoạt venv nếu có
.\venv\Scripts\activate

python scripts/create_loadtest_users.py --count 100 --password "LoadTest123!"
```

**Kết quả mong đợi:**
```
OK — created=100, updated=0, skipped=0
  Emails: loaduser001@loadtest.local … loaduser100@loadtest.local
  Password: LoadTest123!
  CSV: ...\backend\loadtest_users.csv
```

**Hoặc chạy trực tiếp trên Railway** (khuyến nghị nếu local không kết nối được DB):

```bash
railway link
railway run python scripts/create_loadtest_users.py --count 100 --password "LoadTest123!"
```

> Chạy lại với `--reset-existing` nếu muốn đặt lại mật khẩu + verify email cho user đã có.

### Bước 3 — Kiểm tra 1 user login được

```powershell
$r = Invoke-RestMethod `
    -Uri "https://locksend-be-production.up.railway.app/auth/login" `
    -Method POST -ContentType "application/json" `
    -Body '{"username": "loaduser001@loadtest.local", "password": "LoadTest123!"}'

Write-Host "Login OK — role: $($r.role), verified: $($r.email_verified)"
```

### Bước 4 — Endpoint dùng cho load test upload/download

| Bước | Method | URL | Ghi chú |
|---|---|---|---|
| Login | POST | `/auth/login` | Body: `{"username":"...", "password":"..."}` |
| Upload (vault) | POST | `/upload` | multipart: `file`, `metadata_json`, `storage_mode=vault` |
| List file | GET | `/files/my-files` | Header: `Authorization: Bearer <token>` |
| List vault | GET | `/vault/files` | Sau khi upload vault |
| Download metadata | GET | `/files/{file_id}/ciphertext/chunks/0` | Cần `file_id` từ bước list |

**Payload upload tối thiểu (vault — không cần recipient):**

```
storage_mode = vault
metadata_json = {"filename":"loadtest.bin","encryption_alg":"X25519+HKDF+AES-256-GCM"}
file = <bytes giả lập ciphertext, ví dụ 64KB random>
```

> Upload thật trong app mã hóa client-side; load test chỉ gửi **ciphertext giả** để đo throughput/latency backend + Azure Blob, không test crypto.

### Bước 5 — Azure Load Testing với JMeter + CSV

URL-based test **không hỗ trợ** login khác nhau mỗi user → dùng **Upload JMeter script**:

1. Azure Load Testing → **Tests** → **+ Create** → **Upload a JMeter script**
2. Trong JMX: dùng **CSV Data Set Config** trỏ file `loadtest_users.csv`
3. Thread Group = 100 users, mỗi thread đọc 1 dòng CSV
4. Flow mỗi user:
   ```
   POST /auth/login  →  extract access_token
   POST /upload      →  (multipart, storage_mode=vault)
   GET  /files/my-files
   ```

**Cấu hình Load gợi ý (100 users upload/download):**

```
Engine instances:             5
Concurrent users per engine:  20
Test duration (minutes):      2
Ramp-up time (minutes):       1
```

### Lưu ý quan trọng

- **JWT hết hạn 15 phút** — test dài hơn 15 phút cần login lại trong JMX loop
- **Railway free tier** (~512 MB RAM) có thể OOM khi 100 upload đồng thời
- **Azure Blob** có thể throttle nếu 100 upload cùng lúc
- **Không commit** `loadtest_users.csv` vào git (chứa mật khẩu)

### Dọn dẹp sau test (tùy chọn)

Xóa user test trong DB khi không cần nữa (chạy từ backend với DATABASE_URL):

```sql
DELETE FROM users WHERE email LIKE 'loaduser%@loadtest.local';
```

---

## Checklist trước khi chạy test

```
☐ Backend đang chạy: GET /health trả về {"status":"ok"}
☐ Đã warm-up backend (chạy 10 request trước)
☐ Azure Load Testing resource đã tạo (alt-securefs)
☐ Test duration = 2 phút (không phải 60)
☐ URL endpoint là /health
☐ KHÔNG có header Authorization (health không cần)
☐ Mở Railway Metrics sẵn để theo dõi song song
```

---

## Tham khảo

| Tài nguyên | Link |
|---|---|
| Azure Load Testing docs | https://docs.microsoft.com/azure/load-testing/ |
| Railway docs | https://docs.railway.app |
| FastAPI backend | https://locksend-be-production.up.railway.app |
| Azure Portal | https://portal.azure.com |

---

*Tài liệu này được tạo dựa trên kết quả test thực tế ngày 18/07/2026.*  
*Cập nhật bảng kết quả (Bước 10) sau mỗi lần chạy test.*
