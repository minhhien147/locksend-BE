# Mô tả đồ án: LockSend - Secure File Sharing System

## 1) Tên đề tài
**Xây dựng hệ thống lưu trữ và chia sẻ tệp an toàn (Secure File Sharing)** theo mô hình **client-side encryption / zero-knowledge plaintext**, kết hợp quản lý khóa, chia sẻ theo người nhận, kho cá nhân và giám sát rủi ro token.

## 2) Bối cảnh & bài toán
Trong nhiều hệ thống chia sẻ file truyền thống, server hoặc storage có thể nhìn thấy dữ liệu gốc, hoặc nắm quyền truy cập đủ lớn để suy ra nội dung file. Điều này làm tăng rủi ro khi:
- Storage bị lộ hoặc bị đọc trộm
- Server bị xâm nhập
- Khóa giải mã bị quản lý tập trung không an toàn
- Link chia sẻ hoặc token truy cập bị lạm dụng

Đồ án LockSend được xây dựng để giải quyết bài toán đó theo hướng:
- **Mã hóa/giải mã ở phía trình duyệt**
- **Server không nhìn thấy plaintext**
- **Cloud chỉ lưu ciphertext**
- **Quyền truy cập được tách lớp giữa xác thực tài khoản và mở khóa dữ liệu**

## 3) Mục tiêu của đồ án
- Xây dựng hệ thống chia sẻ file có **bảo mật đầu cuối ở mức ứng dụng**
- Đảm bảo **bí mật, toàn vẹn, xác thực nguồn gửi**
- Cho phép **chia sẻ file bằng SAS URL có thời hạn**
- Hỗ trợ **nhiều người nhận** và **thu hồi quyền** mà không cần mã hóa lại toàn bộ blob
- Triển khai cơ chế **zero-knowledge key management** cho keypair người dùng
- Bổ sung các phân hệ thực tế như:
  - đăng nhập, refresh token, RBAC
  - kho cá nhân (vault)
  - lịch sử chia sẻ/nhận file
  - xác minh email
  - đăng nhập Google
  - giám sát token bảo mật bằng rule engine và AI

## 4) Phạm vi và các phân hệ hiện có

### 4.1) Phân hệ lõi chia sẻ file an toàn
- **Upload**: mã hóa file phía client, ký dữ liệu, upload ciphertext
- **Download**: tải ciphertext, kiểm tra chữ ký, giải mã, đối chiếu checksum
- **Share by link**: backend sinh **SAS URL read-only có thời hạn**
- **Envelope encryption**: hỗ trợ lưu wrapped key theo từng người nhận
- **Revoke recipient**: thu hồi quyền truy cập người nhận mà không re-encrypt blob

### 4.2) Phân hệ quản lý khóa zero-knowledge
- Trình duyệt sinh **X25519 + Ed25519 keypair**
- **Private key plaintext chỉ tồn tại trong RAM**
- Trên client có **session wrapper trong `sessionStorage`** để hỗ trợ F5 cùng tab
- Trên server chỉ lưu **`encrypted_key_blob`** đã được mã hóa bằng passphrase
- Public key được lưu trong DB và có thể mirror lên **Azure Key Vault**

### 4.3) Phân hệ kho cá nhân (Vault)
- Người dùng có thể mã hóa file cho chính mình và lưu vào **vault**
- Hỗ trợ thư mục, quota, tìm kiếm file, tải lại và chia sẻ từ vault
- Chia sẻ lại file trong vault bằng cách **re-wrap content key** cho người nhận khác

### 4.4) Phân hệ tài khoản và xác thực
- Đăng ký, đăng nhập bằng email/mật khẩu
- Refresh token qua cookie httpOnly
- **Google OAuth login**
- **Email verification bằng OTP**
- RBAC theo vai trò `owner`, `recipient`, `admin`

### 4.5) Phân hệ giám sát token bảo mật
- Quản trị viên xem thống kê JWT/SAS token
- Rule engine chấm điểm rủi ro
- **AI analysis background job** cho token security
- Hỗ trợ **manual revoke** và **auto-revoke**
- Phân hệ này là lớp bảo mật vận hành, **không truy cập plaintext file**

### 4.6) Tích hợp bổ sung
- **VirusTotal hash lookup**: sau khi giải mã, client gửi SHA-256 để backend tra cứu danh tiếng hash
- **Gemini assistant** (tùy chọn theo cấu hình)

## 5) Công nghệ sử dụng

### Frontend
- React + Vite + TypeScript
- Tailwind CSS
- Axios
- `@noble/curves`
- Web Crypto API

### Backend
- FastAPI + Uvicorn
- SQLAlchemy async + PostgreSQL
- Alembic migration
- Azure SDK

### Cloud / hạ tầng
- Azure Blob Storage: lưu ciphertext
- Azure Key Vault: mirror public key (tùy chọn)
- Managed Identity / DefaultAzureCredential

### Module mở rộng
- `locksend-ai/`: mô hình AI phân tích rủi ro token

### Primitive mật mã chính
- **X25519**: trao đổi khóa
- **HKDF-SHA256**: dẫn xuất khóa
- **AES-256-GCM**: mã hóa file
- **Ed25519**: chữ ký số
- **SHA-256**: checksum plaintext/ciphertext
- **PBKDF2-SHA256 + AES-256-GCM**: bọc keypair bằng passphrase phía client

## 6) Kiến trúc tổng quan

### Thành phần chính
- **Sender Browser**: mã hóa file, ký dữ liệu, upload ciphertext
- **Recipient Browser**: tải ciphertext, verify, giải mã
- **FastAPI Backend**: auth, metadata, upload orchestration, SAS URL, vault, revoke, token security
- **PostgreSQL**: user, public key, encrypted key blob, file metadata, recipient mapping, refresh token
- **Azure Blob Storage**: lưu ciphertext và metadata
- **Azure Key Vault**: lưu/mirror public key nếu bật cấu hình
- **LockSend AI**: phân tích token security theo background job hoặc model local

### Ranh giới tin cậy
- **Browser zone**: nơi duy nhất plaintext file và private key plaintext xuất hiện
- **Backend zone**: xử lý auth, metadata, token security; không giải mã file
- **Database zone**: lưu metadata và encrypted key blob; không có private key plaintext
- **Storage zone**: chỉ lưu ciphertext

## 7) Luồng hoạt động chính

### 7.1) Đăng ký, đăng nhập và xác minh tài khoản
1. Người dùng đăng ký hoặc đăng nhập bằng email/mật khẩu hoặc Google
2. Backend phát access token + refresh token
3. Nếu hệ thống bật xác minh email, người dùng xác minh bằng OTP
4. Sau khi đăng nhập, người dùng vẫn cần **mở khóa keypair** để thao tác mã hóa/giải mã

### 7.2) Tạo và mở khóa keypair
1. Người dùng tạo **X25519 + Ed25519 keypair** trên trình duyệt
2. Keypair được bọc bằng passphrase thành **`encrypted_key_blob`**
3. Server lưu public key và encrypted blob; không nhận private key plaintext
4. Khi sử dụng, client giải mã blob bằng passphrase và nạp private key vào RAM
5. `sessionStorage` chỉ giữ session wrapper tạm thời để hỗ trợ reload cùng tab

### 7.3) Gửi file
1. Người gửi chọn file và người nhận
2. Trình duyệt tính **SHA-256 plaintext**
3. Sinh khóa phiên, thực hiện **X25519 + HKDF + AES-256-GCM**
4. Ký ciphertext hoặc manifest bằng **Ed25519**
5. Backend nhận ciphertext, tính thêm **SHA-256 ciphertext** để audit
6. Ciphertext được upload lên Azure Blob
7. Backend trả về SAS URL hoặc lưu bản ghi file/vault tùy ngữ cảnh

### 7.4) Nhận file và giải mã
1. Người nhận lấy SAS URL hoặc mở file được chia sẻ trong hệ thống
2. Trình duyệt tải ciphertext và metadata
3. Verify chữ ký Ed25519
4. Dẫn xuất lại khóa và giải mã AES-GCM
5. So sánh lại **SHA-256 plaintext** sau giải mã
6. Nếu hash không khớp, hệ thống cảnh báo file có thể đã bị thay thế hoặc bị giả mạo
7. Sau khi giải mã xong, người dùng có thể tra cứu hash qua VirusTotal

### 7.5) Lưu và chia sẻ từ vault
1. Người dùng mã hóa file cho chính mình và lưu vào vault
2. File được quản lý theo thư mục/quota/lịch sử
3. Khi cần chia sẻ, hệ thống **re-wrap content key** cho recipient mới
4. Không cần upload lại hoặc mã hóa lại toàn bộ blob

### 7.6) Giám sát token security
1. Backend thu thập JWT/SAS metrics
2. Rule engine tính risk score và recommendation
3. Admin có thể chạy AI analysis dưới dạng **background job**
4. Kết quả dùng để hỗ trợ revoke thủ công hoặc auto-revoke

## 8) Thiết kế dữ liệu
Các bảng chính trong hệ thống gồm:
- `users`: thông tin người dùng và vai trò
- `user_public_keys`: public keys và `encrypted_key_blob`
- `files`: metadata file đã mã hóa
- `file_recipients`: wrapped key cho từng người nhận, trạng thái revoke
- `refresh_tokens`: quản lý phiên đăng nhập
- `sas_token_records`: theo dõi SAS token và trạng thái soft-revoke
- `vault_folders`: thư mục trong vault
- `upload_sessions`: multipart/chunked upload
- `token_ai_analysis_jobs`: hàng đợi và trạng thái AI background job

Mục tiêu của thiết kế này là:
- quản lý file chia sẻ và vault trên cùng nền dữ liệu
- hỗ trợ revoke theo recipient
- hỗ trợ audit
- hỗ trợ token security rule engine và AI

## 9) Tính chất an toàn thông tin
- **Confidentiality**: plaintext không rời khỏi trình duyệt
- **Integrity**: AES-GCM auth tag + chữ ký Ed25519 + checksum SHA-256
- **Authenticity**: người nhận xác thực được nguồn gửi
- **Least privilege**: SAS URL có thời hạn, read-only, HTTPS
- **Zero-knowledge key handling**: server không giữ private key plaintext hay passphrase
- **Operational security**: token security giám sát rủi ro JWT/SAS độc lập với plaintext file

### Mô hình đe dọa được giảm thiểu

| Mối đe dọa | Cơ chế bảo vệ |
|---|---|
| Đọc trộm file trên storage | AES-256-GCM, storage chỉ thấy ciphertext |
| Server bị truy cập trái phép | Server không có plaintext file |
| Giả mạo người gửi | Ed25519 signature |
| Nội dung file bị thay thế | SHA-256 plaintext verify sau giải mã |
| Link chia sẻ bị lộ | SAS URL ngắn hạn, HTTPS, read-only |
| Phiên truy cập/token bị lạm dụng | Rule engine + AI token security + revoke |

## 10) Cài đặt và chạy local

### Backend
```bash
cd backend
venv\Scripts\activate
pip install -r requirements.txt
python -m alembic upgrade head
uvicorn main:app --reload --port 8000
```

Biến môi trường quan trọng:
- `DATABASE_URL`
- `JWT_SECRET` hoặc `JWT_PUBLIC_KEY`
- `AZURE_STORAGE_ACCOUNT_NAME`
- `AZURE_STORAGE_CONTAINER_NAME`
- `AZURE_KEY_VAULT_URL` (nếu dùng)
- `ALLOWED_ORIGINS`

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Biến môi trường quan trọng:
- `VITE_API_URL`

### LockSend AI (tùy chọn)
```bash
cd locksend-ai
pip install -r requirements.txt
python train.py
```

Module AI dùng cho trang **Admin Token Security**, không ảnh hưởng tới luồng mã hóa/giải mã file cốt lõi.

## 11) Kết quả đã triển khai
- Mã hóa/giải mã file hoàn toàn ở frontend
- Quản lý keypair theo mô hình zero-knowledge thực tế hơn
- Chia sẻ file bằng SAS URL có thời hạn
- Hỗ trợ vault cá nhân và chia sẻ lại từ vault
- Hỗ trợ revoke recipient mà không re-encrypt blob
- Có đăng nhập Google và xác minh email OTP
- Có giám sát token bảo mật bằng rule engine và AI background jobs
- Có tích hợp tra cứu hash VirusTotal sau giải mã

## 12) Hạn chế hiện tại và hướng phát triển
- Streaming decrypt cho file rất lớn vẫn còn có thể tối ưu thêm
- Key rotation tự động và re-wrap hàng loạt chưa hoàn chỉnh
- Hardening nâng cao như WebAuthn/hardware-backed key chưa triển khai
- Audit integrity cho blob sau lưu trữ có thể mở rộng thêm endpoint riêng
- VirusTotal và Gemini phụ thuộc cấu hình API key ở môi trường chạy

## 13) Kết luận
LockSend không chỉ là một demo mã hóa file đơn lẻ, mà là một hệ thống chia sẻ file an toàn có kiến trúc khá đầy đủ: từ **mã hóa phía client**, **quản lý khóa zero-knowledge**, **chia sẻ và thu hồi quyền**, đến **xác thực tài khoản** và **giám sát rủi ro token ở mức vận hành**. Điều này giúp đồ án vừa có giá trị học thuật về an toàn thông tin, vừa có định hướng triển khai gần với hệ thống thực tế.

## 14) Tài liệu liên quan trong repo
- `../README.md`: tổng quan kiến trúc, stack, cách chạy local
- `DOCUMENTATION_VI.md`: tài liệu chi tiết để tái hiện dự án
- `HUONG_DAN_CHUC_NANG_VA_FLOW_WEB.md`: mô tả flow chức năng theo code hiện tại
- `LUONG_HOAT_DONG.md`, `OWASP_SECURITY_REPORT.md`, `SECURITY_AUDIT_2026-07-29.md`
- `../backend/db/schema.sql` và `../backend/db/README.md`: thiết kế CSDL

