# Changelog trợ lý — tính năng mới (mới nhất ở trên)

> Mỗi lần ship feature: thêm 3–8 dòng bullet **trên cùng**. Assistant đọc mục này sau knowledge gốc.
> Không viết dài; chỉ những gì user/admin cần biết để dùng đúng.

## 2026-07-31
- Admin → **Nhật ký**: xem log upload/download/API theo user (lọc loại, email, ngày).
- Admin → Token Security → **AI Report**: lọc theo JWT/SAS, decision (ALLOW/MONITOR/REVIEW/REVOKE), tìm email/blob; ưu tiên hiện REVOKE/REVIEW khi list dài.
- Admin → **File Activity**: ngoài download, có top file theo **upload** và recent uploads trong chi tiết file.
- Download file rất lớn (multi-GB): Chrome có thể lỗi ghi đĩa nếu mở DevTools / thiếu dung lượng — đóng DevTools rồi tải lại.

## 2026-07-30
- Monorepo: API canonical nằm trong `backend/`; Railway Root Directory = `backend`.
- Chunk upload mặc định 4MB; file lớn Prefer Put Block thẳng Azure.
- Soft-revoke SAS + giám sát token (rule engine / AI) không đụng plaintext file.
