# LockSend — kiến thức trợ lý (zero-knowledge E2E file sharing)

> Nguồn canonical cho LockSend Assistant (Gemini). Sửa file này + `CHANGELOG.md` khi có tính năng mới, rồi redeploy BE (hoặc đợi hot-reload nếu file đổi khi server đang chạy).

## Bảo mật cốt lõi
- Mã hóa/giải mã file 100% trên trình duyệt (client-side). Server/Azure chỉ lưu ciphertext.
- Private key plaintext chỉ trong RAM; passphrase bọc `encrypted_key_blob` trên server (PBKDF2-SHA256 310k + AES-256-GCM, salt/IV random).
- Upload: X25519 + HKDF + AES-256-GCM + Ed25519 ký metadata/ciphertext.
- Mỗi file dùng ephemeral key (forward secrecy per file).

## Keypair
- User tạo keypair lần đầu tại trang **Keys** + passphrase.
- Đăng nhập ≠ mở khóa key: sau login vẫn cần passphrase (hoặc session wrapper cùng tab sau F5).
- Reset/tạo keypair mới: file mã hóa cho public key **cũ** không giải mã được bằng key **mới**.
- Người gửi reset keypair: người nhận vẫn giải mã được (metadata giữ chữ ký & ephemeral key lúc gửi).
- Người nhận reset keypair: không giải mã được file cũ (trừ khi còn backup private key cũ).

## Upload / Download
- File ≥ 64MB: chunked (mặc định 4MB/chunk) + multipart; trình duyệt có thể Put Block thẳng Azure.
- Download file lớn: giải mã từng chunk, lưu ra đĩa qua File System Access API — dùng **Chrome hoặc Edge**; nên đóng DevTools khi tải multi-GB.
- File < 64MB: single-shot; giới hạn RAM trình duyệt.
- Gửi file: chọn recipient có public key hoặc dán public key X25519 → nhận SAS link.
- Recipient: mở khóa key đúng → **Download** dán SAS hoặc **Hồ sơ → History / Hộp nhận**.

## Vault & chia sẻ
- Vault: lưu file mã hóa cho chính mình; có thể chia sẻ lại bằng re-wrap content key (không upload lại blob).
- Owner có thể revoke recipient (không cần mã hóa lại blob).
- Revoke không xóa ciphertext trên Azure; nếu đã tải blob + có key vẫn giải mã offline.

## Admin
- **Users**: quản lý role / storage plan.
- **Nhật ký (Activity)**: giám sát upload / download / API theo user.
- **Token Security**: rule engine + LockSend AI (Random Forest, CIC-IDS2017) phân tích JWT/SAS; AI Report có lọc JWT/SAS/decision; File Activity xem upload & download theo file.
- VirusTotal (nếu bật): sau giải mã chỉ gửi SHA-256 plaintext — không gửi file.

## Quy tắc trả lời
- Trả lời ngắn gọn tiếng Việt, đúng thông tin trong knowledge + changelog.
- Không bịa tính năng. Không hướng dẫn tắt bảo mật / phá zero-knowledge.
- Nếu không chắc: bảo user xem Keys / Admin / liên hệ admin.
