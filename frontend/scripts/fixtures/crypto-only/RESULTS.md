# Mục 2 — Crypto-only: thời gian mã hóa / giải mã (ms)

Ngày: 2026-07-31T15:01:38.556Z
Môi trường: win32 · Node v22.15.1
Thuật toán: AES-256-GCM · chunk 4 MB (DEFAULT_CHUNK_SIZE FE)
Số lần lặp mỗi size: 3 (đã warm-up 1 lần, không tính)
Không gồm: upload/download mạng, SAS, UI

| Size | Chunks | Encrypt (ms) ±σ | Decrypt (ms) ±σ | Encrypt MB/s | Decrypt MB/s | SHA khớp |
|---:|---:|---:|---:|---:|---:|:---:|
| 4 MB | 1 | 2.7 ± 0.2 | 5.9 ± 0.3 | 1482.3 | 679.2 | ✓ |
| 16 MB | 4 | 9.8 ± 0.4 | 21.0 ± 0.9 | 1633.4 | 763.2 | ✓ |
| 64 MB | 16 | 39.6 ± 0.3 | 84.3 ± 2.6 | 1617.4 | 759.5 | ✓ |

## Ghi chú báo cáo

- Cột **Encrypt/Decrypt (ms)** là thời gian thuần Web Crypto trên máy đo.
- **MB/s** = size_MB / (ms/1000).
- So với E2E upload: phần lớn thời gian thực tế thường là mạng Azure, không phải AES.
