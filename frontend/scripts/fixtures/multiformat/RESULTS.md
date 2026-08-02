# Kết quả test đa định dạng (crypto roundtrip)

Ngày: 2026-07-31T12:58:00.432Z
Chunk size: 4 MB (giống DEFAULT_CHUNK_SIZE FE)
Kích thước mẫu: ~2.00 MB / file

| File | MIME | Size | Magic header | Encrypt (ms) | Decrypt (ms) | SHA-256 khớp |
|---|---|---:|:---:|---:|---:|:---:|
| sample.txt | `text/plain` | 2048 KB | ✓ | 1.8 | 2.6 | ✓ |
| sample.pdf | `application/pdf` | 2048 KB | ✓ | 1.3 | 2.6 | ✓ |
| sample.jpg | `image/jpeg` | 2048 KB | ✓ | 1.2 | 3.9 | ✓ |
| sample.png | `image/png` | 2048 KB | ✓ | 1.2 | 2.2 | ✓ |
| sample.zip | `application/zip` | 2048 KB | ✓ | 1.3 | 2.8 | ✓ |
| sample.mp4 | `video/mp4` | 2048 KB | ✓ | 1.5 | 2.3 | ✓ |
| sample.docx | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | 2048 KB | ✓ | 1.2 | 2.3 | ✓ |
| sample.bin | `application/octet-stream` | 2048 KB | ✓ | 1.3 | 2.7 | ✓ |

**PASS** — mọi định dạng khôi phục đúng byte sau encrypt→decrypt.
