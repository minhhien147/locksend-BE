# Dữ liệu huấn luyện LockSend AI

CSV **không** commit vào git (quá nặng). `train.py` hỗ trợ nhiều profile — chọn bằng `--dataset`, `--combine`, hoặc biến môi trường.

## Dataset đang dùng (chốt)

| Profile | Trạng thái local | Ghi chú |
|---------|------------------|---------|
| **trustlab** | Có | Production / baseline LockSend |
| **ciciot2023** | Có (subset Merged) | IoT benchmark bổ sung |
| **cic2017** | Có (4 CSV) | Legacy |

Không dùng **idsiot2024** (IEEE login, bỏ khỏi stack train khuyến nghị).

Profile khác (`uwf_zeek24`, `gotham2025`, `cic2018`, `idsiot2024`) vẫn có trong `train.py` nếu sau này cần.

---

## 1. TRUST Lab 2026 (khuyến nghị cho LockSend)

1. Tải [TRUST Lab Dataset](https://doi.org/10.82432/10317/21203) → `trustlab_dataset-main.zip`
2. Giải nén vào `locksend-ai/data/` — **giữ nguyên** cấu trúc `Datasets/` và file `.csv.gz`

```text
locksend-ai/data/trustlab_dataset-main/trustlab_dataset-main/Datasets/
├── Benign/Benign.csv.gz.001 … .017
├── API/API.csv.gz.001 …
├── Bruteforce/Bruteforce.csv.gz
└── …
```

```powershell
python train.py --dataset trustlab --trustlab-fast --benign-parts 2
python train.py --dataset trustlab --benign-parts 0 --max-rows 0
```

---

## 2. CICIoT2023

**Cách nhanh (mirror Hugging Face):**

```powershell
cd locksend-ai
python download_extra_datasets.py
# → data/ciciot2023/Merged01.csv … (subset ~6 file, đủ train)
```

Hoặc tải full từ [UNB CIC IoT 2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) / [IEEE](https://ieee-dataport.org/documents/ciciot2023-dataset).

```powershell
python train.py --dataset ciciot2023 --max-rows 200000
```

---

## 3. Gộp dataset (khuyến nghị)

Khi gộp, `train.py` **union tất cả feature columns** — cột thiếu ở dataset khác được điền `0`.

```powershell
# Chốt: TRUST Lab + CICIoT2023
python train.py --combine trustlab,ciciot2023 --max-rows 200000

# Đầy đủ hơn (cần RAM lớn)
python train.py --combine trustlab,ciciot2023 --benign-parts 0 --max-rows 0
```

Biến môi trường: `LOCKSEND_TRAIN_COMBINE=trustlab,ciciot2023`

---

## 4. CIC-IDS2017 (legacy)

```text
data/Tuesday-WorkingHours.pcap_ISCX.csv …
```

```powershell
python train.py --dataset cic2017
```

---

## 5. Tự chọn dataset có sẵn

```powershell
python train.py --dataset auto
```

Thứ tự ưu tiên: `trustlab` → `idsiot2024` → `ciciot2023` → … → `cic2017` (idsiot bỏ qua nếu không có thư mục data).

---

## Tùy chọn CLI

| Biến / flag | Mặc định | Mô tả |
|-------------|----------|--------|
| `--dataset` / `LOCKSEND_TRAIN_DATASET` | `auto` | Một profile |
| `--combine` / `LOCKSEND_TRAIN_COMBINE` | — | Gộp nhiều profile (phẩy) |
| `--max-rows` / `LOCKSEND_TRAIN_MAX_ROWS` | `120000` | Subsample mỗi file/category; `0` = hết |
| `--trustlab-fast` | off | TRUST Lab: 6 category chính |
| `--benign-parts` | `2` | TRUST Lab: số part Benign (`0` = 17 part) |

Sau train: `models/model.pkl`, `models/metrics.json`.
