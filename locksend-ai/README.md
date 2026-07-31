# LockSend AI (monorepo)

Random Forest phát hiện hành vi bất thường (TRUST Lab / CICIoT) — dùng cho **Token Security** trong LockSend.

Nằm trong repo: `secure-file-sharing/locksend-ai/`

## Cấu trúc

```
locksend-ai/
├── predict.py      # inference + SHAP
├── train.py        # huấn luyện
├── download_extra_datasets.py  # tải CICIoT2023 (HF)
├── server.py       # HTTP service (host riêng Ubuntu)
├── requirements.txt
├── data/           # CSV train (gitignore — xem data/README.md)
├── models/
│   ├── model.pkl   # gitignore — tạo bằng train.py
│   └── metrics.json
└── deploy/
    └── locksend-ai.service
```

## Dataset

**Chốt:** TRUST Lab 2026 + CICIoT2023 (+ CIC-IDS2017 legacy). Chi tiết: [data/README.md](./data/README.md).

```powershell
# Một dataset
python train.py --dataset trustlab

# Gộp (khuyến nghị)
python train.py --combine trustlab,ciciot2023 --max-rows 200000
```

## Train & chạy local

```powershell
cd locksend-ai
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# TRUST Lab 2026 (khuyến nghị) — xem data/README.md
python train.py --dataset trustlab
python train.py --combine trustlab,ciciot2023

# Hoặc tự chọn: auto | cic2018 | cic2017
python train.py --dataset auto
python predict.py
```

Dataset: [data/README.md](./data/README.md)

## HTTP service (VPS / local)

```bash
cd /opt/secure-file-sharing/locksend-ai
source venv/bin/activate
export LOCKSEND_AI_API_KEY="your-secret"
uvicorn server:app --host 0.0.0.0 --port 8100
```

Backend LockSend (`.env`):

```env
LOCKSEND_AI_URL=http://<host-ai>:8100
LOCKSEND_AI_API_KEY=your-secret
```

## Railway (service riêng — khuyến nghị production)

Repo: [minhhien147/locksend-ai](https://github.com/minhhien147/locksend-ai). Root Directory: `/`.

### 1. Service `locksend-ai`

- **RAM:** tối thiểu **2 GB** (tránh OOM khi load sklearn + SHAP)
- **Volume** mount tại `/data` (khuyến nghị — không cần Azure/S3)

Copy model sau train local:

```powershell
# model combined ~2 MB — từ locksend-ai/models/model.pkl
# Railway CLI hoặc dashboard: upload vào volume → /data/model.pkl
```

Biến môi trường trên **locksend-ai**:

```env
LOCKSEND_AI_API_KEY=<shared-secret>
LOCKSEND_AI_MODELS_DIR=/data
```

(Tuỳ chọn thay Volume: `LOCKSEND_AI_MODEL_URL=https://...` — URL public tải `model.pkl`)

Healthcheck: `GET /health/live`. Model sẵn sàng khi `GET /health` → `ready: true`.

### 2. Service `locksend-be` (cùng Railway project)

```env
LOCKSEND_AI_URL=http://${{locksend-ai.RAILWAY_PRIVATE_DOMAIN}}:${{locksend-ai.PORT}}
LOCKSEND_AI_API_KEY=<cùng-secret-với-ai>
LOCKSEND_AI_TIMEOUT=30
```

Redeploy **cả hai** service sau khi đổi model hoặc code `locksend_ai.py` (mapping feature TRUST Lab).

## Tích hợp backend

- **Local:** backend tự dùng `<repo>/locksend-ai` qua `backend/services/locksend_ai.py`
- **Remote:** chỉ cần `LOCKSEND_AI_URL` — không cài ML libs trên backend

## Risk → quyết định

| Score | Level | Decision |
|-------|-------|----------|
| 0.0–0.2 | NORMAL | ALLOW |
| 0.2–0.5 | LOW | ALLOW |
| 0.5–0.8 | HIGH | MONITOR |
| ≥ 0.8 | CRITICAL | REVOKE |
