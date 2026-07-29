#!/usr/bin/env sh
# Railway / manual: load model (Volume hoặc LOCKSEND_AI_MODEL_URL) rồi chạy uvicorn.
PORT="${PORT:-8100}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-4}"

echo "[locksend-ai] models dir: ${LOCKSEND_AI_MODELS_DIR:-<repo>/models}"
if [ -n "${LOCKSEND_AI_MODEL_URL:-}" ]; then
  echo "[locksend-ai] LOCKSEND_AI_MODEL_URL set — tải model lúc startup nếu thiếu file"
fi

echo "[locksend-ai] uvicorn :${PORT} workers=${WEB_CONCURRENCY}"
exec uvicorn server:app --host 0.0.0.0 --port "${PORT}" --workers "${WEB_CONCURRENCY}"
