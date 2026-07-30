#!/usr/bin/env sh
# Railway production: railway.json → startCommand "sh start.sh"
PORT="${PORT:-8000}"
# Mỗi worker có pool DB riêng (db/session.py): tổng conn ≈ WEB_CONCURRENCY × (pool+overflow).
# Railway Pro: 4 worker mặc định; chỉnh WEB_CONCURRENCY nếu Postgres gần trần max_connections.
WEB_CONCURRENCY="${WEB_CONCURRENCY:-4}"
# Access log 1 dòng/request tốn CPU — tắt mặc định; bật ACCESS_LOG=true khi debug.
ACCESS_LOG="${ACCESS_LOG:-false}"
if [ "${ACCESS_LOG}" = "false" ]; then
  ACCESS_LOG_FLAG="--no-access-log"
else
  ACCESS_LOG_FLAG=""
fi

if [ -n "${DATABASE_URL:-}" ]; then
  echo "[start] alembic upgrade head..."
  alembic upgrade head || echo "[start] WARN: migration failed"
else
  echo "[start] WARN: DATABASE_URL not set — skip migration"
fi

echo "[start] uvicorn :${PORT} workers=${WEB_CONCURRENCY} access_log=${ACCESS_LOG}"
# shellcheck disable=SC2086 — ACCESS_LOG_FLAG phải được word-split (rỗng = không thêm flag)
exec uvicorn main:app --host 0.0.0.0 --port "${PORT}" --workers "${WEB_CONCURRENCY}" ${ACCESS_LOG_FLAG}
