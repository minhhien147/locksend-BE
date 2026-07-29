#!/usr/bin/env sh
# Railway production: railway.json → startCommand "sh start.sh"
PORT="${PORT:-8000}"
# 2 worker: mỗi worker giữ pool DB riêng (xem db/session.py) nên nhiều worker sẽ
# nhân số connection tới Postgres; Railway free cũng chỉ có vCPU chia sẻ.
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"
# Access log ghi 1 dòng/request — tốn CPU đáng kể khi load test. ACCESS_LOG=false để tắt.
ACCESS_LOG="${ACCESS_LOG:-true}"
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
