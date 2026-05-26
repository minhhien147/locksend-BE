#!/usr/bin/env sh
# Local / manual: sh start.sh — production Railway dùng uvicorn trực tiếp (railway.json).
PORT="${PORT:-8000}"

if [ -n "${DATABASE_URL:-}" ]; then
  echo "[start] alembic upgrade head..."
  alembic upgrade head || echo "[start] WARN: migration failed"
else
  echo "[start] WARN: DATABASE_URL not set — skip migration"
fi

echo "[start] uvicorn :${PORT}"
exec uvicorn main:app --host 0.0.0.0 --port "${PORT}"
