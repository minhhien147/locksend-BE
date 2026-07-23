#!/usr/bin/env sh
# Railway production: railway.json → startCommand "sh start.sh"
PORT="${PORT:-8000}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"

if [ -n "${DATABASE_URL:-}" ]; then
  echo "[start] alembic upgrade head..."
  alembic upgrade head || echo "[start] WARN: migration failed"
else
  echo "[start] WARN: DATABASE_URL not set — skip migration"
fi

echo "[start] uvicorn :${PORT} workers=${WEB_CONCURRENCY}"
exec uvicorn main:app --host 0.0.0.0 --port "${PORT}" --workers "${WEB_CONCURRENCY}"
