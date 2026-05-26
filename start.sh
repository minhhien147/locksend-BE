#!/usr/bin/env sh
set -e

if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: DATABASE_URL is not set. Add Railway PostgreSQL and reference it on locksend-BE."
  exit 1
fi

echo "Running alembic upgrade head..."
alembic upgrade head

echo "Starting uvicorn on port ${PORT}..."
exec uvicorn main:app --host 0.0.0.0 --port "${PORT}"
