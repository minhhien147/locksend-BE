#!/usr/bin/env sh
# Monorepo helper — canonical backend lives in backend/
# Railway Root Directory should be set to: backend
cd "$(dirname "$0")/backend" || exit 1
exec sh start.sh
