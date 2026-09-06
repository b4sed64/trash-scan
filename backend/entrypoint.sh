#!/bin/sh
# API container entrypoint: apply migrations, then start the server.
set -e

echo "Applying database migrations..."
alembic upgrade head

if [ "${TRASHSCAN_RUN_SEED:-0}" = "1" ]; then
  echo "Seeding development data..."
  python -m app.seed || echo "seed skipped/failed (non-fatal)"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
