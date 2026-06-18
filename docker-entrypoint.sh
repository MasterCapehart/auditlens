#!/bin/sh
# docker-entrypoint.sh — starts AuditLens dashboard via gunicorn

set -e

SCAN_PATH="${SCAN_PATH:-/data/scan}"
PORT="${PORT:-8080}"
HOST="${HOST:-0.0.0.0}"
WEB_CONCURRENCY="${WEB_CONCURRENCY:-2}"

# Ensure scan directory exists (may be empty on first boot)
mkdir -p "${SCAN_PATH}"

# Ensure DB directory exists (Azure Files may not auto-create subdirs)
mkdir -p "$(dirname "${AUDITLENS_DB:-/data/db/history.db}")"

echo "[AuditLens] Starting dashboard on ${HOST}:${PORT} (workers=${WEB_CONCURRENCY})"
echo "[AuditLens] Scan path: ${SCAN_PATH}"
echo "[AuditLens] DB path:   ${AUDITLENS_DB:-/data/db/history.db}"

# SCAN_PATH is read at request time by the lazy WSGI wrapper in wsgi.py
exec gunicorn \
    --bind "${HOST}:${PORT}" \
    --workers "${WEB_CONCURRENCY}" \
    --timeout 180 \
    --access-logfile - \
    --error-logfile - \
    "auditlens.wsgi:app"
