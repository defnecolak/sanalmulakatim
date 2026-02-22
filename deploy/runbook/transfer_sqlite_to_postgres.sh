#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SVC="${APP_SERVICE:-app}"

# SQLite DB is expected to be present on the mounted volume.
SQLITE_IN_CONTAINER="${SQLITE_IN_CONTAINER:-/app/backend/data/usage.db}"

# Hardened defaults (override via env if desired)
ARCHIVE_DIR_IN_CONTAINER="${SQLITE_ARCHIVE_DIR_IN_CONTAINER:-/app/deploy/backups}"

echo "Running SQLite -> Postgres transfer inside container ($APP_SVC) ..."
echo "- source sqlite: $SQLITE_IN_CONTAINER"
echo "- archive dir  : $ARCHIVE_DIR_IN_CONTAINER"
echo "NOTE: For best consistency, stop traffic / pause writes before running."

# IMPORTANT: This runs with strict counts + archive snapshot + set-readonly.
# If you don't want read-only, remove --set-readonly.

docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.pg.yml" exec -T "$APP_SVC" \
  python /app/backend/db_transfer_sqlite_to_postgres.py \
    --sqlite "$SQLITE_IN_CONTAINER" \
    --migrate \
    --strict-counts \
    --archive-sqlite \
    --archive-dir "$ARCHIVE_DIR_IN_CONTAINER" \
    --set-readonly

echo "OK"
