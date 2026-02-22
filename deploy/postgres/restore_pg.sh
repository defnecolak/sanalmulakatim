#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: ./deploy/postgres/restore_pg.sh ./deploy/backups/backup-pg-YYYYMMDD-HHMMSS.sql.gz"
  exit 1
fi

ARCHIVE="$1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$ROOT_DIR/deploy/.env"
COMPOSE_FILE="$ROOT_DIR/deploy/docker-compose.prod.pg.yml"

if [ ! -f "$ARCHIVE" ]; then
  echo "Backup not found: $ARCHIVE"
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Env file not found: $ENV_FILE"
  exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "Compose file not found: $COMPOSE_FILE"
  exit 1
fi

echo "Restoring Postgres from: $ARCHIVE"

# Safety: take a fresh dump before overwriting
"$ROOT_DIR/deploy/postgres/backup_pg.sh" || true

# Restore into the running postgres service.
# WARNING: this drops existing objects owned by the current db.
# For MVP, the simplest safe path is to recreate schema from scratch.

gunzip -c "$ARCHIVE" \
  | docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec -T postgres \
      bash -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1'

echo "Restore complete. Consider restarting app containers." 
