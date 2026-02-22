#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$ROOT_DIR/deploy/.env"
COMPOSE_FILE="$ROOT_DIR/deploy/docker-compose.prod.pg.yml"
OUT_DIR="$ROOT_DIR/deploy/backups"

mkdir -p "$OUT_DIR"

ts="$(date +"%Y%m%d-%H%M%S")"
out="$OUT_DIR/backup-pg-$ts.sql.gz"

if [ ! -f "$ENV_FILE" ]; then
  echo "Env file not found: $ENV_FILE"
  echo "Create it from deploy/.env.prod.example"
  exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "Compose file not found: $COMPOSE_FILE"
  exit 1
fi

echo "Dumping Postgres (compose: $COMPOSE_FILE) ..."
# Use container's own env vars for user/db.
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec -T postgres \
  bash -lc 'pg_dump --no-owner --no-acl -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  | gzip -9 > "$out"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$out" > "$out.sha256"
fi

echo "Postgres backup created: $out"
