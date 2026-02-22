#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SVC="${APP_SERVICE:-app}"

echo "Running DB migrations inside container ($APP_SVC) ..."
docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.yml" exec -T "$APP_SVC" python /app/backend/db_migrate.py --db /app/backend/data/usage.db --dir /app/backend/migrations/sql
echo "OK"
