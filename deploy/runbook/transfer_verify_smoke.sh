#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SVC="${APP_SERVICE:-app}"
BASE_URL="${BASE_URL:-http://localhost:5555}"

echo "=== SQLite -> Postgres transfer (strict) ==="
"$ROOT/runbook/transfer_sqlite_to_postgres.sh"

echo
echo "=== Restart app service ($APP_SVC) ==="
docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.pg.yml" restart "$APP_SVC"

echo
echo "=== Critical-flow smoke tests ==="
BASE_URL="$BASE_URL" "$ROOT/runbook/smoke_critical_flows.sh"

echo
echo "ALL OK"
