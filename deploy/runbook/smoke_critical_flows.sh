#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SVC="${APP_SERVICE:-app}"
BASE_URL="${BASE_URL:-http://localhost:5555}"

echo "Running critical-flow smoke tests inside container ($APP_SVC) ..."
echo "- base url: $BASE_URL"

# This script assumes the app is running inside the same container (localhost:5555).
# If you run it from outside, set BASE_URL to the public domain.

docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.pg.yml" exec -T "$APP_SVC" \
  python /app/backend/smoke_critical_flows.py --base-url "$BASE_URL"

echo "OK"
