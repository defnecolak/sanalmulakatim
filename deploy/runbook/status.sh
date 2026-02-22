#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== docker compose ps =="
docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.prod.yml" ps || true

echo
echo "== healthz =="
DOMAIN="${DOMAIN:-}"
if [[ -n "$DOMAIN" ]]; then
  curl -fsS "https://$DOMAIN/api/healthz" || true
else
  curl -fsS "http://localhost/api/healthz" || true
fi

echo
echo "== tail app log =="
tail -n 120 "$ROOT/../backend/data/app.log" 2>/dev/null || true

echo
echo "== tail caddy access log =="
tail -n 120 "$ROOT/logs/access.log" 2>/dev/null || true
